"""Bounded worker invariants and actual service/runtime startup-process recovery."""
import concurrent.futures
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import select
import socket
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from service_management import Service, ServiceError
from service_management.authority import LocalDevUntrustedVerifier
from service_management.composition import CompositionConfig, BoundedWorker, build_application
from service_management.contracts import canonical
from service_management.runtime_port import RuntimeCallError
from test_integration import FakeRuntime
from test_service import command


class CompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    def test_invalid_bounds_shared_storage_and_production_localdev_rejected(self):
        for changes in ({"local_dev_untrusted":True},{"poll_runtime":True},{"rebuild_projection":True},
                        {"projection_database":self.root/"service.db"},{"poll_interval":0},
                        {"batch_size":101},{"projection_pages":True},{"runtime_timeout":float("nan")}):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                CompositionConfig(self.root/"service.db",**changes)

    def test_production_missing_outbound_issuer_disables_workers_without_poisoning_outbox(self):
        from test_integration import ServiceIntegrationTests
        fixture=ServiceIntegrationTests();fixture.setUp();self.addCleanup(fixture.doCleanups)
        approval=fixture.approve()
        app=build_application(CompositionConfig(fixture.path,runtime_endpoint="http://127.0.0.1:9",
            projection_database=self.root/"projection.db",poll_runtime=True,poll_interval=.05,max_backoff=.1))
        app.start();self.addCleanup(app.stop)
        self.assertEqual(app.workers,{})
        row=app.storage.transact(lambda tx:tx.get_handoff(approval["handoff"]["event_id"]))
        self.assertEqual((row["state"],row["attempts"]),("pending",0))
        ready=app.readiness();self.assertFalse(ready["ready"])
        self.assertEqual(ready["checks"]["runtime_authority"]["state"],"unavailable")
        self.assertEqual(ready["checks"]["outbox_delivery"]["owner"],"native-service-authority")
        self.assertNotIn(str(self.root),canonical(ready))

    def test_backoff_failure_codes_are_redacted_and_stop_interrupts_wait(self):
        stopped=threading.Event()
        def failure():raise RuntimeError("SECRET authority or raw intake must never be logged")
        worker=BoundedWorker("fixture",failure,interval=.05,max_backoff=.2,stopped=stopped)
        worker.start()
        deadline=time.monotonic()+2
        while worker.health()["cycles"]<2 and time.monotonic()<deadline:time.sleep(.01)
        health=worker.health();self.assertGreaterEqual(health["cycles"],2)
        self.assertEqual(health["next_delay_seconds"],.2)
        self.assertEqual(health["last_error"],"worker_unavailable")
        self.assertNotIn("SECRET",canonical(health))
        start=time.monotonic();stopped.set();worker.join(1)
        self.assertLess(time.monotonic()-start,.5)

    def test_outbox_batches_are_bounded_and_retries_rotate_fairly(self):
        app=build_application(CompositionConfig(self.root/"service.db",environment="test",local_dev_untrusted=True,
            runtime_endpoint="http://127.0.0.1:9",projection_database=self.root/"projection.db",poll_runtime=True,batch_size=2))
        seen=[]
        class Delivery:
            def pending(inner,after,limit):return [{"event_id":key} for key in "abcd" if key>after][:limit]
            def reconcile(inner,key):
                seen.append(key);return {"state":"pending","last_error":"not_ready"}
        app.delivery=Delivery()
        for _ in range(4):app._deliver()
        self.assertEqual(seen,["a","b","c","d","a","b"])

    def test_projection_rebuild_advances_in_bounded_pages_and_gap_requires_review(self):
        from test_integration import event
        app=build_application(CompositionConfig(self.root/"service.db",environment="test",local_dev_untrusted=True,
            runtime_endpoint="http://127.0.0.1:9",projection_database=self.root/"projection.db",poll_runtime=True,batch_size=2,projection_pages=1))
        runtime=FakeRuntime();runtime.events=[event(i,"run.created") for i in range(1,6)]
        app.runtime=runtime
        self.assertEqual(app._sync()["cursor"],2);self.assertEqual(app._sync()["cursor"],4)
        self.assertEqual(app._sync()["state"],"healthy")
        fingerprint=app.projection.fingerprint();app._rebuild=app.projection.begin_rebuild()
        for _ in range(3):app._sync()
        self.assertEqual(app.projection.fingerprint(),fingerprint)
        self.assertFalse(app.projection.health()["last_rebuild"]["drift_detected"])
        app.projection.reset_for_rebuild();runtime.events=[event(2,"run.created")]
        with self.assertRaises(ServiceError):app._sync()
        self.assertEqual(app.projection.health()["freshness"],"gap")
        with self.assertRaises(ServiceError):app._sync()

    def test_trusted_factory_injects_outbound_port_without_creating_a_signer(self):
        calls=[]
        def authority(request):calls.append(request);raise RuntimeCallError("unauthenticated")
        app=build_application(CompositionConfig(self.root/"service.db",runtime_endpoint="http://127.0.0.1:9"),runtime_authority=authority)
        self.assertTrue(app.outbound_enabled)
        self.assertFalse(app.readiness()["ready"])
        self.assertEqual(calls,[])
        app.stop()
        with self.assertRaises(RuntimeCallError):
            app.runtime.query({"schema":"runtime.query.v1","operation":"events.list","payload":{"after":0,"limit":1}})
        self.assertEqual(calls,[],"shutdown must stop new outbound authority requests")


def eventually(check,seconds=10):
    deadline=time.monotonic()+seconds
    last=None
    while time.monotonic()<deadline:
        try:
            last=check()
            if last:return last
        except (OSError,ValueError,HTTPError):pass
        time.sleep(.03)
    raise AssertionError("bounded process check did not converge: "+repr(last))


@unittest.skipUnless(os.environ.get("SERVICE_RUNTIME_COMMAND"),"set SERVICE_RUNTIME_COMMAND for actual runtime/service process qualification")
class ProcessCompositionTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)
        self.runtime_argv=json.loads(os.environ["SERVICE_RUNTIME_COMMAND"])
        self.processes=[];self.addCleanup(self.stop_all)

    def stop_all(self):
        for process in reversed(self.processes):
            if process.poll() is None:process.terminate()
            try:process.communicate(timeout=15)
            except subprocess.TimeoutExpired:process.kill();process.communicate(timeout=5)

    def spawn(self,argv):
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        self.processes.append(process);return process

    def stop_clean(self,process):
        process.terminate();stdout,stderr=process.communicate(timeout=15)
        self.assertEqual(process.returncode,0,(stdout,stderr))

    def policy(self,path,enabled,expected=None):
        value={"schema":"runtime.new-run-admission-apply.v1","expected_digest":expected,
               "policy":{"schema":"runtime.new-run-admission.v1","enabled":enabled,"composition_digest":"b"*64}}
        request_file=self.root/"apply.json";request_file.write_text(canonical(value));request_file.chmod(0o600)
        result=subprocess.run([*self.runtime_argv[:-1],"process_runtime.admission","apply","--policy",str(path),"--request-file",str(request_file)],capture_output=True,text=True,timeout=10)
        self.assertEqual(result.returncode,0,result.stderr)
        return json.loads(result.stdout)["data"]["policy_digest"]

    def service(self,runtime_endpoint,*,production=False,rebuild=False):
        argv=[sys.executable,"-m","service_management","--database",str(self.root/"service.db"),"--port","0",
              "--runtime-endpoint",runtime_endpoint,"--projection-database",str(self.root/"projection.db"),
              "--poll-runtime","--poll-interval",".05","--max-backoff",".2","--batch-size","2","--projection-pages","1","--runtime-timeout",".2"]
        if not production:argv += ["--environment","test","--local-dev-untrusted"]
        if rebuild:argv += ["--rebuild-projection"]
        process=self.spawn(argv)
        self.assertTrue(select.select([process.stdout],[],[],10)[0],"service CLI did not report startup")
        line=process.stdout.readline();self.assertIn("127.0.0.1:",line)
        port=int(line.split("127.0.0.1:")[1].split(";")[0]);return process,"http://127.0.0.1:"+str(port)

    def get(self,endpoint,path):
        try:
            with urlopen(endpoint+path,timeout=1) as response:return response.status,json.load(response)
        except HTTPError as error:return error.code,json.load(error)

    def post(self,endpoint,raw,query=False):
        with urlopen(Request(endpoint+("/v1/queries" if query else "/v1/commands"),data=raw,headers={"Content-Type":"application/json"}),timeout=3) as response:return json.load(response)

    def summary(self,endpoint):
        raw=canonical({"schema":"service.query.v1","request_id":"summary","operation":"case.summary","resource":{"kind":"Case","id":"case-1"},"payload":{}}).encode()
        return self.post(endpoint,raw,True)["data"]

    def source_command(self,event_id):
        with sqlite3.connect(self.root/"service.db") as db:
            row=json.loads(db.execute("SELECT data_json FROM service_outbox WHERE event_id=?",(event_id,)).fetchone()[0])
        return row,hashlib.sha256(canonical(row["command"]).encode()).hexdigest()

    def test_real_cli_admission_pending_ack_loss_exact_retry_restart_and_projection_rebuild(self):
        from process_runtime_client import RuntimeClient,LocalDevAuthority,command_envelope
        policy=self.root/"admission.json";digest=self.policy(policy,False)
        with socket.socket() as sock:sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
        runtime=self.spawn([*self.runtime_argv,"--database",str(self.root/"runtime.db"),"--port",str(port),"--environment","test","--local-dev-untrusted","--admission-policy",str(policy)])
        origin="http://127.0.0.1:"+str(port)
        eventually(lambda:self.get(origin,"/live")[0]==200)
        client=RuntimeClient(origin,authority=LocalDevAuthority(environment="test"),timeout=1)
        def send(operation,rid,payload,version=None):return client.execute(command_envelope(operation,request_id=rid,expected_version=version,payload=payload))
        draft={"schema":"process.draft.v1","process_id":"worker-proof","inputs":{"location":{"kind":"string"}},"steps":[{"step_id":"inspect","depends_on":[],"capabilities":["inspect"],"resources":[],"inputs":{"location":{"kind":"string"}},"bindings":{"location":{"source":"run_input","name":"location"}},"outputs":{"finding":{"kind":"string"}},"max_attempts":2}]}
        provenance={"source_id":"service-process-test","media_type":"application/json","content_hash":"0"*64,"parser":"explicit-structured-block.v1","uncertainties":[]}
        send("process.draft.put","draft",{"draft":draft,"provenance":provenance})
        send("process.publish","publish",{"process_id":"worker-proof","draft_revision":1,"version_id":"worker-proof-v1"},1)
        pin=client.query({"schema":"runtime.query.v1","operation":"version.get","payload":{"process_version":"worker-proof-v1"}})["data"]["pin"]
        # Real HTTP proxy loses exactly one post-commit handoff acknowledgement;
        # it retains inner request digests only, never native proof or inputs.
        lost=[];handoff_digests=[];lock=threading.Lock()
        class Proxy(BaseHTTPRequestHandler):
            def log_message(inner,*args):pass
            def do_POST(inner):
                raw=inner.rfile.read(int(inner.headers["Content-Length"]))
                body=json.loads(raw)["request"]
                peer=http.client.HTTPConnection("127.0.0.1",port,timeout=2)
                try:
                    peer.request("POST",inner.path,raw,{"Content-Type":"application/json"});response=peer.getresponse();payload=response.read()
                    should_drop=False
                    if body["operation"]=="handoff.consume":
                        with lock:
                            handoff_digests.append(hashlib.sha256(canonical(body).encode()).hexdigest())
                            if response.status==200 and not lost:lost.append(True);should_drop=True
                    if should_drop:
                        inner.close_connection=True;inner.connection.shutdown(socket.SHUT_RDWR);inner.connection.close();return
                    inner.send_response(response.status);inner.send_header("Content-Type","application/json");inner.send_header("Content-Length",str(len(payload)));inner.end_headers();inner.wfile.write(payload)
                finally:peer.close()
        proxy=ThreadingHTTPServer(("127.0.0.1",0),Proxy);thread=threading.Thread(target=proxy.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(proxy.shutdown(),proxy.server_close(),thread.join(2)))
        process,endpoint=self.service("http://127.0.0.1:"+str(proxy.server_port))
        eventually(lambda:self.get(endpoint,"/ready")[0]==200)
        for raw in [command("request.create","create",payload={"summary":"Managed inspection","details":"private-intake-never-projected"}),
                    command("request.qualify","qualify",1,{"qualification":"Qualified"}),command("request.accept","accept",2,{"acceptance":"Accepted"}),
                    command("request.convert","convert",3,{"case_id":"case-1","obligation":"Inspect"}),command("case.plan","plan",1,{"scope":"Inspect"},resource_id="case-1")]:self.post(endpoint,raw)
        approval=command("case.plan.approve","approve",2,{"revision_id":"revision-1","reason":"Approved","pin":pin,"inputs":{"location":"secret-location"},"carry_forward":[]},resource_id="case-1")
        result=self.post(endpoint,approval);event_id=result["handoff"]["event_id"]
        eventually(lambda:self.summary(endpoint)["handoff"]["last_error"]=="not_ready")
        row,before=self.source_command(event_id);self.assertEqual(row["state"],"pending");self.assertGreaterEqual(row["attempts"],1)
        ready=self.get(endpoint,"/ready");self.assertEqual(ready[0],503)
        self.assertEqual(ready[1]["checks"]["outbox_delivery"]["owner"],"process-runtime")
        self.assertEqual(self.post(endpoint,approval),result)
        # Actual service restart retains source command and retries while closed.
        self.stop_clean(process);process,endpoint=self.service("http://127.0.0.1:"+str(proxy.server_port))
        eventually(lambda:self.summary(endpoint)["handoff"]["last_error"]=="not_ready")
        self.assertEqual(self.post(endpoint,approval),result)
        self.policy(policy,True,digest)
        handoff=eventually(lambda:self.summary(endpoint)["handoff"] if self.summary(endpoint)["handoff"]["state"]=="started" else None)
        self.assertEqual(len(lost),1);self.assertGreaterEqual(len(handoff_digests),3);self.assertEqual(set(handoff_digests),{before})
        row,after=self.source_command(event_id);self.assertEqual(before,after);self.assertFalse(row["uncertain"])
        run_id=handoff["run_id"]
        events=client.query({"schema":"runtime.query.v1","operation":"events.list","payload":{"after":0,"limit":100}})["data"]["events"]
        self.assertEqual(sum(event["kind"]=="handoff.accepted" and event["data"].get("source_event_id")==event_id for event in events),1)
        send("actor.register","register",{"actor_id":"inspector","capabilities":["inspect"],"resources":[]})
        claim=send("executor.claim","claim",{"run_id":run_id,"step_id":"inspect","actor_id":"inspector","lease_ms":30000},1)["result"]
        send("executor.complete","complete",{"run_id":run_id,"step_id":"inspect","attempt_id":claim["attempt_id"],"fence":claim["fence"],"outputs":{"finding":"private-output-never-projected"}},claim["step_version"])
        first=eventually(lambda:self.summary(endpoint) if (self.summary(endpoint)["derived_runtime"] or {}).get("state")=="succeeded" else None)
        self.assertEqual(first["canonical_service"]["state"],"planned")
        for secret in ("private-intake-never-projected","secret-location","private-output-never-projected"):self.assertNotIn(secret,canonical(first))
        # An actual runtime outage is diagnosed without exception/endpoint data;
        # restart uses the same runtime-owned store and preserves the known run.
        runtime.terminate();runtime.communicate(timeout=10)
        outage=eventually(lambda:self.get(endpoint,"/ready")[1] if self.get(endpoint,"/ready")[1]["checks"]["runtime_projection"].get("last_error")=="runtime_unavailable" else None)
        self.assertEqual(outage["checks"]["runtime_projection"]["owner"],"process-runtime")
        for secret in (origin,str(self.root),"secret-location","private-output-never-projected"):
            self.assertNotIn(secret,canonical(outage))
        runtime=self.spawn([*self.runtime_argv,"--database",str(self.root/"runtime.db"),"--port",str(port),"--environment","test","--local-dev-untrusted","--admission-policy",str(policy)])
        eventually(lambda:self.get(origin,"/live")[0]==200)
        eventually(lambda:self.get(endpoint,"/ready")[0]==200)
        recovered=client.query({"schema":"runtime.query.v1","operation":"run.get","payload":{"run_id":run_id}})["data"]
        self.assertEqual(recovered["state"],"succeeded");self.assertEqual(recovered["pin"],pin)
        self.assertEqual(self.source_command(event_id)[1],before)
        self.stop_clean(process)
        # Rebuild the disposable projection through bounded pages in the actual CLI.
        process,endpoint=self.service("http://127.0.0.1:"+str(proxy.server_port),rebuild=True)
        rebuilt=eventually(lambda:self.summary(endpoint) if self.summary(endpoint)["projection"]["last_rebuild"] and self.get(endpoint,"/ready")[0]==200 else None)
        self.assertEqual(rebuilt["derived_runtime"],first["derived_runtime"])
        self.assertFalse(rebuilt["projection"]["last_rebuild"]["drift_detected"])
        self.assertEqual(self.source_command(event_id)[1],before)
        self.stop_clean(process)
        # Production defaults must not attempt a native outgoing call or poison history.
        process,endpoint=self.service(origin,production=True)
        status,health=self.get(endpoint,"/ready");self.assertEqual(status,503)
        self.assertEqual(health["checks"]["runtime_authority"]["state"],"unavailable")
        self.assertEqual(health["checks"]["outbox_delivery"]["state"],"disabled")
        self.assertEqual(self.get(endpoint,"/live")[0],200)
        self.stop_clean(process)
        self.assertEqual(self.source_command(event_id)[1],before)


if __name__=="__main__":unittest.main()
