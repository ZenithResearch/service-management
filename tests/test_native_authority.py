"""Receiver policy and durable replay tests; native fixtures are synthetic only."""
import base64
import concurrent.futures
from dataclasses import asdict, replace
import hashlib
import http.client
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from service_management import Command, Service, ServiceError
from service_management.authority import AUDIENCE, ReplayScope, VerifiedCall
from service_management.contracts import canonical
from service_management.http_api import make_server
from service_management.ingress import CommandIngress
from service_management.native_authority import (Descriptor, FileReceiverPolicy, NativeSecSHelper,
    PermissionRule, ReceiverPolicy, SecSServiceAuthorityVerifier, VerifierKey, resource_for)
from service_management.queries import Query
from service_management.sqlite_store import MIGRATION_1, MIGRATION_2, SCHEMA_VERSION, SQLiteUnitOfWork
from service_management.transport import decode_http_request
from test_service import command
from test_integration import query

ROOT = Path(__file__).resolve().parents[1]


def policy(operation="request.create", resource="requests/request-1", opcode=112):
    return ReceiverPolicy(AUDIENCE, (VerifierKey("synthetic-verifier", "a"*64),),
        (Descriptor("service."+operation+".v1", opcode, "a"*64, "service-v1"),),
        (PermissionRule("synthetic-subject", "service."+operation+".v1", resource, "allow", 999000, 1100000),))


class SyntheticHelper:
    def __init__(self, action, opcode=112):
        self.context = {"schema_version": 4, "subject": {"subject_id": "synthetic-subject", "key_id": "synthetic-holder"},
            "audience": AUDIENCE, "operation": "service."+action.operation+".v1", "resource": resource_for(action),
            "descriptor_fingerprint": "a"*64, "handler_id": "service-v1", "replay_scope": "session:opcode:nonce",
            "issued_at": 1000, "expires_at": 1060, "session_id": [1]*16, "nonce": [2]*12, "opcode": opcode}
        self.inputs = []
    def verify(self, value):
        self.inputs.append(value)
        return {"schema":"process-runtime.secs-check-output.v1", "context":self.context,
                "signer_key_id":"synthetic-verifier", "authenticator_kind":"ed25519_node_and_verifier"}


EVIDENCE = canonical({"schema":"service.secs-envelope.v1", "packet_hex":"00", "signed_context_hex":"00"}).encode()


class ReceiverBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.action = Command.parse(command("request.create", "native-create", payload={"summary":"Intake"}))
        self.helper = SyntheticHelper(self.action)
        self.policy = policy()
        self.verifier = SecSServiceAuthorityVerifier(self.helper, lambda:self.policy)

    def denied(self, callback):
        with self.assertRaises(ServiceError) as raised: callback()
        self.assertEqual(raised.exception.code, "forbidden")

    def test_public_helper_protocol_carries_exact_service_bytes_without_runtime_imports(self):
        call = self.verifier.verify(self.action, EVIDENCE, 1001)
        self.assertEqual(call.replay, ReplayScope("01"*16,112,"02"*12))
        sent = self.helper.inputs[0]
        self.assertEqual(set(sent), {"schema","packet_hex","signed_context_hex","request_hex","audience","now_seconds","keys"})
        self.assertEqual(bytes.fromhex(sent["request_hex"]), canonical(self.action.as_dict()).encode())
        self.assertEqual(sent["schema"], "process-runtime.secs-check-input.v1")
        self.assertEqual(sent["audience"], AUDIENCE)

    def test_native_prefix_and_legacy_digest_bind_same_current_descriptor(self):
        for value in ("a"*64, "descriptor:sha256:"+"a"*64):
            with self.subTest(fingerprint=value):
                self.helper.context["descriptor_fingerprint"] = value
                call = self.verifier.verify(self.action,EVIDENCE,1001)
                self.assertEqual(call.command_digest,self.action.digest)
                self.assertEqual(self.helper.context["descriptor_fingerprint"],value)

    def test_native_prefix_requires_exact_current_digest_and_spelling(self):
        for value in ("descriptor:sha256:"+"b"*64,"descriptor:SHA256:"+"a"*64,
                      "descriptor:sha256:"+"A"*64,"descriptor:sha256:"+"a"*63,
                      "descriptor:sha256:"+"a"*64+" ",["a"*64],None):
            with self.subTest(fingerprint=value):
                self.helper.context["descriptor_fingerprint"] = value
                self.denied(lambda:self.verifier.verify(self.action,EVIDENCE,1001))

    def test_missing_forged_oversized_duplicate_and_caller_trust_evidence_denied(self):
        values=[None,b'Bearer matrix',EVIDENCE+b' ',b'{}',b'x'*262145,
                b'{"schema":"x","schema":"service.secs-envelope.v1"}',
                canonical({"schema":"service.secs-envelope.v1","packet_hex":"00","signed_context_hex":"00","keys":[]}).encode(),
                EVIDENCE.replace(b'service.secs-envelope',b'runtime.secs-envelope'),EVIDENCE.replace(b'"00"',b'"AA"')]
        # Trailing whitespace is valid JSON and has no authority significance.
        values.remove(EVIDENCE+b' ')
        for value in values:
            with self.subTest(value=str(value)[:80]): self.denied(lambda:self.verifier.verify(self.action,value,1001))

    def test_runtime_scope_wrong_bindings_and_malformed_native_values_denied(self):
        original=self.helper.context.copy()
        for change in ({"audience":"runtime://receiver-local"},{"operation":"runtime.run.create.v1"},
                       {"resource":"runs/request-1"},{"opcode":113},{"opcode":True},
                       {"descriptor_fingerprint":"b"*64},{"handler_id":"runtime-v1"},{"schema_version":3},
                       {"replay_scope":""},{"session_id":[True]*16},{"nonce":[1]*11},
                       {"issued_at":1002},{"expires_at":1001},{"expires_at":1061}):
            with self.subTest(change=change):
                self.helper.context={**original,**change}
                self.denied(lambda:self.verifier.verify(self.action,EVIDENCE,1001))

    def test_current_deny_revocation_changed_policy_and_policy_expiry_fail_closed(self):
        allow=self.policy
        deny=replace(allow.rules[0],effect="deny")
        for changed in (replace(allow,rules=()),replace(allow,rules=(*allow.rules,deny)),
                        replace(allow,revoked_subject_keys=frozenset({("synthetic-subject","synthetic-holder")}))):
            self.policy=changed
            self.denied(lambda:self.verifier.verify(self.action,EVIDENCE,1001))
        calls=iter([allow,replace(allow,rules=())])
        self.verifier.load_policy=lambda:next(calls)
        self.denied(lambda:self.verifier.verify(self.action,EVIDENCE,1001))
        self.policy=replace(allow,rules=(replace(allow.rules[0],not_after_ms=1001500),))
        self.verifier.load_policy=lambda:self.policy
        call=self.verifier.verify(self.action,EVIDENCE,1001)
        self.assertEqual(call.expires_at,1001.5)
        with tempfile.TemporaryDirectory() as temp:
            times=iter([1001,1002])
            service=Service(SQLiteUnitOfWork(Path(temp)/"service.db"),verifier=self.verifier,clock=lambda:next(times))
            self.denied(lambda:service.execute(canonical(self.action.as_dict()).encode(),EVIDENCE))

    def test_file_policy_closed_parse_reload_and_no_runtime_descriptors(self):
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/"policy.json"
            value={"schema":"service.receiver-policy.v1","audience":AUDIENCE,
                "keys":[asdict(key) for key in self.policy.keys],"descriptors":[asdict(d) for d in self.policy.descriptors],
                "rules":[asdict(rule) for rule in self.policy.rules],"revoked_subject_keys":[]}
            path.write_text(canonical(value))
            loader=FileReceiverPolicy(path)
            self.assertEqual(loader(),self.policy)
            value["rules"]=[];path.write_text(canonical(value));self.assertEqual(loader().rules,())
            value["descriptors"][0]["operation"]="runtime.run.create.v1";path.write_text(canonical(value))
            with self.assertRaises(ValueError):loader()
            path.write_text('{"schema":"x","schema":"service.receiver-policy.v1"}')
            with self.assertRaises(ValueError):loader()

    def test_native_helper_hash_pin_symlink_bad_output_and_closed_environment(self):
        with tempfile.TemporaryDirectory() as temp:
            executable=Path(temp)/"verifier";executable.write_bytes(b"test-helper")
            helper=NativeSecSHelper(executable,hashlib.sha256(executable.read_bytes()).hexdigest())
            result={"schema":"process-runtime.secs-check-output.v1","context":{},"signer_key_id":"x","authenticator_kind":"ed25519_node_and_verifier"}
            process=subprocess.CompletedProcess([],0,canonical(result).encode(),b"")
            with patch("service_management.native_authority.subprocess.run",return_value=process) as invoke:
                valid_input = {"schema": "process-runtime.secs-check-input.v1", "audience": AUDIENCE,
                    "packet_hex": (bytes(29) + bytes(8) + (60).to_bytes(8, "little") + (1).to_bytes(8, "little") + b"\0" + bytes(16)).hex(), "signed_context_hex": "00", "request_hex": "00", "now_seconds": 1001, "keys": []}
                self.assertEqual(helper.verify(valid_input),result)
                self.assertEqual(invoke.call_args.kwargs["env"],{})
                self.assertEqual(invoke.call_args.kwargs["timeout"],5)
            for stdout,stderr,code in ((b'{"schema":"x","schema":"x"}',b'',0),(b'{}',b'',0),(canonical(result).encode(),b'err',0),(b'{}',b'',2),(b'x'*131073,b'',0)):
                with patch("service_management.native_authority.subprocess.run",return_value=subprocess.CompletedProcess([],code,stdout,stderr)):
                    self.denied(lambda:helper.verify({}))
            executable.write_bytes(b"changed");self.denied(lambda:helper.verify({}))
            link=Path(temp)/"link";link.symlink_to(executable)
            self.denied(lambda:NativeSecSHelper(link,hashlib.sha256(executable.read_bytes()).hexdigest()).verify({}))

    def test_transport_is_additive_closed_and_large_evidence_cannot_override_header(self):
        raw=canonical(self.action.as_dict()).encode()
        self.assertEqual(decode_http_request(raw,None),(raw,None))
        wrapper={"schema":"service.transport.v1","request":self.action.as_dict(),"authority_base64":base64.b64encode(EVIDENCE).decode()}
        self.assertEqual(decode_http_request(canonical(wrapper).encode(),None),(raw,EVIDENCE))
        for value,header in ((wrapper,EVIDENCE),({**wrapper,"actor":"matrix"},None),({**wrapper,"authority_base64":"!"},None)):
            with self.assertRaises(ServiceError):decode_http_request(canonical(value).encode(),header)


class ReplayPersistenceTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.path=Path(self.temp.name)/"service.db"
        self.store=SQLiteUnitOfWork(self.path)
        self.allowed=True
        class Verifier:
            def verify(inner,action,evidence,now):
                if not self.allowed:raise ServiceError("forbidden")
                return VerifiedCall("subject",AUDIENCE,action.digest,1060,"verified_call",ReplayScope("01"*16,112,"02"*12))
        self.verifier=Verifier()
        self.service=Service(self.store,verifier=self.verifier,clock=lambda:1001)
        self.raw=command("request.create","create",payload={"summary":"Intake"})

    def test_exact_command_retry_restart_and_revocation_before_saved_disclosure(self):
        result=self.service.execute(self.raw)
        restarted=Service(SQLiteUnitOfWork(self.path),verifier=self.verifier,clock=lambda:1001)
        self.assertEqual(restarted.execute(self.raw),result)
        self.allowed=False
        with self.assertRaises(ServiceError):restarted.execute(self.raw)
        with sqlite3.connect(self.path) as db:self.assertEqual(db.execute("SELECT count(*) FROM authority_replays").fetchone()[0],1)

    def test_concurrent_signed_nonce_reuse_for_different_intent_has_one_winner(self):
        barrier=threading.Barrier(2)
        raws=[self.raw,command("request.create","different",payload={"summary":"Other"},resource_id="request-2")]
        def run(raw):
            service=Service(SQLiteUnitOfWork(self.path),verifier=self.verifier,clock=lambda:1001)
            barrier.wait()
            try:return service.execute(raw)["service_request"]["id"]
            except ServiceError as error:return error.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:results=list(pool.map(run,raws))
        self.assertEqual(results.count("forbidden"),1)
        with sqlite3.connect(self.path) as db:
            for table in ("authority_replays","service_requests","command_results","audit_events"):
                self.assertEqual(db.execute("SELECT count(*) FROM "+table).fetchone()[0],1,table)

    def test_query_replay_consumed_atomically_and_failed_mutation_does_not_consume(self):
        def fail(tx):
            tx.admit_replay("subject","01"*16,112,"02"*12,"a"*64)
            raise RuntimeError("crash fixture")
        with self.assertRaises(RuntimeError):self.store.transact(fail)
        self.service.execute(self.raw)
        # A distinct query opcode cannot collide with the committed mutation.
        class QueryVerifier:
            def verify(inner,action,evidence,now):
                return VerifiedCall("subject",AUDIENCE,action.digest,1060,"verified_call",ReplayScope("01"*16,128,"02"*12))
        service=Service(self.store,verifier=QueryVerifier(),clock=lambda:1001)
        raw=query("request.execution","request-1")
        self.assertEqual(service.query(raw)["data"]["request_id"],"request-1")
        with self.assertRaises(ServiceError) as raised:service.query(raw)
        self.assertEqual(raised.exception.code,"forbidden")

    def test_process_death_rolls_back_nonce_with_state_and_result(self):
        code = """
import os,sys
from service_management.sqlite_store import SQLiteUnitOfWork
from service_management.domain import ServiceRequest
store=SQLiteUnitOfWork(sys.argv[1])
def fail(tx):
    tx.admit_replay('subject','01'*16,112,'02'*12,'a'*64)
    tx.insert_request(ServiceRequest('request-1','Crash fixture','','intake',1,'time','time'))
    tx.save_result('subject','create','a'*64,{'schema':'service.result.v1','request_id':'create'})
    os._exit(91)
store.transact(fail)
"""
        process=subprocess.run([sys.executable,"-c",code,str(self.path)],env=dict(os.environ),capture_output=True,text=True,timeout=10)
        self.assertEqual(process.returncode,91,process.stderr)
        restarted=Service(SQLiteUnitOfWork(self.path),verifier=self.verifier,clock=lambda:1001)
        result=restarted.execute(self.raw)
        self.assertEqual(result["service_request"]["summary"],"Intake")
        with sqlite3.connect(self.path) as db:
            self.assertEqual(db.execute("SELECT count(*) FROM authority_replays").fetchone()[0],1)
            self.assertEqual(db.execute("SELECT count(*) FROM command_results").fetchone()[0],1)

    def test_plan_external_preparation_checks_twice_but_commits_one_nonce(self):
        from service_management.authority import LocalDevUntrustedVerifier
        from test_integration import FakeRuntime
        runtime=FakeRuntime();pin=runtime.publish("native-plan-v1",{"location":{"kind":"string"}})
        seed=Service(self.store,verifier=LocalDevUntrustedVerifier(),environment="test",allow_local_dev_untrusted=True)
        for raw in [self.raw,command("request.qualify","qualify",1,{"qualification":"Qualified"}),
                    command("request.accept","accept",2,{"acceptance":"Accepted"}),
                    command("request.convert","convert",3,{"case_id":"case-1","obligation":"Inspect"}),
                    command("case.plan","plan",1,{"scope":"Inspect"},resource_id="case-1")]:seed.execute(raw)
        calls=[]
        class PlanVerifier:
            def verify(inner,action,evidence,now):
                calls.append(action.digest)
                return VerifiedCall("subject",AUDIENCE,action.digest,1060,"verified_call",ReplayScope("01"*16,120,"02"*12))
        service=Service(self.store,verifier=PlanVerifier(),runtime=runtime,clock=lambda:1001)
        raw=command("case.plan.approve","approve",2,{"revision_id":"native-revision","reason":"Approved","pin":pin,"inputs":{"location":"onsite"},"carry_forward":[]},resource_id="case-1")
        first=service.execute(raw)
        self.assertEqual(len(calls),2)
        with sqlite3.connect(self.path) as db:self.assertEqual(db.execute("SELECT count(*) FROM authority_replays").fetchone()[0],1)
        self.assertEqual(service.execute(raw),first)
        with sqlite3.connect(self.path) as db:self.assertEqual(db.execute("SELECT count(*) FROM authority_replays").fetchone()[0],1)

    def test_v2_migration_preserves_saved_result_and_canonical_history(self):
        path=Path(self.temp.name)/"v2.db"
        with sqlite3.connect(path) as db:
            for sql in (*MIGRATION_1,*MIGRATION_2):db.execute(sql)
            db.execute("PRAGMA user_version=2")
            db.execute("INSERT INTO command_results VALUES(?,?,?,?)",("subject","historical","a"*64,'{"schema":"service.result.v1","request_id":"historical"}'))
            db.execute("INSERT INTO audit_events(event_id,resource_kind,resource_id,event_json) VALUES(?,?,?,?)",("old-event","ServiceRequest","old-request",'{"retained":true}'))
        migrated=SQLiteUnitOfWork(path)
        self.assertEqual(migrated.transact(lambda tx:tx.find_result("subject","historical")),("a"*64,{"schema":"service.result.v1","request_id":"historical"}))
        self.assertEqual(migrated.audit_history("ServiceRequest","old-request")[0]["event"],{"retained":True})
        with sqlite3.connect(path) as db:self.assertEqual(db.execute("PRAGMA user_version").fetchone()[0],SCHEMA_VERSION)


@unittest.skipUnless(os.environ.get("SERVICE_NATIVE_VERIFIER"),"set SERVICE_NATIVE_VERIFIER for pinned native synthetic receiver verification")
class NativeReceiverIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        data=json.loads((ROOT/"tests/fixtures/native-secs-v4.json").read_text())
        self.fixtures={item["name"]:item for item in data["fixtures"]}
        executable=Path(os.environ["SERVICE_NATIVE_VERIFIER"])
        self.helper=NativeSecSHelper(executable,hashlib.sha256(executable.read_bytes()).hexdigest())
        self.policy=ReceiverPolicy(AUDIENCE,(VerifierKey("synthetic-verifier",self.fixtures["create"]["public_key_hex"]),),
            (Descriptor("service.request.create.v1",112,"a"*64,"service-v1"),Descriptor("service.request.execution.v1",128,"a"*64,"service-v1")),
            (PermissionRule("synthetic-subject","service.request.create.v1","requests/","allow",999000,1100000,"prefix"),
             PermissionRule("synthetic-subject","service.request.execution.v1","requests/native-request","allow",999000,1100000)))
        self.verifier=SecSServiceAuthorityVerifier(self.helper,lambda:self.policy)
        self.store=SQLiteUnitOfWork(Path(self.temp.name)/"service.db")
        self.service=Service(self.store,verifier=self.verifier,clock=lambda:1001)

    def raw(self,name):return self.fixtures[name]["request"].encode()
    def evidence(self,name):
        return canonical({**self.fixtures[name]["envelope"],"schema":"service.secs-envelope.v1"}).encode()
    def denied(self,callback):
        with self.assertRaises(ServiceError) as raised:callback()
        self.assertEqual(raised.exception.code,"forbidden")

    def test_actual_native_signature_service_request_and_query_with_restart_replay(self):
        result=self.service.execute(self.raw("create"),self.evidence("create"))
        self.assertEqual(result["authority"],{"subject":"synthetic-subject","mode":"verified_call"})
        restarted=Service(SQLiteUnitOfWork(self.store.database),verifier=self.verifier,clock=lambda:1001)
        self.assertEqual(restarted.execute(self.raw("create"),self.evidence("create")),result)
        self.denied(lambda:restarted.execute(self.raw("second"),self.evidence("second")))
        self.assertEqual(self.service.query(self.raw("query"),self.evidence("query"))["data"]["request_id"],"native-request")
        self.denied(lambda:self.service.query(self.raw("query"),self.evidence("query")))
        self.policy=replace(self.policy,revoked_subject_keys=frozenset({("synthetic-subject","synthetic-holder")}))
        self.denied(lambda:restarted.execute(self.raw("create"),self.evidence("create")))

    def test_actual_signed_runtime_operation_resource_wrong_opcode_and_tampering_deny(self):
        for name in ("wrong-operation","wrong-resource","wrong-opcode"):
            with self.subTest(name=name):self.denied(lambda:self.service.execute(self.raw(name),self.evidence(name)))
        self.denied(lambda:self.service.execute(self.raw("changed"),self.evidence("create")))
        for field in ("packet_hex","signed_context_hex"):
            value=json.loads(self.evidence("create"));value[field]=value[field][:-2]+("00" if value[field][-2:]!="00" else "01")
            self.denied(lambda:self.service.execute(self.raw("create"),canonical(value).encode()))
        self.policy=replace(self.policy,keys=(replace(self.policy.keys[0],status="revoked"),))
        self.denied(lambda:self.service.execute(self.raw("create"),self.evidence("create")))
        self.assertIsNone(self.store.transact(lambda tx:tx.get_request("native-request")))

    def test_real_http_transport_supports_large_native_packet_without_header_limit(self):
        server=make_server(CommandIngress(self.service));thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        self.addCleanup(lambda:(server.shutdown(),server.server_close(),thread.join(2)))
        evidence=self.evidence("large");self.assertGreater(len(evidence),16384)
        wrapper={"schema":"service.transport.v1","request":json.loads(self.raw("large")),"authority_base64":base64.b64encode(evidence).decode()}
        connection=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=5);self.addCleanup(connection.close)
        connection.request("POST","/v1/commands",canonical(wrapper),{"Content-Type":"application/json"})
        response=connection.getresponse();body=json.loads(response.read())
        self.assertEqual(response.status,200,body)
        self.assertEqual(body["service_request"]["id"],"native-large")
        self.assertFalse(self.service.readiness()["ready"],"synthetic fixtures cannot qualify production readiness")

    def test_verifier_key_revocation_during_native_latency_rolls_back_every_write(self):
        self.policy=replace(self.policy,keys=(replace(self.policy.keys[0],revoked_at=1002),))
        times=iter([1001,1002])
        delayed=Service(self.store,verifier=self.verifier,clock=lambda:next(times))
        with self.assertRaises(ServiceError) as error:
            delayed.execute(self.raw("create"),self.evidence("create"))
        self.assertEqual(error.exception.code,"forbidden")
        with sqlite3.connect(self.store.database) as db:
            for table in ("service_requests","authority_replays","command_results","audit_events"):
                self.assertEqual(db.execute("SELECT count(*) FROM "+table).fetchone()[0],0,table)
        # The denied transaction did not consume the exact signed request. Its
        # legitimate pre-revocation retry still succeeds without new evidence.
        self.assertEqual(self.service.execute(self.raw("create"),self.evidence("create"))["service_request"]["id"],"native-request")

    def test_installed_cli_native_flags_and_policy_start_with_fail_closed_readiness(self):
        value={"schema":"service.receiver-policy.v1","audience":AUDIENCE,"keys":[asdict(k) for k in self.policy.keys],
               "descriptors":[asdict(d) for d in self.policy.descriptors],"rules":[asdict(r) for r in self.policy.rules],"revoked_subject_keys":[]}
        path=Path(self.temp.name)/"policy.json";path.write_text(canonical(value))
        argv=[sys.executable,"-m","service_management","--database",str(Path(self.temp.name)/"cli.db"),"--port","0",
              "--native-verifier",str(self.helper.executable),"--native-verifier-sha256",self.helper.sha256,"--receiver-policy",str(path)]
        process=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        def stop():
            if process.poll() is None:process.terminate()
            process.communicate(timeout=5)
        self.addCleanup(stop)
        import select
        self.assertTrue(select.select([process.stdout],[],[],10)[0],"CLI did not start")
        startup=process.stdout.readline();self.assertIn("native_receiver_unqualified",startup)
        port=int(startup.split("127.0.0.1:")[1].split(";")[0])
        connection=http.client.HTTPConnection("127.0.0.1",port,timeout=5);self.addCleanup(connection.close)
        connection.request("GET","/ready");response=connection.getresponse();body=json.loads(response.read())
        self.assertEqual(response.status,503);self.assertEqual(body["checks"]["authority"],"unqualified")
        connection.request("POST","/v1/commands",self.raw("create"),{"Content-Type":"application/json"})
        response=connection.getresponse();self.assertEqual(response.status,403);response.read()


if __name__ == "__main__":unittest.main()
