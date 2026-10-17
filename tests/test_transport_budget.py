"""Service transport size/framing evidence; inert buffers do not assert authority."""
import base64
import hashlib
import io
import json
import struct
import subprocess
import tempfile
import threading
import unittest
from email.message import Message
from pathlib import Path
from unittest.mock import patch

from service_management.contracts import Command, MAX_BODY, canonical
from service_management.queries import Query
from service_management.errors import ServiceError
from service_management.http_api import BODY_READ_CHUNK, handler_for
from service_management.native_authority import (AUDIENCE, MAX_AUTHORITY_BYTES, MAX_HELPER_INPUT_BYTES,
    MAX_NATIVE_PACKET_BYTES, MAX_NATIVE_PROOF_BYTES, MAX_RECEIVER_POLICY_BYTES, MAX_SIGNED_CONTEXT_BYTES,
    FileReceiverPolicy, NativeSecSHelper, _bounded_helper_input, _object)
from service_management.transport import MAX_TRANSPORT_BODY, decode_http_request, transport_schema

def encoded(value): return canonical(value).encode()
def command(text=''):
    return {'schema':'service.command.v1','request_id':'budget-command','operation':'case.plan.approve',
        'resource':{'kind':'Case','id':'budget-case'},'expected_version':1,
        'payload':{'revision_id':'budget-revision','reason':'Budget vectors',
            'pin':{'process_id':'budget-process','process_version':'v1','compilation_hash':'a'*64},
            'inputs':{'value':text},'carry_forward':[]}}
def maximum(pattern):
    lo,hi=0,MAX_BODY
    while lo<hi:
        n=(lo+hi+1)//2
        if len(encoded(command(pattern*n)))<=MAX_BODY:lo=n
        else:hi=n-1
    text=pattern*lo
    return encoded(command(text+'a'*(MAX_BODY-len(encoded(command(text))))))
def packet(raw,proof=MAX_NATIVE_PROOF_BYTES):
    return bytes(29)+struct.pack('<Q',proof)+bytes(proof)+struct.pack('<Q',60)+struct.pack('<Q',len(raw))+raw+bytes(16)
def authority(raw):
    return encoded({'schema':'service.secs-envelope.v1','packet_hex':packet(raw).hex(),
        'signed_context_hex':bytes(MAX_SIGNED_CONTEXT_BYTES).hex()})
def transport(value,evidence,ascii=False):
    value={'schema':'service.transport.v1','request':value,'authority_base64':base64.b64encode(evidence).decode()}
    return json.dumps(value,ensure_ascii=True,sort_keys=True,separators=(',',':'),allow_nan=False).encode() if ascii else encoded(value)
def helper_input(raw):
    return {'schema':'process-runtime.secs-check-input.v1','audience':AUDIENCE,'now_seconds':1001,
        'packet_hex':packet(raw).hex(),'signed_context_hex':bytes(MAX_SIGNED_CONTEXT_BYTES).hex(),
        'request_hex':raw.hex(),'keys':[{'key_id':'synthetic','public_key_hex':'a'*64,'status':'active',
            'production_authority':True,'not_before':None,'not_after':None,'revoked_at':None}]}
class Connection:
    def __init__(self):self.timeouts=[]
    def settimeout(self,value):self.timeouts.append(value)
class RecordingStream(io.BytesIO):
    def __init__(self,raw):super().__init__(raw);self.sizes=[]
    def read1(self,size=-1):self.sizes.append(size);return super().read1(size)
class CaptureIngress:
    def __init__(self):self.calls=[]
    def submit(self,raw,*,authority_evidence=None):
        Command.parse(raw);self.calls.append((raw,authority_evidence));return {'capture_only':True}
    def query(self,raw,*,authority_evidence=None):
        Query.parse(raw);self.calls.append((raw,authority_evidence));return {'capture_only':True}
def handler(cls,raw,path='/v1/commands',headers=None,stream=None):
    h=object.__new__(cls);h.path=path;h.headers=Message();h.headers['Content-Type']='application/json';h.headers['Content-Length']=str(len(raw))
    for key,value in (headers or {}).items():h.headers[key]=value
    h.connection=Connection();h.rfile=stream or RecordingStream(raw);h.replies=[]
    h._reply=lambda status,value:h.replies.append((status,value))
    return h

class ServiceTransportBudgetTests(unittest.TestCase):
    def denied(self,fn,code='invalid_command'):
        with self.assertRaises(ServiceError) as e:fn()
        self.assertEqual(e.exception.code,code)

    def test_nine_full_public_requests_roundtrip_both_producer_forms(self):
        patterns=('a','\x7f','é','漢','😀','"','\\','\x01\n\t\r','a\x7fé漢😀"\\\x01\n ')
        self.assertEqual(MAX_AUTHORITY_BYTES,295127);self.assertEqual(MAX_NATIVE_PACKET_BYTES,81989)
        self.assertEqual(MAX_TRANSPORT_BODY,786786)
        for pattern in patterns:
            with self.subTest(pattern=repr(pattern)):
                raw=maximum(pattern);action=Command.parse(raw);self.assertEqual(len(raw),MAX_BODY)
                self.assertEqual(encoded(action.as_dict()),raw);evidence=authority(raw)
                self.assertEqual(len(evidence),MAX_AUTHORITY_BYTES);self.assertEqual(_object(evidence)['schema'],'service.secs-envelope.v1')
                self.assertLessEqual(len(_bounded_helper_input(helper_input(raw))),MAX_HELPER_INPUT_BYTES)
                for ascii in (False,True):
                    outer=transport(action.as_dict(),evidence,ascii)
                    self.assertLessEqual(len(outer),MAX_TRANSPORT_BODY)
                    self.assertEqual(decode_http_request(outer,None),(raw,evidence))
                    ingress=CaptureIngress();h=handler(handler_for(ingress),outer);h.do_POST()
                    self.assertEqual(h.replies[0][0],200);self.assertEqual(ingress.calls,[(raw,evidence)])
                    self.assertLessEqual(max(h.rfile.sizes),BODY_READ_CHUNK)
                self.denied(lambda:Command.parse(raw+b' '),'invalid_json')

    def test_actual_queries_and_public_numeric_control_profile(self):
        for op,kind,payload in [('request.execution','ServiceRequest',{}),('case.summary','Case',{}),
            ('case.plan-history','Case',{'after_revision':int('9'*4300),'limit':100})]:
            value={'schema':'service.query.v1','request_id':'q'*128,'operation':op,'resource':{'kind':kind,'id':'c'*128},'payload':payload}
            raw=encoded(value);self.assertEqual(encoded(Query.parse(raw).as_dict()),raw)
            evidence=authority(raw);outer=transport(value,evidence,True)
            self.assertEqual(decode_http_request(outer,None),(raw,evidence))
            h=handler(handler_for(CaptureIngress()),outer,'/v1/queries');h.do_POST();self.assertEqual(h.replies[0][0],200)
            padded=raw+b' '*(MAX_BODY-len(raw));Query.parse(padded)
            self.denied(lambda:Query.parse(padded+b' '),'invalid_json')
            self.denied(lambda:Query.parse(encoded({**value,'payload':{'value':'é'}})))
        Command.parse(encoded(command('\x7f\x01\n"\\é😀')))
        self.denied(lambda:Command.parse(encoded(command('\0'))))
        finite=encoded(command('TOKEN')).replace(b'"TOKEN"',b'1.234567890123456789')
        self.assertNotEqual(encoded(Command.parse(finite).as_dict()),finite)
        self.denied(lambda:Command.parse(encoded(command('TOKEN')).replace(b'"TOKEN"',b'1e309')))

    def test_outer_authority_base64_and_header_adjacent_bounds(self):
        value=command();small=transport(value,b'x')
        at_max=small+b' '*(MAX_TRANSPORT_BODY-len(small))
        self.assertEqual(decode_http_request(at_max,None)[0],encoded(value))
        self.denied(lambda:decode_http_request(at_max+b' ',None),'invalid_json')
        self.denied(lambda:decode_http_request(transport(value,b'x'*(MAX_AUTHORITY_BYTES+1)),None))
        for text in ('','!','eA==='):
            self.denied(lambda:decode_http_request(encoded({'schema':'service.transport.v1','request':value,'authority_base64':text}),None))
        self.denied(lambda:decode_http_request(small,b'header'))
        h=handler(handler_for(CaptureIngress()),small,headers={'X-Service-Authority':'x'*16385});h.do_POST();self.assertEqual(h.replies[0][0],403)
        self.assertEqual(transport_schema()['properties']['authority_base64']['maxLength'],393504)
        self.assertEqual(MAX_RECEIVER_POLICY_BYTES,262144)

    def test_prelaunch_packet_proof_context_request_metadata_and_unknown_fields(self):
        raw=maximum('a');good=helper_input(raw)
        with tempfile.TemporaryDirectory() as temp:
            executable=Path(temp)/'inert-artifact';executable.write_bytes(b'inert')
            helper=NativeSecSHelper(executable,hashlib.sha256(executable.read_bytes()).hexdigest())
            output={'schema':'process-runtime.secs-check-output.v1','context':{},'signer_key_id':'synthetic','authenticator_kind':'ed25519_node_and_verifier'}
            completed=subprocess.CompletedProcess([],0,encoded(output),b'')
            with patch('service_management.native_authority.subprocess.run',return_value=completed) as run:
                self.assertEqual(helper.verify(good),output)
                self.assertEqual(run.call_args.kwargs['input'],encoded(good));self.assertEqual(run.call_args.kwargs['env'],{})
            bad=[{**good,'packet_hex':good['packet_hex']+'00'},
                 {**good,'signed_context_hex':good['signed_context_hex']+'00'},
                 {**good,'request_hex':good['request_hex']+'00'},
                 {**good,'packet_hex':packet(b'x',MAX_NATIVE_PROOF_BYTES+1).hex()},
                 {**good,'packet_hex':bytes(68).hex()},
                 {**good,'packet_hex':(bytes(29)+struct.pack('<Q',2**64-1)+bytes(32)).hex()},
                 {**good,'keys':[{'key_id':'k'*65536}]},{**good,'unknown':'x'},
                 {**good,'audience':'runtime://receiver-local'}]
            for value in bad:
                with self.subTest(fields=list(value)):
                    with patch('service_management.native_authority.subprocess.run') as run:
                        self.denied(lambda:helper.verify(value),'forbidden');run.assert_not_called()
            for n,accepted in ((131072,True),(131073,False)):
                empty={**output,'context':{'padding':''}};response=encoded({**output,'context':{'padding':'a'*(n-len(encoded(empty)))}})
                with patch('service_management.native_authority.subprocess.run',return_value=subprocess.CompletedProcess([],0,response,b'')):
                    if accepted:self.assertEqual(helper.verify(good)['schema'],output['schema'])
                    else:self.denied(lambda:helper.verify(good),'forbidden')

    def test_per_server_two_body_admissions_and_release_after_handler_failure(self):
        started=[threading.Event(),threading.Event()];release=threading.Event();counter=[0];lock=threading.Lock()
        class Blocking(CaptureIngress):
            def submit(self,raw,*,authority_evidence=None):
                with lock:i=counter[0];counter[0]+=1
                started[i].set();release.wait(3);return super().submit(raw,authority_evidence=authority_evidence)
        cls=handler_for(Blocking());raw=encoded(command());first=[handler(cls,raw),handler(cls,raw)]
        threads=[threading.Thread(target=h.do_POST) for h in first]
        try:
            for t in threads:t.start()
            self.assertTrue(all(e.wait(2) for e in started));third=handler(cls,raw);third.do_POST()
            self.assertEqual(third.replies[0][0],503)
            independent=handler(handler_for(CaptureIngress()),raw);independent.do_POST();self.assertEqual(independent.replies[0][0],200)
        finally:
            release.set()
            for t in threads:t.join(3)
        self.assertTrue(all(not t.is_alive() for t in threads))
        class Broken(CaptureIngress):
            def submit(self,*args,**kwargs):raise RuntimeError('capture failure')
        broken=handler_for(Broken())
        for _ in range(3):
            h=handler(broken,raw);h.do_POST();self.assertEqual(h.replies[0][0],500)

    def test_final_complete_read_crossing_deadline_denies_before_ingress(self):
        raw=encoded(command());ingress=CaptureIngress();cls=handler_for(ingress);clock=[0.0]
        class LateFinal(RecordingStream):
            def read1(self,size=-1):
                data=super().read1(size);clock[0]=5.001;return data
        with patch('service_management.http_api.time.monotonic',side_effect=lambda:clock[0]):
            late=handler(cls,raw,stream=LateFinal(raw));late.do_POST()
            self.assertEqual(late.replies[0][0],400);self.assertEqual(ingress.calls,[])
            self.assertEqual(late.connection.timeouts[-1],5)
        for _ in range(3):
            fresh=handler(cls,raw);fresh.do_POST();self.assertEqual(fresh.replies[0][0],200)

    def test_policy_file_limit_remains_historical_and_separate(self):
        value={'schema':'service.receiver-policy.v1','audience':AUDIENCE,
            'keys':[{'key_id':'synthetic','public_key_hex':'a'*64}],
            'descriptors':[{'operation':'service.case.plan.approve.v1','opcode':118,'fingerprint':'a'*64,'handler_id':'service-v1'}],
            'rules':[],'revoked_subject_keys':[]}
        raw=encoded(value)
        with tempfile.TemporaryDirectory() as temp:
            path=Path(temp)/'synthetic-policy.json';loader=FileReceiverPolicy(path)
            path.write_bytes(raw+b' '*(MAX_RECEIVER_POLICY_BYTES-len(raw)))
            self.assertEqual(loader().audience,AUDIENCE)
            path.write_bytes(raw+b' '*(MAX_RECEIVER_POLICY_BYTES+1-len(raw)))
            with self.assertRaises(ValueError):loader()

    def test_absolute_deadline_and_parse_timeout_eof_release(self):
        raw=encoded(command());cls=handler_for(CaptureIngress());clock=[0.0]
        class Slow(io.BytesIO):
            def read1(self,size=-1):clock[0]+=0.6;return super().read1(1)
        with patch('service_management.http_api.time.monotonic',side_effect=lambda:clock[0]):
            slow=handler(cls,raw,stream=Slow(raw));slow.do_POST();self.assertEqual(slow.replies[0][0],400)
            self.assertEqual(slow.connection.timeouts[-1],5)
        for _ in range(3):
            bad=handler(cls,b'{');bad.do_POST();self.assertEqual(bad.replies[0][0],400)
            eof=handler(cls,raw,stream=io.BytesIO(b''));eof.do_POST();self.assertEqual(eof.replies[0][0],400)
            good=handler(cls,raw);good.do_POST();self.assertEqual(good.replies[0][0],200)

if __name__=='__main__':unittest.main()
