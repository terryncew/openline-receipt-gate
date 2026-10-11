import base64, hashlib, hmac, http.client, json, pathlib, sys, tempfile, threading, time
sys.path.insert(0,'/workspace/openline-receipt-gate/gateway/receiver-package')
from openline_receiver.lithic_adapter import SecureLithicAdapter
from openline_receiver.lithic_server import PilotHTTPServer
key=bytes(range(32)); secret='whsec_'+base64.b64encode(key).decode()
body=pathlib.Path('/workspace/openline-receipt-gate/gateway/receiver-package/fixtures/official-asa-request.json').read_bytes()
def headers(timestamp=None):
 stamp=str(int(time.time()) if timestamp is None else timestamp)
 digest=base64.b64encode(hmac.new(key,b'msg_http_audit.'+stamp.encode()+b'.'+body,hashlib.sha256).digest()).decode()
 return [('webhook-id','msg_http_audit'),('webhook-timestamp',stamp),('webhook-signature','v1,'+digest)]
with tempfile.TemporaryDirectory() as directory:
 try: SecureLithicAdapter(pathlib.Path(directory)/'missing-secret.sqlite',initialize=True)
 except ValueError: pass
 else: raise AssertionError('Sandbox accepted missing secret')
 adapter=SecureLithicAdapter(pathlib.Path(directory)/'state.sqlite', signing_secrets=secret, initialize=True)
 server=PilotHTTPServer(('127.0.0.1',0),adapter); thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
 cases=[('valid-auth-no-pending',headers(),body,[],200),('missing-headers',[],body,[],401),('duplicate-identical-id',headers()+[('webhook-id','msg_http_audit')],body,[],401),('duplicate-signature',headers()+[('webhook-signature','v1,AAAA')],body,[],401),('wrong-signature',[(k,'v1,AAAA' if k=='webhook-signature' else v) for k,v in headers()],body,[],401),('tampered-body',headers(),body.replace(b'100',b'101'),[],401),('expired-timestamp',headers(int(time.time())-301),body,[],401),('duplicate-length',headers(),body,[('Content-Length',str(len(body)))],400),('transfer-encoding',headers(),body,[('Transfer-Encoding','chunked')],400)]
 results=[]
 for name,signed,payload,extra,expected in cases:
  client=http.client.HTTPConnection(*server.server_address,timeout=5); start=time.perf_counter();client.putrequest('POST','/asa');client.putheader('Content-Length',str(len(payload)))
  for k,v in signed+extra: client.putheader(k,v)
  client.endheaders(payload); response=client.getresponse(); data=response.read(); elapsed=time.perf_counter()-start;client.close()
  assert response.status==expected,(name,response.status,data)
  if response.status==200: assert json.loads(data)=={'result':'CARD_PAUSED'},data
  assert elapsed<6,(name,elapsed)
  results.append({'case':name,'status':response.status,'elapsed_seconds':elapsed})
 assert adapter.db.execute('SELECT COUNT(*) FROM decisions').fetchone()[0]==1
 server.shutdown();server.server_close();thread.join();adapter.close()
 pathlib.Path('/workspace/lithic-preflight-scratch/hmac-http-audit.json').write_text(json.dumps({'result':'PASS','sandbox_missing_secret_rejected':True,'committed_decisions':1,'cases':results},indent=2)+'\n')
 print(json.dumps({'result':'PASS','cases':len(results),'max_seconds':max(x['elapsed_seconds'] for x in results),'committed_decisions':1}))
