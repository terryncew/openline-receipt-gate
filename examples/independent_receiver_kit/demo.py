"""Run both independent receiver processes using only offline public fixtures."""
import argparse
from contextlib import contextmanager
import json
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

from .fixtures import fixture,call,T0
from .receiver import canonical

HERE=Path(__file__).resolve().parent
REPO=HERE.parents[1]


@contextmanager
def running(root,mode,at):
    command=[sys.executable,str(HERE/'receiver.py'),'--state',str(root/'state.sqlite3'),
        '--config',str(root/'config.json'),'--key',str(root/'receiver-test-key.txt'),
        '--mode',mode,'--fixture-clock',str(at)]
    log=(root/'server.stderr').open('a')
    started=time.perf_counter()
    p=subprocess.Popen(command,cwd=REPO,stdout=subprocess.PIPE,stderr=log,text=True)
    try:
        line=p.stdout.readline()
        if not line:raise RuntimeError('receiver_failed_to_start')
        port=json.loads(line)['port']
        yield port,time.perf_counter()-started
    finally:
        p.terminate();p.wait(timeout=10);log.close()


def post(port,path,request):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    req=urllib.request.Request(f'http://127.0.0.1:{port}'+path,canonical(request).encode(),{'Content-Type':'application/json'})
    with opener.open(req,timeout=10) as response:return json.load(response)


def run(output):
    output=Path(output);output.mkdir(parents=True,exist_ok=False)
    results={}
    for mode in ('openline','conventional'):
        root=output/mode;root.mkdir()
        f=fixture(mode)
        (root/'config.json').write_text(canonical(f['config']))
        # Public receiver-only TEST key. The server is never handed owner/worker secrets.
        (root/'receiver-test-key.txt').write_text('74'*32)
        observed=[];start=time.perf_counter();boots=[]
        with running(root,mode,T0) as (port,boot):
            boots.append(boot)
            observed.append(post(port,'/authority',f['events'][0]))
            observed.append(post(port,'/submit',{'proof':call(f,mode,nonce='provider-a',record_id='doc-a')}))
        with running(root,mode,T0+10) as (port,boot):
            boots.append(boot)
            observed.append(post(port,'/authority',f['events'][1]))
            observed.append(post(port,'/submit',{'proof':call(f,mode,at=T0+10,nonce='a-after-stop',record_id='forbidden-a')}))
        with running(root,mode,T0+20) as (port,boot):
            boots.append(boot)
            observed.append(post(port,'/authority',f['events'][2]))
            observed.append(post(port,'/submit',{'proof':call(f,mode,worker='b',at=T0+20,nonce='provider-b',record_id='doc-b')}))
            observed.append(post(port,'/submit',{'proof':call(f,mode,at=T0+20,nonce='a-after-b',record_id='forbidden-a2')}))
        expected=['ACCEPT','ALLOW','ACCEPT','DENY','ACCEPT','ALLOW','DENY']
        actual=[d['verdict'] for d in observed]
        if actual!=expected:raise AssertionError((mode,actual,expected))
        (root/'decisions.json').write_text(json.dumps(observed,indent=2)+'\n')
        command=[sys.executable,'-m','examples.independent_receiver_kit.verify','--state',str(root/'state.sqlite3'),
                 '--config',str(root/'config.json'),'--mode',mode]
        verification=subprocess.run(command,cwd=REPO,text=True,capture_output=True)
        (root/'verification.json').write_text(verification.stdout)
        (root/'verification.stderr').write_text(verification.stderr)
        if verification.returncode:raise RuntimeError(verification.stdout+verification.stderr)
        results[mode]=dict(scenarios=actual,provider_labels_are_simulated=True,receiver_process_boots=3,
            startup_seconds=boots,total_seconds=time.perf_counter()-start,verifier_exit=verification.returncode)
    (output/'summary.json').write_text(json.dumps(results,indent=2)+'\n')
    print(json.dumps(results,indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',type=Path,required=True)
    run(parser.parse_args().output)
