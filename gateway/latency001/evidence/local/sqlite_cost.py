import json, sqlite3, time, os, statistics
from pathlib import Path
import tempfile

def pct(x,p):
    x=sorted(x); k=(len(x)-1)*p; f=int(k); c=min(f+1,len(x)-1)
    return x[f]+(x[c]-x[f])*(k-f)
def summarize(x):
    return {'n':len(x),'p50_ms':pct(x,.5),'p95_ms':pct(x,.95),'p99_ms':pct(x,.99),'mean_ms':statistics.mean(x)}
results=[]
for parent in (Path('/workspace/gateway-latency-scratch'),Path('/tmp')):
  with tempfile.TemporaryDirectory(prefix='sqlite-cost-',dir=parent) as td:
    for journal in ('DELETE','WAL'):
      for commits in (2,1):
        db=sqlite3.connect(str(Path(td)/f'{journal}-{commits}.db'))
        db.execute('PRAGMA synchronous=FULL')
        assert db.execute('PRAGMA synchronous').fetchone()[0]==2
        assert db.execute('PRAGMA journal_mode='+journal).fetchone()[0].upper()==journal
        db.execute('CREATE TABLE nonces(nonce TEXT PRIMARY KEY, ts INTEGER)')
        db.execute('CREATE TABLE receipts(receipt_id TEXT PRIMARY KEY, body TEXT)')
        db.commit()
        samples=[]
        for i in range(1200):
          t=time.perf_counter()
          db.execute('INSERT INTO nonces VALUES(?,?)',(str(i),i))
          if commits==2: db.commit()
          db.execute('INSERT INTO receipts VALUES(?,?)',(str(i),'x'*1000))
          db.commit()
          if i>=200: samples.append((time.perf_counter()-t)*1000)
        results.append({'filesystem':str(parent),'journal':journal,'synchronous':db.execute('PRAGMA synchronous').fetchone()[0],'commits_per_request':commits,**summarize(samples)})
        db.close()
print(json.dumps(results,indent=2))
