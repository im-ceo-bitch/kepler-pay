"""Bounded readiness smoke probe against local pre-license service only.
Not a load, DDoS or production certification tool; never submits money operations.
"""
import argparse
import concurrent.futures
import http.client
import json
import time


def probe(port,path):
    start=time.monotonic();conn=http.client.HTTPConnection('127.0.0.1',port,timeout=5)
    try:
        conn.request('GET',path);res=conn.getresponse();data=res.read(4097)
        ok=res.status==200 and len(data)<=4096 and json.loads(data).get('real_money') is False
        return ok,round((time.monotonic()-start)*1000,2)
    except (OSError,http.client.HTTPException,ValueError,AttributeError):return False,round((time.monotonic()-start)*1000,2)
    finally:conn.close()


def summarize(results):
    if not results:raise ValueError('missing_probe_results')
    times=sorted(t for _,t in results);n=len(times)
    return {'requests':n,'successes':sum(ok for ok,_ in results),'p95_ms':times[(95*n+99)//100-1],'max_ms':times[-1]}


def main():
    p=argparse.ArgumentParser();p.add_argument('--port',type=int,default=8766);p.add_argument('--requests',type=int,default=30);p.add_argument('--workers',type=int,default=4);p.add_argument('--ready',action='store_true');a=p.parse_args()
    if not 1024<=a.port<=65535 or not 1<=a.requests<=120 or not 1<=a.workers<=8:p.error('out_of_bounds')
    path='/health/ready' if a.ready else '/health/live'
    results=[]
    with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as executor:
        pending=[]
        for _ in range(a.requests):
            pending.append(executor.submit(probe,a.port,path));time.sleep(.125)
        for f in pending:results.append(f.result())
    report=summarize(results);print(json.dumps(report,sort_keys=True));raise SystemExit(0 if report['requests']==report['successes'] else 2)

if __name__=='__main__':main()
