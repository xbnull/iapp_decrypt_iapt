from __future__ import annotations
import json, os, signal, subprocess, sys, time, traceback
from pathlib import Path
from .config import APP_STORAGE, MAX_DECRYPT_WORKERS
VERSION="V136-single-authoritative-worker"
ROOT=Path(__file__).resolve().parents[1]
STORAGE=Path(APP_STORAGE).resolve(); JOB=STORAGE/"queue_v136"; LOG=ROOT/"logs"; HEART=STORAGE/"queue_v136.heartbeat.json"
JOB.mkdir(parents=True,exist_ok=True); LOG.mkdir(parents=True,exist_ok=True)
CONFIG_LIMIT=max(1,min(10,int(os.environ.get("MAX_DECRYPT_WORKERS") or MAX_DECRYPT_WORKERS or 5)))
STOP=False

def _sig(*_):
    global STOP; STOP=True

def _effective_limit():
    # Keep the configured concurrency, but never launch more tasks than current
    # free RAM can safely sustain. Enumeration threads remain 32 per task.
    try:
        mem={}
        for line in Path('/proc/meminfo').read_text().splitlines():
            k,v=line.split(':',1); mem[k]=int(v.strip().split()[0])
        avail=mem.get('MemAvailable',0)//1024
        reserve=max(384,int(os.environ.get('IAPT_WORKER_RAM_RESERVE_MB') or 512))
        per=max(128,int(os.environ.get('IAPT_TASK_RAM_BUDGET_MB') or 256))
        by_mem=max(1,(avail-reserve)//per) if avail>reserve else 1
        return max(1,min(CONFIG_LIMIT,by_mem))
    except Exception: return CONFIG_LIMIT

def _job_path(tid): return JOB/f"task-{int(tid)}.job"
def _write_job(tid):
    p=_job_path(tid)
    if p.exists(): return
    q=JOB/f".{p.name}.{os.getpid()}.{time.time_ns()}.tmp"; q.write_text(json.dumps({"task_id":int(tid),"recovered":True,"version":VERSION}),encoding='utf-8'); os.replace(q,p)
def _recover():
    try:
        from . import db
        for r in db.all("SELECT id FROM tasks WHERE status IN ('pending','queued') ORDER BY id ASC LIMIT 500") or []:
            try:_write_job(int(r['id']))
            except Exception:pass
    except Exception as e: print(f"[{VERSION}] recover warning {e!r}",flush=True)
def _ids():
    a=[]
    for p in JOB.glob('task-*.job'):
        try:a.append(int(p.stem.split('-',1)[1]))
        except Exception:
            try:p.unlink()
            except Exception:pass
    return sorted(set(a))
def _spawn(tid):
    env=os.environ.copy(); env['PYTHONPATH']=str(ROOT)+(os.pathsep+env['PYTHONPATH'] if env.get('PYTHONPATH') else '')
    lp=LOG/'task-worker-v136.log'
    f=lp.open('ab',buffering=0)
    p=subprocess.Popen([sys.executable,'-m','app.task_worker_v136',str(int(tid))],cwd=str(ROOT),env=env,stdin=subprocess.DEVNULL,stdout=f,stderr=subprocess.STDOUT,close_fds=True)
    p._iapt_log_handle=f
    return p
def _reap(tid,p):
    code=p.poll()
    if code is None:return False
    try:p._iapt_log_handle.close()
    except Exception:pass
    try:_job_path(tid).unlink()
    except Exception:pass
    print(f"[{VERSION}] reaped task={tid} exit={code}",flush=True); return True
def main():
    signal.signal(signal.SIGTERM,_sig); signal.signal(signal.SIGINT,_sig)
    children={}; last=0.0
    print(f"[{VERSION}] start pid={os.getpid()} configured_limit={CONFIG_LIMIT}",flush=True)
    try:
        while not STOP:
            now=time.monotonic()
            if now-last>=5: _recover(); last=now
            for tid,p in list(children.items()):
                if _reap(tid,p): children.pop(tid,None)
            limit=_effective_limit(); free=max(0,limit-len(children))
            if free:
                for tid in _ids():
                    if free<=0:break
                    if tid in children:continue
                    p=_spawn(tid); children[tid]=p; free-=1; print(f"[{VERSION}] spawned task={tid} pid={p.pid} limit={limit}",flush=True)
            try: HEART.write_text(json.dumps({"version":VERSION,"pid":os.getpid(),"time":time.time(),"configured_limit":CONFIG_LIMIT,"effective_limit":limit,"running":{str(k):v.pid for k,v in children.items()}},separators=(",",":")),encoding='utf-8')
            except Exception:pass
            time.sleep(.25)
    except BaseException: traceback.print_exc(); return 1
    finally:
        for p in children.values():
            try:p.terminate()
            except Exception:pass
        end=time.monotonic()+8
        while time.monotonic()<end and any(p.poll() is None for p in children.values()):time.sleep(.2)
        for p in children.values():
            if p.poll() is None:
                try:p.kill()
                except Exception:pass
        try:HEART.unlink()
        except Exception:pass
    return 0
if __name__=='__main__':raise SystemExit(main())
