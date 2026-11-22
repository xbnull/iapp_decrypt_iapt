from __future__ import annotations
import fcntl, json, os, sys, traceback
from pathlib import Path
VERSION="V136-task-worker"

def _storage():
    from .config import APP_STORAGE
    return Path(APP_STORAGE).resolve()

def _fail(task_id:int,msg:str):
    try:
        from . import db
        row=db.one("SELECT status,options_json FROM tasks WHERE id=%s",(task_id,)) or {}
        if str(row.get("status") or "") in {"done","failed","cancelled"}: return
        try: opt=json.loads(row.get("options_json") or "{}")
        except Exception: opt={}
        if not isinstance(opt,dict): opt={}
        opt["task_worker"]=VERSION; opt["task_worker_error"]=msg[-3000:]
        db.exec("UPDATE tasks SET status='failed',error_text=%s,options_json=%s WHERE id=%s",(msg[-4000:],json.dumps(opt,ensure_ascii=False,separators=(",",":")),task_id))
    except Exception: traceback.print_exc()

def _lock(task_id:int):
    d=_storage()/"worker_locks_v136"; d.mkdir(parents=True,exist_ok=True)
    f=(d/f"task-{task_id}.lock").open("a+")
    try: fcntl.flock(f.fileno(),fcntl.LOCK_EX|fcntl.LOCK_NB)
    except BlockingIOError: f.close(); return None
    f.seek(0); f.truncate(); f.write(str(os.getpid())); f.flush(); return f

def run(task_id:int):
    lk=_lock(task_id)
    if lk is None:
        print(f"[{VERSION}] duplicate task={task_id}",flush=True); return {"ok":True,"duplicate":True}
    try:
        from . import db
        row=db.one("SELECT status FROM tasks WHERE id=%s",(task_id,)) or {}
        if str(row.get("status") or "") in {"done","failed","cancelled"}:
            return {"ok":True,"terminal":True}
        from .task_feature_guard_v191 import enforce_task_or_mark_failed
        if not enforce_task_or_mark_failed(task_id, stage='task_worker_v136'):
            return {'ok': False, 'error': 'task feature denied'}
        from .ancient_supervisor_v136 import dispatch_task
        result=dispatch_task(task_id)
        print(f"[{VERSION}] task={task_id} result={result!r}",flush=True)
        return result
    except BaseException as exc:
        msg=f"V136任务进程异常：{type(exc).__name__}: {exc}"
        traceback.print_exc(); _fail(task_id,msg); return {"ok":False,"error":msg}
    finally:
        try: fcntl.flock(lk.fileno(),fcntl.LOCK_UN); lk.close()
        except Exception: pass

def main():
    if len(sys.argv)!=2: return 2
    try: tid=int(sys.argv[1])
    except Exception: return 2
    result=run(tid)
    return 0 if result and result.get("ok") else 1
if __name__=="__main__": raise SystemExit(main())

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD
