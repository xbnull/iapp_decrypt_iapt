"""Single-task worker launched only by the managed V135 queue daemon."""
from __future__ import annotations

import fcntl
import json
import os
import sys
import traceback
from pathlib import Path

VERSION = "V135-managed-task-worker"
APP_DIR = Path(__file__).resolve().parents[1]


def _storage_root() -> Path:
    from .config import APP_STORAGE
    return Path(APP_STORAGE).resolve()


def _safe_fail(task_id: int, message: str) -> None:
    try:
        from . import db
        row = db.one("SELECT status,options_json FROM tasks WHERE id=%s", (int(task_id),)) or {}
        if str(row.get("status") or "") in {"done", "failed", "cancelled"}:
            return
        try:
            options = json.loads(row.get("options_json") or "{}")
            if not isinstance(options, dict):
                options = {}
        except Exception:
            options = {}
        options["task_worker"] = VERSION
        options["task_worker_error"] = str(message)[-3000:]
        db.exec(
            "UPDATE tasks SET status='failed',error_text=%s,options_json=%s WHERE id=%s",
            (str(message)[-4000:], json.dumps(options, ensure_ascii=False, separators=(",", ":")), int(task_id)),
        )
    except Exception:
        traceback.print_exc()


def _lock_task(task_id: int):
    lock_dir = _storage_root() / "worker_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    handle = (lock_dir / f"task-{int(task_id)}.lock").open("a+")
    try:
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        handle.close()
        return None
    handle.seek(0)
    handle.truncate()
    handle.write(str(os.getpid()))
    handle.flush()
    return handle


def run_task_once(task_id: int):
    lock = _lock_task(task_id)
    if lock is None:
        print(f"[{VERSION}] duplicate ignored task={task_id}", flush=True)
        return {"ok": True, "duplicate": True}
    try:
        from . import db
        row = db.one("SELECT status FROM tasks WHERE id=%s", (int(task_id),)) or {}
        if str(row.get("status") or "") in {"done", "failed", "cancelled"}:
            print(f"[{VERSION}] terminal task ignored task={task_id} status={row.get('status')}", flush=True)
            return {"ok": True, "terminal": True}
        print(f"[{VERSION}] start task={task_id} pid={os.getpid()}", flush=True)
        from .task_feature_guard_v191 import enforce_task_or_mark_failed
        if not enforce_task_or_mark_failed(task_id, stage='task_worker_v135'):
            return {'ok': False, 'error': 'task feature denied'}
        from .ancient_supervisor_v131 import dispatch_task
        result = dispatch_task(int(task_id))
        print(f"[{VERSION}] finish task={task_id} result={result!r}", flush=True)
        return result
    except BaseException as exc:
        message = f"托管任务进程异常：{type(exc).__name__}: {exc}"
        print(f"[{VERSION}] {message}", flush=True)
        traceback.print_exc()
        _safe_fail(task_id, message)
        return {"ok": False, "error": message}
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
        except Exception:
            pass


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python -m app.task_worker_v135 TASK_ID", file=sys.stderr)
        return 2
    try:
        task_id = int(sys.argv[1])
    except ValueError:
        print("invalid task id", file=sys.stderr)
        return 2
    run_task_once(task_id)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD
