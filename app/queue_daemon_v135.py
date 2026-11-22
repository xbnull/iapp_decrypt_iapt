"""Managed external queue daemon.

This process is run by systemd with KillMode=control-group.  Therefore a
restart stops the daemon, task workers, Python decryptors and native enum
children together; no detached task survives an API/service restart.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
import traceback
from pathlib import Path

from .config import APP_STORAGE, MAX_DECRYPT_WORKERS

VERSION = "V135-managed-queue-service"
APP_DIR = Path(__file__).resolve().parents[1]
STORAGE = Path(APP_STORAGE).resolve()
JOB_DIR = STORAGE / "queue_v135"
LOG_DIR = APP_DIR / "logs"
HEARTBEAT = STORAGE / "queue_v135.heartbeat.json"
JOB_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
LIMIT = max(1, int(os.environ.get("MAX_DECRYPT_WORKERS") or MAX_DECRYPT_WORKERS or 5))
STOP = False


def _signal(_signum, _frame):
    global STOP
    STOP = True


def _write_job(task_id: int) -> None:
    path = JOB_DIR / f"task-{int(task_id)}.job"
    if path.exists():
        return
    tmp = JOB_DIR / f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    tmp.write_text(json.dumps({"task_id": int(task_id), "recovered": True, "version": VERSION}), encoding="utf-8")
    os.replace(tmp, path)


def _recover_db_queue() -> None:
    try:
        from . import db
        rows = db.all(
            "SELECT id FROM tasks WHERE status IN ('pending','queued') ORDER BY id ASC LIMIT 500"
        ) or []
        for row in rows:
            try:
                _write_job(int(row.get("id")))
            except Exception:
                pass
    except Exception as exc:
        print(f"[{VERSION}] db recovery warning: {exc!r}", flush=True)


def _job_ids() -> list[int]:
    values = []
    for path in JOB_DIR.glob("task-*.job"):
        try:
            values.append(int(path.stem.split("-", 1)[1]))
        except Exception:
            try:
                path.unlink()
            except OSError:
                pass
    return sorted(set(values))


def _spawn(task_id: int):
    log_path = LOG_DIR / "task-worker-v135.log"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(APP_DIR) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    with log_path.open("ab", buffering=0) as log:
        return subprocess.Popen(
            [sys.executable, "-m", "app.task_worker_v135", str(int(task_id))],
            cwd=str(APP_DIR),
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            close_fds=True,
        )


def _terminate(children: dict[int, subprocess.Popen]) -> None:
    for process in children.values():
        if process.poll() is None:
            try:
                process.terminate()
            except Exception:
                pass
    deadline = time.monotonic() + 8
    while time.monotonic() < deadline and any(p.poll() is None for p in children.values()):
        time.sleep(0.2)
    for process in children.values():
        if process.poll() is None:
            try:
                process.kill()
            except Exception:
                pass


def main() -> int:
    signal.signal(signal.SIGTERM, _signal)
    signal.signal(signal.SIGINT, _signal)
    children: dict[int, subprocess.Popen] = {}
    last_recover = 0.0
    print(f"[{VERSION}] started pid={os.getpid()} limit={LIMIT}", flush=True)
    try:
        while not STOP:
            now = time.monotonic()
            if now - last_recover >= 5.0:
                _recover_db_queue()
                last_recover = now

            for task_id, process in list(children.items()):
                code = process.poll()
                if code is None:
                    continue
                children.pop(task_id, None)
                try:
                    (JOB_DIR / f"task-{task_id}.job").unlink()
                except OSError:
                    pass
                print(f"[{VERSION}] reaped task={task_id} exit={code}", flush=True)

            available = max(0, LIMIT - len(children))
            if available:
                for task_id in _job_ids():
                    if available <= 0:
                        break
                    if task_id in children:
                        continue
                    process = _spawn(task_id)
                    children[task_id] = process
                    available -= 1
                    print(f"[{VERSION}] spawned task={task_id} pid={process.pid}", flush=True)

            try:
                HEARTBEAT.write_text(
                    json.dumps(
                        {
                            "version": VERSION,
                            "pid": os.getpid(),
                            "time": time.time(),
                            "limit": LIMIT,
                            "running": {str(k): v.pid for k, v in children.items()},
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    encoding="utf-8",
                )
            except Exception:
                pass
            time.sleep(0.25)
    except BaseException:
        traceback.print_exc()
        return 1
    finally:
        _terminate(children)
        try:
            HEARTBEAT.unlink()
        except OSError:
            pass
        print(f"[{VERSION}] stopped", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
