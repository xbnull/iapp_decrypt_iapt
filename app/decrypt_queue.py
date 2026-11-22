"""IAPT V179 single authoritative filesystem queue.

The API only writes an atomic job marker.  The queue daemon owned by the
single ``iapt.service`` systemd unit is the only process allowed to execute
jobs.  Celery publishing/consumption is intentionally disabled.
"""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .config import APP_STORAGE, LOCAL_QUEUE_WORKERS, MAX_DECRYPT_WORKERS

VERSION = "V179-single-authoritative-worker"
JOB_DIR = Path(APP_STORAGE) / "queue_v136"
JOB_DIR.mkdir(parents=True, exist_ok=True)


class QueueTicket:
    def __init__(self, task_id: int, path: Path):
        self.task_id = int(task_id)
        self.id = str(task_id)
        self.path = str(path)


def enqueue_task(task_id):
    task_id = int(task_id)
    from .task_feature_guard_v191 import enforce_task_or_mark_failed
    if not enforce_task_or_mark_failed(task_id, stage='enqueue_task'):
        try:
            from fastapi import HTTPException
        except Exception:
            raise PermissionError('task feature denied')
        raise HTTPException(403, '当前账号没有任务所需功能或订阅已失效')
    path = JOB_DIR / f"task-{task_id}.job"
    tmp = JOB_DIR / f".{path.name}.{os.getpid()}.{time.time_ns()}.tmp"
    tmp.write_text(
        json.dumps(
            {
                "task_id": task_id,
                "queued_at": time.time(),
                "api_pid": os.getpid(),
                "version": VERSION,
            },
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    os.replace(tmp, path)
    return QueueTicket(task_id, path)


def queue_runtime_config():
    return {
        "mode": "managed-v179",
        "dispatcher": VERSION,
        "systemd_unit": "iapt.service",
        "api_process_executes_decrypt": False,
        "api_process_spawns_children": False,
        "celery_enabled": False,
        "job_dir": str(JOB_DIR),
        "local_queue_workers": int(LOCAL_QUEUE_WORKERS or 1),
        "max_decrypt_workers": int(MAX_DECRYPT_WORKERS or 1),
    }


# Compatibility names for imports only.  No Celery application is created.
celery_app = None

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD
