"""Legacy Celery entry point disabled by IAPT V179.

Production tasks are handled only by ``app.queue_daemon_v136`` under the
single ``iapt.service`` unit.  This module remains importable so old tooling
fails closed instead of starting a second consumer.
"""
from __future__ import annotations

from .decrypt_queue import enqueue_task

celery_app = None


def decrypt_task(task_id: int):
    from .task_feature_guard_v191 import enforce_task_or_mark_failed
    if not enforce_task_or_mark_failed(int(task_id), stage='legacy_worker_enqueue'):
        return {'ok': False, 'task_id': int(task_id), 'error': 'task feature denied'}
    ticket = enqueue_task(int(task_id))
    return {
        "ok": True,
        "queued": True,
        "task_id": int(task_id),
        "dispatcher": "V179-filesystem-queue",
        "ticket": ticket.path,
    }

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD
