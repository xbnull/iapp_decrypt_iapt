"""V111 database access layer.

The API is intentionally synchronous because the existing application imports db.one/all/exec
from both normal FastAPI handlers and worker threads.  The important properties here are:

* pool exhaustion fails immediately instead of blocking the only asyncio event-loop thread;
* MySQL socket and lock waits have finite limits;
* every borrowed connection is returned in a finally block;
* slow-query diagnostics are emitted without changing query results.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Any, Callable

import pymysql
from pymysql.cursors import DictCursor
from dbutils.pooled_db import PooledDB

from .config import DB_HOST, DB_PORT, DB_USER, DB_PASSWORD, DB_NAME


def _env_int(name: str, default: int, lo: int = 1, hi: int = 10000) -> int:
    try:
        value = int(str(os.environ.get(name, default)).strip())
    except Exception:
        value = default
    return max(lo, min(value, hi))


_MAX_CONNECTIONS = _env_int('IAPT_DB_MAX_CONNECTIONS', 64, 4, 256)
_MIN_CACHED = _env_int('IAPT_DB_MIN_CACHED', 2, 0, _MAX_CONNECTIONS)
_MAX_CACHED = _env_int('IAPT_DB_MAX_CACHED', 16, 1, _MAX_CONNECTIONS)
_CONNECT_TIMEOUT = _env_int('IAPT_DB_CONNECT_TIMEOUT', 4, 1, 30)
_READ_TIMEOUT = _env_int('IAPT_DB_READ_TIMEOUT', 8, 1, 120)
_WRITE_TIMEOUT = _env_int('IAPT_DB_WRITE_TIMEOUT', 8, 1, 120)
_LOCK_WAIT_TIMEOUT = _env_int('IAPT_DB_LOCK_WAIT_TIMEOUT', 4, 1, 60)
_SLOW_MS = _env_int('IAPT_DB_SLOW_MS', 800, 50, 60000)

_pool = PooledDB(
    creator=pymysql,
    maxconnections=_MAX_CONNECTIONS,
    mincached=_MIN_CACHED,
    maxcached=_MAX_CACHED,
    maxshared=0,
    maxusage=500,
    blocking=False,
    ping=1,
    setsession=[
        f'SET SESSION innodb_lock_wait_timeout={_LOCK_WAIT_TIMEOUT}',
        f'SET SESSION lock_wait_timeout={_LOCK_WAIT_TIMEOUT}',
    ],
    host=DB_HOST,
    port=DB_PORT,
    user=DB_USER,
    password=DB_PASSWORD,
    database=DB_NAME,
    charset='utf8mb4',
    cursorclass=DictCursor,
    autocommit=True,
    connect_timeout=_CONNECT_TIMEOUT,
    read_timeout=_READ_TIMEOUT,
    write_timeout=_WRITE_TIMEOUT,
)

_stats_lock = threading.Lock()
_stats = {
    'queries': 0,
    'errors': 0,
    'slow_queries': 0,
    'last_error': '',
    'last_slow_ms': 0.0,
}

DB_POOL_MODE = {
    'version': 'V111-fail-fast-finite-lock-waits',
    'maxconnections': _MAX_CONNECTIONS,
    'maxcached': _MAX_CACHED,
    'blocking': False,
    'connect_timeout': _CONNECT_TIMEOUT,
    'read_timeout': _READ_TIMEOUT,
    'write_timeout': _WRITE_TIMEOUT,
    'lock_wait_timeout': _LOCK_WAIT_TIMEOUT,
}


def conn():
    """Borrow one connection.  Pool exhaustion raises immediately; it never waits forever."""
    return _pool.connection()


def _record(sql: str, started: float, error: BaseException | None = None) -> None:
    elapsed_ms = (time.monotonic() - started) * 1000.0
    with _stats_lock:
        _stats['queries'] += 1
        if error is not None:
            _stats['errors'] += 1
            _stats['last_error'] = f'{type(error).__name__}: {error}'[:500]
        if elapsed_ms >= _SLOW_MS:
            _stats['slow_queries'] += 1
            _stats['last_slow_ms'] = round(elapsed_ms, 3)
    if elapsed_ms >= _SLOW_MS:
        compact = ' '.join(str(sql or '').split())[:260]
        print(f'[IAPT_V111_DB_SLOW] {elapsed_ms:.1f}ms sql={compact}', flush=True)


def _run(sql: str, args: Any, fetch: str):
    started = time.monotonic()
    c = None
    try:
        c = conn()
        with c.cursor() as cur:
            cur.execute(sql, args or ())
            if fetch == 'one':
                result = cur.fetchone()
            elif fetch == 'all':
                result = cur.fetchall()
            else:
                result = cur.lastrowid
        _record(sql, started)
        return result
    except BaseException as exc:
        _record(sql, started, exc)
        raise
    finally:
        if c is not None:
            try:
                c.close()
            except Exception:
                pass


def one(sql, args=None):
    return _run(sql, args, 'one')


def all(sql, args=None):
    return _run(sql, args, 'all')


def exec(sql, args=None):
    return _run(sql, args, 'exec')


def transaction(fn: Callable[[Any], Any]):
    started = time.monotonic()
    c = None
    try:
        c = conn()
        c.autocommit(False)
        with c.cursor() as cur:
            result = fn(cur)
        c.commit()
        _record('TRANSACTION', started)
        return result
    except BaseException as exc:
        if c is not None:
            try:
                c.rollback()
            except Exception:
                pass
        _record('TRANSACTION', started, exc)
        raise
    finally:
        if c is not None:
            try:
                c.autocommit(True)
            except Exception:
                pass
            try:
                c.close()
            except Exception:
                pass


def pool_stats() -> dict[str, Any]:
    with _stats_lock:
        result = dict(_stats)
    result.update(DB_POOL_MODE)
    try:
        result['pool_connections'] = int(getattr(_pool, '_connections', -1))
        result['idle_cached'] = len(getattr(_pool, '_idle_cache', ()) or ())
    except Exception:
        pass
    return result


# Compatibility names used by later hotfix routes.
query_one = one
query = all
query_all = all


# IAPT_V124_AUTOCOMMIT_COMPAT_BEGIN
# DBUtils SteadyDBConnection 兼容：事务辅助不能依赖 c.autocommit 属性/方法。
def _iapt_v124_raw_connection(c):
    for name in ('_con', '_db', '_connection', 'connection'):
        try:
            raw = getattr(c, name, None)
        except Exception:
            raw = None
        if raw is not None and raw is not c:
            return raw
    return None

def _iapt_v124_autocommit(self, flag=None):
    raw = _iapt_v124_raw_connection(self)
    if raw is None:
        return True if flag is None else None
    if flag is None:
        try:
            gac = getattr(raw, 'get_autocommit', None)
            if callable(gac): return gac()
        except Exception:
            pass
        try:
            val = getattr(raw, 'autocommit')
            if not callable(val): return bool(val)
        except Exception:
            pass
        return True
    try:
        ac = getattr(raw, 'autocommit', None)
        if callable(ac): return ac(bool(flag))
    except Exception:
        pass
    try: setattr(raw, 'autocommit', bool(flag))
    except Exception: pass
    return None
try:
    from dbutils.steady_db import SteadyDBConnection as _IAPT_V124_SteadyDBConnection
    if not hasattr(_IAPT_V124_SteadyDBConnection, 'autocommit'):
        _IAPT_V124_SteadyDBConnection.autocommit = _iapt_v124_autocommit
except Exception:
    pass
try:
    from dbutils.pooled_db import PooledDedicatedDBConnection as _IAPT_V124_PooledDedicatedDBConnection
    if not hasattr(_IAPT_V124_PooledDedicatedDBConnection, 'autocommit'):
        _IAPT_V124_PooledDedicatedDBConnection.autocommit = _iapt_v124_autocommit
except Exception:
    pass

def transaction(fn):
    c = conn()
    try:
        try:
            begin = getattr(c, 'begin', None)
            if callable(begin): begin()
        except Exception:
            pass
        with c.cursor() as cur:
            result = fn(cur)
        try: c.commit()
        except Exception: pass
        return result
    except Exception:
        try: c.rollback()
        except Exception: pass
        raise
    finally:
        try: c.close()
        except Exception: pass
# IAPT_V124_AUTOCOMMIT_COMPAT_END

