"""IAPT V179 unified runtime supervisor.

One systemd unit owns exactly one Uvicorn API process and one V136 queue daemon.
If either child exits unexpectedly, both are stopped and systemd restarts the
whole runtime.  This prevents old Celery and duplicate API/worker units from
racing for the same task.
"""
from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

VERSION = "V179-unified-runtime"
ROOT = Path(__file__).resolve().parents[1]
STOP = False
CHILDREN: dict[str, subprocess.Popen] = {}


def _positive_int(name: str, default: int, low: int = 1, high: int = 65535) -> int:
    try:
        value = int(str(os.environ.get(name, default)).strip())
    except Exception:
        value = default
    return max(low, min(high, value))


def _signal_handler(signum, _frame):
    global STOP
    STOP = True
    print(f"[{VERSION}] received signal={signum}", flush=True)


def _terminate_children(timeout: float = 20.0) -> None:
    for name, proc in list(CHILDREN.items()):
        if proc.poll() is None:
            try:
                proc.terminate()
                print(f"[{VERSION}] terminate {name} pid={proc.pid}", flush=True)
            except ProcessLookupError:
                pass
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if all(proc.poll() is not None for proc in CHILDREN.values()):
            break
        time.sleep(0.2)
    for name, proc in list(CHILDREN.items()):
        if proc.poll() is None:
            try:
                proc.kill()
                print(f"[{VERSION}] kill {name} pid={proc.pid}", flush=True)
            except ProcessLookupError:
                pass
    for proc in CHILDREN.values():
        try:
            proc.wait(timeout=2)
        except Exception:
            pass


def _spawn(name: str, command: list[str], env: dict[str, str]) -> subprocess.Popen:
    proc = subprocess.Popen(
        command,
        cwd=str(ROOT),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=None,
        stderr=None,
        close_fds=True,
        start_new_session=False,
    )
    CHILDREN[name] = proc
    print(f"[{VERSION}] started {name} pid={proc.pid} command={command!r}", flush=True)
    return proc


def main() -> int:
    global STOP
    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(sig, _signal_handler)

    env = os.environ.copy()
    env["PYTHONPATH"] = str(ROOT) + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
    env.setdefault("APP_STORAGE", str(ROOT / "storage"))
    env.setdefault("IAPT_FORCE_LOCAL_QUEUE", "1")
    env.setdefault("USE_CELERY", "0")
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")

    host = str(env.get("IAPT_API_HOST") or env.get("API_HOST") or "127.0.0.1")
    port = _positive_int("API_PORT", _positive_int("IAPT_API_PORT", 8000))
    log_level = str(env.get("IAPT_API_LOG_LEVEL") or "info")

    api_command = [
        sys.executable,
        "-m",
        "uvicorn",
        "app.main:app",
        "--app-dir",
        str(ROOT),
        "--host",
        host,
        "--port",
        str(port),
        "--workers",
        "1",
        "--proxy-headers",
        "--log-level",
        log_level,
    ]
    worker_command = [sys.executable, "-m", "app.queue_daemon_v136"]

    print(
        f"[{VERSION}] root={ROOT} api={host}:{port} storage={env['APP_STORAGE']}",
        flush=True,
    )

    try:
        _spawn("worker", worker_command, env)
        _spawn("api", api_command, env)
        while not STOP:
            for name, proc in list(CHILDREN.items()):
                code = proc.poll()
                if code is not None:
                    print(f"[{VERSION}] child exited name={name} pid={proc.pid} code={code}", flush=True)
                    STOP = True
                    _terminate_children()
                    return code if code else 1
            time.sleep(0.25)
    except BaseException as exc:
        print(f"[{VERSION}] fatal {type(exc).__name__}: {exc}", flush=True)
        _terminate_children()
        return 1
    finally:
        _terminate_children()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
