import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DOTENV_PATH = Path(os.environ.get("IAPT_ENV_FILE", str(PROJECT_ROOT / ".env"))).expanduser().resolve()


def load_dotenv(path=None, override=None):
    p = Path(path or DOTENV_PATH)
    if not p.exists():
        return
    # Read the project .env regardless of process working directory.  The old
    # relative loader silently missed it under some systemd launch layouts.
    if override is None:
        override = os.environ.get("IAPT_DOTENV_OVERRIDE", "1") != "0"
    for raw in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and (override or key not in os.environ):
            os.environ[key] = value


load_dotenv()


def _int_env(name, default, low=1, high=1024):
    try:
        value = int(os.getenv(name, str(default)) or default)
    except Exception:
        value = default
    return max(low, min(high, value))


def _bool_env(name, default=False):
    raw = os.getenv(name)
    if raw is None:
        return bool(default)
    return str(raw).strip().lower() in ("1", "true", "yes", "on", "y")


DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "iapp_saas")

APP_STORAGE = Path(os.getenv("APP_STORAGE", "/www/wwwroot/iapt/storage")).resolve()
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
ALLOW_REGISTER = os.getenv("ALLOW_REGISTER", "0") == "1"

APP_ID = os.getenv("APP_ID", "iapt-android")
APP_SECRET = os.getenv("APP_SECRET", "CHANGE_ME_32_BYTES_MIN_SECRET")
SIGN_WINDOW_SECONDS = int(os.getenv("SIGN_WINDOW_SECONDS", "300"))
TOKEN_EXPIRE_MINUTES = int(os.getenv("TOKEN_EXPIRE_MINUTES", "30"))
ALLOW_INSECURE_DEV = os.getenv("ALLOW_INSECURE_DEV", "0") == "1"

REDIS_URL = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
CELERY_BROKER_URL = os.getenv("CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("CELERY_RESULT_BACKEND", REDIS_URL)
USE_CELERY = False  # V179: legacy Celery consumers are disabled
IAPT_FORCE_LOCAL_QUEUE = True  # V179: one filesystem queue is authoritative

# Whole-task concurrency.  These two values must both be raised in local mode.
LOCAL_QUEUE_WORKERS = _int_env("LOCAL_QUEUE_WORKERS", 1, 1, 64)
MAX_DECRYPT_WORKERS = _int_env("MAX_DECRYPT_WORKERS", LOCAL_QUEUE_WORKERS, 1, 64)
WORKER_CONCURRENCY = _int_env("WORKER_CONCURRENCY", LOCAL_QUEUE_WORKERS, 1, 64)

# Per-task processes/threads.
IAPT_ENUM_WORKERS = _int_env("IAPT_ENUM_WORKERS", 32, 1, 32)
IAPT_NORMAL_WORKERS = _int_env("IAPT_NORMAL_WORKERS", IAPT_ENUM_WORKERS, 1, 32)

# Joint sokey+dexkey acceleration.  The DEX value is only a priority hint and
# must pass the same native mian.iyu verifier; a miss falls back to exhaustive
# enumeration.  The hidden-prefix pass improves no-hint APKs without changing
# the candidate set or final correctness.
IAPT_JOINT_DEX_HINT_FIRST = _bool_env("IAPT_JOINT_DEX_HINT_FIRST", True)
IAPT_JOINT_FAST_HIDDEN_LIMIT = _int_env("IAPT_JOINT_FAST_HIDDEN_LIMIT", 256, 0, 1000000)
IAPT_JOINT_FAST_HIDDEN_BATCH_SIZE = _int_env("IAPT_JOINT_FAST_HIDDEN_BATCH_SIZE", 8, 1, 4096)

# True no-metadata joint enumeration.  This does not assume f.b(), timestamps,
# or any other key hint.  It changes only scheduling: one native full-range
# dex scan per sokey, avoiding repeated hidden-dependent setup for tiny tiles.
IAPT_JOINT_NO_HINT_HIDDEN_MAJOR = _bool_env("IAPT_JOINT_NO_HINT_HIDDEN_MAJOR", True)
IAPT_JOINT_NO_HINT_MIN_HIDDEN = _int_env("IAPT_JOINT_NO_HINT_MIN_HIDDEN", 16, 1, 1000000)

APP_STORAGE.mkdir(parents=True, exist_ok=True)
ZIP_ENCRYPTION = os.getenv("ZIP_ENCRYPTION", "1") == "1"
DOWNLOAD_CACHE_TTL_MINUTES = int(os.getenv("DOWNLOAD_CACHE_TTL_MINUTES", "30"))
SOURCE_CACHE_TTL_MINUTES = int(os.getenv("SOURCE_CACHE_TTL_MINUTES", "30"))
RSA_PRIVATE_KEY_PATH = Path(os.getenv("RSA_PRIVATE_KEY_PATH", str(PROJECT_ROOT / "keys" / "server_private.pem"))).resolve()
RSA_PUBLIC_KEY_PATH = Path(os.getenv("RSA_PUBLIC_KEY_PATH", str(PROJECT_ROOT / "keys" / "server_public.pem"))).resolve()

for directory in ("uploads", "tasks", "zips", "secure_zips", "cache"):
    (APP_STORAGE / directory).mkdir(exist_ok=True)

# IAPT_UNIFIED_RUNTIME_V179
