#!/usr/bin/env -S python3 -S
#skak
# IAPT_V146_JOINT_NO_HINT_EXHAUSTIVE: true no-hint hidden-major exhaustive joint enum
# -*- coding: utf-8 -*-
# IAPT_V3_NO_DYNAMIC_KEY_V88_BEGIN
# 独立开关：只禁止动态 key 获取/缓存，不关闭 outer-mode auto 的其它高级外层算法。

# IAPT_V3_NO_DYNAMIC_KEY_V88_END
from __future__ import annotations
import argparse
import contextlib
import io
import itertools
import base64
import ctypes
import platform
import sys
import hashlib
import json
import os
import re
import struct
import time
import zipfile
import zlib
import datetime as _dt
import signal
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed, wait, FIRST_COMPLETED
from collections import deque
from ctypes import c_int, c_uint8, c_void_p
from functools import lru_cache
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple



_CRYPTO_BACKEND = None
def _lazy_crypto():
    global _CRYPTO_BACKEND
    if _CRYPTO_BACKEND is not None:
        return _CRYPTO_BACKEND
    try:
        from cryptography.hazmat.backends import default_backend as _db
        from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _alg, modes as _modes
    except ModuleNotFoundError:
        # run_fast uses python -S. Add only the interpreter's package dirs if
        # the C helper is unavailable and the compatibility fallback is needed.
        import sysconfig
        for _p in {sysconfig.get_paths().get("purelib"), sysconfig.get_paths().get("platlib")}:
            if _p and _p not in sys.path:
                sys.path.append(_p)
        from cryptography.hazmat.backends import default_backend as _db
        from cryptography.hazmat.primitives.ciphers import Cipher as _Cipher, algorithms as _alg, modes as _modes
    _CRYPTO_BACKEND=(_Cipher,_alg,_modes,_db)
    return _CRYPTO_BACKEND

GENERIC_SLKY_POST_KEY = bytes.fromhex("e25f487325c6e711807c46c3e31d3c973c771e01")
GENERIC_KEY_XOR_CONST = bytes.fromhex("e24825e78046e33c3c1e251d4e0555e169a818ca")

# Server-side dynamic-key pool.  The API writes this file inside the private
# task .tmp directory; only opaque refs are printed, never the key bytes.
IAPT_SERVER_KEY_POOL: List[Tuple[str, bytes, bytes]] = []
IAPT_REDACT_SELECTED_KEYS = False
_QUISHUI_STATIC_SOKEY_ACTIVE = False

# IAPT_ANTI_IAPEC_V1_BEGIN
IAPT_ANTI_IAPEC_ENABLED = False

def _iapt_iapec_restore_blob(blob: bytes) -> bytes:
    if not IAPT_ANTI_IAPEC_ENABLED or b"iApEcPro-" not in bytes(blob or b""):
        return bytes(blob or b"")
    try:
        from iapt_iapec_restore import restore_iapec_blob
        restored, report = restore_iapec_blob(bytes(blob or b""))
        if int(report.get("restored_count") or 0) > 0:
            print("[IAPT_ANTI_IAPEC_CORE] restored=" + str(int(report.get("restored_count") or 0)), flush=True)
        return restored
    except Exception as exc:
        print("[IAPT_ANTI_IAPEC_CORE_ERROR] " + type(exc).__name__ + ": " + str(exc), flush=True)
        return bytes(blob or b"")
# IAPT_ANTI_IAPEC_V1_END


def _iapt_load_server_key_pool(path: Optional[Path]) -> List[Tuple[str, bytes, bytes]]:
    if path is None:
        return []
    obj = json.loads(Path(path).read_text(encoding="utf-8"))
    rows = obj.get("keys") if isinstance(obj, dict) else obj
    if not isinstance(rows, list):
        raise ValueError("invalid server key pool file")
    out: List[Tuple[str, bytes, bytes]] = []
    seen = set()
    for i, row in enumerate(rows):
        if not isinstance(row, dict):
            continue
        ref = re.sub(r"[^A-Za-z0-9]", "", str(row.get("ref") or f"key{i+1}"))[:64]
        post = bytes.fromhex(str(row.get("post_key") or "").strip())
        xor = bytes.fromhex(str(row.get("xor_key") or "").strip())
        if not post or not xor:
            continue
        sig = (post, xor)
        if sig in seen:
            continue
        seen.add(sig)
        out.append((ref or f"key{i+1}", post, xor))
    if not out:
        raise ValueError("server key pool is empty")
    return out


def _iapt_server_pool_match(post_key: bytes, xor_key: bytes) -> str:
    for ref, post, xor in IAPT_SERVER_KEY_POOL:
        if post == post_key and xor == xor_key:
            return ref
    return ""

STATIC_OUTER_BUILD = "outer-resolver-v146-joint-no-hint-exhaustive"
FN_RESTORE_CACHE_BUILD = "numeric-fn-indexed-random-table-v2"
MEMBER_OFFSET_CACHE_BUILD = "member-offset-cache-v12-cn-path-call-uigo"
FILE_EXTS = ("mjava", "myu", "iyu", "mlua", "mjs", "ijs", "ilua", "ijava")
# cn-ref-recursive-v4:
# 旧版只允许 ASCII 成员名，递归扫描会漏掉 uigo("广告.iyu")、call(...,"广告.方法")、fn 广告.xxx。
# v4 同时支持中文/UTF-8 路径、call/fn 中文模块名，并对 页面\广告.iyu 同时尝试原反斜杠和 页面/广告.iyu。
_MEMBER_NAME_CHARS_BRE = rb"A-Za-z0-9_./\\\-+=\x80-\xff"
FILE_RE = re.compile(rb"([" + _MEMBER_NAME_CHARS_BRE + rb"]{1,240}\.(?:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava))", re.I)
FILE_NAME_FULL_RE = re.compile(rb"[" + _MEMBER_NAME_CHARS_BRE + rb"]{1,240}\.(?:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)\Z", re.I)
_EXT_BYTES_SET = {x.encode("ascii") for x in FILE_EXTS}
_EXT_DOT_TOKENS = tuple(b"." + x.encode("ascii") for x in sorted(FILE_EXTS, key=len, reverse=True))
_NAME_BYTE_OK = bytes(
    1 if (65 <= i <= 90 or 97 <= i <= 122 or 48 <= i <= 57 or i in (43, 45, 46, 47, 61, 92, 95) or i >= 128) else 0
    for i in range(256)
)
# Interface/code cross-language references that point to encrypted member files.
#   fn showym.start()        -> showym.myu
#   fn 广告.事件()            -> 广告.myu
#   call(a, "mjava", "mk.abcd", ...) -> mk.mjava
#   call(a, "mjava", "广告.开始", ...) -> 广告.mjava
FN_MODULE_RE = re.compile(rb"(?:^|[^A-Za-z0-9_./\\\-\x80-\xff])fn\s+([A-Za-z_\x80-\xff][A-Za-z0-9_/\\\-\x80-\xff]*)\s*\.", re.I | re.M)
CALL_MODULE_RE = re.compile(
    rb"call\s*\(\s*[^,\r\n)]*?\s*,\s*(['\"])([A-Za-z0-9_]+)\1\s*,\s*(['\"])([A-Za-z_\x80-\xff][A-Za-z0-9_/\\\-\x80-\xff]*)\.[A-Za-z_\x80-\xff][A-Za-z0-9_\x80-\xff]*\3",
    re.I | re.S,
)
UIGO_ARG_RE = re.compile(
    rb"(?<![A-Za-z0-9_.$])uigo\s*\(\s*(['\"])([^'\"\r\n]{1,300})\1",
    re.I,
)
MUST_HAVE_MAIN = "mian.iyu"
# Some protected projects rename the root page (for example lianyi.iyu).
# Keep discovery bounded and deterministic; the normal member decryptor remains
# the final validator, so a DEX string alone is never accepted as a hit.
_MAIN_FILE_PROBE_CANDIDATES: List[str] = ["mian.iyu", "main.iyu", "start.iyu", "index.iyu", "home.iyu"]
_APK_DISCOVERED_MEMBER_CANDIDATES: List[str] = []

_MEMBER_MARKER_CACHE: Dict[tuple, Tuple[bytes, bytes]] = {}
_MEMBER_KEY_CACHE: Dict[tuple, bytes] = {}
_OUTER_KEY_CACHE: Dict[tuple, Tuple[bytes, Dict[str, bytes]]] = {}
_FILE_NAME_SCAN_CACHE: Dict[tuple, Tuple[str, ...]] = {}  # key=(scan_mode, exact bytes object); avoids per-blob md5 hashing
_XOR_TRANSLATE_CACHE: Dict[bytes, Tuple[bytes, ...]] = {}
_EXTRA_OUTER_ENV: Dict[str, bytes] = {}
# v57: APK mode may contain several ABI siblings.  Keep all of them for
# SO-backed dynamic outer-key analysis instead of using only x86.
_APK_NATIVE_SO_CANDIDATES: List[Tuple[str, bytes]] = []
# Exact static profile exposed by the BMP-parity -> RC4 -> zlib native wrapper.
# It is populated only after zlib length, hidden-string and table-construction
# validation all succeed; no APK code is executed.
_IAPT_PACKED_NATIVE_PROFILE: Optional[Dict[str, object]] = None
_PASSWORD_DEEP_SCAN = False


def ms_since(start: float) -> float:
    return (time.perf_counter() - start) * 1000.0

class _IaptProbeTimeout(RuntimeError):
    pass


class _IaptSoftTimeoutMs:
    """Best-effort per-candidate timeout for Unix/Termux.

    This keeps a single bad sokey candidate from blocking the whole enum loop.
    It is intentionally used only around the candidate probe, not around final
    full decrypt after a key has been selected.
    """
    def __init__(self, timeout_ms: int, label: str = "probe"):
        try:
            self.timeout_ms = int(timeout_ms or 0)
        except Exception:
            self.timeout_ms = 0
        self.label = label
        self.enabled = False
        self.old_handler = None
        self.old_timer = None

    def _handler(self, signum, frame):
        raise _IaptProbeTimeout(f"{self.label} timeout after {self.timeout_ms} ms")

    def __enter__(self):
        if self.timeout_ms <= 0:
            return self
        try:
            self.old_handler = signal.getsignal(signal.SIGALRM)
            # Preserve an existing timer if one exists.
            self.old_timer = signal.getitimer(signal.ITIMER_REAL)
            signal.signal(signal.SIGALRM, self._handler)
            signal.setitimer(signal.ITIMER_REAL, self.timeout_ms / 1000.0)
            self.enabled = True
        except Exception:
            # Signal timeouts only work in the main thread on Unix-like systems.
            self.enabled = False
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.enabled:
            try:
                signal.setitimer(signal.ITIMER_REAL, 0)
                if self.old_handler is not None:
                    signal.signal(signal.SIGALRM, self.old_handler)
                # Do not restore a previous non-zero timer here; this script does
                # not rely on nested timers and restoring stale timers can create
                # confusing late SIGALRM events in Termux.
            except Exception:
                pass
        return False


def _iapt_probe_timeout_ms(args) -> int:
    try:
        return max(0, int(getattr(args, "sokey_probe_timeout_ms", 300) or 0))
    except Exception:
        return 300

def _iapt_dexkey_probe_timeout_ms(args) -> int:
    """Best-effort per-dexkey watchdog.

    dexkey enum can hit pathological outer formulas / member probes.  Without a
    per-key watchdog, one bad candidate inside the first multiprocessing chunk
    can make the UI look stuck forever.  300 ms is intentionally conservative for
    outer-shell + mian.iyu gate; use --dexkey-probe-timeout-ms 0 to disable.
    """
    try:
        return max(0, int(getattr(args, "dexkey_probe_timeout_ms", 300) or 0))
    except Exception:
        return 300

def fmt_ms(value_ms: float) -> str:
    return f"{value_ms:.3f} ms"

def log_timing(stage: str, start: float) -> float:
    elapsed = ms_since(start)
    print(f"[T] {stage:<24s} {elapsed:.3f} ms")
    return elapsed

def normalize_find_names(items: List[str]) -> List[str]:
    out: List[str] = []
    seen: Set[str] = set()
    for item in items or []:
        for part in re.split(r"[,;\n\r]+", str(item)):
            name = part.strip().strip('\"\'')
            if not name or name in seen:
                continue
            seen.add(name)
            out.append(name)
    return out

def _fast_digest_bytes(data: bytes, sample: int = 65536) -> str:
    """Fast, stable fingerprint for cache invalidation without hashing huge APK blobs."""
    h = hashlib.sha256()
    h.update(str(len(data)).encode())
    h.update(b"\0")
    if len(data) <= sample * 2:
        h.update(data)
    else:
        h.update(data[:sample])
        h.update(data[-sample:])
    return h.hexdigest()


def outer_cache_fingerprint(
    so_data: bytes, container: bytes, hidden: bytes, package: str, version_name: str,
    version_code, app_label: str, fb_value, mode: str, outer_mode: str, extra_env: Dict[str, bytes]
) -> str:
    env_summary = {}
    for k, v in sorted((extra_env or {}).items()):
        if isinstance(v, bytes):
            env_summary[k] = hashlib.sha256(v).hexdigest() if len(v) > 64 else v.hex()
        else:
            env_summary[k] = str(v)
    payload = {
        "build": STATIC_OUTER_BUILD,
        "so": _fast_digest_bytes(so_data),
        "container": _fast_digest_bytes(container),
        "hidden": hidden.hex(),
        "package": str(package),
        "versionName": str(version_name),
        "versionCode": str(parse_int_auto(version_code)),
        "appLabel": str(app_label),
        "fb": str(parse_int_auto(fb_value)),
        "mode": str(mode),
        "outerMode": str(outer_mode),
        "extra": env_summary,
    }
    raw = json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def _trace_to_json(trace: Dict[str, bytes]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for k, v in (trace or {}).items():
        if isinstance(v, bytes):
            out[k] = v.hex()
        else:
            out[k] = str(v).encode("utf-8", "replace").hex()
    return out


def _trace_from_json(obj: Dict[str, str]) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    for k, v in (obj or {}).items():
        try:
            out[k] = bytes.fromhex(str(v))
        except Exception:
            out[k] = str(v).encode("utf-8", "replace")
    return out


def load_cached_outer_result(
    cache_path: Path, fingerprint: str, container: bytes, hidden: bytes, fb_value, use_c: bool, c_path: str
) -> Optional[Tuple[bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    if not cache_path.exists():
        return None
    t_cache = time.perf_counter()
    try:
        obj = json.loads(cache_path.read_text(encoding="utf-8"))
        if obj.get("fingerprint") != fingerprint:
            return None
        post_key = bytes.fromhex(obj["post_key"])
        key_xor = bytes.fromhex(obj["key_xor"])
        outer_key = bytes.fromhex(obj["outer_key"])
        trace = _trace_from_json(obj.get("trace", {}))
        member_ctx_name = trace.get("member_ctx", b"post")
        if member_ctx_name == b"nopost":
            ctx = NoPostSlkyContext()
        else:
            ctx = SlkyContext(post_key, use_c=use_c, c_path=c_path)
        member_key_mode = trace.get("member_key_mode", b"xor").decode("utf-8", "replace")

        plain_path = cache_path.parent / "container_plain.bin"
        container_plain = None
        if plain_path.exists():
            try:
                t_plain = time.perf_counter()
                candidate_plain = plain_path.read_bytes()
                verify_mian_or_fail(candidate_plain, ctx, key_xor, hidden, fb_value, member_key_mode)
                container_plain = candidate_plain
                trace["container_plain_from_cache"] = b"1"
                trace["timing_outer_key_ms"] = b"cached"
                trace["timing_outer_decrypt_ms"] = b"cached-plain"
                trace["timing_mian_candidate_verify_ms"] = f"{ms_since(t_plain):.3f}".encode()
                print(f"[+] outer cache hit: {cache_path} plain-load+verify={ms_since(t_plain):.3f} ms")
            except Exception as e:
                print(f"[!] cached container_plain ignored: {type(e).__name__}: {e}")
                container_plain = None

        if container_plain is None:
            if not aes_cbc_pkcs7_padding_maybe_valid(container, outer_key):
                print("[!] outer cache stale: fast padding reject")
                return None
            t_dec = time.perf_counter()
            container_plain = aes_cbc_then_xor_decrypt(container, outer_key)
            verify_mian_or_fail(container_plain, ctx, key_xor, hidden, fb_value, member_key_mode)
            trace["timing_outer_key_ms"] = b"cached"
            trace["timing_outer_decrypt_ms"] = f"{ms_since(t_dec):.3f}".encode()
            print(f"[+] outer cache hit: {cache_path} decrypt+verify={ms_since(t_dec):.3f} ms")
        print(f"[T] outer cache total      {ms_since(t_cache):.3f} ms")
        trace.setdefault("algorithm", b"<cached outer result>")
        return post_key, key_xor, outer_key, container_plain, trace
    except Exception as e:
        print(f"[!] outer cache ignored: {type(e).__name__}: {e}")
        return None


def save_cached_outer_result(cache_path: Path, fingerprint: str, post_key: bytes, key_xor: bytes, outer_key: bytes, trace: Dict[str, bytes], container_plain: Optional[bytes] = None) -> None:
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        obj = {
            "fingerprint": fingerprint,
            "post_key": post_key.hex(),
            "key_xor": key_xor.hex(),
            "outer_key": outer_key.hex(),
            "trace": _trace_to_json(trace),
            "saved_at": int(time.time()),
        }
        cache_path.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
        if container_plain is not None:
            (cache_path.parent / "container_plain.bin").write_bytes(container_plain)
    except Exception as e:
        print(f"[!] outer cache save failed: {type(e).__name__}: {e}")




# IAPT_VERIFIED_DYNAMIC_KEY_RESULT_V1_BEGIN
def _iapt_write_verified_dynamic_key_result(
    out_dir: Path,
    post_key: bytes,
    key_xor: bytes,
    trace: Dict[str, bytes],
    fingerprint: str = "",
) -> Optional[Path]:
    """Persist the exact key pair only after the original mian.iyu verifier passed.

    This is a task-local handoff record, not a reusable key cache.  The worker
    consumes it to persist the key into the server pool.  Atomic replace avoids
    partially-written JSON when the task process is interrupted.
    """
    try:
        out_dir = Path(out_dir)
        target = out_dir / ".tmp" / "verified_dynamic_key.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        source = trace.get("key_source", b"") if isinstance(trace, dict) else b""
        if isinstance(source, bytes):
            source = source.decode("utf-8", "replace")
        payload = {
            "version": 1,
            "verified": True,
            "verified_member": str(MUST_HAVE_MAIN),
            "post_key": bytes(post_key).hex(),
            "key_xor": bytes(key_xor).hex(),
            "key_source": str(source or "verified-decrypt"),
            "fingerprint": str(fingerprint or ""),
            "verified_at": int(time.time()),
        }
        tmp = target.with_name(target.name + ".tmp." + str(os.getpid()))
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2),
            encoding="utf-8",
        )
        try:
            tmp.chmod(0o600)
        except Exception:
            pass
        os.replace(tmp, target)
        try:
            target.chmod(0o600)
        except Exception:
            pass
        print(
            "[IAPT_DYNAMIC_KEY_VERIFIED] "
            f"member={MUST_HAVE_MAIN} source={payload['key_source']} manifest={target}",
            flush=True,
        )
        return target
    except Exception as exc:
        print(
            f"[!] verified dynamic key result write failed: {type(exc).__name__}: {exc}",
            flush=True,
        )
        return None
# IAPT_VERIFIED_DYNAMIC_KEY_RESULT_V1_END

def shared_cache_root() -> Path:
    base = os.environ.get("IAPP_DECRYPT_CACHE_DIR")
    if base:
        return Path(base)
    return Path.home() / ".cache" / "iapp_auto_decrypt_fastcache" / STATIC_OUTER_BUILD


def shared_outer_cache_path(fingerprint: str) -> Path:
    
    return shared_cache_root() / "outer" / fingerprint / "outer_key_cache.json"


def shared_restore_cache_path(apk_sig: str, needed_hash: str) -> Path:
    key = hashlib.sha256((FN_RESTORE_CACHE_BUILD + "\n" + apk_sig + "\n" + needed_hash).encode("utf-8", "ignore")).hexdigest()
    return shared_cache_root() / "fn_restore" / key / "numeric_fn_restore_cache.json"


def member_offset_cache_signature(container_plain: bytes, ctx: "SlkyContext", hidden: bytes, fb_value, member_key_mode: str) -> str:
    payload = {
        "build": MEMBER_OFFSET_CACHE_BUILD,
        "container": _fast_digest_bytes(container_plain),
        "ctx": hashlib.sha256(getattr(ctx, "post_key", b"")).hexdigest(),
        "hidden": hidden.hex(),
        "fb": str(parse_int_auto(fb_value)),
        "member_key_mode": str(member_key_mode or "xor"),
    }
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def shared_member_offset_cache_path(signature: str) -> Path:
    return shared_cache_root() / "member_offsets" / signature / "member_offsets_cache.json"


def load_member_offset_cache(cache_paths: List[Path], signature: str) -> Dict[str, Tuple[int, int]]:
    for cp in cache_paths:
        try:
            if not cp.exists():
                continue
            obj = json.loads(cp.read_text(encoding="utf-8"))
            if obj.get("build") != MEMBER_OFFSET_CACHE_BUILD or obj.get("signature") != signature:
                continue
            out: Dict[str, Tuple[int, int]] = {}
            for k, v in (obj.get("offsets") or {}).items():
                if isinstance(v, list) and len(v) == 2:
                    a, b = int(v[0]), int(v[1])
                    if (a == -1 and b == -1) or (0 <= a <= b):
                        out[str(k)] = (a, b)
            print(f"[+] member offset cache hit: {cp} entries={len(out)}")
            return out
        except Exception as e:
            print(f"[!] member offset cache ignored: {type(e).__name__}: {e}")
    return {}


def save_member_offset_cache(cache_paths: List[Path], signature: str, offsets: Dict[str, Tuple[int, int]]) -> None:
    if not offsets:
        return
    obj = {
        "build": MEMBER_OFFSET_CACHE_BUILD,
        "signature": signature,
        "offsets": {str(k): [int(v[0]), int(v[1])] for k, v in sorted(offsets.items())},
        "saved_at": int(time.time()),
    }
    for cp in cache_paths:
        try:
            cp.parent.mkdir(parents=True, exist_ok=True)
            cp.write_text(json.dumps(obj, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        except Exception as e:
            print(f"[!] member offset cache save failed: {type(e).__name__}: {e}")


# v56: prebuilt Linux x86_64 helpers embedded in the Python script.
# Non-matching platforms fall back to Python/legacy paths instead of compiling.
_EMBEDDED_SO_PLATFORM = "linux"
_EMBEDDED_SO_MACHINES = {"x86_64", "amd64"}
_EMBEDDED_FASTCORE_SHA256 = "b8bffc25858da9db29a01f1f7fb11831b71c551a77ff0128a6461beef7df7186"
_EMBEDDED_MARKER_SHA256 = "5a8d715b33b47263555ca8bd138847cbdba5ea6d3578cbe4eed7c92523f2fecf"
_EMBEDDED_FASTCORE_FILE = "embedded_fastcore_x86_64.so"
_EMBEDDED_MARKER_FILE = "embedded_marker_x86_64.so"

# v133 single-file payloads.  They are compressed/base64 inside this .py so the
# script can be distributed as one file while still writing native helpers to
# the normal cache directory at runtime.
_EMBEDDED_FASTCORE_C_ZB64 = "eNrtffl73DaS6O/+K+jMN56mmrL7VssU5S/rZHbzJpPJy7Fv9/kp/fFqiVZfabLbrZG1f/urKtwg2Dp8jJPYM1GTQKFQAAqFqkIBfPSnLJ8Wi9yb/Pt3P09+/MfPP7z8+tGfikU622S5d1JWWbGonl6cmmmzIrHT1sXivAZXLM2kVXWxzuOMJU49VnXWmkxmxWKzm0x87+1bLfXL77764R/ffAXpOtr0ImcY8kVWTLWc5SpflOXs2TwbmtWKjHy7qle9G48mo0Gt7qIP6UbFb+Zz6Atop4k8N5IFTXoNcbxOL1gVT57ozfvh75O/fv3lTz//8PXk5Q///f1P/9Cri9fzySJfLt6ts67KZ/FmtzVJjsv5s4s3abzSSWY/j8oqrorUKxYz5ApomVeO09YGHsaTytv53rW3zqvNeuG1IM1vsQx/F3o3jrLpJCu2KQJ5cUApiYYh8V54rdh7honPvQ6iePTswPt2mcaz/LBYZDkMXJZDKSiZn+drb7pcz+OqQl7zvP+MZ5u89DZlnnnJlffjt3/7by9eZNAnu8v86pF34OWLzTxfA1HLhRevc6+cx7NZ4CWbyqsuitKLZ+XSu4AyM8DzzXc/Tf7+zXdeGU/z2dVT7+CZo0FFvKqAN3qTuEyLghq2RTICL72I195yU73qjs6gjY88+Edp63yLaSGlYEdC6crbsHdEsPAirxN4K/zhqVOvRWi9E68jkOE/xL9qt88A9C+Hfwll+gYSWgK33zpEwoDjKp+w+AzwxstnZa5hM0sRKIekv9lSg8VWLFjNLWyW3/pL5y9eG8p7f/a6nY3v69Q8izBNVPvmopjlCPkYWrjhgDxx4euNwloODxe8szibrMJHNzZjbpdFxgajnF1eTVbLsppU63hRIodIds2K87ykEWHMt87nMbLVOpC0pstFWXmiwAEiYrCEcpYv5FgSIDF1jyjlqKAPxqEFkRXrPK2IKuwv+oWpL1B6p9A9I94PQDBNJa+g8YefE8iE33ZbH3mqeLMGGJyPvGHFmdbr1EAaHgADvoHJdYiPz7EciB6vOww9mF5xUrYoBcZthFyuI9gCAsjUsAIrrr1Tb6wTg/+2nBTR2X5r6/0CfaMzAnGRIFUwG8JuFcyNfALavl/nZb7e5jA9c2+5Ls6LRTwDwg5XszjNPSEQ0qtnyzX2fb6L04pPVr0Zy1k2sfpqrfeVTGsgCltdHzVzLta5Z5UAOn3sX1BhbPtz/gSdLvCd3aGfWqwhvwBqjfraRG4sT8Xtvr7B6cSF2YrNn3S5zlusMTSzDuLJqlqziRAjsYGn5yYqN6FcazoxKGqoBBTNDnguzHrMFD2KPf6YasVljer0TmBC4NtjCcslwmFXn3Fy8sbE/WaaTzid4IkLPGkEF7PZLiGaaQuBi7icUBUJclEiWSh8JCV/WZzD4j0pN3OAozY3ywSWzcSCVq7NmDxWskBREG/PcQ4o4GcCC0y1l8fHz71qvVmkcQWrX7V8E68z75/5eikmk0I0LdbUdlZTp17TLNby2eAdet063LzYYY/o9LOyB6wOX5JoFVTi1mjQnwW0Wm6himQzVSuuUTkSFtmLOKQHvFiN4GpZgQDigwPEchyw7rHhfcEH9jkNrFjhkTFgvUovkZJht3dmZh1AMraDQ6g1n9V2ylSrsvhnvpy2BJSvyx6GoKWYEBWbJQhjLATznhD5pjx7jEjkDOqLlf4RF71/BT0KG47ssOAqEyhT//WPH7Ajlt4SVt0366LKvVVclk9NJhGEzOPyUpc/wIFKz4GJolSc21gcew4KcI1DykPkcxCHWM+e9ZON0n5MauHiHAMTyMSMnUaj7DsrSW6nNjGoNXhAqSassr9/NWwBlsAzhjDgcBpFOPSPFfMAbes8bynebVSKGKbA0FwcXBx4TAeS+g9DO8/n6eqqxSWxoCtQegxnrA4pa8BPq97g2ao3JL17uc3Xby7yGVhK5zOmqbdA90iuQPIgCvbkg07/E6rltKoflqs8LeIZ9EaGuvwqri5AosHaUXrn+SJfgzJITE+8+iyBdqYXgJ8rlkAOtBLfUZUo43mOXQx8uNpUiA55W+ZIBYNkvOyyZhuAL5vdEfzfWhBipm6aiQkl3l3pDGSmZVHUVg1QFW9XIx++Xgj0+0W4XBegY9lzd3jm+87yjZJcgr4vKS47HxANxmfhe5dXsn8/AWH1EPqSGn13lk6AzZZN95E73dGtYuY2EXM/Lw73cn3z5fc/Tb78+sfJ1//1/ZfffTX58aevv29dBuvUJ2vX+39Uz2Qy7/bGhTeposl8Ponz8jK/ApkD614B1JYF5LZal37QgoJ+KODKi810Ossn+Qq4sjWpgs5uCrxoI91FUDTEXyy0W645wskuICyzWaFSBr5CcPcC98YNFDlKVJTP7fdWx380mcRVtS6STZVPJq1WFa/P86r1BXRQUJZ57wsf5nyTnQ5AgHeS71YgenG8LLkJXUxCUvTT+vJVFzRIJvbgpXNGFM6WcbYRQ8Aw8BIHPqDwQyx3FlGB0DncBABj0+kScI+Au83APQLuEXCfgHvNwH0CHhDwgID7zcADAh4T8JCAB83AQwTudgh4RMDDZuARAvcY8BEBj5qBjxB4wIDHBHzUDDxG4DEDPibgcTPwMdGcsEHpEPTxnlHpIHgfZ/vN+2C1LE/XV/Ba57ViQazmZkB75b02pi9jy7CBpQFHsIbZLaB3t/JsAZLPnq27gPWGH4IAZUI9Og6L06gbFoeH/k5IJWigLMGTirlIAhSwSAjkDBpNLb0OrILkQgX2v6RQ0oZSeEejIbzDD3ds87GyxoH34qRMlrtXveEI16frR53dqA+ccJTinyP8k6As7cGfET6NpvAnHSKzdGgiYxrC9Qguhz8Zvsb4ejQKAGEaI9sihvQYEzMExLQhvg4Qeoq4YszIBviEwDHWdIx0xJh2RAg6iDChIgh9jLT2RsS6+AeLTDE3xXJ9woW05vhnirQe4Z9sjLn41B0iwg4CptQKRJjiny7CHCPWDhY+RoI7CNLt0SxErPiUY0N7mJHg6xFDiC0bE3FISDemuYhdhR00xNcYMQyxSB8zMqwpoRJYNqcnbM54gAiH+J4hxR2qOSMZg41C/AlmDAk/ok7xKcGa+tTDmDZAuCG2KZ0iwozQYAUxZk+xyAArGSDqPj6Nsd0D6rljEsPYPCwxxLJ9RHhMCMZEIdIQEwbMHtPoYZFjQog1TxFXQgRjazOsuEejQC2hwaN29ohtsFyHug8Tc2oAYcXOHuCQdWmoaZSJVanJWGyEaUN86hLL9RHhiOjC+gaIJkOEPaSwh4QcUy6SOUDicsSV4GsXcWU0bvinQ6OVIMKc+oGGkLiD+pm6CjH0iAasJEWQDBsR4+uIegXpOCbeJO4+JoTUHmJOfBphA8Y0K2gosPoY8Y+oL7CSKRbOseIRghwRZxGZNCgJvh8hwh5m9zCnS1OK2I3YnlqLIBnWdET9iv0zIC4iEvBpHCPCI2oy9Q0iHGHhARbuYPOmNF0wd4TN6yPIkKYGzQfMTWm8ae7m1GR8n9Jco84meYLQGRVBXMdI0jHS0MXXMSLMMTelQaGGEf3E2GNqHqIZ01BgVQm2JydaSZDRKNMAIEiPGA1BEpqTWF1C1Y1uQssGlXtIUnyul9Wb5TqTezneG/9a7NK9OTkZ+29bb05Pe6CW3NyKq9wkNVy69t1SO0am+OZVPOkNh2cnJ/D0di8oaPUcFJ7e6q7svcXGohQ2qgHuDYHgunU3ZTQGK2WPLgBjAEmGPqo659VgcCYtML5Wd8LiZBCi5fUG1uBIaw/iHRwU9f7hGe0u7w9HVo81Wrz2ebXOhXWdkr513Q16wSAYB2BvgYwAiQStDmChGA5ubKIHSDSj+lo2r4qgBYeo70xbreJJ34+ijl9FNWapcWLl+79obQB6imeDwy5reEjdgpgHZ79U4Y1prSurUxC3hh5dn3S74RqJE6mvIfU19PNrg+It4B0crNuvz8IEHl5D96sNKjYHKB162sxBK5Pl9Kycscjoaxnb8AY4Yn0WbWdZ99fJZtxKcHbdynJCKa3z3AOU0hp7hg3cLfRSrcBOUc500G2+XNOrUj8tFtF00GuAR51SFUB/EksEHZQl+3xoa7CIe1tWrHalZTZst2MkBPHWZlEV87yFfQodoOui//F/Xn75PdoUpIm27h4r4RuiDUwMjJaIZ60vf5oQTv+JQv0YGA404VmZ64W6odCOb+pBFLwFU9S7ab5ARh7h9lUTCA5cvI2LWZzMZFOZ77flwHUK85ET4sgN7+clwWrMAv/+3c8va+BgRizOBfxkkmyKWVUsJulqMykWRdWSzuqWmVluVqvluirJigMDTm1nOGXYJTJ6dN0JUIj1QYwNg1FwBMLsOABdDRZpUIJBKwPVqDu8CffjSjkutqyTtkaKEynhpK+SiUE6eF9mkPZHij6p2qR3MH2FlIr4tlpXolbSl0mtIF2PNFtSHodSgSE7h1Q/0gdIISYFgKwIUotIHZxOtVqlVCCZ2Wj7BpfB0g9dnIjutvmqtQxWsESgcA/3MZPaQjaDhh5uFeqMbU/zzwzyMRiE1qH3yyCcK6RT2EIpUXT2yHxdHHJS3225vLcgtOWtKZiBOZumW7EIcLmFqv1QrhHYK7P3Mk3uRQ+ObiM9cpQMv7rBqF//5/eTl998/x9f/+AdrIr0cpKnCSkDgFEPjsKNSZ7kRRTcJJAiBhx7UkigsLaTqRUAtaxW4Li3p0C/VyvQG470Ajz3u5+//Vbjs4ZmpUn68GZh4Xs1q7lAQ7O0AlazcKf1rxhAoYc6nmNEB22m5h5G5qagyAOjHM7j9WW+pv17D6Mfqyqfr6o8Y7EXz2lbdFoBxPd/e/njn468cpOmeZ7hTg/jJ2+5mF3RtumUArOyuIq9ZLZML2k/NV3OV7jdW4BdVFQXiA9hU8grADRnW7pTGAbgPY9Ts5x6J6s4vYzP89Onq/XydZ5WQPs3U0Dpffn93zC+E2hFZMCv03ydU7zJFW0RfX9VXUCD1zksGiVVSjWu1jCddtQPYqN34U03sxkGayIp0EsBbSqzeDPcJk6XawzcWuQ8uIEzDNvvYkJpXsSLCcMNiuW8qNj2oK3KYV9PsO5JvsDJmRlghu+TQBfxPOdRIk5UmM8YBNHAgB92PRjgqvSSJTS4yJLpa2jYGqirYKw60WJ5iDurMXBKTkMWeN3ITDG3tkVcK2KacEyT+TLLoUpUVtWud+7oBb4n6OG0ae6oRajkDCwSBsp6xTQb8UFOxUYCW+yXx4qJl67vvWAvz2W4mC7njPqpmxk/0sAZoXDU/TKMTQwGe+MDbBDpGn7x9MLrUqSzBW2OsAzYkdgV4TJPUIVtlsVFwJxMMEOJzAr9Wjgd33w1wQJPdYDY/RX4/T0NEY+OrVvZ9yjfQLZNVnGWwRyc0Ow0Oj/l4SacxdKqHoyI4lMOj0OAP2Y4KJCQw+IzQyX5psXfMUzWt3u8vmqkxeqCQhjkqihq1saIAbmRyeCP1BlUmFaNcYhQkasEb5oV+oCy+VVfBKCBDsHJjKLuCPWOZmWrarMeOeyOSH8gVLpObgexrPNtxHsRsfsvoNRzDQ+sbaHpI+uOyN3EiCzOfokQBzyEUj+Os4jldofkg4KEk+7bt/CD/hrZryZayCW8AC8KHxZnjyNIV0WU9a6sGooc3lQzFo8PS9xMTUg1+JOXP/0XDhuGwZipk0X+pmUwQLWrTV6s49Kc6IjlK9bv34ABPcl30G074HLin4AW+wBZmz36XL6pobDIQJHGpxRD1LFCAbUKf15lJPAQjHor8J5gH0DtldcWs+SQIjZQ/8GqkXE0FH9FXUASzdSBtseQPMFerBPcwD/E15Wubr3AZoPIbJnUIC8ZyPaHv3AG836JPMFiRmmN36C44jgDiGLCAeCU9wA+nzAqzYbRQQ0c4m5YS3fRifzKCKX4Pl47tBIofhxhNi6snGm8ZJ3Hl6EWNm8G0d9o/GyxBQUKIksaInl5KfRIPpykQVFQ7mK5OOR85L38t5eapgfCmyuCMMwgBzFKVIXNoWb116VUIxkbV/mOn7qB/2tJDOnisBfKxy6C8IodiopaN3DLnPa0URGdUPE7rB7OYHXXKtIchde8rGCsura8nACrNi8vZhz7u64v0IUfbYGx66CTKfYcdYfR1+Y5Gj0N83ww9u+/cm3W0uBVuwXGioPDWehefpbwCxcOv6AbAf3ZUnR/hPVBRGSzGEkcs8PBp7dEkNUlFgjoaH1NqAm7xjUC58gdVoi9Qp0NmXlYhiX9IoQ8PNFIen8WM/rMWjZYR3fCh4tP+HHrtCibTM/VO2m01rEZWZ4SIL92lqZZPBnPvOidNeK7iix0WXxaIksmI/cZhyd4n4S/oUmOoY73nuPdB8xxeCQTMuWHIW/V/+44t4XPgMWSk1XZom5vU5+71DvhilHCYGHKAlDvxHwXOMW8N9Hpk4ZcEx9IKOzTW4SLlrlJ3q/awgvqHpiPJz9QRn9s+aFxk+F2OhFEvTDTn/N0VhpojLz/ESzTHar6WGtq0/cPI64GNXE1/HjiqvMO4mrx4bQSzmvny+pusgtJR+BTdJCyUos7STeAfT/yDRF9aLWHXL7k9ZzHV4npQSXrTBc6lGC76QQUbclxAFJGbnGgZa6pJJDpJehg0cEiz/G6h1cUavzFyX8W+ZsvAu+Lk2fyKd/mi+qbap7T28/ffI3vwJ34+m2xyOP1t7T9gO9viqy6iPDpIi/OLyp6XK4LKEG7DPQ+3SxSfMHnTXG+xN80ns0ob+F9cWMKsQknkQ5IkeOWJ+CBKjNFncXVJKDsvBNv0DkegeyTKc8pRTsxxItx38Ilrqmieng1ryDQexGJEzRcatzH8c3peOsaqmyV1iyeK1c9mxKAtioW4uqJxvnQBviTSC7517U5xreqM4AsgNMCb+6b7NN187vhmhZLNjEuLtPrfJXHVe2U30EJjbdP+R3sLtlCvLvc6z64r12DdTFzZndJs5/hP/NtJWMeX+YTWOXybEJ+mQmIB5vwiyLLxPYFe3ZpF2yUV5fn/Fzi5bluprDcLcey3YNhm3KYtF5+Fif5LODnx+GxGcs0YWBT520De89R7h+heqCE6Laau4f1FfKt6jV1QwEdHIUHeVmEzNld4g+rj1JrqhBdoxCXYuNEQ9/mfQsPfATovDzvK8xO+QPrGdcJdEDsOoJ+kccrzIMK2V6yeUCd5UgM2vFjQajrlDrkGcfUtUqaz6oLjPZxdVG4puzRAXiGVcDUvPjTqVrg+LYWFWljVuCJSSBoUH3uh1S4rY+DdinPQrsJxIV4qyHdWgjZu3DdkjuZD2ozPpqB8tAlA1cYeYKOUnFHM1I+8QRaWUQhlkk6as5sexqfao1PrcanNrppcgs6nPUCHQNW6Di/e2bs8Kp7zE5fr3oD8TBU8cSuvRfrDhSsP5CzUTGKJimtg6sB1urT1UY+wy6sBLqkxayDHRiHAlTKgQojRnRUgzuh6g1cqIYmqqGGyljZADLwUDCKZUsKQf0iBDkbSSGUr669BKkUsqWI3cc1KdN48VAzl3e/tHQ/5YWLjuhX8bqaiGWrrJYr+cLuB2IBKPe4NEeHgXGSEPZChmkH0+VmkUGNTQa96k65eMkXhpweFRp7xQJ8sh1cydLevZZoPy54vPU+D37QV71pwhYZgtVO/8PsxiPrct+a3xWm1QlSA71QVg3odVAwJxLmVMHYd2pxKVS7TgCHi5FhrUtKbDHkXNPWF0NezlZSDR1DSSVDh3UpcKYGd+Drk8GQS8j0kuG39B9/TgPJyJx5FePyZgZCu/Ls+hRLKna0YQRLGiJE6N/17VEpyhoiQHh9wjlO2GivAZcKyd4ergOhUu9v2RQl1TvB1UPySNhkB1giTHQzHf9/dzmWzJaJIchSaFH1e9LJ358wY+IBL47YadJUe1cCVRd+BHCL/MNh0BR6GgSpuDdp+c2CklfpkJVaG9iNjnqCoY6oxqHQ0gnztYZ7ZhaGZ9xLMHNKIg2lSzwX2U7KZwJyX6OGvRh5DVIKc28R4liNRYtTkCPcqQFX905YZi6L5kjwpiOhSSKWA6fi/+gOgrpRSDsVxQcL5I8mjN+HIBYsCT3rFsbqCTv/TvLX8Grkc+juRVZ3wlzEV1LswrPL4mdOKmYMcEhiaNO2j69oyjMUcgeDAIFLRfqhsRfgvINQ3JTHq+2cGd45EQurI6w74wox6cgzFLFS9QtB6XayK/IVRbxemCTcC4YtIj8YI0Tu0yvvAykshWMAsGEOtxIgToDXWZQs8EpLXwzwZh8eLcoKFAun++U+zidrgbnPpVnUe2zMRVK+yGouHUk1eSM5zUra7/f4TGnpEPqfy68jgzC7dLUFmJU9etC8Pl2Xz0f35RBUj0PxytpO1wTHZbplki7JUo7Byuv5NdeKsMK7t7hIJJxBjNtkNxD3Gsx6mS/bv5+CJvvdFoUaYyqmxOax7qqbzVw4PDYGtP+O9fUCPgT1+oAv7doGYeOpHHs2QmkRt57awlFNRxmzvn+xrE3L9+WD3TcHxfSrxbC/v+lXm3V3m0/3nTO9u7D/fdhbnbTTOU6Lyb8Tc+1jH3TLfJKC/JZ9FaX2B/bRv3+FgI/JwQ6yA/dpDG8j38RUdbf3iHqgOHbwXNzIcjEXMmy8BB+JukzWi3EDTY7mrbznKHVXUe+QkkBo7FZVnfKyJpPzPNsjkhknNG228JZQGALbtJP3CdZdoQxA94UqL2iTPF6tl0nOjzzNsA01SUzJKipn9klOKmctjeJA7PPGuwkmilnnUMC40FfD5dYmnYzgMqp048i5eLvWVO3wBe5caxYFHxttUDiSjsbOJbPaTWR6LAOzFFQ4SEl3XKpK89sqBZIDDZVWN30DggxijjtHxtZA3WSlTPCoQodaGYU9NSM+ZbwWxXMxWaTG+PZzTNQiaLtdlSWk90Y4yQ3ClAkdedaDRDpGdbtbzGNeNH+KY7unvvq9F8bTJUZHhTt1bIOtOUIY0KVC4AR02kbGNcnAyw6Pe69H2xCsAPWN0yc3Wt9dkoX44bug+yl2Ae1b0Sl4x5ZVTZ4zz061ZPWkdw/hrjmP/lVa90cQ98RVD3QfqTksbqD/sYoXGX6EoPhytaKwIKgKVgc8Vz6nk+d4bJwOeddOjP+lxEzWqAN+tFxcJ+44f97tjQ+TApudp5ceElJ6sbcGwOVcnDyCMakEQroBP154eVnmi6oA+XTFbilHIG9TIjhRiLfkY3F0bsUz78uvf2SnmuR9+XwKuI4Ji0Mt5kla66sjYjzPl2J93UGjKl3xbJxptaNSTcMTIHr3EuoSpIYVap8erjfJKVvqJ+X2yBrRZiUSuNsLyFa5DqdX91/YCBYO23k/1JuDon3FAc/tMWcgXvPwnOYwTI1qXeAtCuvcW+AntJB/MZCRjvAl+XmxoKvyl1NMEEwvZyBMJHE2MPYS9PkCt/I7FthlAt6XgPcQ58I6LzezCg/wLZYVuybiuUCIlfEbG9Llcg2TLK6Wa3F7A+a+uVji3f3x4jxnE12P2o469VlUv2ngVK4RrlwREK5PKSHG45XYBq6Xe1KPD5cqFJQzosQ79Z2EA95bLi0HirfNA60kVlkJF1Irul9XeVxqz20LrzyB0CwNgMaA1wfrsaq4eU/BYRSJ8qr4uykZTq1FrlC+8wiupga9JwrlrH4X0rT9aVRS+NDXZjvqKtp0N+1LJ29VE5cOTfANWrS0Sfbr0Xu0uEYu4lbPE1mFW0F0DUzNXvqYjHML09ybtndmGU2fZUN5vyAsov9zJNaHjsR6iGIdvNf4LcP9+Tma63M01weM5mqwmt2rwV374EO05TZB+0nEl70PEf05yOyDBJm9P/n+UUPUXGvB54C1zwFrv8WAtXutNbdp4x91TfkgoXLPnnnbbqfjJetlnHkv6SpQvM4yf+7l+FFvvAWT7uEkN+oz/LjnNn+Gd3/OMIvd4IQXN21mcYnYikVZZLn3MmAXZ4rLP/HiJ7pSEzv8aXG1kYBekkP5nNOFnqQYHaNPH1VXqzzLp3gWdJNW0A+23zpkASrQBUxlS0rjEsyknOS/tngOfUKeP+qfkY+fkuRI4Acvf+ev7Igpc6zFT1cB5K/UjjUAcf4yPlxPNabL1ZU6rpYJzzo5QSQpdNfllNXGN+jw8RTBdJEqgORGNOGLbVpCrTEOiuLqVoLMvlERBYq+xCS1TQk1gvWStxGtgmVMWMAN+VaXJ08tQ1USYdwDLRrcv0+L1WOqfymTxCnrPsJB5aFc4ofyeoeOs/FIWbq3e9Jak1Hn0Buc2g3mSK3mUphEUrbc7XqHT4XSGK7o49Psh88Mdn9WIl58281knzFTs8f2qtR20+y4DyykOCF5umjCYfQIk+xMymNExv0330QkDusqeTMdeqp+x9txDWoAfVla7wL/tqAXtv5qQTLqs5y4pFphNHzs3+uq/HD/ncVLq96QcdJdmEjMO9pAUa9lDmUzNgibMp+o4f2jcdYtB2xtYtFnKToMr+DBn+faeXNmYTKPjQUnvketWRpcTvLBEYOyugwYDuMgrhX3I+QpQOC1H3Rqlr6sZSNPKIv91TGrc7lNmHsDwoxHcfdiprO6OuahG7Pw5tZkoTWh6PSuyYcfb3YhRfyjv/edY9by/YefWmbw6EeZSagJGczoCLS8JzeypeFfxY7sfniYaPdnR/owvMaSdA+AeBOugVLzGvGsbb4uwTr7ToUJJHh3LUWnaMy+Wn3LnV5muZfLTANDf6ejDnl1fyC+/y7uwP8DzAsS97SB0OvIr7gbC7VmhjBzkQ2lHDQwwMWxLHVXCKk15uaBZi3ISgNzK0Ak+4HgEKzL2lNYuKJFyTmMxZ9ilIFEFPLEhboVTN1iguOO8nUzF0WeLpq/9i4A2EExrWw78spx2uK108W2sootXTKlQA3IDtgSB0aKIPbQ6+pY8MY+QLSF9HSSFdu0tQ28ERYeqcEhIG5/0vOpN2xaTtniXr5iHwQ25picW2pOGXNJzVU2nW7Ce10R0qRolK+Q5rO9t3/cW+lQE9neBH8s5zzwCx5FlK/WWQQryEPQromM5LabRqxYotrUaFKP7ozxXTSl5ltN3kFd6n7ENYm8cpNqfTVZLvL7b+n8nu7tMrZkkPnlngy+1CBeawCvzz/cBtA7bOTEs/NJIT//4lg4HfsMgtywvoo6oBnhpkSRIi66dm9i6Gx9wzz6LmBkE84hN+TqdwEBt2wFIuAGJ0gaMD65EbsCLijGNpJjbrh8rgMC1zCGudnzhVv8ctXVpHzVpRWic2P2EMtF5Bwu6EB95JJw1fiF8Gh/EYwBLltWbrCn89flF8EAm1m4af8CMp6Wyy+CkUURcrirgJwGfAoA7tduSDEd2FSwljU+3jzUgh03hhfBKTKNbraiQFZM63Z6A5FI78O+BFosBTYONc+rGFM1nJSj1IDFRJKhVCmDskDcX2mk+vVV29exyoZoCpreNonVSPU5Kl0T1LFiL5h7mfe7bM8+Gqr3bO0LQtr1ZhKozWjQN9r8kBPWjsRtcXtL6ht2Wll5L9zewvY+noZAu/9tP+VyW1CnPL1DSbXWaiWN45CaJUbZ0bWBKWCFbvQh5bcCch4RbC3ZQySY/CaxavsZHBXXVnW+lkmKKU/26H6AhdPNSMZHg2ScVaj7EwUGr9TnmzV9te9xGfTzus3y0bUDH6u+1oVs7kfazHjAnZSO2SFFyt7pIaHaOjUujY04R4G0I+0c951QWhNPR7W9B5raLNQROediEybnlNSxNUzMxgaa89NoYNow19jgX5t4A73wjVMdwUKmsNfmzY22HEXXpvTW5tKNw7wvXx3RGq9dzchEiN5Qk7mN+S1p0Ei4cZubY2ZusnJMa1IaDVd/6qtKjagbfqaJToDPziNt11DbjrAME9Y8DWn3A9spbAe7xVVYrspG8FOPTIDEdtu0W/ccTbrFxK6Ze3bDXRZ2FHXk1yW5TR2RRY0WpG35IhYyIgmTRIQGag1PbxCRKVrDQwjICLWxDBELbqE2GZuphAy6AR9AbfykfmthhqHjI6cGTo7bPYcN/6cZ39oAStdRCQK+PBmGZbsdUL5/Jw4Vc6U8+6RYVHnE6ENPR/SdJ5X6GlJfn4zD16qx1qmDxmZzIVScqba/PqP4/c4n0nZrhB/cpE9oOE2fEXlZhXjWJMVrJqG5XRdIs88lvJnFJoy7m9DFNWPkGjd/1LYWrC7lJBZnDkl+xwWFS65Pna006c+CHD9ax3xazPnsmfcl++R1CsJ0k5Q53juObgowPg5ZRNwhriaeCLXDM44xHdzbFstNObvyKCjT241HXrJZQ4O68VOD8RmyySqGCTuJXw3tCWApHnWlxKWvGUgTjlTDVNedBDotwfI/vF7i5+v1LRprag1D+/46c8eFIZCmGnv1A7sHkI0s+ouz2v7LqSNulDf+NaifvC6hBRrMbW9oW9z8euEk6dOQnPZsfXCjkt9Bo+7COJ9qG29uPTbCdhX+iIf63t8ewm/+eKDxCiz0WzsuuH3n84LbuxwY3D7sxODWdWSQWfT1w/UPP0dIcQvmHqElyT72iUF7S4L0bG3rgUtC64zEvc5EBN4T5Nf6abstGuEtxdGKuZt1VP303fa+1wvPQBVgs5Xd/JANJ8Aq63ySVuKjjH//aii/n9cYbY3JwDww818NzqLrlnj3odDh6ZeBlfBvdsJLO+ErZaJoFuwALVj/Git/fTDQPmG8BQsu5Mntrv5tY8w5PR37MrdXz8VYXpHdr2f3Bn54g/0mznPI1lKnbQcbbzKJq2pdJJsqn0xarS0MwHI9QdZv4XU/vjzWoZhZIYBe300uX42w5x51dtnRKI4HR+Ogs8vH6VFyNBzBY2/Q6xx1sgQe026SpXmew+N0eJR2pvEUHqHEUTrqxfAYj/udwajbR4BsMDoedroBIB4djzvH4wwRj5PBYHpE5abwb5gkXUw9HqbZUYKIR8lxp9vt9QjF8fioe4zY4tHR8aA/RoDBcTLojHuEeDrq5r3hCIHTzqCT9AcdpHg0zIfxEBHnx8koPYqRtmzUm3Y7wwweO73BoDsYIuJsHHfz0Zhgj7L+NEnHiLjXzbtplmP7037/qHOU4eN0kA072fgIqRgO4+4gR2zxcd7PjztDBEjzadyfYkNHR6Npp5cdY+uyXjxIxzFRPAWA4wFSPD466k5Z1aPsOBuJRufD/riTIuJBkufxYIDVJVmeTmPENh0lySAZYUOTPAGCjzpE8fg4OcpTJDOP427vaEqNHuTTfmeMtIGJMO5mRCbUNsg6fcSWj7Lk+DjH1O407h2lRHw6iNPhaDQkige9416PUdHvxdPpMbY/TqAR/fiIGn3cjxm20XCYDI9T7NjxtJOm6TE1aZpPp4Mj7KvxcDwYZhnjimk8PsoHxAp5L81HObYp7ne6g36Xqss74243xg6aHg37R/kYsSVZP572+khxL86Osl6CrJkn41HWP+7eOBh+bPB7yfj9KOj2gu5RAJ1+6+OjYXAcAEm9TrD/aRB0u0F3FPT6DY+PtOdR0O0E3WEArHzb401oSU5zHs+yfs9arVb+NZO8SrxhYNlb/bV7dnIyNlJ6kNIdGUl9SOoNwhuLACmA2MN6OWvJpF1ARqakYHdysvDftnanp61+7xCU8xo2YyHYDSZo3it8ZQWyPTDHk27SKiH9Vfe4dxbwj4/518rixpJz5f425Xl3RAJ9DmI2khX516o3Of7OWRvQtgcHr/2gltndl9nbl9lXmbqTAEmOI2hu5yxI8LcLzcZfaGGGv32rMczGHw3IyL+WOKYhZp6HsKQX0FT/ehq1kicpjEHrfxL/SeaH51ER3vCvWwFMv0cw2ZOEYDIfgAGmNTwo2l3/SXeoAw/GCJz8kv6SIUwfYIYKBrLSX1rJW8RCOI4OCpYryauiLMyiNEyjJJSJl9voWl+UwEq8z+tNmERJWzFj3J62L7ft+atzHbIkr0UcVeEND3HBEY7ikPq6DfRQZ7eBOOrtNlD6qMb6i0rn1XlelvF5Xspzc/PyXDEm41qyqfIFJge6IoNQoMuok3PVsopnCBaKIZ7BEM9A/5jRCE9bhGZ2dtJ5+5Y/nnbHfZ9NNdDzOYbZWSQgh6MXo8FzWbDb67zo9sbPgTw/vDHY6U28qCLgJvw9iQCAntqQBFVTnDe1YAEkucgD6lTtERb1scSi3QZikBkfL/z6V0fdM1pWsIUKtlDBltpPNSLS7cnixfZ55yyc5/Myr8TE2p4FnUBszxMFodivlQA0PrMzCcY7xg8lyCuedBbBitUJkcLRAEksqpIpafgqCh6MN6E5Icmf7St0SMjhuF3oGh7iAoE4htkhhsGQAyT0QKFVwgl1isGwB+tjcNvjTWCUy6dpFidjWu/3PlrljsdJnKVT1Lr2P1rlup1+bzg4Ql1k/+ON5gq0xX9ZBawHg46PzIOdeBoB5/rNkMCoGigweDMoIjI+fatx26LGbYofDXtALsM7lM6vzxAQ5/XszDITdlqyaSbspI3Ac3tWrrAReHbfyiYbgTuudFurQWYlm2LG/XcwDyareF2VturArmNjd7LKG9mU3wTDS7XoUrNwuZmKwuzRAcOKs9JmvD3DS0H65Thgnij2rAlXueIfpD1NdNJN55GiuM3oaysyaFWMt+eRqvBZLDPmxS5qqZy2IOOAk+BrsOt8riH5M8sgJ8o8IZWDEALvmM4NqCKYJ34oJX1EJdvzWZtFYAkJaop02fa4vFSDDw0hRCtNGjPxo/qA5BB22QplMEuHJfAXxGQV4jFgRgFZ1zRpKKV3rl6SpTcUms8aqpk3VeOgTYECG0QwILwL+RygbrzTPOiOcCZYd8fHFEBhqZyU1siIxMllBJqlSTskIOFl2Y7wSEdMKojkxPIZ5kv2K9sMpnPmH7Cn7vDM9wUQ8V35Z3i7O7Pdl3s4vbKj4/c2ijbm+hAChDjVDGvio2cH3td02++P3/7tv2lnK6YTOXijCr/Zk30qglpMz5THuI/dZEoXqx5wGePhYZt4ts7j7Mq7XCzfLMRlxVD7cos7hW+WHjuhjdBpjBcULzIoM6PtxOU6Xl8hPtyWe8aON7HtjXxBH54vvel6Oad7P2iH1rtYghBbLld0h6qTGfnJfRLF2Kw0nqWtxlNh/K5MSzo/5IAZF9WeJaubwDnSxOHMV/LbMwS4p0vwe5xzk6DCBchbit2XlzykWoY9aXns/msG4LqlR/ccKs1cfC1Eu9m1rT5So4m4R9YtsXSkShVq/oQJ3f3R/EETRcpFXE4oiJuuihC+bRsKJq95fuwZw27DzdnVt8ZBMzE4wMNiYWsqDnMixptz1mZlfzagSQ4VOwpLN0/Rcgqcbn4UTryYb5ch0Q1FYj4AHEcbv7uGvfOCd8xz+a0I88vrQInjw+uQLL+svplqNzRQba6vqlubBgxB7a5XYUUQHvsyYcRhf0TmxnFmBYWghpykszrltyxFTPDedR4pfAXAhjBumYu+78KjLf1uHC1TEfCbUVn6gBudqRw48bAxvxNJnPksskCTIm7xvSZNwo03scgSI5QVYOJX5leGcNMiWy5yMTqwXP0Ecp+tCqOBl1xV/PJvFm/ChQZL3tDEivHm+kNM8f7rHz8QHzwV13a/jNMLdoPUclUVc2CzzPvHKl/8+OO3KBjVaW86qZPT+phDGW+ZlPl6C9CETt3d3VIMcwo2PYoYpm3qL+gfYFfuaiLXTmBy1nGr2oKvs/MC+pS/+LTEaxNDiE9DZs+Ls6arPvmpXbTb0HdrxiQ4XWFGkeLW6aAvN98siqr1xFxw5kasi4D8SfS/AzzQCLCKutseOa+lFj1Aklp1gMedHio56JDtaw2HUBlpYA9HA5XPnSIaAgxiHw2kUwSKaei0+iGDu0UMKl3+EaoWvSOP3IPF3CQ68uFoj5OkphWk1S6q9bwJpo0R7iKqqvy640HbgCRgNuU1QDnfrU+8tB6LHB8rbeGurrEsmKigAEA8juQqw66UVkshEcR0QtSI5DxvMTSBXJfbTMa9IKH2vOObgc3mJ8XwOy28vH2DkLjP7sDbomMQORSdJRuQKUhFiynVs+XifBIHHp2cTmY53lKV+KA//yjOPDPJFpjqdoCXHpEkogUftOgd3mnGdWqsZ5ZDRSjQhHwkBw3KzUf0CRB+VNuL0/WyLL18m6+vPBaC86xcwl/1pRESdrXL7wS/0C0ExprLrsFLeyGfKmAWyCvxaABY02NoKhC3Mu7IawICuu0PkcXkyogXQVMZD/drJDfFb9/Gi5Oo8/bt45XyAnD7Ml5YVlW8cNiXyisCRia/G6Asg3jhB8yGPISMA6AIzU6ZXzM+Y6j4zMdiuraXvMLjh7QCLpqsTh5Bs4jkxXWLtvxS3sKhtrEYxgD1NDYz0BmyONU1Mt+/xtyaCrYgpx8pW7y3etyj2mz7OvuQ6RHNFq+CgtYUbpP3kbWQHJ4i2/khJv28QiaViQGdwiHilUDwLWEAsEQ9IYcXaSm3x/hKPAsCyen6czMpWJyzK86iexjS6f1w2W6G6WYbW4qrV8jOnGB4TOA/vIOu5uXaMaeG03Www35mfgPeL6q/5YrAOtfocBTnu4QEHyb/FT+PQhIRc/ywUeAiCPX54diWrYbsZFeBHj336EtHsKb/k4cXMx8AE1bkTliwOz/pKzFvluvsmbwxwitjlIXlU8RGPonLPF+x77MIJwKMqfeShCcI2qpk3z5CAHRbSLWPxzQnXnkRr3JxtWgFHc+/NONdgPa5zrMS389zoAnYhV1jKu4jfWpx0WrCAs4XS4xOosjH3cAV92iGPZqOXx7vaYU6ap5lDKXS4xu1rC0rt62V2aaBFtGoZbCIKzOc0aSH3VhDLcQn5ZAW0Yl6cKIZm2i5zGvzwMzfXQZaLKJGo4rWMgIQ7fhD9DHKwEDrajim0NIR8tD0CuHMmWpnSNus89q8d9uyW9qs8051G5h/DEVJVK5HsPS25nuqnbTyQ80Lrx8OBWr4sc/rRmzy3gMTCz8XeoNWDD/x2YxDu2DBxCIOhSIaddizGZF1d4KJTJ0JRXT8uOeehonbGqyGsfOg6vYhxopFKU5tStaMtK588oRfsctYuD4EEQx+bWcmsnC/wIvMnlNiyL2AVJEN1nkuiQiZgw/WCn2rhRfcvw9BpZiSIq0wv76f4IIvmYEfSu+ijqVzxiU4O1H6angWXe+7TmP/fRy335+x7x6O69pI3NwYobeRDLyl8Fotuva08+QJAJxEImT27VuVecIyT2Wmb4bT0vXuUSfYsuiBYDrDvyU9o9FDATQ9emNhCCEP+S15DELojF7AI6U8v2bDmYEJtHcKFLYlyQe05W+2b3va1LjtiWxZAirCZbjlcQTbENoCv5aeuQ2Q9hnniaysbWNQKeKjDDRjzYGFpYCZwpLQMyYj4HZWhtRXM9q/wsF7IZiPv6M2/BzTbHyEAHOJnF8jQs62EA84zlDc2BX9esg17l+DkX8wsucpnQxk85FEJpWJhv41y4nq97ZgZWG5iFibZagOFjyNoHPx4UQhwElCt2o9XWEp9brgZbnM74c8wiFq3jrm+xGanGPkBERLAP0W8L4L+M2h5SIoGQTd88V7R0ZlPAE2pWFVoS7DkTPWZRAS17fbWviEYk7KUwwqLnfgtdBvh88GFCCipTwhJCoi+AvPN7rvyhX5g9gIFU4Y/3HUESQOrTgZThTGyjSpnDjlZjRZ4a/LnjcW/96Az0889SymKtVHOYBm0BRMhBD1oeW7oZwK/qONzUAMTnM/4NHt3kDvhpE7XKixC6iWgFXW2AeslUPWymFzK4e3t5JVpLVyeIdWDulIutbKo/u2cshaOdzXyib+ua5fOm1cLs2xq7Pt/G5p8gLvuTCa6+3sumjXGXptcj/oGP21VGQjLuJDebjgxjhS0I7UWsIaXo9yedRgpvzOjRRrxSjOA/0k1m/FhEGvAND89i0n/ETOJRjcRs9EuRIxf0/KVdAJhIdo5asZ2+CWw44SnQSF9cnbC/8VVlX/s1X12ar6bFV9tqo+W1V/GKtq8GlbVcNP36oa/UusqoYTD807LKieCAvDvhALB8MwHT5ds2b82az5+GaNZc780S+cYIqSJFsZQrdfS/FbvnbCoN19/YR1j/0tV1DIfsQ32YsP+4rph7qigksnxvi8eZP5MsvxDkFSidZR84akMd333OCgcb6mqCo7SRkWtrlSw6qYU/GlZDTBY4q9Gj98KZmq4bOXt4uhQI4MCsR1FHVBvzXYxOQaEL58BNfhza2933X0/qfY901XfQuJ8BsZm649Ns4PE0TN/ez8ohF1U9TYjWHThfpR43X6rhK7y2jfhfr2QYTiPGoYNH6j6zN24EJ+zhjFkPZ1EorDZ98noUh7/oUSDQq/UcJi8kU4rNPT49VcPTKY+N38PXYQ+G1uH9dnh70G/48g8S5OIIF3nzNIRgvfySMkMO73DAmcd3cPydO5t7qJZPvv4CuS7d/nM7LOI1h+GzzM4HIeYYy0y33kGMoo6rgnAju3FNWqfEGfHINVknmVLAJV0L2zaEeU07hFuJsmPFDTOvxin3nZf+7AwMS/eqT5ou5wTMCFQZ4SqB0QEUdYbHfVo/1Hhlwe3tqxIRlbXc9XvmZHKLwv7p42r7aeENXv6DyTauAH86JZH8vQ/OQ3dkiy7Y0vzikyVrrk2bvml2cJPvPh8LfJ8jISF5qiB+vuTnuODXXB+tVlxukMwy2oLjR7uG/QeYNZ5Li/rH592ZRfVMZqpL2Ou1xRRmbJeVHhsSuYN3uO7UgwnD2aG23CQlrDGl51nivSJ584NC3x1UvyU2ORmsMvtOmqUl1ePSKHVXHYtc9UMG/nnhPYdXBy4m0P5cfPyPFnXfNmOeyiod3NLkHMvIX8W5v4rGShA/t+PyJ9b05hEV/buKlhYx8AU+5ETYBIx6JC4wJwYbWvhxe3w/PL4QPrq8VW85rOp7o8lHSdHT90yg+Xus6V2v+EB1M2LdAOlMqzpOIYqemdaURqiP/AIczV7fZOHO4b792gjTbTY+Q6JfKePGkkt0nGCk8il6r7LtdvxG2MIvu0OOFpumJ/Hy78Zzvk6t64/c18V1edzmZ7a5K88LDr/m/FrVx+eIGivD/xNnuuu79/bh7dL+fm3kzZpQW3zhBNzHU7374f5noHxvq4TPUhGOp+zNS5AzPdlV3MlIb7PTWvdfPtnmCmfxdXxTYHJWGRe2V6kWebWb5+Tme9yjxepxeUVXrrzQIPJRRgli8RFLQ4UP1nRYIXLHiwxMye4ukv426G76+qiyV98D7Ny5I5czerwPvy+78dwvBN8zWs46urYnEeeP97k29yPCIL60+KJyYQm7rYgao7FNUVi6KiUxt0hYO6wSFdzufwzg5xTGEB8lZxdeE8ZPbIdhin/GODhlc+fNTskQ8tj7wOK73xoe6NDy1vfKh54+ult2moeeLDuic+ND3xze4jPEGZhJpBxpOX06kjlSpTdrS25eHw3Ye6777RGVUngFLt+sUMbXBR1bFAmo2DzWxG1mV+BTZOvQWWVz80vPqh7dVXFkp6sVlc0l2tLG27nAEDznK5OaEZM9L3b8gB8YpzSjwzKsUbdxjwM40Lmp2oysEEg2Fm8yB85GbnPUVgwC4UdVg9rDSBtr8i91aUc9VLVxuAaiTmNYyGjOfj+z4uuDfL9WW+bjGI5Sr+dZP7+ygGvN7Ba37NoyPzwGdIwjs0Onp9eIot/1Mx9aC/8HsGrclkViw2u8mEbsJWqV9+99UP//jmK0gXHioozPrgFLcy8BH5CRihDF9+//Pk/379wz9aT9LSp7cfv/5JFQgomdrsr6oLPESHZVG6gey6mixWLZU8m7Z8YX5DMVb25tGf8kVWTB8py5IPDLZJ7dK88IzX5x4SIcb1hNrPhlbu22inTdPNOtLAdbP7cclKopvMssGhlI64ZoZD/qmeXzPF8+wcfcMaUiAOSrWhTjXJDpFcSD00Uttdw043CEO8p1rF+K4R4i54wgue3KWgsOgvYUW/PAHCdBnz5InotPDS/IhHk5MewKV8bIsXEGmvLi3rru6vB2guEtvs0VVMkPsrkPsrkqvJdI3aX+vUiqG6KFhAFVNjDh3qS33FiWRFgjy53rz61WW22rtUte1zp2aEbMHDg+mJLNHDU23jSr01qonY6ZfnAfsRKLb8r3xP2V/xztx44qEZOTQ7kK0HKGg9vssNLvbYWBx4P0BO1Da8SJMVjIIYLym4gnEAf29qp9J2xQtvjtzyegKjHTwRKqzTv4AbYY02+BSkaHm1SCfJcjmjCxxBDE9AmZuUb+IVmMWM34JO0N2rXwOc1K6BpFC+Cz7kvyoDVzScsHxlC29HzSZudKlwsK22X8N7WG1cnUZnf/gAPR3FLw5we5+uzpDfHmMiV7+WMyBiTyR9LdbkrqEm7qh6rzGs3rPi6p2IXRH2e4JMUMQELtU2cGm2gaXY7v9eijMuRUNL3EaLZ1BPXa5qiTDMtTTQFwKpkzGaTF1zT3yL3XaxfAQOpdqNhi8hQU2pDmo6dWCr1LcFy+w9XtAQKlOPlNGTSG3W3rnqrKXQ0KrgGhFb8/atFlkDL4p15Au0WT4DwW/falxCd3sIih+rUYcCcrDFM4zx27dqMKmoej3t9zRMchDxqgU+duKRaHjMx4c9sVw2Gm/f6kNhEiiHAKBlFEMt9KelWOwEP1Duq/doNBz2R7fr16BZy32kC20L6ULc/lNePGUDEHHzmiWgO5wb2JCgRibSrGuVgdC2mQ25IHhwvzpkj+wyWW5nQ9J2EW35A2VxKxsT0ghMa3pgOamBloQO264OxSvBKUMbkhUDNcRmkK0qcEoOi5ThLZNn+ukGlcxi2XUbHLK4YIqE9c2TaHtBt8GxTwRvuSNBiD4BhpRJi1wkUocaFjnkcH50RYsIjIxRI26bswTExS1zSNA5N6ob6QAhOThSVrpIRlzSWKdEJlIiabAjkyletq12yJXKBcwG+arpuDKN1Ao9gWsNehJTG8S8enbgfSO8Uzl6zapinoOlU67iKr3w2OcOPWb6ld46TtGfxi6NW+SHBEy7HvIaOGZD0ixEj9YkzstubzyJt3Exw2udWuLeGW5OVl6FN2DjV6EarWv4j0OQiM5y932FSmyx7xVImU3li7On5UUEEz8Ur1z5igqZIgzLSMlM3N1U2WReRVKI6pnK3hVyVc9lZnYkltAX4gHynh+aJqLomXSd0+Uy1D/FWYCKVbDHYxE84ZVRdPU1zjUgMeqG7GjGDXac+BrdjetORMinjhME4PcUW3rt6oIxhH0cqQ73rfijAqWq5FtyRygHtJZzqyPaZndz01syva+tuJExHVQNbC74xlocWTNFQbOVWV+mI3MKafHXt37QTywHBe4xvqcga9KDdJ8uU3J+I3HXzpuE3+NHAN9nbLWK7MZb8XZacLf23hjf/Q6fAtTQ3/lrgMgW+K4zhQzA1qLJHhSTTQQ5w7K1/sEv9Pl6h6nP6jFI0XH4/T6dTF/rVM/M8g69+8WAc0oiDaXrY4VFtpMfKyQgpy+f+jRq+mCfUp0av2iI1Vi0OD9qiHCnBpzjDlQzQBcvc0by2p68KhixHHiuEM/bP3i4/5OFrg+qPvzzhP/iTxMKPoPuesDXCbGT7/ZNQnbv5dFzb7opwQip3iwPM9CbFhg3HM88umKSx//6MIzmZW60S8k3JukgVunF3mpdLNdFdXW4XGc529cs6SPVHE2Auzw+qT2gpqWgnLFtU8TFF3eP6Qyll11BjxW4IXrlTXPU+bBY6C2W1n4o3/MMPLxdLl8f0jWc7HpM3N0paVPVK/Cr7tvlbJtnT7nj4hI6Oup68xwvu4cuYFufm/U6lyuVF5eITt1qzyJcdQQdCwHGY0PLaU7EwknynrZOrSnGN/LqS+1vfDM10B1N4hk7++PtpwYP3kUN7rZ3SiVwOnC/l3xZrsQzTGGGg97cGGBOTITwoxeEZaXwzV1ovXyDlAJdMHnoDUuV/DJYeNWKiSTEJo4MdHrD2oX3B1kRnxOeCU3+gKewMiFXRSDhvewiGzvGi3xXIX2Bc+9Y9M4tO8mO3WPxQl0qNm/R9qia94/rQMCS/LZdtgvsGYiYtGvcAtaBmjd+bVTewRux7WtnOfZ8LWKjN7hf99Cd3jf33up986H2es3tV3vr9HUR8T0WWlxocyXOMtpbkQzVNWOZXxenuCUnJ5bvMQv2kbnRJ2AY5716jd99r2QqchOmGZgvCvyu3QXDr8vyt28ryqpYlpIEvlf/opz7oJTCSLuISv06EI/G9p6li8lamdOhwsYkWuJyxdIymYYOhspq3+PMz6JWfBIl/ouu4Vf4Q20E19dB9yZu0RR0LSvE1fDVr/jlAFwOuVs3pIKROZxeU7y1d/sOs8Sn77y6MN5th/s97k9zqf4pbEwXvIxjNzoOkiBzl/yDbUBzWXRRhHfek36XrWeZgBIpqoqPtBft3m/mllZ//Jw0IDKuel+pKNGnnve/YNEWxhOaKpyp1/HiklleTLPCdxUeCqrVFkwVNLxm8fo851YP2VwUygnCKi0W5/zLAdyigRV0uTm/oOhTQIzYshzWVeFSjwHw/OJQUsOLwRT14mwbg9XmVUuvgGpxmYQ/8Tq5IhVV/9JXTYcRLf+szHyqyoxDl5ktQaIzhcbW3RVRs2W7e3JRsEPy8wLWeUiB99PTbsiWLM0QeAUAZyfR68IH3PAc0loEVeDzjVF5Fs2WZqQZKkLZqUmN48O6jHKw+qGaQ6v67MzS1ubFIsoOW4ZuhaF9qJRB3knHJ5COXSzeRRkDinc1rc2nfCvR2E1hJvsuQuRtItbSB7PdCRGHWmG2O0WEDU3FK2guoQ0IZyChDFIe8cHWHxuQqcFWttwrQmBqdE1q6TtrpdnuoXqpQy3NblNLQS99D4rpb0ovvZNaej8t9FrTQR0qqFsDvb5d/3Sqn++kff7x1M9PVv8kBfR96J/3UT9BRP7xFFC56cu1I1QTm8Mepap2j/jHW/eDaz7q33FoZC0RxeT7DZjUHMf1VDNgUix+tTTmpjX9y+7KeNgHD7AUr82t+D3GVGq3Y981yrIhqlJPoP2w5iBLFrKozxsKUFTzxoxXbAjAfKy4cE80pmIpKCE5STxTNOZjxTeo+s1yF56PFovJemF/aKbOqyddX3+NyDrRU077PROi3wu1U0PC4oj08WjrVoOC5p+rjlAnq30xt6Vwtbv+Abf78FoMFcfEvxRqhy/JS1/sQLMMErITzUjLDE1PN3Xexc6pGzn7LJwUO4uVA9wvCMchWTxd/7lWE35hkf1Z7NB65G++tNnaqRVgtdid9rqDo8G4Pxocffutf00fj+N9JgKgDgearihwtbtnNCr+Ymd8zLLmPChVSK4WkSsDcu14XDsc96k2haNbAzQkeJ3DFCorfrdUkbu1wF2OlAfv2rG7InTXitwtzZhdZ8guR3y3sN3SHbDrjtd9qu2pazu+ZWMYLyelFspbi+QtnyrZFqlHlb5cRfJJpILAi+QuLE9jNNi7seVTy1yO1GPIM7k44JuhPJGhsx0r5d0ijl0Bx43xxreHG9vRxnaw8a2xxu5QY1eksSPQmKOQvqhIzFbZN2cCxtDnMXzYDEJ2xCDXI47tgGORQLq6EGLvGi9c82PeMVhYX4GawoWjJ6UdwKuUtBfq8UFBvE5/rR3D+6FCeA05bgb16h0j18W+Cut1RvUKb5PBN6EW8qsifusBvE2hv1bk7y2BvGYcb70WV0CvEc8rIUlb1DTHSGfcvWG/bAPi6DnYO/+88miEjf0HEVEVl2XOv65JmwKH6+UbMg/gtUzXxaparssQ9wxkmFa+xnsvzAAv2n2I6SPHcUqKen6er5F/PQpugxr1Cy4oxOrN0rvYnOcEFK/X8VXptap8QZ/qnBezWbFkz5zUAjc+8IOi3XHnku18lP7eHQhs+ufdh99SKAXffgAeRFgrMKm2AQH59h4EJqltCCuMqWEnAmurb0ZgqrUdAUnoAoefU4O8Bs/6uiOgeOjVK3g+C9ZdRzIoqcEaV81193DdMWvl3wu6fdvDai7W5tiAoBLP1jUHezlbViyTNhYOLAi+RdHh2xP1sBUsj9n4exph6b07DjII7dW608Yyn/xuw+comPcYBfO7j3r5HPbySW07fPy4l88bD7dvPKCG9nnT4Xe16XCH7QU9Gt1KJo0gMKLSP+9Q/At2KLzfzBZF066ExmQAL3mL1HcNXr6d4k0Ov/Ndjc8u788u74e6vLX5FGnPIcuhuRWpg0UsleGyzPg/sLv7o7myWfdrvoD6/uEab9Y9UWOzrm0fxpHhpMBwOyOh3TWN3Rgt9uQkhj+6xW45bq3tv3xX6RuANcLXZ20tW5cZB1p6KzmMTXcTIjZ3DNUeoYSr16Y2C6G87t3W9yrqxUQvnmnOaQmvfez5cPh5q8F0zH6sbYb9mwq9z5sKd9lUuJ9199mw+6MZdtrZZCsVCwbGGeXPZt1ns+4BZp1iMQAXnPX2rb7YfjbiPhtxn404pxGnZk+kHkOWTqqAvFBC13eteyU+G3CfY5E+sIHw2Tb4rdkG/x8RBoEI"
_EMBEDDED_FASTCORE_SO_ZB64 = "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"
_EMBEDDED_MARKER_SO_ZB64 = "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"

def _embedded_zb64_bytes(name: str) -> bytes:
    if name == "fastcore_c":
        blob = _EMBEDDED_FASTCORE_C_ZB64
    elif name == "fastcore_so":
        blob = _EMBEDDED_FASTCORE_SO_ZB64
    elif name == "marker_so":
        blob = _EMBEDDED_MARKER_SO_ZB64
    else:
        raise KeyError(name)
    return zlib.decompress(base64.b64decode(blob.encode("ascii")))

def _package_file(name: str) -> Path:
    return Path(__file__).resolve().with_name(name)

def _get_fastcore_c_source() -> str:
    p = _package_file("iapp_fastcore_v132.c")
    if p.exists():
        return p.read_text(encoding="utf-8")
    return _embedded_zb64_bytes("fastcore_c").decode("utf-8")

_EMBEDDED_SO_NOTICE_PRINTED: Set[str] = set()


def _embedded_so_supported() -> bool:
    return sys.platform.startswith(_EMBEDDED_SO_PLATFORM) and platform.machine().lower() in _EMBEDDED_SO_MACHINES


def _extract_embedded_so(kind: str, so_path: Path, verbose: bool = False) -> bool:
    if not _embedded_so_supported():
        return False
    if kind == "fastcore":
        src_file, sha, label = _package_file(_EMBEDDED_FASTCORE_FILE), _EMBEDDED_FASTCORE_SHA256, "c-fast core"
    elif kind == "marker":
        src_file, sha, label = _package_file(_EMBEDDED_MARKER_FILE), _EMBEDDED_MARKER_SHA256, "c-marker locator"
    else:
        return False
    try:
        if so_path.exists() and hashlib.sha256(so_path.read_bytes()).hexdigest() == sha:
            return True
        if src_file.exists():
            raw = src_file.read_bytes()
        else:
            raw = _embedded_zb64_bytes("fastcore_so" if kind == "fastcore" else "marker_so")
        if hashlib.sha256(raw).hexdigest() != sha:
            return False
        so_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = so_path.with_suffix(so_path.suffix + ".tmp")
        tmp.write_bytes(raw)
        try:
            os.chmod(tmp, 0o755)
        except Exception:
            pass
        os.replace(tmp, so_path)
        if verbose or kind not in _EMBEDDED_SO_NOTICE_PRINTED:
            print(f"[+] embedded {label} extracted: {so_path}")
            _EMBEDDED_SO_NOTICE_PRINTED.add(kind)
        return True
    except Exception as e:
        if verbose:
            print(f"[!] embedded {label} extract failed: {type(e).__name__}: {e}")
        return False



_C_MARKER_LIB = None
_C_MARKER_BUILD = "member-marker-locator-v56-embedded-persist-index"


def _load_c_marker_locator():
    """Optional embedded C helper for first-run member marker location."""
    global _C_MARKER_LIB
    if _C_MARKER_LIB is not None:
        return _C_MARKER_LIB
    import sysconfig
    root = shared_cache_root() / "c_helpers" / _C_MARKER_BUILD
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so_path = root / ("libmember_marker" + suffix)
    if not _extract_embedded_so("marker", so_path):
        return None
    try:
        lib = ctypes.CDLL(str(so_path))
        lib.locate_iapp_member_markers.argtypes = [
            c_void_p, ctypes.c_size_t, c_void_p, c_void_p, ctypes.c_size_t, c_void_p
        ]
        lib.locate_iapp_member_markers.restype = c_int
        lib.member_marker_create_index.argtypes = [c_void_p, ctypes.c_size_t]
        lib.member_marker_create_index.restype = c_void_p
        lib.member_marker_free_index.argtypes = [c_void_p]
        lib.member_marker_free_index.restype = None
        lib.locate_iapp_member_markers_indexed.argtypes = [c_void_p, c_void_p, c_void_p, ctypes.c_size_t, c_void_p]
        lib.locate_iapp_member_markers_indexed.restype = c_int
        _C_MARKER_LIB = lib
        return lib
    except Exception as e:
        print(f"[!] embedded c-marker load failed: {type(e).__name__}: {e}")
        return None


_C_MARKER_INDEX_PTR = None
_C_MARKER_INDEX_OWNER = None
_C_MARKER_INDEX_KEY = None
_C_MARKER_INDEX_BUILD_MS = 0.0


def _get_c_marker_index(container_plain: bytes):
    """Build/reuse a persistent C first-2-byte position index for container_plain.

    The old cindex scanned the whole container once per recursive wave.  This
    index scans the container once, then each marker lookup only checks the tiny
    bucket sharing the marker's first two bytes.  Keep a Python reference to the
    bytes object so the C index's data pointer remains valid.
    """
    global _C_MARKER_INDEX_PTR, _C_MARKER_INDEX_OWNER, _C_MARKER_INDEX_KEY, _C_MARKER_INDEX_BUILD_MS
    lib = _load_c_marker_locator()
    if lib is None or not hasattr(lib, 'member_marker_create_index'):
        return None
    key = (id(container_plain), len(container_plain))
    if _C_MARKER_INDEX_PTR and _C_MARKER_INDEX_KEY == key:
        return _C_MARKER_INDEX_PTR
    if _C_MARKER_INDEX_PTR:
        try:
            lib.member_marker_free_index(_C_MARKER_INDEX_PTR)
        except Exception:
            pass
    _C_MARKER_INDEX_PTR = None
    _C_MARKER_INDEX_OWNER = None
    _C_MARKER_INDEX_KEY = None
    t_idx = time.perf_counter()
    try:
        ptr = lib.member_marker_create_index(ctypes.c_char_p(container_plain), len(container_plain))
    except Exception:
        return None
    if not ptr:
        return None
    _C_MARKER_INDEX_BUILD_MS = ms_since(t_idx)
    _C_MARKER_INDEX_PTR = ptr
    _C_MARKER_INDEX_OWNER = container_plain
    _C_MARKER_INDEX_KEY = key
    print(f"[T] member c-index build {_C_MARKER_INDEX_BUILD_MS:.3f} ms size={len(container_plain)}")
    return ptr


def locate_member_offsets_c_indexed(container_plain: bytes, ctx: "SlkyContext", names: Tuple[str, ...], hidden: bytes, fb_value) -> Optional[Dict[str, Tuple[int, int]]]:
    if not names:
        return {}
    lib = _load_c_marker_locator()
    if lib is None or not hasattr(lib, 'locate_iapp_member_markers_indexed'):
        return None
    idx_ptr = _get_c_marker_index(container_plain)
    if not idx_ptr:
        return None
    starts = bytearray()
    ends = bytearray()
    valid_names: List[str] = []
    for name in names:
        try:
            st, en = member_markers(ctx, name, hidden, fb_value)
        except Exception:
            continue
        if len(st) != 16 or len(en) != 16:
            return None
        starts.extend(st); ends.extend(en); valid_names.append(name)
    count = len(valid_names)
    if count == 0:
        return {}
    out = (ctypes.c_int64 * (count * 2))()
    try:
        ret = lib.locate_iapp_member_markers_indexed(
            idx_ptr, ctypes.c_char_p(bytes(starts)), ctypes.c_char_p(bytes(ends)),
            count, ctypes.cast(out, c_void_p)
        )
        if ret < 0:
            return None
    except Exception:
        return None
    result: Dict[str, Tuple[int, int]] = {}
    for i, name in enumerate(valid_names):
        a = int(out[i * 2]); b = int(out[i * 2 + 1])
        result[name] = (a, b) if (a >= 0 and b >= a) else (-1, -1)
    return result


def locate_member_offsets_c(container_plain: bytes, ctx: "SlkyContext", names: Tuple[str, ...], hidden: bytes, fb_value) -> Optional[Dict[str, Tuple[int, int]]]:
    if not names:
        return {}
    lib = _load_c_marker_locator()
    if lib is None:
        return None
    starts = bytearray()
    ends = bytearray()
    valid_names: List[str] = []
    for name in names:
        try:
            st, en = member_markers(ctx, name, hidden, fb_value)
        except Exception:
            continue
        if len(st) != 16 or len(en) != 16:
            return None
        starts.extend(st)
        ends.extend(en)
        valid_names.append(name)
    count = len(valid_names)
    if count == 0:
        return {}
    out = (ctypes.c_int64 * (count * 2))()
    try:
        ret = lib.locate_iapp_member_markers(
            ctypes.c_char_p(container_plain), len(container_plain),
            ctypes.c_char_p(bytes(starts)), ctypes.c_char_p(bytes(ends)),
            count, ctypes.cast(out, c_void_p)
        )
        if ret < 0:
            return None
    except Exception:
        return None
    result: Dict[str, Tuple[int, int]] = {}
    for i, name in enumerate(valid_names):
        a = int(out[i * 2]); b = int(out[i * 2 + 1])
        if a >= 0 and b >= a:
            result[name] = (a, b)
        else:
            result[name] = (-1, -1)
    return result



_PROC_MARKER_CONTAINER = None


def _proc_marker_init(container_plain: bytes):
    global _PROC_MARKER_CONTAINER
    _PROC_MARKER_CONTAINER = container_plain


def _proc_locate_marker_item(item: Tuple[str, bytes, bytes]) -> Tuple[str, int, int]:
    name, start, end = item
    c = _PROC_MARKER_CONTAINER
    if c is None:
        return name, -1, -1
    s = c.find(start)
    if s < 0:
        return name, -1, -1
    data_start = s + len(start)
    e = c.find(end, data_start)
    if e < 0 or e <= data_start or ((e - data_start) % 16):
        return name, -1, -1
    return name, data_start, e


def parse_int_auto(v) -> int:
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if s.lower().startswith("-0x"):
        return -int(s[3:], 16)
    if s.lower().startswith("0x"):
        return int(s[2:], 16)
    return int(s, 10)


def s8(x: int) -> int:
    x &= 0xFF
    return x - 256 if x >= 128 else x


def c_div(a: int, b: int) -> int:
    if b == 0:
        raise ZeroDivisionError("division by zero")
    sign = 1 if (a >= 0) == (b >= 0) else -1
    return sign * (abs(a) // abs(b))


def xor_repeat(data: bytes, key: bytes) -> bytes:
    """Fast repeating-key XOR.

    Small derivation inputs use a direct loop.  Larger buffers use the original
    C-backed big-int chunk path, which is faster for one-shot per-member keys
    than building translate tables that are rarely reused.  If a key is already
    cached, the translate-table path is used for repeated large decrypts.
    """
    if not key:
        raise ValueError("empty xor key")
    n = len(data)
    if n == 0:
        return b""
    klen = len(key)
    if n < 4096 or klen > n * 2:
        out = bytearray(data)
        for i in range(n):
            out[i] ^= key[i % klen]
        return bytes(out)

    tables = _XOR_TRANSLATE_CACHE.get(key)
    if tables is not None and klen <= 64:
        out = bytearray(n)
        for phase, table in enumerate(tables):
            chunk = data[phase::klen]
            if chunk:
                out[phase::klen] = chunk.translate(table)
        return bytes(out)

    base_chunk = 1 << 20
    chunk_size = max(klen, (base_chunk // klen) * klen)
    parts = []
    for off in range(0, n, chunk_size):
        part = data[off:off + chunk_size]
        plen = len(part)
        ks = key * (plen // klen) + key[:plen % klen]
        parts.append((int.from_bytes(part, "little") ^ int.from_bytes(ks, "little")).to_bytes(plen, "little"))
    return b"".join(parts)




def xor_repeat_prefix(data: bytes, key: bytes, n: int = 16) -> bytes:
    """Return xor_repeat(data, key)[:n] without building the full XOR output.

    SO-backed outer-key formulas only use the first 16 bytes as the AES key.
    This keeps the exact old semantics while avoiding repeat-key allocation in
    the hot outer-candidate path.
    """
    if not key:
        raise ValueError("empty xor key")
    m = min(n, len(data))
    return bytes((data[i] ^ key[i % len(key)]) for i in range(m))


_IDBFJ_PREP_CACHE: Dict[tuple, Tuple[bytes, bytes, int, bytes]] = {}

def _idbfj_prepare(env: Dict[str, bytes], input_name: str) -> Tuple[bytes, bytes, int, bytes]:
    """Cache x86 idbfj prework: input bytes, first concat, pick, second arg.

    The uploaded x86 SO computes idbfj(input) before burden1b.  Signature and
    non-signature candidates share the same p19 input, so this avoids repeated
    base+input concatenation and pick computation across candidate trials.
    """
    inp = env.get(input_name, b"")
    base = env["base"]
    hidden = env["hidden"]
    key = (input_name, base, inp, env["versionName"], env["package"], env["appLabel"], env["versionCode"], hidden, env["fb"])
    cached = _IDBFJ_PREP_CACHE.get(key)
    if cached is not None:
        return cached
    first = base if not inp else base + inp
    pick = _idbfj_pick6(first)
    seconds = (env["versionName"], env["package"], env["appLabel"], env["versionCode"], env["hidden"], env["fb"])
    if not 0 <= pick < len(seconds):
        raise ValueError(f"idbfj pick out of range: {pick}")
    second = seconds[pick]
    result = (inp, first, pick, second)
    if len(_IDBFJ_PREP_CACHE) > 4096:
        _IDBFJ_PREP_CACHE.clear()
    _IDBFJ_PREP_CACHE[key] = result
    return result


def pkcs7_unpad(data: bytes, block: int = 16) -> bytes:
    if not data or len(data) % block:
        raise ValueError("bad padded length")
    pad = data[-1]
    if not 1 <= pad <= block:
        raise ValueError("bad padding value")
    if data[-pad:] != bytes([pad]) * pad:
        raise ValueError("bad padding bytes")
    return data[:-pad]


def aes_cbc_pkcs5_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError(f"bad AES key length: {len(key)}")
    if len(ciphertext) % 16:
        raise ValueError("ciphertext is not block aligned")
    _Cipher, _algorithms, _modes, _default_backend = _lazy_crypto()
    decryptor = _Cipher(_algorithms.AES(key), _modes.CBC(key[:16]), backend=_default_backend()).decryptor()
    mid = decryptor.update(ciphertext) + decryptor.finalize()
    return pkcs7_unpad(mid, 16)


def aes_cbc_pkcs7_padding_maybe_valid(ciphertext: bytes, key: bytes) -> bool:
    """Cheap reject for wrong outer/member AES keys."""
    c_ok = _cfast_padding_valid(ciphertext, key)
    if c_ok is not None:
        return c_ok
    if len(key) not in (16, 24, 32) or not ciphertext or (len(ciphertext) % 16):
        return False
    last = ciphertext[-16:]
    prev = key[:16] if len(ciphertext) == 16 else ciphertext[-32:-16]
    try:
        _Cipher, _algorithms, _modes, _default_backend = _lazy_crypto()
        dec = _Cipher(_algorithms.AES(key), _modes.ECB(), backend=_default_backend()).decryptor()
        block = dec.update(last) + dec.finalize()
    except Exception:
        return False
    plain_last = bytes(a ^ b for a, b in zip(block, prev))
    pad = plain_last[-1]
    return 1 <= pad <= 16 and plain_last[-pad:] == bytes([pad]) * pad


def aes_cbc_then_xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    c_plain = _cfast_aes_cbc_then_xor_decrypt(ciphertext, key)
    if c_plain is not None:
        return c_plain
    mid = aes_cbc_pkcs5_decrypt(ciphertext, key)
    return xor_repeat(mid, key)


def uniq_bytes_list(items: List[bytes]) -> List[bytes]:
    seen = set()
    out = []
    for x in items:
        if not x or x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def looks_like_iapp_plain(data: bytes) -> bool:
    head = data[:4096]
    needles = [
        b"<View", b"</View", b"<eventItme", b"<UIEventset", b"LinearLayout",
        b"width=", b"height=", b"orientation=", b"backgroundcolor=", b"function",
    ]
    return sum(1 for x in needles if x in head) >= 2


_HIDDEN_SUFFIX = b"Q" * 10 + b"W" * 10 + b"EE"
_HIDDEN_RE = re.compile(rb"[A-Za-z0-9]{10}Q{10}W{10}EE")
_HIDDEN_HEX_RE = re.compile(rb"[A-F0-9]{10}Q{10}W{10}EE")


def _append_unique_hidden(out: List[bytes], seen: Set[bytes], cand: bytes) -> None:
    if not cand or cand in seen:
        return
    if _HIDDEN_RE.fullmatch(cand):
        seen.add(cand)
        out.append(cand)


def extract_hidden_candidates(so_data: bytes, max_candidates: int = 32) -> List[bytes]:
    """Enumerate possible iApp hidden constants from the sample SO.

    The normal layout is ten alnum bytes immediately before Q{10}W{10}EE.
    Older code returned the first match.  For portability across packed/multi-copy
    SOs, enumerate all exact suffix-adjacent matches first, then full-regex
    matches, and let key verification select the working candidate.
    """
    max_candidates = max(1, int(max_candidates or 32))
    out: List[bytes] = []
    seen: Set[bytes] = set()
    pos = so_data.find(_HIDDEN_SUFFIX)
    while pos >= 0:
        if pos >= 10:
            _append_unique_hidden(out, seen, so_data[pos - 10:pos + len(_HIDDEN_SUFFIX)])
            if len(out) >= max_candidates:
                return out[:max_candidates]
        pos = so_data.find(_HIDDEN_SUFFIX, pos + 1)

    # Prefer the native uppercase/hex-looking form when multiple string copies
    # exist, then keep generic alnum matches as fallback.
    for m in _HIDDEN_HEX_RE.finditer(so_data):
        _append_unique_hidden(out, seen, m.group(0))
        if len(out) >= max_candidates:
            return out[:max_candidates]
    for m in _HIDDEN_RE.finditer(so_data):
        _append_unique_hidden(out, seen, m.group(0))
        if len(out) >= max_candidates:
            break
    return out[:max_candidates]


def parse_hidden_value(value: str) -> bytes:
    s = str(value or "").strip()
    if s.lower().startswith("hex:"):
        raw = bytes.fromhex(s[4:])
    elif len(s) == 64 and re.fullmatch(r"[0-9a-fA-F]+", s):
        raw = bytes.fromhex(s)
    else:
        raw = s.encode("ascii", "strict")
    if not _HIDDEN_RE.fullmatch(raw):
        raise ValueError("hidden must look like 10 alnum chars + QQQQQQQQQQ + WWWWWWWWWW + EE")
    return raw


def _hidden_from_prefix(prefix10: str) -> bytes:
    p = str(prefix10 or "").strip()
    if len(p) != 10 or not re.fullmatch(r"[A-Za-z0-9]{10}", p):
        raise ValueError("hidden prefix must be exactly 10 alnum chars")
    return p.encode("ascii") + _HIDDEN_SUFFIX


def _sokey_from_ms_timestamp(ts_ms: int) -> bytes:
    prefix = hashlib.md5(str(int(ts_ms)).encode("ascii")).hexdigest()[:10].upper()
    return prefix.encode("ascii") + _HIDDEN_SUFFIX



_APK_SNAPSHOT_CACHE: Dict[tuple, dict] = {}

def _apk_snapshot(apk_path: Optional[Path]) -> Optional[dict]:
    if not apk_path:
        return None
    p=Path(apk_path).resolve()
    st=p.stat(); key=(str(p),st.st_size,st.st_mtime_ns)
    snap=_APK_SNAPSHOT_CACHE.get(key)
    if snap is not None:
        return snap
    z=zipfile.ZipFile(p,"r")
    infos=z.infolist(); by_name={i.filename:i for i in infos}
    snap={"zip":z,"infos":infos,"names":set(by_name),"by_name":by_name,"data":{}}
    _APK_SNAPSHOT_CACHE.clear();_APK_SNAPSHOT_CACHE[key]=snap
    return snap

def _apk_read_cached(apk_path: Optional[Path], name: str, default=None):
    snap=_apk_snapshot(apk_path)
    if snap is None or name not in snap["names"]:
        return default
    data=snap["data"]
    if name not in data:
        data[name]=snap["zip"].read(name)
    return data[name]

def _apk_infos_cached(apk_path: Optional[Path]):
    snap=_apk_snapshot(apk_path)
    return list(snap["infos"]) if snap is not None else []


def _iapt_zipinfo_epoch_sec_beijing(info) -> int:
    """Convert a ZipInfo DOS/local timestamp as iApp's UTC+8 build time."""
    zdt = _dt.datetime(*tuple(info.date_time), tzinfo=_dt.timezone(_dt.timedelta(hours=8)))
    return int(zdt.timestamp())


def _iapt_sokey_time_model(apk_path: Path, infos) -> Dict[str, object]:
    """Estimate the build-time lag between sokey timestamp and assets/lib.so mtime.

    This never reads/extracts the already-known hidden value.  It only uses ZIP
    metadata, encrypted container size, and native-runtime ABI size fingerprints.
    The model is deliberately conservative: the estimated lag is only an ordering
    hint; nearby and zero-lag windows are always retained.
    """
    asset_info = None
    abi_sizes: Dict[str, int] = {}
    for info in infos or []:
        name = (getattr(info, 'filename', '') or '').replace('\\', '/').strip('/')
        low = name.lower()
        if low == 'assets/lib.so':
            asset_info = info
        if low.endswith('/libygsiyu.so') and low.startswith('lib/'):
            parts = low.split('/')
            if len(parts) >= 3:
                abi_sizes[parts[1]] = int(getattr(info, 'file_size', 0) or 0)

    asset_size = int(getattr(asset_info, 'file_size', 0) or 0) if asset_info else 0
    asset_sec = _iapt_zipinfo_epoch_sec_beijing(asset_info) if asset_info else None

    a64 = abi_sizes.get('arm64-v8a', 0)
    a32 = abi_sizes.get('armeabi-v7a', 0)
    x86 = abi_sizes.get('x86', 0)
    x64 = abi_sizes.get('x86_64', 0)

    family = 'unknown'
    predicted = 1
    spread = 1

    # Legacy iApp runtime family seen in the 20 KiB and 1.5 MiB samples.
    # In this family, packing lag tracks encrypted assets/lib.so size closely.
    if (390000 <= a64 <= 397000 and 235000 <= a32 <= 241500 and
            (x86 == 0 or 352000 <= x86 <= 359500)):
        family = 'legacy-slow-pack'
        predicted = int(round(0.55 + (asset_size / 46373.0))) if asset_size else 1
        predicted = max(1, min(45, predicted))
        spread = 1
    # Newer protected/runtime family: large container but much faster pack stage.
    elif (398000 <= a64 <= 408500 and 345000 <= a32 <= 353500 and
          (218000 <= x64 <= 229000 or x64 == 0)):
        family = 'modern-fast-pack'
        predicted = int(round(asset_size / 330000.0)) if asset_size else 2
        predicted = max(1, min(12, predicted))
        spread = 1
    # 423k/353k/296k runtime family: observed lag is normally around 0..2 sec.
    elif (418000 <= a64 <= 429000 and 348000 <= a32 <= 359000 and
          (x86 == 0 or 290000 <= x86 <= 302000)):
        family = 'modern-near-time'
        predicted = 1
        spread = 1
    else:
        # Unknown family: size remains a hint, not a hard formula.  Use a wider
        # +/-3s probe for large containers while preserving immediate windows.
        family = 'generic-size-hint'
        if asset_size <= 64 * 1024:
            predicted = 1
        elif asset_size <= 512 * 1024:
            predicted = 2
        else:
            predicted = max(3, min(40, int(round(asset_size / 50000.0))))
            spread = 3

    return {
        'asset_info': asset_info,
        'asset_sec': asset_sec,
        'asset_size': asset_size,
        'abi_sizes': abi_sizes,
        'family': family,
        'predicted_back_sec': predicted,
        'spread_sec': spread,
    }


def _iapt_sokey_offset_order(window_count: int, predicted: int, spread: int = 1) -> List[int]:
    """Return unique backward-second offsets, preserving a fixed candidate budget."""
    n = max(1, int(window_count or 1))
    p = max(0, int(predicted or 0))
    d = max(1, int(spread or 1))
    preferred = [
        p, max(0, p - d), p + d,
        0, 1, 2, 3, 4, 5,
        max(0, p - 1), p + 1,
        max(0, p - 2), p + 2,
        max(0, p - 3), p + 3,
        8, 16, 24, 32, 33, 34, 35, 36, 40,
    ]
    out: List[int] = []
    seen: Set[int] = set()
    for off in preferred:
        off = int(off)
        if off < 0 or off in seen:
            continue
        seen.add(off)
        out.append(off)
        if len(out) >= n:
            return out
    off = 0
    while len(out) < n:
        if off not in seen:
            seen.add(off)
            out.append(off)
        off += 1
    return out


def build_sokey_timestamp_candidates_from_apk(
    apk_path: Optional[Path],
    seconds: int = 180,
    max_files: int = 1,
    base_ts: Optional[int] = None,
    list_mtimes: bool = False,
    max_candidates: int = 0,
) -> List[bytes]:
    """Build sokey candidates.

    sokey = MD5(<pack millisecond timestamp>)[:10].upper() + QQQQQQQQQQWWWWWWWWWWEE.

    Normal mode reads ZIP mtimes under bsh/util/lib/.  ZIP date_time is interpreted
    as Beijing time (UTC+8), not the device/server local timezone. ZIP stores only
    second-level timestamps, so each selected second enumerates millisecond offsets
    000..999 and then walks backwards exhaustively for `seconds` seconds.  The
    default is 180 seconds (three minutes).

    Manual mode (`--sokey-base-ts`) avoids timezone/file-selection mistakes:
      * 13-digit value => exact millisecond timestamp is tried first, then that
        second's 000..999 window and previous seconds.
      * 10-digit value => treated as the first second window directly.
    """
    seconds = max(1, int(seconds or 180))
    max_files = max(1, int(max_files or 1))
    try:
        max_candidates = int(max_candidates or 0)
    except Exception:
        max_candidates = 0
    if max_candidates <= 0:
        max_candidates = seconds * 1000 * max_files

    out: List[bytes] = []
    seen: Set[bytes] = set()

    def add_ts(ts_ms: int, label: str = "") -> None:
        if len(out) >= max_candidates:
            return
        cand = _sokey_from_ms_timestamp(int(ts_ms))
        if cand not in seen:
            seen.add(cand)
            out.append(cand)
            if label:
                print(f"[+] sokey manual candidate {label}: ts_ms={int(ts_ms)} key={cand.decode('ascii','replace')}")

    def _sokey_second_offsets(n: int, smart: bool, predicted: int = 0, spread: int = 1) -> List[int]:
        if not smart:
            return list(range(max(1, int(n or 1))))
        return _iapt_sokey_offset_order(n, predicted, spread)

    def add_second_window(base_sec: int, name: str, smart_offsets: bool = False,
                          predicted: int = 0, spread: int = 1, model_name: str = "") -> None:
        offsets = _sokey_second_offsets(seconds, smart_offsets, predicted, spread)
        mode = ("model:" + model_name) if smart_offsets and model_name else ("smart" if smart_offsets else "linear")
        suffix = "..." if len(offsets) > 12 else ""
        print(f"[+] sokey mtime source = {name} sec={base_sec} windows={seconds} mode={mode} offsets={offsets[:12]}{suffix}")
        for win_i, back in enumerate(offsets):
            sec = int(base_sec) - int(back)
            base_ms = sec * 1000
            if win_i == 0:
                print(f"    window[{win_i}] ts_ms={base_ms:013d}-{base_ms+999:013d}")
            for milli in range(1000):
                add_ts(base_ms + milli)
                if len(out) >= max_candidates:
                    return


    def add_exhaustive_priority_grid(base_sec: int, name: str, offsets: List[int]) -> None:
        """Emit every (second,millisecond) pair once, with a fast priority prefix.

        The prefix covers three common cases without using a known key:
        - low milliseconds in the best predicted second;
        - center milliseconds in the best predicted second;
        - center milliseconds in the two neighboring priority seconds.
        The rest of the complete 3-minute grid follows afterward.
        """
        offsets=[int(x) for x in offsets]
        center=[500]
        for d in range(1,501):
            if 500-d>=0:center.append(500-d)
            if 500+d<1000:center.append(500+d)
        emitted=set()
        def emit(back:int, seq) -> None:
            if back<0:return
            base_ms=(int(base_sec)-int(back))*1000
            for milli in seq:
                key=(int(back),int(milli))
                if key in emitted:continue
                emitted.add(key);add_ts(base_ms+int(milli))
                if len(out)>=max_candidates:return
        top=offsets[:3]
        if top:
            emit(top[0],range(256))
        # Interleave the best second and its closest alternate around 500ms.
        # This keeps low-ms hits in the predicted second first while preventing
        # a one-second prediction error from being delayed by a full 1000-ms window.
        if len(top)>1:
            for i in range(256):
                emit(top[0],center[i:i+1])
                emit(top[1],center[i:i+1])
                if len(out)>=max_candidates:return
        elif top:
            emit(top[0],center[:256])
        if len(top)>2:emit(top[2],center[:256])
        for back in offsets:
            emit(back,center)
            if len(out)>=max_candidates:return
        print(f"[+] sokey priority grid = {name} base={base_sec} prefix_seconds={top} total_pairs={len(emitted)}")

    if base_ts is not None:
        raw = int(base_ts)
        if raw <= 0:
            raise SystemExit("--sokey-base-ts must be a positive 10-digit second timestamp or 13-digit millisecond timestamp")
        # 13-digit ms timestamp: try the exact value first so a known timestamp hits immediately.
        if raw >= 1_000_000_000_000:
            base_sec = raw // 1000
            add_ts(raw, "exact-first")
            print(f"[+] sokey manual base-ts(ms) = {raw}; base_sec={base_sec}; exact key is first candidate")
            add_second_window(base_sec, "--sokey-base-ts(ms)//1000")
        else:
            base_sec = raw
            print(f"[+] sokey manual base-ts(sec) = {base_sec}; no APK mtime conversion used")
            add_second_window(base_sec, "--sokey-base-ts(sec)")
        if not out:
            raise SystemExit("--sokey-enum produced no candidates from --sokey-base-ts")
        print(f"[+] sokey enum candidates = {len(out)} from manual base timestamp; per-second attempts={seconds * 1000}; max={max_candidates}")
        return out

    if not apk_path:
        raise SystemExit("--sokey-enum needs --apk so bsh/util/lib/ mtimes can be read, or pass --sokey-base-ts")
    apk_path = Path(apk_path)
    if not apk_path.exists():
        raise SystemExit("--sokey-enum APK not found: " + str(apk_path))

    mtimes: List[Tuple[int, str, Tuple[int, int, int, int, int, int]]] = []
    path_hints: List[str] = []
    try:
        for info in _apk_infos_cached(apk_path):
            name = (info.filename or "").replace("\\", "/")
            norm = name.strip("/")
            if not norm or norm.endswith("/"):
                continue
            low = norm.lower()
            # Some APKs store this under assets/bsh/util/lib/... or with odd case.
            # Match case-insensitively and allow any prefix before bsh/util/lib/.
            if "bsh" in low or "util/lib" in low:
                if len(path_hints) < 80:
                    path_hints.append(norm)
            if "bsh/util/lib/" not in low:
                continue
            try:
                # zipfile.date_time is a naive DOS/local timestamp, not UTC.
                # iApp pack timestamps here are Beijing time (UTC+8).  Do NOT use
                # time.mktime(), because that interprets the tuple using the
                # phone/server local timezone (Termux/Japan/etc.) and shifts the
                # epoch seconds.
                sec = _iapt_zipinfo_epoch_sec_beijing(info)
            except Exception as e:
                print(f"[!] skip bad ZIP mtime: {norm} date_time={getattr(info, 'date_time', None)} err={type(e).__name__}: {e}")
                continue
            mtimes.append((sec, norm, tuple(info.date_time)))
    except zipfile.BadZipFile:
        raise SystemExit("--sokey-enum input is not a valid APK/ZIP")
    if not mtimes:
        if path_hints:
            print("[!] no exact bsh/util/lib/ entries found; related APK paths:")
            for p in path_hints[:80]:
                print("    " + p)
        raise SystemExit("--sokey-enum could not find files under bsh/util/lib/ in APK; use --sokey-base-ts if you already know the timestamp")

    sorted_mtimes = sorted(mtimes, key=lambda x: (-x[0], x[1]))
    print("[+] bsh/util/lib mtime candidates (top 10 after Beijing/UTC+8 ZIP time conversion):")
    for i, (sec, name, zdt) in enumerate(sorted_mtimes[:10], start=1):
        print(f"    {i:02d}. sec={sec} zip_date_time={zdt} name={name}")
    if list_mtimes:
        print("[+] full bsh/util/lib mtime list:")
        for i, (sec, name, zdt) in enumerate(sorted_mtimes, start=1):
            print(f"    {i:04d}. sec={sec} zip_date_time={zdt} name={name}")

    # Try newest mtimes first.  Several entries commonly share one timestamp;
    # de-duplicate by second to avoid repeating the same 4000 candidates.
    uniq: List[Tuple[int, str]] = []
    seen_sec: Set[int] = set()
    for sec, name, _zdt in sorted_mtimes:
        if sec in seen_sec:
            continue
        seen_sec.add(sec)
        uniq.append((sec, name))
        if len(uniq) >= max_files:
            break

    # v137 strict strategy: the candidate SET is still exactly the exhaustive
    # bsh/util/lib backward interval (default 180 seconds = 180,000 real ms
    # candidates).  Container/runtime information is used only to PRIORITIZE
    # the order of those seconds; it never removes a candidate and never injects
    # an already-known hidden/sokey value.
    model = _iapt_sokey_time_model(apk_path, _apk_infos_cached(apk_path))
    asset_sec = model.get("asset_sec")
    for base_sec, name in uniq:
        predicted = int(model.get("predicted_back_sec") or 0)
        if asset_sec is not None:
            predicted += int(base_sec) - int(asset_sec)
        predicted = max(0, min(seconds - 1, predicted))
        abi_desc = ",".join(f"{k}:{v}" for k, v in sorted((model.get("abi_sizes") or {}).items()))
        print(
            f"[+] sokey exhaustive priority = base=bsh/util/lib predicted_back={predicted}s "
            f"family={model.get('family')} assets/lib.so={model.get('asset_size')}B "
            f"abi_sizes={abi_desc or '<none>'}; coverage=0..{seconds-1}s"
        )
        offsets=_sokey_second_offsets(
            seconds, True, predicted,
            max(1, int(model.get("spread_sec") or 1)),
        )
        print(f"[+] sokey mtime source = {name} sec={base_sec} windows={seconds} mode=model:exhaustive-priority offsets={offsets[:12]}{'...' if len(offsets)>12 else ''}")
        add_exhaustive_priority_grid(base_sec,name,offsets)
        if len(out) >= max_candidates:
            break
    if not out:
        raise SystemExit("--sokey-enum produced no candidates")
    print(f"[+] sokey enum candidates = {len(out)} from {len(uniq)} unique mtime second(s); per-second attempts={seconds * 1000}; max={max_candidates}")
    return out



def build_quishui_sokey_priority_candidates(apk_path: Optional[Path]) -> List[bytes]:
    """Build a small, protector-backed sokey window for QuiShui/Tosks apps.

    This is not enabled from timestamps alone.  It requires a statically valid
    Tosks embedded DEX and cross-ABI .ArmEpic metadata.  QuiShui rewrites the APK
    resource set a few seconds after iApp creates the millisecond sokey; probe the
    narrow 4-second-centered window first.  Every candidate is still accepted
    only by the normal outer/member cryptographic verifier.
    """
    if not apk_path or not extract_tosks_embedded_dexes(apk_path):
        return []
    armepic_votes = 0
    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".so") or "libqs_" not in info.filename.lower():
                    continue
                try:
                    elf = MiniELF(archive.read(info))
                    sec = elf.section_by_name(".ArmEpic")
                except Exception:
                    sec = None
                if sec and sec.get("size", 0) >= 32:
                    armepic_votes += 1
    except Exception:
        return []
    if armepic_votes < 2:
        return []
    seconds: List[int] = []
    for info in _apk_infos_cached(apk_path):
        low = (getattr(info, "filename", "") or "").replace("\\", "/").lower()
        if "bsh/util/lib/" not in low or low.endswith("/"):
            continue
        try:
            seconds.append(_iapt_zipinfo_epoch_sec_beijing(info))
        except Exception:
            continue
    if not seconds:
        return []
    base_sec = max(seconds)
    offsets = (4, 3, 5, 2, 1, 0, 6)
    # Low milliseconds are common in the original pack stage; keep the complete
    # 0..999 set after the 0..255 priority prefix so no value is omitted.
    milli_order = list(range(256)) + list(range(256, 1000))
    out: List[bytes] = []
    seen: Set[bytes] = set()
    for back in offsets:
        base_ms = (base_sec - back) * 1000
        for milli in milli_order:
            cand = _sokey_from_ms_timestamp(base_ms + milli)
            if cand not in seen:
                seen.add(cand)
                out.append(cand)
    print(
        f"[+] QuiShui sokey priority window: base={base_sec} offsets={list(offsets)} "
        f"candidates={len(out)} ArmEpic_votes={armepic_votes}"
    )
    return out


def _split_hidden_tokens(items: List[str]) -> List[str]:
    out: List[str] = []
    for item in items or []:
        for part in re.split(r"[,;\n\r\t ]+", str(item)):
            tok = part.strip().strip('"\'')
            if tok and not tok.startswith("#"):
                out.append(tok)
    return out


def _hidden_candidate_from_token(token: str) -> Optional[bytes]:
    tok = str(token or "").strip()
    if not tok:
        return None
    # Full hidden value in ASCII/hex form.
    try:
        return parse_hidden_value(tok)
    except Exception:
        pass
    # Common explicit form: only the first 10-byte random/alnum prefix.
    if len(tok) == 10 and re.fullmatch(r"[A-Za-z0-9]{10}", tok):
        return tok.encode("ascii") + _HIDDEN_SUFFIX
    return None


def build_explicit_hidden_candidates(args) -> List[bytes]:
    """Build hidden candidates only from user-supplied enum data.

    This intentionally does not inspect libygsiyu.so.  The enum mode is for
    samples whose SO is missing/encrypted or whose hidden string cannot be
    extracted.  Candidates may be full hidden values, 10-byte prefixes, or masks
    with '?' placeholders inside the 10-byte prefix.
    """
    max_n = max(1, int(args.max_hidden_candidates or 1))
    charset = "".join(dict.fromkeys(str(args.hidden_charset or "0123456789ABCDEF")))
    if not charset or not re.fullmatch(r"[A-Za-z0-9]+", charset):
        raise SystemExit("--hidden-charset must contain only alnum characters")

    tokens: List[str] = []
    tokens.extend(_split_hidden_tokens(args.hidden_candidates or []))
    if args.hidden_prefix:
        tokens.append(str(args.hidden_prefix).strip())
    if args.hidden_candidates_file:
        raw = args.hidden_candidates_file.read_text(encoding="utf-8", errors="ignore")
        tokens.extend(_split_hidden_tokens([raw]))
    if not tokens:
        raise SystemExit("--hidden-enum needs --hidden-prefix, --hidden-candidates, or --hidden-candidates-file; full 62^10 brute force is intentionally not started by default")

    out: List[bytes] = []
    seen: Set[bytes] = set()

    def add(c: bytes) -> None:
        if c not in seen:
            seen.add(c)
            out.append(c)

    for tok in tokens:
        direct = _hidden_candidate_from_token(tok)
        if direct is not None:
            add(direct)
            if len(out) >= max_n:
                break
            continue
        mask = tok
        # Accept accidental full hidden with unknowns only in first 10 bytes.
        if len(mask) == len(_HIDDEN_SUFFIX) + 10 and mask[10:].encode("ascii", "ignore") == _HIDDEN_SUFFIX:
            mask = mask[:10]
        if len(mask) != 10 or not re.fullmatch(r"[A-Za-z0-9?*]{10}", mask):
            raise SystemExit(f"bad hidden enum token: {tok!r}; use full hidden, 10-char prefix, or 10-char mask with '?'")
        qpos = [i for i, ch in enumerate(mask) if ch in "?*"]
        if not qpos:
            add(_hidden_from_prefix(mask))
            if len(out) >= max_n:
                break
            continue
        total = len(charset) ** len(qpos)
        if total > max_n and len(out) == 0:
            print(f"[!] hidden enum mask expands to {total} candidates; limiting to --max-hidden-candidates={max_n}")
        base = list(mask)
        for combo in itertools.product(charset, repeat=len(qpos)):
            for pos, ch in zip(qpos, combo):
                base[pos] = ch
            add(_hidden_from_prefix("".join(base)))
            if len(out) >= max_n:
                break
        if len(out) >= max_n:
            break
    if not out:
        raise SystemExit("hidden enum produced no candidates")
    return out


_C_FAST_LIB = None
_C_FAST_MODE = "auto"
_C_FAST_READY_PRINTED = False


def set_fast_c_mode(mode: str) -> None:
    global _C_FAST_MODE
    _C_FAST_MODE = (mode or "auto").lower()





def _fastcore_load_symbols(lib):
    lib.iapp_slky_core.argtypes = [c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p]
    lib.iapp_slky_core.restype = c_int
    lib.iapp_aes_cbc_xor_decrypt.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_void_p, c_void_p]
    lib.iapp_aes_cbc_xor_decrypt.restype = c_int
    lib.iapp_aes_cbc_padding_valid.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int]
    lib.iapp_aes_cbc_padding_valid.restype = c_int
    if hasattr(lib, "iapp_set_mian_prefix_limit"):
        lib.iapp_set_mian_prefix_limit.argtypes = [ctypes.c_size_t]
        lib.iapp_set_mian_prefix_limit.restype = c_int
    if hasattr(lib, "iapp_set_tail_marker_gate"):
        lib.iapp_set_tail_marker_gate.argtypes = [c_void_p, c_int, c_int]
        lib.iapp_set_tail_marker_gate.restype = c_int
    if hasattr(lib, "iapp_set_idbfj_variant_mode"):
        lib.iapp_set_idbfj_variant_mode.argtypes = [c_int]
        lib.iapp_set_idbfj_variant_mode.restype = c_int
    lib.iapp_mian_gate_maybe.argtypes = [c_void_p, ctypes.c_size_t]
    lib.iapp_mian_gate_maybe.restype = c_int
    try:
        lib.iapp_fixed_dexkey_scan.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p]
        lib.iapp_fixed_dexkey_scan.restype = c_int
        lib.iapp_fixed_hidden_list_scan.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p]
        lib.iapp_fixed_hidden_list_scan.restype = c_int
        if hasattr(lib, "iapp_fixed_dexkey_scan_mian"):
            lib.iapp_fixed_dexkey_scan_mian.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, ctypes.c_size_t, c_void_p]
            lib.iapp_fixed_dexkey_scan_mian.restype = c_int
        if hasattr(lib, "iapp_fixed_hidden_list_scan_mian"):
            lib.iapp_fixed_hidden_list_scan_mian.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p, c_int, ctypes.c_size_t, c_void_p]
            lib.iapp_fixed_hidden_list_scan_mian.restype = c_int
        if hasattr(lib, "iapp_broad_dexkey_scan_mian"):
            lib.iapp_broad_dexkey_scan_mian.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, ctypes.c_size_t, c_void_p, c_void_p]
            lib.iapp_broad_dexkey_scan_mian.restype = c_int
        if hasattr(lib, "iapp_idbfj_dexkey_scan_mian"):
            lib.iapp_idbfj_dexkey_scan_mian.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, ctypes.c_size_t, c_void_p, c_void_p]
            lib.iapp_idbfj_dexkey_scan_mian.restype = c_int
        if hasattr(lib, "iapp_joint_sokey_dexkey_scan_mian_parallel"):
            lib.iapp_joint_sokey_dexkey_scan_mian_parallel.restype = c_int
        if hasattr(lib, "iapp_joint_sokey_dexkey_scan_mian_parallel_lazy"):
            lib.iapp_joint_sokey_dexkey_scan_mian_parallel_lazy.restype = c_int
        if hasattr(lib, "iapp_joint_sokey_dexkey_scan_mian_parallel_diagonal"):
            lib.iapp_joint_sokey_dexkey_scan_mian_parallel_diagonal.restype = c_int
        if hasattr(lib, "iapp_broad_hidden_list_scan_mian"):
            lib.iapp_broad_hidden_list_scan_mian.argtypes = [c_void_p, ctypes.c_size_t, c_void_p, c_int, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_int, c_int, c_int, c_void_p, c_int, ctypes.c_size_t, c_void_p, c_void_p]
            lib.iapp_broad_hidden_list_scan_mian.restype = c_int
    except Exception:
        pass
    return lib


def _try_compile_local_fast_core(root: Path, verbose: bool = False) -> Optional[Path]:
    """Compile an on-device fast core for Termux/Linux ARM/x86 when embedded x86_64 is unavailable."""
    if str(os.environ.get("IAPT_NO_COMPILE_FASTCORE", "")).strip() in ("1", "true", "on", "yes"):
        return None
    env_so = os.environ.get("IAPT_FASTCORE_SO")
    if env_so:
        p = Path(env_so).expanduser()
        if p.exists():
            return p
    try:
        import subprocess, shutil, sysconfig, platform
        cc = os.environ.get("CC") or shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not cc:
            if verbose:
                print("[!] no cc/clang found; install: pkg install clang openssl")
            return None
        build_tag = "termux-fastcore-v45-joint-nohint-" + (platform.machine() or "unknown")
        build_dir = root / build_tag
        build_dir.mkdir(parents=True, exist_ok=True)
        c_path = build_dir / "iapp_fastcore.c"
        suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
        so_path = build_dir / ("libiapp_fastcore" + suffix)
        core_source = _get_fastcore_c_source()
        source_changed = True
        if c_path.exists():
            try:
                source_changed = c_path.read_text(encoding="utf-8") != core_source
            except Exception:
                source_changed = True
        if source_changed:
            c_path.write_text(core_source, encoding="utf-8")
        if so_path.exists() and not source_changed and so_path.stat().st_mtime >= c_path.stat().st_mtime:
            return so_path
        cmd = [cc, "-shared", "-fPIC", "-O3", "-fno-semantic-interposition", "-fomit-frame-pointer"]
        machine = (platform.machine() or "").lower()
        if machine in ("aarch64", "arm64"):
            cmd.append("-march=armv8-a+crypto")
        cmd += ["-o", str(so_path), str(c_path), "-lcrypto", "-pthread"]
        if verbose:
            print("[+] compiling local c-fast core:", " ".join(cmd))
        cp = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60)
        if cp.returncode != 0:
            if verbose:
                print("[!] local c-fast compile failed:", (cp.stderr or cp.stdout)[-1200:])
            return None
        return so_path if so_path.exists() else None
    except Exception as e:
        if verbose:
            print(f"[!] local c-fast compile unavailable: {type(e).__name__}: {e}")
        return None

def _load_c_fast_core(verbose: bool = False):
    """C fast core for hot paths; on Termux/Linux ARM it compiles a local helper once."""
    global _C_FAST_LIB, _C_FAST_READY_PRINTED
    if _C_FAST_MODE == "off":
        return None
    if _C_FAST_LIB is not None:
        return _C_FAST_LIB
    import sysconfig
    root = shared_cache_root() / "c_helpers" / "iapp-fastcore-v146-joint-nohint"
    suffix = sysconfig.get_config_var("EXT_SUFFIX") or ".so"
    so_path = root / ("libiapp_fastcore" + suffix)
    # v100: full-C enum needs newly compiled symbols. Prefer local compile over
    # the embedded legacy helper; otherwise broad enum silently falls back.
    source_label = "local compiled c-fast core"
    local = _try_compile_local_fast_core(root, verbose=verbose)
    if local is not None:
        so_path = local
    else:
        source_label = "embedded c-fast core"
        if not _extract_embedded_so("fastcore", so_path, verbose=False):
            if _C_FAST_MODE == "on" and verbose:
                print("[!] local/embedded c-fast core unavailable; using Python fallback")
            return None
    try:
        lib = ctypes.CDLL(str(so_path))
        _fastcore_load_symbols(lib)
        _C_FAST_LIB = lib
        if verbose and not _C_FAST_READY_PRINTED:
            print(f"[+] {source_label}: {so_path}")
            _C_FAST_READY_PRINTED = True
        return lib
    except Exception as e:
        if _C_FAST_MODE == "on" or verbose:
            print(f"[!] c-fast load failed: {type(e).__name__}: {e}")
        return None


def _cfast_set_mian_prefix_limit(limit_bytes: int) -> bool:
    try:
        lib = _load_c_fast_core(False)
        if lib is None or not hasattr(lib, "iapp_set_mian_prefix_limit"):
            return False
        lib.iapp_set_mian_prefix_limit(max(0, int(limit_bytes or 0)))
        return True
    except Exception:
        return False


def _cfast_set_idbfj_variant_mode(mode: int) -> bool:
    try:
        lib = _load_c_fast_core(False)
        if lib is None or not hasattr(lib, "iapp_set_idbfj_variant_mode"):
            return False
        return lib.iapp_set_idbfj_variant_mode(int(mode)) == 0
    except Exception:
        return False


def _cfast_set_tail_marker_gate(name: str, enabled: bool) -> bool:
    try:
        lib = _load_c_fast_core(False)
        if lib is None or not hasattr(lib, "iapp_set_tail_marker_gate"):
            return False
        raw = str(name or "").encode("utf-8")
        if not enabled:
            return lib.iapp_set_tail_marker_gate(None, 0, 0) == 0
        if not raw:
            return False
        return lib.iapp_set_tail_marker_gate(ctypes.c_char_p(raw), len(raw), 1) == 0
    except Exception:
        return False


def _cfast_aes_cbc_then_xor_decrypt(ciphertext: bytes, key: bytes) -> Optional[bytes]:
    # auto mode uses C only for large buffers such as the outer container.
    # Small member files stay on the Python/cryptography path to avoid ctypes
    # overhead; --fast-c on forces C for all buffers.
    if _C_FAST_MODE == "off":
        return None
    if _C_FAST_MODE == "auto" and len(ciphertext) < (256 * 1024):
        return None
    lib = _load_c_fast_core(False)
    if lib is None:
        return None
    if len(key) not in (16, 24, 32) or not ciphertext or (len(ciphertext) & 15):
        return None
    out = ctypes.create_string_buffer(len(ciphertext))
    out_len = ctypes.c_size_t(0)
    try:
        ret = lib.iapp_aes_cbc_xor_decrypt(
            ctypes.c_char_p(ciphertext), len(ciphertext), ctypes.c_char_p(key), len(key),
            ctypes.cast(out, c_void_p), ctypes.byref(out_len)
        )
        if ret != 0:
            return None
        return out.raw[:int(out_len.value)]
    except Exception:
        return None


def _cfast_padding_valid(ciphertext: bytes, key: bytes) -> Optional[bool]:
    # Padding probe is a one-block operation; Python/cryptography is usually
    # faster than crossing ctypes in auto mode.  Force C only with --fast-c on.
    if _C_FAST_MODE != "on":
        return None
    lib = _load_c_fast_core(False)
    if lib is None:
        return None
    if len(key) not in (16, 24, 32) or not ciphertext or (len(ciphertext) & 15):
        return False
    try:
        return bool(lib.iapp_aes_cbc_padding_valid(ctypes.c_char_p(ciphertext), len(ciphertext), ctypes.c_char_p(key), len(key)))
    except Exception:
        return None


def _cfast_mian_gate_maybe(data: bytes) -> Optional[bool]:
    if _C_FAST_MODE != "on":
        return None
    lib = _load_c_fast_core(False)
    if lib is None:
        return None
    try:
        return bool(lib.iapp_mian_gate_maybe(ctypes.c_char_p(data), len(data)))
    except Exception:
        return None


def _cfast_fixed_dexkey_scan(container: bytes, hidden: bytes, package: str, version_name: str, version_code, app_label: str, start_fb: int, stop_fb: int, direction: int, post_key: bytes, key_xor: bytes) -> Optional[int]:
    if _C_FAST_MODE == "off":
        return None
    lib = _load_c_fast_core(False)
    if lib is None or not hasattr(lib, "iapp_fixed_dexkey_scan"):
        return None
    found = c_int(-1)
    pkg = str(package).encode(); vn = str(version_name).encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label).encode()
    try:
        ret = lib.iapp_fixed_dexkey_scan(
            ctypes.c_char_p(container), len(container), ctypes.c_char_p(hidden), len(hidden),
            ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab),
            int(start_fb), int(stop_fb), int(direction or (1 if start_fb <= stop_fb else -1)),
            ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor), ctypes.byref(found)
        )
        return int(found.value) if ret == 1 else None
    except Exception:
        return None


def _cfast_fixed_hidden_list_scan(container: bytes, hidden_candidates: List[bytes], package: str, version_name: str, version_code, app_label: str, fb_value, start_index: int, stop_index: int, direction: int, post_key: bytes, key_xor: bytes) -> Optional[int]:
    if _C_FAST_MODE == "off" or not hidden_candidates:
        return None
    lib = _load_c_fast_core(False)
    if lib is None or not hasattr(lib, "iapp_fixed_hidden_list_scan"):
        return None
    hlen = len(hidden_candidates[0])
    if hlen <= 0 or any(len(h) != hlen for h in hidden_candidates):
        return None
    blob = b"".join(hidden_candidates)
    pkg = str(package).encode(); vn = str(version_name).encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label).encode(); fb = str(parse_int_auto(fb_value)).encode()
    found = c_int(-1)
    try:
        ret = lib.iapp_fixed_hidden_list_scan(
            ctypes.c_char_p(container), len(container), ctypes.c_char_p(blob), len(hidden_candidates), hlen,
            ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab),
            ctypes.c_char_p(fb), len(fb), ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor),
            int(start_index), int(stop_index), int(direction or (1 if start_index <= stop_index else -1)), ctypes.byref(found)
        )
        return int(found.value) if ret == 1 else None
    except Exception:
        return None



def _iapt_enum_main_max_bytes() -> int:
    try:
        return max(16, int(os.environ.get("IAPT_ENUM_MAIN_MAX_BYTES", "8388608")))
    except Exception:
        return 8388608


def _cfast_fixed_dexkey_scan_mian(container: bytes, hidden: bytes, package: str, version_name: str, version_code, app_label: str, start_fb: int, stop_fb: int, direction: int, post_key: bytes, key_xor: bytes, main_file: str = "mian.iyu") -> Optional[int]:
    if _C_FAST_MODE == "off":
        return None
    lib = _load_c_fast_core(False)
    if lib is None or not hasattr(lib, "iapp_fixed_dexkey_scan_mian"):
        return None
    found = c_int(-1)
    pkg = str(package).encode(); vn = str(version_name).encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label).encode(); mf = str(main_file or MUST_HAVE_MAIN).encode()
    try:
        ret = lib.iapp_fixed_dexkey_scan_mian(
            ctypes.c_char_p(container), len(container), ctypes.c_char_p(hidden), len(hidden),
            ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab),
            int(start_fb), int(stop_fb), int(direction or (1 if start_fb <= stop_fb else -1)),
            ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor), ctypes.c_char_p(mf), len(mf), _iapt_enum_main_max_bytes(), ctypes.byref(found)
        )
        return int(found.value) if ret == 1 else None
    except Exception:
        return None


def _cfast_fixed_hidden_list_scan_mian(container: bytes, hidden_candidates: List[bytes], package: str, version_name: str, version_code, app_label: str, fb_value, start_index: int, stop_index: int, direction: int, post_key: bytes, key_xor: bytes, main_file: str = "mian.iyu") -> Optional[int]:
    if _C_FAST_MODE == "off" or not hidden_candidates:
        return None
    lib = _load_c_fast_core(False)
    if lib is None or not hasattr(lib, "iapp_fixed_hidden_list_scan_mian"):
        return None
    hlen = len(hidden_candidates[0])
    if hlen <= 0 or any(len(h) != hlen for h in hidden_candidates):
        return None
    blob = b"".join(hidden_candidates)
    pkg = str(package).encode(); vn = str(version_name).encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label).encode(); fb = str(parse_int_auto(fb_value)).encode(); mf = str(main_file or MUST_HAVE_MAIN).encode()
    found = c_int(-1)
    try:
        ret = lib.iapp_fixed_hidden_list_scan_mian(
            ctypes.c_char_p(container), len(container), ctypes.c_char_p(blob), len(hidden_candidates), hlen,
            ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab),
            ctypes.c_char_p(fb), len(fb), ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor),
            int(start_index), int(stop_index), int(direction or (1 if start_index <= stop_index else -1)), ctypes.c_char_p(mf), len(mf), _iapt_enum_main_max_bytes(), ctypes.byref(found)
        )
        return int(found.value) if ret == 1 else None
    except Exception:
        return None


def _iapt_cbatch_extra_bytes() -> Tuple[bytes, bytes]:
    sig = _EXTRA_OUTER_ENV.get("signature") or b""
    if isinstance(sig, str):
        sig = sig.encode()
    jg = _EXTRA_OUTER_ENV.get("jgapp") or b""
    if isinstance(jg, str):
        jg = jg.encode()
    return bytes(sig or b""), bytes(jg or b"")


def _cfast_idbfj_dexkey_scan_mian(container: bytes, hidden: bytes, package: str, version_name: str, version_code, app_label: str, input_bytes: bytes, signature: bytes, start_fb: int, stop_fb: int, direction: int, post_key: bytes, key_xor: bytes, main_file: str = "mian.iyu") -> Optional[Tuple[int, int]]:
    lib = _load_c_fast_core(verbose=False)
    if lib is None or not hasattr(lib, "iapp_idbfj_dexkey_scan_mian") or not input_bytes:
        return None
    found = ctypes.c_int(0)
    variant = ctypes.c_int(-1)
    pkg = str(package or "").encode(); vn = str(version_name or "").encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label or "").encode(); mf = str(main_file or MUST_HAVE_MAIN).encode()
    sig = bytes(signature or b""); inp = bytes(input_bytes or b"")
    ret = lib.iapp_idbfj_dexkey_scan_mian(
        ctypes.c_char_p(container), len(container), ctypes.c_char_p(hidden), len(hidden),
        ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab),
        ctypes.c_char_p(inp), len(inp), ctypes.c_char_p(sig), len(sig),
        int(start_fb), int(stop_fb), int(direction or (1 if start_fb <= stop_fb else -1)),
        ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor),
        ctypes.c_char_p(mf), len(mf), _iapt_enum_main_max_bytes(), ctypes.byref(found), ctypes.byref(variant)
    )
    if ret == 1:
        return int(found.value), int(variant.value)
    return None



def _cfast_idbfj_parallel_scan_mian(
    container: bytes, hidden: bytes, package: str, version_name: str, version_code,
    app_label: str, inputs: List[Tuple[str, bytes]], signature: bytes,
    lanes: List[List[Tuple[int, int, int]]], chunk_size: int,
    keysets: List[Tuple[str, bytes, bytes]], main_file: str = "mian.iyu",
    cpu_slots: Optional[List[int]] = None,
) -> Optional[Tuple[int, int, int, int, int]]:
    """Run all idbfj lanes in native pthreads through a single ctypes call."""
    lib = _load_c_fast_core(False)
    if lib is None or not hasattr(lib, "iapp_idbfj_dexkey_scan_mian_parallel"):
        return None
    clean_inputs: List[Tuple[str, bytes]] = []
    seen = set()
    if hidden:
        clean_inputs.append(("hidden", bytes(hidden))); seen.add(bytes(hidden))
    for name, value in inputs or []:
        value = bytes(value or b"")
        if value and value not in seen:
            seen.add(value); clean_inputs.append((str(name), value))
    clean_keys = [(str(n), bytes(pk), bytes(xk)) for n, pk, xk in (keysets or []) if pk and xk]
    live_lanes = [lane for lane in (lanes or []) if lane]
    if not clean_inputs or not clean_keys or not live_lanes:
        return None

    def pack(items: List[bytes]):
        blob = b"".join(items)
        offs=[]; lens=[]; pos=0
        for item in items:
            offs.append(pos); lens.append(len(item)); pos += len(item)
        A = ctypes.c_int * len(items)
        return blob, A(*offs), A(*lens)

    in_blob, in_off, in_len = pack([v for _, v in clean_inputs])
    post_blob, post_off, post_len = pack([pk for _, pk, _ in clean_keys])
    xk_blob, xk_off, xk_len = pack([xk for _, _, xk in clean_keys])
    starts=[]; stops=[]; dirs=[]
    for lane in live_lanes:
        starts.append(int(lane[0][0])); stops.append(int(lane[-1][1]));
        dirs.append(1 if int(lane[0][0]) <= int(lane[0][1]) else -1)
    L = ctypes.c_int * len(starts)
    lane_start=L(*starts); lane_stop=L(*stops); lane_dir=L(*dirs)
    slots=[int(x) for x in (cpu_slots or [])]
    lane_cpu=L(*([slots[i % len(slots)] if slots else -1 for i in range(len(starts))]))
    pkg=str(package or "").encode(); vn=str(version_name or "").encode();
    vc=str(parse_int_auto(version_code)).encode(); lab=str(app_label or "").encode();
    sig=bytes(signature or b""); mf=str(main_file or MUST_HAVE_MAIN).encode()
    found=ctypes.c_int(-1); variant=ctypes.c_int(-1); lane_id=ctypes.c_int(-1)
    keyset_id=ctypes.c_int(-1); input_id=ctypes.c_int(-1)
    try:
        ret=lib.iapp_idbfj_dexkey_scan_mian_parallel(
            ctypes.c_char_p(container),len(container),ctypes.c_char_p(hidden),len(hidden),
            ctypes.c_char_p(pkg),len(pkg),ctypes.c_char_p(vn),len(vn),ctypes.c_char_p(vc),len(vc),
            ctypes.c_char_p(lab),len(lab),ctypes.c_char_p(in_blob),in_off,in_len,len(clean_inputs),
            ctypes.c_char_p(sig),len(sig),lane_start,lane_stop,lane_dir,lane_cpu,len(starts),int(chunk_size),
            ctypes.c_char_p(post_blob),post_off,post_len,ctypes.c_char_p(xk_blob),xk_off,xk_len,len(clean_keys),
            ctypes.c_char_p(mf),len(mf),_iapt_enum_main_max_bytes(),ctypes.byref(found),ctypes.byref(variant),
            ctypes.byref(lane_id),ctypes.byref(keyset_id),ctypes.byref(input_id))
    except Exception:
        return None
    if ret == 1:
        return int(found.value), int(variant.value), int(lane_id.value), int(keyset_id.value), int(input_id.value)
    return None


def _iapt_priority_idbfj_inputs(extra_env: Dict[str, bytes]) -> List[Tuple[str, bytes]]:
    out: List[Tuple[str, bytes]] = []
    seen: Set[bytes] = set()
    for name in ["user_password_native"] + [f"user_password_native_{i}" for i in range(1, 8)] + ["user_password", "password"]:
        value = (extra_env or {}).get(name) or b""
        if isinstance(value, str):
            value = value.encode()
        value = bytes(value or b"")
        if value and value not in seen:
            seen.add(value); out.append((name, value))
    return out



def _iapt_balanced_index_order(count: int, lanes: int) -> List[int]:
    count=max(0,int(count)); lanes=max(1,min(int(lanes or 1),count or 1))
    if count<=1:return list(range(count))
    seg=[]
    for i in range(lanes):
        lo=(count*i)//lanes; hi=(count*(i+1))//lanes-1
        if lo<=hi:seg.append(list(range(lo,hi+1)) if i%2==0 else list(range(hi,lo-1,-1)))
    out=[]
    depth=0
    while True:
        added=False
        for part in seg:
            if depth<len(part):out.append(part[depth]);added=True
        if not added:break
        depth+=1
    return out


def _iapt_sokey_timegrid_order(count: int, lanes: int = 8) -> List[int]:
    """Keep the exhaustive generator's priority order unchanged.

    v138 uses a native two-dimensional diagonal scheduler, so reordering the
    milliseconds here only obscures the intended (predicted-second, natural-ms)
    priority.  The candidate set and order are both deterministic.
    """
    return list(range(max(0, int(count))))

def _cfast_joint_sokey_dexkey_scan(container: bytes, hidden_candidates: List[bytes], package: str,
        version_name: str, version_code, app_label: str, constant_inputs: List[Tuple[str,bytes]],
        signature: bytes, lanes, keysets, workers: int, hidden_lanes: int, main_file: str = "mian.iyu",
        include_hidden_input: bool = True):
    lib=_load_c_fast_core(False)
    if lib is None or not hasattr(lib,"iapp_joint_sokey_dexkey_scan_mian_parallel") or not hidden_candidates:return None
    hlen=len(hidden_candidates[0])
    if any(len(h)!=hlen for h in hidden_candidates):return None
    order=_iapt_sokey_timegrid_order(len(hidden_candidates),hidden_lanes)
    ordered=[hidden_candidates[i] for i in order]; hidden_blob=b"".join(ordered)
    # The priority pass can omit dynamic-hidden when the APK explicitly requires
    # the native password transform.  This removes a full impossible formula
    # scan for every hidden×dexkey pair while the expanded pass remains exact.
    input_names=[]; input_vals=[]; input_kind=[]; seen=set()
    if include_hidden_input:
        input_names.append("hidden"); input_vals.append(b""); input_kind.append(1)
    for n,v in constant_inputs or []:
        v=bytes(v or b"")
        if v and v not in seen:seen.add(v);input_names.append(str(n));input_vals.append(v);input_kind.append(0)
    if not input_names:
        return None
    def pack(items):
        blob=b"".join(items);offs=[];lens=[];p=0
        for x in items:offs.append(p);lens.append(len(x));p+=len(x)
        A=ctypes.c_int*len(items);return blob,A(*offs),A(*lens)
    in_blob,in_off,in_len=pack(input_vals)
    post_blob,post_off,post_len=pack([bytes(pk) for _,pk,_ in keysets])
    xk_blob,xk_off,xk_len=pack([bytes(xk) for _,_,xk in keysets])
    # Breadth-first dex tiles: each hidden sees every anchor at the current depth
    # before any candidate advances to a deeper part of the numeric range.
    tiles=[]; max_depth=max((len(x) for x in lanes),default=0)
    depth_tiles=[]
    for d in range(max_depth):
        row=[]
        for lane in lanes:
            if d<len(lane):
                a,b,_=lane[d];row.append(len(tiles));tiles.append((int(a),int(b),1 if int(a)<=int(b) else -1))
        depth_tiles.append(row)
    # Tile rank is depth-major across all numeric anchors.  Native workers
    # enumerate (hidden_rank,tile_rank) by increasing diagonal sum.
    tile_order=[]
    for row in depth_tiles: tile_order.extend(row)
    if not tiles or not tile_order:return None
    IA=ctypes.c_int
    TS=IA*len(tiles);IK=IA*len(input_kind);TO=IA*len(tile_order)
    tile_start=TS(*(x[0] for x in tiles));tile_stop=TS(*(x[1] for x in tiles));tile_dir=TS(*(x[2] for x in tiles))
    tile_order_arr=TO(*tile_order);kind_arr=IK(*input_kind)
    workers=max(1,min(int(workers or 1),32)); cpu=[]
    if hasattr(os,"sched_getaffinity"):
        try:cpu=sorted(int(x) for x in os.sched_getaffinity(0))[:workers]
        except Exception:cpu=[]
    CA=IA*workers;cpu_arr=CA(*([cpu[i%len(cpu)] if cpu else -1 for i in range(workers)]))
    pkg=str(package or "").encode();vn=str(version_name or "").encode();vc=str(parse_int_auto(version_code)).encode();lab=str(app_label or "").encode();sig=bytes(signature or b"");mf=str(main_file or MUST_HAVE_MAIN).encode()
    fh=IA(-1);ff=IA(-1);fv=IA(-1);fk=IA(-1);fi=IA(-1);ft=IA(-1)
    diagonal=getattr(lib,"iapp_joint_sokey_dexkey_scan_mian_parallel_diagonal",None)
    if diagonal is None:return None
    ret=diagonal(
        ctypes.c_char_p(container),len(container),ctypes.c_char_p(hidden_blob),len(ordered),hlen,
        ctypes.c_char_p(pkg),len(pkg),ctypes.c_char_p(vn),len(vn),ctypes.c_char_p(vc),len(vc),ctypes.c_char_p(lab),len(lab),
        ctypes.c_char_p(in_blob),in_off,in_len,kind_arr,len(input_vals),ctypes.c_char_p(sig),len(sig),
        tile_start,tile_stop,tile_dir,tile_order_arr,len(tiles),cpu_arr,workers,
        ctypes.c_char_p(post_blob),post_off,post_len,ctypes.c_char_p(xk_blob),xk_off,xk_len,len(keysets),
        ctypes.c_char_p(mf),len(mf),_iapt_enum_main_max_bytes(),ctypes.byref(fh),ctypes.byref(ff),ctypes.byref(fv),ctypes.byref(fk),ctypes.byref(fi),ctypes.byref(ft))
    if ret==1 and 0<=fh.value<len(order):
        return order[fh.value],ff.value,fv.value,fk.value,input_names[fi.value] if 0<=fi.value<len(input_names) else "?",ft.value
    return None

def _cfast_broad_dexkey_scan_mian(container: bytes, hidden: bytes, package: str, version_name: str, version_code, app_label: str, start_fb: int, stop_fb: int, direction: int, post_key: bytes, key_xor: bytes, main_file: str = "mian.iyu") -> Optional[Tuple[int, int]]:
    lib = _load_c_fast_core(verbose=False)
    if lib is None or not hasattr(lib, "iapp_broad_dexkey_scan_mian"):
        return None
    found = ctypes.c_int(0)
    alg = ctypes.c_int(0)
    sig, jg = _iapt_cbatch_extra_bytes()
    pkg = str(package or "").encode(); vn = str(version_name or "").encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label or "").encode(); mf = str(main_file or MUST_HAVE_MAIN).encode()
    ret = lib.iapp_broad_dexkey_scan_mian(
        ctypes.c_char_p(container), len(container), ctypes.c_char_p(hidden), len(hidden),
        ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab),
        ctypes.c_char_p(sig), len(sig), ctypes.c_char_p(jg), len(jg), int(start_fb), int(stop_fb), int(direction or (1 if start_fb <= stop_fb else -1)),
        ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor), ctypes.c_char_p(mf), len(mf), _iapt_enum_main_max_bytes(), ctypes.byref(found), ctypes.byref(alg)
    )
    if ret == 1:
        return int(found.value), int(alg.value)
    return None


def _cfast_broad_hidden_list_scan_mian(container: bytes, hidden_candidates: List[bytes], package: str, version_name: str, version_code, app_label: str, fb_value, start_index: int, stop_index: int, direction: int, post_key: bytes, key_xor: bytes, main_file: str = "mian.iyu") -> Optional[Tuple[int, int]]:
    lib = _load_c_fast_core(verbose=False)
    if lib is None or not hasattr(lib, "iapp_broad_hidden_list_scan_mian"):
        return None
    if not hidden_candidates:
        return None
    hlen = len(hidden_candidates[0])
    if any(len(x) != hlen for x in hidden_candidates):
        return None
    blob = b"".join(hidden_candidates)
    found = ctypes.c_int(0); alg = ctypes.c_int(0)
    sig, jg = _iapt_cbatch_extra_bytes()
    pkg = str(package or "").encode(); vn = str(version_name or "").encode(); vc = str(parse_int_auto(version_code)).encode(); lab = str(app_label or "").encode(); fb = str(parse_int_auto(fb_value)).encode(); mf = str(main_file or MUST_HAVE_MAIN).encode()
    ret = lib.iapp_broad_hidden_list_scan_mian(
        ctypes.c_char_p(container), len(container), ctypes.c_char_p(blob), len(hidden_candidates), hlen,
        ctypes.c_char_p(pkg), len(pkg), ctypes.c_char_p(vn), len(vn), ctypes.c_char_p(vc), len(vc), ctypes.c_char_p(lab), len(lab), ctypes.c_char_p(fb), len(fb),
        ctypes.c_char_p(sig), len(sig), ctypes.c_char_p(jg), len(jg), ctypes.c_char_p(post_key), len(post_key), ctypes.c_char_p(key_xor), len(key_xor),
        int(start_index), int(stop_index), int(direction or (1 if start_index <= stop_index else -1)), ctypes.c_char_p(mf), len(mf), _iapt_enum_main_max_bytes(), ctypes.byref(found), ctypes.byref(alg)
    )
    if ret == 1:
        return int(found.value), int(alg.value)
    return None

def _iapt_cbatch_keysets_from_plan(plan: Dict[str, object]) -> List[Tuple[str, bytes, bytes]]:
    """Return C-enum keysets in evidence order.

    Keep exact post/xor pairs recovered from the same ABI ahead of the old
    cross-product list.  x86 exact pairs are preferred for burden1b/idbfj
    formulas; mixing constants from different ABIs is retained only as a
    fallback.  This avoids rescanning a large assets/lib.so several times with
    impossible key pairs before reaching the real x86 pair.
    """
    exact: List[Tuple[int, str, bytes, bytes]] = []
    for label, _cands, key_sets in list(plan.get("priority_plans") or []):
        label_s = str(label)
        for name, pk, xk in list(key_sets or []):
            if not pk or not xk or not str(name).startswith("so-exact"):
                continue
            # Native x86 burden1b/idbfj is the best-supported recovered model.
            # A pair whose constants differ is also more credible than the
            # common false-positive case where one byte table is used for both.
            score = 0
            if "/x86/" not in label_s.replace("\\", "/"):
                score += 10
            if bytes(pk) == bytes(xk):
                score += 2
            exact.append((score, f"{label_s}:{name}", bytes(pk), bytes(xk)))
    exact.sort(key=lambda x: x[0])

    candidates: List[Tuple[str, bytes, bytes]] = [(n, pk, xk) for _s, n, pk, xk in exact]
    # Try deterministic/generic keysets before noisy fallback SO cross-products.
    # Some stripped SOs produce thousands of false table candidates; putting them
    # before the generic/exact pairs can make enum look frozen.
    candidates += list(plan.get("fast_keysets") or [])
    candidates += list(plan.get("so_keysets") or [])

    out: List[Tuple[str, bytes, bytes]] = []
    seen = set()
    try:
        _fallback_cap = max(0, int(plan.get("dexkey_max_so_keysets", 16) or 0))
    except Exception:
        _fallback_cap = 16
    _fallback_used = 0
    for name, pk, xk in candidates:
        _is_fallback = str(name).startswith("so-primary[") or str(name).startswith("so-pair[") or str(name).startswith("so[")
        if _is_fallback and _fallback_cap > 0 and _fallback_used >= _fallback_cap:
            continue
        if not pk or not xk or len(xk) <= 0:
            continue
        sig = (bytes(pk), bytes(xk))
        if sig in seen:
            continue
        seen.add(sig)
        out.append((str(name), bytes(pk), bytes(xk)))
        if _is_fallback:
            _fallback_used += 1
    return out


_C_CORE = None


def load_c_core(path: str = "./libiapp_core.so"):
    global _C_CORE
    if _C_CORE is not None:
        return _C_CORE
    lib = ctypes.CDLL(path)
    lib.slky_c.argtypes = [c_void_p, c_int, c_void_p, c_int, c_void_p, c_int, c_void_p]
    lib.slky_c.restype = c_int
    _C_CORE = lib
    return lib


class SlkyContext:
    def __init__(self, post_key: bytes, use_c: bool = False, c_path: str = "./libiapp_core.so"):
        if not post_key:
            raise ValueError("empty SLKY_POST_KEY")
        self.post_key = bytes(post_key)
        self.use_c = use_c
        self.c_lib = load_c_core(c_path) if use_c else None
        self.fast_lib = (_load_c_fast_core(False) if ((not use_c) and _C_FAST_MODE == "on") else None)

        @lru_cache(maxsize=300000)
        def _cached(a: bytes, b: bytes) -> bytes:
            if self.use_c:
                return self._slky_c(a, b)
            if self.fast_lib is not None:
                out = self._slky_fast(a, b)
                if out is not None:
                    return out
            return self._slky_raw(a, b)
        self._cached = _cached

    def slky(self, a: bytes | str, b: bytes | str = b"") -> bytes:
        if isinstance(a, str):
            a = a.encode()
        if isinstance(b, str):
            b = b.encode()
        return self._cached(bytes(a), bytes(b))

    def _slky_c(self, a: bytes, b: bytes) -> bytes:
        out = (c_uint8 * 16)()
        a_buf = (c_uint8 * len(a)).from_buffer_copy(a)
        if b:
            b_buf = (c_uint8 * len(b)).from_buffer_copy(b)
            b_ptr = ctypes.cast(b_buf, c_void_p)
            b_len = len(b)
        else:
            b_ptr = None
            b_len = 0
        post_buf = (c_uint8 * len(self.post_key)).from_buffer_copy(self.post_key)
        ret = self.c_lib.slky_c(ctypes.cast(a_buf, c_void_p), len(a), b_ptr, b_len, ctypes.cast(post_buf, c_void_p), len(self.post_key), ctypes.cast(out, c_void_p))
        if ret != 0:
            raise RuntimeError(f"slky_c failed: {ret}")
        return bytes(out)

    def _slky_fast(self, a: bytes, b: bytes) -> Optional[bytes]:
        if self.fast_lib is None or not a:
            return None
        out = (c_uint8 * 16)()
        try:
            ret = self.fast_lib.iapp_slky_core(
                ctypes.c_char_p(a), len(a), ctypes.c_char_p(b) if b else None, len(b),
                ctypes.c_char_p(self.post_key), len(self.post_key), ctypes.cast(out, c_void_p)
            )
            if ret != 0:
                return None
            return bytes(out)
        except Exception:
            return None

    def _slky_raw(self, a: bytes, b: bytes = b"") -> bytes:
        if not a:
            raise ValueError("slky(a,b): a is empty")
        n = len(a)
        signed_sum = n + sum(s8(x) for x in a)
        avg = c_div(signed_sum, n)
        first = s8(a[0])
        last = s8(a[-1])
        mix = c_div(signed_sum + last * first, n)
        c = signed_sum - avg * n
        buf = bytearray(a)
        buf.extend(str(mix).encode())
        if b:
            buf.extend(b)
            c += len(b)
        mask = avg & 0xFF
        for i in range(len(buf)):
            buf[i] ^= mask
        digest = bytearray(hashlib.md5(bytes(buf)).digest())
        m = len(digest)
        half = m // 2
        c2 = c + half
        post_key = self.post_key
        post_len = len(post_key)
        for i in range(m):
            cur = s8(digest[i])
            r = abs(cur) % m
            v = cur
            if half < r:
                v = s8((v ^ c2) & 0xFF)
                digest[i] = v & 0xFF
            old_r = s8(digest[r])
            digest[r] = v & 0xFF
            digest[i] = (old_r ^ post_key[i % post_len]) & 0xFF
        return bytes(digest)

    def cache_info(self):
        return self._cached.cache_info()

    def cache_clear(self):
        self._cached.cache_clear()


class NoPostSlkyContext(SlkyContext):
    """
    iApp native variants in newer arm64/x86_64 samples use the same MD5/swap
    slky core but omit the final XOR with SLKY_POST_KEY.  This context keeps the
    public slky(a,b) interface so it can be used by the existing expression
    engine and member-marker verifier.
    """
    def __init__(self):
        self.post_key = b""
        self.use_c = False
        self.c_lib = None
        self.fast_lib = (_load_c_fast_core(False) if _C_FAST_MODE == "on" else None)

        @lru_cache(maxsize=300000)
        def _cached(a: bytes, b: bytes) -> bytes:
            if self.fast_lib is not None:
                out = self._slky_fast_no_post(a, b)
                if out is not None:
                    return out
            return self._slky_raw_no_post(a, b)
        self._cached = _cached

    def _slky_fast_no_post(self, a: bytes, b: bytes) -> Optional[bytes]:
        if self.fast_lib is None or not a:
            return None
        out = (c_uint8 * 16)()
        try:
            ret = self.fast_lib.iapp_slky_core(
                ctypes.c_char_p(a), len(a), ctypes.c_char_p(b) if b else None, len(b),
                None, 0, ctypes.cast(out, c_void_p)
            )
            if ret != 0:
                return None
            return bytes(out)
        except Exception:
            return None

    def _slky_raw_no_post(self, a: bytes, b: bytes = b"") -> bytes:
        if not a:
            raise ValueError("slky(a,b): a is empty")
        n = len(a)
        signed_sum = n + sum(s8(x) for x in a)
        avg = c_div(signed_sum, n)
        first = s8(a[0])
        last = s8(a[-1])
        mix = c_div(signed_sum + last * first, n)
        c = signed_sum - avg * n
        buf = bytearray(a)
        buf.extend(str(mix).encode())
        if b:
            buf.extend(b)
            c += len(b)
        mask = avg & 0xFF
        for i in range(len(buf)):
            buf[i] ^= mask
        digest = bytearray(hashlib.md5(bytes(buf)).digest())
        m = len(digest)
        half = m // 2
        c2 = c + half
        for i in range(m):
            cur = s8(digest[i])
            r = abs(cur) % m
            v = cur
            if half < r:
                v = s8((v ^ c2) & 0xFF)
                digest[i] = v & 0xFF
            old_r = s8(digest[r])
            digest[r] = v & 0xFF
            digest[i] = old_r & 0xFF
        return bytes(digest)


class MiniELF:
    def __init__(self, data: bytes):
        self.data = data
        if data[:4] != b"\x7fELF":
            raise ValueError("not ELF")
        self.bits = 64 if data[4] == 2 else 32
        if data[5] != 1:
            raise ValueError("only little endian ELF is supported")
        self._parse64() if self.bits == 64 else self._parse32()
        self._load_section_names()
        self._symbols_cache: Optional[List[Dict]] = None

    def _parse64(self):
        hdr = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
        (_, self.e_type, self.e_machine, _, self.e_entry, self.e_phoff, self.e_shoff, _, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx) = hdr
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh = struct.unpack_from("<IIQQQQIIQQ", self.data, off)
            self.sections.append({"name_off": sh[0], "type": sh[1], "flags": sh[2], "addr": sh[3], "offset": sh[4], "size": sh[5], "link": sh[6], "info": sh[7], "addralign": sh[8], "entsize": sh[9]})
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p = struct.unpack_from("<IIQQQQQQ", self.data, off)
            self.phdrs.append({"type": p[0], "flags": p[1], "offset": p[2], "vaddr": p[3], "paddr": p[4], "filesz": p[5], "memsz": p[6], "align": p[7]})

    def _parse32(self):
        hdr = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data, 0)
        (_, self.e_type, self.e_machine, _, self.e_entry, self.e_phoff, self.e_shoff, _, self.e_ehsize, self.e_phentsize, self.e_phnum, self.e_shentsize, self.e_shnum, self.e_shstrndx) = hdr
        self.sections = []
        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh = struct.unpack_from("<IIIIIIIIII", self.data, off)
            self.sections.append({"name_off": sh[0], "type": sh[1], "flags": sh[2], "addr": sh[3], "offset": sh[4], "size": sh[5], "link": sh[6], "info": sh[7], "addralign": sh[8], "entsize": sh[9]})
        self.phdrs = []
        for i in range(self.e_phnum):
            off = self.e_phoff + i * self.e_phentsize
            p = struct.unpack_from("<IIIIIIII", self.data, off)
            self.phdrs.append({"type": p[0], "offset": p[1], "vaddr": p[2], "paddr": p[3], "filesz": p[4], "memsz": p[5], "flags": p[6], "align": p[7]})

    def _load_section_names(self):
        if not (0 <= self.e_shstrndx < len(self.sections)):
            return
        shstr = self.sections[self.e_shstrndx]
        blob = self.data[shstr["offset"]:shstr["offset"] + shstr["size"]]
        for s in self.sections:
            no = s["name_off"]
            end = blob.find(b"\x00", no)
            s["name"] = blob[no:end].decode("utf-8", "replace") if end >= 0 else ""

    def section_by_name(self, name: str):
        for s in self.sections:
            if s.get("name") == name:
                return s
        return None

    def vaddr_to_offset(self, vaddr: int) -> Optional[int]:
        for p in self.phdrs:
            if p["type"] != 1:
                continue
            start = p["vaddr"]
            end = start + p["filesz"]
            if start <= vaddr < end:
                return p["offset"] + (vaddr - start)
        for s in self.sections:
            start = s["addr"]
            end = start + s["size"]
            if start <= vaddr < end:
                return s["offset"] + (vaddr - start)
        return None

    def read_symbols(self) -> List[Dict]:
        if self._symbols_cache is not None:
            return self._symbols_cache
        out = []
        for sec_name in (".symtab", ".dynsym"):
            sec = self.section_by_name(sec_name)
            if not sec or not sec["entsize"] or sec["link"] >= len(self.sections):
                continue
            strsec = self.sections[sec["link"]]
            strtab = self.data[strsec["offset"]:strsec["offset"] + strsec["size"]]
            for i in range(sec["size"] // sec["entsize"]):
                off = sec["offset"] + i * sec["entsize"]
                if self.bits == 64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from("<IBBHQQ", self.data, off)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from("<IIIBBH", self.data, off)
                if st_name >= len(strtab):
                    continue
                end = strtab.find(b"\x00", st_name)
                if end < 0:
                    continue
                name = strtab[st_name:end].decode("utf-8", "replace")
                if name:
                    out.append({"name": name, "value": st_value, "size": st_size, "info": st_info, "shndx": st_shndx})
        self._symbols_cache = out
        return out

    def get_symbols_contains(self, needle: str, fallback_size: int = 0x8000):
        out = []
        for s in self.read_symbols():
            if needle not in s["name"]:
                continue
            off = self.vaddr_to_offset(s["value"])
            if off is None:
                continue
            size = s["size"] or fallback_size
            out.append((s, self.data[off:off + size]))
        out.sort(key=lambda x: (0 if x[0]["size"] else 1, x[0]["value"]))
        return out


def arm64_mov_imm_w(insn: int):
    if (insn & 0x7F800000) == 0x52800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 3
        val = (imm16 << (16 * hw)) & 0xFFFFFFFF
        return rd, val & 0xFF
    if (insn & 0x7F800000) == 0x12800000:
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 3
        val = (~(imm16 << (16 * hw))) & 0xFFFFFFFF
        return rd, val & 0xFF
    return None


def arm64_strb_unsigned(insn: int):
    if (insn & 0xFFC00000) != 0x39000000:
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = (insn >> 10) & 0xFFF
    return rt, rn, imm


def split_zero_and_lengths(blob: bytes) -> List[bytes]:
    out = []
    if b"\x00" in blob:
        for part in blob.split(b"\x00"):
            if 16 <= len(part) <= 96:
                out.append(part)
    else:
        if 16 <= len(blob) <= 96:
            out.append(blob)
    for n in (16, 20, 32, 38, 39, 40, 48, 64, 72, 83, 84, 85, 96):
        if len(blob) >= n:
            out.append(blob[:n])
    return uniq_bytes_list(out)


def extract_arm64_strb_tables(func_code: bytes, min_len: int = 16) -> List[bytes]:
    regs: Dict[int, int] = {}
    stores = []
    for idx in range(0, len(func_code) - 3, 4):
        insn = struct.unpack_from("<I", func_code, idx)[0]
        mv = arm64_mov_imm_w(insn)
        if mv:
            regs[mv[0]] = mv[1]
            continue
        st = arm64_strb_unsigned(insn)
        if st:
            rt, rn, imm = st
            if rt == 31:
                val = 0
            elif rt in regs:
                val = regs[rt]
            else:
                continue
            stores.append((idx // 4, rn, imm, val & 0xFF))
    candidates = []
    for start in range(len(stores)):
        base_i, base_r, _off, _val = stores[start]
        local = []
        for i, rn, off, val in stores[start:]:
            if i - base_i > 420:
                break
            if rn == base_r:
                local.append((off, val))
        if len(local) < min_len:
            continue
        d: Dict[int, int] = {}
        for off, val in local:
            d[off] = val
        run = []
        last = None
        for off in sorted(d):
            if last is None or off == last + 1:
                run.append(off)
            else:
                if len(run) >= min_len:
                    candidates.extend(split_zero_and_lengths(bytes(d[x] for x in run)))
                run = [off]
            last = off
        if len(run) >= min_len:
            candidates.extend(split_zero_and_lengths(bytes(d[x] for x in run)))
    return uniq_bytes_list(candidates)


def get_exec_sections(elf: MiniELF):
    out = []
    for sec in elf.sections:
        name = sec.get("name", "")
        flags = sec.get("flags", 0)
        # SHF_EXECINSTR = 0x4
        if name == ".text" or (flags & 0x4):
            off = sec["offset"]
            size = sec["size"]
            vaddr = sec["addr"]
            out.append((name, vaddr, elf.data[off:off + size]))
    return out


def extract_x86_mov_tables(func_code: bytes, min_len: int = 16) -> List[bytes]:
    """
    x86 32-bit 表提取。覆盖常见：
      c6 45 xx imm8              mov byte [ebp+disp8], imm8
      c6 85 xx xx xx xx imm8     mov byte [ebp+disp32], imm8
      c7 45 xx imm32             mov dword [ebp+disp8], imm32
      c7 85 xx xx xx xx imm32    mov dword [ebp+disp32], imm32
      c6 40 xx imm8              mov byte [eax+disp8], imm8
      c6 80 xx xx xx xx imm8     mov byte [eax+disp32], imm8
      c7 40 xx imm32             mov dword [eax+disp8], imm32
      c7 80 xx xx xx xx imm32    mov dword [eax+disp32], imm32
    返回候选 bytes。为了兼容混淆函数名，也可用于整段 .text 扫描。
    """
    stores = []  # (insn_index, base_name, disp, val)
    i = 0
    n = len(func_code)

    while i < n - 10:
        b0 = func_code[i]
        b1 = func_code[i + 1]

        # mov byte ptr [ebp+disp8], imm8
        if b0 == 0xC6 and b1 == 0x45 and i + 4 <= n:
            disp = struct.unpack_from('b', func_code, i + 2)[0]
            imm = func_code[i + 3]
            stores.append((i, 'ebp', disp, imm))
            i += 4
            continue

        # mov byte ptr [ebp+disp32], imm8
        if b0 == 0xC6 and b1 == 0x85 and i + 7 <= n:
            disp = struct.unpack_from('<i', func_code, i + 2)[0]
            imm = func_code[i + 6]
            stores.append((i, 'ebp', disp, imm))
            i += 7
            continue

        # mov dword ptr [ebp+disp8], imm32
        if b0 == 0xC7 and b1 == 0x45 and i + 7 <= n:
            disp = struct.unpack_from('b', func_code, i + 2)[0]
            imm32 = func_code[i + 3:i + 7]
            for k, val in enumerate(imm32):
                stores.append((i, 'ebp', disp + k, val))
            i += 7
            continue

        # mov dword ptr [ebp+disp32], imm32
        if b0 == 0xC7 and b1 == 0x85 and i + 10 <= n:
            disp = struct.unpack_from('<i', func_code, i + 2)[0]
            imm32 = func_code[i + 6:i + 10]
            for k, val in enumerate(imm32):
                stores.append((i, 'ebp', disp + k, val))
            i += 10
            continue

        # mov byte ptr [eax], imm8
        # Some x86 builds initialize the first byte with C6 00 xx, then the rest
        # with C6 40 disp xx.  Without this, offset 0 is missing and the whole
        # key candidate is shifted/truncated.
        if b0 == 0xC6 and b1 == 0x00 and i + 3 <= n:
            imm = func_code[i + 2]
            stores.append((i, 'eax', 0, imm))
            i += 3
            continue

        # mov dword ptr [eax], imm32
        if b0 == 0xC7 and b1 == 0x00 and i + 6 <= n:
            imm32 = func_code[i + 2:i + 6]
            for k, val in enumerate(imm32):
                stores.append((i, 'eax', k, val))
            i += 6
            continue

        # mov byte ptr [eax+disp8], imm8
        if b0 == 0xC6 and b1 == 0x40 and i + 4 <= n:
            disp = struct.unpack_from('b', func_code, i + 2)[0]
            imm = func_code[i + 3]
            stores.append((i, 'eax', disp, imm))
            i += 4
            continue

        # mov byte ptr [eax+disp32], imm8
        if b0 == 0xC6 and b1 == 0x80 and i + 7 <= n:
            disp = struct.unpack_from('<i', func_code, i + 2)[0]
            imm = func_code[i + 6]
            stores.append((i, 'eax', disp, imm))
            i += 7
            continue

        # mov dword ptr [eax+disp8], imm32
        if b0 == 0xC7 and b1 == 0x40 and i + 7 <= n:
            disp = struct.unpack_from('b', func_code, i + 2)[0]
            imm32 = func_code[i + 3:i + 7]
            for k, val in enumerate(imm32):
                stores.append((i, 'eax', disp + k, val))
            i += 7
            continue

        # mov dword ptr [eax+disp32], imm32
        if b0 == 0xC7 and b1 == 0x80 and i + 10 <= n:
            disp = struct.unpack_from('<i', func_code, i + 2)[0]
            imm32 = func_code[i + 6:i + 10]
            for k, val in enumerate(imm32):
                stores.append((i, 'eax', disp + k, val))
            i += 10
            continue

        i += 1

    candidates = []

    for start_idx in range(len(stores)):
        base_i, base_name, _disp, _val = stores[start_idx]
        local = []
        for insn_i, name, disp, val in stores[start_idx:]:
            if insn_i - base_i > 0x700:
                break
            if name == base_name:
                local.append((disp, val))
        if len(local) < min_len:
            continue

        d = {}
        for disp, val in local:
            d[disp] = val & 0xff

        run = []
        last = None
        for off in sorted(d):
            if last is None or off == last + 1:
                run.append(off)
            else:
                if len(run) >= min_len:
                    candidates.extend(split_zero_and_lengths(bytes(d[x] for x in run)))
                run = [off]
            last = off
        if len(run) >= min_len:
            candidates.extend(split_zero_and_lengths(bytes(d[x] for x in run)))

    return uniq_bytes_list(candidates)



def _looks_like_binary_key_blob(blob: bytes) -> bool:
    if not (16 <= len(blob) <= 96):
        return False
    if not any(blob):
        return False
    high = sum(1 for b in blob if b >= 0x80)
    printable = sum(1 for b in blob if 0x20 <= b < 0x7f)
    distinct = len(set(blob))
    # Avoid ordinary JNI class/method strings while keeping random-looking key tables.
    return high >= 4 and printable / max(1, len(blob)) < 0.70 and distinct >= min(12, len(blob) // 2)


def extract_x86_pic_rodata_copies(elf: MiniELF, func_sym: Dict, min_len: int = 16, max_len: int = 96) -> List[bytes]:
    """
    Recover x86 PIC literal byte strings copied from .rodata, e.g.:
      call __x86.get_pc_thunk.bx
      add  ebx, imm32
      lea  esi, [ebx + disp32]
      mov  ecx, 0x15
      rep movsd
      movzx eax, byte ptr [esi]
      mov  byte ptr [edi], al

    This catches SLKY_POST_KEY in x86 builds where the post key is not built by
    C6/C7 byte stores but copied as a NUL-terminated binary blob from .rodata.
    """
    base, code = func_sym["value"], b""
    off = elf.vaddr_to_offset(base)
    if off is None:
        return []
    size = func_sym.get("size") or 0x8000
    code = elf.data[off:off + size]

    ebx_base = None
    scan_end = min(len(code) - 11, 96)
    for i in range(max(0, scan_end)):
        if code[i] == 0xE8 and code[i + 5:i + 7] == b"\x81\xc3":
            add_imm = struct.unpack_from("<i", code, i + 7)[0]
            ebx_base = (base + i + 5 + add_imm) & 0xFFFFFFFF
            break
    if ebx_base is None:
        return []

    out: List[bytes] = []
    i = 0
    while i < len(code) - 6:
        # LEA r32, [ebx+disp32] : 8D /r with mod=10b, r/m=011b.
        if code[i] == 0x8D and (code[i + 1] & 0xC7) == 0x83:
            disp = struct.unpack_from("<i", code, i + 2)[0]
            vaddr = (ebx_base + disp) & 0xFFFFFFFF
            roff = elf.vaddr_to_offset(vaddr)
            if roff is not None and 0 <= roff < len(elf.data):
                raw = elf.data[roff:roff + max_len + 1]
                nul = raw.find(b"\x00")
                if nul >= 0:
                    raw = raw[:nul]
                else:
                    raw = raw[:max_len]
                for cand in split_zero_and_lengths(raw):
                    if _looks_like_binary_key_blob(cand):
                        out.append(cand)
            i += 6
            continue
        i += 1
    return uniq_bytes_list(out)




def _x86_find_pic_base_from_code(func_base: int, code: bytes) -> Optional[int]:
    """Find the PIC base used by Android x86 code: call next; pop reg; add reg, imm32."""
    for i in range(0, min(len(code) - 12, 0x120)):
        if code[i] != 0xE8 or i + 12 > len(code):
            continue
        rel = struct.unpack_from('<i', code, i + 1)[0]
        target = (func_base + i + 5 + rel) & 0xffffffff
        # Most compiler thunks in these SOs use call $+5; pop reg; add reg, imm32.
        if target != (func_base + i + 5) & 0xffffffff:
            continue
        pop = code[i + 5]
        if not (0x58 <= pop <= 0x5f):
            continue
        reg = pop - 0x58
        # ADD r32, imm32 : 81 /0 id, mod=11, reg/opcode=0.
        if code[i + 6] == 0x81 and i + 12 <= len(code):
            m = code[i + 7]
            if (m & 0xF8) == 0xC0 and (m & 7) == reg:
                imm = struct.unpack_from('<i', code, i + 8)[0]
                return (func_base + i + 5 + imm) & 0xffffffff
    return None


def _x86_modrm_disp32_mem(code: bytes, off: int):
    if off >= len(code):
        return None
    m = code[off]
    mod = (m >> 6) & 3
    reg = (m >> 3) & 7
    rm = m & 7
    if mod != 2:
        return None
    p = off + 1
    # SIB forms are uncommon in the observed key-copy blocks; support simple disp32.
    if rm == 4:
        return None
    if p + 4 > len(code):
        return None
    disp = struct.unpack_from('<i', code, p)[0]
    return reg, rm, disp, 5


def extract_x86_sse_rodata_tables(elf: MiniELF, func_sym: Dict, min_len: int = 16, max_len: int = 128) -> List[bytes]:
    """
    Recover x86 PIC constant tables copied by SSE load/store sequences.

    Newer iApp x86 SOs build SLKY_POST_KEY / KEY_XOR_CONST with blocks like:
      movaps/movups/movdqu xmm0, [ebx+disp32]
      movups/movaps/movdqa [eax+off] or [esp+off], xmm0
      movsd xmm0, qword [ebx+disp32]
      movsd [eax+off] or [esp+off], xmm0

    The old C6/C7 and rodata string scanners miss these binary tables, causing
    the outer key search to try only junk ASCII constants.  This extractor
    reconstructs the destination buffer by its store offsets.
    """
    func_base = int(func_sym.get('value') or 0)
    off = elf.vaddr_to_offset(func_base)
    if off is None:
        return []
    code = elf.data[off:off + (func_sym.get('size') or 0x9000)]
    pic_base = _x86_find_pic_base_from_code(func_base, code)
    if pic_base is None:
        return []

    pending = None  # (load_off, data, size)
    stores = []     # (code_off, dest_base, dest_disp, data)
    i = 0
    while i < len(code) - 8:
        size = None
        modrm_off = None
        # 16-byte loads: 0f 28/10 /r, f3 0f 6f /r, 66 0f 6f /r.
        if code[i:i+2] in (b'\x0f\x28', b'\x0f\x10'):
            size = 16; modrm_off = i + 2
        elif code[i:i+3] in (b'\xf3\x0f\x6f', b'\x66\x0f\x6f'):
            size = 16; modrm_off = i + 3
        # 8-byte loads: f2 0f 10 /r (movsd), f3 0f 7e /r (movq)
        elif code[i:i+3] in (b'\xf2\x0f\x10', b'\xf3\x0f\x7e'):
            size = 8; modrm_off = i + 3
        if size is not None:
            m = _x86_modrm_disp32_mem(code, modrm_off)
            if m is not None:
                _xmm_reg, _base_reg, disp, used = m
                roff = elf.vaddr_to_offset((pic_base + disp) & 0xffffffff)
                if roff is not None and 0 <= roff + size <= len(elf.data):
                    pending = (i, elf.data[roff:roff + size], size)
                    i = modrm_off + used
                    continue

        if pending is not None:
            data = pending[1]
            # 16-byte stores to [eax] / [eax+disp8]
            if len(data) == 16 and code[i:i+3] in (b'\x0f\x11\x00', b'\x0f\x29\x00'):
                stores.append((i, 'eax', 0, data)); pending = None; i += 3; continue
            if len(data) == 16 and code[i:i+3] == b'\x0f\x11\x40' and i + 4 <= len(code):
                stores.append((i, 'eax', struct.unpack_from('b', code, i + 3)[0], data)); pending = None; i += 4; continue
            # 16-byte stores to [esp+disp8]: 0f 29/11 44 24 xx or 66 0f 7f 44 24 xx
            if len(data) == 16 and code[i:i+4] in (b'\x0f\x29\x44\x24', b'\x0f\x11\x44\x24') and i + 5 <= len(code):
                stores.append((i, 'esp', code[i + 4], data)); pending = None; i += 5; continue
            if len(data) == 16 and code[i:i+5] == b'\x66\x0f\x7f\x44\x24' and i + 6 <= len(code):
                stores.append((i, 'esp', code[i + 5], data)); pending = None; i += 6; continue
            # 8-byte stores to [eax+disp8] or [esp+disp8]
            if len(data) == 8 and code[i:i+3] == b'\xf2\x0f\x11' and i + 5 <= len(code):
                m = code[i + 3]
                if m == 0x00:
                    stores.append((i, 'eax', 0, data)); pending = None; i += 4; continue
                if m == 0x40:
                    stores.append((i, 'eax', struct.unpack_from('b', code, i + 4)[0], data)); pending = None; i += 5; continue
                if m == 0x44 and i + 6 <= len(code) and code[i + 4] == 0x24:
                    stores.append((i, 'esp', code[i + 5], data)); pending = None; i += 6; continue
        i += 1

    out: List[bytes] = []
    # Build local runs.  Use a limited code window so unrelated SSE constants do not merge.
    for start in range(len(stores)):
        base_i, base_name, _disp, _data = stores[start]
        d: Dict[int, int] = {}
        for insn_i, name, disp, data in stores[start:]:
            if insn_i - base_i > 0x90:
                break
            if name != base_name:
                continue
            for k, b in enumerate(data):
                d[disp + k] = b
        if len(d) < min_len:
            continue
        run = []
        last = None
        for off2 in sorted(d):
            if last is None or off2 == last + 1:
                run.append(off2)
            else:
                if len(run) >= min_len:
                    blob = bytes(d[x] for x in run[:max_len])
                    out.extend(split_zero_and_lengths(blob))
                run = [off2]
            last = off2
        if len(run) >= min_len:
            blob = bytes(d[x] for x in run[:max_len])
            out.extend(split_zero_and_lengths(blob))
    return uniq_bytes_list([x for x in out if 16 <= len(x) <= max_len and _looks_like_binary_key_blob(x)])

def _key_candidate_rank(x: bytes, prefer: Tuple[int, ...] = (84, 85, 83, 72, 20, 38, 39, 40, 32, 16, 64, 48)) -> Tuple[int, int, int, int]:
    try:
        pref = prefer.index(len(x))
    except ValueError:
        pref = 99
    mostly_zero = 1 if sum(1 for b in x if b == 0) > len(x) // 2 else 0
    # Higher entropy / more distinct bytes earlier among same preferred length.
    return (mostly_zero, pref, abs(len(x) - 84), -len(set(x)))


# IAPT_V40_MULTI_ABI_DYNAMIC_KEY_BEGIN

def _iapt_v40_read_vaddr(elf: MiniELF, vaddr: int, size: int = 16) -> bytes:
    off = elf.vaddr_to_offset(int(vaddr))
    if off is None or off < 0 or off + size > len(elf.data):
        return b""
    return elf.data[off:off + size]


def _iapt_v40_add_key_blob(out: List[bytes], blob: bytes, min_len: int = 16) -> None:
    if len(blob) < min_len:
        return
    for cand in split_zero_and_lengths(blob):
        if len(cand) >= min_len and _looks_like_binary_key_blob(cand):
            out.append(cand)


def _iapt_v40_sign_extend(value: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (value & (sign - 1)) - (value & sign)


def extract_arm64_pc_relative_tables(elf: MiniELF, func_sym: Dict, min_len: int = 16) -> List[bytes]:
    """Recover 16-byte literals loaded through ADRP/ADD/LDR Q on AArch64."""
    start = int(func_sym.get("value") or 0)
    size = int(func_sym.get("size") or 0x8000)
    off = elf.vaddr_to_offset(start)
    if off is None:
        return []
    code = elf.data[off:off + size]
    regs: Dict[int, int] = {}
    out: List[bytes] = []
    # slky may point at a complete variable-length post table with ADR and copy
    # it using LDP/LDR Q. burden1b more often references independent 16-byte
    # Q literals; reading a full 96-byte window there would ingest unrelated
    # lookup tables and rank them ahead of the real XOR block.
    full_blob = "slky" in str(func_sym.get("name") or "")
    for idx in range(0, len(code) - 3, 4):
        insn = struct.unpack_from("<I", code, idx)[0]
        pc = start + idx
        # ADR Xd, label (direct PC-relative address, no page/add pair).
        if (insn & 0x9F000000) == 0x10000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm = _iapt_v40_sign_extend((immhi << 2) | immlo, 21)
            regs[rd] = pc + imm
            if full_blob:
                _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, regs[rd], 96), min_len)
            continue
        # ADRP Xd, page
        if (insn & 0x9F000000) == 0x90000000:
            rd = insn & 0x1F
            immlo = (insn >> 29) & 0x3
            immhi = (insn >> 5) & 0x7FFFF
            imm = _iapt_v40_sign_extend((immhi << 2) | immlo, 21) << 12
            regs[rd] = (pc & ~0xFFF) + imm
            continue
        # ADD Xd, Xn, #imm12{,LSL #12}
        if (insn & 0xFF000000) == 0x91000000:
            rd = insn & 0x1F
            rn = (insn >> 5) & 0x1F
            if rn in regs:
                imm12 = (insn >> 10) & 0xFFF
                shift = 12 if ((insn >> 22) & 1) else 0
                regs[rd] = regs[rn] + (imm12 << shift)
                if full_blob:
                    _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, regs[rd], 96), min_len)
            continue
        # LDR Qt, [Xn, #imm12*16]
        if (insn & 0xFFC00000) == 0x3DC00000:
            rn = (insn >> 5) & 0x1F
            if rn in regs:
                addr = regs[rn] + (((insn >> 10) & 0xFFF) << 4)
                _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, addr, 16), min_len)
            continue
    return uniq_bytes_list(out)


def extract_x64_rip_relative_tables(elf: MiniELF, func_sym: Dict, min_len: int = 16) -> List[bytes]:
    """Recover SSE 16-byte literals loaded with RIP-relative addressing on x86_64."""
    start = int(func_sym.get("value") or 0)
    size = int(func_sym.get("size") or 0x8000)
    off = elf.vaddr_to_offset(start)
    if off is None:
        return []
    code = elf.data[off:off + size]
    out: List[bytes] = []
    i = 0
    while i + 7 <= len(code):
        prefix_len = 0
        if code[i] in (0x66, 0xF2, 0xF3):
            prefix_len = 1
        j = i + prefix_len
        if j + 7 <= len(code) and code[j] == 0x0F and code[j + 1] in (0x10, 0x28, 0x6F):
            modrm = code[j + 2]
            if (modrm & 0xC7) == 0x05:  # mod=00, r/m=101 => RIP+disp32
                disp = struct.unpack_from("<i", code, j + 3)[0]
                insn_len = prefix_len + 7
                target = start + i + insn_len + disp
                _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, target, 16), min_len)
                i += insn_len
                continue
        i += 1
    return uniq_bytes_list(out)


def extract_thumb_pc_relative_tables(elf: MiniELF, func_sym: Dict, min_len: int = 16) -> List[bytes]:
    """Recover Thumb/Thumb-2 literals used by ARMv7 slky/burden1b implementations."""
    start = int(func_sym.get("value") or 0) & ~1
    size = int(func_sym.get("size") or 0x8000)
    off = elf.vaddr_to_offset(start)
    if off is None:
        return []
    code = elf.data[off:off + size]
    out: List[bytes] = []
    i = 0
    while i + 2 <= len(code):
        pc = start + i
        hw = struct.unpack_from("<H", code, i)[0]

        # ADR (T1): add Rd, Align(PC+4,4), #imm8*4
        if (hw & 0xF800) == 0xA000:
            target = ((pc + 4) & ~3) + ((hw & 0xFF) << 2)
            _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, target, 16), min_len)

        # ADR.W / ADDW Rd, PC, #imm12 (T3), common clang output.
        if i + 4 <= len(code):
            hw2 = struct.unpack_from("<H", code, i + 2)[0]
            if (hw & 0xFBFF) == 0xF20F:
                imm12 = (((hw >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF)
                target = ((pc + 4) & ~3) + imm12
                _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, target, 16), min_len)

        # LDR literal followed by ADD Rd,PC.  This is used by slky on ARMv7.
        if (hw & 0xF800) == 0x4800:
            rt = (hw >> 8) & 7
            literal_addr = ((pc + 4) & ~3) + ((hw & 0xFF) << 2)
            raw = _iapt_v40_read_vaddr(elf, literal_addr, 4)
            if len(raw) == 4:
                rel = struct.unpack("<i", raw)[0]
                for step in (2, 4, 6):
                    if i + step + 2 > len(code):
                        break
                    add_hw = struct.unpack_from("<H", code, i + step)[0]
                    # ADD (high register): 010001 00 D Rm Rdn, with Rm=PC.
                    if (add_hw & 0xFF00) == 0x4400:
                        rm = (add_hw >> 3) & 0xF
                        rd = ((add_hw >> 4) & 0x8) | (add_hw & 0x7)
                        if rm == 15 and rd == rt:
                            add_pc = start + i + step
                            target = add_pc + 4 + rel
                            _iapt_v40_add_key_blob(out, _iapt_v40_read_vaddr(elf, target, 16), min_len)
                            break
        i += 2
    return uniq_bytes_list(out)


def _iapt_v40_arch_literal_candidates(elf: MiniELF, sym: Dict) -> List[bytes]:
    if elf.e_machine == 183:
        return extract_arm64_pc_relative_tables(elf, sym)
    if elf.e_machine == 62:
        return extract_x64_rip_relative_tables(elf, sym)
    if elf.e_machine == 40:
        return extract_thumb_pc_relative_tables(elf, sym)
    return []

# IAPT_V40_MULTI_ABI_DYNAMIC_KEY_END

def auto_extract_key_candidates_from_so(so_data: bytes) -> Tuple[List[bytes], List[bytes]]:
    # V40: x86/x86_64/armeabi-v7a/arm64-v8a all recover native literals.
    elf = MiniELF(so_data)

    print(f"[+] ELF bits={elf.bits}, machine={elf.e_machine}")
    symbols = elf.read_symbols()
    print(f"[+] ELF symbols: {len(symbols)}")

    post_candidates: List[bytes] = []
    xor_candidates: List[bytes] = []

    if elf.e_machine == 183:  # AArch64
        slky_funcs = elf.get_symbols_contains("_ZN4iapp4slky", 0x8000)
        burden_funcs = elf.get_symbols_contains("_ZN4iapp6burden1b", 0x9000)
        extractor = extract_arm64_strb_tables
        arch_name = 'arm64'
    elif elf.e_machine == 3:  # EM_386
        slky_funcs = elf.get_symbols_contains("_ZN4iapp4slky", 0x8000)
        burden_funcs = elf.get_symbols_contains("_ZN4iapp6burden1b", 0x9000)
        extractor = extract_x86_mov_tables
        arch_name = 'x86'
    elif elf.e_machine == 62:  # EM_X86_64
        # x86_64 iApp samples usually store the native outer seed directly and
        # may not contain the old KEY_XOR_CONST/SLKY_POST_KEY tables.  Reuse the
        # x86 table scanner as a best-effort source of constants, but do not
        # treat absence as a fatal static-analysis problem in outer-auto mode.
        slky_funcs = elf.get_symbols_contains("_ZN4iapp4slky", 0x8000)
        burden_funcs = elf.get_symbols_contains("_ZN4iapp6burden1b", 0x9000)
        extractor = extract_x86_mov_tables
        arch_name = 'x86_64'
    elif elf.e_machine == 40:  # EM_ARM / armeabi-v7a
        # Thumb/ARM table extraction is intentionally conservative; static
        # outer analysis can still use other ABI siblings from the APK.
        slky_funcs = elf.get_symbols_contains("_ZN4iapp4slky", 0x8000)
        burden_funcs = elf.get_symbols_contains("_ZN4iapp6burden1b", 0x9000)
        extractor = lambda code, min_len=16: []
        arch_name = 'armv7'
    else:
        raise ValueError(f"unsupported ELF machine={elf.e_machine}, bits={elf.bits}")

    print(f"[+] SO analyzer arch: {arch_name}")
    print(f"[+] slky symbol matches: {len(slky_funcs)}")
    for sym, _ in slky_funcs[:8]:
        print(f"    slky: {sym['name']} va=0x{sym['value']:x} size={sym['size']}")

    print(f"[+] burden1b symbol matches: {len(burden_funcs)}")
    for sym, _ in burden_funcs[:8]:
        print(f"    burden1b: {sym['name']} va=0x{sym['value']:x} size={sym['size']}")

    for sym, code in slky_funcs:
        cands = extractor(code)
        arch_literals = _iapt_v40_arch_literal_candidates(elf, sym)
        if arch_literals:
            print(f"[IAPT_V40] {arch_name} slky pc-relative candidates from {sym['name']}: {len(arch_literals)}")
            cands.extend(arch_literals)
        if elf.e_machine == 3:
            ro_cands = extract_x86_pic_rodata_copies(elf, sym)
            if ro_cands:
                print(f"[+] slky rodata-copy cands from {sym['name']}: {len(ro_cands)}")
                for i, c in enumerate(ro_cands[:8]):
                    print(f"    post_ro[{i}] len={len(c)} {c.hex()}")
                cands.extend(ro_cands)
            sse_cands = extract_x86_sse_rodata_tables(elf, sym)
            if sse_cands:
                print(f"[+] slky sse-rodata cands from {sym['name']}: {len(sse_cands)}")
                for i, c in enumerate(sse_cands[:8]):
                    print(f"    post_sse[{i}] len={len(c)} {c.hex()}")
                cands.extend(sse_cands)
        cands = uniq_bytes_list(cands)
        print(f"[+] slky cands from {sym['name']}: {len(cands)}")
        for i, c in enumerate(cands[:8]):
            print(f"    post_sym[{i}] len={len(c)} {c.hex()}")
        post_candidates.extend(cands)

    for sym, code in burden_funcs:
        cands = extractor(code)
        arch_literals = _iapt_v40_arch_literal_candidates(elf, sym)
        if arch_literals:
            print(f"[IAPT_V40] {arch_name} burden pc-relative candidates from {sym['name']}: {len(arch_literals)}")
            if elf.e_machine == 183:
                # Direct Q-load literals are stronger than the AArch64 STRB
                # stack scanner, which can also reconstruct unrelated tables.
                cands = list(arch_literals)
            else:
                cands.extend(arch_literals)
        if elf.e_machine == 3:
            sse_cands = extract_x86_sse_rodata_tables(elf, sym)
            if sse_cands:
                print(f"[+] burden sse-rodata cands from {sym['name']}: {len(sse_cands)}")
                for i, c in enumerate(sse_cands[:8]):
                    print(f"    xor_sse [{i}] len={len(c)} {c.hex()}")
                cands.extend(sse_cands)
        print(f"[+] burden cands from {sym['name']}: {len(cands)}")
        for i, c in enumerate(cands[:8]):
            print(f"    xor_sym [{i}] len={len(c)} {c.hex()}")
        xor_candidates.extend(cands)

    if not post_candidates or not xor_candidates:
        print("[!] symbol-based extraction incomplete; fallback to executable section scan")
        text_candidates = []
        for sec_name, sec_vaddr, code in get_exec_sections(elf):
            print(f"[+] scanning exec section: {sec_name}, va=0x{sec_vaddr:x}, size={len(code)}")
            cands = extractor(code)
            print(f"    section candidates: {len(cands)}")
            text_candidates.extend(cands)
        text_candidates = uniq_bytes_list([x for x in text_candidates if 16 <= len(x) <= 96])
        text_candidates.sort(key=lambda x: (0 if len(x) in (16, 20, 32, 38, 39, 40) else 1, abs(len(x) - 38)))
        print(f"[+] fallback text candidates: {len(text_candidates)}")
        for i, c in enumerate(text_candidates[:20]):
            print(f"    text[{i}] len={len(c)} {c.hex()}")
        if not post_candidates:
            post_candidates = text_candidates
        if not xor_candidates:
            xor_candidates = text_candidates

    # V40: literals seen in both slky overloads are stronger evidence than
    # unrelated one-off vector constants referenced by only one function.
    post_frequency: Dict[bytes, int] = {}
    xor_frequency: Dict[bytes, int] = {}
    for _c in post_candidates:
        if 16 <= len(_c) <= 96 and any(_c):
            post_frequency[_c] = post_frequency.get(_c, 0) + 1
    for _c in xor_candidates:
        if 16 <= len(_c) <= 96 and any(_c):
            xor_frequency[_c] = xor_frequency.get(_c, 0) + 1

    post_candidates = uniq_bytes_list([x for x in post_candidates if 16 <= len(x) <= 96 and any(x)])
    xor_candidates = uniq_bytes_list([x for x in xor_candidates if 16 <= len(x) <= 96 and any(x)])

    post_candidates.sort(key=lambda x: (-post_frequency.get(x, 0),) + _key_candidate_rank(x))
    if elf.e_machine == 183:
        # AArch64 burden1b usually exposes the effective XOR input as Q-sized
        # literals. Prefer those over nearby long compiler tables.
        xor_candidates.sort(key=lambda x: (0 if len(x) == 16 else 1, -xor_frequency.get(x, 0)) + _key_candidate_rank(x))
    else:
        xor_candidates.sort(key=lambda x: (-xor_frequency.get(x, 0),) + _key_candidate_rank(x))

    if not post_candidates:
        raise ValueError("no SLKY_POST_KEY candidates found; symbols/fallback found no usable table")
    if not xor_candidates:
        raise ValueError("no KEY_XOR_CONST candidates found; symbols/fallback found no usable table")

    return post_candidates, xor_candidates

def derive_outer_key(ctx: SlkyContext, key_xor: bytes, hidden: bytes, package: str, version_name: str, version_code, app_label: str, fb_value) -> Tuple[bytes, Dict[str, bytes]]:
    
    vc = parse_int_auto(version_code)
    fb = parse_int_auto(fb_value)
    cache_key = (id(ctx), key_xor, hidden, str(package), str(version_name), vc, str(app_label), fb)
    cached = _OUTER_KEY_CACHE.get(cache_key)
    if cached is not None:
        return cached
    base = hidden + str(version_name).encode() + str(package).encode() + str(app_label).encode() + str(vc).encode() + str(fb).encode()
    p19 = ctx.slky(base, hidden)
    p24 = ctx.slky(p19, p19)
    p25 = ctx.slky(p19, p24)
    outer_key = xor_repeat_prefix(p25, key_xor, 16)
    result = (outer_key, {"base": base, "p19": p19, "p24": p24, "p25": p25})
    if len(_OUTER_KEY_CACHE) > 200000:
        _OUTER_KEY_CACHE.clear()
    _OUTER_KEY_CACHE[cache_key] = result
    return result


def member_markers(ctx: SlkyContext, filename: str, hidden: bytes, fb_value) -> Tuple[bytes, bytes]:
    fb_int = parse_int_auto(fb_value)
    cache_key = (id(ctx), filename, hidden, fb_int)
    cached = _MEMBER_MARKER_CACHE.get(cache_key)
    if cached is not None:
        return cached
    name = filename.encode()
    fb = str(fb_int).encode()
    start = ctx.slky(name, hidden + fb)
    end = ctx.slky(name, fb + hidden)
    result = (start, end)
    _MEMBER_MARKER_CACHE[cache_key] = result
    return result


def derive_member_key(ctx: SlkyContext, key_xor: bytes, filename: str, hidden: bytes, fb_value) -> bytes:
    
    fb_int = parse_int_auto(fb_value)
    cache_key = (id(ctx), key_xor, filename, hidden, fb_int)
    cached = _MEMBER_KEY_CACHE.get(cache_key)
    if cached is not None:
        return cached
    name = filename.encode()
    fb = str(fb_int).encode()
    seed = ctx.slky(name + hidden + fb, name)
    key = xor_repeat_prefix(seed, key_xor, 16)
    _MEMBER_KEY_CACHE[cache_key] = key
    return key


def derive_member_key_mode(ctx: SlkyContext, key_xor: bytes, filename: str, hidden: bytes, fb_value, member_key_mode: str = "xor") -> bytes:
    member_key_mode = (member_key_mode or "xor").lower()
    if member_key_mode == "xor":
        return derive_member_key(ctx, key_xor, filename, hidden, fb_value)
    if member_key_mode == "direct":
        fb_int = parse_int_auto(fb_value)
        name = filename.encode()
        fb = str(fb_int).encode()
        seed = ctx.slky(name + hidden + fb, name)
        return seed[:16]
    raise ValueError(f"unknown member key mode: {member_key_mode}")


def locate_member_ciphertext(container_plain: bytes, ctx: SlkyContext, filename: str, hidden: bytes, fb_value) -> Optional[bytes]:
    start, end = member_markers(ctx, filename, hidden, fb_value)
    s = container_plain.find(start)
    if s < 0:
        return None
    data_start = s + len(start)
    e = container_plain.find(end, data_start)
    if e < 0 or e <= data_start:
        return None
    ciphertext = container_plain[data_start:e]
    if len(ciphertext) % 16:
        return None
    return ciphertext


def decrypt_member_ciphertext(ciphertext: bytes, ctx: SlkyContext, key_xor: bytes, filename: str, hidden: bytes, fb_value, member_key_mode: str = "xor") -> Optional[bytes]:
    key = derive_member_key_mode(ctx, key_xor, filename, hidden, fb_value, member_key_mode)
    try:
        return aes_cbc_then_xor_decrypt(ciphertext, key)
    except Exception:
        return None


def try_decrypt_member(container_plain: bytes, ctx: SlkyContext, key_xor: bytes, filename: str, hidden: bytes, fb_value, member_key_mode: str = "xor") -> Optional[bytes]:
    ciphertext = locate_member_ciphertext(container_plain, ctx, filename, hidden, fb_value)
    if ciphertext is None:
        return None
    return decrypt_member_ciphertext(ciphertext, ctx, key_xor, filename, hidden, fb_value, member_key_mode)


def locate_member_ciphertexts_wave(container_plain: bytes, ctx: SlkyContext, names: Tuple[str, ...], hidden: bytes, fb_value) -> List[Tuple[str, bytes]]:
    """Locate encrypted member payloads for many candidate filenames in one plaintext pass.

    The old hot path called bytes.find(start_marker) once per candidate name,
    which rescanned the whole outer plaintext hundreds of times.  Markers are
    16-byte slky outputs, so duplicates are extremely unlikely; when there are
    multiple names in a wave, a fixed-bytes regex alternation lets CPython's C
    regex engine scan the container once and report all matching start markers.
    End-marker validation and AES/member-key derivation stay exactly the same.
    """
    if not names:
        return []
    if len(names) == 1:
        ct = locate_member_ciphertext(container_plain, ctx, names[0], hidden, fb_value)
        return [(names[0], ct)] if ct is not None else []

    marker_to_entries: Dict[bytes, List[Tuple[str, bytes]]] = {}
    for name in names:
        try:
            start, end = member_markers(ctx, name, hidden, fb_value)
        except Exception:
            continue
        marker_to_entries.setdefault(start, []).append((name, end))
    if not marker_to_entries:
        return []

    # Sort longer/rarer-looking markers first for deterministic behavior.  All
    # current markers are 16 bytes, but sorting keeps this safe for variants.
    pattern = b"|".join(re.escape(m) for m in sorted(marker_to_entries, key=lambda x: (-len(x), x)))
    try:
        rx = re.compile(pattern)
    except Exception:
        # Extremely defensive fallback for pathological future markers.
        out: List[Tuple[str, bytes]] = []
        for name in names:
            ct = locate_member_ciphertext(container_plain, ctx, name, hidden, fb_value)
            if ct is not None:
                out.append((name, ct))
        return out

    out: List[Tuple[str, bytes]] = []
    seen_names: Set[str] = set()
    for m in rx.finditer(container_plain):
        start = m.group(0)
        entries = marker_to_entries.get(start)
        if not entries:
            continue
        data_start = m.end()
        for name, end in entries:
            if name in seen_names:
                continue
            e = container_plain.find(end, data_start)
            if e < 0 or e <= data_start:
                continue
            ciphertext = container_plain[data_start:e]
            if len(ciphertext) % 16:
                continue
            out.append((name, ciphertext))
            seen_names.add(name)
    return out


def parse_axml_manifest(axml: bytes) -> Dict[str, str]:
    def u16(off: int) -> int:
        return struct.unpack_from("<H", axml, off)[0]
    def u32(off: int) -> int:
        return struct.unpack_from("<I", axml, off)[0]
    def read_len8(p: int) -> Tuple[int, int]:
        b = axml[p]
        if b & 0x80:
            return ((b & 0x7F) << 8) | axml[p + 1], 2
        return b, 1
    def read_len16(p: int) -> Tuple[int, int]:
        x = u16(p)
        if x & 0x8000:
            return ((x & 0x7FFF) << 16) | u16(p + 2), 4
        return x, 2
    if len(axml) < 16:
        raise ValueError("bad axml")
    off = 8
    ctype, hsize, csize = struct.unpack_from("<HHI", axml, off)
    if ctype != 0x0001:
        raise ValueError("string pool not found")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from("<IIIII", axml, off + 8)
    utf8 = bool(flags & 0x100)
    offsets = [u32(off + hsize + i * 4) for i in range(string_count)]
    base = off + strings_start
    strings: List[str] = []
    for string_offset in offsets:
        p = base + string_offset
        if utf8:
            _, n1 = read_len8(p)
            l2, n2 = read_len8(p + n1)
            raw = axml[p + n1 + n2:p + n1 + n2 + l2]
            s = raw.decode("utf-8", "replace")
        else:
            l, n = read_len16(p)
            raw = axml[p + n:p + n + l * 2]
            s = raw.decode("utf-16le", "replace")
        strings.append(s)
    def sx(i: int) -> str:
        if i == 0xFFFFFFFF:
            return ""
        return strings[i] if 0 <= i < len(strings) else ""
    def attr_value(dtype: int, data: int, raw: int) -> str:
        if raw != 0xFFFFFFFF:
            return sx(raw)
        if dtype == 0x03:
            return sx(data)
        if dtype == 0x04:
            # Android TypedValue.TYPE_FLOAT stores IEEE-754 raw bits in data.
            value = struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0]
            text = format(value, ".8g")
            if value.is_integer() and "e" not in text.lower() and "." not in text:
                text += ".0"
            return text
        if dtype == 0x10:
            return str(data if data < 0x80000000 else data - 0x100000000)
        if dtype == 0x11:
            return str(data)
        if dtype == 0x12:
            return "true" if data else "false"
        if dtype == 0x01:
            return f"@{data:08x}"
        return str(data)
    result: Dict[str, str] = {}
    pos = off + csize
    while pos + 8 <= len(axml):
        typ, head, size = struct.unpack_from("<HHI", axml, pos)
        if size <= 0:
            break
        if typ == 0x0102:
            ns, name, attr_start, attr_size, attr_count, id_idx, cls_idx, style_idx = struct.unpack_from("<IIHHHHHH", axml, pos + 16)
            tag = sx(name)
            attr_off = pos + 16 + attr_start
            attrs: Dict[str, str] = {}
            for i in range(attr_count):
                ns_i, name_i, raw, value_size, zero, dtype, data = struct.unpack_from("<IIIHBBI", axml, attr_off + i * attr_size)
                attrs[sx(name_i)] = attr_value(dtype, data, raw)
            if tag == "manifest":
                for k in ("package", "versionName", "versionCode"):
                    if k in attrs:
                        result[k] = attrs[k]
            elif tag == "application" and "label" in attrs:
                result["appLabel"] = attrs["label"]
        pos += size
    return result



def _arsc_u16(blob: bytes, off: int) -> int:
    return struct.unpack_from("<H", blob, off)[0]


def _arsc_u32(blob: bytes, off: int) -> int:
    return struct.unpack_from("<I", blob, off)[0]


def _arsc_read_len8(blob: bytes, p: int) -> Tuple[int, int]:
    b = blob[p]
    if b & 0x80:
        return ((b & 0x7F) << 8) | blob[p + 1], 2
    return b, 1


def _arsc_read_len16(blob: bytes, p: int) -> Tuple[int, int]:
    x = struct.unpack_from("<H", blob, p)[0]
    if x & 0x8000:
        return ((x & 0x7FFF) << 16) | struct.unpack_from("<H", blob, p + 2)[0], 4
    return x, 2


def _arsc_parse_string_pool(blob: bytes, off: int) -> Tuple[List[str], int]:
    if off + 28 > len(blob):
        raise ValueError("bad resources.arsc string pool offset")
    typ = _arsc_u16(blob, off)
    hsize = _arsc_u16(blob, off + 2)
    size = _arsc_u32(blob, off + 4)
    if typ != 0x0001 or size <= 0 or off + size > len(blob):
        raise ValueError("bad resources.arsc string pool chunk")
    string_count = _arsc_u32(blob, off + 8)
    flags = _arsc_u32(blob, off + 16)
    strings_start = _arsc_u32(blob, off + 20)
    utf8 = bool(flags & 0x100)
    offsets = [_arsc_u32(blob, off + hsize + i * 4) for i in range(string_count)]
    base = off + strings_start
    out: List[str] = []
    for so in offsets:
        p = base + so
        if not (0 <= p < len(blob)):
            out.append("")
            continue
        try:
            if utf8:
                _, n1 = _arsc_read_len8(blob, p)
                l2, n2 = _arsc_read_len8(blob, p + n1)
                raw = blob[p + n1 + n2:p + n1 + n2 + l2]
                out.append(raw.decode("utf-8", "replace"))
            else:
                l, n = _arsc_read_len16(blob, p)
                raw = blob[p + n:p + n + l * 2]
                out.append(raw.decode("utf-16le", "replace"))
        except Exception:
            out.append("")
    return out, size


def resolve_arsc_string_ref(arsc: bytes, ref: str) -> Optional[str]:
    """Resolve simple @7fTTEEEE string resource references from resources.arsc.

    This intentionally implements the small subset needed for iApp labels: global
    string pool + package key/type pools + simple string entries.  It is safe to
    fail closed and return None when the resource table uses a shape we do not
    understand.
    """
    ref = str(ref or "").strip()
    if not ref.startswith("@"):
        return None
    try:
        rid = int(ref[1:], 16)
    except Exception:
        return None
    pkg_id = (rid >> 24) & 0xFF
    type_id = (rid >> 16) & 0xFF
    entry_id = rid & 0xFFFF
    if len(arsc) < 12 or _arsc_u16(arsc, 0) != 0x0002:
        return None
    off = 12
    try:
        global_strings, sp_size = _arsc_parse_string_pool(arsc, off)
    except Exception:
        return None
    off += sp_size
    while off + 8 <= len(arsc):
        ctyp = _arsc_u16(arsc, off)
        hsize = _arsc_u16(arsc, off + 2)
        size = _arsc_u32(arsc, off + 4)
        if size <= 0 or off + size > len(arsc):
            break
        if ctyp != 0x0200:
            off += size
            continue
        try:
            cur_pkg_id = _arsc_u32(arsc, off + 8)
            if pkg_id and cur_pkg_id != pkg_id:
                off += size
                continue
        except Exception:
            off += size
            continue
        p = off + hsize
        while p + 20 <= off + size:
            try:
                ttyp = _arsc_u16(arsc, p)
                thsize = _arsc_u16(arsc, p + 2)
                tsize = _arsc_u32(arsc, p + 4)
            except Exception:
                break
            if tsize <= 0 or p + tsize > off + size:
                break
            if ttyp == 0x0201:
                tid = arsc[p + 8]
                entry_count = _arsc_u32(arsc, p + 12)
                entries_start = _arsc_u32(arsc, p + 16)
                if tid == type_id and entry_id < entry_count:
                    ent_off_pos = p + thsize + entry_id * 4
                    if ent_off_pos + 4 <= len(arsc):
                        ent_off = _arsc_u32(arsc, ent_off_pos)
                        if ent_off != 0xFFFFFFFF:
                            ep = p + entries_start + ent_off
                            if ep + 16 <= len(arsc):
                                flags = _arsc_u16(arsc, ep + 2)
                                if not (flags & 0x0001):
                                    dtype = arsc[ep + 11]
                                    data = _arsc_u32(arsc, ep + 12)
                                    if dtype == 0x03 and data < len(global_strings):
                                        return global_strings[data]
                                    if dtype in (0x10, 0x11):
                                        return str(data if data < 0x80000000 else data - 0x100000000)
            p += tsize
        off += size
    return None


def _xml_tag_text(data: bytes, tag: str) -> Optional[str]:
    """Tiny XML helper for iApp's small assets/*.xml control files."""
    if not data:
        return None
    try:
        text = data.decode("utf-8", "ignore")
    except Exception:
        text = str(data)
    m = re.search(r"<\s*" + re.escape(tag) + r"\s*>\s*(.*?)\s*<\s*/\s*" + re.escape(tag) + r"\s*>", text, re.I | re.S)
    if not m:
        return None
    return m.group(1).strip()


def _read_u32_le(buf: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(buf):
        raise ValueError("u32 out of range")
    return struct.unpack_from("<I", buf, off)[0]


def _read_len_prefixed_u32(buf: bytes, off: int) -> Tuple[bytes, int]:
    n = _read_u32_le(buf, off)
    start = off + 4
    end = start + n
    if n < 0 or end > len(buf):
        raise ValueError("length-prefixed field out of range")
    return buf[start:end], end


def _extract_v2_v3_signing_block_certs(value: bytes) -> List[bytes]:
    """Extract DER certificates from APK Signature Scheme v2/v3 block values.

    Android PackageInfo.signatures[].toByteArray() returns DER X.509 cert bytes.
    This parser only reads enough of the public v2/v3 wire format to recover
    the certificates; it does not verify signatures.
    """
    out: List[bytes] = []
    try:
        signers, p = _read_len_prefixed_u32(value, 0)
        sp = 0
        while sp < len(signers):
            signer, sp = _read_len_prefixed_u32(signers, sp)
            signed_data, q = _read_len_prefixed_u32(signer, 0)
            # signedData = digests + certificates + additionalAttributes (+ sdk fields in v3 after these)
            _digests, sd_p = _read_len_prefixed_u32(signed_data, 0)
            certs, sd_p = _read_len_prefixed_u32(signed_data, sd_p)
            cp = 0
            while cp < len(certs):
                cert, cp = _read_len_prefixed_u32(certs, cp)
                if cert and cert not in out:
                    out.append(cert)
    except Exception:
        pass
    return out


def _extract_apk_signing_block_certs(apk_path: Path) -> List[bytes]:
    """Best-effort APK v2/v3 cert extractor."""
    out: List[bytes] = []
    try:
        data = apk_path.read_bytes()
        # Find EOCD in the last 64K + comment.
        start = max(0, len(data) - (0xFFFF + 22))
        eocd = data.rfind(b"PK\x05\x06", start)
        if eocd < 0 or eocd + 22 > len(data):
            return out
        cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
        footer = cd_offset - 24
        if footer < 0 or data[footer + 8:footer + 24] != b"APK Sig Block 42":
            return out
        size2 = struct.unpack_from("<Q", data, footer)[0]
        block_start = cd_offset - size2 - 8
        if block_start < 0 or block_start + 8 > len(data):
            return out
        size1 = struct.unpack_from("<Q", data, block_start)[0]
        if size1 != size2:
            return out
        pos = block_start + 8
        pairs_end = cd_offset - 24
        while pos + 12 <= pairs_end:
            pair_size = struct.unpack_from("<Q", data, pos)[0]
            pos += 8
            if pair_size < 4 or pos + pair_size > pairs_end:
                break
            pair_id = struct.unpack_from("<I", data, pos)[0]
            value = data[pos + 4:pos + pair_size]
            # APK Signature Scheme v2 and v3 block IDs.
            if pair_id in (0x7109871A, 0xF05368C0):
                for cert in _extract_v2_v3_signing_block_certs(value):
                    if cert not in out:
                        out.append(cert)
            pos += pair_size
    except Exception:
        pass
    return out


def extract_apk_signature_certs(apk_path: Optional[Path]) -> List[bytes]:
    """Return DER X.509 certificates from v1 META-INF or v2/v3 signing block."""
    if not apk_path:
        return []
    certs: List[bytes] = []
    try:
        # v2/v3 first because modern APKs may not contain useful META-INF RSA.
        for cert in _extract_apk_signing_block_certs(apk_path):
            if cert and cert not in certs:
                certs.append(cert)
    except Exception:
        pass
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates, load_pem_pkcs7_certificates
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                n = info.filename.upper()
                if not n.startswith("META-INF/") or not n.endswith((".RSA", ".DSA", ".EC", ".CER", ".CRT")):
                    continue
                blob = z.read(info.filename)
                parsed = []
                for loader in (load_der_pkcs7_certificates, load_pem_pkcs7_certificates):
                    try:
                        parsed = loader(blob) or []
                        if parsed:
                            break
                    except Exception:
                        pass
                if not parsed:
                    for loader in (x509.load_der_x509_certificate, x509.load_pem_x509_certificate):
                        try:
                            parsed = [loader(blob)]
                            break
                        except Exception:
                            pass
                for c in parsed:
                    der = c.public_bytes(Encoding.DER)
                    if der and der not in certs:
                        certs.append(der)
    except Exception:
        pass
    return certs



def _dex_collect_user_password_salts(dex: bytes) -> List[str]:
    """Find salts used by Java password gate before native h2(context, key).

    Common iApp user-encryption flow:
        native_input = p.d(user_password + salt)
        b.h2(context, native_input)
    where p.d(String) is MD5 hex.  The salt is app-specific, so recover it
    from the current APK DEX instead of hard-coding.
    """
    try:
        strings, hdr = dex_read_strings(dex)
    except Exception:
        return []
    try:
        type_ids = [struct.unpack_from("<I", dex, hdr["type_ids_off"] + i * 4)[0] for i in range(hdr["type_ids_size"])]
        def tname(type_idx: int) -> str:
            return strings[type_ids[type_idx]] if 0 <= type_idx < len(type_ids) else ""
        protos = []
        for i in range(hdr["proto_ids_size"]):
            shorty, ret, params = struct.unpack_from("<III", dex, hdr["proto_ids_off"] + i * 12)
            ps = []
            if params:
                psz = struct.unpack_from("<I", dex, params)[0]
                ps = [tname(struct.unpack_from("<H", dex, params + 4 + 2 * j)[0]) for j in range(psz)]
            protos.append((strings[shorty], tname(ret), ps))
        methods = []
        for i in range(hdr["method_ids_size"]):
            class_idx, proto_idx, name_idx = struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + i * 8)
            methods.append((tname(class_idx), strings[name_idx], protos[proto_idx]))
    except Exception:
        return []

    h2_idxs = {i for i, (c, n, pr) in enumerate(methods) if c == "Lcom/iapp/app/b;" and n == "h2"}
    # p.d(String):String -> MD5 hex helper in observed iApp password gate.
    md5_idxs = {i for i, (c, n, pr) in enumerate(methods) if c == "Lc/b/a/a/p;" and n == "d" and pr[1] == "Ljava/lang/String;"}
    if not h2_idxs or not md5_idxs:
        return []

    def insn_step(insns: List[int], pc: int) -> int:
        op = insns[pc] & 0xFF
        if op in (0x00,0x01,0x04,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x21) or 0x7b <= op <= 0xcf:
            return 1
        if op in (0x02,0x05,0x08,0x13,0x15,0x19,0x1a,0x1c,0x1f,0x20,0x22,0x23,0x29) or 0x32 <= op <= 0x3d or 0x44 <= op <= 0x6d or 0x90 <= op <= 0xaf or 0xd0 <= op <= 0xe2:
            return 2
        if op in (0x03,0x06,0x09,0x14,0x16,0x17,0x24,0x26,0x2a) or 0x6e <= op <= 0x78:
            return 3
        if op == 0x18:
            return 5
        return 1

    salts: List[str] = []
    try:
        for class_def_index in range(hdr["class_defs_size"]):
            off = hdr["class_defs_off"] + class_def_index * 32
            _class_idx, _access_flags, _super_idx, _interfaces_off, _source_idx, _annotations_off, class_data_off, _static_values_off = struct.unpack_from("<IIIIIIII", dex, off)
            if class_data_off == 0:
                continue
            p = class_data_off
            static_fields_size, p = dex_uleb(dex, p)
            instance_fields_size, p = dex_uleb(dex, p)
            direct_methods_size, p = dex_uleb(dex, p)
            virtual_methods_size, p = dex_uleb(dex, p)
            for _ in range(static_fields_size + instance_fields_size):
                _, p = dex_uleb(dex, p); _, p = dex_uleb(dex, p)
            for method_count in (direct_methods_size, virtual_methods_size):
                last_method_index = 0
                for _ in range(method_count):
                    method_idx_diff, p = dex_uleb(dex, p)
                    _access_flags, p = dex_uleb(dex, p)
                    code_off, p = dex_uleb(dex, p)
                    last_method_index += method_idx_diff
                    if not code_off or code_off + 16 > len(dex):
                        continue
                    try:
                        _regs, _ins, _outs, _tries, _dbg, insns_size = struct.unpack_from("<HHHHII", dex, code_off)
                        insns_off = code_off + 16
                        if insns_off + insns_size * 2 > len(dex):
                            continue
                        insns = list(struct.unpack_from("<" + "H" * insns_size, dex, insns_off))
                    except Exception:
                        continue
                    string_idxs: List[int] = []
                    has_h2 = False
                    has_md5 = False
                    pc = 0
                    while pc < len(insns):
                        op = insns[pc] & 0xFF
                        if op == 0x1a and pc + 1 < len(insns):
                            string_idxs.append(insns[pc + 1])
                        elif op == 0x1b and pc + 2 < len(insns):
                            string_idxs.append(insns[pc + 1] | (insns[pc + 2] << 16))
                        elif 0x6e <= op <= 0x72 and pc + 2 < len(insns):
                            midx = insns[pc + 1]
                            has_h2 = has_h2 or (midx in h2_idxs)
                            has_md5 = has_md5 or (midx in md5_idxs)
                        elif 0x74 <= op <= 0x78 and pc + 2 < len(insns):
                            midx = insns[pc + 1]
                            has_h2 = has_h2 or (midx in h2_idxs)
                            has_md5 = has_md5 or (midx in md5_idxs)
                        pc += insn_step(insns, pc)
                    if has_h2 and has_md5:
                        for si in string_idxs:
                            if 0 <= si < len(strings):
                                st = strings[si]
                                if re.fullmatch(r"[A-Za-z0-9_]{1,32}", st) and not st.isdigit() and st not in ("MD5",):
                                    if st not in salts:
                                        salts.append(st)
    except Exception:
        pass
    return salts


def extract_user_password_native_candidates(apk_path: Optional[Path], user_password: Optional[str]) -> Dict[str, bytes]:
    out: Dict[str, bytes] = {}
    if user_password is None:
        return out
    raw = str(user_password).encode()
    # Fast path: most current user-encryption samples use this Java-side salt.
    # It is still verified by outer AES + mian.iyu before being accepted.  A
    # deep DEX scan is performed only when requested or after the fast attempt
    # fails, which avoids parsing every method on the common path.
    salts: List[str] = ["mmpfbf"]
    if _PASSWORD_DEEP_SCAN:
        t_salt_scan = time.perf_counter()
        for name, dex in load_apk_dex_blobs(apk_path):
            for salt in _dex_collect_user_password_salts(dex):
                if salt not in salts:
                    salts.append(salt)
        print(f"[T] password salt DEX scan {ms_since(t_salt_scan):.3f} ms salts={len(salts)}")
    for idx, salt in enumerate(salts[:8]):
        native = hashlib.md5(raw + salt.encode()).hexdigest().encode()
        key = "user_password_native" if idx == 0 else f"user_password_native_{idx}"
        out[key] = native
        out[f"user_password_salt_{idx}"] = salt.encode()
    if salts:
        out["user_password_transform"] = b"md5(raw_password+salt)"
    return out

def load_apk_extra_env(
    apk_path: Optional[Path],
    user_password: Optional[str] = None,
    signature_mode: str = "auto",
    signature_bytes_hex: Optional[str] = None,
) -> Dict[str, bytes]:
    env: Dict[str, bytes] = {}
    if not apk_path:
        return env
    signature_mode = (signature_mode or "auto").lower()
    try:
        _snap = _apk_snapshot(apk_path)
        names = set(_snap["names"] if _snap else ())
        for name in ("assets/.jgapp", ".jgapp", "assets/jgapp"):
            if name in names:
                env["jgapp"] = _apk_read_cached(apk_path, name)
                break

        # User password gate.  Native consumes Java helper results; XML is
        # parsed here so CLI can select idbfj(user_password) automatically.
        userenc_blob = b""
        for name in ("assets/userencryption.xml", "userencryption.xml"):
            if name in names:
                userenc_blob = _apk_read_cached(apk_path, name)
                env["userencryption.xml"] = userenc_blob
                break
        ok_text = _xml_tag_text(userenc_blob, "ok")
        if ok_text is not None:
            env["user_encryption_ok"] = ok_text.lower().encode()
        if ok_text and ok_text.strip().lower() == "true":
            env["user_encryption_required"] = b"true"
            if user_password is not None:
                env["user_password"] = str(user_password).encode()
                env["password"] = env["user_password"]
        elif user_password is not None:
            # Allow manual testing even when the XML is absent from a SO-only run.
            env["user_password"] = str(user_password).encode()
            env["password"] = env["user_password"]

        if user_password is not None:
            env.update(extract_user_password_native_candidates(apk_path, user_password))

        # Signature gate.  <signature>1</signature> means skip signature;
        # empty/missing/non-1 means normal Android signature participates in p24.
        sig_blob = b""
        for name in ("assets/extra_conf1g.xml", "extra_conf1g.xml"):
            if name in names:
                sig_blob = _apk_read_cached(apk_path, name)
                env["extra_conf1g.xml"] = sig_blob
                break
        sig_text = _xml_tag_text(sig_blob, "signature")
        if sig_text is not None:
            env["extra_conf1g_signature"] = sig_text.encode()
        if signature_mode == "auto":
            effective_sig_mode = "skip" if (sig_text and sig_text.strip() == "1") else "verify"
        else:
            effective_sig_mode = signature_mode
        env["signature_mode"] = effective_sig_mode.encode()
    except Exception:
        pass

    if signature_bytes_hex:
        try:
            env["signature"] = bytes.fromhex(signature_bytes_hex)
            env["apk_signature"] = env["signature"]
            env["signature_source"] = b"manual-hex"
        except Exception as e:
            print(f"[!] invalid --signature-bytes-hex ignored: {e}")
    elif env.get("signature_mode") == b"verify" and apk_path:
        certs = extract_apk_signature_certs(apk_path)
        if certs:
            env["signature"] = certs[0]
            env["apk_signature"] = certs[0]
            env["signature_source"] = b"apk-cert"
            # Extra aliases for unknown native variants; signature candidates
            # currently use raw DER bytes, matching Signature.toByteArray().
            env["signature_sha1_hex"] = hashlib.sha1(certs[0]).hexdigest().encode()
            env["signature_sha256_hex"] = hashlib.sha256(certs[0]).hexdigest().encode()
            env["signature_count"] = str(len(certs)).encode()
    return env


def load_apk_dex_blobs(apk_path: Optional[Path]) -> List[Tuple[str, bytes]]:
    """Return all DEX blobs in the APK, including extensionless entries like lib/Lottiesx."""
    out: List[Tuple[str, bytes]] = []
    if not apk_path:
        return out
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size < 8:
                    continue
                name = info.filename
                # Avoid reading huge non-code assets unless their names are likely to be dex-like.
                maybe = name.endswith(".dex") or name.startswith("classes") or name.startswith("lib/") or info.file_size < 5_000_000
                if not maybe:
                    continue
                try:
                    data = z.read(name)
                except Exception:
                    continue
                if data.startswith(b"dex\n"):
                    out.append((name, data))
    except Exception:
        return out
    return out




def iter_apk_dex_blobs(apk_path: Optional[Path], primary_dex: Optional[bytes] = None):
    """Yield DEX blobs lazily, preferring the already loaded classes.dex.

    This avoids inflating extensionless secondary DEX files when an early
    indexed-table hit in classes.dex is enough for restore-map recovery.
    """
    yielded: Set[str] = set()
    if primary_dex and primary_dex.startswith(b"dex\n"):
        yielded.add("classes.dex")
        yield "classes.dex", primary_dex
    if not apk_path:
        return
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size < 8:
                    continue
                name = info.filename
                if name in yielded:
                    continue
                maybe = name.endswith(".dex") or name.startswith("classes") or name.startswith("lib/") or info.file_size < 5_000_000
                if not maybe:
                    continue
                try:
                    data = z.read(name)
                except Exception:
                    continue
                if data.startswith(b"dex\n"):
                    yielded.add(name)
                    yield name, data
    except Exception:
        return

def extract_fb_from_lianyi_native(apk_path: Optional[Path]) -> Optional[int]:
    """Recover virtualized ``com.iapp.app.f.b()`` constants from libLianYi.so.

    Some protected iApp builds move the tiny constant-return method out of DEX
    and encode it as four VMP code units::

        EA 00 <imm32-le> 36 00

    where EA is the build's const/31i handler and 36 is its integer-return
    handler.  Require the JNI registration strings and use multi-ABI voting to
    avoid treating unrelated byte sequences as a dexkey.
    """
    if not apk_path:
        return None
    counts: Dict[int, int] = {}
    entries = 0
    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            for info in z.infolist():
                if info.is_dir() or info.file_size <= 0 or info.file_size > 64 * 1024 * 1024:
                    continue
                simple = info.filename.replace("\\", "/").rsplit("/", 1)[-1].lower()
                if simple != "liblianyi.so":
                    continue
                try:
                    data = z.read(info)
                except Exception:
                    continue
                if b"Lcom/iapp/app/f;" not in data and b"classesInit0" not in data:
                    continue
                entries += 1
                local: Set[int] = set()
                for off in range(0, max(0, len(data) - 7)):
                    if data[off] != 0xEA or data[off + 1] != 0x00:
                        continue
                    if data[off + 6] != 0x36 or data[off + 7] != 0x00:
                        continue
                    value = int.from_bytes(data[off + 2:off + 6], "little", signed=True)
                    if 100_000 <= value <= 20_000_000:
                        local.add(value)
                for value in local:
                    counts[value] = counts.get(value, 0) + 1
    except Exception:
        return None
    if not counts:
        return None
    ranked = sorted(counts.items(), key=lambda row: (-row[1], row[0]))
    best, votes = ranked[0]
    if len(ranked) > 1 and ranked[1][1] == votes:
        return None
    # One ABI is enough when the APK only ships one matching native library;
    # multi-ABI packages naturally require the winning consensus.
    if entries > 1 and votes < 2:
        return None
    return int(best)




def _x86_native_constant_return_candidates(so_data: bytes) -> List[int]:
    """Find conservative 32-bit x86 constant-return branches in executable code.

    This is intentionally narrower than a generic immediate scan.  Protected
    iApp builds sometimes hide ``f.b()`` in a JNI/protector initializer: one
    branch loads a plausible integer into EAX and jumps through the ordinary
    function epilogue.  We require a real x86 ELF, a nearby standard epilogue,
    no unconditional near jump between the load and that epilogue, and no
    second ``mov eax, imm32`` overriding the value.
    """
    try:
        elf = MiniELF(so_data)
    except Exception:
        return []
    if elf.bits != 32 or elf.e_machine != 3:  # EM_386
        return []

    epilogue_re = re.compile(
        rb"(?:\x8d\x65[\x80-\xff])?(?:\x5e|\x5f|\x5b){1,5}\x5d\xc3"
    )
    out: Set[int] = set()
    for _name, _vaddr, code in get_exec_sections(elf):
        for off in range(0, max(0, len(code) - 6)):
            if code[off] != 0xB8:  # mov eax, imm32
                continue
            value = int.from_bytes(code[off + 1:off + 5], "little", signed=False)
            if not (100_000 <= value <= 20_000_000):
                continue
            tail = code[off + 5:off + 101]
            match = epilogue_re.search(tail)
            if match is None:
                continue
            before = tail[:match.start()]
            # A near unconditional jump means the apparent RET is normally in
            # another basic block or even another function.
            if b"\xE9" in before:
                continue
            if b"\xB8" in before:
                continue
            # Accept either a direct short return path or a conditional branch
            # that can preserve EAX until the shared epilogue.
            has_conditional = any(0x70 <= b <= 0x7F for b in before)
            has_conditional = has_conditional or any(
                before[i] == 0x0F and 0x80 <= before[i + 1] <= 0x8F
                for i in range(max(0, len(before) - 1))
            )
            if len(before) > 12 and not has_conditional:
                continue
            out.add(value)
    return sorted(out)


def _native_protector_fb_evidence(so_data: bytes) -> bool:
    low = so_data.lower()
    has_target = b"com/iapp/app/f" in low or b"com.iapp.app.f" in low
    has_runtime = any(
        token in low
        for token in (
            b"vminterpret", b"classesinit0", b"registernativesforclass",
            b"shellapplication", b"assetmanager", b"native_jvm",
        )
    )
    return has_target and has_runtime


def extract_fb_from_native_constant_consensus(apk_path: Optional[Path]) -> Optional[int]:
    """Recover a protected ``f.b()`` via strict cross-ABI native consensus.

    The immediate is accepted only when a protector/VM SO's x86 build exposes a
    constant-return path and the same four little-endian bytes occur in an
    executable section of another ABI with the same basename.  This avoids
    treating arbitrary constants from one architecture as a dex key.
    """
    if not apk_path:
        return None
    groups: Dict[str, List[Tuple[str, bytes]]] = {}
    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".so"):
                    continue
                if info.file_size <= 0 or info.file_size > 64 * 1024 * 1024:
                    continue
                name = info.filename.replace("\\", "/")
                base = name.rsplit("/", 1)[-1].lower()
                try:
                    blob = archive.read(info)
                except Exception:
                    continue
                groups.setdefault(base, []).append((name, blob))
    except Exception:
        return None

    winners: List[Tuple[int, str, str, List[str]]] = []
    for base, rows in groups.items():
        if len(rows) < 2 or not any(_native_protector_fb_evidence(blob) for _, blob in rows):
            continue
        x86_rows: List[Tuple[str, bytes]] = []
        other_rows: List[Tuple[str, bytes]] = []
        for name, blob in rows:
            try:
                elf = MiniELF(blob)
            except Exception:
                continue
            if elf.bits == 32 and elf.e_machine == 3:
                x86_rows.append((name, blob))
            else:
                other_rows.append((name, blob))
        if not x86_rows or not other_rows:
            continue
        for x86_name, x86_blob in x86_rows:
            for value in _x86_native_constant_return_candidates(x86_blob):
                needle = int(value).to_bytes(4, "little", signed=False)
                votes: List[str] = []
                for other_name, other_blob in other_rows:
                    try:
                        other_elf = MiniELF(other_blob)
                    except Exception:
                        continue
                    if any(needle in code for _n, _v, code in get_exec_sections(other_elf)):
                        votes.append(other_name)
                if votes:
                    winners.append((int(value), base, x86_name, votes))

    by_value: Dict[int, List[Tuple[str, str, List[str]]]] = {}
    for value, base, x86_name, votes in winners:
        by_value.setdefault(value, []).append((base, x86_name, votes))
    if len(by_value) != 1:
        return None
    value = next(iter(by_value))
    evidence = by_value[value]
    if len(evidence) != 1:
        # Multiple unrelated protector families agreeing is fine only if every
        # row names the same library; otherwise remain conservative.
        if len({row[0] for row in evidence}) != 1:
            return None
    base, x86_name, votes = evidence[0]
    print(
        f"[+] f.b() native constant consensus: {value} "
        f"({x86_name} + {len(votes)} ABI vote(s), family={base})"
    )
    return int(value)



def _rc4_static_crypt(data: bytes, key: bytes) -> bytes:
    """Small static RC4 implementation used only for protected asset metadata."""
    if not key:
        raise ValueError("empty RC4 key")
    box = list(range(256))
    j = 0
    for i in range(256):
        j = (j + box[i] + key[i % len(key)]) & 0xFF
        box[i], box[j] = box[j], box[i]
    out = bytearray(len(data))
    i = j = 0
    for pos, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + box[i]) & 0xFF
        box[i], box[j] = box[j], box[i]
        out[pos] = value ^ box[(box[i] + box[j]) & 0xFF]
    return bytes(out)


def _tosks_rodata_aes16_candidates(so_data: bytes) -> List[bytes]:
    """Return the tiny set of explicit 16-byte ASCII AES materials in rodata.

    Tosks stores its AES key/IV as NUL-terminated constants.  Accept exact
    16-byte strings and the common 16-byte value padded with spaces; do not scan
    arbitrary 16-byte windows from C++ symbols or code.
    """
    try:
        elf = MiniELF(so_data)
    except Exception:
        return []
    sec = elf.section_by_name(".rodata")
    if not sec:
        return []
    blob = so_data[sec["offset"]:sec["offset"] + sec["size"]]
    out: List[bytes] = []
    seen: Set[bytes] = set()
    for match in re.finditer(rb"[ -~]+\x00", blob):
        raw = match.group(0)[:-1]
        cand = b""
        if len(raw) == 16:
            cand = raw
        elif 16 < len(raw) <= 32 and raw[16:].strip(b" ") == b"":
            cand = raw[:16]
        if not cand or cand in seen:
            continue
        # Key/IV constants in this protector are compact identifiers, not prose.
        if sum(1 for value in cand if chr(value).isalnum()) < 12:
            continue
        seen.add(cand)
        out.append(cand)
    return out


def _aes_cbc_decrypt_static(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    _Cipher, _algorithms, _modes, _default_backend = _lazy_crypto()
    decryptor = _Cipher(
        _algorithms.AES(key), _modes.CBC(iv), backend=_default_backend()
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def _pkcs7_unpad_static(data: bytes, block_size: int = 16) -> Optional[bytes]:
    if not data:
        return None
    pad = data[-1]
    if not (1 <= pad <= block_size) or len(data) < pad:
        return None
    if data[-pad:] != bytes([pad]) * pad:
        return None
    return data[:-pad]


def _parse_tosks_payload_records(payload: bytes) -> List[bytes]:
    """Parse Tosks name-length + big-endian-size records and return valid DEXes."""
    out: List[bytes] = []
    pos = 0
    while pos + 6 <= len(payload):
        name_len = payload[pos]
        if not (1 <= name_len <= 160):
            break
        pos += 1
        if pos + name_len + 4 > len(payload):
            break
        name = payload[pos:pos + name_len]
        pos += name_len
        size = int.from_bytes(payload[pos:pos + 4], "big")
        pos += 4
        if size < 0x70 or pos + size > len(payload):
            break
        item = payload[pos:pos + size]
        pos += size
        if item.startswith(b"dex\n") and len(item) >= 0x70:
            declared = struct.unpack_from("<I", item, 0x20)[0]
            if declared == len(item):
                out.append(item)
        # Unknown non-DEX records are allowed, but names must stay printable.
        if not all(value >= 0x20 or value >= 0x80 for value in name):
            break
    return out


_TOSKS_DEX_CACHE: Dict[tuple, List[Tuple[str, bytes]]] = {}

def extract_tosks_embedded_dexes(apk_path: Optional[Path]) -> List[Tuple[str, bytes]]:
    """Statically recover original DEX records appended by the Tosks shell.

    The shell DEX stores its own logical end in the final big-endian dword.  Only
    the first 0x210 bytes of the appended stream are AES-CBC/PKCS7 encrypted.
    Key/IV candidates are taken from explicit 16-byte rodata constants and a
    pair is accepted only when the reconstructed record is a size-consistent DEX.
    """
    if not apk_path:
        return []
    path = Path(apk_path).resolve()
    try:
        stat = path.stat()
    except Exception:
        return []
    cache_key = (str(path), stat.st_size, stat.st_mtime_ns)
    if cache_key in _TOSKS_DEX_CACHE:
        return list(_TOSKS_DEX_CACHE[cache_key])
    result: List[Tuple[str, bytes]] = []
    try:
        with zipfile.ZipFile(path, "r") as archive:
            dex_rows: List[Tuple[str, bytes, int]] = []
            protector_sos: List[Tuple[str, bytes]] = []
            for info in archive.infolist():
                if info.is_dir() or info.file_size <= 0:
                    continue
                low = info.filename.replace("\\", "/").lower()
                if low.startswith("classes") and low.endswith(".dex") and info.file_size >= 0x400:
                    data = archive.read(info)
                    if not data.startswith(b"dex\n") or len(data) < 0x70:
                        continue
                    data_size = struct.unpack_from("<I", data, 0x68)[0]
                    data_off = struct.unpack_from("<I", data, 0x6C)[0]
                    shell_end = data_off + data_size
                    trailer_end = int.from_bytes(data[-4:], "big")
                    if shell_end == trailer_end and shell_end + 0x210 + 4 <= len(data):
                        dex_rows.append((info.filename, data, shell_end))
                elif low.endswith(".so") and "tosks" in low and info.file_size <= 32 * 1024 * 1024:
                    blob = archive.read(info)
                    if b"sourceDir" in blob and b"invoke1" in blob:
                        protector_sos.append((info.filename, blob))
            if not dex_rows or not protector_sos:
                _TOSKS_DEX_CACHE[cache_key] = []
                return []
            # Prefer x86_64/64-bit SO: its rodata is least likely to be compacted.
            protector_sos.sort(key=lambda row: ("x64" not in row[0].lower() and "x86_64" not in row[0].lower(), -len(row[1])))
            materials: List[bytes] = []
            for _name, blob in protector_sos:
                for cand in _tosks_rodata_aes16_candidates(blob):
                    if cand not in materials:
                        materials.append(cand)
                if len(materials) >= 2:
                    break
            if len(materials) < 2:
                _TOSKS_DEX_CACHE[cache_key] = []
                return []
            hits: List[Tuple[bytes, bytes, List[Tuple[str, bytes]]]] = []
            for key in materials:
                for iv in materials:
                    pair_rows: List[Tuple[str, bytes]] = []
                    for dex_name, shell, shell_end in dex_rows:
                        encrypted_head = shell[shell_end:shell_end + 0x210]
                        if len(encrypted_head) != 0x210 or len(encrypted_head) % 16:
                            continue
                        try:
                            plain_head = _pkcs7_unpad_static(_aes_cbc_decrypt_static(encrypted_head, key, iv))
                        except Exception:
                            continue
                        if plain_head is None:
                            continue
                        payload = plain_head + shell[shell_end + 0x210:-4]
                        records = _parse_tosks_payload_records(payload)
                        for idx, dex in enumerate(records):
                            pair_rows.append((f"{dex_name}:tosks[{idx}]", dex))
                    if pair_rows:
                        hits.append((key, iv, pair_rows))
            # Structural validation should leave exactly one key/IV pair.
            unique = {(key, iv): rows for key, iv, rows in hits}
            if len(unique) == 1:
                (key, iv), result = next(iter(unique.items()))
                print(
                    f"[+] Tosks original DEX recovered: records={len(result)} "
                    f"key_sha1={hashlib.sha1(key).hexdigest()[:10]} "
                    f"iv_sha1={hashlib.sha1(iv).hexdigest()[:10]}"
                )
    except Exception:
        result = []
    _TOSKS_DEX_CACHE.clear()
    _TOSKS_DEX_CACHE[cache_key] = list(result)
    return list(result)


def _dex_qsvm_zero_arg_int_indices(dex: bytes) -> List[int]:
    """Return VM indices used by unique static zero-arg int wrappers."""
    try:
        strings, hdr = dex_read_strings(dex)
        type_ids = [struct.unpack_from("<I", dex, hdr["type_ids_off"] + i * 4)[0] for i in range(hdr["type_ids_size"])]
        def tname(index: int) -> str:
            return strings[type_ids[index]]
        protos: List[Tuple[str, List[str]]] = []
        for i in range(hdr["proto_ids_size"]):
            _shorty, ret, params_off = struct.unpack_from("<III", dex, hdr["proto_ids_off"] + i * 12)
            params: List[str] = []
            if params_off:
                count = struct.unpack_from("<I", dex, params_off)[0]
                params = [tname(struct.unpack_from("<H", dex, params_off + 4 + j * 2)[0]) for j in range(count)]
            protos.append((tname(ret), params))
        methods: List[Tuple[int, int, int]] = [
            struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + i * 8)
            for i in range(hdr["method_ids_size"])
        ]
        vm_ids: Set[int] = set()
        for index, (class_idx, proto_idx, name_idx) in enumerate(methods):
            if tname(class_idx) in ("LQsvm/VProtect;", "LQiuShui/VProtect;") and strings[name_idx] == "VmInt":
                vm_ids.add(index)
        if not vm_ids:
            return []
    except Exception:
        return []

    def code_vm_index(code_off: int) -> Optional[int]:
        if code_off <= 0 or code_off + 16 > len(dex):
            return None
        try:
            _regs, _ins, _outs, _tries, _dbg, count = struct.unpack_from("<HHHHII", dex, code_off)
            insns = struct.unpack_from("<" + "H" * count, dex, code_off + 16)
        except Exception:
            return None
        consts: Dict[int, int] = {}
        found: List[int] = []
        pos = 0
        while pos < count:
            word = insns[pos]
            op = word & 0xFF
            if op == 0x12:
                aa = word >> 8; reg = aa & 0x0F; value = (aa >> 4) & 0x0F
                if value & 8: value -= 16
                consts[reg] = value; pos += 1; continue
            if op == 0x13 and pos + 1 < count:
                reg = word >> 8; value = insns[pos + 1]
                if value & 0x8000: value -= 0x10000
                consts[reg] = value; pos += 2; continue
            if op == 0x14 and pos + 2 < count:
                reg = word >> 8; value = insns[pos + 1] | (insns[pos + 2] << 16)
                if value & 0x80000000: value -= 0x100000000
                consts[reg] = value; pos += 3; continue
            if 0x6E <= op <= 0x72 and pos + 2 < count:
                argc = (word >> 12) & 0x0F; reg_g = (word >> 8) & 0x0F
                method_idx = insns[pos + 1]
                packed = insns[pos + 2]
                regs = [packed & 0xF, (packed >> 4) & 0xF, (packed >> 8) & 0xF, (packed >> 12) & 0xF, reg_g][:argc]
                if method_idx in vm_ids and regs and regs[0] in consts:
                    found.append(consts[regs[0]])
                pos += 3; continue
            if 0x74 <= op <= 0x78 and pos + 2 < count:
                argc = word >> 8; method_idx = insns[pos + 1]; start = insns[pos + 2]
                if method_idx in vm_ids and argc and start in consts:
                    found.append(consts[start])
                pos += 3; continue
            pos += _dex_instr_len_units(insns, pos)
        return found[0] if len(set(found)) == 1 else None

    out: List[int] = []
    try:
        for class_def_index in range(hdr["class_defs_size"]):
            off = hdr["class_defs_off"] + class_def_index * 32
            class_idx, _af, _super, _interfaces, _source, _ann, class_data_off, _static = struct.unpack_from("<IIIIIIII", dex, off)
            if not class_data_off:
                continue
            p = class_data_off
            static_fields, p = dex_uleb(dex, p); instance_fields, p = dex_uleb(dex, p)
            direct_methods, p = dex_uleb(dex, p); virtual_methods, p = dex_uleb(dex, p)
            for _ in range(static_fields + instance_fields):
                _, p = dex_uleb(dex, p); _, p = dex_uleb(dex, p)
            for method_count in (direct_methods, virtual_methods):
                last = 0
                for _ in range(method_count):
                    diff, p = dex_uleb(dex, p); access, p = dex_uleb(dex, p); code_off, p = dex_uleb(dex, p)
                    last += diff
                    if not (0 <= last < len(methods)):
                        continue
                    method_class, proto_idx, name_idx = methods[last]
                    ret, params = protos[proto_idx]
                    if method_class != class_idx or ret != "I" or params or not (access & 0x8) or not code_off:
                        continue
                    index = code_vm_index(code_off)
                    if index is not None and 0 <= index <= 1_000_000:
                        # iApp's f.b() wrapper convention keeps the method name b.
                        if strings[name_idx] == "b":
                            out.append(index)
    except Exception:
        return []
    return sorted(set(out))


def _valid_dalvik_code_bytes(code: bytes) -> bool:
    if not code or len(code) % 2:
        return False
    try:
        insns = struct.unpack("<" + "H" * (len(code) // 2), code)
    except Exception:
        return False
    pos = 0
    last_op = -1
    while pos < len(insns):
        last_op = insns[pos] & 0xFF
        step = _dex_instr_len_units(insns, pos)
        if step <= 0 or pos + step > len(insns):
            return False
        pos += step
    return pos == len(insns) and last_op in (0x0E, 0x0F, 0x10, 0x11, 0x27)


def _qsvm_epic_method_codes(blob: bytes) -> List[bytes]:
    """Parse the compact Epic method-code prefix used by QuiShui VM assets."""
    if len(blob) < 64 or not blob.startswith(b"Epic"):
        return []
    method_count = struct.unpack_from("<I", blob, 4)[0]
    if not (1 <= method_count <= 4096):
        return []

    def parse_record(start: int):
        if start + 18 > len(blob):
            return None
        code_len = struct.unpack_from("<I", blob, start + 5)[0]
        if not (2 <= code_len <= 0x10000) or code_len % 2:
            return None
        hits = []
        for delta in range(13, 25):
            end = start + delta + code_len
            if end > len(blob):
                continue
            code = blob[start + delta:end]
            if _valid_dalvik_code_bytes(code):
                hits.append((delta, code, end))
        if len(hits) != 1:
            return None
        return hits[0]

    chains: List[List[bytes]] = []
    for first in range(0x20, min(0x80, len(blob) - 18)):
        current = first
        codes: List[bytes] = []
        ok = True
        for idx in range(method_count):
            parsed = parse_record(current)
            if not parsed:
                ok = False; break
            _delta, code, end = parsed
            codes.append(code)
            if idx + 1 == method_count:
                current = end
                continue
            next_starts = []
            for pad in range(0, 5):
                candidate = end + pad
                if candidate < len(blob) and all(value == 0 for value in blob[end:candidate]):
                    if parse_record(candidate):
                        next_starts.append(candidate)
            if len(next_starts) != 1:
                ok = False; break
            current = next_starts[0]
        if ok and len(codes) == method_count:
            chains.append(codes)
    # Deduplicate equivalent chains found by overlapping scan starts.
    unique: Dict[Tuple[bytes, ...], List[bytes]] = {tuple(row): row for row in chains}
    return next(iter(unique.values())) if len(unique) == 1 else []


def _dalvik_const_return_from_bytes(code: bytes) -> Optional[int]:
    if len(code) == 8 and code[:2] == b"\x14\x00" and code[-2:] == b"\x0f\x00":
        value = int.from_bytes(code[2:6], "little", signed=True)
        return value
    return None


def extract_fb_from_quishui_native(apk_path: Optional[Path]) -> Optional[int]:
    """Recover f.b() through Tosks DEX + QuiShui .ArmEpic/RC4 VM metadata."""
    if not apk_path:
        return None
    path = Path(apk_path)
    dexes = extract_tosks_embedded_dexes(path)
    if not dexes:
        return None
    vm_indices: Set[int] = set()
    for _name, dex in dexes:
        vm_indices.update(_dex_qsvm_zero_arg_int_indices(dex))
    if len(vm_indices) != 1:
        return None
    vm_index = next(iter(vm_indices))

    records: Dict[Tuple[bytes, str, str], int] = {}
    try:
        with zipfile.ZipFile(path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".so") or "libqs_" not in info.filename.lower():
                    continue
                blob = archive.read(info)
                try:
                    elf = MiniELF(blob)
                except Exception:
                    continue
                sec = elf.section_by_name(".ArmEpic")
                if not sec or sec["size"] < 32:
                    continue
                meta = blob[sec["offset"]:sec["offset"] + sec["size"]]
                key = meta[:16]
                p0 = 16; p1 = meta.find(b"\x00", p0)
                if p1 <= p0:
                    continue
                asset_name = meta[p0:p1].decode("utf-8", "replace")
                p2 = meta.find(b"\x00", p1 + 1)
                vm_class = meta[p1 + 1:p2 if p2 > p1 else len(meta)].decode("utf-8", "replace")
                if not asset_name or "VProtect" not in vm_class:
                    continue
                records[(key, asset_name, vm_class)] = records.get((key, asset_name, vm_class), 0) + 1
            if not records:
                return None
            ranked = sorted(records.items(), key=lambda row: (-row[1], row[0][1]))
            (key, asset_name, _vm_class), votes = ranked[0]
            if len(ranked) > 1 and ranked[1][1] == votes:
                return None
            if sum(records.values()) > 1 and votes < 2:
                return None
            if asset_name not in archive.namelist():
                return None
            encrypted = archive.read(asset_name)
    except Exception:
        return None
    decoded = _rc4_static_crypt(encrypted, key)
    if not decoded.startswith(b"Epic"):
        return None
    codes = _qsvm_epic_method_codes(decoded)
    if not codes or vm_index >= len(codes):
        # Conservative fallback: accept only one plausible constant-return body.
        values = {
            int.from_bytes(match.group(1), "little", signed=True)
            for match in re.finditer(rb"\x14\x00(.{4})\x0f\x00", decoded, re.S)
            if 100_000 <= int.from_bytes(match.group(1), "little", signed=True) <= 20_000_000
        }
        if len(values) != 1:
            return None
        value = next(iter(values))
    else:
        value = _dalvik_const_return_from_bytes(codes[vm_index])
        if value is None:
            return None
    if not (100_000 <= value <= 20_000_000):
        return None
    print(
        f"[+] f.b() QuiShui VM: {value} "
        f"(VmInt index={vm_index}, ArmEpic ABI votes={votes}, asset={asset_name})"
    )
    return int(value)


def extract_fb_candidates_from_epic_vm(apk_path: Optional[Path]) -> List[int]:
    """Return statically visible EPIC VM ``VmInt`` constant candidates.

    Older EPIC builds used XOR 0x2b, while the two V181 samples derive another
    one-byte key per APK.  The key is proven by the exact four-byte ``Epic``
    header; no brute force or APK code execution is used.  Multiple plausible
    constants are returned to the wrapper, which verifies them against the
    normal container/main-entry decryptor and stops at the first real hit.
    """
    if not apk_path:
        return []
    try:
        with zipfile.ZipFile(apk_path, "r") as archive:
            info = next(
                (
                    item for item in archive.infolist()
                    if not item.is_dir()
                    and item.filename.replace("\\", "/").lower() == "epic.vm"
                    and 32 <= int(item.file_size or 0) <= 16 * 1024 * 1024
                ),
                None,
            )
            if info is None:
                return []
            raw = archive.read(info)
    except Exception:
        return []

    blobs: List[Tuple[str, bytes]] = [("identity", raw)]
    if len(raw) >= 4:
        keys = {raw[index] ^ b"Epic"[index] for index in range(4)}
        if len(keys) == 1:
            key = next(iter(keys))
            decoded = bytes(value ^ key for value in raw)
            if decoded != raw:
                blobs.append(("header-xor-%02x" % key, decoded))
    legacy = bytes(value ^ 0x2B for value in raw)
    if legacy != raw and all(legacy != blob for _label, blob in blobs):
        blobs.append(("legacy-xor-2b", legacy))

    values: Set[int] = set()
    accepted_modes: List[str] = []
    for mode, blob in blobs:
        if not blob.startswith(b"Epic"):
            continue
        if b"com/iapp/app/f" not in blob and b"com.iapp.app.f" not in blob:
            continue
        if b"()I" not in blob:
            continue
        local: Set[int] = set()
        for match in re.finditer(rb"\x14\x00(.{4})\x0f\x00", blob, flags=re.S):
            value = int.from_bytes(match.group(1), "little", signed=True)
            if 100_000 <= value <= 20_000_000:
                local.add(int(value))
        if local:
            values.update(local)
            accepted_modes.append(mode)
    result = sorted(values)
    if result:
        print(
            "[IAPT_EPIC_FB_CANDIDATES] modes="
            + ",".join(accepted_modes)
            + " values=" + ",".join(str(value) for value in result),
            flush=True,
        )
    return result


def extract_fb_from_epic_vm(apk_path: Optional[Path]) -> Optional[int]:
    """Return an EPIC VM f.b() value only when static evidence is unique."""
    values = extract_fb_candidates_from_epic_vm(apk_path)
    return values[0] if len(values) == 1 else None



def _dex_native_iapp_fb_present(dex: bytes) -> bool:
    """Return True when ``com.iapp.app.f.b():int`` is a native stub.

    The test is structural rather than protector-name based.  A native stub is
    the normal Java side of a dynamically registered f.b() implementation.
    """
    try:
        strings, hdr = dex_read_strings(dex)
        type_ids = [
            struct.unpack_from("<I", dex, hdr["type_ids_off"] + index * 4)[0]
            for index in range(hdr["type_ids_size"])
        ]

        def type_name(type_index: int) -> str:
            if not (0 <= type_index < len(type_ids)):
                return ""
            string_index = type_ids[type_index]
            return strings[string_index] if 0 <= string_index < len(strings) else ""

        protos: List[Tuple[str, Tuple[str, ...]]] = []
        for index in range(hdr["proto_ids_size"]):
            _shorty, return_type, params_off = struct.unpack_from(
                "<III", dex, hdr["proto_ids_off"] + index * 12
            )
            params: List[str] = []
            if params_off:
                size = struct.unpack_from("<I", dex, params_off)[0]
                for item in range(size):
                    parameter_type = struct.unpack_from(
                        "<H", dex, params_off + 4 + item * 2
                    )[0]
                    params.append(type_name(parameter_type))
            protos.append((type_name(return_type), tuple(params)))
        methods = [
            struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + index * 8)
            for index in range(hdr["method_ids_size"])
        ]
    except Exception:
        return False

    for class_def_index in range(hdr["class_defs_size"]):
        try:
            off = hdr["class_defs_off"] + class_def_index * 32
            class_idx, _access, _super, _interfaces, _source, _annotations, class_data_off, _static = struct.unpack_from(
                "<IIIIIIII", dex, off
            )
            if type_name(class_idx) != "Lcom/iapp/app/f;" or not class_data_off:
                continue
            cursor = class_data_off
            static_fields, cursor = dex_uleb(dex, cursor)
            instance_fields, cursor = dex_uleb(dex, cursor)
            direct_methods, cursor = dex_uleb(dex, cursor)
            virtual_methods, cursor = dex_uleb(dex, cursor)
            for _ in range(static_fields + instance_fields):
                _, cursor = dex_uleb(dex, cursor)
                _, cursor = dex_uleb(dex, cursor)
            for method_count in (direct_methods, virtual_methods):
                method_index = 0
                for _ in range(method_count):
                    diff, cursor = dex_uleb(dex, cursor)
                    access_flags, cursor = dex_uleb(dex, cursor)
                    code_off, cursor = dex_uleb(dex, cursor)
                    method_index += diff
                    if not (0 <= method_index < len(methods)):
                        continue
                    _owner, proto_index, name_index = methods[method_index]
                    if not (0 <= proto_index < len(protos) and 0 <= name_index < len(strings)):
                        continue
                    if strings[name_index] != "b" or protos[proto_index] != ("I", ()):
                        continue
                    # ACC_STATIC=0x8, ACC_NATIVE=0x100.  Some protectors omit
                    # ACC_NATIVE but leave code_off=0 before RegisterNatives.
                    if (access_flags & 0x8) and ((access_flags & 0x100) or code_off == 0):
                        return True
        except Exception:
            continue
    return False


def _dex_static_zero_arg_string_returns(dex: bytes) -> List[Tuple[str, str, str]]:
    """Extract literal strings returned by simple static ``():String`` methods.

    Only const-string/return-object data flow is accepted.  This deliberately
    ignores arbitrary DEX strings so class names that merely *look* like Base64
    cannot become key material.
    """
    try:
        strings, hdr = dex_read_strings(dex)
        type_ids = [
            struct.unpack_from("<I", dex, hdr["type_ids_off"] + index * 4)[0]
            for index in range(hdr["type_ids_size"])
        ]

        def type_name(type_index: int) -> str:
            if not (0 <= type_index < len(type_ids)):
                return ""
            string_index = type_ids[type_index]
            return strings[string_index] if 0 <= string_index < len(strings) else ""

        protos: List[Tuple[str, Tuple[str, ...]]] = []
        for index in range(hdr["proto_ids_size"]):
            _shorty, return_type, params_off = struct.unpack_from(
                "<III", dex, hdr["proto_ids_off"] + index * 12
            )
            params: List[str] = []
            if params_off:
                size = struct.unpack_from("<I", dex, params_off)[0]
                for item in range(size):
                    parameter_type = struct.unpack_from(
                        "<H", dex, params_off + 4 + item * 2
                    )[0]
                    params.append(type_name(parameter_type))
            protos.append((type_name(return_type), tuple(params)))
        methods = [
            struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + index * 8)
            for index in range(hdr["method_ids_size"])
        ]
    except Exception:
        return []

    results: List[Tuple[str, str, str]] = []
    for class_def_index in range(hdr["class_defs_size"]):
        try:
            off = hdr["class_defs_off"] + class_def_index * 32
            class_idx, _access, _super, _interfaces, _source, _annotations, class_data_off, _static = struct.unpack_from(
                "<IIIIIIII", dex, off
            )
            if not class_data_off:
                continue
            class_name = type_name(class_idx)
            cursor = class_data_off
            static_fields, cursor = dex_uleb(dex, cursor)
            instance_fields, cursor = dex_uleb(dex, cursor)
            direct_methods, cursor = dex_uleb(dex, cursor)
            virtual_methods, cursor = dex_uleb(dex, cursor)
            for _ in range(static_fields + instance_fields):
                _, cursor = dex_uleb(dex, cursor)
                _, cursor = dex_uleb(dex, cursor)
            for method_count in (direct_methods, virtual_methods):
                method_index = 0
                for _ in range(method_count):
                    diff, cursor = dex_uleb(dex, cursor)
                    access_flags, cursor = dex_uleb(dex, cursor)
                    code_off, cursor = dex_uleb(dex, cursor)
                    method_index += diff
                    if not code_off or not (access_flags & 0x8):
                        continue
                    if not (0 <= method_index < len(methods)):
                        continue
                    _owner, proto_index, name_index = methods[method_index]
                    if not (0 <= proto_index < len(protos) and 0 <= name_index < len(strings)):
                        continue
                    if protos[proto_index] != ("Ljava/lang/String;", ()):
                        continue
                    if code_off + 16 > len(dex):
                        continue
                    _registers, _ins, _outs, _tries, _debug, insns_size = struct.unpack_from(
                        "<HHHHII", dex, code_off
                    )
                    insns_off = code_off + 16
                    if insns_size <= 0 or insns_off + insns_size * 2 > len(dex):
                        continue
                    insns = struct.unpack_from("<" + "H" * insns_size, dex, insns_off)
                    register_values: Dict[int, str] = {}
                    returned: Optional[str] = None
                    pc = 0
                    while pc < len(insns):
                        op = insns[pc] & 0xFF
                        try:
                            if op == 0x1A and pc + 1 < len(insns):  # const-string vAA, string@BBBB
                                register = (insns[pc] >> 8) & 0xFF
                                string_index = insns[pc + 1]
                                if 0 <= string_index < len(strings):
                                    register_values[register] = strings[string_index]
                            elif op == 0x1B and pc + 2 < len(insns):  # const-string/jumbo
                                register = (insns[pc] >> 8) & 0xFF
                                string_index = insns[pc + 1] | (insns[pc + 2] << 16)
                                if 0 <= string_index < len(strings):
                                    register_values[register] = strings[string_index]
                            elif op == 0x07:  # move-object vA, vB
                                register_a = (insns[pc] >> 8) & 0x0F
                                register_b = (insns[pc] >> 12) & 0x0F
                                if register_b in register_values:
                                    register_values[register_a] = register_values[register_b]
                            elif op == 0x08 and pc + 1 < len(insns):  # move-object/from16
                                register_a = (insns[pc] >> 8) & 0xFF
                                register_b = insns[pc + 1]
                                if register_b in register_values:
                                    register_values[register_a] = register_values[register_b]
                            elif op == 0x09 and pc + 2 < len(insns):  # move-object/16
                                register_a = insns[pc + 1]
                                register_b = insns[pc + 2]
                                if register_b in register_values:
                                    register_values[register_a] = register_values[register_b]
                            elif op == 0x11:  # return-object vAA
                                returned = register_values.get((insns[pc] >> 8) & 0xFF)
                        except Exception:
                            pass
                        step = _dex_instr_len_units(insns, pc)
                        if step <= 0:
                            break
                        pc += step
                    if returned is not None:
                        item = (class_name, strings[name_index], returned)
                        if item not in results:
                            results.append(item)
        except Exception:
            continue
    return results


def extract_fb_candidates_from_registered_native_xor(apk_path: Optional[Path]) -> List[int]:
    """Recover native f.b() values from a registered Base64/repeating-XOR flow.

    This is a protector-agnostic static resolver.  It requires all of these
    independent facts before producing a candidate:

    * DEX declares native ``com.iapp.app.f.b():int``;
    * a static zero-argument String method returns a valid Base64 literal;
    * an ELF references Base64 decoding, getBytes, parseInt and JNI native
      registration; and
    * repeating-XOR of the decoded literal with a string resident in that ELF
      yields a decimal value in the accepted f.b() range.

    No APK code is executed and no numeric range is enumerated.  The normal
    main-entry decryptor still verifies every returned value.
    """
    if not apk_path:
        return []
    path = Path(apk_path)
    dex_blobs = load_apk_dex_blobs(path)
    if not dex_blobs or not any(_dex_native_iapp_fb_present(dex) for _name, dex in dex_blobs):
        return []

    encoded_literals: List[Tuple[str, str, str, bytes]] = []
    for dex_name, dex in dex_blobs:
        for class_name, method_name, literal in _dex_static_zero_arg_string_returns(dex):
            if not (8 <= len(literal) <= 88 and len(literal) % 4 == 0):
                continue
            if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", literal):
                continue
            try:
                decoded = base64.b64decode(literal, validate=True)
            except Exception:
                continue
            if not (3 <= len(decoded) <= 32):
                continue
            item = (dex_name, class_name, method_name, decoded)
            if item not in encoded_literals:
                encoded_literals.append(item)
    if not encoded_literals:
        return []

    required_groups = (
        (b"java.util.Base64", b"java/util/Base64"),
        (b"parseInt",),
        (b"getBytes",),
        (b"registerNativesForClass", b"RegisterNatives"),
        (b"com.iapp.app.f", b"com/iapp/app/f"),
    )
    votes: Dict[int, Set[str]] = {}
    evidence: Dict[int, List[Tuple[str, str, str, str]]] = {}
    evidence_so_count = 0
    try:
        with zipfile.ZipFile(path, "r") as archive:
            for info in archive.infolist():
                if info.is_dir() or not info.filename.lower().endswith(".so"):
                    continue
                blob = archive.read(info)
                if not blob.startswith(b"\x7fELF"):
                    continue
                if not all(any(token in blob for token in group) for group in required_groups):
                    continue
                evidence_so_count += 1
                printable = {
                    match.group(0).decode("ascii", "ignore")
                    for match in re.finditer(rb"[\x20-\x7e]{4,48}", blob)
                }
                key_candidates: List[str] = []
                for candidate in printable:
                    if not (4 <= len(candidate) <= 32):
                        continue
                    if not re.fullmatch(r"[A-Za-z0-9_.|@#:+\-]+", candidate):
                        continue
                    if candidate.startswith("_") or candidate.isdigit():
                        continue
                    lowered = candidate.lower()
                    if any(
                        marker in lowered
                        for marker in (
                            "base64", "parseint", "getbytes", "register", "native",
                            "java.", "com.", "android", "hidekey", "special_", "glibc",
                            "malloc", "memcpy", "strlen", "pthread", "operator",
                        )
                    ):
                        continue
                    if candidate.count(".") >= 2 or candidate.count("_") >= 2:
                        continue
                    if sum(char.isalpha() for char in candidate) < 2:
                        continue
                    key_candidates.append(candidate)

                abi_identity = info.filename.replace("\\", "/")
                for dex_name, class_name, method_name, decoded in encoded_literals:
                    for key_text in key_candidates:
                        key = key_text.encode("ascii", "strict")
                        plain = bytes(
                            value ^ key[index % len(key)]
                            for index, value in enumerate(decoded)
                        )
                        if not (6 <= len(plain) <= 8 and plain.isdigit()):
                            continue
                        number = int(plain)
                        if not (100_000 <= number <= 20_000_000):
                            continue
                        votes.setdefault(number, set()).add(abi_identity)
                        row = (dex_name, class_name, method_name, hashlib.sha256(key).hexdigest()[:12])
                        if row not in evidence.setdefault(number, []):
                            evidence[number].append(row)
    except Exception:
        return []

    if not votes:
        return []
    # When several ABI libraries expose the same registration flow, require
    # cross-ABI agreement.  A single-ABI APK is accepted because the normal
    # mian.iyu verification remains authoritative.
    minimum_votes = 2 if evidence_so_count >= 2 else 1
    ranked = sorted(
        (number for number, sources in votes.items() if len(sources) >= minimum_votes),
        key=lambda number: (-len(votes[number]), number),
    )
    if ranked:
        details = ";".join(
            f"{number}:abi_votes={len(votes[number])}:dex={evidence[number][0][0]}:method={evidence[number][0][1]}->{evidence[number][0][2]}"
            for number in ranked
        )
        print(f"[IAPT_REGISTERED_NATIVE_XOR_FB] {details}", flush=True)
    return ranked


def extract_fb_candidates_from_apk(apk_path: Optional[Path], primary_dex: Optional[bytes] = None) -> List[int]:
    """Collect a small, evidence-derived f.b()/dexkey candidate set.

    This function never creates a numeric range.  Values come only from a
    constant-return iApp method, strict native consensus, QuiShui VM metadata,
    or exact EPIC VM ``const/return`` records.  The caller must verify every
    candidate by decrypting the real main entry.
    """
    values: List[int] = []

    def add(value) -> None:
        try:
            number = int(value)
        except Exception:
            return
        if 100_000 <= number <= 20_000_000 and number not in values:
            values.append(number)

    if primary_dex:
        add(extract_fb_from_dex(primary_dex))
    for _name, dex in load_apk_dex_blobs(apk_path):
        add(extract_fb_from_dex(dex))
    for resolver in (
        extract_fb_from_lianyi_native,
        extract_fb_from_native_constant_consensus,
        extract_fb_from_quishui_native,
    ):
        try:
            add(resolver(apk_path))
        except Exception:
            pass
    for value in extract_fb_candidates_from_registered_native_xor(apk_path):
        add(value)
    for value in extract_fb_candidates_from_epic_vm(apk_path):
        add(value)
    return values

def extract_fb_from_apk_dexes(apk_path: Optional[Path], primary_dex: Optional[bytes] = None) -> Optional[int]:
    if primary_dex:
        v = extract_fb_from_dex(primary_dex)
        if v is not None:
            print("[+] f.b() auto from classes.dex:", v)
            return v
    for name, dex in load_apk_dex_blobs(apk_path):
        v = extract_fb_from_dex(dex)
        if v is not None:
            print(f"[+] f.b() auto from {name}: {v}")
            return v
    native_v = extract_fb_from_lianyi_native(apk_path)
    if native_v is not None:
        print("[+] f.b() auto from libLianYi.so VMP:", native_v)
        return native_v
    consensus_v = extract_fb_from_native_constant_consensus(apk_path)
    if consensus_v is not None:
        return consensus_v
    quishui_v = extract_fb_from_quishui_native(apk_path)
    if quishui_v is not None:
        return quishui_v
    registered_values = extract_fb_candidates_from_registered_native_xor(apk_path)
    if len(registered_values) == 1:
        print("[+] f.b() auto from registered native Base64/XOR flow:", registered_values[0])
        return registered_values[0]
    epic_v = extract_fb_from_epic_vm(apk_path)
    if epic_v is not None:
        print("[+] f.b() auto from Epic.vm:", epic_v)
        return epic_v
    return None

def dex_uleb(dex: bytes, p: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        b = dex[p]
        p += 1
        result |= (b & 0x7F) << shift
        if b < 0x80:
            return result, p
        shift += 7


def dex_read_strings(dex: bytes) -> Tuple[List[str], Dict[str, int]]:
    names = ["string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off", "proto_ids_size", "proto_ids_off", "field_ids_size", "field_ids_off", "method_ids_size", "method_ids_off", "class_defs_size", "class_defs_off"]
    hdr = dict(zip(names, struct.unpack_from("<" + "I" * 12, dex, 0x38)))
    strings: List[str] = []
    for i in range(hdr["string_ids_size"]):
        off = struct.unpack_from("<I", dex, hdr["string_ids_off"] + i * 4)[0]
        _, p = dex_uleb(dex, off)
        q = dex.find(b"\x00", p)
        strings.append(dex[p:q].decode("utf-8", "replace"))
    return strings, hdr


def read_dex_const_return_int(dex: bytes, code_off: int) -> Optional[int]:
    if code_off <= 0 or code_off + 16 > len(dex):
        return None
    registers_size, ins_size, outs_size, tries_size, debug_info_off, insns_size = struct.unpack_from("<HHHHII", dex, code_off)
    insns_off = code_off + 16
    if insns_off + insns_size * 2 > len(dex):
        return None
    insns = list(struct.unpack_from("<" + "H" * insns_size, dex, insns_off))
    i = 0
    last_const = None
    last_reg = None
    while i < len(insns):
        op = insns[i] & 0xFF
        if op == 0x12:
            aa = (insns[i] >> 8) & 0xFF
            reg = aa & 0x0F
            imm = (aa >> 4) & 0x0F
            if imm & 0x8:
                imm -= 0x10
            last_reg = reg
            last_const = imm
            i += 1
            continue
        if op == 0x13 and i + 1 < len(insns):
            reg = (insns[i] >> 8) & 0xFF
            imm = insns[i + 1]
            if imm & 0x8000:
                imm -= 0x10000
            last_reg = reg
            last_const = imm
            i += 2
            continue
        if op == 0x14 and i + 2 < len(insns):
            reg = (insns[i] >> 8) & 0xFF
            imm = insns[i + 1] | (insns[i + 2] << 16)
            if imm & 0x80000000:
                imm -= 0x100000000
            last_reg = reg
            last_const = imm
            i += 3
            continue
        if op == 0x15 and i + 1 < len(insns):
            reg = (insns[i] >> 8) & 0xFF
            imm = insns[i + 1] << 16
            if imm & 0x80000000:
                imm -= 0x100000000
            last_reg = reg
            last_const = imm
            i += 2
            continue
        if op == 0x0F:
            reg = (insns[i] >> 8) & 0xFF
            if last_const is not None and (last_reg is None or last_reg == reg):
                return last_const
            return last_const
        i += 1
    return last_const


def extract_fb_from_dex(dex: bytes) -> Optional[int]:
    """Recover iApp ``f.b():int`` from the original application DEX.

    Besides the canonical ``Lcom/iapp/app/f;`` name, protected builds may rename
    that helper while preserving its distinctive three-method API:

    * ``a(String, Context): String``
    * ``b(): int``
    * ``b(String, Context): byte[]``

    The alias path is accepted only when exactly one ``com/iapp/app`` class has
    that complete signature set and its zero-argument ``b`` is a direct literal
    return in the normal dexkey range.  This avoids treating unrelated integer
    constants as f.b().
    """
    try:
        strings, hdr = dex_read_strings(dex)
        type_ids = [
            struct.unpack_from("<I", dex, hdr["type_ids_off"] + i * 4)[0]
            for i in range(hdr["type_ids_size"])
        ]

        def tname(type_idx: int) -> str:
            if not (0 <= type_idx < len(type_ids)):
                return ""
            string_idx = type_ids[type_idx]
            return strings[string_idx] if 0 <= string_idx < len(strings) else ""

        protos: List[Tuple[str, Tuple[str, ...]]] = []
        for i in range(hdr["proto_ids_size"]):
            _shorty, ret, params_off = struct.unpack_from(
                "<III", dex, hdr["proto_ids_off"] + i * 12
            )
            params: List[str] = []
            if params_off:
                count = struct.unpack_from("<I", dex, params_off)[0]
                for j in range(count):
                    param_type = struct.unpack_from(
                        "<H", dex, params_off + 4 + j * 2
                    )[0]
                    params.append(tname(param_type))
            protos.append((tname(ret), tuple(params)))

        methods = [
            struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + i * 8)
            for i in range(hdr["method_ids_size"])
        ]
    except Exception:
        return None

    aliases: List[Tuple[str, int]] = []
    for class_def_index in range(hdr["class_defs_size"]):
        try:
            off = hdr["class_defs_off"] + class_def_index * 32
            class_idx, _access_flags, _super_idx, _interfaces_off, _source_idx, _annotations_off, class_data_off, _static_values_off = struct.unpack_from(
                "<IIIIIIII", dex, off
            )
            class_name = tname(class_idx)
            if not class_data_off:
                continue
            # The canonical class and renamed aliases both stay in iApp's own
            # package.  Do not scan arbitrary application/library classes.
            if class_name != "Lcom/iapp/app/f;" and not (
                class_name.startswith("Lcom/iapp/app/")
                and class_name.endswith(";")
                and "/" not in class_name[len("Lcom/iapp/app/"):-1]
            ):
                continue

            cursor = class_data_off
            static_fields, cursor = dex_uleb(dex, cursor)
            instance_fields, cursor = dex_uleb(dex, cursor)
            direct_methods, cursor = dex_uleb(dex, cursor)
            virtual_methods, cursor = dex_uleb(dex, cursor)
            for _ in range(static_fields + instance_fields):
                _, cursor = dex_uleb(dex, cursor)
                _, cursor = dex_uleb(dex, cursor)

            rows: List[Tuple[str, Tuple[str, Tuple[str, ...]], int, int]] = []
            method_index = 0
            for method_count in (direct_methods, virtual_methods):
                for _ in range(method_count):
                    diff, cursor = dex_uleb(dex, cursor)
                    access_flags, cursor = dex_uleb(dex, cursor)
                    code_off, cursor = dex_uleb(dex, cursor)
                    method_index += diff
                    if not (0 <= method_index < len(methods)):
                        continue
                    owner, proto_index, name_index = methods[method_index]
                    if owner != class_idx or not (0 <= proto_index < len(protos)) or not (0 <= name_index < len(strings)):
                        continue
                    rows.append((strings[name_index], protos[proto_index], access_flags, code_off))

            int_rows = [
                row for row in rows
                if row[0] == "b" and row[1] == ("I", ()) and (row[2] & 0x8) and row[3]
            ]
            if len(int_rows) != 1:
                continue
            value = read_dex_const_return_int(dex, int_rows[0][3])
            if value is None or not (100_000 <= int(value) <= 20_000_000):
                # A protector stub returning 0 is not authoritative.
                continue
            value = int(value)

            if class_name == "Lcom/iapp/app/f;":
                return value

            has_string_helper = any(
                name == "a"
                and proto == ("Ljava/lang/String;", ("Ljava/lang/String;", "Landroid/content/Context;"))
                and (access & 0x8)
                for name, proto, access, _code in rows
            )
            has_bytes_helper = any(
                name == "b"
                and proto == ("[B", ("Ljava/lang/String;", "Landroid/content/Context;"))
                and (access & 0x8)
                for name, proto, access, _code in rows
            )
            if has_string_helper and has_bytes_helper:
                aliases.append((class_name, value))
        except Exception:
            continue

    unique = {(name, value) for name, value in aliases}
    values = {value for _name, value in unique}
    if len(unique) == 1 and len(values) == 1:
        class_name, value = next(iter(unique))
        print(
            "[IAPT_FB_RENAMED_CLASS] class=%s value=%d evidence=a(String,Context):String+b():int+b(String,Context):byte[]"
            % (class_name, value),
            flush=True,
        )
        return int(value)
    return None



# ---------------- Numeric iApp function-name restoration ----------------
# Some dynamic-packaging iApp builds replace native/source function calls with
# decimal IDs, for example f(x) -> 146323(x) or call(...) -> 147710(...).
# The ID->name table is emitted into app DEX bytecode as a pair of arrays:
# one list of original strings like "f("/"call(" and one list of hex/int IDs.
# This post-processing stage only rewrites decrypted source files; it does not
# change any container/key/member decryption logic.
NUMERIC_FN_DEF_RE = re.compile(r"(?m)^\s*fn\s+(\d{2,12})(?=\s*\()")
NORMAL_FN_DEF_RE = re.compile(r"(?m)^\s*fn\s+([A-Za-z_\u0080-\uffff][A-Za-z0-9_.$\u0080-\uffff]*(?:\.[A-Za-z_\u0080-\uffff][A-Za-z0-9_.$\u0080-\uffff]*)?)(?=\s*\()")
NUMERIC_FN_CALL_RE = re.compile(r"(?<![A-Za-z0-9_.$])([1-9]\d{3,11})(?=\s*\()")
NUMERIC_FN_DEF_BRE = re.compile(br"(?m)^\s*fn\s+(\d{2,12})(?=\s*\()")
NUMERIC_FN_CALL_BRE = re.compile(br"(?<![A-Za-z0-9_.$])([1-9]\d{3,11})(?=\s*\()")
NORMAL_FN_DEF_BRE = re.compile(br"(?m)^\s*fn\s+([A-Za-z_\x80-\xff][A-Za-z0-9_.$\x80-\xff]*(?:\.[A-Za-z_\x80-\xff][A-Za-z0-9_.$\x80-\xff]*)?)(?=\s*\()")
SOURCE_EXTS = set(FILE_EXTS)


def _dex_instr_len_units(insns: Tuple[int, ...], i: int) -> int:
    """Return the exact Dalvik instruction length in 16-bit code units.

    The previous abbreviated table treated many arithmetic/conversion opcodes as
    one unit and array-length as two units.  That desynchronized long iApp
    dispatch methods and shifted the dynamic numeric mapping.
    """
    word = insns[i]
    op = word & 0xFF
    if op == 0x00:
        ident = word & 0xFF00
        if ident == 0x0100 and i + 1 < len(insns):  # packed-switch-payload
            size = insns[i + 1]
            return 4 + int(size) * 2
        if ident == 0x0200 and i + 1 < len(insns):  # sparse-switch-payload
            size = insns[i + 1]
            return 2 + int(size) * 4
        if ident == 0x0300 and i + 3 < len(insns):  # fill-array-data-payload
            width = insns[i + 1]
            size = insns[i + 2] | (insns[i + 3] << 16)
            return 4 + ((int(width) * int(size) + 1) // 2)
        return 1
    if op in (0x01, 0x04, 0x07, *range(0x0A, 0x13), 0x1D, 0x1E, 0x21, 0x27, 0x28,
              *range(0x3E, 0x44), 0x73, 0x79, 0x7A,
              *range(0x7B, 0x90), *range(0xB0, 0xD0)):
        return 1
    if op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20,
              0x22, 0x23, 0x29, *range(0x2D, 0x3E), *range(0x44, 0x6E),
              *range(0x90, 0xB0), *range(0xD0, 0xE3), 0xFE, 0xFF):
        return 2
    if op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C,
              *range(0x6E, 0x73), *range(0x74, 0x79), 0xFC, 0xFD):
        return 3
    if op in (0xFA, 0xFB):
        return 4
    if op == 0x18:
        return 5
    # Unknown/vendor opcode: one unit is safer than jumping over a real opcode.
    return 1


def _normalize_iapp_func_string(s: str) -> Optional[str]:
    """Return the iApp function token before '(' from a DEX const-string entry."""
    if not s or "(" not in s:
        return None
    if "\n" in s or "\r" in s or "->" in s:
        return None
    head = s.split("(", 1)[0].strip().strip('"\'')
    if not (1 <= len(head) <= 96):
        return None
    if head in {"SUPPRESS_ERROR_PAGE"}:
        return None
    # Dynamic-pack native commands include operator-like names such as s+(...),
    # s-(...), s*(...), s/(...), s%(...) which must not be filtered out.
    if re.fullmatch(r"s[+\-*/%]", head):
        return head
    # Drop descriptors, regexes, prose, and obvious Java/internal signatures.
    bad_chars = set('[]{};:<>\\/|?*=')
    if any(ch in bad_chars for ch in head):
        return None
    if head.startswith(("L", "java.", "android.", "kotlin.", "com.")) and "/" in head:
        return None
    if re.fullmatch(r"\d+", head):
        return None
    if not re.fullmatch(r"[A-Za-z_\u0080-\uffff][A-Za-z0-9_.$\u0080-\uffff]*(?:\.[A-Za-z_\u0080-\uffff][A-Za-z0-9_.$\u0080-\uffff]*)?", head):
        return None
    return head


def _dex_scan_code_literals(dex: bytes, code_off: int, strings: List[str]) -> Tuple[List[str], List[int], int]:
    """Return ordered function-like const-strings and int constants from one code item."""
    if code_off <= 0 or code_off + 16 > len(dex):
        return [], [], 0
    try:
        _registers_size, _ins_size, _outs_size, _tries_size, _debug_info_off, insns_size = struct.unpack_from("<HHHHII", dex, code_off)
    except Exception:
        return [], [], 0
    insns_off = code_off + 16
    if insns_off + insns_size * 2 > len(dex):
        return [], [], 0
    try:
        insns = struct.unpack_from("<" + "H" * insns_size, dex, insns_off)
    except Exception:
        return [], [], 0

    funcs: List[str] = []
    nums: List[int] = []
    i = 0
    while i < insns_size:
        word = insns[i]
        op = word & 0xFF
        if op == 0x1A and i + 1 < insns_size:  # const-string vAA, string@BBBB
            idx = insns[i + 1]
            if 0 <= idx < len(strings):
                f = _normalize_iapp_func_string(strings[idx])
                if f is not None:
                    funcs.append(f)
            i += 2
            continue
        if op == 0x1B and i + 2 < insns_size:  # const-string/jumbo
            idx = insns[i + 1] | (insns[i + 2] << 16)
            if 0 <= idx < len(strings):
                f = _normalize_iapp_func_string(strings[idx])
                if f is not None:
                    funcs.append(f)
            i += 3
            continue
        if op == 0x12:  # const/4; mostly array indexes, filtered later
            aa = (word >> 8) & 0xFF
            imm = (aa >> 4) & 0x0F
            if imm & 0x08:
                imm -= 0x10
            nums.append(imm)
            i += 1
            continue
        if op == 0x13 and i + 1 < insns_size:  # const/16
            val = insns[i + 1]
            if val & 0x8000:
                val -= 0x10000
            nums.append(val)
            i += 2
            continue
        if op == 0x14 and i + 2 < insns_size:  # const
            val = insns[i + 1] | (insns[i + 2] << 16)
            if val & 0x80000000:
                val -= 0x100000000
            nums.append(val)
            i += 3
            continue
        if op == 0x15 and i + 1 < insns_size:  # const/high16
            val = insns[i + 1] << 16
            if val & 0x80000000:
                val -= 0x100000000
            nums.append(val)
            i += 2
            continue
        i += _dex_instr_len_units(insns, i)
    # iApp dynamic pack tables usually store 5-hex-digit IDs (0x10000+), which
    # become decimal names in source.  Filtering avoids array indexes and sizes.
    nums = [abs(x) for x in nums if 10000 <= abs(x) <= 999999999999]
    return funcs, nums, insns_size





# IAPT_NUMERIC_DYNAMIC_TABLE_V147_BEGIN
# iApp keeps a built-in sequential compatibility table (145001 -> f,
# 145002 -> for, ... ) in ordinary applications as well.  That table is not
# evidence of dynamic numeric encryption and must never be used for source
# replacement.  Dynamic builds create a second, dense but shuffled/random ID
# table.  The helpers below reconstruct both arrays by their explicit DEX
# aput-object index so function names cannot be shifted by unrelated constants.

def _numeric_table_profile(nums: List[int], funcs: List[str]) -> Dict[str, object]:
    n = min(len(nums), len(funcs))
    if n <= 0:
        return {
            "pairs": 0, "baseline": False, "dynamic": False,
            "unique_ratio": 0.0, "sequential_ratio": 0.0,
            "span": 0, "iapp_header": False,
        }
    vals = [abs(int(x)) for x in nums[:n]]
    names = [str(x or "").strip() for x in funcs[:n]]
    unique_ratio = len(set(vals)) / float(n)
    sequential_hits = sum(1 for i in range(n - 1) if vals[i + 1] == vals[i] + 1)
    sequential_ratio = sequential_hits / float(max(1, n - 1))
    baseline_hits = sum(1 for i, value in enumerate(vals) if value == 145001 + i)
    baseline_ratio = baseline_hits / float(n)
    span = max(vals) - min(vals) if vals else 0
    iapp_header = len(names) >= 4 and names[:4] == ["f", "for", "w", "t"]

    # The compatibility table is normally exactly 145001..145180.  Permit a
    # small amount of parser loss but never treat it as a restore table.
    baseline = bool(
        n >= 20 and iapp_header
        and (baseline_ratio >= 0.80 or (
            145000 <= vals[0] <= 145010 and sequential_ratio >= 0.80
        ))
    )

    # A real dynamic table is a compact permutation/randomization: many unique
    # IDs in a narrow range, same iApp command header, and not a sequential run.
    dense_limit = max(10000, n * 250)
    dynamic = bool(
        n >= 20 and iapp_header and not baseline
        and unique_ratio >= 0.85
        and sequential_ratio <= 0.35
        and span <= dense_limit
    )
    return {
        "pairs": n,
        "baseline": baseline,
        "dynamic": dynamic,
        "unique_ratio": unique_ratio,
        "sequential_ratio": sequential_ratio,
        "baseline_ratio": baseline_ratio,
        "span": span,
        "iapp_header": iapp_header,
    }


def _dex_scan_indexed_method_numeric_table(
    dex_name: str,
    dex: bytes,
    code_off: int,
    strings: List[str],
    class_name: str,
    method_name: str,
) -> Optional[Dict]:
    """Rebuild one iApp function/number table by explicit array index.

    The old scanner paired all function strings and integer constants by raw
    encounter order.  In dynamic samples, unrelated constants or one omitted
    table entry shift every mapping after that point.  Here each const-string
    and random ID is paired only when its aput-object index is known.
    """
    if code_off <= 0 or code_off + 16 > len(dex):
        return None
    try:
        _registers_size, _ins_size, _outs_size, _tries_size, _debug_info_off, insns_size = struct.unpack_from(
            "<HHHHII", dex, code_off
        )
    except Exception:
        return None
    insns_off = code_off + 16
    if insns_off + insns_size * 2 > len(dex):
        return None
    try:
        insns = struct.unpack_from("<" + "H" * insns_size, dex, insns_off)
    except Exception:
        return None

    int_regs: Dict[int, int] = {}
    pending_funcs: Dict[int, str] = {}
    funcs_by_index: Dict[int, str] = {}
    nums_by_index: Dict[int, int] = {}
    last_large: Optional[int] = None
    large_age = 10 ** 9

    def set_int(reg: int, value: int) -> None:
        nonlocal last_large, large_age
        int_regs[int(reg)] = int(value)
        pending_funcs.pop(int(reg), None)
        av = abs(int(value))
        if 10000 <= av <= 999999999999:
            last_large = av
            large_age = 0

    i = 0
    while i < insns_size:
        word = insns[i]
        op = word & 0xFF
        large_age += 1

        if op == 0x12:  # const/4 vA, #+B
            reg = (word >> 8) & 0x0F
            value = (word >> 12) & 0x0F
            if value & 0x08:
                value -= 0x10
            set_int(reg, value)
            i += 1
            continue
        if op == 0x13 and i + 1 < insns_size:  # const/16
            reg = (word >> 8) & 0xFF
            value = insns[i + 1]
            if value & 0x8000:
                value -= 0x10000
            set_int(reg, value)
            i += 2
            continue
        if op == 0x14 and i + 2 < insns_size:  # const
            reg = (word >> 8) & 0xFF
            value = insns[i + 1] | (insns[i + 2] << 16)
            if value & 0x80000000:
                value -= 0x100000000
            set_int(reg, value)
            i += 3
            continue
        if op == 0x15 and i + 1 < insns_size:  # const/high16
            reg = (word >> 8) & 0xFF
            value = insns[i + 1] << 16
            if value & 0x80000000:
                value -= 0x100000000
            set_int(reg, value)
            i += 2
            continue

        # Track simple register copies and index increments used by some iApp
        # compiler versions while filling the arrays.
        if op == 0x01:  # move vA, vB (12x)
            a = (word >> 8) & 0x0F
            b = (word >> 12) & 0x0F
            if b in int_regs:
                int_regs[a] = int_regs[b]
            else:
                int_regs.pop(a, None)
            pending_funcs.pop(a, None)
            i += 1
            continue
        if op == 0x02 and i + 1 < insns_size:  # move/from16
            a = (word >> 8) & 0xFF
            b = insns[i + 1]
            if b in int_regs:
                int_regs[a] = int_regs[b]
            else:
                int_regs.pop(a, None)
            pending_funcs.pop(a, None)
            i += 2
            continue
        if op == 0xD8 and i + 1 < insns_size:  # add-int/lit8, format 22b
            a = (word >> 8) & 0xFF
            second = insns[i + 1]
            b = second & 0xFF
            lit = (second >> 8) & 0xFF
            if lit & 0x80:
                lit -= 0x100
            if b in int_regs:
                int_regs[a] = int_regs[b] + lit
            else:
                int_regs.pop(a, None)
            pending_funcs.pop(a, None)
            i += 2
            continue

        if op == 0x1A and i + 1 < insns_size:  # const-string
            reg = (word >> 8) & 0xFF
            idx = insns[i + 1]
            pending_funcs.pop(reg, None)
            if 0 <= idx < len(strings):
                fn = _normalize_iapp_func_string(strings[idx])
                if fn is not None:
                    pending_funcs[reg] = fn
            i += 2
            continue
        if op == 0x1B and i + 2 < insns_size:  # const-string/jumbo
            reg = (word >> 8) & 0xFF
            idx = insns[i + 1] | (insns[i + 2] << 16)
            pending_funcs.pop(reg, None)
            if 0 <= idx < len(strings):
                fn = _normalize_iapp_func_string(strings[idx])
                if fn is not None:
                    pending_funcs[reg] = fn
            i += 3
            continue

        if op == 0x4D and i + 1 < insns_size:  # aput-object, format 23x
            value_reg = (word >> 8) & 0xFF
            second = insns[i + 1]
            index_reg = (second >> 8) & 0xFF
            index_value = int_regs.get(index_reg)
            if index_value is not None and 0 <= index_value < 4096:
                if value_reg in pending_funcs:
                    funcs_by_index.setdefault(index_value, pending_funcs.pop(value_reg))
                elif last_large is not None and large_age <= 16:
                    nums_by_index.setdefault(index_value, last_large)
                    last_large = None
                    large_age = 10 ** 9
            i += 2
            continue

        i += _dex_instr_len_units(insns, i)

    common = sorted(set(funcs_by_index).intersection(nums_by_index))
    if len(common) < 20:
        return None
    funcs = [funcs_by_index[idx] for idx in common]
    nums = [nums_by_index[idx] for idx in common]
    profile = _numeric_table_profile(nums, funcs)
    if not profile.get("iapp_header"):
        return None
    return {
        "dex": dex_name,
        "class": class_name,
        "method": method_name,
        "funcs": funcs,
        "nums": nums,
        "pairs": len(common),
        "score": len(common) * 500 + (50000 if profile.get("dynamic") else 0),
        "preferred": 10,
        "code_units": insns_size,
        "exact": True,
        "indexed_method": True,
        "baseline_table": bool(profile.get("baseline")),
        "dynamic_table": bool(profile.get("dynamic")),
        "table_span": int(profile.get("span") or 0),
        "table_unique_ratio": float(profile.get("unique_ratio") or 0.0),
        "table_sequential_ratio": float(profile.get("sequential_ratio") or 0.0),
    }
# IAPT_NUMERIC_DYNAMIC_TABLE_V147_END

def _dex_scan_indexed_reflection_tables(dex_name: str, dex: bytes, strings: List[str]) -> List[Dict]:
    """
    Recover the real iApp dynamic-pack reflection table from DEX bytecode/data.

    The packed table is not simply two sequential lists.  Function names are
    commonly materialized with filled-new-array/range, while decimal call IDs are
    written into a String[] using aput-object with an explicit index register.
    Pairing by raw encounter order is wrong around Java/call/json entries.  This
    scanner reconstructs the numeric array by its aput-object index, then pairs
    array[index] -> function[index].
    """
    rows: List[Dict] = []
    n = len(dex)

    def read_const_string_at(off: int):
        if off + 4 <= n and dex[off] == 0x1A:
            idx = dex[off + 2] | (dex[off + 3] << 8)
            if 0 <= idx < len(strings):
                return 4, _normalize_iapp_func_string(strings[idx])
        if off + 6 <= n and dex[off] == 0x1B:
            idx = dex[off + 2] | (dex[off + 3] << 8) | (dex[off + 4] << 16) | (dex[off + 5] << 24)
            if 0 <= idx < len(strings):
                return 6, _normalize_iapp_func_string(strings[idx])
        return None

    def read_const_int_at(off: int):
        if off + 2 > n:
            return None
        w = struct.unpack_from('<H', dex, off)[0]
        op = w & 0xFF
        aa = (w >> 8) & 0xFF
        if op == 0x12:
            imm = (aa >> 4) & 0x0F
            if imm & 0x08:
                imm -= 0x10
            return 2, aa & 0x0F, imm
        if op == 0x13 and off + 4 <= n:
            return 4, aa, struct.unpack_from('<h', dex, off + 2)[0]
        if op == 0x14 and off + 6 <= n:
            return 6, aa, struct.unpack_from('<i', dex, off + 2)[0]
        if op == 0x15 and off + 4 <= n:
            val = struct.unpack_from('<h', dex, off + 2)[0] << 16
            return 4, aa, val
        return None

    def read_aput_object_at(off: int):
        if off + 4 > n:
            return None
        w = struct.unpack_from('<H', dex, off)[0]
        if (w & 0xFF) != 0x4D:  # aput-object, format 23x
            return None
        aa = (w >> 8) & 0xFF
        b2 = dex[off + 2]
        c2 = dex[off + 3]
        return aa, b2, c2  # value, array, index

    def next_const_string_opcode(pos: int) -> int:
        while True:
            i1 = dex.find(b"\x1a", pos)
            i2 = dex.find(b"\x1b", pos)
            if i1 < 0:
                i = i2
            elif i2 < 0:
                i = i1
            else:
                i = i1 if i1 < i2 else i2
            if i < 0:
                return -1
            # DEX code units are 16-bit aligned.  Odd hits are register/data
            # bytes from other instructions or raw payloads.
            if (i & 1) == 0:
                return i
            pos = i + 1

    i = next_const_string_opcode(0)
    seen: Set[int] = set()
    while 0 <= i < n - 8:
        got = read_const_string_at(i)
        if not got or got[1] is None:
            i = next_const_string_opcode(i + 1)
            continue
        start = i
        funcs: List[str] = []
        p = i
        while True:
            got = read_const_string_at(p)
            if not got or got[1] is None:
                break
            size, func = got
            funcs.append(func)
            p += size
        if len(funcs) < 20 or start in seen:
            i = next_const_string_opcode(max(i + 2, p))
            continue
        seen.add(start)

        # Scan the following bytecode/data window.  Track const values by
        # register; when an aput-object writes the generated string into the
        # numeric array, the third register is the real table index.  Pair that
        # index with the most recent large decimal ID constant.
        regs: Dict[int, int] = {}
        # Some index registers are initialized immediately before the large
        # filled-new-array/range function-name block and then reused while the
        # numeric String[] is populated.  Seed the register constants from a
        # small prelude window so aput-object v?,vArray,v13/v14/... is decoded
        # with the real target index instead of being dropped.
        pre = max(0, start - 0x300)
        while pre < p:
            ci0 = read_const_int_at(pre)
            if ci0:
                size0, reg0, val0 = ci0
                regs[reg0] = val0
                pre += size0
            else:
                pre += 2
        by_index: Dict[int, int] = {}
        last_large: Optional[int] = None
        q = p
        scan_end = min(n, p + 0x30000)
        while q + 2 <= scan_end and len(by_index) < len(funcs):
            ci = read_const_int_at(q)
            if ci:
                size, reg, val = ci
                regs[reg] = val
                av = abs(val)
                if 10000 <= av <= 999999999999:
                    last_large = av
                q += size
                continue
            ap = read_aput_object_at(q)
            if ap:
                _vreg, _areg, ireg = ap
                idx = regs.get(ireg)
                if idx is not None and 0 <= idx < len(funcs) and last_large is not None:
                    by_index.setdefault(idx, last_large)
                    last_large = None
                q += 4
                continue
            q += 2

        if len(by_index) >= max(20, int(len(funcs) * 0.75)):
            nums: List[Optional[int]] = [by_index.get(j) for j in range(len(funcs))]
            pairs = [(num, func) for num, func in zip(nums, funcs) if num is not None]
            native_hits = sum(1 for _num, f in pairs if f in {"f", "for", "tw", "fd", "fs", "fr", "fw", "fl", "java", "javax", "cls", "call", "json", "uigo", "loadjar"})
            score = len(pairs) * 120 + native_hits * 80 - (len(funcs) - len(pairs)) * 10
            rows.append({
                "dex": dex_name,
                "class": "<dex-indexed-reflection-table>",
                "method": f"indexed@0x{start:x}",
                "funcs": [func for _num, func in pairs],
                "nums": [num for num, _func in pairs],
                "pairs": len(pairs),
                "score": score,
                "preferred": 4,
                "code_units": (q - start) // 2,
                "exact": True,
            })
        i = next_const_string_opcode(max(i + 2, p))
    return rows

def _dex_scan_raw_native_func_tables(dex_name: str, dex: bytes, strings: List[str]) -> List[Dict]:
    """
    Recover dynamic-pack native-call restore tables even when the bytecode table
    lives in raw payload/code bytes that are not reachable through class_defs.

    Pattern observed in iApp dynamic packers:
      const-string v?, "f("
      const-string v?, "for("
      ...
      const v?, 0x23b93      # decimal call id seen in decrypted source
      const v?, 0x23c00
      ...

    The string block and numeric block are ordered arrays; pairing by order maps
    decimal-id -> original native iApp function name.
    """
    rows: List[Dict] = []
    n = len(dex)

    def read_const_string_at(off: int):
        if off + 4 <= n and dex[off] == 0x1A:  # const-string, format 21c
            idx = dex[off + 2] | (dex[off + 3] << 8)
            if 0 <= idx < len(strings):
                return 4, _normalize_iapp_func_string(strings[idx])
        if off + 6 <= n and dex[off] == 0x1B:  # const-string/jumbo, format 31c
            idx = dex[off + 2] | (dex[off + 3] << 8) | (dex[off + 4] << 16) | (dex[off + 5] << 24)
            if 0 <= idx < len(strings):
                return 6, _normalize_iapp_func_string(strings[idx])
        return None

    # Find dense const-string blocks.  In normal DEX code each const-string is 2
    # code units (4 bytes).  A jumbo entry is rare but supported.
    i = 0
    seen_starts: Set[int] = set()
    while i < n - 4:
        got = read_const_string_at(i)
        if not got or got[1] is None:
            i += 2
            continue
        start = i
        funcs: List[str] = []
        p = i
        while True:
            got = read_const_string_at(p)
            if not got or got[1] is None:
                break
            size, func = got
            funcs.append(func)
            p += size
        if len(funcs) < 20 or start in seen_starts:
            i = max(i + 2, p)
            continue
        seen_starts.add(start)

        # The matching number block normally begins shortly after the string
        # array.  Collect const/32 values (opcode 0x14, any destination register)
        # from a bounded following window.  Do not require register == v12: the
        # first item in this sample uses v22.
        scan_start = p
        scan_end = min(n, p + 0x10000)
        nums: List[int] = []
        q = scan_start
        while q + 6 <= scan_end and len(nums) < len(funcs) + 16:
            if dex[q] == 0x14:
                val = struct.unpack_from("<i", dex, q + 2)[0]
                av = abs(val)
                # Dynamic native IDs are decimalized small int constants.  Keep
                # a broad range for other packers, but avoid array indexes/sizes.
                if 10000 <= av <= 999999999999:
                    nums.append(av)
                    q += 6
                    continue
            q += 2
        native_hits = sum(1 for f in funcs if f in {"f", "for", "tw", "fd", "fs", "fr", "fw", "fl", "java", "javax", "cls", "call", "json", "uigo"})
        if len(nums) >= max(20, int(len(funcs) * 0.80)):
            pair_count = min(len(funcs), len(nums))
            # Prefer tables with balanced lengths and many native built-in names.
            score = pair_count * 100 + native_hits * 50 - abs(len(funcs) - len(nums)) * 20
            rows.append({
                "dex": dex_name,
                "class": "<raw-dex-native-table>",
                "method": f"raw@0x{start:x}",
                "funcs": funcs,
                "nums": nums[:pair_count],
                "pairs": pair_count,
                "score": score,
                "preferred": 2,
                "code_units": (q - start) // 2,
            })
        elif len(funcs) >= 20:
            rows.append({
                "dex": dex_name,
                "class": "<raw-dex-native-func-order>",
                "method": f"raw-funcs@0x{start:x}",
                "funcs": funcs,
                "nums": [],
                "pairs": len(funcs),
                "score": len(funcs) * 50 + native_hits * 50,
                "preferred": 1,
                "code_units": (q - start) // 2,
                "enum_source": True,
            })
        i = max(i + 2, p)
    return rows

def _dex_restore_candidates_from_blob(dex_name: str, dex: bytes) -> List[Dict]:
    try:
        strings, hdr = dex_read_strings(dex)
    except Exception:
        return []
    try:
        type_ids = [struct.unpack_from("<I", dex, hdr["type_ids_off"] + i * 4)[0] for i in range(hdr["type_ids_size"])]
        method_ids = [struct.unpack_from("<HHI", dex, hdr["method_ids_off"] + i * 8) for i in range(hdr["method_ids_size"])]
    except Exception:
        return []

    rows: List[Dict] = []
    # First, scan raw DEX bytes for the dynamic-pack native function table.
    # This catches tables that are visible in smali but not cleanly reachable
    # through class_defs/code_off in some packed builds.
    rows.extend(_dex_scan_indexed_reflection_tables(dex_name, dex, strings))
    rows.extend(_dex_scan_raw_native_func_tables(dex_name, dex, strings))

    for class_def_index in range(hdr["class_defs_size"]):
        off = hdr["class_defs_off"] + class_def_index * 32
        try:
            class_idx, _access_flags, _super_idx, _interfaces_off, _source_idx, _ann_off, class_data_off, _static_values_off = struct.unpack_from("<IIIIIIII", dex, off)
            class_name = strings[type_ids[class_idx]]
        except Exception:
            continue
        if class_data_off == 0:
            continue
        try:
            p = class_data_off
            static_fields_size, p = dex_uleb(dex, p)
            instance_fields_size, p = dex_uleb(dex, p)
            direct_methods_size, p = dex_uleb(dex, p)
            virtual_methods_size, p = dex_uleb(dex, p)
            for _ in range(static_fields_size + instance_fields_size):
                _, p = dex_uleb(dex, p)
                _, p = dex_uleb(dex, p)
            last_method_index = 0
            class_funcs: List[str] = []
            class_nums: List[int] = []
            class_code_units = 0
            for _ in range(direct_methods_size + virtual_methods_size):
                method_idx_diff, p = dex_uleb(dex, p)
                _access_flags, p = dex_uleb(dex, p)
                code_off, p = dex_uleb(dex, p)
                last_method_index += method_idx_diff
                if code_off == 0 or not (0 <= last_method_index < len(method_ids)):
                    continue
                _class_idx_m, _proto_idx_m, name_idx_m = method_ids[last_method_index]
                method_name = strings[name_idx_m] if 0 <= name_idx_m < len(strings) else f"method_{last_method_index}"
                indexed_row = _dex_scan_indexed_method_numeric_table(
                    dex_name, dex, code_off, strings, class_name, method_name
                )
                if indexed_row is not None:
                    rows.append(indexed_row)
                funcs, nums, units = _dex_scan_code_literals(dex, code_off, strings)
                class_code_units += units
                class_funcs.extend(funcs)
                class_nums.extend(nums)
                preferred = 1 if class_name in ("Lc/b/a/a/w;", "Lc/b/a/a/v;", "Lc/b/a/a/t;") else 0
                if funcs and nums:
                    n = min(len(funcs), len(nums))
                    closeness = abs(len(funcs) - len(nums))
                    score = n * 10 - closeness + preferred * 5000
                    if n >= 5:
                        rows.append({
                            "dex": dex_name, "class": class_name, "method": method_name,
                            "funcs": funcs, "nums": nums, "pairs": n, "score": score,
                            "preferred": preferred, "code_units": units,
                        })
                elif funcs and len(funcs) >= 8:
                    rows.append({
                        "dex": dex_name, "class": class_name, "method": method_name,
                        "funcs": funcs, "nums": [], "pairs": len(funcs),
                        "score": len(funcs) * 8 + preferred * 5000,
                        "preferred": preferred, "code_units": units,
                        "enum_source": True,
                    })
            preferred = 1 if class_name in ("Lc/b/a/a/w;", "Lc/b/a/a/v;", "Lc/b/a/a/t;") else 0
            if class_funcs and class_nums:
                n = min(len(class_funcs), len(class_nums))
                closeness = abs(len(class_funcs) - len(class_nums))
                score = n * 10 - closeness + preferred * 5000 + min(class_code_units, 5000) // 20
                if n >= 8:
                    rows.append({
                        "dex": dex_name, "class": class_name, "method": "<class-merged>",
                        "funcs": class_funcs, "nums": class_nums, "pairs": n, "score": score,
                        "preferred": preferred, "code_units": class_code_units,
                    })
            elif class_funcs and len(class_funcs) >= 8:
                rows.append({
                    "dex": dex_name, "class": class_name, "method": "<class-merged-func-order>",
                    "funcs": class_funcs, "nums": [], "pairs": len(class_funcs),
                    "score": len(class_funcs) * 8 + preferred * 5000 + min(class_code_units, 5000) // 20,
                    "preferred": preferred, "code_units": class_code_units,
                    "enum_source": True,
                })
        except Exception:
            continue
    rows.sort(key=lambda r: (r["preferred"], r["score"], r["pairs"], r["code_units"]), reverse=True)
    return rows



def _dex_enum_candidates_from_func_order(
    candidates: List[Dict],
    needed_numeric: Optional[Set[str]],
    enum_start: int = 1000000,
    enum_limit: int = 20000,
) -> List[Dict]:
    """Build explicit DEX-enumeration restore candidates.

    Some dynamic iApp packs keep the native function-name order in DEX but do
    not keep the generated decimal IDs as constants. In those samples the
    decrypted source may call 1000000(...), 1000001(...), ... in the same order
    as the DEX function table. This helper is enabled only by --dex-enum.
    """
    enum_start = int(enum_start)
    enum_limit = max(1, int(enum_limit or 1))
    needed_numeric = needed_numeric or set()
    needed_ints: Set[int] = set()
    for x in needed_numeric:
        try:
            needed_ints.add(int(str(x)))
        except Exception:
            pass
    out: List[Dict] = []
    seen: Set[Tuple[str, str, str, Tuple[str, ...]]] = set()
    native_names = {"f", "for", "tw", "fd", "fs", "fr", "fw", "fl", "java", "javax", "cls", "call", "json", "uigo", "loadjar"}
    for cand in candidates:
        funcs0 = [str(x) for x in cand.get("funcs", []) if str(x)]
        if len(funcs0) < 5:
            continue
        funcs = funcs0[:enum_limit]
        key = (str(cand.get("dex", "")), str(cand.get("class", "")), str(cand.get("method", "")), tuple(funcs[:256]))
        if key in seen:
            continue
        seen.add(key)
        nums = [enum_start + i for i in range(len(funcs))]
        if needed_ints:
            lo, hi = enum_start, enum_start + len(funcs) - 1
            hits = sum(1 for v in needed_ints if lo <= v <= hi)
            if hits <= 0:
                continue
            exact = all(lo <= v <= hi for v in needed_ints)
        else:
            hits = len(funcs)
            exact = False
        native_hits = sum(1 for f in funcs if f in native_names)
        base_score = int(cand.get("score", 0) or 0)
        enum_score = base_score + len(funcs) * 80 + native_hits * 120 + hits * 10000
        cc = dict(cand)
        cc.update({
            "nums": nums,
            "funcs": funcs,
            "pairs": len(funcs),
            "score": enum_score,
            "preferred": int(cand.get("preferred", 0) or 0) + 3,
            "exact": exact,
            "dex_enum": True,
            "enum_start": enum_start,
            "method": f"{cand.get('method', '')}:enum@{enum_start}",
        })
        out.append(cc)
    out.sort(key=lambda r: (bool(r.get("exact")), int(r.get("score", 0) or 0), int(r.get("pairs", 0) or 0)), reverse=True)
    return out



def _dex_enum_worker_task(payload: Tuple[List[int], List[Dict], Tuple[str, ...], int]) -> List[Dict]:
    starts, candidates, needed_tuple, enum_limit = payload
    needed = set(needed_tuple)
    out: List[Dict] = []
    for st in starts:
        try:
            out.extend(_dex_enum_candidates_from_func_order(candidates, needed, int(st), int(enum_limit)))
        except Exception:
            continue
    return out


def _dex_enum_candidates_from_func_order_parallel(
    candidates: List[Dict],
    needed_numeric: Optional[Set[str]],
    enum_start: int = 1000000,
    enum_limit: int = 20000,
    enum_windows: int = 1,
    enum_workers: int = 1,
) -> List[Dict]:
    """Parallel DEX numeric-start enumeration.

    The normal single-window mode is identical to v47.  When enum_windows > 1,
    starts are split as start + window * limit, and each worker scores a segment.
    This is useful for samples where the decimal start is near 1000000 but not
    exactly known, without serially rebuilding every candidate window.
    """
    enum_windows = max(1, int(enum_windows or 1))
    enum_workers = max(1, int(enum_workers or 1))
    enum_start = int(enum_start)
    enum_limit = max(1, int(enum_limit or 1))
    if enum_windows <= 1 or enum_workers <= 1:
        return _dex_enum_candidates_from_func_order(candidates, needed_numeric, enum_start, enum_limit)
    starts = [enum_start + i * enum_limit for i in range(enum_windows)]
    worker_count = min(enum_workers, len(starts), max(1, os.cpu_count() or 1))
    # Round-robin start segments keep work balanced when some starts produce no
    # needed-number hits and return quickly.
    chunks: List[List[int]] = [[] for _ in range(worker_count)]
    for i, st in enumerate(starts):
        chunks[i % worker_count].append(st)
    payloads = [(chunk, candidates, tuple(sorted(needed_numeric or set())), enum_limit) for chunk in chunks if chunk]
    out: List[Dict] = []
    with ProcessPoolExecutor(max_workers=worker_count) as ex:
        for fut in as_completed([ex.submit(_dex_enum_worker_task, payload) for payload in payloads]):
            out.extend(fut.result())
    out.sort(key=lambda r: (bool(r.get("exact")), int(r.get("score", 0) or 0), int(r.get("pairs", 0) or 0)), reverse=True)
    return out


def _select_best_restore_candidate(candidates: List[Dict], needed_numeric: Optional[Set[str]] = None) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Select DEX restore table by current DEX exact/enum mapping first.

    This avoids the old behavior where a heuristic fallback with many apparent
    pairs could beat the real current-sample DEX table.  When --dex-enum is on,
    exact enum candidates are preferred and filtered to IDs found in current
    source, so restore comes from the uploaded APK's classes*.dex only.
    """
    needed_numeric = set(needed_numeric or set())

    def make_map(cand: Dict) -> Dict[str, str]:
        nums0 = list(cand.get("nums", []) or [])
        funcs0 = list(cand.get("funcs", []) or [])
        profile = _numeric_table_profile(nums0, funcs0)
        cand["baseline_table"] = bool(cand.get("baseline_table") or profile.get("baseline"))
        cand["dynamic_table"] = bool(cand.get("dynamic_table") or profile.get("dynamic"))
        cand["table_span"] = int(cand.get("table_span") or profile.get("span") or 0)
        # Every normal iApp runtime includes 145001 -> f, 145002 -> for, ... .
        # It is a compatibility dispatch table, not an obfuscation map.
        if cand.get("baseline_table"):
            return {}
        # Reject class-merged/junk constant collections.  A usable dynamic table
        # must be a compact non-sequential iApp command table.
        if not cand.get("dynamic_table"):
            return {}
        local: Dict[str, str] = {}
        ambiguous: Set[str] = set()
        for num, func in zip(nums0, funcs0):
            try:
                key = str(abs(int(num)))
            except Exception:
                continue
            val = str(func or "").strip()
            if not key or not val:
                continue
            if needed_numeric and key not in needed_numeric:
                continue
            old = local.get(key)
            if old is not None and old != val:
                ambiguous.add(key)
                continue
            local.setdefault(key, val)
        for key in ambiguous:
            local.pop(key, None)
        return local

    def score(cand: Dict, local: Dict[str, str]):
        hits = len(local)
        indexed_bonus = 1 if cand.get("indexed_method") else 0
        exact_bonus = 1 if cand.get("exact") else 0
        enum_bonus = 1 if cand.get("dex_enum") else 0
        preferred = int(cand.get("preferred", 0) or 0)
        base = int(cand.get("score", 0) or 0)
        # Explicit aput index pairing is authoritative.  It must beat raw
        # encounter-order tables even when both cover the same source IDs.
        return (indexed_bonus, exact_bonus, enum_bonus, hits, preferred, base)

    best = None
    best_local: Dict[str, str] = {}
    for cand in candidates:
        local = make_map(cand)
        if not local:
            continue
        if best is None or score(cand, local) > score(best, best_local):
            best = cand
            best_local = local

    if not best:
        return {}, {"reason": "no current-DEX numeric table matched", "candidate_count": str(len(candidates)), "needed_count": str(len(needed_numeric))}

    meta = {
        "dex": str(best.get("dex", "")),
        "class": str(best.get("class", "")),
        "method": str(best.get("method", "")),
        "pairs": str(len(best_local)),
        "hit_count": str(len(best_local)),
        "needed_count": str(len(needed_numeric)),
        "candidate_count": str(len(candidates)),
        "table_score": str(int(best.get("score", 0) or 0)),
        "exact": "1" if best.get("exact") else "0",
        "dex_enum": "1" if best.get("dex_enum") else "0",
        "direct_dex_enum": "1",
        "indexed_method": "1" if best.get("indexed_method") else "0",
        "dynamic_table": "1" if best.get("dynamic_table") else "0",
        "baseline_table": "1" if best.get("baseline_table") else "0",
        "table_span": str(int(best.get("table_span", 0) or 0)),
    }
    return best_local, meta

def extract_numeric_function_restore_map_from_apk(
    apk_path: Optional[Path],
    needed_numeric: Optional[Set[str]] = None,
    primary_dex: Optional[bytes] = None,
    dex_enum: bool = False,
    dex_enum_start: int = 1000000,
    dex_enum_limit: int = 20000,
    dex_enum_windows: int = 1,
    enum_workers: int = 1,
) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Build decimal-id -> original-function-name mapping from APK DEX code tables.

    v30 fast path: first scan only indexed DEX reflection tables and stop early
    when an exact table covers the numeric IDs observed in the decrypted source.
    The slower raw/code-literal fallback is used only when that authoritative
    indexed table is not found.
    """
    if not apk_path:
        return {}, {"reason": "no apk path"}
    needed_numeric = needed_numeric or set()
    indexed_candidates: List[Dict] = []
    scanned_dex_blobs: List[Tuple[str, bytes]] = []
    early_threshold = 1
    if needed_numeric:
        early_threshold = len(needed_numeric)

    for dex_name, dex in iter_apk_dex_blobs(apk_path, primary_dex):
        scanned_dex_blobs.append((dex_name, dex))
        try:
            strings, _hdr = dex_read_strings(dex)
        except Exception:
            continue
        rows = _dex_scan_indexed_reflection_tables(dex_name, dex, strings)
        indexed_candidates.extend(rows)
        best_map, best_meta = _select_best_restore_candidate(indexed_candidates, needed_numeric)
        if best_map and best_meta.get("exact") == "1" and int(best_meta.get("hit_count", "0")) >= early_threshold:
            best_meta["candidate_count"] = str(len(indexed_candidates))
            best_meta["fast_path"] = "indexed-early"
            return best_map, best_meta

    # If indexed tables exist but do not cover many current-source IDs, keep the
    # best one as a candidate but run the broad fallback for older packers.
    candidates: List[Dict] = list(indexed_candidates)
    # Reuse blobs already inflated during the indexed pass, then lazily include
    # any remaining secondary DEX files only if the fast indexed path failed.
    seen_dex_names = {name for name, _dex in scanned_dex_blobs}
    for dex_name, dex in scanned_dex_blobs:
        candidates.extend(_dex_restore_candidates_from_blob(dex_name, dex))
    for dex_name, dex in iter_apk_dex_blobs(apk_path, primary_dex):
        if dex_name in seen_dex_names:
            continue
        candidates.extend(_dex_restore_candidates_from_blob(dex_name, dex))
    if dex_enum:
        t_enum_build = time.perf_counter()
        enum_candidates = _dex_enum_candidates_from_func_order_parallel(candidates, needed_numeric, dex_enum_start, dex_enum_limit, dex_enum_windows, enum_workers)
        if enum_candidates:
            print(f"[T] fn-restore dex enum   {ms_since(t_enum_build):.3f} ms start={int(dex_enum_start)} limit={int(dex_enum_limit)} windows={int(dex_enum_windows)} workers={int(enum_workers)} candidates={len(enum_candidates)}")
            candidates.extend(enum_candidates)
        else:
            print(f"[T] fn-restore dex enum   {ms_since(t_enum_build):.3f} ms start={int(dex_enum_start)} limit={int(dex_enum_limit)} windows={int(dex_enum_windows)} workers={int(enum_workers)} candidates=0")
    if not candidates:
        return {}, {"reason": "no dex restore candidates"}

    best_map, best_meta = _select_best_restore_candidate(candidates, needed_numeric)
    if not best_map:
        return {}, {"reason": "candidate tables produced no pairs", "candidate_count": str(len(candidates))}
    best_meta["candidate_count"] = str(len(candidates))
    best_meta.setdefault("fast_path", "fallback")
    return best_map, best_meta

def _iter_source_files(outdir: Path) -> List[Path]:
    if not outdir.exists():
        return []
    files: List[Path] = []
    for p in outdir.iterdir():
        if p.is_file() and p.suffix.lower().lstrip(".") in SOURCE_EXTS:
            files.append(p)
    files.sort(key=lambda x: x.name)
    return files


def analyze_numeric_function_obfuscation(outdir: Path) -> Dict[str, int]:
    numeric_defs = normal_defs = numeric_calls = 0
    files_with_numeric = 0
    needed: Set[str] = set()
    for p in _iter_source_files(outdir):
        try:
            text = p.read_text("utf-8", "ignore")
        except Exception:
            continue
        nd = NUMERIC_FN_DEF_RE.findall(text)
        nc = NUMERIC_FN_CALL_RE.findall(text)
        nf = NORMAL_FN_DEF_RE.findall(text)
        if nd or nc:
            files_with_numeric += 1
        numeric_defs += len(nd)
        numeric_calls += len(nc)
        normal_defs += len(nf)
        needed.update(nd)
        needed.update(nc)
    return {
        "numeric_defs": numeric_defs,
        "numeric_calls": numeric_calls,
        "normal_defs": normal_defs,
        "files_with_numeric": files_with_numeric,
        "needed_count": len(needed),
    }



def _split_iapp_call_args(arg_text: str) -> List[str]:
    """Small comma splitter for one-line iApp calls; ignores commas in strings."""
    args: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    esc = False
    depth = 0
    for ch in arg_text:
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            cur.append(ch)
            continue
        if ch in "([{" :
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == ',' and depth == 0:
            args.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur or arg_text.strip():
        args.append(''.join(cur).strip())
    return args


def _strip_iapp_quote(x: str) -> str:
    x = x.strip()
    if len(x) >= 2 and x[0] == x[-1] and x[0] in ('"', "'"):
        return x[1:-1]
    return x


def infer_native_restore_overrides_from_sources(source_files: List[Path]) -> Dict[str, str]:
    """
    Use un-restored decrypted source syntax to correct high-confidence native
    numeric-call mappings.  This handles dynamic-pack tables whose raw DEX array
    contains extra/missing helper entries around Java/call commands.
    """
    votes: Dict[str, Dict[str, int]] = {}

    def vote(num: str, name: str, weight: int = 1):
        votes.setdefault(num, {})[name] = votes.setdefault(num, {}).get(name, 0) + weight

    ui_props = {
        'text', 'background', 'visibility', 'src', 'dh', 'width', 'height', 'title',
        'textColor', 'textSize', 'enabled', 'checked', 'hint', 'gravity', 'rotation',
        'alpha', 'x', 'y', 'padding', 'layout_margin', 'layout_width', 'layout_height',
    }
    lang_set = {'myu', 'iyu', 'mlua', 'mjs', 'mjava', 'ijava', 'ilua', 'ijs'}
    call_line_re = re.compile(r'(?m)(?<![A-Za-z0-9_.$])([1-9]\d{3,11})\s*\(([^\n{}]*)\)')

    for p in source_files:
        try:
            text = p.read_text('utf-8', 'ignore')
        except Exception:
            continue
        for m in call_line_re.finditer(text):
            num = m.group(1)
            arg_text = m.group(2).strip()
            args = _split_iapp_call_args(arg_text)
            args_u = [_strip_iapp_quote(a) for a in args]
            tail = text[m.end():m.end()+8]

            # for(...) IDs are usually recovered reliably from the DEX table.
            # Do not infer for from raw semicolons because iApp strings may also
            # contain semicolons and that caused false overrides.
            if tail.lstrip().startswith('{'):
                if not arg_text:
                    vote(num, 't', 8)
                elif re.search(r'(==|!=|>=|<=|>|<|\?\*|\?\(|\?")', arg_text):
                    vote(num, 'f', 20)

            if len(args_u) >= 3 and args_u[1].lower() in lang_set and '.' in args_u[2]:
                vote(num, 'call', 50)
                continue
            # json(json_text, out_obj) / json(obj, "get", "key", out).
            # The raw DEX table for some dynamic-pack builds is shifted around
            # call/json/utb, so prefer source syntax here.
            if (
                len(args_u) == 2
                and not args[1].strip().startswith(('"', "'"))
                and args_u[1].lower() not in {'true', 'false', 'null'}
                and not re.fullmatch(r'-?\d+(?:\.\d+)?', args_u[1])
                and args_u[0].lower() not in {'true', 'false', 'null'}
                and not re.fullmatch(r'-?\d+(?:\.\d+)?', args_u[0])
                and not args_u[0].startswith('#')
            ):
                vote(num, 'json', 35)
                continue
            if len(args_u) >= 4 and args[1].strip().startswith(('"', "'")) and args_u[1].lower() in {'get', 'set', 'del', 'remove', 'has', 'len', 'length', 'size'}:
                vote(num, 'json', 60)
                continue
            if len(args_u) == 2 and re.search(r'\.(?:dex|jar)$', args_u[0], re.I):
                vote(num, 'loadjar', 50)
                continue
            if len(args_u) == 3 and re.search(r'(?:dex|jar)', args_u[0], re.I) and re.match(r'^(?:[A-Za-z_$][\w$]*\.)+[A-Za-z_$][\w$]*$', args_u[1]):
                vote(num, 'cls', 50)
                continue
            if len(args_u) >= 4 and args[3].strip().startswith(('"', "'")):
                # javax(out, class/object, target, "method", "Type", value, ...)
                vote(num, 'javax', 30)
                continue
            if len(args_u) == 3 and args[2].strip().startswith(('"', "'")) and '.' in args_u[2]:
                # java(out, object, "class.method")
                vote(num, 'java', 30)
                continue
            if len(args_u) == 3 and args[1].strip().startswith(('"', "'")) and args_u[1] in ui_props:
                vote(num, 'us', 12)
                continue

    out: Dict[str, str] = {}
    for num, vv in votes.items():
        name, score = max(vv.items(), key=lambda kv: kv[1])
        if score >= 12:
            out[num] = name
    return out



def find_suspicious_native_restore_ids(source_files: List[Path], restore_map: Dict[str, str]) -> Set[str]:
    """
    Disable replacements whose recovered native name is syntactically unlikely.

    This is intentionally conservative: it does not try to guess an unknown name.
    It only prevents obviously bad output such as ushsp("#fff", true) when the
    recovered DEX table says ushsp but the argument shape does not match the
    standard one-boolean orientation command.
    """
    bad: Set[str] = set()
    call_line_re = re.compile(r'(?m)(?<![A-Za-z0-9_.$])([1-9]\d{3,11})\s*\(([^\n{}]*)\)')
    for p in source_files:
        try:
            text = p.read_text('utf-8', 'ignore')
        except Exception:
            continue
        for m in call_line_re.finditer(text):
            num = m.group(1)
            name = restore_map.get(num)
            if not name:
                continue
            args = _split_iapp_call_args(m.group(2).strip())
            args_u = [_strip_iapp_quote(a) for a in args]
            if name == 'ushsp':
                # Known safe shape: ushsp(true/false).  Color+boolean belongs to
                # another UI/system-bar command in dynamic pack output, so do not
                # rewrite it based only on the raw table.
                if not (len(args_u) == 1 and args_u[0].lower() in {'true', 'false'}):
                    bad.add(num)
            elif name == 'utb':
                # JSON object parsing/extraction shape must not be rendered as utb.
                if len(args_u) == 2 or (len(args_u) >= 4 and args_u[1].lower() in {'get', 'set', 'del', 'remove', 'has', 'len', 'length', 'size'}):
                    bad.add(num)
    return bad

def _collect_numeric_restore_source_state(
    outdir: Path,
    member_sources: Optional[Dict[str, bytes]] = None,
) -> Tuple[Dict[str, int], List[Tuple[Path, bytes]], Set[str]]:
    """Read decrypted source files once and collect numeric-call restore inputs.

    v38 keeps source bodies as bytes.  That avoids utf-8 decode/encode for the
    hot restore path and lets the apply phase write restored bytes directly.
    """
    numeric_defs = normal_defs = numeric_calls = 0
    files_with_numeric = 0
    needed: Set[str] = set()
    source_datas: List[Tuple[Path, bytes]] = []
    seen_names: Set[str] = set()
    if member_sources:
        for name, data in sorted(member_sources.items(), key=lambda kv: safe_out_name(kv[0])):
            out_name = safe_out_name(name)
            if Path(out_name).suffix.lower().lstrip(".") not in SOURCE_EXTS:
                continue
            p = outdir / out_name
            source_datas.append((p, bytes(data)))
            seen_names.add(p.name)
    for p in _iter_source_files(outdir):
        if p.name in seen_names:
            continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        source_datas.append((p, data))

    apply_datas: List[Tuple[Path, bytes]] = []
    for p, data in source_datas:
        has_fn = b"fn" in data
        has_paren = b"(" in data
        has_digit = any(48 <= b <= 57 for b in data)
        nd_b = NUMERIC_FN_DEF_BRE.findall(data) if (has_fn and has_digit and has_paren) else []
        nc_b = NUMERIC_FN_CALL_BRE.findall(data) if (has_digit and has_paren) else []
        # normal_defs is only needed for the auto gate.  On numeric-heavy iApp
        # projects the numeric-call signal is already far beyond the threshold,
        # so skip the broad normal-def regex unless numeric evidence is weak.
        nf_count = 0
        if has_fn and has_paren and (len(nc_b) < 80 and len(nd_b) < 10):
            nf_count = len(NORMAL_FN_DEF_BRE.findall(data))
        if nd_b or nc_b:
            files_with_numeric += 1
        if nc_b:
            apply_datas.append((p, data))
        numeric_defs += len(nd_b)
        numeric_calls += len(nc_b)
        normal_defs += nf_count
        for x in nd_b:
            try:
                needed.add(x.decode("ascii"))
            except Exception:
                pass
        for x in nc_b:
            try:
                needed.add(x.decode("ascii"))
            except Exception:
                pass
    return {
        "numeric_defs": numeric_defs,
        "numeric_calls": numeric_calls,
        "normal_defs": normal_defs,
        "files_with_numeric": files_with_numeric,
        "needed_count": len(needed),
    }, apply_datas, needed


def _mian_source_data_for_restore_gate(outdir: Path, member_sources: Optional[Dict[str, bytes]] = None) -> Optional[bytes]:
    """Return decrypted mian.iyu bytes for the cheap auto gate only."""
    if member_sources:
        for name, data in member_sources.items():
            if safe_out_name(name).replace('\\', '/') == MUST_HAVE_MAIN:
                return bytes(data)
    p = outdir / MUST_HAVE_MAIN
    try:
        if p.exists():
            return p.read_bytes()
    except Exception:
        pass
    return None


def _collect_numeric_restore_mian_gate(
    outdir: Path,
    member_sources: Optional[Dict[str, bytes]] = None,
) -> Tuple[Dict[str, int], Set[str]]:
    """Very cheap feature gate for --restore-fn-names auto.

    Auto mode only inspects decrypted mian.iyu.  It intentionally avoids a full
    project scan and avoids broad normal-function parsing.  The gate looks for
    decimal native bridge calls/defs plus small DEX/Java/native-loader hints in
    mian.iyu; if absent, DEX map recovery is skipped.
    """
    data = _mian_source_data_for_restore_gate(outdir, member_sources) or b""
    if not data or b"(" not in data:
        return {
            "numeric_defs": 0, "numeric_calls": 0, "normal_defs": 0,
            "files_with_numeric": 0, "needed_count": 0,
            "dex_signal": 0, "java_signal": 0, "native_signal": 0,
            "mian_bytes": len(data),
        }, set()

    # C first-stage gate only answers "definitely no" vs "maybe". If it says
    # maybe, Python still enumerates exact IDs with the existing regex so auto
    # behavior remains unchanged.
    c_maybe = _cfast_mian_gate_maybe(data)
    if c_maybe is False:
        return {
            "numeric_defs": 0, "numeric_calls": 0, "normal_defs": 0,
            "files_with_numeric": 0, "needed_count": 0,
            "dex_signal": 0, "java_signal": 0, "native_signal": 0,
            "mian_bytes": len(data),
        }, set()

    # One compiled bytes regex search is enough to reject normal samples; avoid
    # broad scans and only enumerate matches after the first numeric-call hit.
    first_call = NUMERIC_FN_CALL_BRE.search(data)
    if first_call is None:
        nd_b = NUMERIC_FN_DEF_BRE.findall(data) if b"fn" in data else []
        if not nd_b:
            return {
                "numeric_defs": 0, "numeric_calls": 0, "normal_defs": 0,
                "files_with_numeric": 0, "needed_count": 0,
                "dex_signal": 0, "java_signal": 0, "native_signal": 0,
                "mian_bytes": len(data),
            }, set()
        nc_b = []
    else:
        nd_b = NUMERIC_FN_DEF_BRE.findall(data) if b"fn" in data else []
        nc_b = [m.group(1) for m in NUMERIC_FN_CALL_BRE.finditer(data)]
    needed: Set[str] = set()
    for x in nd_b + nc_b:
        try:
            needed.add(x.decode("ascii"))
        except Exception:
            pass

    # Lightweight substring hints only; no DEX parsing and no full source scan.
    dex_signal = int(any(x in data for x in (b".dex", b"jardex", b"loadDex", b"DexClassLoader", b"dalvik.system")))
    java_signal = int(any(x in data for x in (b"android.", b"java.", b"ClassLoader", b"getMethod", b"invoke")))
    native_signal = int(any(x in data for x in (b"java", b"cls", b"javax", b"dex", b"zj", b"sj", b"loadjar")))
    return {
        "numeric_defs": len(nd_b),
        "numeric_calls": len(nc_b),
        "normal_defs": 0,
        "files_with_numeric": 1 if (nd_b or nc_b) else 0,
        "needed_count": len(needed),
        "dex_signal": dex_signal,
        "java_signal": java_signal,
        "native_signal": native_signal,
        "mian_bytes": len(data),
    }, needed

def maybe_restore_numeric_function_names(
    apk_path: Optional[Path],
    outdir: Path,
    mode: str = "auto",
    backup: bool = False,
    member_sources: Optional[Dict[str, bytes]] = None,
    primary_dex: Optional[bytes] = None,
    threads: int = 4,
    dex_enum: bool = False,
    dex_enum_start: int = 1000000,
    dex_enum_limit: int = 20000,
    dex_enum_windows: int = 1,
    enum_workers: int = 1,
) -> Dict[str, int]:
    """Optionally restore numeric iApp function names in decrypted source files.

    v30 reads source files once, uses the current APK DEX reflection table as the
    only mapping source, and skips backup writes by default for speed.  Use
    --restore-backup when you need original pre-restore files on disk.
    """
    mode = (mode or "off").lower()
    if mode == "off":
        print("[+] fn-restore    = off source-scan=skipped (normal decrypt default)")
        return {"numeric_defs": 0, "numeric_calls": 0, "normal_defs": 0, "files_with_numeric": 0, "needed_count": 0}
    if mode == "auto":
        t_gate = time.perf_counter()
        gate_stats, gate_needed = _collect_numeric_restore_mian_gate(outdir, member_sources)
        print(
            f"[T] fn-restore auto gate {ms_since(t_gate):.3f} ms scope=mian.iyu "
            f"needed={len(gate_needed)} numeric_defs={gate_stats['numeric_defs']} "
            f"numeric_calls={gate_stats['numeric_calls']} normal_defs={gate_stats['normal_defs']} "
            f"dex_signal={gate_stats['dex_signal']} java_signal={gate_stats['java_signal']} native_signal={gate_stats.get('native_signal', 0)}"
        )
        # Auto only triggers from mian.iyu.  Use a low call threshold only when
        # mian.iyu also shows DEX/Java bridge evidence; otherwise require a
        # stronger decimal-function footprint.
        should_restore = (
            gate_stats["numeric_defs"] >= 3
        ) or (
            gate_stats["numeric_calls"] >= 8 and (gate_stats["dex_signal"] or gate_stats["java_signal"] or gate_stats.get("native_signal", 0))
        ) or (
            gate_stats["numeric_calls"] >= 20
        )
        if not should_restore:
            print(
                f"[+] fn-restore    = auto skip scope=mian.iyu "
                f"numeric_defs={gate_stats['numeric_defs']} numeric_calls={gate_stats['numeric_calls']} "
                f"normal_defs={gate_stats['normal_defs']}"
            )
            return gate_stats
        print("[+] fn-restore    = auto enable: mian.iyu dynamic numeric bridge detected")

    t_collect = time.perf_counter()
    stats, source_texts, needed = _collect_numeric_restore_source_state(outdir, member_sources)
    print(f"[T] fn-restore source scan {ms_since(t_collect):.3f} ms files={len(source_texts)} needed={len(needed)}")
    if dex_enum:
        print(f"[+] fn-restore dex enum = on start={int(dex_enum_start)} limit={int(dex_enum_limit)} windows={int(dex_enum_windows)} workers={int(enum_workers)}")
    should_restore = True

    if not needed:
        print("[+] fn-restore    = skip: decrypted source contains no numeric command calls")
        stats.update({
            "restore_pairs": 0,
            "restore_replacements": 0,
            "restore_changed_files": 0,
            "dynamic_table_detected": 0,
        })
        return stats

    t_map = time.perf_counter()
    restore_map: Dict[str, str] = {}
    meta: Dict[str, str] = {}
    cache_path = outdir / ".tmp" / "numeric_fn_restore_cache.json"
    needed_hash_payload = "\n".join(sorted(needed)) + f"\n#dex_enum={int(bool(dex_enum))}:start={int(dex_enum_start)}:limit={int(dex_enum_limit)}:windows={int(dex_enum_windows)}"
    needed_hash = hashlib.sha256(needed_hash_payload.encode("utf-8")).hexdigest()
    apk_sig = ""
    try:
        if apk_path:
            st = Path(apk_path).stat()
            apk_sig = f"{Path(apk_path).name}:{st.st_size}:{st.st_mtime_ns}"
    except Exception:
        apk_sig = str(apk_path)
    cache_paths = [cache_path]
    try:
        shared_path = shared_restore_cache_path(apk_sig, needed_hash)
        if shared_path != cache_path:
            cache_paths.append(shared_path)
    except Exception:
        shared_path = None
    try:
        for cp in cache_paths:
            if not cp.exists():
                continue
            obj = json.loads(cp.read_text(encoding="utf-8"))
            if obj.get("build") == FN_RESTORE_CACHE_BUILD and obj.get("apk") == apk_sig and obj.get("needed_hash") == needed_hash:
                restore_map = {str(k): str(v) for k, v in obj.get("map", {}).items()}
                meta = {str(k): str(v) for k, v in obj.get("meta", {}).items()}
                meta["cache"] = "hit"
                meta["cache_path"] = str(cp)
                break
    except Exception as e:
        print(f"[!] fn-restore cache ignored: {type(e).__name__}: {e}")
    if restore_map:
        print(f"[T] fn-restore dex map     {ms_since(t_map):.3f} ms cache=hit")
    else:
        restore_map, meta = extract_numeric_function_restore_map_from_apk(
            apk_path, needed, primary_dex=primary_dex,
            dex_enum=bool(dex_enum), dex_enum_start=int(dex_enum_start), dex_enum_limit=int(dex_enum_limit),
            dex_enum_windows=int(dex_enum_windows), enum_workers=int(enum_workers),
        )
        print(f"[T] fn-restore dex map     {ms_since(t_map):.3f} ms cache=miss")
        for cp in cache_paths:
            try:
                cp.parent.mkdir(parents=True, exist_ok=True)
                cp.write_text(json.dumps({"build": FN_RESTORE_CACHE_BUILD, "apk": apk_sig, "needed_hash": needed_hash, "map": restore_map, "meta": meta}, ensure_ascii=False, sort_keys=True), encoding="utf-8")
            except Exception as e:
                print(f"[!] fn-restore cache save failed: {type(e).__name__}: {e}")
    if not restore_map:
        print(f"[!] fn-restore    = no map found ({meta.get('reason', 'unknown')})")
        return stats

    try:
        print(f"[+] fn-restore direct-dex-enum map: hits={len(restore_map)}/{len(needed)} exact={meta.get('exact')} enum={meta.get('dex_enum')} dex={meta.get('dex')}")
    except Exception:
        pass
    print("[+] fn-restore source-infer: disabled; using dynamic DEX reflection table only")

    outdir.mkdir(parents=True, exist_ok=True)
    map_path = outdir / "numeric_fn_restore_map.txt"
    t_map_write = time.perf_counter()
    with map_path.open("w", encoding="utf-8") as f:
        f.write("# decimal_id -> original_function\n")
        for k in sorted(restore_map, key=lambda x: int(x) if x.isdigit() else x):
            f.write(f"{k} -> {restore_map[k]}\n")
    print(f"[T] fn-restore map write   {ms_since(t_map_write):.3f} ms")
    print(f"[+] fn-restore map: {len(restore_map)} pairs from {meta.get('dex')} {meta.get('class')}::{meta.get('method')} hits={meta.get('hit_count')} -> {map_path}")

    backup_dir = outdir / "_fn_restore_backup"
    replacements = 0
    changed_files = 0
    bytes_delta = 0
    # Match only IDs that actually exist in the DEX restore map.  The older
    # generic numeric-call regex called back for every decimal-looking call; on
    # large projects that spent most of fn-restore time proving non-map IDs.
    restore_map_b = {str(k).encode("ascii", "ignore"): str(v).encode("utf-8", "ignore") for k, v in restore_map.items()}

    def replace_numeric_calls_safely(data: bytes) -> Tuple[bytes, int]:
        """Replace executable numeric calls, not quoted text/comments/definitions."""
        if not restore_map_b or not data:
            return data, 0
        out = bytearray()
        n = len(data)
        i = 0
        replacements_local = 0
        quote = 0
        escaped = False
        line_comment = False
        block_comment = False
        line_start = 0

        def ident_byte(value: int) -> bool:
            return (
                48 <= value <= 57 or 65 <= value <= 90 or 97 <= value <= 122
                or value in (95, 46, 36)
            )

        while i < n:
            b = data[i]
            nxt = data[i + 1] if i + 1 < n else -1

            if line_comment:
                out.append(b)
                i += 1
                if b in (10, 13):
                    line_comment = False
                    line_start = i
                continue
            if block_comment:
                out.append(b)
                i += 1
                if b == 42 and nxt == 47:  # */
                    out.append(nxt)
                    i += 1
                    block_comment = False
                continue
            if quote:
                out.append(b)
                i += 1
                # iApp command strings are line-local.  A malformed/unclosed
                # quote on one decrypted line must not suppress restoration in
                # every following line.
                if b in (10, 13):
                    quote = 0
                    escaped = False
                    line_start = i
                elif escaped:
                    escaped = False
                elif b == 92:
                    escaped = True
                elif b == quote:
                    quote = 0
                continue

            if b in (34, 39):
                quote = b
                out.append(b)
                i += 1
                continue
            if b == 47 and nxt == 47:
                line_comment = True
                out.extend((b, nxt))
                i += 2
                continue
            if b == 47 and nxt == 42:
                block_comment = True
                out.extend((b, nxt))
                i += 2
                continue
            if b in (10, 13):
                out.append(b)
                i += 1
                line_start = i
                continue

            if 49 <= b <= 57 and (i == 0 or not ident_byte(data[i - 1])):
                j = i + 1
                while j < n and 48 <= data[j] <= 57 and j - i < 12:
                    j += 1
                token = data[i:j]
                k = j
                while k < n and data[k] in (9, 10, 13, 32):
                    k += 1
                replacement = restore_map_b.get(token)
                if replacement is not None and k < n and data[k] == 40:
                    # Numeric user-function declarations use: fn 123(...).
                    before = data[line_start:i].rstrip()
                    mword = re.search(br"([A-Za-z_][A-Za-z0-9_]*)\s*$", before)
                    if not (mword and mword.group(1).lower() == b"fn"):
                        out.extend(replacement)
                        replacements_local += 1
                        i = j
                        continue
            out.append(b)
            i += 1
        return bytes(out), replacements_local

    def apply_one(item: Tuple[Path, bytes]) -> Tuple[int, int, int]:
        p, old = item
        new, local_replacements = replace_numeric_calls_safely(old)
        if new == old:
            return 0, local_replacements, 0
        if backup:
            backup_dir.mkdir(parents=True, exist_ok=True)
            (backup_dir / p.name).write_bytes(old)
        p.write_bytes(new)
        return 1, local_replacements, len(new) - len(old)

    t_apply = time.perf_counter()
    apply_workers = max(1, min(int(threads or 1), len(source_texts) or 1))
    if apply_workers == 1 or len(source_texts) <= 1:
        results = map(apply_one, source_texts)
    else:
        ex_apply = ThreadPoolExecutor(max_workers=apply_workers)
        results = ex_apply.map(apply_one, source_texts, chunksize=4)
    try:
        for chg, reps, delta in results:
            changed_files += chg
            replacements += reps
            bytes_delta += delta
    finally:
        if 'ex_apply' in locals():
            ex_apply.shutdown(wait=True)
    apply_ms = ms_since(t_apply)
    stats.update({
        "restore_pairs": len(restore_map),
        "restore_replacements": replacements,
        "restore_changed_files": changed_files,
        "restore_overrides": 0,
        "restore_strict_blocked": 0,
        "dynamic_table_detected": 1,
        "restore_indexed_table": 1 if str(meta.get("indexed_method", "0")) == "1" else 0,
        "restore_output_bytes_delta": bytes_delta,
    })
    print(f"[T] fn-restore apply/write {apply_ms:.3f} ms backup={'on' if backup else 'off'}")
    print(f"[+] fn-restore done: changed_files={changed_files} replacements={replacements} backup={backup_dir if (backup and changed_files) else 'none'}")
    return stats

# IAPT_SERVER_SOKEY_STATIC_V280_IMPORT_BEGIN
try:
    from .iapt_sokey_static_v2 import (
        extract_sokey_from_apk as _iapt_v280_extract_sokey_from_apk,
    )
except (ImportError, ValueError):
    _iapt_v280_tool_dir = str(Path(__file__).resolve().parent)
    if _iapt_v280_tool_dir not in sys.path:
        sys.path.insert(0, _iapt_v280_tool_dir)
    from iapt_sokey_static_v2 import (
        extract_sokey_from_apk as _iapt_v280_extract_sokey_from_apk,
    )
# IAPT_SERVER_SOKEY_STATIC_V280_IMPORT_END

def load_inputs(apk_path: Optional[Path], native_so_path: Optional[Path], container_path: Optional[Path], require_container: bool = True, allow_missing_so: bool = False) -> Tuple[Optional[bytes], Optional[bytes], bytes, Optional[bytes]]:
    global _APK_NATIVE_SO_CANDIDATES, _IAPT_PACKED_NATIVE_PROFILE
    manifest=dex=native_so=container=None; selected_so_name=None; _APK_NATIVE_SO_CANDIDATES=[]; _IAPT_PACKED_NATIVE_PROFILE=None
    if apk_path:
        snap=_apk_snapshot(apk_path); names=snap["names"] if snap else set()
        manifest=_apk_read_cached(apk_path,"AndroidManifest.xml")
        dex=_apk_read_cached(apk_path,"classes.dex")
        container=_apk_read_cached(apk_path,"assets/lib.so")
        # IAPT_PACKED_CONTAINER_LOCATE_V282_BEGIN
        if container is None:
            try:
                _iapt_v282_container_probe = _iapt_v282_locate_container(
                    apk_path, include_data=True
                )
                container = bytes(_iapt_v282_container_probe.get("data") or b"")
                print(
                    "[IAPT_V282] relocated encrypted container: locator=%s size=%d sidecars=%d"
                    % (
                        _iapt_v282_container_probe.get("locator"),
                        len(container),
                        len(_iapt_v282_container_probe.get("sidecar_entries") or []),
                    ),
                    flush=True,
                )
            except Exception as _iapt_v282_container_error:
                print(
                    "[IAPT_V282] relocated container lookup failed: %s: %s"
                    % (type(_iapt_v282_container_error).__name__, _iapt_v282_container_error),
                    flush=True,
                )
        # IAPT_PACKED_CONTAINER_LOCATE_V282_END
        _mach=(platform.machine() or "").lower()
        if "aarch64" in _mach or "arm64" in _mach:
            pref=("lib/arm64-v8a/libygsiyu.so","lib/armeabi-v7a/libygsiyu.so","lib/x86_64/libygsiyu.so","lib/x86/libygsiyu.so")
        elif "x86_64" in _mach or "amd64" in _mach:
            pref=("lib/x86_64/libygsiyu.so","lib/x86/libygsiyu.so","lib/arm64-v8a/libygsiyu.so","lib/armeabi-v7a/libygsiyu.so")
        else:
            pref=("lib/arm64-v8a/libygsiyu.so","lib/x86_64/libygsiyu.so","lib/x86/libygsiyu.so","lib/armeabi-v7a/libygsiyu.so")
        ordered=[x for x in pref if x in names]
        ordered += sorted(x for x in names if x.endswith("/libygsiyu.so") and x not in ordered)
        for name in ordered:
            data=_apk_read_cached(apk_path,name)
            if data:_APK_NATIVE_SO_CANDIDATES.append((name,data))
        if _APK_NATIVE_SO_CANDIDATES:
            # Restore the real native module from the exact BMP-parity -> RC4
            # -> zlib wrapper before hidden/table analysis.
            _expanded_native=[]
            try:
                from iapt_bmp_rc4_zlib_restore import unpack_native_wrapper
                for _outer_label,_outer_blob in list(_APK_NATIVE_SO_CANDIDATES):
                    _packed=unpack_native_wrapper(_outer_blob)
                    if _packed is None:
                        continue
                    _inner=bytes(_packed.get("inner_data") or b"")
                    if not _inner:
                        continue
                    _expanded_native.append((_outer_label+"#bmp-rc4-zlib-inner",_inner))
                    if _IAPT_PACKED_NATIVE_PROFILE is None:
                        _IAPT_PACKED_NATIVE_PROFILE=dict(_packed)
                        print(
                            "[IAPT_BMP_RC4_ZLIB] native=%s inner=%d hidden=%d key_pairs=%d" % (
                                _outer_label,len(_inner),
                                len(_packed.get("hidden_candidates") or []),
                                len(_packed.get("key_pairs") or []),
                            ),
                            flush=True,
                        )
            except Exception as _packed_error:
                print("[IAPT_BMP_RC4_ZLIB] skipped: %s: %s" % (type(_packed_error).__name__,_packed_error),flush=True)
            if _expanded_native:
                _APK_NATIVE_SO_CANDIDATES=_expanded_native+_APK_NATIVE_SO_CANDIDATES
            selected_so_name,native_so=_APK_NATIVE_SO_CANDIDATES[0]
            print("[+] selected native so:",selected_so_name,"(from APK primary)")
            if len(_APK_NATIVE_SO_CANDIDATES)>1:print("[+] APK native SO candidates:",", ".join(n for n,_ in _APK_NATIVE_SO_CANDIDATES))
        if native_so_path:print("[!] --native-so ignored because --apk was provided; using APK internal libygsiyu.so candidates")
    elif native_so_path:
        native_so=native_so_path.read_bytes();selected_so_name=str(native_so_path);_APK_NATIVE_SO_CANDIDATES=[(selected_so_name,native_so)]
        try:
            from iapt_bmp_rc4_zlib_restore import unpack_native_wrapper
            _packed=unpack_native_wrapper(native_so)
            if _packed is not None and _packed.get("inner_data"):
                _IAPT_PACKED_NATIVE_PROFILE=dict(_packed)
                _inner=bytes(_packed["inner_data"])
                _APK_NATIVE_SO_CANDIDATES=[(selected_so_name+"#bmp-rc4-zlib-inner",_inner),(selected_so_name,native_so)]
                selected_so_name,native_so=_APK_NATIVE_SO_CANDIDATES[0]
                print("[IAPT_BMP_RC4_ZLIB] external inner=%d hidden=%d key_pairs=%d" % (len(_inner),len(_packed.get("hidden_candidates") or []),len(_packed.get("key_pairs") or [])),flush=True)
        except Exception as _packed_error:
            print("[IAPT_BMP_RC4_ZLIB] external skipped: %s: %s" % (type(_packed_error).__name__,_packed_error),flush=True)
        print("[+] selected native so:",selected_so_name,"(external)")
    if container_path:container=container_path.read_bytes()
    if native_so is None:
        if allow_missing_so:native_so=b"";_APK_NATIVE_SO_CANDIDATES=[];print("[!] native SO not found; continuing because explicit --hidden/--hidden-enum was provided; SO analysis is unavailable")
        else:raise SystemExit("native SO not found. Use --apk containing lib/*/libygsiyu.so, or --native-so for container-only input; use --hidden/--hidden-enum only when you intentionally run without SO analysis")
    if require_container and container is None:raise SystemExit("container not found. Use --apk or --container")
    return manifest,dex,native_so,container


def iter_direct_member_file_names(blob: bytes):
    """Fast exact-extension filename locator.

    v31 walked every dot byte.  This version scans only known extension tokens
    (case-insensitive via one lower() copy) and validates each candidate with a
    small fullmatch regex.  It keeps the broad FILE_RE behavior available through
    extract_file_names_from_blob(..., scan_mode="regex") for diagnostics.
    """
    n = len(blob)
    if n == 0 or b"." not in blob:
        return
    lower = blob.lower()
    seen: Set[bytes] = set()
    for token in _EXT_DOT_TOKENS:
        pos = lower.find(token)
        token_len = len(token)
        while pos >= 0:
            end = pos + token_len
            # Match the old extension scanner's behavior: do not accept when the
            # extension is immediately followed by another ASCII letter.
            if end < n and (65 <= blob[end] <= 90 or 97 <= blob[end] <= 122):
                pos = lower.find(token, pos + 1)
                continue
            start = pos
            limit = max(0, pos - 120)
            while start > limit and _NAME_BYTE_OK[blob[start - 1]]:
                start -= 1
            if start < pos:
                raw = blob[start:end]
                if raw not in seen and FILE_NAME_FULL_RE.fullmatch(raw):
                    seen.add(raw)
                    yield raw
            pos = lower.find(token, pos + 1)


def _decode_candidate_filename(raw: bytes) -> Optional[str]:
    """Decode member filename bytes without dropping Chinese characters silently."""
    if raw is None:
        return None
    for enc in ("utf-8", "gb18030"):
        try:
            s = raw.decode(enc)
            if s:
                return s
        except Exception:
            pass
    s = raw.decode("utf-8", "ignore")
    return s or None


def _clean_candidate_member_name(name: str) -> Optional[str]:
    """Return a safe member-name candidate while preserving relative directories."""
    name = str(name or "").replace("\x00", "").strip().strip('"\'')
    if not name:
        return None
    name = re.sub(r"^(?:file:)?/*", "", name)
    while name.startswith("./") or name.startswith(".\\"):
        name = name[2:]
    name = name.lstrip("/\\").strip()
    if not name or "." not in name:
        return None
    parts = re.split(r"[\\/]+", name)
    if any(p in ("", ".", "..") for p in parts):
        return None
    stem, ext = name.rsplit(".", 1)
    ext_l = ext.lower()
    if ext_l not in FILE_EXTS:
        return None
    return f"{stem}.{ext_l}"


def _candidate_member_name_variants(name: str, default_ext: Optional[str] = None) -> Tuple[str, ...]:
    """Try both source separator and APK/zip separator variants."""
    raw = str(name or "").strip().strip('"\'')
    if not raw:
        return ()
    tail = raw.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    if default_ext and "." not in tail:
        raw = f"{raw}.{default_ext.lstrip('.').lower()}"
    cleaned = _clean_candidate_member_name(raw)
    if not cleaned:
        return ()
    variants: List[str] = []
    for candidate in (
        cleaned,
        re.sub(r"[\\/]+", "/", cleaned),
        re.sub(r"[\\/]+", r"\\", cleaned),
    ):
        if candidate not in variants:
            variants.append(candidate)
    return tuple(variants)


# IAPT_COMPOSED_MEMBER_NAME_V1_BEGIN
# Some iApp projects do not store a complete page filename in any one source
# string.  A common pattern is:
#   ulag(st_vW,3,nx)
#   java(raw,nx,"java.lang.String.getBytes")
#   java(enc,null,"android.util.Base64.encodeToString","byte[]",raw,"int",0)
#   strim(enc,enc)
#   uigo(nx+enc+".iyu")
# The list values and the filename template may live in different decrypted
# members.  The normal per-blob regex scanner therefore cannot recover the
# filename.  This resolver keeps a small cross-member symbolic state and emits
# exact candidates only; the encrypted-container marker check remains the final
# authority, so harmless extra candidates cannot create fake output files.

def _iapp_source_text(blob: bytes) -> str:
    raw = bytes(blob or b"")
    if not raw:
        return ""
    for enc in ("utf-8", "gb18030"):
        try:
            return raw.decode(enc)
        except Exception:
            pass
    return raw.decode("utf-8", "ignore")


def _iapp_unquote_text(token: str) -> Optional[str]:
    token = str(token or "").strip()
    if len(token) < 2 or token[0] not in ('"', "'") or token[-1] != token[0]:
        return None
    body = token[1:-1]
    # iApp source uses Java-like string escaping for the cases relevant to
    # filenames.  Avoid unicode_escape because it corrupts already-decoded CJK.
    body = body.replace(r"\\", "\0")
    body = body.replace(r'\"', '"').replace(r"\'", "'")
    body = body.replace(r"\n", "\n").replace(r"\r", "\r").replace(r"\t", "\t")
    return body.replace("\0", "\\")


def _iapp_var_name(token: str) -> Optional[str]:
    token = str(token or "").strip()
    if not token or _iapp_unquote_text(token) is not None:
        return None
    if token.lower() in {"null", "true", "false"} or re.fullmatch(r"-?\d+(?:\.\d+)?", token):
        return None
    if any(ch in token for ch in ",(){}[]+\r\n"):
        return None
    return token


def _iapp_split_concat_expr(expr: str) -> List[str]:
    parts: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    esc = False
    depth = 0
    for ch in str(expr or ""):
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in ('"', "'"):
            quote = ch
            cur.append(ch)
            continue
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth = max(0, depth - 1)
        if ch == "+" and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur or str(expr or "").strip():
        parts.append("".join(cur).strip())
    return [part for part in parts if part]


class _IappComposedMemberNameResolver:
    """Resolve deterministic member filenames assembled across source files."""

    def __init__(self, max_values_per_expr: int = 4096):
        self.max_values_per_expr = max(64, int(max_values_per_expr or 4096))
        self.field_values: Dict[str, Set[str]] = {}
        self.templates: List[tuple] = []
        self.template_seen: Set[tuple] = set()
        self.emitted: Set[str] = set()
        self.blob_seen: Set[bytes] = set()

    def _add_field_value(self, field: str, value: str) -> None:
        field = str(field or "").strip()
        value = str(value or "")
        if not field or not value or len(value) > 512 or "\x00" in value:
            return
        self.field_values.setdefault(field, set()).add(value)

    def _parse_symbol(self, token: str, env: Dict[str, tuple]) -> tuple:
        literal = _iapp_unquote_text(token)
        if literal is not None:
            return ("const", literal)
        var = _iapp_var_name(token)
        if var and var in env:
            return env[var]
        return ("unknown", var or str(token or "").strip())

    def _parse_concat(self, expr: str, env: Dict[str, tuple]) -> Optional[tuple]:
        terms = _iapp_split_concat_expr(expr)
        if not terms:
            return None
        parsed = tuple(self._parse_symbol(term, env) for term in terms)
        if len(parsed) == 1:
            return parsed[0]
        return ("concat", parsed)

    def _field_refs(self, expr: tuple, out: Optional[Set[Tuple[str, str]]] = None) -> Set[Tuple[str, str]]:
        if out is None:
            out = set()
        if not expr:
            return out
        kind = expr[0]
        if kind == "field":
            field = str(expr[1])
            identity = str(expr[2]) if len(expr) >= 3 else field
            out.add((field, identity))
        elif kind in {"bytes", "trim", "base64"}:
            self._field_refs(expr[1], out)
        elif kind == "concat":
            for term in expr[1]:
                self._field_refs(term, out)
        return out

    def _eval_bound(self, expr: tuple, bindings: Dict[Tuple[str, str], str]) -> Optional[str]:
        kind = expr[0] if expr else "unknown"
        if kind == "const":
            return str(expr[1])
        if kind == "field":
            field = str(expr[1])
            identity = str(expr[2]) if len(expr) >= 3 else field
            return bindings.get((field, identity))
        if kind == "bytes":
            return self._eval_bound(expr[1], bindings)
        if kind == "trim":
            value = self._eval_bound(expr[1], bindings)
            # iApp strim() normalizes the string to lowercase (and removes the
            # Base64 DEFAULT trailing newline).  This is why generated member
            # names use 5zu+... rather than Java Base64's original 5Zu+....
            return value.strip().lower() if value is not None else None
        if kind == "base64":
            value = self._eval_bound(expr[1], bindings)
            if value is None:
                return None
            try:
                return base64.b64encode(value.encode("utf-8")).decode("ascii")
            except Exception:
                return None
        if kind == "concat":
            parts: List[str] = []
            for term in expr[1]:
                value = self._eval_bound(term, bindings)
                if value is None:
                    return None
                parts.append(value)
            value = "".join(parts)
            return value if len(value) <= 1000 else None
        return None

    def _values(self, expr: tuple) -> Set[str]:
        refs = sorted(self._field_refs(expr))
        if not refs:
            value = self._eval_bound(expr, {})
            return {value} if value is not None else set()
        states: List[Dict[Tuple[str, str], str]] = [{}]
        for ref in refs:
            values = sorted(self.field_values.get(ref[0], set()))
            if not values:
                return set()
            next_states: List[Dict[Tuple[str, str], str]] = []
            for state in states:
                for value in values:
                    merged = dict(state)
                    merged[ref] = value
                    next_states.append(merged)
                    if len(next_states) >= self.max_values_per_expr:
                        break
                if len(next_states) >= self.max_values_per_expr:
                    break
            states = next_states
        out: Set[str] = set()
        for state in states:
            value = self._eval_bound(expr, state)
            if value is not None:
                out.add(value)
        return out

    def _evaluate_templates(self) -> Set[str]:
        out: Set[str] = set()
        for expr in self.templates:
            for value in self._values(expr):
                for normalized in _candidate_member_name_variants(value):
                    if normalized not in self.emitted:
                        self.emitted.add(normalized)
                        out.add(normalized)
        return out

    def add_blob(self, blob: bytes) -> Set[str]:
        raw = bytes(blob or b"")
        if not raw or raw in self.blob_seen:
            return set()
        self.blob_seen.add(raw)
        # Binary native libraries are part of the first scan blob.  Only enter
        # symbolic parsing when source-like tokens are actually present.
        lower = raw.lower()
        if not any(token in lower for token in (b"uigo", b"ulag", b"ula(", b"base64", b"strim")):
            return set()
        text = _iapp_source_text(raw)
        if not text:
            return set()

        # Collect Recycler/list record fields.  Values for field 3 in one module
        # can feed ulag(...,3,var) in a separate item-layout page.
        for match in re.finditer(r"(?im)^\s*ula\s*\((.*?)\)\s*$", text):
            try:
                args = _split_iapp_call_args(match.group(1))
            except Exception:
                args = []
            for arg in args[1:]:
                field_match = re.fullmatch(r"\s*(\d+)\s*=\s*(.+?)\s*", arg)
                if not field_match:
                    continue
                value = _iapp_unquote_text(field_match.group(2))
                if value is not None:
                    self._add_field_value(field_match.group(1), value)

        env: Dict[str, tuple] = {}

        # Literal local assignments, e.g. s page="abc" or page="abc".
        assignment_re = re.compile(
            r"(?im)^\s*(?:(?:s|ss|sss)\s+)?([^\s=(),]+)\s*=\s*((?:\"(?:\\.|[^\"\\])*\")|(?:'(?:\\.|[^'\\])*'))\s*$"
        )
        for match in assignment_re.finditer(text):
            value = _iapp_unquote_text(match.group(2))
            if value is not None:
                env[match.group(1).strip()] = ("const", value)

        # ulag(listItem,3,nx) means nx can take every value written to list field 3.
        for match in re.finditer(r"(?im)^\s*ulag\s*\((.*?)\)\s*$", text):
            try:
                args = _split_iapp_call_args(match.group(1))
            except Exception:
                continue
            if len(args) < 3:
                continue
            field = str(args[1]).strip()
            out_var = _iapp_var_name(args[2])
            if out_var and re.fullmatch(r"\d+", field):
                env[out_var] = ("field", field, out_var)

        # Resolve byte/base64/trim aliases.  A few passes handle definitions that
        # appear before or after their source variable without implementing a full
        # interpreter.
        source_lines = text.splitlines()
        for _pass in range(4):
            changed = False
            for line in source_lines:
                call_match = re.match(r"^\s*(java|strim)\s*\((.*)\)\s*$", line, re.I)
                if not call_match:
                    continue
                try:
                    args = _split_iapp_call_args(call_match.group(2))
                except Exception:
                    continue
                call_name = call_match.group(1).lower()
                if call_name == "strim" and len(args) >= 2:
                    out_var = _iapp_var_name(args[0])
                    if out_var:
                        expr = ("trim", self._parse_symbol(args[1], env))
                        if env.get(out_var) != expr:
                            env[out_var] = expr
                            changed = True
                    continue
                if call_name != "java" or len(args) < 3:
                    continue
                out_var = _iapp_var_name(args[0])
                method = _iapp_unquote_text(args[2]) or ""
                if not out_var or not method:
                    continue
                expr = None
                if method.endswith("java.lang.String.getBytes") or method == "java.lang.String.getBytes":
                    expr = ("bytes", self._parse_symbol(args[1], env))
                elif method.endswith("android.util.Base64.encodeToString") or method == "android.util.Base64.encodeToString":
                    source_token = args[4] if len(args) >= 5 else args[-1]
                    expr = ("base64", self._parse_symbol(source_token, env))
                if expr is not None and env.get(out_var) != expr:
                    env[out_var] = expr
                    changed = True
            if not changed:
                break

        for match in re.finditer(r"(?im)(?<![A-Za-z0-9_.$])uigo\s*\(([^\r\n]*)\)", text):
            expr_text = match.group(1).strip()
            # uigo(page, flags) is not a filename-concat expression; use only the
            # first top-level argument.
            try:
                first_arg = _split_iapp_call_args(expr_text)[0]
            except Exception:
                first_arg = expr_text
            expr = self._parse_concat(first_arg, env)
            if expr is None or expr[0] == "unknown":
                continue
            if expr not in self.template_seen:
                self.template_seen.add(expr)
                self.templates.append(expr)

        return self._evaluate_templates()
# IAPT_COMPOSED_MEMBER_NAME_V1_END


def extract_file_names_from_blob(blob: bytes, scan_mode: str = "hybrid") -> Set[str]:
    # Decode iAPEC source before filename discovery so call(null,"mjava",...)
    # references hidden inside the encrypted block participate in the same
    # recursive V3 member traversal, not merely a late post-processing pass.
    blob = _iapt_iapec_restore_blob(bytes(blob or b""))
    scan_mode = (scan_mode or "hybrid").lower()
    if scan_mode not in ("hybrid", "direct", "regex"):
        scan_mode = "hybrid"
    cache_key = (scan_mode, blob)
    cached = _FILE_NAME_SCAN_CACHE.get(cache_key)
    if cached is not None:
        return set(cached)
    if (b"." not in blob and b"fn" not in blob and b"FN" not in blob and
            b"call" not in blob and b"CALL" not in blob and b"uigo" not in blob and b"UIGO" not in blob):
        _FILE_NAME_SCAN_CACHE[cache_key] = ()
        return set()
    out = set()

    def add_candidate_name(name: str, case_fallback: bool = False, default_ext: Optional[str] = None):
        variants = _candidate_member_name_variants(name, default_ext=default_ext)
        if not variants:
            return
        for norm in variants:
            out.add(norm)
        if case_fallback:
            for norm in variants:
                stem, ext_l = norm.rsplit(".", 1)
                for alt_stem in (stem.lower(), stem.upper(), stem[:1].lower() + stem[1:], stem[:1].upper() + stem[1:]):
                    if alt_stem and alt_stem != stem:
                        for alt in _candidate_member_name_variants(f"{alt_stem}.{ext_l}"):
                            out.add(alt)

    if scan_mode == "regex":
        for m in FILE_RE.finditer(blob):
            s = _decode_candidate_filename(m.group(1))
            if s:
                add_candidate_name(s, case_fallback=False)
    else:
        for raw in iter_direct_member_file_names(blob):
            s = _decode_candidate_filename(raw)
            if s:
                add_candidate_name(s, case_fallback=False)
        if scan_mode == "hybrid" and len(blob) < 4096:
            for m in FILE_RE.finditer(blob):
                s = _decode_candidate_filename(m.group(1))
                if s:
                    add_candidate_name(s, case_fallback=False)

    # Page jumps: uigo("广告.iyu"), uigo('页面/广告.iyu'), uigo('页面\\广告.iyu').
    # If source omits extension, try .iyu as a conservative page default.
    for m in UIGO_ARG_RE.finditer(blob):
        s = _decode_candidate_filename(m.group(2))
        if s:
            add_candidate_name(s, case_fallback=False, default_ext="iyu")

    # iApp UI/event functions: fn showym.start(), fn 广告.事件() -> showym.myu / 广告.myu.
    for m in FN_MODULE_RE.finditer(blob):
        module = _decode_candidate_filename(m.group(1))
        if module:
            add_candidate_name(module, case_fallback=True, default_ext="myu")

    # Multi-language module calls:
    # call(a, "mjava", "mk.abcd", 123)     -> mk.mjava
    # call(a, "mjava", "广告.开始", 123)    -> 广告.mjava
    # call(a, "mjava", "页面/广告.开始", 1) -> 页面/广告.mjava plus backslash variant.
    for m in CALL_MODULE_RE.finditer(blob):
        try:
            ext = m.group(2).decode("ascii", "ignore").lower()
            module = _decode_candidate_filename(m.group(4))
        except Exception:
            continue
        if ext in FILE_EXTS and module:
            add_candidate_name(module, case_fallback=True, default_ext=ext)

    _FILE_NAME_SCAN_CACHE[cache_key] = tuple(out)
    return out


def safe_out_name(name: str) -> str:
    name = name.replace("/", "_").replace("\\", "_").replace("..", "_").strip()
    return name or "unknown.bin"


def safe_dir_name(name: str) -> str:
    """Make a stable filesystem directory name for per-package outputs."""
    name = str(name or "unknown.package").strip()
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name)
    name = name.replace("..", "_").strip("._-/\\")
    return name or "unknown.package"



# IAPT_V18_2_RESTORE_V7_PROJECT_META_BEGIN
def _iapt_project_text_variants(data: bytes) -> List[str]:
    """Decode project metadata from text and common binary string records."""
    import base64 as _base64

    raw = bytes(data or b"")
    if len(raw) > 16 * 1024 * 1024:
        raw = raw[:8 * 1024 * 1024] + b"\n" + raw[-8 * 1024 * 1024:]

    out: List[str] = []
    seen: Set[str] = set()

    def add(value: object) -> None:
        if value is None:
            return
        value = str(value)
        for candidate in (value, value.replace("\x00", ""), value.replace("\x00", "\n")):
            candidate = candidate.replace("\r\n", "\n").replace("\r", "\n")
            candidate = re.sub(r"[\x01-\x08\x0b\x0c\x0e-\x1f\x7f]+", "\n", candidate).strip()
            if candidate and candidate not in seen:
                seen.add(candidate)
                out.append(candidate)

    for enc in ("utf-8", "utf-16le", "utf-16be", "gb18030", "latin1"):
        try:
            add(raw.decode(enc, "ignore"))
        except Exception:
            pass

    try:
        add("\n".join(x.decode("utf-8", "ignore") for x in re.findall(rb"[\x20-\x7e]{3,}", raw)))
    except Exception:
        pass
    try:
        add("\n".join(x.decode("utf-16le", "ignore") for x in re.findall(rb"(?:[\x20-\x7e]\x00){3,}", raw)))
    except Exception:
        pass
    try:
        add("\n".join(x.decode("utf-16be", "ignore") for x in re.findall(rb"(?:\x00[\x20-\x7e]){3,}", raw)))
    except Exception:
        pass

    # DataOutputStream/custom binary formats commonly use length-prefixed strings.
    sample = raw if len(raw) <= 4 * 1024 * 1024 else raw[:2 * 1024 * 1024] + raw[-2 * 1024 * 1024:]
    extracted: List[str] = []
    extracted_seen: Set[str] = set()

    def accept_binary_string(chunk: bytes) -> None:
        if not chunk or len(extracted) >= 4096:
            return
        for enc in ("utf-8", "gb18030", "utf-16le", "utf-16be"):
            try:
                value = chunk.decode(enc, "strict").strip("\x00\r\n\t \"'")
            except Exception:
                continue
            if not (2 <= len(value) <= 240):
                continue
            ratio = sum(1 for c in value if c.isprintable() and c != "\ufffd") / max(1, len(value))
            if ratio < 0.82 or value in extracted_seen:
                continue
            extracted_seen.add(value)
            extracted.append(value)
            return

    n = len(sample)
    for width, byteorder in ((1, "big"), (2, "big"), (2, "little"), (4, "big"), (4, "little")):
        i = 0
        while i + width <= n and len(extracted) < 4096:
            length = sample[i] if width == 1 else int.from_bytes(sample[i:i + width], byteorder, signed=False)
            if 2 <= length <= 512 and i + width + length <= n:
                accept_binary_string(sample[i + width:i + width + length])
                i += width + length
            else:
                i += 1
    if extracted:
        add("\n".join(extracted))

    # Decode small base64-wrapped identity records.
    for current in list(out)[:8]:
        for match in re.finditer(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/]{24,512}={0,2})(?![A-Za-z0-9+/])", current):
            token = match.group(1)
            try:
                decoded = _base64.b64decode(token + "=" * ((4 - len(token) % 4) % 4), validate=False)
            except Exception:
                continue
            if not (4 <= len(decoded) <= 4096):
                continue
            for enc in ("utf-8", "gb18030", "utf-16le"):
                try:
                    value = decoded.decode(enc, "strict")
                except Exception:
                    continue
                ratio = sum(1 for c in value if c.isprintable() or c in "\r\n\t") / max(1, len(value))
                if ratio >= 0.80:
                    add(value)
                    break
    return out


def _iapt_clean_project_text(data: bytes) -> str:
    return "\n".join(_iapt_project_text_variants(data))


def _iapt_first_re(text: str, patterns: List[str]) -> str:
    for pattern in patterns:
        match = re.search(pattern, text, flags=re.I | re.S | re.M)
        if match:
            value = str(match.group(1)).strip().strip('"\' <>\r\n\t;，,')
            if value and value.lower() not in ("null", "none", "unknown", "未知", "未识别"):
                return value[:240]
    return ""


def _iapt_meta_key_norm(key: object) -> str:
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", str(key or "").lower())


def _iapt_flatten_mapping(obj: object, out: Dict[str, object]) -> None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            norm = _iapt_meta_key_norm(key)
            if norm and not isinstance(value, (dict, list, tuple)) and value not in (None, ""):
                out.setdefault(norm, value)
            _iapt_flatten_mapping(value, out)
    elif isinstance(obj, (list, tuple)):
        for value in obj:
            _iapt_flatten_mapping(value, out)


def _iapt_json_mapping_from_texts(texts: List[str]) -> Dict[str, object]:
    mapping: Dict[str, object] = {}
    for text in texts:
        candidates = [text.strip()]
        left, right = text.find("{"), text.rfind("}")
        if 0 <= left < right:
            candidates.append(text[left:right + 1])
        for candidate in candidates:
            if not candidate or len(candidate) > 4 * 1024 * 1024:
                continue
            try:
                obj = json.loads(candidate)
            except Exception:
                continue
            _iapt_flatten_mapping(obj, mapping)
    return mapping


def _iapt_project_token_sequences(texts: List[str]) -> List[List[str]]:
    sequences: List[List[str]] = []
    for text in texts:
        rough = re.split(r"[\x00-\x1f\x7f|;,{}\[\]<>]+", text)
        sequence: List[str] = []
        for part in rough:
            part = re.sub(r"\s+", " ", part).strip(" \t\"'`，；")
            if not part:
                continue
            candidates = [part]
            if re.search(r"[:=：]", part):
                candidates.extend(re.split(r"\s*(?:=>|->|[:=：])\s*", part))
            for candidate in candidates:
                candidate = candidate.strip(" \t\"'`，；")
                if 1 <= len(candidate) <= 240 and candidate not in sequence:
                    sequence.append(candidate)
        if sequence:
            sequences.append(sequence)
    return sequences


def _iapt_token_pair_mapping(sequences: List[List[str]], aliases: List[str]) -> Dict[str, object]:
    wanted = {_iapt_meta_key_norm(x) for x in aliases}
    out: Dict[str, object] = {}
    for sequence in sequences:
        for index, token in enumerate(sequence):
            norm = _iapt_meta_key_norm(token)
            if norm not in wanted:
                continue
            for next_index in range(index + 1, min(len(sequence), index + 4)):
                value = sequence[next_index].strip().strip('"\' <>\r\n\t;，,')
                if value and _iapt_meta_key_norm(value) not in wanted:
                    out.setdefault(norm, value)
                    break
    return out


def _iapt_pick_mapping_value(mapping: Dict[str, object], aliases: List[str]) -> str:
    for alias in aliases:
        value = mapping.get(_iapt_meta_key_norm(alias))
        if value is None:
            continue
        value = str(value).strip().strip('"\' <>\r\n\t;，,')
        if value and value.lower() not in ("null", "none", "unknown", "未知", "未识别"):
            return value[:240]
    return ""


def _iapt_find_labeled_value(text: str, aliases: List[str], value_pattern: str) -> str:
    alternatives = "|".join(re.escape(x) for x in sorted(set(aliases), key=len, reverse=True))
    patterns = [
        rf'["\']?(?:{alternatives})["\']?\s*(?:[:=：]|=>|->)\s*["\']?({value_pattern})',
        rf'<(?:{alternatives})>\s*({value_pattern})\s*</',
        rf'(?:^|\n)\s*["\']?(?:{alternatives})["\']?\s*(?:\n|[\x00-\x1f])+\s*["\']?({value_pattern})',
    ]
    return _iapt_first_re(text, patterns)


def _iapt_project_time(timestamp: str) -> Tuple[int, str]:
    try:
        raw = int(str(timestamp).strip())
    except Exception:
        return 0, ""
    seconds = raw / 1000.0 if raw > 10_000_000_000 else float(raw)
    if seconds < 946684800 or seconds > 4102444800:
        return raw, ""
    try:
        import datetime as _dt
        return raw, _dt.datetime.fromtimestamp(seconds, _dt.timezone(_dt.timedelta(hours=8))).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return raw, ""


def _iapt_unlabeled_meta_candidates(sequences: List[List[str]], timestamp: str = "") -> Dict[str, str]:
    """Infer fixed-position ID/UUID/model values close to the build timestamp."""
    timestamp_digits = re.sub(r"\D", "", str(timestamp or ""))
    known_words = {
        "project", "package", "version", "versionname", "versioncode", "build",
        "timestamp", "time", "uuid", "uid", "id", "model", "device", "phone",
        "android", "null", "none", "unknown", "true", "false", "mian", "main",
    }
    brands = (
        "pixel", "samsung", "huawei", "honor", "xiaomi", "redmi", "oneplus",
        "oppo", "vivo", "realme", "meizu", "nubia", "lenovo", "motorola",
        "sony", "asus", "zte", "tecno", "infinix", "iqoo", "nothing",
    )
    model_patterns = [
        r"SM-[A-Z0-9-]{3,}", r"Pixel(?:\s+[A-Za-z0-9+._-]+){0,4}",
        r"(?:MI|MIX|Redmi|POCO)\s*[A-Za-z0-9+._ -]{2,}", r"ONEPLUS\s*[A-Z0-9-]{2,}",
        r"(?:CPH|RMX|V|PD|LE|LIO|ELS|ANA|TAS|NOH|JNY|STK|MAR|LYA)[A-Z0-9-]{3,}",
        r"(?:HUAWEI|HONOR|OPPO|vivo|realme|Meizu|Nubia|ZTE)\s*[A-Za-z0-9+._ -]{2,}",
    ]
    scored = {"packer_id": [], "uuid": [], "device_model": []}

    def clean(value: str) -> str:
        return re.sub(r"\s+", " ", str(value or "")).strip(" \t\"'`<>[]{}(),;，：:=")[:160]

    def proximity(sequence: List[str], index: int) -> int:
        anchors: List[int] = []
        for pos, item in enumerate(sequence):
            digits = re.sub(r"\D", "", item)
            if (timestamp_digits and timestamp_digits in digits) or re.fullmatch(r"1[5-9]\d{8}(?:\d{3})?|2\d{9}(?:\d{3})?", digits or ""):
                anchors.append(pos)
        if not anchors:
            return 0
        distance = min(abs(index - pos) for pos in anchors)
        return max(0, 42 - distance * 6)

    for sequence in sequences:
        for index, raw in enumerate(sequence):
            value = clean(raw)
            if not value:
                continue
            lower = value.lower()
            norm = _iapt_meta_key_norm(value)
            if norm in known_words or lower.endswith((".iyu", ".myu", ".java", ".xml", ".json", ".project", ".so")):
                continue
            if timestamp_digits and timestamp_digits in re.sub(r"\D", "", value):
                continue
            near = proximity(sequence, index)
            package_like = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,}", value))
            path_like = "/" in value or "\\" in value
            hex_like = bool(re.fullmatch(r"[0-9a-fA-F]+", value))

            uuid_score = 0
            if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
                uuid_score = 110
            elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+/=-]{15,79}", value):
                unique = len(set(value.lower()))
                if unique >= 7 and not package_like and not path_like:
                    uuid_score = 52 + min(18, unique)
                    if len(value) in (16, 32, 36, 40, 64):
                        uuid_score += 12
                    if any(c in value for c in "-_:."):
                        uuid_score += 5
            if uuid_score:
                scored["uuid"].append((uuid_score + near, value))

            packer_score = 0
            if re.fullmatch(r"\d{4,12}", value):
                if not (1900 <= int(value) <= 2200):
                    packer_score = 58 + (8 if 6 <= len(value) <= 10 else 0)
            elif re.fullmatch(r"(?:u(?:id|ser)?|id|user|owner|builder)[-_]?[A-Za-z0-9]{3,24}", value, re.I):
                packer_score = 60
            elif re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]{4,23}", value) and not package_like:
                packer_score = 25
            if hex_like and len(value) >= 16:
                packer_score = 0
            if packer_score:
                scored["packer_id"].append((packer_score + near, value))

            model_score = 0
            if any(re.fullmatch(pattern, value, re.I) for pattern in model_patterns):
                model_score = 90
            elif any(brand in lower for brand in brands) and re.search(r"\d", value):
                model_score = 76
            elif re.fullmatch(r"[A-Za-z]{1,8}[-_ ]?[A-Za-z0-9+._-]{2,24}", value) and re.search(r"\d", value):
                model_score = 42
            if package_like or path_like or (hex_like and len(value) >= 12):
                model_score = 0
            if model_score:
                scored["device_model"].append((model_score + near, value))

    out: Dict[str, str] = {}
    thresholds = {"packer_id": 58, "uuid": 66, "device_model": 68}
    for key, values in scored.items():
        if values:
            values.sort(key=lambda item: (item[0], len(item[1])), reverse=True)
            if values[0][0] >= thresholds[key]:
                out[key] = values[0][1]
    return out



# __IAPT_V7_OWNER_POSITIONAL_BEGIN__
def _iapt_owner_positional_from_timestamp(data: bytes, timestamp: str) -> Dict[str, str]:
    """Recover the common owner-id / uuid / model / timestamp record layout.

    Several iApp builds store the four values as neighboring binary strings with
    no field labels.  Restricting inference to a small window around the exact
    timestamp is much safer than guessing from all strings in the project file.
    """
    ts = re.sub(r"\D", "", str(timestamp or ""))
    if not ts:
        return {}
    raw = bytes(data or b"")
    windows: List[bytes] = []
    needles = [ts.encode("ascii")]
    try:
        needles.extend([ts.encode("utf-16le"), ts.encode("utf-16be")])
    except Exception:
        pass
    for needle in needles:
        start = 0
        while needle:
            pos = raw.find(needle, start)
            if pos < 0:
                break
            windows.append(raw[max(0, pos - 1536): min(len(raw), pos + len(needle) + 1536)])
            start = pos + 1
            if len(windows) >= 12:
                break
        if len(windows) >= 12:
            break
    if not windows:
        return {}

    sequences: List[List[str]] = []
    for window in windows:
        variants = _iapt_project_text_variants(window)
        sequences.extend(_iapt_project_token_sequences(variants))

    def clean(v: str) -> str:
        return re.sub(r"\s+", " ", str(v or "")).strip(" \t\r\n\x00\"'`<>[]{}(),;，：:=")[:160]

    def is_ts(v: str) -> bool:
        return ts in re.sub(r"\D", "", v or "")

    best: Dict[str, Tuple[int, str]] = {}
    model_re = re.compile(
        r"(?:SM-[A-Z0-9-]{3,}|Pixel(?:\s+[A-Za-z0-9+._-]+){0,4}|ONEPLUS\s*[A-Z0-9-]{2,}|"
        r"(?:CPH|RMX|V|PD|LE|LIO|ELS|ANA|TAS|NOH|JNY|STK|MAR|LYA)[A-Z0-9-]{3,}|"
        r"(?:MI|MIX|Redmi|POCO|HUAWEI|HONOR|OPPO|vivo|realme|Meizu|Nubia|ZTE)\s*[A-Za-z0-9+._ -]{2,})$",
        re.I,
    )

    def offer(key: str, score: int, value: str):
        old = best.get(key)
        if value and (old is None or score > old[0]):
            best[key] = (score, value)

    for seq in sequences:
        vals = [clean(x) for x in seq]
        vals = [x for x in vals if x]
        anchors = [i for i, x in enumerate(vals) if is_ts(x)]
        for anchor in anchors:
            lo, hi = max(0, anchor - 10), min(len(vals), anchor + 11)
            for i in range(lo, hi):
                value = vals[i]
                if i == anchor or is_ts(value):
                    continue
                dist = abs(i - anchor)
                package_like = bool(re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+){2,}", value))
                path_like = "/" in value or "\\" in value or value.lower().endswith((".iyu", ".myu", ".project", ".so"))
                if package_like or path_like:
                    continue

                if re.fullmatch(r"\d{4,12}", value) and not (len(value) == 4 and 1900 <= int(value) <= 2200):
                    offer("packer_id", 120 - dist * 5 + (8 if i < anchor else 0), value)
                elif re.fullmatch(r"(?:uid|user|owner|builder|author)[-_]?[A-Za-z0-9]{3,32}", value, re.I):
                    offer("packer_id", 105 - dist * 5, value)

                uuid_score = 0
                if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", value):
                    uuid_score = 145
                elif re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+/=-]{11,95}", value):
                    unique = len(set(value.lower()))
                    if unique >= 6 and not re.fullmatch(r"\d+", value):
                        uuid_score = 88 + min(18, unique)
                        if len(value) in (16, 24, 32, 36, 40, 64):
                            uuid_score += 14
                if uuid_score:
                    offer("uuid", uuid_score - dist * 4 + (5 if i < anchor else 0), value)

                model_score = 0
                if model_re.fullmatch(value):
                    model_score = 140
                elif (re.search(r"[A-Za-z]", value) and re.search(r"\d", value)
                      and re.fullmatch(r"[A-Za-z0-9+._ -]{3,40}", value)
                      and not re.fullmatch(r"[0-9a-fA-F]{12,}", value)):
                    model_score = 82
                if model_score:
                    offer("device_model", model_score - dist * 4 + (6 if i < anchor else 0), value)

    out = {k: v for k, (_s, v) in best.items()}
    # Never use one token for two fields.
    used = set()
    for key in ("uuid", "device_model", "packer_id"):
        val = out.get(key)
        if val in used:
            out.pop(key, None)
        elif val:
            used.add(val)
    return out
# __IAPT_V7_OWNER_POSITIONAL_END__

def parse_iapt_project_meta(project_name: str, data: bytes) -> Dict[str, object]:
    texts = _iapt_project_text_variants(data)
    text = "\n".join(texts)
    sequences = _iapt_project_token_sequences(texts)

    packer_aliases = [
        "packerId", "packer_id", "packId", "pack_id", "builderId", "builder_id",
        "builderUid", "builder_uid", "userId", "user_id", "userid", "uid",
        "authorId", "author_id", "creatorId", "creator_id", "ownerId", "owner_id",
        "owner", "ownerInfo", "owner_info", "packer", "builder", "author", "creator",
        "maker", "producer", "account", "accountId", "account_id", "iappOwner", "iapp_owner",
        "iappUid", "iapp_uid", "iappUserId", "iapp_user_id",
        "打包者id", "打包者ID", "打包者", "打包者信息", "打包id", "打包ID", "打包用户id",
        "打包用户ID", "用户id", "用户ID", "作者id", "作者ID", "作者", "创建者",
        "所有者id", "所有者ID", "所有者", "归属者",
    ]
    uuid_aliases = [
        "uuid", "deviceUuid", "device_uuid", "deviceUUID", "machineUuid", "machine_uuid",
        "deviceId", "device_id", "deviceUid", "device_uid", "androidId", "android_id",
        "machineId", "machine_id", "deviceCode", "device_code", "machineCode", "machine_code",
        "hardwareId", "hardware_id", "terminalId", "terminal_id",
        "imei", "oaid", "serial", "deviceSerial", "device_serial",
        "设备uuid", "设备UUID", "手机uuid", "手机UUID", "设备标识", "设备ID", "机器码",
        "设备码", "设备编号", "终端ID", "终端id",
    ]
    model_aliases = [
        "deviceModel", "device_model", "phoneModel", "phone_model", "productModel",
        "product_model", "brandModel", "brand_model", "ro.product.model", "Build.MODEL",
        "model", "device", "phone", "product", "deviceName", "device_name", "phoneName", "phone_name", "productName",
        "buildModel", "build_model", "androidModel", "android_model", "mobileModel", "mobile_model",
        "设备型号", "手机型号", "打包机型", "设备机型", "机型", "型号", "设备名称", "手机名称", "设备", "手机",
    ]
    time_aliases = [
        "buildTimestampMs", "build_timestamp_ms", "buildTimestamp", "build_timestamp",
        "buildTime", "build_time", "packTimestamp", "pack_timestamp", "packTime", "pack_time",
        "compileTimestamp", "compile_timestamp", "compileTime", "compile_time", "timestamp", "time",
        "打包毫秒时间戳", "打包时间戳", "打包时间", "编译时间戳", "编译时间",
    ]
    aliases = packer_aliases + uuid_aliases + model_aliases + time_aliases
    mapping = _iapt_json_mapping_from_texts(texts)
    for key, value in _iapt_token_pair_mapping(sequences, aliases).items():
        mapping.setdefault(key, value)

    meta: Dict[str, object] = {"project_file": project_name, "project_bytes": len(data)}
    packer_id = _iapt_pick_mapping_value(mapping, packer_aliases)
    if not packer_id:
        packer_id = _iapt_find_labeled_value(text, packer_aliases, r'[^"\'\r\n<>{}\[\],;|&]{1,120}')

    uuid = _iapt_pick_mapping_value(mapping, uuid_aliases)
    if not uuid:
        uuid = _iapt_find_labeled_value(text, uuid_aliases, r'[A-Za-z0-9._:/+\-=]{6,160}')
    if not uuid:
        uuid = _iapt_first_re(text, [r'\b([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b'])

    device_model = _iapt_pick_mapping_value(mapping, model_aliases)
    if not device_model:
        device_model = _iapt_find_labeled_value(text, model_aliases, r'[^"\'\r\n<>{}\[\],;|&]{1,160}')

    timestamp = _iapt_pick_mapping_value(mapping, time_aliases)
    if timestamp:
        match = re.search(r'\d{10,13}', timestamp)
        timestamp = match.group(0) if match else ""
    if not timestamp:
        timestamp = _iapt_find_labeled_value(text, time_aliases, r'\d{10,13}')
    if not timestamp:
        timestamp = _iapt_first_re(text, [r'\b(1[5-9]\d{8}(?:\d{3})?|2\d{9}(?:\d{3})?)\b'])

    inferred = _iapt_unlabeled_meta_candidates(sequences, timestamp)
    positional = _iapt_owner_positional_from_timestamp(data, timestamp)
    packer_id = packer_id or positional.get("packer_id", "") or inferred.get("packer_id", "")
    uuid = uuid or positional.get("uuid", "") or inferred.get("uuid", "")
    device_model = device_model or positional.get("device_model", "") or inferred.get("device_model", "")

    if packer_id:
        meta["packer_id"] = packer_id
    if uuid:
        meta["uuid"] = uuid
    if device_model:
        meta["device_model"] = device_model
    if timestamp:
        raw, human = _iapt_project_time(timestamp)
        if raw:
            meta["build_timestamp"] = raw
            meta["build_timestamp_ms"] = raw * 1000 if 0 < raw < 100_000_000_000 else raw
        if human:
            meta["build_time"] = human

    if not all(meta.get(key) for key in ("packer_id", "uuid", "device_model")):
        preview = re.sub(r"\s+", " ", text).strip()[:1200]
        if preview:
            meta["preview"] = preview
        candidates: List[str] = []
        for sequence in sequences:
            for token in sequence:
                token = re.sub(r"\s+", " ", token).strip()
                if 3 <= len(token) <= 100 and token not in candidates:
                    candidates.append(token)
                if len(candidates) >= 80:
                    break
            if len(candidates) >= 80:
                break
        if candidates:
            meta["candidate_tokens"] = candidates
    return meta


def _iapt_project_member_name_candidates(container_plain: bytes, package: str) -> List[str]:
    names: List[str] = []

    def add(name: str) -> None:
        name = str(name or "").replace("\\", "/").strip().strip("\x00\"'").lstrip("/")
        if name and len(name) <= 240 and name.lower().endswith(".project") and name not in names:
            names.append(name)

    package = str(package or "").strip()
    if package:
        add(package + ".project")
        add(safe_dir_name(package) + ".project")
        add(package.rsplit(".", 1)[-1] + ".project")
    for fallback in ("project.project", "main.project", "mian.project", "app.project"):
        add(fallback)

    sample = bytes(container_plain or b"")
    if len(sample) > 8 * 1024 * 1024:
        sample = sample[:4 * 1024 * 1024] + sample[-4 * 1024 * 1024:]
    for match in re.finditer(rb'([A-Za-z0-9_./\\-]{1,220}\.project)', sample, flags=re.I):
        add(match.group(1).decode("utf-8", "ignore"))
    for enc in ("utf-16le", "utf-16be"):
        try:
            decoded = sample.decode(enc, "ignore")
        except Exception:
            continue
        for match in re.finditer(r'([A-Za-z0-9_./\\-]{1,220}\.project)', decoded, flags=re.I):
            add(match.group(1))
    return names[:48]


def _iapt_merge_project_meta(destination: Dict[str, object], source: Dict[str, object]) -> None:
    if not isinstance(source, dict):
        return
    for key in ("packer_id", "uuid", "device_model", "build_timestamp", "build_timestamp_ms", "build_time"):
        if source.get(key) not in (None, "") and destination.get(key) in (None, ""):
            destination[key] = source.get(key)
    for key in ("project_file", "project_bytes", "project_decrypted", "preview", "candidate_tokens"):
        if source.get(key) not in (None, "") and destination.get(key) in (None, ""):
            destination[key] = source.get(key)


def decrypt_iapt_project_meta(container_plain: bytes, ctx: SlkyContext, key_xor: bytes, hidden: bytes, fb_value, package: str, member_key_mode: str = "xor", apk_path: Optional[Path] = None) -> Dict[str, object]:
    merged: Dict[str, object] = {}
    for name in _iapt_project_member_name_candidates(container_plain, package):
        try:
            plain = try_decrypt_member(container_plain, ctx, key_xor, name, hidden, fb_value, member_key_mode)
        except Exception:
            plain = None
        if not plain:
            continue
        meta = parse_iapt_project_meta(name, plain)
        meta["project_decrypted"] = True
        _iapt_merge_project_meta(merged, meta)
        if all(merged.get(key) for key in ("packer_id", "uuid", "device_model", "build_timestamp_ms")):
            break

    # Some versions duplicate the identity record in a small APK asset.
    if apk_path and not all(merged.get(key) for key in ("packer_id", "uuid", "device_model")):
        try:
            with zipfile.ZipFile(apk_path, "r") as archive:
                total = 0
                count = 0
                for info in archive.infolist():
                    lower = info.filename.lower()
                    base = lower.rsplit("/", 1)[-1]
                    if info.is_dir() or info.file_size <= 0 or info.file_size > 8 * 1024 * 1024:
                        continue
                    interesting = (
                        "project" in base or "build" in base or "device" in base or "meta" in base or
                        base.endswith((".project", ".json", ".xml", ".properties", ".cfg", ".dat", ".txt"))
                    )
                    if not interesting or base in ("androidmanifest.xml", "resources.arsc"):
                        continue
                    try:
                        blob = archive.read(info)
                    except Exception:
                        continue
                    total += len(blob)
                    count += 1
                    _iapt_merge_project_meta(merged, parse_iapt_project_meta("apk:" + info.filename, blob))
                    if all(merged.get(key) for key in ("packer_id", "uuid", "device_model", "build_timestamp_ms")):
                        break
                    if total >= 32 * 1024 * 1024 or count >= 64:
                        break
        except Exception:
            pass
    return merged


def _iapt_v91_write_project_member_to_outdir(container_plain: bytes, ctx: SlkyContext, key_xor: bytes, hidden: bytes, fb_value, package: str, member_key_mode: str, outdir) -> Dict[str, object]:
    """Decrypt and write 包名.project to output if present.

    Older builds parsed the metadata but then the quota pruner removed the actual
    .project member from downloads.  V91 keeps the file and still returns the
    parsed metadata for the UI.
    """
    result: Dict[str, object] = {}
    try:
        out_root = Path(outdir)
    except Exception:
        return result
    for name in _iapt_project_member_name_candidates(container_plain, package):
        try:
            plain = try_decrypt_member(container_plain, ctx, key_xor, name, hidden, fb_value, member_key_mode)
        except Exception:
            plain = None
        if not plain:
            continue
        rel = safe_out_name(name)
        if not rel.lower().endswith('.project'):
            rel = (safe_dir_name(package) if package else 'app') + '.project'
        target = out_root / rel
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(plain)
            result.update(parse_iapt_project_meta(name, plain))
            result['project_decrypted'] = True
            result['project_file'] = rel.replace('\\', '/')
            result['project_bytes'] = len(plain)
            return result
        except Exception as exc:
            result['project_write_error'] = f'{type(exc).__name__}: {exc}'
            return result
    return result
# IAPT_V18_2_RESTORE_V7_PROJECT_META_END

def _safe_root_source_name(value: str) -> Optional[str]:
    name = str(value or "").strip().strip('"\'').replace("\\", "/").lstrip("/")
    if not name or "/" in name or ".." in name:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_.\-\u0080-\uffff]{1,240}\.(?:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)", name, flags=re.I):
        return None
    return name


def _name_case_variants(name: str) -> List[str]:
    safe = _safe_root_source_name(name)
    if not safe:
        return []
    stem, ext = safe.rsplit(".", 1)
    values = [safe, f"{stem.lower()}.{ext.lower()}", f"{stem.upper()}.{ext.lower()}"]
    if stem:
        values.extend([f"{stem[:1].lower() + stem[1:]}.{ext.lower()}", f"{stem[:1].upper() + stem[1:]}.{ext.lower()}"])
    out: List[str] = []
    for value in values:
        if value not in out:
            out.append(value)
    return out


def set_main_file_probe_candidates(items: Iterable[str]) -> None:
    global _MAIN_FILE_PROBE_CANDIDATES
    raw: List[str] = []
    for item in items or []:
        safe = _safe_root_source_name(str(item))
        if safe and safe not in raw:
            raw.append(safe)
        if len(raw) >= 24:
            break
    for fallback in (MUST_HAVE_MAIN, "mian.iyu", "main.iyu", "start.iyu", "index.iyu", "home.iyu"):
        safe = _safe_root_source_name(fallback)
        if safe and safe not in raw:
            raw.append(safe)
    # Preserve semantic priority first; case variants are only fallbacks.  This
    # prevents MIAN/MAIN variants from consuming the bounded list before an
    # app-specific entry such as lianyi.iyu.
    out = list(raw[:24])
    for item in list(raw):
        for value in _name_case_variants(item)[1:]:
            if value not in out:
                out.append(value)
            if len(out) >= 24:
                break
        if len(out) >= 24:
            break
    _MAIN_FILE_PROBE_CANDIDATES = out[:24]


def _enum_main_probe_name_list() -> List[str]:
    names: List[str] = []
    for value in [MUST_HAVE_MAIN] + list(_MAIN_FILE_PROBE_CANDIDATES):
        safe = _safe_root_source_name(value)
        if safe and safe not in names:
            names.append(safe)
    return names[:24]


def verify_main_or_fail(container_plain: bytes, ctx: SlkyContext, key_xor: bytes, hidden: bytes, fb_value, member_key_mode: str = "xor") -> Tuple[str, bytes]:
    errors: List[str] = []
    for name in _enum_main_probe_name_list():
        try:
            plain = try_decrypt_member(container_plain, ctx, key_xor, name, hidden, fb_value, member_key_mode)
        except Exception as exc:
            errors.append(f"{name}:{type(exc).__name__}")
            continue
        if not plain:
            continue
        if looks_like_iapp_plain(plain):
            return name, plain
        errors.append(f"{name}:signature")
    detail = ", ".join(errors[-6:]) if errors else "no candidate marker found"
    raise RuntimeError(f"main entry decrypt failed ({detail}): wrong params/key/f.b()/hidden or mismatched lib.so")


def verify_mian_or_fail(container_plain: bytes, ctx: SlkyContext, key_xor: bytes, hidden: bytes, fb_value, member_key_mode: str = "xor") -> bytes:
    # Backward-compatible wrapper used by older patch blocks.
    return verify_main_or_fail(container_plain, ctx, key_xor, hidden, fb_value, member_key_mode)[1]


def finalize_outer_shell_probe(
    container_plain: bytes,
    post_key: bytes,
    key_xor: bytes,
    hidden: bytes,
    fb_value,
    trace: Dict[str, bytes],
    use_c: bool = False,
    c_path: str = "./libiapp_core.so",
) -> Tuple[Dict[str, bytes], bytes]:
    """Enum finalizer: use the original member decrypt path, but only for mian.iyu.

    This is intentionally *not* a separate AES shortcut and not marker-only.
    It calls the same member-marker/member-key/member-decrypt helpers used by
    the normal full decrypt, but stops after the root main file.  To avoid a
    bogus sokey causing a giant false member span to be decrypted, the candidate
    ciphertext is bounded before decrypting; normal mian.iyu files are tiny.
    """
    marker_contexts: List[Tuple[str, object]] = [
        ("post", SlkyContext(post_key, use_c=use_c, c_path=c_path)),
        ("nopost", NoPostSlkyContext()),
    ]
    if isinstance(trace, dict) and trace.get("member_ctx_hint") == b"nopost":
        marker_contexts = [marker_contexts[1], marker_contexts[0]]

    # 不是 timeout；只是防止错误 sokey 误定位出超大垃圾块后去解一大坨。
    # 可用环境变量调大：IAPT_ENUM_MAIN_MAX_BYTES=16777216
    try:
        max_main_cipher = int(os.environ.get("IAPT_ENUM_MAIN_MAX_BYTES", "8388608"))
    except Exception:
        max_main_cipher = 8388608
    max_main_cipher = max(16, max_main_cipher)

    last_error = ""
    for main_name in _enum_main_probe_name_list():
        for marker_name, marker_ctx in marker_contexts:
            try:
                ciphertext = locate_member_ciphertext(container_plain, marker_ctx, main_name, hidden, fb_value)
                if ciphertext is None:
                    last_error = f"{marker_name}: {main_name} member not found"
                    continue
                clen = len(ciphertext)
                if clen <= 0 or (clen % 16):
                    last_error = f"{marker_name}/{main_name}: bad ciphertext len={clen}"
                    continue
                if clen > max_main_cipher:
                    last_error = f"{marker_name}/{main_name}: candidate ciphertext too large len={clen} max={max_main_cipher}"
                    continue

                for member_key_mode in ("xor", "direct"):
                    t0 = time.perf_counter()
                    try:
                        main_plain = decrypt_member_ciphertext(
                            ciphertext, marker_ctx, key_xor, main_name, hidden, fb_value, member_key_mode
                        )
                    except Exception as e:
                        last_error = f"{marker_name}/{main_name}/{member_key_mode}: {type(e).__name__}: {e}"
                        continue
                    if not main_plain or not looks_like_iapp_plain(main_plain):
                        last_error = f"{marker_name}/{main_name}/{member_key_mode}: plaintext check failed"
                        continue
                    out_trace = dict(trace or {})
                    out_trace["member_ctx"] = marker_name.encode()
                    out_trace["member_key_mode"] = member_key_mode.encode()
                    out_trace["main_file"] = main_name.encode("utf-8", "replace")
                    out_trace["enum_shell_probe_finalized"] = b"1"
                    out_trace["enum_main_file"] = main_name.encode("utf-8", "replace")
                    out_trace["enum_probe_mode"] = b"main-original-decrypt"
                    out_trace["enum_main_cipher_len"] = str(clen).encode()
                    out_trace["enum_main_decrypt_ms"] = f"{ms_since(t0):.3f}".encode()
                    return out_trace, main_plain
            except Exception as e:
                last_error = f"{marker_name}/{main_name}: {type(e).__name__}: {e}"
                continue

    raise RuntimeError(
        f"outer shell decrypted but no main entry passed original decrypt check. Last: {last_error}"
    )


def _hidden_enum_outer_key_attempts(
    ctx: SlkyContext, key_xor: bytes, hidden_try: bytes, package: str, version_name: str, version_code, app_label: str, fb_value
) -> List[Tuple[str, bytes, Dict[str, bytes]]]:
    """Return fast outer-key attempts for explicit hidden enumeration.

    This intentionally stays bounded: fixed legacy formula plus the x86 idbfj
    hidden formula observed in iApp SOs.  It avoids constructing hundreds of
    generic template candidates per hidden candidate.
    """
    out: List[Tuple[str, bytes, Dict[str, bytes]]] = []
    try:
        outer_key, trace = derive_outer_key(ctx, key_xor, hidden_try, package, version_name, version_code, app_label, fb_value)
        trace = dict(trace)
        trace["algorithm"] = b"hidden-enum-fixed:p19_p24_p25"
        out.append(("fixed", outer_key, trace))
    except Exception:
        pass
    try:
        env = build_outer_env(hidden_try, str(package), str(version_name), str(version_code), str(app_label), str(fb_value))
        cand = NativeX86IdbfjP25Candidate("hidden", confidence=99, source="hidden-enum-fast")
        outer_key, trace = cand.derive(ctx, key_xor, env)
        trace = dict(trace)
        trace["algorithm"] = str(cand).encode("utf-8", "replace")
        out.append(("x86-idbfj-hidden", outer_key, trace))
    except Exception:
        pass
    return out


def try_explicit_hidden_enum_fixed_fast(
    hidden_candidates: List[bytes], container: bytes, package: str, version_name: str, version_code, app_label: str, fb_value,
    manual_post_key: Optional[bytes], manual_key_xor: Optional[bytes], mode: str, member_key_mode: str = "xor",
) -> Optional[Tuple[int, bytes, bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    """Fast explicit hidden enumeration for no-SO/missing-hidden cases.

    It does not inspect SO.  It tries the fixed legacy outer formula with manual
    key constants when provided, otherwise the built-in generic constants in
    fast/auto mode.  Wrong hidden values are rejected by decrypting only the last
    AES block first; only padding-pass candidates pay for full container decrypt
    and mian.iyu verification.
    """
    keysets: List[Tuple[str, bytes, bytes]] = []
    if manual_post_key and manual_key_xor:
        keysets.append(("manual", manual_post_key, manual_key_xor))
    elif manual_post_key or manual_key_xor:
        print("[!] hidden enum fixed-fast: both --post-key and --key-xor are needed for manual key mode; incomplete manual key ignored")
    if mode in ("fast", "auto"):
        keysets.append(("generic", GENERIC_SLKY_POST_KEY, GENERIC_KEY_XOR_CONST))
    keysets = [(n, pk, xk) for n, pk, xk in keysets if pk and xk]
    if not keysets:
        return None

    t0 = time.perf_counter()
    tested = 0
    padding_hits = 0
    for ks_name, post_key, key_xor in keysets:
        ctx = SlkyContext(post_key)
        for idx, hidden_try in enumerate(hidden_candidates):
            tested += 1
            try:
                t_key = time.perf_counter()
                for formula_name, outer_key, trace in _hidden_enum_outer_key_attempts(ctx, key_xor, hidden_try, package, version_name, version_code, app_label, fb_value):
                    trace["algorithm"] = f"hidden-enum-fixed-fast:{ks_name}:{formula_name}".encode()
                    trace["timing_outer_key_ms"] = f"{ms_since(t_key):.3f}".encode()
                    if not aes_cbc_pkcs7_padding_maybe_valid(container, outer_key):
                        continue
                    padding_hits += 1
                    t_dec = time.perf_counter()
                    container_plain = aes_cbc_then_xor_decrypt(container, outer_key)
                    verify_mian_or_fail(container_plain, ctx, key_xor, hidden_try, fb_value, member_key_mode)
                    trace["timing_outer_decrypt_ms"] = f"{ms_since(t_dec):.3f}".encode()
                    print(f"[T] hidden enum fixed-fast {ms_since(t0):.3f} ms tested={tested} padding_hits={padding_hits} keyset={ks_name} formula={formula_name}")
                    return idx, hidden_try, post_key, key_xor, outer_key, container_plain, trace
            except Exception:
                continue
    print(f"[T] hidden enum fixed-fast {ms_since(t0):.3f} ms no-hit tested={tested} padding_hits={padding_hits} keysets={len(keysets)}")
    return None




_HIDDEN_ENUM_WORKER_STATE: Dict[str, object] = {}


def _hidden_enum_worker_init(
    container: bytes, package: str, version_name: str, version_code_s: str, app_label: str, fb_value_s: str,
    manual_post_key: Optional[bytes], manual_key_xor: Optional[bytes], mode: str, member_key_mode: str, fast_c_mode: str,
) -> None:
    """Initializer for hidden enum process workers.

    The large container is installed once per process so each task only carries a
    small list of hidden candidates.  This is the real multi-core path for
    missing/encrypted SO cases where hidden must be brute-forced from a prefix or
    candidate list.
    """
    try:
        set_fast_c_mode(fast_c_mode)
        if fast_c_mode == "on":
            _load_c_fast_core(verbose=False)
    except Exception:
        pass
    keysets: List[Tuple[str, bytes, bytes]] = []
    if manual_post_key and manual_key_xor:
        keysets.append(("manual", manual_post_key, manual_key_xor))
    if mode in ("fast", "auto"):
        keysets.append(("generic", GENERIC_SLKY_POST_KEY, GENERIC_KEY_XOR_CONST))
    _HIDDEN_ENUM_WORKER_STATE.clear()
    _HIDDEN_ENUM_WORKER_STATE.update({
        "container": container,
        "package": package,
        "version_name": version_name,
        "version_code": version_code_s,
        "app_label": app_label,
        "fb_value": fb_value_s,
        "member_key_mode": member_key_mode,
        "keysets": keysets,
    })


def _hidden_enum_worker_chunk(task: Tuple[int, int, List[bytes]]) -> Dict[str, object]:
    chunk_id, start_idx, hidden_chunk = task
    container = _HIDDEN_ENUM_WORKER_STATE["container"]
    package = _HIDDEN_ENUM_WORKER_STATE["package"]
    version_name = _HIDDEN_ENUM_WORKER_STATE["version_name"]
    version_code = _HIDDEN_ENUM_WORKER_STATE["version_code"]
    app_label = _HIDDEN_ENUM_WORKER_STATE["app_label"]
    fb_value = _HIDDEN_ENUM_WORKER_STATE["fb_value"]
    member_key_mode = _HIDDEN_ENUM_WORKER_STATE["member_key_mode"]
    keysets = _HIDDEN_ENUM_WORKER_STATE["keysets"]
    tested = 0
    padding_hits = 0
    for ks_name, post_key, key_xor in keysets:
        ctx = SlkyContext(post_key)
        for rel_idx, hidden_try in enumerate(hidden_chunk):
            tested += 1
            try:
                t_key = time.perf_counter()
                for formula_name, outer_key, trace in _hidden_enum_outer_key_attempts(ctx, key_xor, hidden_try, package, version_name, version_code, app_label, fb_value):
                    if not aes_cbc_pkcs7_padding_maybe_valid(container, outer_key):
                        continue
                    padding_hits += 1
                    t_dec = time.perf_counter()
                    container_plain = aes_cbc_then_xor_decrypt(container, outer_key)
                    verify_mian_or_fail(container_plain, ctx, key_xor, hidden_try, fb_value, member_key_mode)
                    trace["algorithm"] = f"hidden-enum-mp:{ks_name}:{formula_name}:chunk{chunk_id}".encode()
                    trace["timing_outer_key_ms"] = f"{ms_since(t_key):.3f}".encode()
                    trace["timing_outer_decrypt_ms"] = f"{ms_since(t_dec):.3f}".encode()
                    return {
                        "found": True,
                        "index": start_idx + rel_idx,
                        "hidden": hidden_try,
                        "post_key": post_key,
                        "key_xor": key_xor,
                        "outer_key": outer_key,
                        "container_plain": container_plain,
                        "trace": trace,
                        "tested": tested,
                        "padding_hits": padding_hits,
                        "chunk_id": chunk_id,
                        "keyset": ks_name,
                        "formula": formula_name,
                    }
            except Exception:
                continue
    return {"found": False, "tested": tested, "padding_hits": padding_hits, "chunk_id": chunk_id}


def try_explicit_hidden_enum_parallel(
    hidden_candidates: List[bytes], container: bytes, package: str, version_name: str, version_code, app_label: str, fb_value,
    manual_post_key: Optional[bytes], manual_key_xor: Optional[bytes], mode: str, member_key_mode: str,
    workers: int = 0, chunk_size: int = 4096, fast_c_mode: str = "on",
) -> Optional[Tuple[int, bytes, bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    workers = int(workers or 0)
    if workers <= 0:
        workers = max(1, min(8, os.cpu_count() or 1))
    workers = max(1, workers)
    chunk_size = max(1, int(chunk_size or 4096))
    # Serial is still faster for small explicit lists because process startup and
    # container handoff dominate.  Use true multi-process only for large ranges.
    mp_threshold = max(4096, chunk_size * max(2, workers) * 4)
    if workers <= 1 or len(hidden_candidates) <= mp_threshold:
        return try_explicit_hidden_enum_fixed_fast(
            hidden_candidates, container, package, version_name, version_code, app_label, fb_value,
            manual_post_key, manual_key_xor, mode, member_key_mode,
        )
    keyset_count = int(bool(manual_post_key and manual_key_xor)) + (1 if mode in ("fast", "auto") else 0)
    if keyset_count <= 0:
        return None
    tasks: List[Tuple[int, int, List[bytes]]] = []
    for chunk_id, off in enumerate(range(0, len(hidden_candidates), chunk_size)):
        tasks.append((chunk_id, off, hidden_candidates[off:off + chunk_size]))
    t0 = time.perf_counter()
    tested = 0
    padding_hits = 0
    found_result = None
    ex = ProcessPoolExecutor(
        max_workers=workers,
        initializer=_hidden_enum_worker_init,
        initargs=(container, str(package), str(version_name), str(version_code), str(app_label), str(fb_value), manual_post_key, manual_key_xor, mode, member_key_mode, fast_c_mode),
    )
    futures = [ex.submit(_hidden_enum_worker_chunk, task) for task in tasks]
    try:
        for fut in as_completed(futures):
            res = fut.result()
            tested += int(res.get("tested", 0) or 0)
            padding_hits += int(res.get("padding_hits", 0) or 0)
            if res.get("found"):
                found_result = res
                for other in futures:
                    if other is not fut:
                        other.cancel()
                break
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    if found_result:
        print(
            f"[T] hidden enum mp-fast    {ms_since(t0):.3f} ms workers={workers} chunks={len(tasks)} "
            f"tested~={tested} padding_hits~={padding_hits} hit_index={found_result.get('index')} chunk={found_result.get('chunk_id')}"
        )
        return (
            int(found_result["index"]), found_result["hidden"], found_result["post_key"], found_result["key_xor"],
            found_result["outer_key"], found_result["container_plain"], found_result["trace"],
        )
    print(
        f"[T] hidden enum mp-fast    {ms_since(t0):.3f} ms no-hit workers={workers} chunks={len(tasks)} "
        f"tested~={tested} padding_hits~={padding_hits}"
    )
    return None



def discover_apk_source_candidates(
    apk_path: Optional[Path],
    app_label: str = "",
    package: str = "",
    explicit_main: str = "",
) -> Tuple[List[str], List[str]]:
    """Discover bounded source names from metadata and DEX string tables.

    This discovers *names only*.  Every name is still required to pass marker,
    AES, and source-signature checks before it can select a key/container.
    """
    main: List[str] = []
    members: List[str] = []

    def add_member(value: str) -> None:
        safe = _safe_root_source_name(value)
        if safe and safe not in members and len(members) < 256:
            members.append(safe)

    def add_main(value: str) -> None:
        for safe in _name_case_variants(value):
            if safe.lower().endswith(".iyu") and safe not in main and len(main) < 24:
                main.append(safe)
            add_member(safe)

    explicit_safe = _safe_root_source_name(explicit_main or MUST_HAVE_MAIN)
    if explicit_safe and explicit_safe.lower() != "mian.iyu":
        add_main(explicit_safe)
    # Package tail is usually the generated project/root page name.  Probe it
    # before generic home/start fallbacks, while keeping mian first for ordinary
    # iApp builds.
    add_main("mian.iyu")
    for raw in (str(package or "").rsplit(".", 1)[-1], app_label):
        raw = str(raw or "").strip()
        if raw:
            add_main(raw + ".iyu")

    total = 0
    for _dex_name, blob in load_apk_dex_blobs(apk_path):
        total += len(blob)
        if total > 96 * 1024 * 1024:
            break
        try:
            names = sorted(extract_file_names_from_blob(blob, scan_mode="direct"))
        except Exception:
            continue
        for value in names:
            safe = _safe_root_source_name(value)
            if not safe:
                continue
            add_member(safe)
            if safe.lower().endswith(".iyu"):
                add_main(safe)
        if len(members) >= 256 and len(main) >= 24:
            break
    for value in ("main.iyu", "start.iyu", "index.iyu", "home.iyu"):
        add_main(value)
    return main[:24], members[:256]


def decrypt_members_recursive(
    container_plain: bytes,
    ctx: SlkyContext,
    key_xor: bytes,
    hidden: bytes,
    fb_value,
    so_data: bytes,
    outdir: Path,
    manual_find: List[str],
    skip_existing: Optional[Set[str]] = None,
    threads: int = 4,
    member_key_mode: str = "xor",
    only_manual: bool = False,
    max_new_members: Optional[int] = None,
    verbose: bool = False,
    scan_mode: str = "hybrid",
    member_batch_size: int = 1,
    member_marker_mode: str = "legacy",
    member_marker_wave_size: int = 96,
    defer_writes: bool = False,
) -> Dict[str, bytes]:
    found: Dict[str, bytes] = {}
    tried: Set[str] = set(skip_existing or set())
    queued: Set[str] = set()
    queue = deque()
    manual_find = normalize_find_names(manual_find)
    composed_name_resolver = _IappComposedMemberNameResolver()
    composed_candidate_count = 0
    if max_new_members is not None:
        max_new_members = max(0, int(max_new_members))

    def limit_reached() -> bool:
        return max_new_members is not None and len(found) >= max_new_members

    def add_queue(name: str):
        if limit_reached():
            return
        if name not in tried and name not in queued and name not in found:
            queue.append(name)
            queued.add(name)

    def add_composed_names(source_name: str, plain: bytes) -> Tuple[str, ...]:
        nonlocal composed_candidate_count
        if only_manual or limit_reached():
            return ()
        inferred = tuple(sorted(composed_name_resolver.add_blob(plain)))
        if inferred:
            composed_candidate_count += len(inferred)
            print(f"[+] 拼接文件名识别: source={source_name} candidates={len(inferred)}", flush=True)
            for candidate in inferred:
                add_queue(candidate)
        return inferred

    if max_new_members == 0:
        print("[+] member output limit reached before recursive phase; no extra members will be decrypted")
        return found

    if only_manual:
        for n in manual_find:
            add_queue(n)
        print(f"[+] find-only mode: decrypting only --find targets ({len(queue)})")
    else:
        t_scan = time.perf_counter()
        for n in sorted(extract_file_names_from_blob(so_data, scan_mode=scan_mode)):
            add_queue(n)
        add_composed_names("initial-scan", so_data)
        print(f"[T] member name scan        {ms_since(t_scan):.3f} ms")
        for n in manual_find:
            add_queue(n)
    if max_new_members is not None:
        print(f"[+] member output limit: {max_new_members} additional member(s)")
    print(f"[+] initial member candidate count: {len(queue)}")
    print(f"[+] member decrypt threads: {threads}")
    member_batch_size = max(1, int(member_batch_size or 1))
    member_marker_mode = (member_marker_mode or "auto").lower()
    member_marker_wave_size = max(1, int(member_marker_wave_size or 96))
    if member_marker_mode == "auto":
        # Tiny containers / tiny candidate lists are faster with simple bytes.find;
        # C-index shines when many candidates would otherwise rescan a multi-MB
        # container hundreds of times.
        if len(container_plain) < (512 * 1024):
            member_marker_mode = "legacy"
        else:
            member_marker_mode = "cindex"
        print(f"[+] member marker auto selected: {member_marker_mode} container={len(container_plain)} initial={len(queue)}")
    print(f"[+] member batch size: {member_batch_size}")
    print(f"[+] member marker mode: {member_marker_mode} wave_size={member_marker_wave_size}")
    t_all_start = time.perf_counter()

    offset_sig = member_offset_cache_signature(container_plain, ctx, hidden, fb_value, member_key_mode)
    offset_cache_paths = [outdir / ".tmp" / "member_offsets_cache.json", shared_member_offset_cache_path(offset_sig)]
    t_offset_cache = time.perf_counter()
    member_offset_cache: Dict[str, Tuple[int, int]] = load_member_offset_cache(offset_cache_paths, offset_sig)
    member_offset_hits = 0
    member_offset_misses = 0
    c_marker_locate_ms = 0.0
    c_marker_locate_calls = 0
    c_marker_locate_names = 0
    if member_offset_cache:
        print(f"[T] member offset cache   {ms_since(t_offset_cache):.3f} ms")

    def locate_cipher_cached(name: str) -> Optional[bytes]:
        nonlocal member_offset_hits, member_offset_misses
        cached = member_offset_cache.get(name)
        if cached is not None:
            data_start, end_off = cached
            if data_start == -1 and end_off == -1:
                member_offset_hits += 1
                return None
            try:
                start, end = member_markers(ctx, name, hidden, fb_value)
                if (len(start) <= data_start <= end_off <= len(container_plain) and
                        container_plain[data_start - len(start):data_start] == start and
                        container_plain[end_off:end_off + len(end)] == end and
                        ((end_off - data_start) % 16) == 0):
                    member_offset_hits += 1
                    return container_plain[data_start:end_off]
            except Exception:
                pass
        member_offset_misses += 1
        start, end = member_markers(ctx, name, hidden, fb_value)
        s = container_plain.find(start)
        if s < 0:
            member_offset_cache[name] = (-1, -1)
            return None
        data_start = s + len(start)
        e = container_plain.find(end, data_start)
        if e < 0 or e <= data_start:
            member_offset_cache[name] = (-1, -1)
            return None
        ciphertext = container_plain[data_start:e]
        if len(ciphertext) % 16:
            member_offset_cache[name] = (-1, -1)
            return None
        member_offset_cache[name] = (data_start, e)
        return ciphertext

    def locate_batch_c_cached(names: Tuple[str, ...]) -> Dict[str, Optional[bytes]]:
        nonlocal member_offset_hits, member_offset_misses, c_marker_locate_ms, c_marker_locate_calls, c_marker_locate_names
        result: Dict[str, Optional[bytes]] = {}
        missing: List[str] = []
        for name in names:
            cached = member_offset_cache.get(name)
            if cached is not None:
                data_start, end_off = cached
                if data_start == -1 and end_off == -1:
                    member_offset_hits += 1
                    result[name] = None
                elif 0 <= data_start <= end_off <= len(container_plain) and ((end_off - data_start) % 16) == 0:
                    member_offset_hits += 1
                    result[name] = container_plain[data_start:end_off]
                else:
                    missing.append(name)
            else:
                missing.append(name)
        if missing:
            t_c_loc = time.perf_counter()
            offsets = locate_member_offsets_c_indexed(container_plain, ctx, tuple(missing), hidden, fb_value)
            if offsets is None:
                offsets = locate_member_offsets_c(container_plain, ctx, tuple(missing), hidden, fb_value)
            if offsets is None:
                for name in missing:
                    result[name] = locate_cipher_cached(name)
                return result
            c_marker_locate_ms += ms_since(t_c_loc)
            c_marker_locate_calls += 1
            c_marker_locate_names += len(missing)
            for name in missing:
                member_offset_misses += 1
                data_start, end_off = offsets.get(name, (-1, -1))
                member_offset_cache[name] = (data_start, end_off)
                if data_start == -1 and end_off == -1:
                    result[name] = None
                else:
                    result[name] = container_plain[data_start:end_off]
        return result

    def worker_one(name: str):
        t_one_start = time.perf_counter()
        ciphertext = locate_cipher_cached(name)
        plain = None if ciphertext is None else decrypt_member_ciphertext(ciphertext, ctx, key_xor, name, hidden, fb_value, member_key_mode)
        decrypt_ms = ms_since(t_one_start)
        write_ms = 0.0
        scan_ms = 0.0
        out_path_s = ""
        new_names: Tuple[str, ...] = ()
        if plain is not None:
            plain = _iapt_iapec_restore_blob(plain)
            out_path = outdir / safe_out_name(name)
            out_path_s = str(out_path)
            if not defer_writes:
                t_write = time.perf_counter()
                out_path.write_bytes(plain)
                write_ms = ms_since(t_write)
            if not only_manual:
                t_scan_plain = time.perf_counter()
                new_names = tuple(sorted(extract_file_names_from_blob(plain, scan_mode=scan_mode)))
                scan_ms = ms_since(t_scan_plain)
        return name, plain, decrypt_ms, write_ms, scan_ms, out_path_s, new_names

    def worker_batch(names: Tuple[str, ...]):
        # Small batches reduce Future scheduling overhead without changing marker,
        # member-key, AES, or recursive reference logic.  In cindex/auto mode the
        # whole batch is located with one C-level scan of container_plain, then
        # each member is decrypted exactly as before.
        if member_marker_mode in ("cindex", "auto") and len(names) > 1:
            ciphers = locate_batch_c_cached(names)
            out = []
            for name in names:
                t_one_start = time.perf_counter()
                ciphertext = ciphers.get(name)
                plain = None if ciphertext is None else decrypt_member_ciphertext(ciphertext, ctx, key_xor, name, hidden, fb_value, member_key_mode)
                decrypt_ms = ms_since(t_one_start)
                write_ms = 0.0
                scan_ms = 0.0
                out_path_s = ""
                new_names: Tuple[str, ...] = ()
                if plain is not None:
                    plain = _iapt_iapec_restore_blob(plain)
                    t_write = time.perf_counter()
                    out_path = outdir / safe_out_name(name)
                    out_path.write_bytes(plain)
                    write_ms = ms_since(t_write)
                    out_path_s = str(out_path)
                    if not only_manual:
                        t_scan_plain = time.perf_counter()
                        new_names = tuple(sorted(extract_file_names_from_blob(plain, scan_mode=scan_mode)))
                        scan_ms = ms_since(t_scan_plain)
                out.append((name, plain, decrypt_ms, write_ms, scan_ms, out_path_s, new_names))
            return out
        return [worker_one(name) for name in names]

    def worker_cipher(item: Tuple[str, bytes]):
        name, ciphertext = item
        t_one_start = time.perf_counter()
        plain = decrypt_member_ciphertext(ciphertext, ctx, key_xor, name, hidden, fb_value, member_key_mode)
        decrypt_ms = ms_since(t_one_start)
        write_ms = 0.0
        scan_ms = 0.0
        out_path_s = ""
        new_names: Tuple[str, ...] = ()
        if plain is not None:
            plain = _iapt_iapec_restore_blob(plain)
            out_path = outdir / safe_out_name(name)
            out_path_s = str(out_path)
            if not defer_writes:
                t_write = time.perf_counter()
                out_path.write_bytes(plain)
                write_ms = ms_since(t_write)
            if not only_manual:
                t_scan_plain = time.perf_counter()
                new_names = tuple(sorted(extract_file_names_from_blob(plain, scan_mode=scan_mode)))
                scan_ms = ms_since(t_scan_plain)
        return name, plain, decrypt_ms, write_ms, scan_ms, out_path_s, new_names

    max_workers = max(1, int(threads or 1))

    def iter_batches(seq, n: int):
        n = max(1, int(n or 1))
        for i in range(0, len(seq), n):
            yield seq[i:i + n]

    def worker_cipher_batch(items: List[Tuple[str, bytes]]):
        return [worker_cipher(item) for item in items]

    if member_marker_mode in ("cindex", "auto"):
        # v49: default path.  Instead of scanning container_plain once per small
        # ThreadPool task, take a recursive wave of candidate names, locate all
        # their 16-byte start/end markers with one C-level scan, then decrypt the
        # hits in batched Python worker calls.  This keeps recursive discovery
        # exact while cutting the hot bytes.find/container-scan count sharply.
        marker_locate_total_ms = 0.0
        marker_waves = 0
        marker_candidates = 0
        marker_hits = 0
        decrypt_batches = 0
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            while queue and not limit_reached():
                wave: List[str] = []
                while queue and len(wave) < member_marker_wave_size:
                    name = queue.popleft()
                    queued.discard(name)
                    if name in tried or name in found:
                        continue
                    tried.add(name)
                    wave.append(name)
                if not wave:
                    continue
                marker_waves += 1
                marker_candidates += len(wave)
                t_loc = time.perf_counter()
                ciphers = locate_batch_c_cached(tuple(wave))
                loc_ms = ms_since(t_loc)
                marker_locate_total_ms += loc_ms
                located: List[Tuple[str, bytes]] = [(name, ct) for name, ct in ciphers.items() if ct is not None]
                marker_hits += len(located)
                if verbose:
                    print(f"[T] member marker cindex wave {marker_waves:04d} names={len(wave)} hits={len(located)} locate={loc_ms:.3f} ms")
                if not located:
                    continue
                # ThreadPoolExecutor chunksize is ignored for thread pools, so
                # explicitly batch items to reduce future scheduling overhead.
                batches = list(iter_batches(located, member_batch_size))
                decrypt_batches += len(batches)
                for result_batch in ex.map(worker_cipher_batch, batches):
                    for name, plain, dt_one_ms, write_ms, scan_ms, out_path_s, new_names in result_batch:
                        if plain is None:
                            continue
                        if max_new_members is not None and len(found) >= max_new_members:
                            continue
                        found[name] = plain
                        mb = len(plain) / 1024 / 1024
                        speed = mb / (dt_one_ms / 1000.0) if dt_one_ms > 0 else 0
                        if verbose:
                            print(f"[+] member decrypted: {name:30s} {len(plain):8d} bytes decrypt={dt_one_ms:.3f} ms write={write_ms:.3f} ms speed={speed:.2f} MB/s -> {out_path_s}")
                            if (not only_manual) and new_names:
                                print(f"[T] member ref scan {name:18s} {scan_ms:.3f} ms found={len(new_names)}")
                        if not only_manual and not limit_reached():
                            for new_name in new_names:
                                add_queue(new_name)
                            add_composed_names(name, plain)
        print(f"[T] member marker cindex {marker_locate_total_ms:.3f} ms waves={marker_waves} candidates={marker_candidates} hits={marker_hits} decrypt_batches={decrypt_batches}")
        save_member_offset_cache(offset_cache_paths, offset_sig, member_offset_cache)
        if c_marker_locate_calls:
            print(f"[T] member c-marker locate {c_marker_locate_ms:.3f} ms calls={c_marker_locate_calls} names={c_marker_locate_names}")
        print(f"[+] member offset cache stats: hits={member_offset_hits} misses={member_offset_misses} entries={len(member_offset_cache)}")
        print(f"[+] member decrypt total time: {ms_since(t_all_start):.3f} ms")
        if max_new_members is not None and len(found) >= max_new_members:
            print(f"[+] member output limit reached: {len(found)}/{max_new_members}; remaining queued candidates were not decrypted")
        return found

    if member_marker_mode in ("process", "proc"):
        import multiprocessing as _mp
        marker_locate_total_ms = 0.0
        marker_waves = 0
        marker_candidates = 0
        marker_hits = 0
        marker_proc_count = max(1, min(4, max_workers))
        try:
            mp_ctx = _mp.get_context("fork")
        except Exception:
            mp_ctx = _mp.get_context()
        with mp_ctx.Pool(processes=marker_proc_count, initializer=_proc_marker_init, initargs=(container_plain,)) as marker_pool, ThreadPoolExecutor(max_workers=max_workers) as ex:
            while queue and not limit_reached():
                wave: List[str] = []
                while queue and len(wave) < member_marker_wave_size:
                    name = queue.popleft()
                    queued.discard(name)
                    if name in tried or name in found:
                        continue
                    tried.add(name)
                    wave.append(name)
                if not wave:
                    continue
                marker_waves += 1
                marker_candidates += len(wave)
                located: List[Tuple[str, bytes]] = []
                proc_items: List[Tuple[str, bytes, bytes]] = []
                for name in wave:
                    cached = member_offset_cache.get(name)
                    if cached is not None:
                        data_start, end_off = cached
                        if data_start == -1 and end_off == -1:
                            member_offset_hits += 1
                            continue
                        if 0 <= data_start <= end_off <= len(container_plain) and ((end_off - data_start) % 16) == 0:
                            member_offset_hits += 1
                            located.append((name, container_plain[data_start:end_off]))
                            continue
                    try:
                        start, end = member_markers(ctx, name, hidden, fb_value)
                        proc_items.append((name, start, end))
                    except Exception:
                        member_offset_cache[name] = (-1, -1)
                        member_offset_misses += 1
                if proc_items:
                    t_loc = time.perf_counter()
                    for name, data_start, end_off in marker_pool.imap_unordered(_proc_locate_marker_item, proc_items, chunksize=4):
                        member_offset_misses += 1
                        if data_start >= 0 and end_off >= data_start:
                            member_offset_cache[name] = (data_start, end_off)
                            located.append((name, container_plain[data_start:end_off]))
                        else:
                            member_offset_cache[name] = (-1, -1)
                    loc_ms = ms_since(t_loc)
                    marker_locate_total_ms += loc_ms
                marker_hits += len(located)
                if verbose:
                    print(f"[T] member marker proc wave {marker_waves:04d} names={len(wave)} hits={len(located)}")
                if not located:
                    continue
                for name, plain, dt_one_ms, write_ms, scan_ms, out_path_s, new_names in ex.map(worker_cipher, located, chunksize=max(1, member_batch_size)):
                    if plain is None:
                        continue
                    if max_new_members is not None and len(found) >= max_new_members:
                        continue
                    found[name] = plain
                    mb = len(plain) / 1024 / 1024
                    speed = mb / (dt_one_ms / 1000.0) if dt_one_ms > 0 else 0
                    if verbose:
                        print(f"[+] member decrypted: {name:30s} {len(plain):8d} bytes decrypt={dt_one_ms:.3f} ms write={write_ms:.3f} ms speed={speed:.2f} MB/s -> {out_path_s}")
                        if (not only_manual) and new_names:
                            print(f"[T] member ref scan {name:18s} {scan_ms:.3f} ms found={len(new_names)}")
                    if not only_manual and not limit_reached():
                        for new_name in new_names:
                            add_queue(new_name)
                        add_composed_names(name, plain)
        print(f"[T] member marker process {marker_locate_total_ms:.3f} ms procs={marker_proc_count} waves={marker_waves} candidates={marker_candidates} hits={marker_hits}")
        save_member_offset_cache(offset_cache_paths, offset_sig, member_offset_cache)
        print(f"[+] member offset cache stats: hits={member_offset_hits} misses={member_offset_misses} entries={len(member_offset_cache)}")
        print(f"[+] member decrypt total time: {ms_since(t_all_start):.3f} ms")
        if max_new_members is not None and len(found) >= max_new_members:
            print(f"[+] member output limit reached: {len(found)}/{max_new_members}; remaining queued candidates were not decrypted")
        return found

    if member_marker_mode in ("wave", "auto"):
        marker_locate_total_ms = 0.0
        marker_waves = 0
        marker_candidates = 0
        marker_hits = 0
        with ThreadPoolExecutor(max_workers=max_workers) as ex:
            while queue and not limit_reached():
                wave: List[str] = []
                while queue and len(wave) < member_marker_wave_size:
                    name = queue.popleft()
                    queued.discard(name)
                    if name in tried or name in found:
                        continue
                    tried.add(name)
                    wave.append(name)
                if not wave:
                    continue
                marker_waves += 1
                marker_candidates += len(wave)
                t_loc = time.perf_counter()
                located = locate_member_ciphertexts_wave(container_plain, ctx, tuple(wave), hidden, fb_value)
                loc_ms = ms_since(t_loc)
                marker_locate_total_ms += loc_ms
                marker_hits += len(located)
                if verbose:
                    print(f"[T] member marker wave {marker_waves:04d} names={len(wave)} hits={len(located)} locate={loc_ms:.3f} ms")
                if not located:
                    continue
                for name, plain, dt_one_ms, write_ms, scan_ms, out_path_s, new_names in ex.map(worker_cipher, located, chunksize=max(1, member_batch_size)):
                    if plain is None:
                        continue
                    if max_new_members is not None and len(found) >= max_new_members:
                        continue
                    found[name] = plain
                    mb = len(plain) / 1024 / 1024
                    speed = mb / (dt_one_ms / 1000.0) if dt_one_ms > 0 else 0
                    if verbose:
                        print(f"[+] member decrypted: {name:30s} {len(plain):8d} bytes decrypt={dt_one_ms:.3f} ms write={write_ms:.3f} ms speed={speed:.2f} MB/s -> {out_path_s}")
                        if (not only_manual) and new_names:
                            print(f"[T] member ref scan {name:18s} {scan_ms:.3f} ms found={len(new_names)}")
                    if not only_manual and not limit_reached():
                        for new_name in new_names:
                            add_queue(new_name)
                        add_composed_names(name, plain)
        print(f"[T] member marker locate {marker_locate_total_ms:.3f} ms waves={marker_waves} candidates={marker_candidates} hits={marker_hits}")
        save_member_offset_cache(offset_cache_paths, offset_sig, member_offset_cache)
        print(f"[+] member offset cache stats: hits={member_offset_hits} misses={member_offset_misses} entries={len(member_offset_cache)}")
        print(f"[+] member decrypt total time: {ms_since(t_all_start):.3f} ms")
        if max_new_members is not None and len(found) >= max_new_members:
            print(f"[+] member output limit reached: {len(found)}/{max_new_members}; remaining queued candidates were not decrypted")
        return found


    # Dynamic scheduling still feeds newly discovered names back immediately when
    # a batch completes.  The batch is intentionally small; large batches can
    # delay recursive discovery and hurt long iApp projects.
    pending_limit = max(max_workers * 4, 16)
    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        pending: Dict[object, Tuple[str, ...]] = {}
        in_flight_names = 0

        def can_submit_more() -> bool:
            nonlocal in_flight_names
            if limit_reached():
                return False
            if max_new_members is None:
                return len(pending) < pending_limit
            # Count in-flight names pessimistically as possible successes so
            # --max-output-files cannot overshoot with batched futures.
            return len(pending) < pending_limit and (len(found) + in_flight_names) < max_new_members

        def submit_available() -> None:
            nonlocal in_flight_names
            while queue and can_submit_more():
                target = member_batch_size
                if max_new_members is not None:
                    target = max(1, min(target, max_new_members - len(found) - in_flight_names))
                batch: List[str] = []
                while queue and len(batch) < target:
                    name = queue.popleft()
                    queued.discard(name)
                    if name in tried:
                        continue
                    tried.add(name)
                    batch.append(name)
                if not batch:
                    continue
                names_t = tuple(batch)
                pending[ex.submit(worker_batch, names_t)] = names_t
                in_flight_names += len(names_t)

        submit_available()
        while pending:
            done, _not_done = wait(pending.keys(), return_when=FIRST_COMPLETED)
            for fut in done:
                names_t = pending.pop(fut, ())
                in_flight_names -= len(names_t)
                for name, plain, dt_one_ms, write_ms, scan_ms, out_path_s, new_names in fut.result():
                    if plain is not None:
                        found[name] = plain
                        mb = len(plain) / 1024 / 1024
                        speed = mb / (dt_one_ms / 1000.0) if dt_one_ms > 0 else 0
                        if verbose:
                            print(f"[+] member decrypted: {name:30s} {len(plain):8d} bytes decrypt={dt_one_ms:.3f} ms write={write_ms:.3f} ms speed={speed:.2f} MB/s -> {out_path_s}")
                            if (not only_manual) and new_names:
                                print(f"[T] member ref scan {name:18s} {scan_ms:.3f} ms found={len(new_names)}")
                        if not only_manual and not limit_reached():
                            for new_name in new_names:
                                add_queue(new_name)
                            add_composed_names(name, plain)
            submit_available()
    save_member_offset_cache(offset_cache_paths, offset_sig, member_offset_cache)
    if c_marker_locate_calls:
        print(f"[T] member c-marker locate {c_marker_locate_ms:.3f} ms calls={c_marker_locate_calls} names={c_marker_locate_names}")
    print(f"[+] member offset cache stats: hits={member_offset_hits} misses={member_offset_misses} entries={len(member_offset_cache)}")
    print(f"[+] member decrypt total time: {ms_since(t_all_start):.3f} ms")
    if max_new_members is not None and len(found) >= max_new_members:
        print(f"[+] member output limit reached: {len(found)}/{max_new_members}; remaining queued candidates were not decrypted")
    return found



class DecryptDiag:
    """Small layered diagnostic collector used by fixed/static verification paths."""
    def __init__(self):
        self.items: List[Tuple[str, str, str]] = []

    def ok(self, stage: str, msg: str = ""):
        self.items.append(("OK", stage, msg))
        print(f"[OK] {stage}" + (f": {msg}" if msg else ""))

    def warn(self, stage: str, msg: str = ""):
        self.items.append(("WARN", stage, msg))
        print(f"[WARN] {stage}" + (f": {msg}" if msg else ""))

    def fail(self, stage: str, msg: str = ""):
        self.items.append(("FAIL", stage, msg))
        print(f"[FAIL] {stage}" + (f": {msg}" if msg else ""))

    def dump(self):
        print("[+] diagnostic summary:")
        for lvl, stage, msg in self.items:
            print(f"[{lvl}] {stage}" + (f": {msg}" if msg else ""))


class StaticExpr:
    def __init__(self, text: str):
        self.text = text

    def __str__(self):
        return self.text

    __repr__ = __str__


def _arm64_sign_extend(v: int, bits: int) -> int:
    sign = 1 << (bits - 1)
    return (v ^ sign) - sign


def arm64_bl_target(insn: int, pc: int) -> Optional[int]:
    if (insn & 0xFC000000) != 0x94000000:
        return None
    imm26 = insn & 0x03FFFFFF
    return pc + (_arm64_sign_extend(imm26, 26) << 2)


def arm64_add_sp_imm(insn: int):
    # ADD/SUB immediate aliases used for stack object addresses, e.g. add x1, sp, #0x130
    if (insn & 0x7F000000) not in (0x11000000, 0x91000000):
        return None
    rd = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm = (insn >> 10) & 0xFFF
    shift = (insn >> 22) & 0x3
    if shift == 1:
        imm <<= 12
    elif shift != 0:
        return None
    return rd, rn, imm


def arm64_mov_reg(insn: int):
    # MOV Xd, Xm = ORR Xd, XZR, Xm
    if (insn & 0xFFE0FFE0) == 0xAA0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        return rd, rm
    # MOV Wd, Wm = ORR Wd, WZR, Wm
    if (insn & 0xFFE0FFE0) == 0x2A0003E0:
        rd = insn & 0x1F
        rm = (insn >> 16) & 0x1F
        return rd, rm
    return None


def arm64_ldr_str_unsigned(insn: int):
    # Unsigned offset LDR/STR for 32/64-bit general registers.
    opc = insn & 0xFFC00000
    if opc not in (0xF9400000, 0xF9000000, 0xB9400000, 0xB9000000):
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm12 = (insn >> 10) & 0xFFF
    scale = 8 if opc in (0xF9400000, 0xF9000000) else 4
    kind = "ldr" if opc in (0xF9400000, 0xB9400000) else "str"
    return kind, rt, rn, imm12 * scale


def arm64_ldr_str_unscaled(insn: int):
    # LDUR/STUR 32/64-bit, signed imm9.
    opc = insn & 0xFFC00000
    if opc not in (0xF8400000, 0xF8000000, 0xB8400000, 0xB8000000):
        return None
    rt = insn & 0x1F
    rn = (insn >> 5) & 0x1F
    imm9 = _arm64_sign_extend((insn >> 12) & 0x1FF, 9)
    kind = "ldr" if opc in (0xF8400000, 0xB8400000) else "str"
    return kind, rt, rn, imm9


X86_REGS = {0: "eax", 1: "ecx", 2: "edx", 3: "ebx", 4: "esp", 5: "ebp", 6: "esi", 7: "edi"}
X86_REG_IDS = {v: k for k, v in X86_REGS.items()}


def x86_rel_call_target(code: bytes, off: int, base: int) -> Optional[int]:
    """Return direct CALL rel32 target for 32-bit x86, or None."""
    if off + 5 > len(code) or code[off] != 0xE8:
        return None
    rel = struct.unpack_from('<i', code, off + 1)[0]
    return (base + off + 5 + rel) & 0xFFFFFFFF


def _x86_disp_label(disp: int) -> str:
    if disp < 0:
        return f"local_0x{-disp:x}"
    return f"arg_0x{disp:x}"


def _x86_parse_modrm_disp(code: bytes, off: int):
    """
    Minimal ModRM parser for the compiler patterns in this iApp x86 SO.
    Returns (mod, reg, rm, disp, size_after_modrm) where size_after_modrm counts
    disp/SIB bytes after the ModRM byte.  Only enough for mov/lea patterns.
    """
    if off >= len(code):
        return None
    m = code[off]
    mod = (m >> 6) & 3
    reg = (m >> 3) & 7
    rm = m & 7
    p = off + 1
    sib = None
    if mod != 3 and rm == 4:
        if p >= len(code):
            return None
        sib = code[p]
        p += 1
    disp = 0
    if mod == 1:
        if p >= len(code):
            return None
        disp = struct.unpack_from('b', code, p)[0]
        p += 1
    elif mod == 2 or (mod == 0 and rm == 5):
        if p + 4 > len(code):
            return None
        disp = struct.unpack_from('<i', code, p)[0]
        p += 4
    return mod, reg, rm, disp, p - (off + 1)


def static_call_base(name: str) -> str:
    if name.startswith("operator+"):
        return "operator+"
    if name.startswith("slky"):
        return "slky"
    if name.startswith("asendn"):
        return "asendn"
    if name.startswith("idbfj"):
        return "idbfj"
    return name.split("+")[0]


class StaticOuterAnalyzer:
    """
    Lightweight ELF IR dumper for the iApp outer-key path.
    It intentionally does not try to guess unknown keys at level 1/2; it records calls,
    argument sources, and best-effort expression edges for slky/operator+/asendn.
    """
    def __init__(self, so_data: bytes, outdir: Path = Path("out"), trace_slky_args: bool = False, trace_asendn_args: bool = False, backtrace_insns: int = 100):
        self.so_data = so_data
        self.outdir = outdir
        self.trace_slky_args = trace_slky_args
        self.trace_asendn_args = trace_asendn_args
        self.backtrace_insns = backtrace_insns
        self.elf: Optional[MiniELF] = None
        self.symbols: List[Dict] = []
        self.func_symbols: List[Dict] = []
        self.calls_by_func: Dict[str, List[Dict]] = {}
        self.slky_reports: List[Dict] = []
        self.asendn_reports: List[Dict] = []
        self.expr_lines: List[str] = []
        self.status: List[Tuple[str, str]] = []

    def parse_elf(self):
        self.elf = MiniELF(self.so_data)
        self.symbols = self.elf.read_symbols()
        self.func_symbols = [s for s in self.symbols if s.get("value", 0) and (s.get("size", 0) or True)]
        self.status.append(("OK", f"ELF parsed bits={self.elf.bits} machine={self.elf.e_machine} symbols={len(self.symbols)}"))
        return self.elf

    def find_symbol(self, needle: str) -> Optional[Dict]:
        if not self.elf:
            self.parse_elf()
        matches = [s for s in self.symbols if needle in s["name"] and self.elf.vaddr_to_offset(s["value"]) is not None]
        if not matches:
            return None
        matches.sort(key=lambda s: (0 if s.get("size") else 1, len(s["name"]), s["value"]))
        return matches[0]

    def symbol_name_at(self, addr: int) -> str:
        exact = [s for s in self.symbols if s.get("value") == addr and s.get("name")]
        if exact:
            exact.sort(key=lambda s: len(s["name"]))
            return self.short_sym(exact[0]["name"])
        containing = []
        for s in self.symbols:
            val, size = s.get("value", 0), s.get("size", 0)
            if size and val <= addr < val + size:
                containing.append((addr - val, s))
        if containing:
            containing.sort(key=lambda x: (x[0], len(x[1]["name"])))
            off, s = containing[0]
            return f"{self.short_sym(s['name'])}+0x{off:x}"
        return f"sub_{addr:x}"

    def short_sym(self, name: str) -> str:
        mapping = {
            "_ZN4iapp4slky": "slky",
            "_ZN4iapp6asendn": "asendn",
            "_ZN4iapp6burden1a": "burden1a",
            "_ZN4iapp6burden1b": "burden1b",
            "Interact5idbfj": "idbfj",
            "_ZN4iapp5idbfj": "idbfj",
            "basic_string": "operator+" if "pl" in name or "plus" in name else "std::string",
        }
        for k, v in mapping.items():
            if k in name:
                return v
        if "slky" in name:
            return "slky"
        if "asendn" in name:
            return "asendn"
        if "idbfj" in name:
            return "idbfj"
        if "burden1a" in name:
            return "burden1a"
        if "operator+" in name or "Stpl" in name or "plIc" in name:
            return "operator+"
        return name

    def get_func_code(self, sym: Dict) -> Tuple[int, bytes]:
        if not self.elf:
            self.parse_elf()
        off = self.elf.vaddr_to_offset(sym["value"])
        if off is None:
            return sym["value"], b""
        size = sym.get("size") or 0x9000
        return sym["value"], self.so_data[off:off + size]

    def scan_calls(self, func_sym: Dict) -> List[Dict]:
        base, code = self.get_func_code(func_sym)
        calls = []
        machine = self.elf.e_machine if self.elf else None
        if machine == 183:  # AArch64
            for off in range(0, len(code) - 3, 4):
                insn = struct.unpack_from("<I", code, off)[0]
                target = arm64_bl_target(insn, base + off)
                if target is None:
                    continue
                name = self.symbol_name_at(target)
                calls.append({"addr": base + off, "off": off, "target": target, "name": name})
        elif machine in (3, 62):  # x86 32-bit and x86_64 direct rel32 calls
            off = 0
            while off < len(code) - 4:
                target = x86_rel_call_target(code, off, base)
                if target is not None:
                    name = self.symbol_name_at(target)
                    calls.append({"addr": base + off, "off": off, "target": target, "name": name})
                    off += 5
                    continue
                # Indirect calls are useful in the IR even when the vtable target is unknown.
                if code[off] == 0xFF and off + 2 < len(code):
                    b = code[off + 1]
                    if (b >> 3) & 7 == 2:
                        calls.append({"addr": base + off, "off": off, "target": 0, "name": "indirect_call"})
                off += 1
        else:
            self.status.append(("WARN", f"call scan unsupported for machine={machine}"))
        self.calls_by_func[func_sym["name"]] = calls
        return calls

    def _call_label_counts_before(self, calls: List[Dict], addr: int) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for c in calls:
            if c["addr"] >= addr:
                break
            base = static_call_base(c["name"])
            if base in ("slky", "asendn", "operator+") or base.startswith("sub_") or base in ("idbfj",):
                counts[base] = counts.get(base, 0) + 1
        return counts

    def backtrace_arg_x86(self, func_sym: Dict, call: Dict, arg_slot: int) -> str:
        """
        x86 cdecl style backtrace for arguments written to [esp+slot*4].
        arg_slot 1 => first real argument after `this` for slky/asendn wrappers:
          slky(Interact*, arg1, arg2)      -> slots 1,2
          asendn(Interact*, data,key,mode) -> slots 1,2,3
        """
        base, code = self.get_func_code(func_sym)
        calls = self.scan_calls(func_sym)
        global_counts: Dict[str, int] = {}
        call_label_by_off: Dict[int, str] = {}
        for cc in calls:
            cname = static_call_base(cc["name"])
            if cname == "indirect_call":
                continue
            global_counts[cname] = global_counts.get(cname, 0) + 1
            if cname in ("slky", "operator+", "asendn", "idbfj"):
                call_label_by_off[cc["off"]] = f"result({cname}#{global_counts[cname]})"
            else:
                call_label_by_off[cc["off"]] = f"result({cname})"

        start = max(0, call["off"] - self.backtrace_insns * 8)  # x86 instrs are variable length
        end = call["off"]
        regs: Dict[str, str] = {}
        locals_map: Dict[int, str] = {}
        stack_args: Dict[int, str] = {}
        i = start
        while i < end:
            b = code[i]
            # call rel32
            tgt = x86_rel_call_target(code, i, base)
            if tgt is not None:
                regs["eax"] = call_label_by_off.get(i, f"result({static_call_base(self.symbol_name_at(tgt))})")
                i += 5
                continue

            # mov r32, imm32: B8+rd imm32
            if 0xB8 <= b <= 0xBF and i + 5 <= len(code):
                reg = X86_REGS[b - 0xB8]
                imm = struct.unpack_from('<I', code, i + 1)[0]
                regs[reg] = f"#0x{imm:x}"
                i += 5
                continue

            # lea r32, [ebp+disp]: 8D /r
            if b == 0x8D and i + 2 < len(code):
                pr = _x86_parse_modrm_disp(code, i + 1)
                if pr:
                    mod, reg, rm, disp, used = pr
                    if rm == 5 and mod in (1, 2):  # ebp + disp
                        regs[X86_REGS[reg]] = f"stack_string_0x{-disp:x}" if disp < 0 else f"arg_0x{disp:x}"
                    elif rm in X86_REGS:
                        regs[X86_REGS[reg]] = f"addr({X86_REGS[rm]}+0x{disp:x})"
                    i += 2 + used
                    continue

            # mov r32, r/m32: 8B /r
            if b == 0x8B and i + 2 < len(code):
                pr = _x86_parse_modrm_disp(code, i + 1)
                if pr:
                    mod, reg, rm, disp, used = pr
                    dst = X86_REGS[reg]
                    if mod == 3:
                        regs[dst] = regs.get(X86_REGS[rm], X86_REGS[rm])
                    elif rm == 5 and mod in (1, 2):  # [ebp+disp]
                        regs[dst] = locals_map.get(disp, _x86_disp_label(disp))
                    elif rm == 4:
                        regs[dst] = f"mem[esp+0x{disp:x}]"
                    elif rm in X86_REGS:
                        regs[dst] = f"mem[{regs.get(X86_REGS[rm], X86_REGS[rm])}+0x{disp:x}]"
                    i += 2 + used
                    continue

            # mov r/m32, r32: 89 /r
            if b == 0x89 and i + 2 < len(code):
                pr = _x86_parse_modrm_disp(code, i + 1)
                if pr:
                    mod, reg, rm, disp, used = pr
                    src = regs.get(X86_REGS[reg], X86_REGS[reg])
                    if mod == 3:
                        regs[X86_REGS[rm]] = src
                    elif rm == 5 and mod in (1, 2):  # [ebp+disp]
                        locals_map[disp] = src
                    elif rm == 4:  # [esp+disp]
                        stack_args[disp] = src
                    i += 2 + used
                    continue

            # mov dword [esp+imm8], imm32: C7 44 24 xx imm32
            if b == 0xC7 and i + 8 <= len(code) and code[i+1] == 0x44 and code[i+2] == 0x24:
                disp = code[i+3]
                imm = struct.unpack_from('<I', code, i + 4)[0]
                stack_args[disp] = f"#{imm}" if imm < 10 else f"#0x{imm:x}"
                i += 8
                continue

            # mov dword [ebp+disp32], imm32: C7 85 disp imm
            if b == 0xC7 and i + 10 <= len(code) and code[i+1] == 0x85:
                disp = struct.unpack_from('<i', code, i + 2)[0]
                imm = struct.unpack_from('<I', code, i + 6)[0]
                locals_map[disp] = f"#{imm}" if imm < 10 else f"#0x{imm:x}"
                i += 10
                continue

            # mov dword [ebp+disp8], imm32: C7 45 disp imm
            if b == 0xC7 and i + 7 <= len(code) and code[i+1] == 0x45:
                disp = struct.unpack_from('b', code, i + 2)[0]
                imm = struct.unpack_from('<I', code, i + 3)[0]
                locals_map[disp] = f"#{imm}" if imm < 10 else f"#0x{imm:x}"
                i += 7
                continue

            # mov byte [ebp+disp], imm8 initializes local std::string; not an arg source.
            if b == 0xC6 and i + 4 <= len(code):
                i += 4
                continue

            # sub/add esp, imm8/imm32
            if b in (0x83, 0x81) and i + 3 < len(code) and code[i+1] in (0xEC, 0xC4):
                i += 3 if b == 0x83 else 6
                continue

            i += 1

        return stack_args.get(arg_slot * 4, f"arg{arg_slot}:unresolved")

    def backtrace_arg(self, func_sym: Dict, call: Dict, reg: int) -> str:
        if self.elf and self.elf.e_machine == 3:
            return self.backtrace_arg_x86(func_sym, call, reg)
        base, code = self.get_func_code(func_sym)
        calls = self.scan_calls(func_sym)
        # Pre-compute GLOBAL call ordinals inside the function.  The earlier
        # implementation counted only calls inside the local backtrace window,
        # which could label an x0 value as result(slky#1) even when it was
        # actually slky#2/#3 in burden1a.  That breaks expression-tree recovery
        # for asendn x2, so keep numbering stable across the whole function.
        global_counts: Dict[str, int] = {}
        global_call_label_by_addr: Dict[int, str] = {}
        for cc in calls:
            cname = static_call_base(cc["name"])
            global_counts[cname] = global_counts.get(cname, 0) + 1
            if cname in ("slky", "operator+", "asendn"):
                global_call_label_by_addr[cc["addr"]] = f"result({cname}#{global_counts[cname]})"
            else:
                global_call_label_by_addr[cc["addr"]] = f"result({cname})"

        start_off = max(0, call["off"] - self.backtrace_insns * 4)
        end_off = call["off"]
        regs: Dict[int, str] = {}
        stack: Dict[int, str] = {}
        for off in range(start_off, end_off, 4):
            insn = struct.unpack_from("<I", code, off)[0]
            pc = base + off
            blt = arm64_bl_target(insn, pc)
            if blt is not None:
                regs[0] = global_call_label_by_addr.get(pc, f"result({static_call_base(self.symbol_name_at(blt))})")
                continue
            ai = arm64_add_sp_imm(insn)
            if ai:
                rd, rn, imm = ai
                if rn == 31:
                    regs[rd] = f"stack_string_0x{imm:x}"
                elif rn in regs:
                    regs[rd] = f"{regs[rn]}+0x{imm:x}"
                continue
            mr = arm64_mov_reg(insn)
            if mr:
                rd, rm = mr
                regs[rd] = regs.get(rm, f"x{rm}")
                continue
            mv = arm64_mov_imm_w(insn)
            if mv:
                rd, val = mv
                regs[rd] = f"#{val}"
                continue
            ls = arm64_ldr_str_unsigned(insn) or arm64_ldr_str_unscaled(insn)
            if ls:
                kind, rt, rn, imm = ls
                if rn == 31:
                    if kind == "ldr":
                        regs[rt] = stack.get(imm, f"stack_slot_0x{imm:x}")
                    else:
                        stack[imm] = regs.get(rt, f"x{rt}")
                elif rn in regs:
                    base_expr = regs[rn]
                    if kind == "ldr":
                        regs[rt] = f"mem[{base_expr}+0x{imm:x}]"
                    else:
                        stack[imm] = regs.get(rt, f"x{rt}")
                continue
        return regs.get(reg, f"x{reg}:unresolved")

    def recover_interesting_calls(self, func_sym: Dict):
        calls = self.scan_calls(func_sym)
        func_short = self.short_sym(func_sym.get("name", "?"))
        slky_idx = 0
        asendn_idx = 0
        plus_idx = 0
        for c in calls:
            n = static_call_base(c["name"])
            if n == "slky":
                slky_idx += 1
                if self.trace_slky_args:
                    self.slky_reports.append({
                        "func": func_short,
                        "idx": slky_idx,
                        "addr": c["addr"],
                        "arg1": self.backtrace_arg(func_sym, c, 1),
                        "arg2": self.backtrace_arg(func_sym, c, 2),
                    })
            elif n == "operator+":
                plus_idx += 1
                if self.trace_slky_args:
                    self.slky_reports.append({
                        "func": func_short,
                        "idx": f"operator+#{plus_idx}",
                        "addr": c["addr"],
                        "dest": self.backtrace_arg(func_sym, c, 0),
                        "left": self.backtrace_arg(func_sym, c, 1),
                        "right": self.backtrace_arg(func_sym, c, 2),
                    })
            elif n == "asendn":
                asendn_idx += 1
                if self.trace_asendn_args:
                    self.asendn_reports.append({
                        "func": func_short,
                        "idx": asendn_idx,
                        "addr": c["addr"],
                        "x1_data": self.backtrace_arg(func_sym, c, 1),
                        "x2_key": self.backtrace_arg(func_sym, c, 2),
                        "x3_mode": self.backtrace_arg(func_sym, c, 3),
                    })
        self.status.append(("OK", f"{self.short_sym(func_sym['name'])} calls={len(calls)} slky={slky_idx} asendn={asendn_idx} operator+={plus_idx}"))

    def build_expr_tree(self):
        # Conservative, report-shaped expression tree from recovered slky/operator+/asendn sources.
        self.expr_lines = []
        for r in self.slky_reports:
            if isinstance(r["idx"], int):
                self.expr_lines.append(f"R{r['idx']} = slky({r.get('arg1','?')}, {r.get('arg2','?')})")
            else:
                lhs = r.get('dest') or r['idx']
                self.expr_lines.append(f"{lhs} = concat({r.get('left','?')}, {r.get('right','?')})")
        for r in self.asendn_reports:
            self.expr_lines.append(f"ASENDN#{r['idx']}.data = {r['x1_data']}")
            self.expr_lines.append(f"ASENDN#{r['idx']}.key  = {r['x2_key']}")
            self.expr_lines.append(f"ASENDN#{r['idx']}.mode = {r['x3_mode']}")
        if self.asendn_reports:
            key_src = self.asendn_reports[0].get("x2_key", "?")
            self.expr_lines.append(f"OUTER? = xor_repeat({key_src}, KEY_XOR_CONST)[:16]  # verify with asendn x2 source")

    def dump_report(self, path: Optional[Path] = None, write: bool = True) -> Path:
        if not self.elf:
            self.parse_elf()
        if path is None:
            path = self.outdir / "outer_static_ir.txt"
        self.outdir.mkdir(parents=True, exist_ok=True)

        targets = []
        # Newer samples put the outer decrypt path in burden1b.  Always scan it,
        # then scan burden1a/idbfj as supporting routines.
        for needle in ("burden1b", "_ZN4iapp6burden1b", "burden1a", "_ZN4iapp6burden1a", "idbfj", "Interact5idbfj", "_ZN4iapp5idbfj"):
            sym = self.find_symbol(needle)
            if sym and sym not in targets:
                targets.append(sym)
        if not targets:
            self.status.append(("FAIL", "burden1b/burden1a/idbfj not found"))
        for sym in targets:
            self.recover_interesting_calls(sym)
        self.build_expr_tree()

        lines = []
        lines.append("# outer static IR")
        lines.append(f"ELF: bits={self.elf.bits} machine={self.elf.e_machine} symbols={len(self.symbols)}")
        lines.append("")
        lines.append("# status")
        for lvl, msg in self.status:
            lines.append(f"[{lvl}] {msg}")
        lines.append("")
        lines.append("# call IR")
        for sym in targets:
            calls = self.calls_by_func.get(sym["name"]) or self.scan_calls(sym)
            lines.append(f"{self.short_sym(sym['name'])}: va=0x{sym['value']:x} size=0x{sym.get('size',0):x}")
            for c in calls:
                mark = ""
                base_name = static_call_base(c["name"])
                if base_name in ("slky", "asendn", "operator+") or base_name in ("idbfj",):
                    mark = "  <interesting>"
                lines.append(f"  0x{c['addr']:x} BL {c['name']} -> 0x{c['target']:x}{mark}")
            lines.append("")
        if self.trace_slky_args and self.slky_reports:
            lines.append("# slky/operator+ argument trace")
            for r in self.slky_reports:
                if isinstance(r["idx"], int):
                    lines.append(f"{r.get('func','?')}:slky#{r['idx']} @ 0x{r['addr']:x}")
                    lines.append(f"  arg1 = {r['arg1']}")
                    lines.append(f"  arg2 = {r['arg2']}")
                else:
                    lines.append(f"{r.get('func','?')}:{r['idx']} @ 0x{r['addr']:x}")
                    if 'dest' in r:
                        lines.append(f"  dest  = {r['dest']}")
                    lines.append(f"  left  = {r['left']}")
                    lines.append(f"  right = {r['right']}")
                lines.append("")
        if self.trace_asendn_args and self.asendn_reports:
            lines.append("# asendn argument trace")
            for r in self.asendn_reports:
                lines.append(f"{r.get('func','?')}:asendn#{r['idx']} @ 0x{r['addr']:x}")
                lines.append(f"  x1_data = {r['x1_data']}")
                lines.append(f"  x2_key  = {r['x2_key']}")
                lines.append(f"  x3_mode = {r['x3_mode']}")
                lines.append("")
        if self.expr_lines:
            lines.append("# recovered outer candidate algorithm / expression tree")
            for line in self.expr_lines:
                lines.append(f"  {line}")
            lines.append("")
        if write:
            path.write_text("\n".join(lines), encoding="utf-8")
            print(f"[+] static IR written: {path}")
        return path


def run_static_outer_analysis(so_data: bytes, outdir: Path, dump_static_ir: bool, trace_slky_args: bool, trace_asendn_args: bool, write_static_ir: bool = True) -> Optional[StaticOuterAnalyzer]:
    if not (dump_static_ir or trace_slky_args or trace_asendn_args):
        return None
    analyzer = StaticOuterAnalyzer(
        so_data,
        outdir=outdir,
        trace_slky_args=trace_slky_args,
        trace_asendn_args=trace_asendn_args,
    )
    try:
        analyzer.parse_elf()
        analyzer.dump_report(outdir / "outer_static_ir.txt", write=write_static_ir)
    except Exception as e:
        print(f"[FAIL] static outer analysis: {type(e).__name__}: {e}")
        if write_static_ir:
            outdir.mkdir(parents=True, exist_ok=True)
            fail_path = outdir / "outer_static_ir.txt"
            fail_path.write_text(f"[FAIL] static outer analysis failed: {type(e).__name__}: {e}\n", encoding="utf-8")
            print(f"[+] static IR written: {fail_path}")
    return analyzer


# ----------------------------
# Outer expression/candidate layer
# ----------------------------

class OuterExpr:
    def eval(self, ctx: SlkyContext, env: Dict[str, bytes]) -> bytes:
        raise NotImplementedError

    def collect_trace(self, ctx: SlkyContext, env: Dict[str, bytes], trace: Dict[str, bytes], name: str) -> bytes:
        val = self.eval(ctx, env)
        trace[name] = val
        return val


class ConstExpr(OuterExpr):
    def __init__(self, name: str):
        self.name = name

    def eval(self, ctx: SlkyContext, env: Dict[str, bytes]) -> bytes:
        if self.name not in env:
            raise KeyError(f"const {self.name} is not available")
        return env[self.name]

    def __str__(self):
        return self.name

    __repr__ = __str__


class BytesExpr(OuterExpr):
    def __init__(self, value: bytes, label: str = "bytes"):
        self.value = bytes(value)
        self.label = label

    def eval(self, ctx: SlkyContext, env: Dict[str, bytes]) -> bytes:
        return self.value

    def __str__(self):
        return self.label

    __repr__ = __str__


class SlkyExpr(OuterExpr):
    def __init__(self, a: OuterExpr, b: OuterExpr):
        self.a = a
        self.b = b

    def eval(self, ctx: SlkyContext, env: Dict[str, bytes]) -> bytes:
        return ctx.slky(self.a.eval(ctx, env), self.b.eval(ctx, env))

    def __str__(self):
        return f"slky({self.a}, {self.b})"

    __repr__ = __str__


class ConcatExpr(OuterExpr):
    def __init__(self, left: OuterExpr, right: OuterExpr):
        self.left = left
        self.right = right

    def eval(self, ctx: SlkyContext, env: Dict[str, bytes]) -> bytes:
        return self.left.eval(ctx, env) + self.right.eval(ctx, env)

    def __str__(self):
        return f"({self.left} + {self.right})"

    __repr__ = __str__


class OuterCandidate:
    def __init__(self, name: str, expr: OuterExpr, transform: str = "xor", confidence: int = 50, source: str = "manual"):
        self.name = name
        self.expr = expr
        self.transform = transform  # xor or direct
        self.confidence = confidence
        self.source = source

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        seed = self.expr.eval(ctx, env)
        if self.transform == "direct":
            outer_key = seed[:16]
        elif self.transform == "xor":
            outer_key = xor_repeat_prefix(seed, key_xor, 16)
        else:
            raise ValueError(f"unknown outer transform: {self.transform}")
        trace = {
            "base": env.get("base", b""),
            "seed": seed,
            "outer_seed": seed,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
        }
        # Keep old print path compatible.
        trace.setdefault("p19", b"")
        trace.setdefault("p24", b"")
        trace.setdefault("p25", seed)
        return outer_key, trace

    def signature(self) -> str:
        return f"{self.transform}:{self.expr}"

    def __str__(self):
        op = "xor_repeat(EXPR, KEY_XOR_CONST)[:16]" if self.transform == "xor" else "EXPR[:16]"
        return f"{self.name}: {op.replace('EXPR', str(self.expr))}"

    __repr__ = __str__



class FixedOuterCandidate(OuterCandidate):
    def __init__(self):
        r1 = SlkyExpr(ConstExpr("base"), ConstExpr("hidden"))
        r2 = SlkyExpr(r1, r1)
        r3 = SlkyExpr(r1, r2)
        super().__init__("fixed:p19_p24_p25", r3, transform="xor", confidence=100, source="fixed")

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        base = env["base"]
        hidden = env["hidden"]
        p19 = ctx.slky(base, hidden)
        p24 = ctx.slky(p19, p19)
        p25 = ctx.slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, key_xor, 16)
        trace = {
            "base": base,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
        }
        return outer_key, trace


class FixedVariantOuterCandidate(OuterCandidate):
    def __init__(self, second_name: str, confidence: int = 97, source: str = "template-armv7-burden1a"):
        self.second_name = second_name
        r1 = SlkyExpr(ConstExpr("base"), ConstExpr(second_name))
        r2 = SlkyExpr(r1, r1)
        r3 = SlkyExpr(r1, r2)
        super().__init__(f"template:fixed_base_{second_name}:p19_p24_p25", r3, transform="xor", confidence=confidence, source=source)

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        base = env["base"]
        second = env[self.second_name]
        p19 = ctx.slky(base, second)
        p24 = ctx.slky(p19, p19)
        p25 = ctx.slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, key_xor, 16)
        trace = {
            "base": base,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
        }
        return outer_key, trace


class NativeNoPostP25Candidate(OuterCandidate):
    """Native arm64/x86_64 burden1b shape:
       p19 = slky_no_post(A, B)
       p24 = slky_no_post(p19, p19)
       p25 = slky_no_post(p19, p24)
       outer_key = p25[:16]
    """
    def __init__(self, first_name: str, second_name: str, confidence: int = 90, source: str = "native-nopost"):
        self.first_name = first_name
        self.second_name = second_name
        r1 = SlkyExpr(ConstExpr(first_name), ConstExpr(second_name))
        r2 = SlkyExpr(r1, r1)
        r3 = SlkyExpr(r1, r2)
        super().__init__(f"native:nopost_{first_name}_{second_name}:p19_p24_p25:direct", r3, transform="direct", confidence=confidence, source=source)

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        nctx = NoPostSlkyContext()
        first = env[self.first_name]
        second = env[self.second_name]
        p19 = nctx.slky(first, second)
        p24 = nctx.slky(p19, p19)
        p25 = nctx.slky(p19, p24)
        outer_key = p25[:16]
        return outer_key, {
            "base": env.get("base", b""),
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
            "slky_variant": b"nopost",
            "member_ctx_hint": b"nopost",
        }


class NativeNoPostExprCandidate(OuterCandidate):
    """Evaluate an arbitrary static IR expression with no-post slky and use it directly."""
    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        nctx = NoPostSlkyContext()
        seed = self.expr.eval(nctx, env)
        outer_key = seed[:16] if self.transform == "direct" else xor_repeat_prefix(seed, key_xor, 16)
        return outer_key, {
            "base": env.get("base", b""),
            "seed": seed,
            "outer_seed": seed,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
            "slky_variant": b"nopost",
            "member_ctx_hint": b"nopost",
            "p19": b"",
            "p24": b"",
            "p25": seed,
        }



class NativePostP25Candidate(OuterCandidate):
    """Native x86 burden1b shape using the normal post-key slky and XOR transform.

    Observed shape:
        p19 = native/idbfj-derived slky(A, B)
        p24 = slky(p19, p19)
        p25 = slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, KEY_XOR_CONST, 16)
    """
    def __init__(self, first_name: str, second_name: str, confidence: int = 91, source: str = "native-post"):
        self.first_name = first_name
        self.second_name = second_name
        r1 = SlkyExpr(ConstExpr(first_name), ConstExpr(second_name))
        r2 = SlkyExpr(r1, r1)
        r3 = SlkyExpr(r1, r2)
        super().__init__(f"native:post_{first_name}_{second_name}:p19_p24_p25:xor", r3, transform="xor", confidence=confidence, source=source)

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        first = env[self.first_name]
        second = env[self.second_name]
        p19 = ctx.slky(first, second)
        p24 = ctx.slky(p19, p19)
        p25 = ctx.slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, key_xor, 16)
        return outer_key, {
            "base": env.get("base", b""),
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
            "slky_variant": b"post",
        }


def _idbfj_pick6(data: bytes) -> int:
    if not data:
        return 0
    signed_sum = len(data) + sum(s8(x) for x in data)
    v = signed_sum + s8(data[0]) * s8(data[-1])
    # C/C++ signed remainder via truncating division.
    return v - c_div(v, 6) * 6


class NativeX86IdbfjP25Candidate(OuterCandidate):
    """Recovered x86 idbfj + burden1b outer-key model.

    idbfj(input) builds:
        base = hidden + versionName + package + appLabel + versionCode + fb
        first = base              when input is empty
                base + input      otherwise
        pick = (len(first)+sum_s8(first)+s8(first[0])*s8(first[-1])) % 6 using C signed division
        second = [versionName, package, appLabel, versionCode, hidden, fb][pick]
        p19 = slky(first, second)
    burden1b then computes p24/p25 and XORs with KEY_XOR_CONST for AES.
    """
    def __init__(self, input_name: str, confidence: int = 98, source: str = "native-x86-idbfj"):
        self.input_name = input_name
        super().__init__(f"native:x86_idbfj_{input_name}:p19_p24_p25:xor", ConstExpr("base"), transform="xor", confidence=confidence, source=source)

    def signature(self) -> str:
        return f"x86-idbfj:{self.input_name}:post:p25:xor"

    def __str__(self):
        return f"native:x86_idbfj_{self.input_name}: outer_key=xor_repeat(p25, KEY_XOR_CONST)[:16] where p19=idbfj({self.input_name}), p24=slky(p19,p19), p25=slky(p19,p24)"

    __repr__ = __str__

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        if (self.input_name.startswith("user_password") or self.input_name == "password") and not env.get(self.input_name):
            raise ValueError(f"missing {self.input_name} env")
        inp, first, pick, second = _idbfj_prepare(env, self.input_name)
        base = env["base"]
        p19 = ctx.slky(first, second)
        p24 = ctx.slky(p19, p19)
        p25 = ctx.slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, key_xor, 16)
        return outer_key, {
            "base": base,
            "idbfj_input": inp,
            "idbfj_first": first,
            "idbfj_pick": str(pick).encode(),
            "idbfj_second": second,
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
            "slky_variant": b"post",
        }



class NativeX86IdbfjSignatureP25Candidate(OuterCandidate):
    """x86 idbfj p19 with Android signature participating in p24.

    For samples whose Java helper says signature verification is enabled:
        p19 = idbfj(input)
        p24 = slky(signature_bytes, p19)
        p25 = slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, KEY_XOR_CONST, 16)
    When signature is disabled, the older NativeX86IdbfjP25Candidate is used:
        p24 = slky(p19, p19)
    """
    def __init__(self, input_name: str, signature_name: str = "signature", confidence: int = 97, source: str = "native-x86-idbfj-signature"):
        self.input_name = input_name
        self.signature_name = signature_name
        super().__init__(f"native:x86_idbfj_{input_name}:signature_{signature_name}:p19_sig_p25:xor", ConstExpr("base"), transform="xor", confidence=confidence, source=source)

    def signature(self) -> str:
        return f"x86-idbfj:{self.input_name}:post:p24sig:{self.signature_name}:xor"

    def __str__(self):
        return f"native:x86_idbfj_{self.input_name}: outer_key=xor_repeat(p25, KEY_XOR_CONST)[:16] where p19=idbfj({self.input_name}), p24=slky({self.signature_name},p19), p25=slky(p19,p24)"

    __repr__ = __str__

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        if self.signature_name not in env or not env[self.signature_name]:
            raise ValueError(f"missing signature env: {self.signature_name}")
        if (self.input_name.startswith("user_password") or self.input_name == "password") and not env.get(self.input_name):
            raise ValueError(f"missing {self.input_name} env")
        inp, first, pick, second = _idbfj_prepare(env, self.input_name)
        base = env["base"]
        p19 = ctx.slky(first, second)
        sig = env[self.signature_name]
        p24 = ctx.slky(sig, p19)
        p25 = ctx.slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, key_xor, 16)
        return outer_key, {
            "base": base,
            "idbfj_input": inp,
            "idbfj_first": first,
            "idbfj_pick": str(pick).encode(),
            "idbfj_second": second,
            "signature_mode": env.get("signature_mode", b"verify"),
            "signature_source": env.get("signature_source", b""),
            "signature_len": str(len(sig)).encode(),
            "signature_sha1": hashlib.sha1(sig).hexdigest().encode(),
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
            "slky_variant": b"post",
        }


class FixedSignatureOuterCandidate(OuterCandidate):
    """Old fixed p19 with signature-aware p24 fallback."""
    def __init__(self, signature_name: str = "signature", confidence: int = 93, source: str = "fixed-signature"):
        self.signature_name = signature_name
        super().__init__(f"fixed:signature_{signature_name}:p19_sig_p25:xor", ConstExpr("base"), transform="xor", confidence=confidence, source=source)

    def signature(self) -> str:
        return f"fixed:post:p24sig:{self.signature_name}:xor"

    def __str__(self):
        return f"fixed: outer_key=xor_repeat(p25, KEY_XOR_CONST)[:16] where p19=slky(base,hidden), p24=slky({self.signature_name},p19), p25=slky(p19,p24)"

    __repr__ = __str__

    def derive(self, ctx: SlkyContext, key_xor: bytes, env: Dict[str, bytes]) -> Tuple[bytes, Dict[str, bytes]]:
        if self.signature_name not in env or not env[self.signature_name]:
            raise ValueError(f"missing signature env: {self.signature_name}")
        base = env["base"]
        hidden = env["hidden"]
        sig = env[self.signature_name]
        p19 = ctx.slky(base, hidden)
        p24 = ctx.slky(sig, p19)
        p25 = ctx.slky(p19, p24)
        outer_key = xor_repeat_prefix(p25, key_xor, 16)
        return outer_key, {
            "base": base,
            "signature_mode": env.get("signature_mode", b"verify"),
            "signature_source": env.get("signature_source", b""),
            "signature_len": str(len(sig)).encode(),
            "signature_sha1": hashlib.sha1(sig).hexdigest().encode(),
            "p19": p19,
            "p24": p24,
            "p25": p25,
            "seed": p25,
            "outer_seed": p25,
            "outer_key": outer_key,
            "algorithm": str(self).encode("utf-8", "replace"),
            "slky_variant": b"post",
        }

@lru_cache(maxsize=4096)
def _outer_env_static_cached(package: str, version_name: str, version_code_s: str, app_label: str) -> Tuple[bytes, bytes, bytes, bytes, bytes]:
    """Cache enum-invariant encoded metadata.

    The old hot path repeatedly called str()/encode()/parse_int_auto() for every
    sokey or dexkey candidate.  Enumeration now only allocates the few byte
    strings that actually depend on hidden/f.b().
    """
    pkg_b = str(package).encode()
    vn_b = str(version_name).encode()
    vc_b = str(version_code_s).encode()
    label_b = str(app_label).encode()
    no_fb = vn_b + pkg_b + label_b + vc_b
    return pkg_b, vn_b, vc_b, label_b, no_fb


def build_outer_env(hidden: bytes, package: str, version_name: str, version_code, app_label: str, fb_value) -> Dict[str, bytes]:
    vc_s = str(parse_int_auto(version_code))
    fb_b = str(parse_int_auto(fb_value)).encode()
    pkg_b, vn_b, vc_b, label_b, no_fb = _outer_env_static_cached(
        str(package), str(version_name), vc_s, str(app_label)
    )
    base_tail = no_fb + fb_b
    return {
        "hidden": hidden,
        "package": pkg_b,
        "versionName": vn_b,
        "versionCode": vc_b,
        "appLabel": label_b,
        "fb": fb_b,
        "empty": b"",
        "mian": b"mian.iyu",
        "dot_mjs": b".mjs",
        "lib_so": b"lib.so",
        "jgapp": b"",
        "hidden_fb": hidden + fb_b,
        "fb_hidden": fb_b + hidden,
        "base_tail": base_tail,
        "base": hidden + base_tail,
        "base_no_fb": hidden + no_fb,
        "meta_no_hidden": base_tail,
    }


def fixed_outer_candidate() -> OuterCandidate:
    # Old, known-good formula for old samples. Uses a subclass so p19/p24/p25 stay in trace.
    return FixedOuterCandidate()


def _dedup_exprs(exprs: List[OuterExpr], limit: int = 200) -> List[OuterExpr]:
    seen = set()
    out: List[OuterExpr] = []
    for e in exprs:
        sig = str(e)
        if sig in seen:
            continue
        seen.add(sig)
        out.append(e)
        if len(out) >= limit:
            break
    return out


def _source_expr_choices(src: str, results: Dict[str, List[OuterExpr]], broad: bool = False) -> List[OuterExpr]:
    src = (src or "").strip()
    if src in results:
        return results[src]
    # Direct call results from the light backtracer.
    m = re.fullmatch(r"result\((slky|operator\+)#(\d+)\)", src)
    if m:
        key = f"{m.group(1)}#{m.group(2)}"
        if key in results:
            return results[key]
    m = re.fullmatch(r"result\(([^)]+)\)", src)
    if m and m.group(1) in results:
        return results[m.group(1)]

    # Stack std::string objects cannot be decoded without deeper constructor tracking yet.
    # Map them to a small semantic pool. Ordered by likelihood for outer generation.
    if src.startswith("stack_string_") or src.startswith("stack_slot_") or src.startswith("local_") or src.startswith("mem[") or src.endswith(":unresolved") or src.startswith("x"):
        names = ["base", "hidden", "base_tail", "hidden_fb", "fb_hidden", "package", "appLabel", "versionName", "versionCode", "fb"]
        if broad:
            names += ["base_no_fb", "meta_no_hidden", "empty"]
        return [ConstExpr(n) for n in names]

    if src.startswith("#"):
        return [BytesExpr(src.encode(), src)]

    # Recognize a few textual names if the IR already contains them.
    low = src.lower()
    for name in ("base", "hidden", "package", "applabel", "versionname", "versioncode", "fb"):
        if name.lower() in low:
            canonical = {"applabel": "appLabel", "versionname": "versionName", "versioncode": "versionCode"}.get(name, name)
            return [ConstExpr(canonical)]

    return [ConstExpr("base"), ConstExpr("hidden")]


def generate_template_outer_candidates() -> List[OuterCandidate]:
    """
    Controlled outer-algorithm templates used only after fixed fails.

    This is intentionally NOT a blind brute force.  It covers the shapes seen in
    burden1a-style native code and the shape described by the static IR:

        R1 = slky(A, B)
        R2 = slky(R1, R1)
        R3 = R1 + R2          or R2 + R1
        R4 = slky(R3, C)      or nearby variants
        outer_key = xor_repeat_prefix(R4, KEY_XOR_CONST, 16)

    The candidate list stays small and every candidate is verified by AES +
    mian.iyu marker checks.
    """
    out: List[OuterCandidate] = []
    base = ConstExpr("base")
    base_no_fb = ConstExpr("base_no_fb")
    base_tail = ConstExpr("base_tail")
    meta_no_hidden = ConstExpr("meta_no_hidden")
    hidden = ConstExpr("hidden")
    hidden_fb = ConstExpr("hidden_fb")
    fb_hidden = ConstExpr("fb_hidden")
    fb = ConstExpr("fb")
    package = ConstExpr("package")
    app_label = ConstExpr("appLabel")
    version_name = ConstExpr("versionName")
    version_code = ConstExpr("versionCode")

    # Native arm64/x86_64 burden1b shape observed in 简源_1.3.6:
    #   p19 = idbfj(...)
    #   p24 = slky_no_post(p19, p19)
    #   p25 = slky_no_post(p19, p24)
    #   asendn(container, p25, 2)
    # idbfj selects metadata-dependent second arguments, so keep this bounded
    # but cover all package/version/label/fb/hidden branches.
    first_names = ["base", "base_tail", "base_no_fb", "meta_no_hidden", "hidden", "hidden_fb", "fb_hidden"]
    second_names = ["versionName", "package", "appLabel", "versionCode", "fb", "hidden", "base_tail", "base"]
    for fn in first_names:
        for sn in second_names:
            conf = 96 if (fn == "base" and sn in ("versionCode", "versionName", "package", "appLabel")) else 72
            out.append(NativeNoPostP25Candidate(fn, sn, confidence=conf))
            # x86 builds can use the same p19/p24/p25 shape but with normal
            # SLKY_POST_KEY and KEY_XOR_CONST xor. Keep it bounded and verified.
            out.append(NativePostP25Candidate(fn, sn, confidence=max(55, conf - 4)))

    # x86 burden1b with idbfj(input) feeding p19, then p24/p25.  The actual
    # Java h2 input is app-dependent, so try a tiny semantic set only.
    idbfj_inputs: List[Tuple[str, int]] = []
    if _EXTRA_OUTER_ENV.get("user_password_native"):
        idbfj_inputs.append(("user_password_native", 112))
        for i in range(1, 8):
            k = f"user_password_native_{i}"
            if _EXTRA_OUTER_ENV.get(k):
                idbfj_inputs.append((k, 111 - i))
    if _EXTRA_OUTER_ENV.get("user_password"):
        idbfj_inputs.extend([("user_password", 101), ("password", 100)])
    idbfj_inputs.extend([("hidden", 99), ("jgapp", 95), ("mian", 86), ("empty", 82), ("package", 72), ("appLabel", 70), ("lib_so", 66), ("dot_mjs", 62)])
    have_signature = bool(_EXTRA_OUTER_ENV.get("signature"))
    for input_name, conf in idbfj_inputs:
        out.append(NativeX86IdbfjP25Candidate(input_name, confidence=conf))
        if have_signature:
            sig_conf = conf + 1 if input_name.startswith("user_password") or input_name in ("password", "hidden") else max(60, conf - 2)
            out.append(NativeX86IdbfjSignatureP25Candidate(input_name, "signature", confidence=sig_conf))
    if have_signature:
        out.append(FixedSignatureOuterCandidate("signature", confidence=94))

    # ARMv7/ARM64 burden1a post-loop shape observed in dome.apk:
    #   p19 = idbfj(meta, key_string)
    #   p24 = slky(p19, p19)
    #   p25 = slky(p19, p24)
    # In this sample idbfj(meta, key_string) collapses to slky(base, versionName),
    # not slky(base, hidden). Keep the old fixed formula separate; this is a
    # static-template candidate verified before use.
    for second_name, conf in [("versionName", 99), ("appLabel", 70), ("package", 66), ("fb", 64), ("versionCode", 62)]:
        out.append(FixedVariantOuterCandidate(second_name, confidence=conf))

    # Exact shape found in the uploaded x86 burden1a:
    #   tmp = A + B
    #   seed = slky(tmp, A)
    #   outer_key = xor_repeat(seed, KEY_XOR_CONST)[:16]
    # The old template set missed this "concat-before-slky" shape and therefore
    # tried hundreds of wrong slky(slky(...), ...) variants.
    concat_pairs = [
        (hidden, base_tail, "hidden_baseTail"),      # slky(base, hidden)
        (hidden, meta_no_hidden, "hidden_meta"),     # same bytes, kept explicit in reports
        (base_tail, hidden, "baseTail_hidden"),
        (base, hidden, "base_hidden"),
        (hidden, base, "hidden_base"),
        (base_no_fb, hidden, "baseNoFb_hidden"),
        (hidden, base_no_fb, "hidden_baseNoFb"),
        (hidden_fb, base_tail, "hiddenfb_baseTail"),
        (base_tail, hidden_fb, "baseTail_hiddenfb"),
    ]
    for a, b, tag in concat_pairs:
        joined_ab = ConcatExpr(a, b)
        joined_ba = ConcatExpr(b, a)
        for seed, st, conf in [
            (SlkyExpr(joined_ab, a), "slky_ab_a", 98),
            (SlkyExpr(joined_ab, b), "slky_ab_b", 82),
            (SlkyExpr(joined_ba, b), "slky_ba_b", 78),
            (SlkyExpr(joined_ba, a), "slky_ba_a", 72),
            (SlkyExpr(a, b), "slky_a_b_direct_shape", 88),
        ]:
            out.append(OuterCandidate(f"template:{tag}:{st}", seed, "xor", conf, "template-x86-burden1a"))
            out.append(OuterCandidate(f"template:{tag}:{st}:direct", seed, "direct", max(25, conf - 45), "template-x86-burden1a"))

    seed_pairs = [
        (base, hidden, "base_hidden"),
        (hidden, base, "hidden_base"),
        (base_no_fb, hidden, "baseNoFb_hidden"),
        (base_tail, hidden, "baseTail_hidden"),
        (hidden, base_tail, "hidden_baseTail"),
        (base, hidden_fb, "base_hiddenfb"),
        (base, fb_hidden, "base_fbhidden"),
        (hidden_fb, base, "hiddenfb_base"),
    ]
    tail_pool = [
        (hidden, "hidden"), (base, "base"), (base_no_fb, "baseNoFb"), (base_tail, "baseTail"),
        (hidden_fb, "hiddenfb"), (fb_hidden, "fbhidden"), (fb, "fb"),
        (package, "package"), (app_label, "appLabel"),
    ]
    for a, b, tag in seed_pairs:
        r1 = SlkyExpr(a, b)
        r2 = SlkyExpr(r1, r1)

        # Legacy-compatible fixed seed plus a direct variant for samples where
        # the native code already applies/omits the xor loop before asendn.
        out.append(OuterCandidate(f"template:{tag}:old_slky_r1_r2", SlkyExpr(r1, r2), "xor", 82, "template"))
        out.append(OuterCandidate(f"template:{tag}:old_slky_r1_r2:direct", SlkyExpr(r1, r2), "direct", 38, "template"))

        joined12 = ConcatExpr(r1, r2)
        joined21 = ConcatExpr(r2, r1)
        for joined, jtag, jconf in [(joined12, "concat12", 74), (joined21, "concat21", 58)]:
            out.append(OuterCandidate(f"template:{tag}:{jtag}:seed_xor", joined, "xor", jconf - 8, "template"))
            out.append(OuterCandidate(f"template:{tag}:{jtag}:seed_direct", joined, "direct", 30, "template"))
            for c, ctag in tail_pool + [(r1, "r1"), (r2, "r2"), (joined, "joined")]:
                out.append(OuterCandidate(f"template:{tag}:{jtag}_slky_{ctag}", SlkyExpr(joined, c), "xor", jconf, "template"))
                out.append(OuterCandidate(f"template:{tag}:{jtag}_slky_{ctag}:direct", SlkyExpr(joined, c), "direct", max(25, jconf - 35), "template"))

        # A few nearby slky graph variants observed in optimized C++ string code.
        for e, etag, conf in [
            (SlkyExpr(r2, r1), "slky_r2_r1", 55),
            (SlkyExpr(r2, r2), "slky_r2_r2", 48),
            (SlkyExpr(r1, joined12), "slky_r1_joined12", 48),
            (SlkyExpr(joined12, joined12), "slky_joined12_joined12", 45),
        ]:
            out.append(OuterCandidate(f"template:{tag}:{etag}", e, "xor", conf, "template"))
            out.append(OuterCandidate(f"template:{tag}:{etag}:direct", e, "direct", max(20, conf - 30), "template"))
    return out


def generate_static_outer_candidates(analyzer: Optional[StaticOuterAnalyzer]) -> List[OuterCandidate]:
    if analyzer is None:
        return []
    # Ensure level-2 data exists.
    if not analyzer.slky_reports and not analyzer.asendn_reports:
        try:
            analyzer.trace_slky_args = True
            analyzer.trace_asendn_args = True
            analyzer.dump_report(analyzer.outdir / "outer_static_ir.txt", write=False)
        except Exception:
            pass

    results: Dict[str, List[OuterExpr]] = {}
    candidates: List[OuterCandidate] = []

    # For candidate recovery, keep call-result numbering within burden1a.
    # Recursive idbfj reports are still useful in the IR, but their slky#1/#2
    # numbering is local to idbfj and must not overwrite burden1a slky#N.
    candidate_slky_reports = [r for r in analyzer.slky_reports if r.get("func") in ("burden1b", "burden1a")] or list(analyzer.slky_reports)
    candidate_asendn_reports = [r for r in analyzer.asendn_reports if r.get("func") in ("burden1b", "burden1a")] or list(analyzer.asendn_reports)

    for r in candidate_slky_reports:
        idx = r.get("idx")
        if isinstance(idx, int):
            a_choices = _source_expr_choices(r.get("arg1", ""), results)
            b_choices = _source_expr_choices(r.get("arg2", ""), results)
            exprs = []
            for a in a_choices[:20]:
                for b in b_choices[:20]:
                    exprs.append(SlkyExpr(a, b))
            results[f"slky#{idx}"] = _dedup_exprs(exprs, 160)
        elif isinstance(idx, str) and idx.startswith("operator+#"):
            plus_no = idx.split("#", 1)[1]
            l_choices = _source_expr_choices(r.get("left", ""), results)
            rr_choices = _source_expr_choices(r.get("right", ""), results)
            exprs = []
            for l in l_choices[:80]:
                for rr in rr_choices[:80]:
                    exprs.append(ConcatExpr(l, rr))
            exprs = _dedup_exprs(exprs, 200)
            results[f"operator+#{plus_no}"] = exprs
            dest = r.get("dest")
            if dest:
                results[dest] = exprs

    # Prefer asendn(mode=1) key source; still keep other asendn calls as lower confidence.
    as_reports = list(candidate_asendn_reports)
    as_reports.sort(key=lambda r: (0 if str(r.get("x3_mode")) == "#1" else 1, r.get("idx", 999)))
    for r in as_reports:
        key_exprs = _source_expr_choices(r.get("x2_key", ""), results, broad=True)
        mode = str(r.get("x3_mode", "?"))
        conf = 95 if mode == "#1" else 60
        for i, e in enumerate(key_exprs[:200]):
            candidates.append(OuterCandidate(f"static:asendn{r.get('idx')}:x2:{i}", e, "xor", conf, "asendn"))
            candidates.append(OuterCandidate(f"static:asendn{r.get('idx')}:x2:{i}:direct", e, "direct", max(20, conf - 35), "asendn"))
            candidates.append(NativeNoPostExprCandidate(f"static:nopost:asendn{r.get('idx')}:x2:{i}:direct", e, "direct", max(35, conf - 10), "asendn-nopost"))

    # If asendn is unresolved, each later slky result can still be a likely key seed.
    for key, exprs in results.items():
        if key.startswith("slky#"):
            try:
                num = int(key.split("#", 1)[1])
            except Exception:
                num = 0
            conf = 65 + min(num, 4)
            for i, e in enumerate(exprs[:80]):
                candidates.append(OuterCandidate(f"static:{key}:seed:{i}", e, "xor", conf, "slky"))
                candidates.append(NativeNoPostExprCandidate(f"static:nopost:{key}:seed:{i}:direct", e, "direct", max(30, conf - 5), "slky-nopost"))

    candidates.extend(generate_template_outer_candidates())
    candidates.sort(key=lambda c: (-c.confidence, c.name))
    # Deduplicate by expression+transform.
    seen = set()
    out: List[OuterCandidate] = []
    for c in candidates:
        sig = c.signature()
        if sig in seen:
            continue
        seen.add(sig)
        out.append(c)
        if len(out) >= 900:
            break
    return out


def verify_outer_candidate(
    candidate: OuterCandidate,
    post_key: bytes,
    key_xor: bytes,
    hidden: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    fb_value,
    use_c: bool = False,
    c_path: str = "./libiapp_core.so",
    diag: Optional[DecryptDiag] = None,
    tag: str = "",
    ctx: Optional[SlkyContext] = None,
    env: Optional[Dict[str, bytes]] = None,
    nopost_ctx: Optional[NoPostSlkyContext] = None,
    shell_probe_only: bool = False,
) -> Optional[Tuple[bytes, bytes, Dict[str, bytes], bytes]]:
    prefix = f"verify {tag}/{candidate.name}".strip()
    if env is None:
        env = build_outer_env(hidden, package, version_name, version_code, app_label, fb_value)
        if _EXTRA_OUTER_ENV:
            env.update(_EXTRA_OUTER_ENV)
    if ctx is None:
        try:
            ctx = SlkyContext(post_key, use_c=use_c, c_path=c_path)
        except Exception as e:
            if diag:
                diag.fail(prefix, f"create SlkyContext failed: {type(e).__name__}: {e}")
            return None
    t_outer_key = time.perf_counter()
    try:
        outer_key, trace = candidate.derive(ctx, key_xor, env)
        trace["timing_outer_key_ms"] = f"{ms_since(t_outer_key):.3f}".encode()
    except Exception as e:
        if diag:
            diag.fail(prefix, f"candidate eval failed: {type(e).__name__}: {e}; algorithm={candidate}")
        return None
    t_outer_dec = time.perf_counter()
    if not aes_cbc_pkcs7_padding_maybe_valid(container, outer_key):
        trace["timing_outer_decrypt_ms"] = f"{ms_since(t_outer_dec):.3f}".encode()
        if diag:
            diag.fail(prefix, f"outer AES fast padding reject; outer_key={outer_key.hex()}; algorithm={candidate}")
        return None
    try:
        container_plain = aes_cbc_then_xor_decrypt(container, outer_key)
        trace["timing_outer_decrypt_ms"] = f"{ms_since(t_outer_dec):.3f}".encode()
    except Exception as e:
        if diag:
            diag.fail(prefix, f"outer AES decrypt failed after fast padding pass: {type(e).__name__}: {e}; outer_key={outer_key.hex()}; algorithm={candidate}")
        return None
    if shell_probe_only:
        # Key enumeration hot path: only prove that the outer shell can be
        # decrypted.  Do not decrypt/verify mian.iyu for every candidate; the
        # caller finalizes the first outer-shell hit and then performs the full
        # decrypt exactly once with the selected key.
        trace["shell_probe_only"] = b"1"
        if diag:
            diag.ok(prefix, f"outer-shell decrypted; outer_key={outer_key.hex()} algorithm={candidate}")
        return outer_key, container_plain, trace, b""
    t_member_verify = time.perf_counter()
    try:
        marker_contexts: List[Tuple[str, SlkyContext]] = [("post", ctx)]
        marker_contexts.append(("nopost", nopost_ctx or NoPostSlkyContext()))
        if trace.get("member_ctx_hint") == b"nopost":
            marker_contexts = [marker_contexts[1], marker_contexts[0]]
        verified_member = None
        verified_name = ""
        last_member_error = ""
        for main_name in _enum_main_probe_name_list():
            for marker_name, marker_ctx in marker_contexts:
                try:
                    start, end = member_markers(marker_ctx, main_name, hidden, fb_value)
                    s = container_plain.find(start)
                    if s < 0:
                        last_member_error = f"{marker_name}/{main_name}: start marker not found"
                        continue
                    data_start = s + len(start)
                    e = container_plain.find(end, data_start)
                    if e < 0:
                        last_member_error = f"{marker_name}/{main_name}: end marker not found at start_offset=0x{s:x}"
                        continue
                    ciphertext = container_plain[data_start:e]
                    if len(ciphertext) % 16:
                        last_member_error = f"{marker_name}/{main_name}: ciphertext not block aligned len={len(ciphertext)}"
                        continue
                    seed = marker_ctx.slky(main_name.encode() + hidden + str(parse_int_auto(fb_value)).encode(), main_name.encode())
                    member_keys = [("xor", xor_repeat(seed, key_xor)[:16]), ("direct", seed[:16])]
                    for key_mode, member_key in member_keys:
                        try:
                            plain_try = aes_cbc_then_xor_decrypt(ciphertext, member_key)
                        except Exception as me:
                            last_member_error = f"{marker_name}/{main_name}/{key_mode}: {type(me).__name__}: {me}"
                            continue
                        if looks_like_iapp_plain(plain_try):
                            trace["member_ctx"] = marker_name.encode()
                            trace["member_key_mode"] = key_mode.encode()
                            trace["member_key"] = member_key
                            trace["main_file"] = main_name.encode("utf-8", "replace")
                            verified_member = plain_try
                            verified_name = main_name
                            break
                    if verified_member is not None:
                        break
                except Exception as inner:
                    last_member_error = f"{marker_name}/{main_name}: {type(inner).__name__}: {inner}"
                    continue
            if verified_member is not None:
                break
        if verified_member is None:
            if diag:
                diag.fail(prefix, f"main-entry verification failed ({last_member_error}); outer_key={outer_key.hex()}; algorithm={candidate}")
            return None
        trace["verified_member"] = verified_name.encode("utf-8", "replace")
        mian_plain = verified_member
    except Exception as e:
        if diag:
            diag.fail(prefix, f"member verification failed: {type(e).__name__}: {e}; outer_key={outer_key.hex()}; algorithm={candidate}")
        return None
    trace["timing_mian_candidate_verify_ms"] = f"{ms_since(t_member_verify):.3f}".encode()
    if diag:
        diag.ok(prefix, f"verified; outer_key={outer_key.hex()} algorithm={candidate}")
    return outer_key, container_plain, trace, mian_plain


class OuterResolver:
    def __init__(
        self,
        so_data: bytes,
        hidden: bytes,
        container: bytes,
        package: str,
        version_name: str,
        version_code,
        app_label: str,
        fb_value,
        outer_mode: str = "fixed",
        outdir: Path = Path("out"),
        analyzer: Optional[StaticOuterAnalyzer] = None,
        use_c: bool = False,
        c_path: str = "./libiapp_core.so",
        debug_candidates: bool = False,
        dump_outer_candidates: bool = False,
    ):
        self.so_data = so_data
        self.hidden = hidden
        self.container = container
        self.package = package
        self.version_name = version_name
        self.version_code = version_code
        self.app_label = app_label
        self.fb_value = fb_value
        self.outer_mode = outer_mode
        self.outdir = outdir
        self.analyzer = analyzer
        self.use_c = use_c
        self.c_path = c_path
        self.debug_candidates = debug_candidates
        self.dump_outer_candidates = dump_outer_candidates
        self._candidate_cache: Optional[List[OuterCandidate]] = None
        self._candidate_dumped = False

    def _ensure_analyzer(self) -> StaticOuterAnalyzer:
        if self.analyzer is None:
            self.analyzer = run_static_outer_analysis(self.so_data, self.outdir, True, True, True)
        if self.analyzer is None:
            raise RuntimeError("static analyzer unavailable")
        return self.analyzer

    def candidates(self) -> List[OuterCandidate]:
        if self._candidate_cache is not None:
            return self._candidate_cache
        t_cands = time.perf_counter()
        cands: List[OuterCandidate] = []
        if self.outer_mode in ("fixed", "auto"):
            cands.append(fixed_outer_candidate())
        if self.outer_mode == "static":
            analyzer = self._ensure_analyzer()
            cands.extend(generate_static_outer_candidates(analyzer))
        elif self.outer_mode == "auto":
            # ABI-specific candidates describe how the supplied key pair is used;
            # they do not extract the key constants.  Keep them available even in
            # --no-dynamic-key mode so default and selected-pool samples using newer
            # outer formulas remain decryptable.
            try:
                if self.so_data and _so_has_dynamic_outer_symbols_any(self.so_data):
                    cands.extend(_native_multiabi_priority_candidates(self.so_data))
            except Exception:
                pass
            if self.analyzer is not None:
                cands.extend(generate_static_outer_candidates(self.analyzer))
            else:
                # Fast default: try the bounded template set first.  Full SO IR
                # analysis is deferred until every template/key pair fails.
                cands.extend(generate_template_outer_candidates())
        # Dedup, keep confidence order.
        cands.sort(key=lambda c: (-c.confidence, c.name))
        seen = set()
        out = []
        for c in cands:
            sig = c.signature()
            if sig in seen:
                continue
            seen.add(sig)
            out.append(c)
        self._candidate_cache = out
        print(f"[T] outer candidates build   {ms_since(t_cands):.3f} ms")
        return out

    def dump_candidates(self, cands: List[OuterCandidate]) -> Path:
        self.outdir.mkdir(parents=True, exist_ok=True)
        path = self.outdir / "outer_candidates.txt"
        lines = ["# outer candidates", f"count={len(cands)}", ""]
        for i, c in enumerate(cands):
            lines.append(f"candidate#{i} confidence={c.confidence} source={c.source}")
            lines.append(f"  {c}")
        path.write_text("\n".join(lines), encoding="utf-8")
        print(f"[+] outer candidates written: {path}")
        return path

    def resolve(self, post_key: bytes, key_xor: bytes, diag: Optional[DecryptDiag] = None, tag: str = "", shell_probe_only: bool = False) -> Optional[Tuple[bytes, bytes, Dict[str, bytes], bytes]]:
        try:
            cands = self.candidates()
        except Exception as e:
            if diag:
                diag.fail(f"outer resolver {tag}", f"candidate generation failed: {type(e).__name__}: {e}")
            return None
        if diag:
            diag.ok(f"outer candidates {tag}", f"count={len(cands)} mode={self.outer_mode}")
        if self.dump_outer_candidates and not self._candidate_dumped:
            self.dump_candidates(cands)
            self._candidate_dumped = True
        max_fail_log = 50 if self.debug_candidates else 12
        env = build_outer_env(self.hidden, self.package, self.version_name, self.version_code, self.app_label, self.fb_value)
        if _EXTRA_OUTER_ENV:
            env.update(_EXTRA_OUTER_ENV)
        try:
            shared_ctx = SlkyContext(post_key, use_c=self.use_c, c_path=self.c_path)
        except Exception as e:
            if diag:
                diag.fail(f"outer resolver {tag}", f"create shared SlkyContext failed: {type(e).__name__}: {e}")
            return None
        shared_nopost_ctx = NoPostSlkyContext()
        t_verify_all = time.perf_counter()
        for i, cand in enumerate(cands):
            local_diag = diag if (self.debug_candidates or i < max_fail_log) else None
            ok = verify_outer_candidate(
                cand, post_key, key_xor, self.hidden, self.container,
                self.package, self.version_name, self.version_code, self.app_label, self.fb_value,
                use_c=self.use_c, c_path=self.c_path, diag=local_diag, tag=tag or "outer",
                ctx=shared_ctx, env=env, nopost_ctx=shared_nopost_ctx,
                shell_probe_only=shell_probe_only,
            )
            if ok:
                print(f"[T] outer verify loop       {ms_since(t_verify_all):.3f} ms")
                return ok
        print(f"[T] outer verify loop       {ms_since(t_verify_all):.3f} ms")
        if diag:
            diag.fail(f"outer resolver {tag}", f"all outer candidates failed: {len(cands)}")
        return None

def verify_key_pair(
    post_key: bytes,
    key_xor: bytes,
    hidden: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    fb_value,
    use_c: bool = False,
    c_path: str = "./libiapp_core.so",
    diag: Optional[DecryptDiag] = None,
    tag: str = "",
) -> Optional[Tuple[bytes, bytes, Dict[str, bytes], bytes]]:
    prefix = f"verify {tag}".strip()

    try:
        ctx = SlkyContext(post_key, use_c=use_c, c_path=c_path)
    except Exception as e:
        if diag:
            diag.fail(prefix, f"create SlkyContext failed: {type(e).__name__}: {e}")
        return None

    try:
        outer_key, trace = derive_outer_key(ctx, key_xor, hidden, package, version_name, version_code, app_label, fb_value)
    except Exception as e:
        if diag:
            diag.fail(prefix, f"derive outer key failed: {type(e).__name__}: {e}")
        return None

    if not aes_cbc_pkcs7_padding_maybe_valid(container, outer_key):
        if diag:
            diag.fail(prefix, f"outer AES fast padding reject; outer_key={outer_key.hex()}")
        return None
    try:
        container_plain = aes_cbc_then_xor_decrypt(container, outer_key)
    except Exception as e:
        if diag:
            diag.fail(prefix, f"outer AES decrypt failed after fast padding pass: {type(e).__name__}: {e}; outer_key={outer_key.hex()}")
        return None

    last_error = ""
    for main_name in _enum_main_probe_name_list():
        try:
            start, end = member_markers(ctx, main_name, hidden, fb_value)
            s = container_plain.find(start)
            if s < 0:
                continue
            data_start = s + len(start)
            e = container_plain.find(end, data_start)
            if e < 0:
                last_error = f"{main_name}: end marker missing"
                continue
            ciphertext = container_plain[data_start:e]
            if not ciphertext or len(ciphertext) % 16:
                last_error = f"{main_name}: bad ciphertext length {len(ciphertext)}"
                continue
            for key_mode in ("xor", "direct"):
                try:
                    seed = ctx.slky(main_name.encode() + hidden + str(parse_int_auto(fb_value)).encode(), main_name.encode())
                    member_key = xor_repeat(seed, key_xor)[:16] if key_mode == "xor" else seed[:16]
                    plain = aes_cbc_then_xor_decrypt(ciphertext, member_key)
                except Exception as exc:
                    last_error = f"{main_name}/{key_mode}: {type(exc).__name__}: {exc}"
                    continue
                if not looks_like_iapp_plain(plain):
                    continue
                trace["main_file"] = main_name.encode("utf-8", "replace")
                trace["verified_member"] = main_name.encode("utf-8", "replace")
                trace["member_ctx"] = b"post"
                trace["member_key_mode"] = key_mode.encode()
                if diag:
                    diag.ok(prefix, f"verified; outer_key={outer_key.hex()} main={main_name} len={len(plain)} marker_offset=0x{s:x}")
                return outer_key, container_plain, trace, plain
        except Exception as exc:
            last_error = f"{main_name}: {type(exc).__name__}: {exc}"
            continue
    if diag:
        diag.fail(prefix, f"no main entry verified; {last_error}; outer_key={outer_key.hex()}")
    return None




def _so_has_x86_idbfj_burden(so_data: bytes) -> bool:
    try:
        elf = MiniELF(so_data)
        if elf.e_machine != 3:
            return False
        names = [x.get("name", "") for x in elf.read_symbols()]
        return any("burden1b" in n for n in names) and any("idbfj" in n for n in names) and any("slky" in n for n in names)
    except Exception:
        return False


def _primary_so_key_candidates(post_candidates: List[bytes], xor_candidates: List[bytes]) -> Tuple[List[bytes], List[bytes]]:
    # IAPT_V110: callers always unpack a two-list tuple. Older no-dynamic-key
    # guards returned None and crashed C enumeration before pool keysets ran.
    if globals().get("IAPT_NO_DYNAMIC_KEY", False):
        print("[IAPT_V110] dynamic SO fallback disabled; primary candidate lists are empty")
        return [], []

    def pick(items: List[bytes]) -> List[bytes]:
        if not items:
            return []
        first = items[0]
        size = len(first)
        return uniq_bytes_list([item for item in items if len(item) == size])[:2]

    return pick(post_candidates), pick(xor_candidates)


def _native_x86_priority_candidates() -> List[OuterCandidate]:
    """Small SO-backed priority list for x86 burden1b/idbfj before full templates.

    burden1b in the uploaded x86 SO uses p19=idbfj(input), then either
    p24=slky(signature,p19) or p24=slky(p19,p19), then p25=slky(p19,p24),
    and finally XORs p25 with KEY_XOR_CONST.  Try the semantically valid inputs
    first, instead of building and testing hundreds of generic templates.
    """
    out: List[OuterCandidate] = []
    have_sig = bool(_EXTRA_OUTER_ENV.get("signature"))
    names: List[Tuple[str, int]] = []
    if _EXTRA_OUTER_ENV.get("user_password_native"):
        names.append(("user_password_native", 130))
        for i in range(1, 8):
            k = f"user_password_native_{i}"
            if _EXTRA_OUTER_ENV.get(k):
                names.append((k, 129 - i))
    if _EXTRA_OUTER_ENV.get("user_password"):
        names.extend([("user_password", 122), ("password", 121)])
    # Native e.af(context) returns null/empty on a clean install; empty is the normal no-password path.
    names.extend([("empty", 120), ("hidden", 82), ("jgapp", 78), ("mian", 74)])
    seen = set()
    for name, conf in names:
        if name in seen:
            continue
        seen.add(name)
        if have_sig:
            out.append(NativeX86IdbfjSignatureP25Candidate(name, "signature", confidence=conf + 1, source="so-priority-x86-idbfj"))
        out.append(NativeX86IdbfjP25Candidate(name, confidence=conf, source="so-priority-x86-idbfj"))
    return out



def _native_so_arch_label(so_data: bytes) -> Tuple[str, int, int]:
    try:
        elf = MiniELF(so_data)
        machine = int(elf.e_machine)
        if machine == 3:
            return "x86", machine, elf.bits
        if machine == 183:
            return "arm64", machine, elf.bits
        if machine == 62:
            return "x86_64", machine, elf.bits
        if machine == 40:
            return "armv7", machine, elf.bits
        return f"machine{machine}", machine, elf.bits
    except Exception:
        return "unknown", -1, 0


def _so_has_dynamic_outer_symbols_any(so_data: bytes) -> bool:
    # This only recognizes the outer-algorithm shape/symbols.  It does not read
    # post_key or xor_key constants, so it must remain available when
    # --no-dynamic-key is used for default/pool/custom strict modes.
    try:
        elf = MiniELF(so_data)
        names = [x.get("name", "") for x in elf.read_symbols()]
        has_burden = any(("burden1b" in n or "burden1a" in n) for n in names)
        has_core = any(("slky" in n or "asendn" in n or "idbfj" in n) for n in names)
        return has_burden and has_core
    except Exception:
        return False


def _native_multiabi_priority_candidates(so_data: bytes) -> List[OuterCandidate]:
    """SO-backed dynamic outer candidates for all ABI siblings.

    v56 only had the x86 idbfj fast path.  v57 keeps that path, but adds a
    compact priority set for arm64/x86_64 no-post direct and armv7/post XOR
    shapes that were already present in the broad template fallback.  This lets
    the correct ABI prove its key formula before the resolver tries hundreds of
    generic templates.
    """
    arch, machine, _bits = _native_so_arch_label(so_data)
    out: List[OuterCandidate] = []
    if arch == "x86":
        out.extend(_native_x86_priority_candidates())
        # Some x86/iApp builds do not route p19 through idbfj; keep a tiny
        # direct p19/p24/p25 set before the full template fallback.
        for fn, sn, conf in [
            ("base", "hidden", 105), ("base", "versionName", 100), ("base", "package", 96),
            ("base", "appLabel", 94), ("base", "versionCode", 90), ("base_tail", "hidden", 84),
        ]:
            out.append(NativePostP25Candidate(fn, sn, confidence=conf, source="so-priority-x86-post"))
    elif arch in ("arm64", "x86_64"):
        # Newer 64-bit samples commonly omit SLKY_POST_KEY and pass p25 directly
        # to asendn/AES.  Try the highest-probability metadata branches first.
        pairs = [
            ("base", "versionName", 126), ("base", "package", 124), ("base", "appLabel", 122),
            ("base", "versionCode", 120), ("base", "fb", 116), ("base", "hidden", 114),
            ("base_tail", "hidden", 108), ("base_no_fb", "hidden", 104),
            ("hidden_fb", "fb", 98), ("fb_hidden", "hidden", 94),
        ]
        for fn, sn, conf in pairs:
            out.append(NativeNoPostP25Candidate(fn, sn, confidence=conf, source=f"so-priority-{arch}-nopost"))
        # A smaller post/xor shadow set covers 64-bit variants that retained the
        # old post-key slky but changed the outer formula.
        for fn, sn, conf in pairs[:6]:
            out.append(NativePostP25Candidate(fn, sn, confidence=max(70, conf - 24), source=f"so-priority-{arch}-post"))
    elif arch == "armv7":
        # armv7 table extraction is conservative, so priority focuses on the
        # burden1a metadata-second-arg family and a tiny nopost shadow fallback.
        for second_name, conf in [("versionName", 124), ("appLabel", 108), ("package", 104), ("fb", 96), ("versionCode", 92), ("hidden", 90)]:
            out.append(FixedVariantOuterCandidate(second_name, confidence=conf, source="so-priority-armv7-fixedvariant"))
        for fn, sn, conf in [("base", "versionName", 88), ("base", "package", 84), ("base", "hidden", 82)]:
            out.append(NativeNoPostP25Candidate(fn, sn, confidence=conf, source="so-priority-armv7-nopost"))
            out.append(NativePostP25Candidate(fn, sn, confidence=max(65, conf - 6), source="so-priority-armv7-post"))
    else:
        return []
    # Dedup by candidate signature.
    out.sort(key=lambda c: (-c.confidence, c.name))
    seen = set(); deduped: List[OuterCandidate] = []
    for c in out:
        sig = c.signature()
        if sig in seen:
            continue
        seen.add(sig)
        deduped.append(c)
    return deduped[:48]


def _native_so_priority_key_sets(
    so_data: bytes,
    cached_key_lists: Optional[Tuple[List[bytes], List[bytes]]] = None,
) -> Tuple[List[Tuple[str, bytes, bytes]], Optional[Tuple[List[bytes], List[bytes]]]]:
    """Return bounded key sets for a SO priority probe.

    Exact SO constants are tried first when recoverable.  Generic constants are
    also included so no-post/direct 64-bit candidates can verify even when the
    ABI has no extractable KEY_XOR_CONST table.

    AArch64 needs a slightly wider *exact* XOR set than x86.  clang commonly
    emits burden1b as several adjacent ``LDR Q`` literals.  The effective table
    is often the first literal in code order, but the generic candidate sorter
    can move it behind other equally-sized 16-byte vectors.  The old 2x2 cap
    therefore omitted the real pair during dexkey C-batch enumeration even
    though the normal resolver could find it when f.b()/dexkey was known.

    Keep the exact post blob tightly bounded (normally one NUL-terminated run),
    but pair it with up to eight Q-sized AArch64 XOR literals.  This preserves
    fast x86-first operation while making arm64-only APK enumeration complete
    for the observed ADR/ADRP+LDR-Q layouts.
    """
    key_sets: List[Tuple[str, bytes, bytes]] = []
    if cached_key_lists is None:
        try:
            post_candidates, xor_candidates = auto_extract_key_candidates_from_so(so_data)
            cached_key_lists = (post_candidates, xor_candidates)
        except Exception:
            post_candidates, xor_candidates = [], []
            cached_key_lists = None
    else:
        post_candidates, xor_candidates = cached_key_lists

    primary_posts, primary_xors = _primary_so_key_candidates(post_candidates, xor_candidates)
    primary_posts = list(primary_posts or [])
    primary_xors = list(primary_xors or [])
    arch, _machine, _bits = _native_so_arch_label(so_data)

    if arch == "arm64":
        # The first ranked post candidate is the exact non-zero table run for
        # current arm64 SOs.  Keep one shadow candidate for compiler variants,
        # but widen only the cheap 16-byte burden literals.
        arm_posts = uniq_bytes_list(primary_posts + list(post_candidates or [])[:4])[:2]
        arm_xors = uniq_bytes_list(
            primary_xors
            + [bytes(x) for x in (xor_candidates or []) if len(x) == 16][:8]
        )[:8]
        for pi, pk in enumerate(arm_posts):
            for xi, xk in enumerate(arm_xors):
                key_sets.append((f"so-exact-arm64[{pi},{xi}]", pk, xk))
    else:
        for pi, pk in enumerate(primary_posts[:2]):
            for xi, xk in enumerate(primary_xors[:2]):
                key_sets.append((f"so-exact[{pi},{xi}]", pk, xk))

    key_sets.append(("generic", GENERIC_SLKY_POST_KEY, GENERIC_KEY_XOR_CONST))
    # Dedup by bytes.
    seen = set(); out: List[Tuple[str, bytes, bytes]] = []
    for name, pk, xk in key_sets:
        if not pk or not xk:
            continue
        sig = (bytes(pk), bytes(xk))
        if sig in seen:
            continue
        seen.add(sig)
        out.append((str(name), bytes(pk), bytes(xk)))
    return out, cached_key_lists

def _try_so_priority_fast_path(
    so_data: bytes, hidden: bytes, container: bytes, package: str, version_name: str, version_code,
    app_label: str, fb_value, outdir: Path, use_c: bool, c_path: str, debug_candidates: bool,
    diag: DecryptDiag, cached_key_lists: Optional[Tuple[List[bytes], List[bytes]]] = None,
    so_label: str = "native-so",
    shell_probe_only: bool = False,
) -> Tuple[Optional[Tuple[bytes, bytes, bytes, bytes, Dict[str, bytes]]], Optional[Tuple[List[bytes], List[bytes]]]]:
    if not so_data or not _so_has_dynamic_outer_symbols_any(so_data):
        return None, cached_key_lists
    t_so_fast = time.perf_counter()
    arch, machine, bits = _native_so_arch_label(so_data)
    priority_cands = _native_multiabi_priority_candidates(so_data)
    if not priority_cands:
        return None, cached_key_lists

    key_sets, cached_key_lists = _native_so_priority_key_sets(so_data, cached_key_lists)
    if not key_sets:
        return None, cached_key_lists

    print(f"[+] SO priority fast path: {so_label} arch={arch} machine={machine} bits={bits} key_sets={len(key_sets)} outer_cands={len(priority_cands)}")
    priority_resolver = OuterResolver(
        so_data, hidden, container, package, version_name, version_code, app_label, fb_value,
        outer_mode="auto", outdir=outdir, analyzer=None, use_c=use_c, c_path=c_path,
        debug_candidates=debug_candidates, dump_outer_candidates=False,
    )
    priority_resolver._candidate_cache = priority_cands
    for ki, (kname, pk, xk) in enumerate(key_sets):
        ok = priority_resolver.resolve(pk, xk, diag=diag if debug_candidates else None, tag=f"so-priority:{so_label}:{kname}", shell_probe_only=shell_probe_only)
        if ok:
            outer_key, container_plain, trace, _mian = ok
            trace["so_priority_fast_path"] = b"1"
            trace["so_priority_label"] = so_label.encode("utf-8", "replace")
            trace["so_priority_arch"] = arch.encode("utf-8", "replace")
            print(f"[T] SO priority total      {ms_since(t_so_fast):.3f} ms")
            print(f"[+] selected SO-priority {so_label} arch={arch} key_set={kname}")
            return (pk, xk, outer_key, container_plain, trace), cached_key_lists
    print(f"[T] SO priority total      {ms_since(t_so_fast):.3f} ms failed ({so_label} arch={arch})")
    return None, cached_key_lists


def auto_select_keys(
    so_data: bytes,
    hidden: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    fb_value,
    manual_post_key: Optional[bytes] = None,
    manual_key_xor: Optional[bytes] = None,
    mode: str = "auto",
    outer_mode: str = "fixed",
    outdir: Path = Path("out"),
    dump_static_ir: bool = False,
    trace_slky_args: bool = False,
    trace_asendn_args: bool = False,
    use_c: bool = False,
    c_path: str = "./libiapp_core.so",
    debug_candidates: bool = False,
    dump_outer_candidates: bool = False,
    shell_probe_only: bool = False,
    strict_manual_key: bool = False,
):
    diag = DecryptDiag()
    diag.ok("params", f"package={package}, version={version_name}, vc={version_code}, label={app_label}, fb={fb_value}")
    diag.ok("hidden", hidden.decode('ascii', 'replace'))
    diag.ok("outer mode", outer_mode)
    if shell_probe_only:
        diag.ok("enum probe", "outer-shell only; member/source decrypt is deferred until key selection succeeds")

    analyzer: Optional[StaticOuterAnalyzer] = None
    so_key_lists_cache: Optional[Tuple[List[bytes], List[bytes]]] = None
    # IAPT_V131_NO_DYNKEY_RUNTIME_BEGIN
    no_dynamic_key = bool(globals().get("IAPT_NO_DYNAMIC_KEY", False))
    if no_dynamic_key and mode == "advanced":
        mode = "auto"
    # IAPT_V131_NO_DYNKEY_RUNTIME_END
    # v57: priority dynamic outer-key fast path tries every ABI sibling inside
    # the APK, not just the primary/x86 SO.  Each result is still verified by
    # outer AES + mian.iyu, so a wrong ABI/formula is only a quick reject.
    if ((not no_dynamic_key) and mode in ("auto", "advanced") and outer_mode in ("auto", "static")
            and not (manual_post_key or manual_key_xor) and len(container) > (1 << 20)):
        priority_sources = list(_APK_NATIVE_SO_CANDIDATES) if _APK_NATIVE_SO_CANDIDATES else [("primary", so_data)]
        seen_so = set()
        for so_label, so_blob in priority_sources:
            sig = (len(so_blob), hashlib.sha1(so_blob[:4096] + so_blob[-4096:]).digest() if so_blob else b"")
            if sig in seen_so:
                continue
            seen_so.add(sig)
            fast_ok, maybe_cache = _try_so_priority_fast_path(
                so_blob, hidden, container, package, version_name, version_code, app_label, fb_value,
                outdir, use_c, c_path, debug_candidates, diag, None, so_label=so_label, shell_probe_only=shell_probe_only,
            )
            if so_blob == so_data and maybe_cache is not None:
                so_key_lists_cache = maybe_cache
            if fast_ok:
                return fast_ok

    if dump_static_ir or trace_slky_args or trace_asendn_args or outer_mode == "static":
        t_static = time.perf_counter()
        analyzer = run_static_outer_analysis(
            so_data, outdir, dump_static_ir,
            trace_slky_args or outer_mode == "static",
            trace_asendn_args or outer_mode == "static",
            write_static_ir=dump_static_ir,
        )
        print(f"[T] static outer analysis   {ms_since(t_static):.3f} ms")

    candidate_sets: List[Tuple[str, bytes, bytes]] = []
    if manual_post_key and manual_key_xor:
        candidate_sets.append(("manual", manual_post_key, manual_key_xor))
    elif manual_post_key or manual_key_xor:
        diag.warn("manual keys", "only one of --post-key/--key-xor was provided; both are needed for manual fast verification")

    if strict_manual_key and not (manual_post_key and manual_key_xor):
        diag.fail("manual keys", "strict manual mode requires both --post-key and --key-xor")
        diag.dump()
        raise RuntimeError("strict manual key mode requires a complete post_key/key_xor pair")

    # Strict custom-key mode must prove exactly the user-supplied pair. It must
    # never fall through to the server pool, generic constants, SO extraction,
    # or a previously cached successful key.
    if not strict_manual_key:
        _packed_profile=globals().get("_IAPT_PACKED_NATIVE_PROFILE") or {}
        _packed_pairs=list(_packed_profile.get("key_pairs") or [])
        _selected_pair=_packed_profile.get("selected_key_pair")
        if _selected_pair:
            _packed_pairs=[_selected_pair]+[pair for pair in _packed_pairs if pair!=_selected_pair]
        for _pair_index,_pair in enumerate(_packed_pairs[:16]):
            try:
                _packed_post,_packed_xor=bytes(_pair[0]),bytes(_pair[1])
            except Exception:
                continue
            if _packed_post and _packed_xor:
                candidate_sets.append((f"bmp-rc4-zlib-static:{_pair_index}",_packed_post,_packed_xor))
        # Server pool is tried before generic/SO extraction. The label contains only
        # an opaque ref, never the actual key bytes.
        for pool_ref, pool_post, pool_xor in IAPT_SERVER_KEY_POOL:
            candidate_sets.append((f"server-pool:{pool_ref}", pool_post, pool_xor))

    if (not strict_manual_key) and mode in ("fast", "auto"):
        # Always try the built-in generic constants first, even when
        # --outer-mode static is selected.  The outer algorithm and the
        # key constants are independent axes: some samples use a new
        # burden1a outer expression but still keep the generic tables.
        candidate_sets.append(("generic", GENERIC_SLKY_POST_KEY, GENERIC_KEY_XOR_CONST))

    resolver_mode = outer_mode if outer_mode in ("static", "auto") else "fixed"
    # Reuse one resolver for all key pairs.  Outer candidates depend on the SO
    # and manifest parameters, not on SLKY_POST_KEY/KEY_XOR_CONST.  Reusing the
    # resolver keeps the candidate list and outer_candidates.txt cached across
    # generic/manual and SO-extracted key tests.
    resolver = OuterResolver(
        so_data, hidden, container, package, version_name, version_code, app_label, fb_value,
        outer_mode=resolver_mode, outdir=outdir, analyzer=analyzer, use_c=use_c, c_path=c_path,
        debug_candidates=debug_candidates,
        dump_outer_candidates=dump_outer_candidates,
    )

    fixed_failed = False
    deferred_generic_key_sets: List[Tuple[str, bytes, bytes]] = []
    fixed_probe_resolver: Optional[OuterResolver] = None
    if mode == "auto" and resolver_mode == "auto":
        fixed_probe_resolver = OuterResolver(
            so_data, hidden, container, package, version_name, version_code, app_label, fb_value,
            outer_mode="fixed", outdir=outdir, analyzer=None, use_c=use_c, c_path=c_path,
            debug_candidates=debug_candidates, dump_outer_candidates=False,
        )

    for name, pk, xk in candidate_sets:
        if fixed_probe_resolver is not None and name == "generic":
            print(f"[+] trying fixed fast probe with {name} key set")
            ok = fixed_probe_resolver.resolve(pk, xk, diag=diag, tag=f"{name}/fixed-probe", shell_probe_only=shell_probe_only)
            if ok:
                outer_key, container_plain, trace, _mian = ok
                print(f"[+] selected fixed fast probe + {name} key set")
                return pk, xk, outer_key, container_plain, trace
            if globals().get("_QUISHUI_STATIC_SOKEY_ACTIVE", False):
                # QuiShui keeps the ordinary iApp tables but uses the real
                # idbfj(empty) field selector.  Probe that exact native path only;
                # a wrong timestamp hidden must not trigger broad SO/table scans.
                qs_probe = OuterResolver(
                    so_data, hidden, container, package, version_name, version_code,
                    app_label, fb_value, outer_mode="fixed", outdir=outdir,
                    analyzer=None, use_c=use_c, c_path=c_path,
                    debug_candidates=debug_candidates, dump_outer_candidates=False,
                )
                qs_candidates: List[OuterCandidate] = [
                    NativeX86IdbfjP25Candidate("empty", confidence=200, source="quishui-static-idbfj")
                ]
                if _EXTRA_OUTER_ENV.get("signature"):
                    qs_candidates.insert(0, NativeX86IdbfjSignatureP25Candidate(
                        "empty", "signature", confidence=201, source="quishui-static-idbfj"
                    ))
                qs_probe._candidate_cache = qs_candidates
                qs_ok = qs_probe.resolve(pk, xk, diag=None, tag=f"{name}/quishui-idbfj", shell_probe_only=shell_probe_only)
                if qs_ok:
                    outer_key, container_plain, trace, _mian = qs_ok
                    if isinstance(trace, dict):
                        trace["key_source"] = b"quishui-static-generic"
                    print(f"[+] selected QuiShui idbfj probe + {name} key set")
                    return pk, xk, outer_key, container_plain, trace
                raise RuntimeError("QuiShui sokey candidate rejected by fixed + idbfj probes")
            # Do not spend time trying hundreds of template candidates with the
            # generic constants yet.  Most modern samples keep a custom SO table;
            # generic templates are retried only if SO-extracted constants fail.
            deferred_generic_key_sets.append((name, pk, xk))
            fixed_failed = True
            continue

        print(f"[+] trying outer resolver mode={resolver_mode} with {name} key set")
        ok = resolver.resolve(pk, xk, diag=diag, tag=name, shell_probe_only=shell_probe_only)
        if ok:
            outer_key, container_plain, trace, _mian = ok
            trace["key_source"] = ("manual-strict" if strict_manual_key and name == "manual" else name).encode("utf-8", "replace")
            print(f"[+] selected outer resolver + {name} key set")
            return pk, xk, outer_key, container_plain, trace
        fixed_failed = True

    if strict_manual_key:
        diag.fail("final", "the supplied custom dynamic key pair did not verify")
        diag.dump()
        raise RuntimeError("custom dynamic key verification failed")

    if outer_mode in ("static", "auto") and (fixed_failed or outer_mode == "static"):
        diag.warn("static outer", "manual/generic constants did not verify; static resolver will continue with SO-extracted constants if available")

    if mode == "fast":
        diag.fail("final", "fast mode failed and advanced mode is disabled")
        diag.dump()
        raise RuntimeError("decrypt failed: fast mode key set invalid")

    # The built-in iApp tables may still be correct while the sample selects a
    # less common idbfj field (for example appLabel instead of hidden).  The
    # one-candidate fixed probe cannot prove the table wrong.  Before expensive
    # SO table recovery, run the ordinary resolver once with deferred generic
    # constants.  This stays within the normal algorithm and is especially
    # useful when a protector packed/stripped the native table construction.
    if deferred_generic_key_sets:
        for name, pk, xk in deferred_generic_key_sets:
            print(f"[+] trying full outer resolver with deferred {name} key set")
            ok = resolver.resolve(pk, xk, diag=diag if debug_candidates else None, tag=f"{name}/full-template", shell_probe_only=shell_probe_only)
            if ok:
                outer_key, container_plain, trace, _mian = ok
                if isinstance(trace, dict):
                    trace["key_source"] = (name + "-full-template").encode("utf-8", "replace")
                print(f"[+] selected full outer resolver + deferred {name} key set")
                return pk, xk, outer_key, container_plain, trace

    # IAPT_V131_SKIP_SO_EXTRACT_BEGIN
    if no_dynamic_key:
        print("[IAPT_V131] no-dynamic-key: skip auto_extract_key_candidates_from_so; try generic/static outer only")
        generic_sets = list(deferred_generic_key_sets or candidate_sets)
        tried = 0
        for name, pk, xk in generic_sets:
            tried += 1
            ok = resolver.resolve(pk, xk, diag=diag if debug_candidates else None, tag=f"{name}/no-dynkey-template", shell_probe_only=shell_probe_only)
            if ok:
                outer_key, container_plain, trace, _mian = ok
                print(f"[+] selected no-dynamic-key generic/static template + {name} key set")
                return pk, xk, outer_key, container_plain, trace

        if resolver_mode == "auto" and resolver.analyzer is None:
            print("[IAPT_V131] no-dynamic-key: running static IR fallback with generic constants only")
            t_static_fallback = time.perf_counter()
            analyzer = run_static_outer_analysis(
                so_data, outdir, dump_static_ir,
                trace_slky_args or dump_static_ir,
                trace_asendn_args or dump_static_ir,
                write_static_ir=dump_static_ir,
            )
            print(f"[T] static fallback analysis {ms_since(t_static_fallback):.3f} ms")
            if analyzer is not None:
                resolver.analyzer = analyzer
                resolver._candidate_cache = None
                for name, pk, xk in generic_sets:
                    tried += 1
                    ok = resolver.resolve(pk, xk, diag=diag if debug_candidates else None, tag=f"{name}/no-dynkey-static-fallback", shell_probe_only=shell_probe_only)
                    if ok:
                        outer_key, container_plain, trace, _mian = ok
                        print(f"[+] selected no-dynamic-key static fallback + {name} key set")
                        return pk, xk, outer_key, container_plain, trace

        diag.fail("final", f"no-dynamic-key enabled; SO key extraction disabled; generic/static candidates failed; tested={tried}")
        diag.dump()
        raise RuntimeError("decrypt failed: no-dynamic-key disabled SO key extraction")
    # IAPT_V131_SKIP_SO_EXTRACT_END
    print("[+] generic/manual failed or advanced forced; extracting keys from SO candidates")
    # IAPT_DYNAMIC_KEY_DECRYPT_DATAFLOW_V275_FAST_BEGIN
    # All complete dataflow pairs are reconstructed once and cached across the
    # current task's sokey/dexkey probes.  A supported pair is authoritative:
    # verify only that exact pair instead of producing a post×xor cross product.
    _iapt_v275_sources = (
        list(_APK_NATIVE_SO_CANDIDATES)
        if _APK_NATIVE_SO_CANDIDATES
        else [("primary", so_data)]
    )
    try:
        _iapt_v275_pair, _iapt_v275_errors = _iapt_v275_consensus_pair(
            _iapt_v275_sources
        )
    except RuntimeError as _iapt_v275_mismatch:
        diag.fail("multi-ABI dataflow", str(_iapt_v275_mismatch))
        diag.dump()
        raise

    if _iapt_v275_pair is not None:
        _iapt_v275_post, _iapt_v275_xor, _iapt_v275_meta = _iapt_v275_pair
        print(
            "[IAPT_V275] decrypt dataflow consensus: abis=%s post=%d xor=%d"
            % (
                ",".join(_iapt_v275_meta.get("successful_abis") or []),
                len(_iapt_v275_post),
                len(_iapt_v275_xor),
            ),
            flush=True,
        )
        _iapt_v275_ok = resolver.resolve(
            _iapt_v275_post,
            _iapt_v275_xor,
            diag=diag if debug_candidates else None,
            tag="multiabi-dataflow-v3",
            shell_probe_only=shell_probe_only,
        )
        if _iapt_v275_ok:
            outer_key, container_plain, trace, _mian = _iapt_v275_ok
            if isinstance(trace, dict):
                trace["dynamic_key_source"] = b"multiabi-dataflow-v3"
                trace["dynamic_key_consensus_count"] = str(
                    int(_iapt_v275_meta.get("consensus_count") or 0)
                ).encode("ascii")
            print(
                "[+] selected complete multi-ABI dataflow key pair via outer resolver",
                flush=True,
            )
            return (
                _iapt_v275_post,
                _iapt_v275_xor,
                outer_key,
                container_plain,
                trace,
            )

        # V201: the deterministic static pair is the preferred first try, not a
        # reason to suppress compatibility candidates. A different native layout,
        # hidden/dexkey branch or parser gap may still be recoverable by the
        # existing candidate verifier. Only a pair that decrypts the real
        # container becomes authoritative and reaches the success hook.
        diag.warn(
            "V201 exact static preferred pair",
            "preferred pair rejected; continue structured candidate fallback",
        )
        print(
            "[IAPT_V201] preferred exact static pair rejected; continue candidate fallback",
            flush=True,
        )

    if _iapt_v275_errors:
        print(
            "[IAPT_V275] no supported complete SO layout; using legacy parser: %s"
            % " | ".join(_iapt_v275_errors),
            flush=True,
        )
    # IAPT_DYNAMIC_KEY_DECRYPT_DATAFLOW_V275_FAST_END
    t_so_extract = time.perf_counter()
    post_candidates: List[bytes] = []
    xor_candidates: List[bytes] = []
    extract_sources = list(_APK_NATIVE_SO_CANDIDATES) if _APK_NATIVE_SO_CANDIDATES else [("primary", so_data)]
    seen_so_extract = set()
    extract_errors: List[str] = []
    for so_label, so_blob in extract_sources:
        sig = (len(so_blob), hashlib.sha1(so_blob[:4096] + so_blob[-4096:]).digest() if so_blob else b"")
        if sig in seen_so_extract:
            continue
        seen_so_extract.add(sig)
        try:
            if so_blob == so_data and so_key_lists_cache is not None:
                pks, xks = so_key_lists_cache
                print(f"[+] SO key extraction source {so_label}: cached post={len(pks)} xor={len(xks)}")
            else:
                pks, xks = auto_extract_key_candidates_from_so(so_blob)
                print(f"[+] SO key extraction source {so_label}: post={len(pks)} xor={len(xks)}")
            post_candidates.extend(pks)
            xor_candidates.extend(xks)
        except Exception as e:
            arch, machine, bits = _native_so_arch_label(so_blob)
            msg = f"{so_label} arch={arch}: {type(e).__name__}: {e}"
            extract_errors.append(msg)
            print(f"[!] SO key extraction skipped: {msg}")
    print(f"[T] SO key extraction       {ms_since(t_so_extract):.3f} ms sources={len(extract_sources)}")
    if not post_candidates or not xor_candidates:
        diag.fail("so analysis", "; ".join(extract_errors) or "no SO key candidates")
        diag.dump()
        raise RuntimeError("decrypt failed during SO analysis: no usable SO key candidates")
    diag.ok("so analysis", f"post_candidates={len(post_candidates)}, xor_candidates={len(xor_candidates)}, sources={len(extract_sources)}")

    if manual_post_key:
        post_candidates = [manual_post_key] + post_candidates
    if manual_key_xor:
        xor_candidates = [manual_key_xor] + xor_candidates

    post_candidates = uniq_bytes_list(post_candidates)
    xor_candidates = uniq_bytes_list(xor_candidates)

    # slky's post table can also be materialized next to decoy bytes and passed
    # through C-string semantics.  Prefer the effective bytes before the first
    # NUL when that produces a normal 16+ byte key.
    _strlen_post = []
    for _raw_post in list(post_candidates):
        _nul = _raw_post.find(b"\x00")
        if 16 <= _nul <= 64:
            _strlen_post.append(_raw_post[:_nul])
    if _strlen_post:
        post_candidates = uniq_bytes_list(_strlen_post + post_candidates)

    # Some builds construct KEY_XOR_CONST as a C string.  Static vector/stack
    # recovery sees bytes after the first NUL, but strlen() truncates them at
    # runtime and xor_repeat() cycles the effective prefix to the post-key
    # length.  iAct is a verified example: 8 effective bytes are repeated to
    # 16, while the trailing bytes are decoys.  Generate only same-length,
    # same-leading-byte pairs to keep the candidate space narrow.
    _strlen_xor = []
    _post_lengths = sorted({len(x) for x in post_candidates if 8 <= len(x) <= 64})
    for _raw_xor in list(xor_candidates):
        _nul = _raw_xor.find(b"\x00")
        if _nul <= 0:
            continue
        _effective = _raw_xor[:_nul]
        if not (1 <= len(_effective) <= 32):
            continue
        for _target_len in _post_lengths:
            if _target_len < len(_effective):
                continue
            if not any(len(_p) == _target_len and _p[:1] == _effective[:1] for _p in post_candidates):
                continue
            _expanded = (_effective * ((_target_len + len(_effective) - 1) // len(_effective)))[:_target_len]
            _strlen_xor.append(_expanded)
    if _strlen_xor:
        print("[IAPT_STRLEN_XOR] effective/repeated candidates:", len(uniq_bytes_list(_strlen_xor)))
        xor_candidates = uniq_bytes_list(_strlen_xor + xor_candidates)

    show_n = 50 if debug_candidates else 12
    print("[+] SLKY_POST_KEY candidates:", len(post_candidates))
    for i, c in enumerate(post_candidates[:show_n]):
        print(f"    post[{i}] len={len(c)} {c.hex()}")
    print("[+] KEY_XOR_CONST candidates:", len(xor_candidates))
    for i, c in enumerate(xor_candidates[:show_n]):
        print(f"    xor [{i}] len={len(c)} {c.hex()}")

    # Pair candidates by the invariant used by real iApp builds before trying
    # the full cross product: POST and XOR normally have the same runtime
    # length (16 or 20 bytes) and share at least the first byte.  This makes the
    # verified table win over long decoy windows such as the anti-QiuShui ARM64
    # constants, while still retaining every fallback combination.
    def _pair_common_prefix(a: bytes, b: bytes) -> int:
        n = 0
        for av, bv in zip(a, b):
            if av != bv:
                break
            n += 1
        return n

    def _pair_rank(row):
        pi, xi = row
        pk, xk = post_candidates[pi], xor_candidates[xi]
        same_len = len(pk) == len(xk)
        same_first = bool(pk and xk and pk[:1] == xk[:1])
        standard = len(pk) in (16, 20) and len(xk) in (16, 20)
        if same_len and same_first and standard:
            structural = 0
        elif same_len and same_first:
            structural = 1
        elif same_first and standard:
            structural = 2
        elif same_first:
            structural = 3
        elif same_len and standard:
            structural = 4
        elif same_len:
            structural = 5
        else:
            structural = 6
        manual = 0 if (manual_post_key and manual_key_xor and
                       pk == manual_post_key and xk == manual_key_xor) else 1
        return (
            manual, structural, -_pair_common_prefix(pk, xk),
            0 if len(pk) in (16, 20) else 1,
            abs(len(pk) - len(xk)), pi, xi,
        )

    candidate_pairs = [
        (pi, xi)
        for pi in range(len(post_candidates))
        for xi in range(len(xor_candidates))
    ]
    candidate_pairs.sort(key=_pair_rank)
    if candidate_pairs:
        _preview = []
        for _pi, _xi in candidate_pairs[:8]:
            _preview.append(
                "p%d(%d)/x%d(%d)/prefix%d"
                % (
                    _pi, len(post_candidates[_pi]), _xi, len(xor_candidates[_xi]),
                    _pair_common_prefix(post_candidates[_pi], xor_candidates[_xi]),
                )
            )
        print("[IAPT_KEY_PAIR_ORDER] " + ", ".join(_preview), flush=True)

    fail_count = 0
    for pi, xi in candidate_pairs:
        pk, xk = post_candidates[pi], xor_candidates[xi]
        tag = f"post[{pi}]/xor[{xi}]"
        ok = resolver.resolve(pk, xk, diag=diag if debug_candidates or fail_count < 12 else None, tag=tag, shell_probe_only=shell_probe_only)
        if ok:
            outer_key, container_plain, trace, _mian = ok
            print(f"[+] selected post[{pi}] and xor[{xi}] via outer resolver")
            return pk, xk, outer_key, container_plain, trace
        fail_count += 1

    # Last-resort compatibility fallback: the fast auto path above intentionally
    # avoids the expensive static IR pass.  If templates fail, build full static
    # IR once and retry the same key pairs before giving up.
    if deferred_generic_key_sets:
        print("[!] SO-extracted constants failed; retrying deferred generic constants with template candidates")
        for name, pk, xk in deferred_generic_key_sets:
            ok = resolver.resolve(pk, xk, diag=diag if debug_candidates else None, tag=f"{name}/deferred-template", shell_probe_only=shell_probe_only)
            if ok:
                outer_key, container_plain, trace, _mian = ok
                print(f"[+] selected deferred template + {name} key set")
                return pk, xk, outer_key, container_plain, trace

    if resolver_mode == "auto" and resolver.analyzer is None:
        print("[!] fast template outer candidates failed; running full static IR fallback")
        t_static_fallback = time.perf_counter()
        analyzer = run_static_outer_analysis(
            so_data, outdir, dump_static_ir,
            trace_slky_args or dump_static_ir,
            trace_asendn_args or dump_static_ir,
            write_static_ir=dump_static_ir,
        )
        print(f"[T] static fallback analysis {ms_since(t_static_fallback):.3f} ms")
        if analyzer is not None:
            resolver.analyzer = analyzer
            resolver._candidate_cache = None
            fail_count = 0
            for pi, xi in candidate_pairs:
                pk, xk = post_candidates[pi], xor_candidates[xi]
                tag = f"post[{pi}]/xor[{xi}]/static-fallback"
                ok = resolver.resolve(pk, xk, diag=diag if debug_candidates or fail_count < 12 else None, tag=tag, shell_probe_only=shell_probe_only)
                if ok:
                    outer_key, container_plain, trace, _mian = ok
                    print(f"[+] selected post[{pi}] and xor[{xi}] via static fallback")
                    return pk, xk, outer_key, container_plain, trace
                fail_count += 1

    diag.fail("final", f"all key/outer candidates failed; tested key pairs={len(post_candidates) * len(xor_candidates)} outer_mode={resolver_mode}")
    diag.dump()
    raise RuntimeError("decrypt failed: no valid SLKY_POST_KEY / KEY_XOR_CONST pair")


# IAPT_DEXKEY_MP_OUTER_PROBE_BEGIN
_IAPT_DEXKEY_MP_STATE: Dict[str, object] = {}

# The native C scanner verifies a candidate with the exact SO keyset and outer
# formula, but older code returned only the numeric f.b()/dexkey.  Re-running
# the broad resolver could then stop at an unrelated padding-only outer-shell
# false positive.  Preserve the already verified tuple for final selection.
_IAPT_LAST_CBATCH_VERIFIED_RESULT: Dict[Tuple[int, bytes], Tuple[bytes, bytes, bytes, bytes, Dict[str, bytes]]] = {}


def _iapt_take_cbatch_verified_result(fb_value, hidden: bytes):
    try:
        return _IAPT_LAST_CBATCH_VERIFIED_RESULT.pop((int(fb_value), bytes(hidden)), None)
    except Exception:
        return None


def _iapt_dexkey_dedup_outer_candidates(cands: List[OuterCandidate]) -> List[OuterCandidate]:
    """Deduplicate reusable outer algorithm candidates once per worker.

    These candidates are pure formulas; their values still depend on the per-key
    environment such as f.b(), but the formula objects themselves do not need to
    be rebuilt for every dexkey candidate.
    """
    out: List[OuterCandidate] = []
    seen = set()
    for c in cands or []:
        try:
            sig = c.signature()
        except Exception:
            sig = (type(c).__name__, str(c))
        if sig in seen:
            continue
        seen.add(sig)
        out.append(c)
    out.sort(key=lambda c: (-getattr(c, "confidence", 0), getattr(c, "name", "")))
    return out


def _iapt_dexkey_build_cached_probe_plan(state: Dict[str, object]) -> Dict[str, object]:
    """Build enum invariant data once inside each worker.

    dexkey 枚举需要尽量全；sokey 枚举只有 4000 次，热路径必须更短。
    如果 state["sokey_strict_main_probe"] 为真，默认启用 sokey tiny-plan：
    只保留少量最高优先级 SO outer 公式/keyset，并跳过庞大的 template×SO 笛卡尔积。
    这样每个 sokey 候选只跑少量“原算法 mian.iyu-only 探测”，不会第一个候选就像卡住。

    可用环境变量放宽：
      IAPT_SOKEY_PLAN=full            # 使用 dexkey 那套大计划
      IAPT_SOKEY_MAX_OUTER_CANDS=16   # tiny-plan 每组 outer 公式数
      IAPT_SOKEY_MAX_KEYSETS=4        # tiny-plan 每组 keyset 数
    """
    so_data = state.get("so_data") or b""
    container = state.get("container") or b""
    mode = str(state.get("mode") or "auto")
    outer_mode = str(state.get("outer_mode") or "auto")
    manual_post_key = state.get("manual_post_key")
    manual_key_xor = state.get("manual_key_xor")

    sokey_strict = bool(state.get("sokey_strict_main_probe", False))
    sokey_plan_mode = str(os.environ.get("IAPT_SOKEY_PLAN", "tiny" if sokey_strict else "full")).strip().lower()
    sokey_tiny_plan = bool(sokey_strict and sokey_plan_mode not in ("0", "false", "off", "full"))
    try:
        sokey_max_outer = max(1, int(os.environ.get("IAPT_SOKEY_MAX_OUTER_CANDS", "32")))
    except Exception:
        sokey_max_outer = 32
    try:
        sokey_max_keysets = max(1, int(os.environ.get("IAPT_SOKEY_MAX_KEYSETS", "8")))
    except Exception:
        sokey_max_keysets = 8
    try:
        dexkey_max_so_keysets = int(state.get("dexkey_max_so_keysets", os.environ.get("IAPT_DEXKEY_MAX_SO_KEYSETS", "16")) or 16)
    except Exception:
        dexkey_max_so_keysets = 16
    # 0 means unlimited; default caps only the noisy fallback cross-product,
    # not SO-exact priority pairs nor the generic keyset.
    if dexkey_max_so_keysets < 0:
        dexkey_max_so_keysets = 16

    extract_sources = list(_APK_NATIVE_SO_CANDIDATES) if _APK_NATIVE_SO_CANDIDATES else [("primary", so_data)]
    # Deduplicate ABI siblings by cheap content signature.
    unique_sources: List[Tuple[str, bytes]] = []
    seen_so = set()
    for label, blob in extract_sources:
        blob = blob or b""
        sig = (len(blob), hashlib.sha1(blob[:4096] + blob[-4096:]).digest() if blob else b"")
        if sig in seen_so:
            continue
        seen_so.add(sig)
        unique_sources.append((str(label), blob))

    priority_plans: List[Tuple[str, List[OuterCandidate], List[Tuple[str, bytes, bytes]]]] = []
    so_key_cache_by_sig: Dict[Tuple[int, bytes], Optional[Tuple[List[bytes], List[bytes]]]] = {}
    for label, blob in unique_sources:
        if not blob:
            continue
        try:
            if not _so_has_dynamic_outer_symbols_any(blob):
                continue
            priority_cands = _iapt_dexkey_dedup_outer_candidates(_native_multiabi_priority_candidates(blob))
            sig = (len(blob), hashlib.sha1(blob[:4096] + blob[-4096:]).digest())
            cached_lists = so_key_cache_by_sig.get(sig)
            keysets, cached_lists = _native_so_priority_key_sets(blob, cached_lists)
            so_key_cache_by_sig[sig] = cached_lists
            if priority_cands and keysets:
                # sokey 枚举热路径必须很短：只保留最高置信的少量公式/keyset。
                if sokey_tiny_plan:
                    priority_cands = list(priority_cands)[:sokey_max_outer]
                    keysets = list(keysets)[:sokey_max_keysets]
                priority_plans.append((label, priority_cands, keysets))
        except Exception:
            continue

    fixed_candidates = _iapt_dexkey_dedup_outer_candidates([fixed_outer_candidate()])
    template_candidates = _iapt_dexkey_dedup_outer_candidates(([fixed_outer_candidate()] if outer_mode in ("fixed", "auto") else []) + (generate_template_outer_candidates() if outer_mode in ("auto", "static") else []))
    if sokey_tiny_plan:
        fixed_candidates = fixed_candidates[:1]
        # 保留少量最高优先级模板兜底；默认不跑大规模 template×SO。
        template_candidates = template_candidates[:sokey_max_outer]

    fast_keysets: List[Tuple[str, bytes, bytes]] = []
    for pool_ref, pool_post, pool_xor in IAPT_SERVER_KEY_POOL:
        fast_keysets.append((f"server-pool:{pool_ref}", pool_post, pool_xor))
    if manual_post_key and manual_key_xor:
        fast_keysets.append(("manual", manual_post_key, manual_key_xor))
    if mode in ("fast", "auto"):
        fast_keysets.append(("generic", GENERIC_SLKY_POST_KEY, GENERIC_KEY_XOR_CONST))

    # SO-extracted key pairs are expensive to build; do it once per worker.
    so_post_candidates: List[bytes] = []
    so_xor_candidates: List[bytes] = []
    if not bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)):
        for label, blob in unique_sources:
            if not blob:
                continue
            try:
                sig = (len(blob), hashlib.sha1(blob[:4096] + blob[-4096:]).digest())
                cached_lists = so_key_cache_by_sig.get(sig)
                if cached_lists is None:
                    pks, xks = auto_extract_key_candidates_from_so(blob)
                    so_key_cache_by_sig[sig] = (pks, xks)
                else:
                    pks, xks = cached_lists
                so_post_candidates.extend(pks or [])
                so_xor_candidates.extend(xks or [])
            except Exception:
                continue
    if manual_post_key:
        so_post_candidates = [manual_post_key] + so_post_candidates
    if manual_key_xor:
        so_xor_candidates = [manual_key_xor] + so_xor_candidates
    so_post_candidates = uniq_bytes_list(so_post_candidates)
    so_xor_candidates = uniq_bytes_list(so_xor_candidates)

    so_keysets: List[Tuple[str, bytes, bytes]] = []
    # v141: never let fallback text/table guesses explode into thousands of
    # post×xor combinations.  Use primary ranked constants, then paired-index
    # candidates as a cheap fallback.  SO-exact pairs from priority_plans are
    # kept separately and are not affected by this cap.
    primary_posts, primary_xors = _primary_so_key_candidates(so_post_candidates, so_xor_candidates)
    primary_posts = list(primary_posts or [])
    primary_xors = list(primary_xors or [])
    for pi, pk in enumerate(primary_posts[:4]):
        for xi, xk in enumerate(primary_xors[:4]):
            so_keysets.append((f"so-primary[{pi},{xi}]", pk, xk))
    pair_limit = max(len(primary_posts), len(primary_xors), 8)
    for i in range(min(pair_limit, len(so_post_candidates), len(so_xor_candidates))):
        so_keysets.append((f"so-pair[{i}]", so_post_candidates[i], so_xor_candidates[i]))

    # Dedup keysets while preserving order.
    seen_keys = set()
    def _dedup_keysets(items: List[Tuple[str, bytes, bytes]]) -> List[Tuple[str, bytes, bytes]]:
        out: List[Tuple[str, bytes, bytes]] = []
        for name, pk, xk in items:
            sig = (pk, xk)
            if sig in seen_keys:
                continue
            seen_keys.add(sig)
            out.append((name, pk, xk))
        return out

    fast_keysets = _dedup_keysets(fast_keysets)
    so_keysets = _dedup_keysets(so_keysets)
    if sokey_tiny_plan:
        fast_keysets = fast_keysets[:sokey_max_keysets]
        so_keysets = so_keysets[:sokey_max_keysets]
    elif dexkey_max_so_keysets > 0:
        _before_so_cap = len(so_keysets)
        so_keysets = so_keysets[:dexkey_max_so_keysets]
        if _before_so_cap > len(so_keysets):
            print(f"[!] noisy SO fallback keysets capped: {_before_so_cap} -> {len(so_keysets)}")

    plan = {
        "priority_plans": priority_plans,
        "fixed_candidates": fixed_candidates,
        "template_candidates": template_candidates,
        "fast_keysets": fast_keysets,
        "so_keysets": so_keysets,
        "sokey_tiny_plan": sokey_tiny_plan,
        "sokey_max_outer": sokey_max_outer,
        "sokey_max_keysets": sokey_max_keysets,
        "dexkey_max_so_keysets": dexkey_max_so_keysets,
        "use_c": bool(state.get("use_c", False)),
        "c_path": str(state.get("c_path") or "./libiapp_core.so"),
    }
    try:
        print(
            "[+] dexkey worker cache: "
            f"priority={sum(len(p[1]) * len(p[2]) for p in priority_plans)} "
            f"fixed_cands={len(fixed_candidates)} template_cands={len(template_candidates)} "
            f"fast_keysets={len(plan['fast_keysets'])} so_keysets={len(plan['so_keysets'])} "
            f"so_cap={plan.get('dexkey_max_so_keysets')} "
            f"sokey_tiny={int(bool(plan.get('sokey_tiny_plan')))}"
        )
    except Exception:
        pass
    return plan


def _iapt_enum_get_slky_context(post_key: bytes, use_c: bool, c_path: str) -> SlkyContext:
    """Reuse SlkyContext/lru caches across millions of enum probes in a worker."""
    cache = _IAPT_DEXKEY_MP_STATE.setdefault("_slky_ctx_cache", {})
    key = (bytes(post_key), bool(use_c), str(c_path))
    ctx = cache.get(key)
    if ctx is None:
        ctx = SlkyContext(post_key, use_c=use_c, c_path=c_path)
        cache[key] = ctx
    return ctx


def _iapt_dexkey_probe_candidate_list_cached(
    cands: List[OuterCandidate],
    keysets: List[Tuple[str, bytes, bytes]],
    hidden: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    fb_value,
    use_c: bool,
    c_path: str,
    tag_prefix: str,
) -> Optional[Tuple[bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    if not cands or not keysets:
        return None

    # sokey 枚举专用：outer 有些算法与 hidden/sokey 无关，错误 sokey 也会
    # “外壳解开”，然后每个候选都跑到 mian.iyu final check failed。
    # 这里把枚举热路径改成强校验：外壳只作为中间步骤，必须能用当前 sokey
    # 解出 mian.iyu 才返回命中。同时 outer_key 相同的外壳明文只解密一次，
    # 后续候选复用，避免 4000 次重复 AES 解同一个 container。
    strict_main_probe = bool(_IAPT_DEXKEY_MP_STATE.get("sokey_strict_main_probe", False))
    outer_plain_cache = _IAPT_DEXKEY_MP_STATE.setdefault("outer_plain_cache", {}) if strict_main_probe else None
    outer_plain_cache_order = _IAPT_DEXKEY_MP_STATE.setdefault("outer_plain_cache_order", []) if strict_main_probe else None
    outer_plain_cache_max = int(_IAPT_DEXKEY_MP_STATE.get("outer_plain_cache_max", 32) or 32)

    env = build_outer_env(hidden, package, version_name, version_code, app_label, fb_value)
    if _EXTRA_OUTER_ENV:
        env.update(_EXTRA_OUTER_ENV)
    nopost_ctx = NoPostSlkyContext()

    for kname, pk, xk in keysets:
        try:
            ctx = _iapt_enum_get_slky_context(pk, use_c=use_c, c_path=c_path)
        except Exception:
            continue
        for cand in cands:
            trace: Dict[str, bytes]
            t_outer_key = time.perf_counter()
            try:
                outer_key, trace = cand.derive(ctx, xk, env)
                trace = dict(trace or {})
                trace["timing_outer_key_ms"] = f"{ms_since(t_outer_key):.3f}".encode()
            except Exception:
                continue

            t_outer_dec = time.perf_counter()
            if not aes_cbc_pkcs7_padding_maybe_valid(container, outer_key):
                continue

            container_plain = None
            if strict_main_probe and isinstance(outer_plain_cache, dict):
                container_plain = outer_plain_cache.get(outer_key)
                if container_plain is not None:
                    trace["outer_plain_cache_hit"] = b"1"
                    trace["timing_outer_decrypt_ms"] = b"cached"

            if container_plain is None:
                try:
                    container_plain = aes_cbc_then_xor_decrypt(container, outer_key)
                    trace["timing_outer_decrypt_ms"] = f"{ms_since(t_outer_dec):.3f}".encode()
                except Exception:
                    continue
                if strict_main_probe and isinstance(outer_plain_cache, dict):
                    if len(outer_plain_cache) >= outer_plain_cache_max and isinstance(outer_plain_cache_order, list) and outer_plain_cache_order:
                        old_key = outer_plain_cache_order.pop(0)
                        outer_plain_cache.pop(old_key, None)
                    outer_plain_cache[outer_key] = container_plain
                    if isinstance(outer_plain_cache_order, list):
                        outer_plain_cache_order.append(outer_key)

            trace["dexkey_cached_probe"] = b"1"
            trace["dexkey_cached_probe_tag"] = f"{tag_prefix}:{kname}".encode("utf-8", "replace")
            trace["algorithm"] = trace.get("algorithm", str(cand).encode("utf-8", "replace"))

            if strict_main_probe:
                try:
                    trace2, _main_plain = finalize_outer_shell_probe(
                        container_plain, pk, xk, hidden, fb_value, trace,
                        use_c=use_c, c_path=c_path,
                    )
                    trace2 = dict(trace2 or {})
                    trace2["sokey_strict_main_probe"] = b"1"
                    trace2["sokey_main_plain_bytes"] = str(len(_main_plain or b"")).encode()
                    return pk, xk, outer_key, container_plain, trace2
                except Exception:
                    # Not the right sokey.  Do not return an outer-only false hit.
                    continue

            # dexkey/f.b. 枚举仍然保持 outer-shell probe；它的 key 空间太大，
            # 命中后再由外层做一次主文件确认。
            return pk, xk, outer_key, container_plain, trace
    return None

def _iapt_dexkey_cached_probe_one(fb_try: int, hidden_override: Optional[bytes] = None) -> Optional[Tuple[bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    st = _IAPT_DEXKEY_MP_STATE
    plan = st.get("probe_plan") or {}
    hidden = hidden_override if hidden_override is not None else st["hidden"]
    container = st["container"]
    package = st["package"]
    version_name = st["version_name"]
    version_code = st["version_code"]
    app_label = st["app_label"]
    use_c = bool(plan.get("use_c", st.get("use_c", False)))
    c_path = str(plan.get("c_path", st.get("c_path") or "./libiapp_core.so"))

    # 1) Cached multi-ABI SO priority path.
    for label, cands, keysets in list(plan.get("priority_plans") or []):
        hit = _iapt_dexkey_probe_candidate_list_cached(
            cands, keysets, hidden, container, package, version_name, version_code, app_label,
            fb_try, use_c, c_path, f"priority:{label}",
        )
        if hit:
            return hit

    # 2) Cached fixed probe with manual/generic constants.
    hit = _iapt_dexkey_probe_candidate_list_cached(
        list(plan.get("fixed_candidates") or []), list(plan.get("fast_keysets") or []),
        hidden, container, package, version_name, version_code, app_label, fb_try,
        use_c, c_path, "fixed-fast",
    )
    if hit:
        return hit

    sokey_tiny = bool(plan.get("sokey_tiny_plan", False))

    # 3) Cached SO-extracted key pairs + cached template/outer formulas.
    # sokey tiny-plan 默认不跑 so-template 大分支，避免一个候选就扫一大批公式。
    if (not sokey_tiny) or str(os.environ.get("IAPT_SOKEY_TRY_SO_TEMPLATE", "1")).strip() in ("1", "true", "on", "yes"):
        hit = _iapt_dexkey_probe_candidate_list_cached(
            list(plan.get("template_candidates") or []), list(plan.get("so_keysets") or []),
            hidden, container, package, version_name, version_code, app_label, fb_try,
            use_c, c_path, "so-template",
        )
        if hit:
            return hit

    # 4) Compatibility fallback: cached template formulas with manual/generic.
    return _iapt_dexkey_probe_candidate_list_cached(
        list(plan.get("template_candidates") or []), list(plan.get("fast_keysets") or []),
        hidden, container, package, version_name, version_code, app_label, fb_try,
        use_c, c_path, "template-fast",
    )

def _iapt_dexkey_mp_init(state: Dict[str, object]) -> None:
    """Process worker initializer for dexkey enumeration.

    Each worker keeps APK/SO/container bytes in memory and probes a contiguous
    dexkey slice.  The hot path performs only outer-shell decrypt plus a one-file
    main gate on rare shell hits; it never recursively decrypts project members.
    """
    global _IAPT_DEXKEY_MP_STATE, _EXTRA_OUTER_ENV, _APK_NATIVE_SO_CANDIDATES, MUST_HAVE_MAIN
    _IAPT_DEXKEY_MP_STATE = dict(state or {})
    _EXTRA_OUTER_ENV = dict(_IAPT_DEXKEY_MP_STATE.get("extra_outer_env") or {})
    _APK_NATIVE_SO_CANDIDATES = list(_IAPT_DEXKEY_MP_STATE.get("apk_native_so_candidates") or [])
    MUST_HAVE_MAIN = str(_IAPT_DEXKEY_MP_STATE.get("main_file") or MUST_HAVE_MAIN)
    globals()["IAPT_NO_DYNAMIC_KEY"] = bool(_IAPT_DEXKEY_MP_STATE.get("no_dynamic_key", False))
    try:
        set_fast_c_mode(str(_IAPT_DEXKEY_MP_STATE.get("fast_c") or "on"))
        if str(_IAPT_DEXKEY_MP_STATE.get("fast_c") or "on") in ("on", "auto"):
            _load_c_fast_core(verbose=False)
    except Exception:
        pass
    try:
        # v94: hard-watchdog mode may kill/restart workers.  Do NOT re-analyze
        # the native SO every time a worker is respawned.  The parent process can
        # prebuild the probe plan once and pass it here; workers then only reuse
        # the already extracted keysets / outer candidates.
        prebuilt_plan = _IAPT_DEXKEY_MP_STATE.get("probe_plan_prebuilt")
        if isinstance(prebuilt_plan, dict) and prebuilt_plan:
            _IAPT_DEXKEY_MP_STATE["probe_plan"] = prebuilt_plan
            try:
                if (not _IAPT_DEXKEY_MP_STATE.get("enum_quiet")) and not _IAPT_DEXKEY_MP_STATE.get("_prebuilt_plan_notice_printed"):
                    print("[+] dexkey worker cache: reuse prebuilt SO probe plan; skip SO re-analysis", flush=True)
                    _IAPT_DEXKEY_MP_STATE["_prebuilt_plan_notice_printed"] = True
            except Exception:
                pass
        else:
            _IAPT_DEXKEY_MP_STATE["probe_plan"] = _iapt_dexkey_build_cached_probe_plan(_IAPT_DEXKEY_MP_STATE)
    except Exception as e:
        # Keep old behavior available if cache preparation hits an unexpected sample.
        _IAPT_DEXKEY_MP_STATE["probe_plan_error"] = f"{type(e).__name__}: {e}"
        _IAPT_DEXKEY_MP_STATE["probe_plan"] = {}


def _iapt_dexkey_mp_probe_range(job: Tuple[int, int, int]) -> Dict[str, object]:
    """Probe [start, stop] dexkey values in one process.

    v91: each dexkey candidate is isolated by a soft watchdog.  A bad candidate
    can no longer block the whole first chunk forever.  Worker-side progress is
    printed so Termux shows that keys are actually being tested.
    """
    start, stop, job_id = job
    st = _IAPT_DEXKEY_MP_STATE
    tested = 0
    timeout_count = 0
    last_error = ""
    import contextlib
    import io
    import tempfile
    worker_out = Path(tempfile.gettempdir()) / ("iapt_dexkey_enum_%s_%s" % (os.getpid(), job_id))
    so_data = st["so_data"]
    hidden = st["hidden"]
    container = st["container"]
    package = st["package"]
    version_name = st["version_name"]
    version_code = st["version_code"]
    app_label = st["app_label"]
    manual_post_key = st.get("manual_post_key")
    manual_key_xor = st.get("manual_key_xor")
    mode = str(st.get("mode") or "auto")
    outer_mode = str(st.get("outer_mode") or "auto")
    use_c = bool(st.get("use_c", False))
    c_path = str(st.get("c_path") or "./libiapp_core.so")
    debug_candidates = bool(st.get("debug_candidates", False))
    try:
        probe_timeout_ms = max(0, int(st.get("dexkey_probe_timeout_ms", 300) or 0))
    except Exception:
        probe_timeout_ms = 300
    verbose_each = bool(st.get("dexkey_verbose_each", False))
    enum_quiet = bool(st.get("enum_quiet", False))
    try:
        progress_every = max(1, int(st.get("dexkey_progress_every", 1000) or 1000))
    except Exception:
        progress_every = 1000

    if (not enum_quiet) and (verbose_each or int(job_id) == 0):
        print(
            f"[+] dexkey worker[{job_id}] range={int(start)}-{int(stop)} "
            f"timeout={probe_timeout_ms}ms verbose={int(verbose_each)}",
            flush=True,
        )

    for fb_try in range(int(start), int(stop) + 1):
        tested += 1
        t_one = time.perf_counter()
        status = "fail"
        err_text = ""
        try:
            def _probe_one_key():
                # Hot path: use per-worker cached SO keys / outer algorithm candidates.
                # Only build the tiny f.b()-dependent env per candidate.  If cache
                # preparation failed, fall back to the old auto_select_keys path.
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    cached_hit = _iapt_dexkey_cached_probe_one(int(fb_try)) if st.get("probe_plan") else None
                    if cached_hit is not None:
                        post_key, key_xor, outer_key, container_plain, trace = cached_hit
                    else:
                        post_key, key_xor, outer_key, container_plain, trace = auto_select_keys(
                            so_data, hidden, container, package, version_name, version_code, app_label, fb_try,
                            manual_post_key, manual_key_xor, mode=mode, outer_mode=outer_mode, outdir=worker_out,
                            dump_static_ir=False, trace_slky_args=False, trace_asendn_args=False,
                            use_c=use_c, c_path=c_path, debug_candidates=False,
                            dump_outer_candidates=False, shell_probe_only=True,
                        )
                    # Padding-valid shell hits can be false positives. Verify only
                    # the selected main file, not the whole project, before returning.
                    finalize_outer_shell_probe(
                        container_plain, post_key, key_xor, hidden, fb_try, trace,
                        use_c=use_c, c_path=c_path,
                    )
                return True

            with _IaptSoftTimeoutMs(probe_timeout_ms, f"dexkey[{fb_try}] probe"):
                _probe_one_key()
            dt = ms_since(t_one)
            print(
                f"[+] dexkey OK worker={job_id} idx={tested} key={int(fb_try)} {dt:.3f} ms",
                flush=True,
            )
            return {
                "ok": True, "fb": int(fb_try), "tested": tested,
                "job_id": int(job_id), "start": int(start), "stop": int(stop),
                "cached_probe": bool(st.get("probe_plan")), "timeouts": timeout_count,
            }
        except _IaptProbeTimeout as e:
            timeout_count += 1
            status = "timeout"
            err_text = str(e)
            last_error = f"{type(e).__name__}: {str(e)[:180]}"
        except BaseException as e:
            status = "fail"
            err_text = f"{type(e).__name__}: {str(e)[:180]}"
            last_error = err_text

        dt = ms_since(t_one)
        if (not enum_quiet) and (verbose_each or tested <= 8 or tested % progress_every == 0 or int(fb_try) == int(stop)):
            print(
                f"[!] dexkey {status} worker={job_id} idx={tested} "
                f"key={int(fb_try)} {dt:.3f} ms {err_text}",
                flush=True,
            )
    return {
        "ok": False, "tested": tested, "job_id": int(job_id),
        "start": int(start), "stop": int(stop), "last_error": last_error,
        "timeouts": timeout_count,
    }



def _iapt_dexkey_hard_batch_worker(state: Dict[str, object], start: int, stop: int, job_id: int, q) -> None:
    """Probe a small dexkey range in a child process.

    This worker intentionally has no in-process timeout.  The parent process
    watches the last reported key and kills this whole process if the current
    key hangs inside native/C code or a pathological Python branch.
    """
    import contextlib
    import io
    import tempfile
    try:
        _iapt_dexkey_mp_init(state)
        st = _IAPT_DEXKEY_MP_STATE
        worker_out = Path(tempfile.gettempdir()) / ("iapt_dexkey_hard_%s_%s" % (os.getpid(), job_id))
        so_data = st["so_data"]
        hidden = st["hidden"]
        container = st["container"]
        package = st["package"]
        version_name = st["version_name"]
        version_code = st["version_code"]
        app_label = st["app_label"]
        manual_post_key = st.get("manual_post_key")
        manual_key_xor = st.get("manual_key_xor")
        mode = str(st.get("mode") or "auto")
        outer_mode = str(st.get("outer_mode") or "auto")
        use_c = bool(st.get("use_c", False))
        c_path = str(st.get("c_path") or "./libiapp_core.so")
        tested = 0
        q.put({"event":"start", "job_id": int(job_id), "start": int(start), "stop": int(stop), "pid": os.getpid()})
        for fb_try in range(int(start), int(stop) + 1):
            tested += 1
            t_one = time.perf_counter()
            q.put({"event":"try", "job_id": int(job_id), "key": int(fb_try), "idx": int(tested), "ts": time.time()})
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    cached_hit = _iapt_dexkey_cached_probe_one(int(fb_try)) if st.get("probe_plan") else None
                    if cached_hit is not None:
                        post_key, key_xor, outer_key, container_plain, trace = cached_hit
                    else:
                        post_key, key_xor, outer_key, container_plain, trace = auto_select_keys(
                            so_data, hidden, container, package, version_name, version_code, app_label, int(fb_try),
                            manual_post_key, manual_key_xor, mode=mode, outer_mode=outer_mode, outdir=worker_out,
                            dump_static_ir=False, trace_slky_args=False, trace_asendn_args=False,
                            use_c=use_c, c_path=c_path, debug_candidates=False,
                            dump_outer_candidates=False, shell_probe_only=True,
                        )
                    finalize_outer_shell_probe(container_plain, post_key, key_xor, hidden, int(fb_try), trace, use_c=use_c, c_path=c_path)
                q.put({"event":"ok", "job_id": int(job_id), "key": int(fb_try), "idx": int(tested), "ms": ms_since(t_one)})
                return
            except BaseException as e:
                q.put({
                    "event":"fail", "job_id": int(job_id), "key": int(fb_try), "idx": int(tested),
                    "ms": ms_since(t_one), "err": f"{type(e).__name__}: {str(e)[:220]}",
                })
        q.put({"event":"done", "job_id": int(job_id), "start": int(start), "stop": int(stop), "tested": int(tested)})
    except BaseException as e:
        try:
            q.put({"event":"crash", "job_id": int(job_id), "start": int(start), "stop": int(stop), "err": f"{type(e).__name__}: {str(e)[:500]}"})
        except Exception:
            pass





def _iapt_build_quad_index_lanes(total: int, workers: int = 4) -> List[List[int]]:
    """Build balanced N-way index lanes with alternating directions.

    The candidate list is split into N contiguous shards.  Even shards scan
    low-to-high and odd shards scan high-to-low, so adjacent worker pairs
    converge.  Unlike the old four-anchor round-robin builder, workers 5..N get
    their own middle shard instead of trailing an existing lane.
    """
    total = max(0, int(total))
    if total <= 0:
        return []
    workers = max(1, min(int(workers or 1), total, 32))
    base, rem = divmod(total, workers)
    lanes: List[List[int]] = []
    lo = 0
    for shard_id in range(workers):
        size = base + (1 if shard_id < rem else 0)
        hi = lo + size - 1
        if shard_id & 1:
            lanes.append(list(range(hi, lo - 1, -1)))
        else:
            lanes.append(list(range(lo, hi + 1)))
        lo = hi + 1
    return lanes

def _iapt_sokey_quad_worker(state: Dict[str, object], indexed_hidden: List[Tuple[int, bytes]], fb_value, job_id: int, q) -> None:
    """Worker for sokey quad-sweep.  It reuses the prebuilt probe plan and only
    swaps hidden/sokey per candidate.  A hit returns the selected key material;
    the parent terminates the other workers.
    """
    try:
        _iapt_dexkey_mp_init(state)
        verbose_each = bool(state.get("sokey_verbose_each", False))
        progress_every = max(1, int(state.get("sokey_progress_every", 100) or 100))
        total = int(state.get("sokey_total", len(indexed_hidden)) or len(indexed_hidden))
        emit_progress = bool(state.get("sokey_emit_progress", True))
        local_tested = 0
        for idx, hidden_try in indexed_hidden:
            local_tested += 1
            t_one = time.perf_counter()
            if verbose_each:
                try:
                    print(f"[+] sokey try worker={job_id} idx={idx + 1}/{total} {hidden_try.decode('ascii','replace')}", flush=True)
                except Exception:
                    pass
            try:
                hit = _iapt_dexkey_cached_probe_one(fb_value, hidden_override=hidden_try)
                if hit is None:
                    raise RuntimeError("cached sokey mian.iyu probe failed")
                post_key, key_xor, outer_key, container_plain, trace = hit
                q.put({
                    "event": "ok", "job_id": int(job_id), "idx": int(idx), "hidden": hidden_try,
                    "post_key": post_key, "key_xor": key_xor, "outer_key": outer_key,
                    "container_plain": container_plain, "trace": trace, "ms": ms_since(t_one),
                })
                return
            except BaseException as e:
                if verbose_each:
                    q.put({
                        "event": "fail", "job_id": int(job_id), "idx": int(idx), "hidden": hidden_try,
                        "ms": ms_since(t_one), "err": f"{type(e).__name__}: {str(e)[:260]}",
                    })
                elif emit_progress and local_tested % progress_every == 0:
                    q.put({
                        "event": "prog", "job_id": int(job_id), "idx": int(idx),
                        "tested": int(local_tested), "ms": ms_since(t_one),
                    })
        q.put({"event": "done", "job_id": int(job_id), "tested": len(indexed_hidden)})
    except BaseException as e:
        try:
            q.put({"event": "crash", "job_id": int(job_id), "err": f"{type(e).__name__}: {str(e)[:500]}"})
        except Exception:
            pass


def _iapt_sokey_quad_parallel_probe(
    hidden_candidates: List[bytes],
    fb_value,
    state: Dict[str, object],
    args,
) -> Optional[Tuple[int, bytes, bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    import multiprocessing as _mp
    import queue as _queue
    total = len(hidden_candidates or [])
    if total <= 0:
        return None
    workers = int(getattr(args, "enum_workers", 0) or 0)
    if workers <= 0:
        workers = 4
    workers = max(1, min(workers, total, 32))
    lanes_idx = _iapt_build_quad_index_lanes(total, workers)
    lanes: List[List[Tuple[int, bytes]]] = [[(i, hidden_candidates[i]) for i in lane] for lane in lanes_idx]
    preview = []
    for lane in lanes_idx:
        preview.append("empty" if not lane else f"{lane[0]+1}->{lane[min(len(lane)-1, 3)]+1}")
    enum_quiet = bool(getattr(args, "enum_quiet", False))
    if not enum_quiet:
        print(f"[+] sokey scan strategy = n-way-sweep; workers={workers}; max={total}; lanes={', '.join(preview)}", flush=True)

    st = dict(state or {})
    st["sokey_total"] = int(total)
    st["sokey_verbose_each"] = bool(getattr(args, "sokey_verbose_each", False))
    st["sokey_progress_every"] = max(1, int(getattr(args, "sokey_progress_every", 100) or 100))
    st["sokey_emit_progress"] = not enum_quiet
    procs = []
    queues = []
    tested = 0
    crashes = []
    t0 = time.perf_counter()
    try:
        for job_id, lane in enumerate(lanes):
            if not lane:
                continue
            q = _mp.Queue()
            p = _mp.Process(target=_iapt_sokey_quad_worker, args=(st, lane, fb_value, job_id, q))
            p.daemon = False
            p.start()
            procs.append(p)
            queues.append(q)
        while procs:
            any_msg = False
            for q in list(queues):
                while True:
                    try:
                        msg = q.get_nowait()
                    except _queue.Empty:
                        break
                    except Exception:
                        break
                    any_msg = True
                    ev = msg.get("event")
                    if ev == "fail":
                        tested += 1
                        try:
                            htxt = msg.get("hidden", b"").decode("ascii", "replace")
                        except Exception:
                            htxt = "<hidden>"
                        print(
                            f"[!] sokey fail tested={tested}/{total} worker={msg.get('job_id')} "
                            f"idx={int(msg.get('idx', -1)) + 1} {float(msg.get('ms') or 0):.3f} ms "
                            f"hidden={htxt}: {msg.get('err')}",
                            flush=True,
                        )
                    elif ev == "prog" and not enum_quiet:
                        print(
                            f"[+] sokey prog worker={msg.get('job_id')} lane_tested={msg.get('tested')} "
                            f"idx={int(msg.get('idx', -1)) + 1}/{total}",
                            flush=True,
                        )
                    elif ev == "ok":
                        idx = int(msg.get("idx"))
                        hidden = msg.get("hidden")
                        print(
                            f"[+] sokey OK idx={idx + 1}/{total} worker={msg.get('job_id')} "
                            f"{float(msg.get('ms') or 0):.3f} ms hidden={hidden.decode('ascii','replace')}",
                            flush=True,
                        )
                        for p in procs:
                            try:
                                if p.is_alive():
                                    p.terminate()
                            except Exception:
                                pass
                        return (idx, hidden, msg.get("post_key"), msg.get("key_xor"), msg.get("outer_key"), msg.get("container_plain"), msg.get("trace"))
                    elif ev == "done":
                        if not bool(getattr(args, "sokey_verbose_each", False)):
                            tested += int(msg.get("tested", 0) or 0)
                    elif ev == "crash":
                        crashes.append(str(msg.get("err") or "worker crash"))
                        print(f"[!] sokey worker crash worker={msg.get('job_id')}: {msg.get('err')}", flush=True)
            procs = [p for p in procs if p.is_alive()]
            if not any_msg:
                time.sleep(0.02)
        print(f"[!] sokey quad-sweep finished without hit; tested≈{tested}/{total}; elapsed={ms_since(t0):.3f} ms", flush=True)
        if crashes:
            print("[!] sokey worker crash summary: " + "; ".join(crashes[:4]), flush=True)
        return None
    finally:
        for p in procs:
            try:
                if p.is_alive():
                    p.terminate()
            except Exception:
                pass



def _iapt_cbatch_validate_fb_hit(state: Dict[str, object], fb_hit: int, hidden: bytes) -> bool:
    """Validate and retain a C hit through the original Python probe path.

    The retained tuple is consumed by the caller after enumeration.  This is
    important for arm64 SOs where several Q literals can produce valid PKCS#7
    outer-shell padding: only the tuple that also decrypts ``mian.iyu`` is safe
    to finalize.
    """
    global _IAPT_DEXKEY_MP_STATE, _IAPT_LAST_CBATCH_VERIFIED_RESULT
    old = dict(_IAPT_DEXKEY_MP_STATE or {})
    try:
        st = dict(state or {})
        st["hidden"] = hidden
        _iapt_dexkey_mp_init(st)
        hit = _iapt_dexkey_cached_probe_one(int(fb_hit), hidden_override=hidden)
        if hit is None:
            return False
        post_key, key_xor, outer_key, container_plain, trace = hit
        trace, _main_plain = finalize_outer_shell_probe(
            container_plain, post_key, key_xor, hidden, int(fb_hit), trace,
            use_c=bool(st.get("use_c", False)),
            c_path=str(st.get("c_path") or "./libiapp_core.so"),
        )
        trace = dict(trace or {})
        trace["enum_shell_probe_finalized"] = b"1"
        _IAPT_LAST_CBATCH_VERIFIED_RESULT[(int(fb_hit), bytes(hidden))] = (
            bytes(post_key), bytes(key_xor), bytes(outer_key), bytes(container_plain), trace
        )
        # Bound stale entries if several false/duplicate C paths race.
        while len(_IAPT_LAST_CBATCH_VERIFIED_RESULT) > 8:
            _IAPT_LAST_CBATCH_VERIFIED_RESULT.pop(next(iter(_IAPT_LAST_CBATCH_VERIFIED_RESULT)))
        return True
    except Exception:
        return False
    finally:
        _IAPT_DEXKEY_MP_STATE = old




def _iapt_dexkey_cbatch_mp_worker(state: Dict[str, object], keysets: List[Tuple[str, bytes, bytes]], jobs: List[Tuple[int, int, int]], main_file: str, q, worker_id: int) -> None:
    """Full-C worker with chunk-first scheduling and native direction support.

    ``jobs`` may contain ascending chunks (start <= stop) or descending chunks
    (start > stop).  The whole numeric chunk is always passed to the C scanner
    in one call; Python never expands a descending lane into per-key calls.
    """
    try:
        # Low-core latency mode may launch more search lanes than CPU slots.
        # Pin each lane process to its assigned CPU so --enum-workers remains
        # a CPU budget instead of silently consuming every core on the device.
        _cpu_id = state.get("cbatch_cpu_id")
        if _cpu_id is not None and hasattr(os, "sched_setaffinity"):
            try:
                os.sched_setaffinity(0, {int(_cpu_id)})
            except Exception:
                pass
        _load_c_fast_core(False)
        _cfast_set_mian_prefix_limit(int(state.get("cbatch_prefix_limit", 0) or 0))
        _cfast_set_tail_marker_gate(str(state.get("cbatch_tail_name") or ""), bool(state.get("cbatch_tail_gate", False)))
        _cfast_set_idbfj_variant_mode(int(state.get("cbatch_idbfj_variant_mode", -1)))
        hidden = bytes(state.get("hidden") or b"")
        container = state.get("container") or b""
        package = str(state.get("package") or "")
        version_name = str(state.get("version_name") or "")
        version_code = state.get("version_code")
        app_label = str(state.get("app_label") or "")
        checked_chunks = 0
        false_hits = 0
        broad_mode = bool(state.get("c_batch_broad", False))
        extra_env = dict(state.get("extra_outer_env") or {})
        emit_progress = bool(state.get("cbatch_emit_progress", False))
        progress_every = max(1, int(state.get("cbatch_progress_every", 1000) or 1000))

        priority_inputs: List[Tuple[str, bytes]] = []
        seen_inputs = set()
        if hidden:
            priority_inputs.append(("hidden", hidden))
            seen_inputs.add(hidden)
        for input_name, input_bytes in list(state.get("c_idbfj_inputs") or _iapt_priority_idbfj_inputs(extra_env)):
            input_bytes = bytes(input_bytes or b"")
            if input_bytes and input_bytes not in seen_inputs:
                seen_inputs.add(input_bytes)
                priority_inputs.append((str(input_name), input_bytes))
        signature = bytes(extra_env.get("signature") or b"")

        # Chunk first, keyset second.  Every plausible ABI key pair is tried on
        # the worker's current numeric chunk before the lane advances.
        for a, b, jid in jobs:
            direction = 1 if int(a) <= int(b) else -1
            for kname, pk, xk in keysets:
                cur_a, cur_b = int(a), int(b)

                for input_name, input_bytes in priority_inputs:
                    res = _cfast_idbfj_dexkey_scan_mian(
                        container, hidden, package, version_name, version_code, app_label,
                        input_bytes, signature, cur_a, cur_b, direction, pk, xk, main_file,
                    )
                    if res is not None:
                        hit, variant = int(res[0]), int(res[1])
                        q.put({"event": "candidate", "worker": worker_id, "key": hit, "keyset": f"{kname}/{input_name}/idbfj{variant}"})
                        if _iapt_cbatch_validate_fb_hit(state, hit, hidden):
                            q.put({"event": "ok", "worker": worker_id, "key": hit, "keyset": f"{kname}/{input_name}/idbfj{variant}"})
                            return

                while (direction > 0 and cur_a <= cur_b) or (direction < 0 and cur_a >= cur_b):
                    if broad_mode:
                        res = _cfast_broad_dexkey_scan_mian(
                            container, hidden, package, version_name, version_code, app_label,
                            cur_a, cur_b, direction, pk, xk, main_file,
                        )
                        hit = (res or (None, None))[0]
                    else:
                        hit = _cfast_fixed_dexkey_scan_mian(
                            container, hidden, package, version_name, version_code, app_label,
                            cur_a, cur_b, direction, pk, xk, main_file,
                        )
                    if hit is None:
                        checked_chunks += 1
                        if emit_progress and checked_chunks % progress_every == 0:
                            q.put({"event": "prog", "worker": worker_id, "chunks": checked_chunks, "last": cur_b})
                        break
                    hit = int(hit)
                    q.put({"event": "candidate", "worker": worker_id, "key": hit, "keyset": kname})
                    if _iapt_cbatch_validate_fb_hit(state, hit, hidden):
                        q.put({"event": "ok", "worker": worker_id, "key": hit, "keyset": kname})
                        return
                    false_hits += 1
                    cur_a = hit + direction
        q.put({"event": "done", "worker": worker_id, "chunks": checked_chunks, "false_hits": false_hits})
    except BaseException as e:
        q.put({"event": "crash", "worker": worker_id, "err": f"{type(e).__name__}: {e}"})


def _iapt_build_dexkey_worker_lanes(
    fb_start: int, fb_stop: int, chunk_size: int, workers: int, strategy: str,
) -> List[List[Tuple[int, int, int]]]:
    """Split the numeric range into balanced, non-overlapping worker lanes.

    In ``quad-sweep`` mode the range is divided into N contiguous shards.  Even
    shards scan upward and odd shards scan downward, so each adjacent worker
    pair converges toward the boundary between its two shards:

      N=2:  start -> middle, stop -> middle
      N=4:  four quarter shards, alternating direction
      N=8:  eight eighth shards, alternating direction

    This scales to any worker count instead of having only four useful anchors
    followed by extra workers that merely trail the first four by one chunk.
    """
    fb_start = int(fb_start)
    fb_stop = int(fb_stop)
    chunk_size = max(1, int(chunk_size))
    if fb_stop < fb_start:
        fb_start, fb_stop = fb_stop, fb_start
    total = fb_stop - fb_start + 1
    if total <= 0:
        return []
    workers = max(1, min(int(workers or 1), total))
    base, rem = divmod(total, workers)

    segments: List[Tuple[int, int]] = []
    lo = fb_start
    for i in range(workers):
        size = base + (1 if i < rem else 0)
        hi = lo + size - 1
        segments.append((lo, hi))
        lo = hi + 1

    lanes: List[List[Tuple[int, int, int]]] = []
    job_id = 0
    use_sweep = (strategy or "linear") == "quad-sweep"
    for shard_id, (lo, hi) in enumerate(segments):
        descending = bool(use_sweep and (shard_id & 1))
        lane: List[Tuple[int, int, int]] = []
        if descending:
            cur = hi
            while cur >= lo:
                nxt = max(lo, cur - chunk_size + 1)
                lane.append((cur, nxt, job_id))
                job_id += 1
                cur = nxt - 1
        else:
            cur = lo
            while cur <= hi:
                nxt = min(hi, cur + chunk_size - 1)
                lane.append((cur, nxt, job_id))
                job_id += 1
                cur = nxt + 1
        lanes.append(lane)

    # Cheap hard validation: shards must exactly tile the requested range and
    # every lane's chunks must exactly tile its shard in its declared direction.
    if segments[0][0] != fb_start or segments[-1][1] != fb_stop:
        raise RuntimeError("dexkey lane partition does not cover range endpoints")
    for i in range(1, len(segments)):
        if segments[i - 1][1] + 1 != segments[i][0]:
            raise RuntimeError("dexkey lane partition has a gap or overlap")
    covered = 0
    for shard_id, (segment, lane) in enumerate(zip(segments, lanes)):
        lo, hi = segment
        lane_count = sum(abs(int(a) - int(b)) + 1 for a, b, _ in lane)
        if lane_count != hi - lo + 1:
            raise RuntimeError(f"dexkey worker lane {shard_id} coverage mismatch")
        covered += lane_count
    if covered != total:
        raise RuntimeError("dexkey worker lanes do not cover the full range")
    return lanes


def _iapt_try_dexkey_cbatch_parallel(
    state: Dict[str, object], keysets: List[Tuple[str, bytes, bytes]], fb_start: int, fb_stop: int, args,
) -> Optional[int]:
    """Parallel full-C dexkey enum with separate CPU budget and search lanes.

    Native C scans are long, non-preemptible calls at the Python scheduler
    level.  With only two lane processes, a key near the middle can be blocked
    behind a complete wrong endpoint chunk.  On low-core devices we therefore
    keep four numeric search lanes (start, middle-down, middle-up, end) for
    a two-CPU budget and pin those lane processes onto the two CPU slots.

    This is intentional light oversubscription: four processes on two CPUs use
    only two cores, but the OS time-slices all four C scans so no anchor waits
    for another full C call to return.  Users can override the logical lane
    count with --dexkey-enum-lanes.
    """
    import multiprocessing as _mp
    import queue as _queue

    cpu_workers = int(getattr(args, "enum_workers", 0) or min(4, os.cpu_count() or 1))
    cpu_workers = max(1, min(cpu_workers, 32))
    raw_chunk = int(getattr(args, "enum_chunk_size", 0) or 0)
    chunk_size = raw_chunk if raw_chunk and raw_chunk != 4096 else 65536
    chunk_size = max(1024, min(chunk_size, 262144))
    strategy = str(getattr(args, "dexkey_scan_strategy", "quad-sweep") or "quad-sweep")
    total = abs(int(fb_stop) - int(fb_start)) + 1
    cpu_workers = min(cpu_workers, max(1, total))

    requested_lanes = int(getattr(args, "dexkey_enum_lanes", 0) or 0)
    if requested_lanes > 0:
        lane_count = requested_lanes
    elif strategy == "quad-sweep" and cpu_workers == 2 and total >= 4:
        lane_count = 4
    else:
        lane_count = cpu_workers
    lane_count = max(1, min(lane_count, 32, total))

    lanes = _iapt_build_dexkey_worker_lanes(
        int(fb_start), int(fb_stop), int(chunk_size), lane_count, strategy
    )
    lanes = [lane for lane in lanes if lane]
    if not lanes:
        return None
    lane_count = len(lanes)

    enum_quiet = bool(getattr(args, "enum_quiet", False))
    native_cpu_slots: List[int] = []
    if hasattr(os, "sched_getaffinity"):
        try:
            _allowed = sorted(int(x) for x in os.sched_getaffinity(0))
            native_cpu_slots = _allowed[: min(cpu_workers, len(_allowed))]
        except Exception:
            native_cpu_slots = []
    # Common fixed-idbfj path: one native pthread call replaces all Python
    # worker creation/copy/Queue overhead. Broad formula mode retains the
    # proven multiprocessing scheduler below.
    if not bool(state.get("c_batch_broad", False)):
        _cfast_set_mian_prefix_limit(int(state.get("cbatch_prefix_limit", 0) or 0))
        _cfast_set_tail_marker_gate(str(state.get("cbatch_tail_name") or ""), bool(state.get("cbatch_tail_gate", False)))
        _cfast_set_idbfj_variant_mode(int(state.get("cbatch_idbfj_variant_mode", -1)))
        extra_env = dict(state.get("extra_outer_env") or {})
        native_inputs = list(state.get("c_idbfj_inputs") or _iapt_priority_idbfj_inputs(extra_env))
        signature = bytes(extra_env.get("signature") or b"")
        t_native = time.perf_counter()
        native_hit = _cfast_idbfj_parallel_scan_mian(
            bytes(state.get("container") or b""), bytes(state.get("hidden") or b""),
            str(state.get("package") or ""), str(state.get("version_name") or ""), state.get("version_code"),
            str(state.get("app_label") or ""), native_inputs, signature, lanes, chunk_size, keysets, str(MUST_HAVE_MAIN), native_cpu_slots,
        )
        if native_hit is not None:
            key, variant, lane_id, keyset_id, input_id = native_hit
            hidden_b = bytes(state.get("hidden") or b"")
            if _iapt_cbatch_validate_fb_hit(state, key, hidden_b):
                print(
                    f"[+] dexkey C-native verified mode=fixed-fast key={key} lane={lane_id} "
                    f"cpu_workers={cpu_workers} search_lanes={lane_count} elapsed={time.perf_counter()-t_native:.3f}s",
                    flush=True,
                )
                return int(key)
        # A native no-hit is authoritative for the idbfj priority formulas, but
        # fixed/broad legacy formulas may still be needed, so continue below.
    worker_state = dict(state or {})
    worker_state["cbatch_emit_progress"] = not enum_quiet
    worker_state["cbatch_progress_every"] = max(
        1, int(getattr(args, "dexkey_progress_every", 1000) or 1000)
    )

    # Respect the caller's CPU budget where affinity is supported.  Under
    # Termux/Linux this pins four low-core lane processes onto one/two CPUs.
    cpu_slots: List[int] = []
    if hasattr(os, "sched_getaffinity"):
        try:
            allowed = sorted(int(x) for x in os.sched_getaffinity(0))
            cpu_slots = allowed[: min(cpu_workers, len(allowed))]
        except Exception:
            cpu_slots = []

    if not enum_quiet:
        _mode_name = "broad" if bool(state.get("c_batch_broad", False)) else "fixed-fast"
        previews = []
        for i, lane in enumerate(lanes[:min(12, len(lanes))]):
            first = lane[0]
            last = lane[-1]
            direction = "+" if first[0] <= first[1] else "-"
            cpu_note = ""
            if cpu_slots:
                cpu_note = f"@cpu{cpu_slots[i % len(cpu_slots)]}"
            previews.append(f"L{i}{cpu_note}:{first[0]}->{last[1]}({direction})")
        print(
            f"[+] dexkey C-batch parallel = mode={_mode_name} cpu_workers={cpu_workers} "
            f"search_lanes={lane_count} strategy={strategy} chunk={chunk_size}",
            flush=True,
        )
        print("[+] dexkey search lanes: " + ", ".join(previews), flush=True)

    q = _mp.Queue()
    procs = []
    t0 = time.perf_counter()
    main_file = str(MUST_HAVE_MAIN)
    for i, lane in enumerate(lanes):
        proc_state = dict(worker_state)
        if cpu_slots:
            proc_state["cbatch_cpu_id"] = int(cpu_slots[i % len(cpu_slots)])
        p = _mp.Process(
            target=_iapt_dexkey_cbatch_mp_worker,
            args=(proc_state, keysets, lane, main_file, q, i),
        )
        p.daemon = False
        p.start()
        procs.append(p)

    done = 0
    last_print = time.time()
    try:
        while done < len(procs):
            try:
                msg = q.get(timeout=0.25)
            except _queue.Empty:
                if not any(p.is_alive() for p in procs):
                    break
                continue
            ev = msg.get("event")
            if ev == "ok":
                key = int(msg.get("key"))
                _mode_name = "broad" if bool(state.get("c_batch_broad", False)) else "fixed-fast"
                print(
                    f"[+] dexkey C-batch verified mode={_mode_name} key={key} "
                    f"lane={msg.get('worker')} cpu_workers={cpu_workers} "
                    f"search_lanes={lane_count} elapsed={time.perf_counter()-t0:.2f}s",
                    flush=True,
                )
                for p in procs:
                    if p.is_alive():
                        p.terminate()
                for p in procs:
                    p.join(timeout=1)
                return key
            if ev == "candidate" and not enum_quiet:
                print(
                    f"[+] dexkey FULL-C candidate key={msg.get('key')} "
                    f"lane={msg.get('worker')} keyset={msg.get('keyset')}; Python verify ...",
                    flush=True,
                )
            elif ev == "done":
                done += 1
                if not enum_quiet:
                    print(
                        f"[+] dexkey FULL-C lane done {done}/{len(procs)} "
                        f"lane={msg.get('worker')} chunks={msg.get('chunks')} "
                        f"false_hits={msg.get('false_hits')} elapsed={time.perf_counter()-t0:.1f}s",
                        flush=True,
                    )
            elif ev == "crash":
                done += 1
                if not enum_quiet:
                    print(
                        f"[!] dexkey FULL-C lane crash lane={msg.get('worker')}: {msg.get('err')}",
                        flush=True,
                    )
            elif ev == "prog" and not enum_quiet:
                now = time.time()
                if now - last_print >= 2.0:
                    last_print = now
                    print(
                        f"[+] dexkey FULL-C prog lane={msg.get('worker')} "
                        f"chunks={msg.get('chunks')} last={msg.get('last')} "
                        f"elapsed={time.perf_counter()-t0:.1f}s",
                        flush=True,
                    )
    finally:
        for p in procs:
            if p.is_alive():
                p.terminate()
        for p in procs:
            try:
                p.join(timeout=1)
            except Exception:
                pass
    return None




def _iapt_effective_mian_prefix_kb(args, container_len: int) -> int:
    """Return the C validation prefix.

    Default is a fixed 64 KiB as requested.  The C core still retries a full
    container pass when gated passes miss, preserving correctness.
    """
    try:
        raw = int(getattr(args, "dexkey_mian_prefix_kb", 64))
    except Exception:
        raw = -1
    if raw >= 0:
        return max(0, raw)
    return 64

def _iapt_effective_mian_prefix_bytes(args, container) -> int:
    try:
        n = len(container or b"")
    except Exception:
        n = 0
    return _iapt_effective_mian_prefix_kb(args, n) * 1024

def _iapt_try_joint_sokey_dexkey_cbatch(hidden_candidates: List[bytes], fb_start: int, fb_stop: int,
        so_data: bytes, container: bytes, package: str, version_name: str, version_code, app_label: str,
        manual_post_key: Optional[bytes], manual_key_xor: Optional[bytes], args):
    """Joint sokey+dexkey enumeration with two verified fast paths.

    Worst-case joint search is inherently two-dimensional.  The old diagonal
    scheduler interleaved every hidden candidate with every dex tile, which is
    fair but very slow when the correct dexkey is deep in the numeric range.

    v145 keeps the exhaustive fallback but adds:
      1. DEX-hint-first: extract f.b() from classes*.dex and scan the complete
         sokey list at that one value.  The hint is never trusted; native
         mian.iyu verification is mandatory.
      2. Hidden-major prefix: complete the full dex range for small batches of
         the highest-priority sokey candidates before entering the global
         diagonal search.  This fixes the common case where the timestamp model
         ranks the correct sokey near the front but the dexkey is far away.
    """
    if not hidden_candidates:
        return None
    sig_mode_raw = (_EXTRA_OUTER_ENV or {}).get("signature_mode", b"")
    sig_mode = (sig_mode_raw.decode("utf-8", "ignore") if isinstance(sig_mode_raw, bytes) else str(sig_mode_raw)).strip().lower()
    variant_mode = 0 if sig_mode == "skip" else (1 if sig_mode == "verify" else -1)
    st = {
        "so_data": so_data, "hidden": hidden_candidates[0], "container": container,
        "package": str(package), "version_name": str(version_name), "version_code": version_code,
        "app_label": str(app_label), "manual_post_key": manual_post_key,
        "manual_key_xor": manual_key_xor, "mode": args.mode, "outer_mode": args.outer_mode,
        "use_c": bool(args.use_c), "c_path": str(args.c_lib), "fast_c": str(args.fast_c),
        "extra_outer_env": dict(_EXTRA_OUTER_ENV),
        "apk_native_so_candidates": list(_APK_NATIVE_SO_CANDIDATES),
        "no_dynamic_key": bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)),
        "main_file": MUST_HAVE_MAIN,
        "dexkey_max_so_keysets": int(getattr(args, "dexkey_max_so_keysets", 16) or 16),
    }
    if bool(getattr(args, "enum_quiet", False)):
        import contextlib, io
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            plan = _iapt_dexkey_build_cached_probe_plan(st)
    else:
        plan = _iapt_dexkey_build_cached_probe_plan(st)
    keysets = _iapt_cbatch_keysets_from_plan(plan)
    if not keysets:
        raise RuntimeError("joint enum has no C keysets")

    workers = max(1, min(int(getattr(args, "enum_workers", 0) or min(4, os.cpu_count() or 1)), 32))
    dex_lanes = int(getattr(args, "dexkey_enum_lanes", 0) or max(4, min(16, workers)))
    hidden_lanes = int(getattr(args, "joint_hidden_lanes", 0) or max(4, min(16, workers * 2)))
    chunk = max(512, min(int(getattr(args, "joint_dex_chunk_size", 512) or 512), 262144))
    lanes = _iapt_build_dexkey_worker_lanes(int(fb_start), int(fb_stop), chunk, dex_lanes, "quad-sweep")
    const_inputs = _iapt_priority_idbfj_inputs(_EXTRA_OUTER_ENV)
    signature = bytes((_EXTRA_OUTER_ENV or {}).get("signature") or b"")

    required_raw = (_EXTRA_OUTER_ENV or {}).get("user_encryption_required", b"")
    required = (required_raw.decode("utf-8", "ignore") if isinstance(required_raw, bytes) else str(required_raw)).strip().lower() in ("1", "true", "yes", "on")
    native_only = []
    for n, v in const_inputs:
        if str(n).startswith("user_password_native"):
            native_only = [(n, v)]
            break
    if required and native_only:
        priority_inputs = native_only
        priority_hidden = False
    else:
        priority_inputs = []
        priority_hidden = True
    stages = [("priority", keysets[:1], priority_inputs, priority_hidden)]
    if len(keysets) > 1 or priority_inputs != const_inputs or not priority_hidden:
        stages.append(("expanded", keysets, const_inputs, True))

    gates = []
    prefix_bytes = _iapt_effective_mian_prefix_bytes(args, container)
    if bool(getattr(args, "dexkey_tail_marker_gate", True)):
        gates.append((True, prefix_bytes, "tail"))
    gates.append((False, prefix_bytes, "prefix"))
    if prefix_bytes > 0:
        gates.append((False, 0, "full"))

    schedule = []
    if gates and gates[0][0]:
        schedule += [(stage, gates[0]) for stage in stages]
        schedule += [(stage, gate) for gate in gates[1:] for stage in stages]
    else:
        schedule += [(stage, gate) for gate in gates for stage in stages]

    t0 = time.perf_counter()

    def run_native(candidates, scan_lanes, stage, gate):
        if not candidates:
            return None
        stage_name, stage_keys, stage_inputs, stage_hidden = stage
        tail, prefix, label = gate
        _cfast_set_tail_marker_gate(f"{str(package)}.project", tail)
        _cfast_set_mian_prefix_limit(prefix)
        _cfast_set_idbfj_variant_mode(variant_mode if tail else -1)
        hit = _cfast_joint_sokey_dexkey_scan(
            container, candidates, package, version_name, version_code, app_label,
            stage_inputs, signature, scan_lanes, stage_keys, workers, hidden_lanes,
            MUST_HAVE_MAIN, stage_hidden,
        )
        return hit, stage_name, label

    # Fast path 1: a constant-return f.b() is common.  Probe it against every
    # sokey candidate, but only accept it after the exact native main-file gate.
    # This turns the common joint task into the already-fast sokey-only scan.
    if bool(getattr(args, "joint_dex_hint_first", True)) and getattr(args, "apk", None):
        try:
            dex_hint = extract_fb_from_apk_dexes(Path(args.apk))
        except Exception as e:
            dex_hint = None
            if not bool(getattr(args, "enum_quiet", False)):
                print(f"[!] joint DEX hint extraction failed: {type(e).__name__}: {e}", flush=True)
        if dex_hint is not None and int(fb_start) <= int(dex_hint) <= int(fb_stop):
            if not bool(getattr(args, "enum_quiet", False)):
                print(f"[+] joint hint-first = verifying dexkey {int(dex_hint)} against {len(hidden_candidates)} sokey candidates", flush=True)
            one_lane = [[(int(dex_hint), int(dex_hint), 0)]]
            for stage, gate in schedule:
                result = run_native(hidden_candidates, one_lane, stage, gate)
                if result and result[0] is not None:
                    hit, stage_name, label = result
                    hi, _fb, var, ks, inp, tile = hit
                    print(
                        f"[+] joint DEX-hint verified hidden_index={hi} dexkey={int(dex_hint)} "
                        f"pass={stage_name}/{label} variant={var} keyset={ks} input={inp} "
                        f"elapsed={time.perf_counter()-t0:.3f}s",
                        flush=True,
                    )
                    return int(hi), int(dex_hint)
            if not bool(getattr(args, "enum_quiet", False)):
                print(f"[+] joint DEX hint {int(dex_hint)} did not verify; continuing exhaustive enum", flush=True)

    # True no-hint exhaustive path.  Joint enumeration is usually requested
    # precisely because neither key is available.  In that case a DEX hint is
    # only opportunistic and must not be the main optimization.
    #
    # The old 2-D scheduler split the dex range into thousands of tiny tiles.
    # Every (sokey,tile) job rebuilt the same hidden-dependent MD5/AES setup,
    # which dominated runtime.  A single full-range tile makes each worker take
    # one sokey and scan the entire dexkey range in one native call.  The search
    # is still exact Cartesian enumeration, but hidden-dependent setup is paid
    # once per sokey instead of once per tile.
    try:
        no_hint_enabled = bool(getattr(args, "joint_no_hint_hidden_major", True))
    except Exception:
        no_hint_enabled = True
    try:
        no_hint_min_hidden = max(1, int(getattr(args, "joint_no_hint_min_hidden", 16) or 16))
    except Exception:
        no_hint_min_hidden = 16

    no_hint_first_pass_done = False
    if no_hint_enabled and len(hidden_candidates) >= no_hint_min_hidden:
        full_direction = 1 if int(fb_start) <= int(fb_stop) else -1
        full_range_lane = [[(int(fb_start), int(fb_stop), full_direction)]]
        fast_stage, fast_gate = schedule[0]
        if not bool(getattr(args, "enum_quiet", False)):
            print(
                f"[+] joint no-hint exhaustive = hidden-major full-range; "
                f"sokey={len(hidden_candidates)} dex={int(fb_start)}..{int(fb_stop)} "
                f"workers={workers}; no metadata required",
                flush=True,
            )
        result = run_native(hidden_candidates, full_range_lane, fast_stage, fast_gate)
        no_hint_first_pass_done = True
        if result and result[0] is not None:
            hit, stage_name, label = result
            hi, fb, var, ks, inp, tile = hit
            print(
                f"[+] joint no-hint hit hidden_index={int(hi)} dexkey={int(fb)} "
                f"pass={stage_name}/{label} variant={var} keyset={ks} "
                f"input={inp} elapsed={time.perf_counter()-t0:.3f}s",
                flush=True,
            )
            return int(hi), int(fb)
        if not bool(getattr(args, "enum_quiet", False)):
            print(
                f"[+] joint no-hint exact first pass exhausted in {time.perf_counter()-t0:.1f}s; "
                "trying broader verification gates",
                flush=True,
            )

    # Compatibility priority prefix.  It is useful only when the sokey model
    # has meaningful ordering.  Disable it after the full no-hint pass because
    # schedule[0] has already covered every Cartesian pair exactly.
    try:
        fast_limit = max(0, int(getattr(args, "joint_fast_hidden_limit", 256) or 0))
    except Exception:
        fast_limit = 256
    try:
        batch_size = max(1, int(getattr(args, "joint_fast_hidden_batch_size", 8) or 8))
    except Exception:
        batch_size = 8
    fast_limit = 0 if no_hint_first_pass_done else min(len(hidden_candidates), fast_limit)
    fast_stage, fast_gate = schedule[0]
    if fast_limit > 0:
        if not bool(getattr(args, "enum_quiet", False)):
            print(
                f"[+] joint hidden-major prefix = {fast_limit} candidates batch={batch_size}; "
                f"full dex range {int(fb_start)}..{int(fb_stop)}",
                flush=True,
            )
        for base in range(0, fast_limit, batch_size):
            end = min(fast_limit, base + batch_size)
            # Use one full-range tile here as well; tiny dex tiles only repeat
            # hidden-dependent setup and make the no-information case slower.
            full_direction = 1 if int(fb_start) <= int(fb_stop) else -1
            prefix_lane = [[(int(fb_start), int(fb_stop), full_direction)]]
            result = run_native(hidden_candidates[base:end], prefix_lane, fast_stage, fast_gate)
            if result and result[0] is not None:
                hit, stage_name, label = result
                hi, fb, var, ks, inp, tile = hit
                global_hi = base + int(hi)
                print(
                    f"[+] joint hidden-major hit hidden_index={global_hi} dexkey={int(fb)} "
                    f"batch={base}:{end} pass={stage_name}/{label} variant={var} "
                    f"keyset={ks} input={inp} tile={tile} elapsed={time.perf_counter()-t0:.3f}s",
                    flush=True,
                )
                return global_hi, int(fb)
            if not bool(getattr(args, "enum_quiet", False)) and (end == fast_limit or end % max(batch_size, 64) == 0):
                print(f"[+] joint hidden-major progress {end}/{fast_limit} elapsed={time.perf_counter()-t0:.1f}s", flush=True)

    # Exhaustive correctness fallback.  When the no-hint full-range pass ran,
    # schedule[0] is already completely covered and is skipped.  Broader
    # keyset/input/gate passes still cover the full Cartesian product.
    for schedule_index, (stage, gate) in enumerate(schedule):
        if schedule_index == 0 and no_hint_first_pass_done:
            continue
        offset = 0
        candidates = hidden_candidates
        if schedule_index == 0 and fast_limit > 0:
            offset = fast_limit
            candidates = hidden_candidates[fast_limit:]
            if not candidates:
                continue
        result = run_native(candidates, lanes, stage, gate)
        if result and result[0] is not None:
            hit, stage_name, label = result
            hi, fb, var, ks, inp, tile = hit
            global_hi = offset + int(hi)
            print(
                f"[+] joint C-native hit hidden_index={global_hi} dexkey={int(fb)} "
                f"pass={stage_name}/{label} variant={var} keyset={ks} input={inp} "
                f"tile={tile} elapsed={time.perf_counter()-t0:.3f}s",
                flush=True,
            )
            return global_hi, int(fb)
        if not bool(getattr(args, "enum_quiet", False)):
            stage_name = stage[0]
            label = gate[2]
            print(f"[+] joint {stage_name}/{label} no-hit; trying next stage", flush=True)
    return None


def _iapt_try_dexkey_cbatch_fixed(
    hidden: bytes, fb_start: int, fb_stop: int, so_data: bytes, container: bytes, package: str,
    version_name: str, version_code, app_label: str, manual_post_key: Optional[bytes], manual_key_xor: Optional[bytes], args,
) -> Optional[int]:
    """C batch scan for the fixed p19/p24/p25 outer formula.

    It is a prefilter only: C scans thousands/millions of f.b()/dexkey values in
    one call and returns a padding hit.  Python then verifies the hit using the
    original cached mian.iyu probe, so a false padding hit will be skipped and the
    scan resumes.  Dynamic/native formulas still fall back to the normal Python
    enum path.
    """
    no_py_fallback = bool(getattr(args, "no_python_fallback", False))
    if not bool(getattr(args, "dexkey_c_batch", False)):
        if no_py_fallback:
            raise RuntimeError("--no-python-fallback requires --dexkey-c-batch for dexkey enum")
        return None
    if str(getattr(args, "fast_c", "on") or "on").lower() == "off":
        if no_py_fallback:
            raise RuntimeError("--no-python-fallback cannot run: --fast-c is off, so dexkey C-batch is disabled")
        return None
    _sig_mode_raw = (_EXTRA_OUTER_ENV or {}).get("signature_mode", b"")
    if isinstance(_sig_mode_raw, bytes):
        _sig_mode_text = _sig_mode_raw.decode("utf-8", "ignore").strip().lower()
    else:
        _sig_mode_text = str(_sig_mode_raw or "").strip().lower()
    _idbfj_variant_mode = 0 if _sig_mode_text == "skip" else (1 if _sig_mode_text == "verify" else -1)
    state = {
        "so_data": so_data, "hidden": hidden, "container": container,
        "package": str(package), "version_name": str(version_name), "version_code": version_code, "app_label": str(app_label),
        "manual_post_key": manual_post_key, "manual_key_xor": manual_key_xor,
        "mode": args.mode, "outer_mode": args.outer_mode, "use_c": bool(args.use_c), "c_path": str(args.c_lib),
        "fast_c": str(args.fast_c), "extra_outer_env": dict(_EXTRA_OUTER_ENV), "c_idbfj_inputs": _iapt_priority_idbfj_inputs(_EXTRA_OUTER_ENV), "apk_native_so_candidates": list(_APK_NATIVE_SO_CANDIDATES),
        "no_dynamic_key": bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)), "main_file": MUST_HAVE_MAIN,
        "c_batch_broad": bool(getattr(args, "full_c_enum", False)),
        "cbatch_prefix_limit": _iapt_effective_mian_prefix_bytes(args, container),
        "cbatch_tail_gate": bool(getattr(args, "dexkey_tail_marker_gate", True)),
        "cbatch_tail_name": f"{str(package)}.project",
        "cbatch_idbfj_variant_mode": _idbfj_variant_mode,
        "dexkey_max_so_keysets": int(getattr(args, "dexkey_max_so_keysets", 16) or 16),
    }
    try:
        _broad_mode = bool(getattr(args, "full_c_enum", False))
        print(f"[+] dexkey C-batch mian.iyu enum core = {'broad' if _broad_mode else 'fixed-fast'}", flush=True)
        t0 = time.perf_counter()
        plan = _iapt_dexkey_build_cached_probe_plan(state)
        state["probe_plan_prebuilt"] = plan
        keysets = _iapt_cbatch_keysets_from_plan(plan)
        if not keysets:
            msg = "dexkey C-batch skipped: no keysets"
            print(f"[!] {msg}", flush=True)
            if no_py_fallback:
                raise RuntimeError(msg + "; --no-python-fallback stops here")
            return None
        # v107: many APKs expose f.b() as a constant-return method. Treat it as
        # a hint only: it must pass the exact original outer + mian.iyu verifier.
        if bool(getattr(args, "allow_known_enum_seeds", False)) and not bool(getattr(args, "no_dexkey_dex_hint", False)) and getattr(args, "apk", None):
            try:
                dex_hint = extract_fb_from_apk_dexes(Path(args.apk))
            except Exception:
                dex_hint = None
            if dex_hint is not None and int(fb_start) <= int(dex_hint) <= int(fb_stop):
                if _iapt_cbatch_validate_fb_hit(state, int(dex_hint), hidden):
                    print(f"[+] dexkey DEX hint verified key={int(dex_hint)}", flush=True)
                    return int(dex_hint)
        # v102-cfix: real parallel full-C scanning.  Older builds called the C
        # scanner from one Python loop and then fell into hard-watchdog Python
        # enum, so four workers/quad-sweep were not actually used by C.
        hit_key = _iapt_try_dexkey_cbatch_parallel(state, keysets, int(fb_start), int(fb_stop), args)
        if hit_key is not None:
            return int(hit_key)
        # The strict tail layout is only a fast common-case pass. Disable it
        # and retry with the bounded main-prefix verifier for arbitrary layouts.
        if bool(state.get("cbatch_tail_gate", False)):
            if not bool(getattr(args, "enum_quiet", False)):
                print("[+] dexkey tail-marker gate no-hit; retrying prefix verification", flush=True)
            state["cbatch_tail_gate"] = False
            state["cbatch_idbfj_variant_mode"] = -1
            hit_key = _iapt_try_dexkey_cbatch_parallel(state, keysets, int(fb_start), int(fb_stop), args)
            if hit_key is not None:
                return int(hit_key)
        # Correctness fallback: if the bounded-prefix pass did not find the
        # complete main marker pair, repeat with full-container verification.
        if int(state.get("cbatch_prefix_limit", 0) or 0) > 0:
            if not bool(getattr(args, "enum_quiet", False)):
                print("[+] dexkey prefix gate no-hit; retrying full-container C verification", flush=True)
            state["cbatch_prefix_limit"] = 0
            hit_key = _iapt_try_dexkey_cbatch_parallel(state, keysets, int(fb_start), int(fb_stop), args)
            if hit_key is not None:
                return int(hit_key)
        msg = f"dexkey C-batch ({'broad' if _broad_mode else 'fixed-fast'}) no verified hit elapsed={time.perf_counter()-t0:.1f}s"
        if no_py_fallback:
            raise RuntimeError(msg + "; --no-python-fallback stops here")
        print(f"[!] {msg}; fallback to Python enum", flush=True)
        return None
    except Exception as e:
        if no_py_fallback:
            raise RuntimeError(f"dexkey C-batch unavailable/failed: {type(e).__name__}: {e}; --no-python-fallback stops here") from e
        print(f"[!] dexkey C-batch unavailable: {type(e).__name__}: {e}; fallback to Python enum", flush=True)
        return None


def _iapt_try_sokey_cbatch_fixed(hidden_candidates: List[bytes], fb_value, state: Dict[str, object], args) -> Optional[Tuple[int, bytes, bytes, bytes, bytes, bytes, Dict[str, bytes]]]:
    no_py_fallback = bool(getattr(args, "no_python_fallback", False))
    if not bool(getattr(args, "sokey_c_batch", False)):
        if no_py_fallback:
            raise RuntimeError("--no-python-fallback requires --sokey-c-batch for sokey enum")
        return None
    if not hidden_candidates:
        if no_py_fallback:
            raise RuntimeError("sokey C-batch has no hidden candidates; --no-python-fallback stops here")
        return None
    try:
        broad_mode = bool(getattr(args, "full_c_enum", False))
        print(f"[+] sokey C-batch mian.iyu enum core = {'broad' if broad_mode else 'fixed-fast'}", flush=True)
        t0 = time.perf_counter()
        st = dict(state or {})
        plan = st.get("probe_plan_prebuilt") or st.get("probe_plan") or _iapt_dexkey_build_cached_probe_plan(st)
        st["probe_plan_prebuilt"] = plan
        keysets = _iapt_cbatch_keysets_from_plan(plan)
        if not keysets:
            msg = "sokey C-batch skipped: no keysets"
            print(f"[!] {msg}", flush=True)
            if no_py_fallback:
                raise RuntimeError(msg + "; --no-python-fallback stops here")
            return None
        total = len(hidden_candidates)
        # Reuse the fused native scanner for sokey-only mode by giving it one
        # fixed dexkey tile.  This keeps all 5000 hidden candidates inside one
        # pthread call and uses the same evidence-staged input/keyset pruning as
        # joint enumeration.  The legacy hidden-list scanner remains below as a
        # compatibility fallback.
        if not broad_mode and hasattr(_load_c_fast_core(False), "iapp_joint_sokey_dexkey_scan_mian_parallel"):
            workers=max(1,min(int(getattr(args,"enum_workers",0) or min(4,os.cpu_count() or 1)),32))
            hidden_lanes=int(getattr(args,"joint_hidden_lanes",0) or max(4,min(16,workers*2)))
            fixed_fb=int(parse_int_auto(fb_value))
            one_lane=[[(fixed_fb,fixed_fb,0)]]
            const_inputs=_iapt_priority_idbfj_inputs(_EXTRA_OUTER_ENV)
            signature=bytes((_EXTRA_OUTER_ENV or {}).get("signature") or b"")
            sig_mode_raw=(_EXTRA_OUTER_ENV or {}).get("signature_mode",b"")
            sig_mode=(sig_mode_raw.decode("utf-8","ignore") if isinstance(sig_mode_raw,bytes) else str(sig_mode_raw)).strip().lower()
            variant_mode=0 if sig_mode=="skip" else (1 if sig_mode=="verify" else -1)
            required_raw=(_EXTRA_OUTER_ENV or {}).get("user_encryption_required",b"")
            required=(required_raw.decode("utf-8","ignore") if isinstance(required_raw,bytes) else str(required_raw)).strip().lower() in ("1","true","yes","on")
            native_only=[]
            for n,v in const_inputs:
                if str(n).startswith("user_password_native"):
                    native_only=[(n,v)];break
            if required and native_only:
                native_inputs=native_only; include_hidden=False
            else:
                native_inputs=[]; include_hidden=True
            native_stages=[("priority",keysets[:1],native_inputs,include_hidden)]
            if len(keysets)>1 or native_inputs!=const_inputs or not include_hidden:
                native_stages.append(("expanded",keysets,const_inputs,True))
            prefix=_iapt_effective_mian_prefix_bytes(args, st.get("container") or b"")
            native_gates=[]
            if bool(getattr(args,"dexkey_tail_marker_gate",True)):native_gates.append((True,prefix,"tail"))
            native_gates.append((False,prefix,"prefix"))
            if prefix>0:native_gates.append((False,0,"full"))
            schedule=[]
            if native_gates and native_gates[0][0]:
                schedule += [(stage,native_gates[0]) for stage in native_stages]
                schedule += [(stage,gate) for gate in native_gates[1:] for stage in native_stages]
            else:
                schedule += [(stage,gate) for gate in native_gates for stage in native_stages]
            for (stage_name,stage_keys,stage_inputs,stage_hidden),(tail,prefix_limit,gate_name) in schedule:
                _cfast_set_tail_marker_gate(f"{str(st['package'])}.project",tail)
                _cfast_set_mian_prefix_limit(prefix_limit)
                _cfast_set_idbfj_variant_mode(variant_mode if tail else -1)
                native_hit=_cfast_joint_sokey_dexkey_scan(
                    st["container"],hidden_candidates,st["package"],st["version_name"],st["version_code"],st["app_label"],
                    stage_inputs,signature,one_lane,stage_keys,workers,hidden_lanes,MUST_HAVE_MAIN,stage_hidden)
                if native_hit is None:
                    continue
                hit_idx=int(native_hit[0]); hidden=hidden_candidates[hit_idx]
                old=dict(_IAPT_DEXKEY_MP_STATE or {})
                try:
                    _iapt_dexkey_mp_init(st)
                    verified=_iapt_dexkey_cached_probe_one(fb_value,hidden_override=hidden)
                    if verified is not None:
                        post_key,key_xor,outer_key,container_plain,trace=verified
                        trace,_mp=finalize_outer_shell_probe(container_plain,post_key,key_xor,hidden,fb_value,trace,use_c=bool(st.get("use_c",False)),c_path=str(st.get("c_path") or "./libiapp_core.so"))
                        print(f"[+] sokey C-native verified idx={hit_idx+1}/{total} pass={stage_name}/{gate_name} elapsed={time.perf_counter()-t0:.3f}s hidden={hidden.decode('ascii','replace')}",flush=True)
                        return hit_idx,hidden,post_key,key_xor,outer_key,container_plain,trace
                finally:
                    globals()["_IAPT_DEXKEY_MP_STATE"]=old
        # Keep existing quad order by scanning lanes, but each lane is one C call.
        lanes = _iapt_build_quad_index_lanes(total, max(1, min(32, int(getattr(args, "enum_workers", 4) or 4), total))) if str(getattr(args, "sokey_scan_strategy", "linear") or "linear") == "quad-sweep" else [list(range(total))]
        for kname, pk, xk in keysets:
            for lane_id, lane in enumerate(lanes):
                if not lane:
                    continue
                # C scans contiguous ranges.  Preserve both +1 and -1 lanes;
                # the old code split every descending lane into thousands of
                # one-candidate ctypes calls, which erased most C-batch speedup.
                runs = []
                run_start = lane[0]
                prev = lane[0]
                step = 0
                for idx in lane[1:]:
                    cur_step = idx - prev
                    if cur_step in (-1, 1) and (step == 0 or cur_step == step):
                        step = cur_step
                        prev = idx
                    else:
                        runs.append((run_start, prev, step or 1))
                        run_start = prev = idx
                        step = 0
                runs.append((run_start, prev, step or 1))
                for a, b, direction in runs:
                    cur_a = int(a)
                    cur_b = int(b)
                    while (direction > 0 and cur_a <= cur_b) or (direction < 0 and cur_a >= cur_b):
                        if broad_mode:
                            hit_idx = (_cfast_broad_hidden_list_scan_mian(
                                st["container"], hidden_candidates, st["package"], st["version_name"], st["version_code"], st["app_label"],
                                fb_value, cur_a, cur_b, direction, pk, xk, MUST_HAVE_MAIN
                            ) or (None, None))[0]
                        else:
                            hit_idx = _cfast_fixed_hidden_list_scan_mian(
                                st["container"], hidden_candidates, st["package"], st["version_name"], st["version_code"], st["app_label"],
                                fb_value, cur_a, cur_b, direction, pk, xk, MUST_HAVE_MAIN
                            )
                        if hit_idx is None:
                            break
                        hidden = hidden_candidates[int(hit_idx)]
                        print(f"[+] sokey C-batch mian.iyu hit idx={int(hit_idx)+1}/{total} keyset={kname}; final Python verify ...", flush=True)
                        old = dict(_IAPT_DEXKEY_MP_STATE or {})
                        try:
                            _iapt_dexkey_mp_init(st)
                            hit = _iapt_dexkey_cached_probe_one(fb_value, hidden_override=hidden)
                            if hit is not None:
                                post_key, key_xor, outer_key, container_plain, trace = hit
                                trace, _mp = finalize_outer_shell_probe(container_plain, post_key, key_xor, hidden, fb_value, trace, use_c=bool(st.get("use_c", False)), c_path=str(st.get("c_path") or "./libiapp_core.so"))
                                print(f"[+] sokey C-batch verified idx={int(hit_idx)+1}/{total} elapsed={time.perf_counter()-t0:.2f}s hidden={hidden.decode('ascii','replace')}", flush=True)
                                return int(hit_idx), hidden, post_key, key_xor, outer_key, container_plain, trace
                        except Exception:
                            pass
                        finally:
                            globals()["_IAPT_DEXKEY_MP_STATE"] = old
                        print(f"[!] sokey C-batch false padding hit idx={int(hit_idx)+1}; resume", flush=True)
                        cur_a = int(hit_idx) + int(direction)
        msg = f"sokey C-batch ({'broad' if broad_mode else 'fixed-fast'}) no verified hit elapsed={time.perf_counter()-t0:.1f}s"
        if no_py_fallback:
            raise RuntimeError(msg + "; --no-python-fallback stops here")
        print(f"[!] {msg}; fallback to Python probe", flush=True)
        return None
    except Exception as e:
        if no_py_fallback:
            raise RuntimeError(f"sokey C-batch unavailable/failed: {type(e).__name__}: {e}; --no-python-fallback stops here") from e
        print(f"[!] sokey C-batch unavailable: {type(e).__name__}: {e}; fallback to Python probe", flush=True)
        return None

def _iapt_build_dexkey_chunk_jobs(fb_start: int, fb_stop: int, chunk_size: int, strategy: str) -> List[Tuple[int, int, int]]:
    """Build dexkey chunk jobs.

    linear: old behavior, chunks go from low to high.
    quad-sweep: no duplicate chunks, but first waves are anchored at:
      low start, high end, middle-left moving left, middle-right moving right.

    This gives four workers useful coverage immediately when enum_workers=4:
      worker 0: near start
      worker 1: near end
      worker 2: near middle-left
      worker 3: near middle-right
    """
    fb_start = int(fb_start)
    fb_stop = int(fb_stop)
    chunk_size = max(1, int(chunk_size))
    chunks: List[Tuple[int, int]] = []
    k = fb_start
    while k <= fb_stop:
        chunks.append((k, min(fb_stop, k + chunk_size - 1)))
        k += chunk_size
    if (strategy or "linear") != "quad-sweep" or len(chunks) <= 4:
        return [(a, b, i) for i, (a, b) in enumerate(chunks)]

    n = len(chunks)
    mid_r = n // 2
    mid_l = mid_r - 1
    ptrs = [0, n - 1, mid_l, mid_r]
    steps = [1, -1, -1, 1]
    seen = set()
    ordered: List[int] = []
    while len(ordered) < n:
        moved = False
        for lane in range(4):
            i = ptrs[lane]
            while 0 <= i < n and i in seen:
                i += steps[lane]
            ptrs[lane] = i + steps[lane]
            if 0 <= i < n and i not in seen:
                seen.add(i)
                ordered.append(i)
                moved = True
                if len(ordered) >= n:
                    break
        if not moved:
            for i in range(n):
                if i not in seen:
                    seen.add(i)
                    ordered.append(i)
                    break
    return [(chunks[i][0], chunks[i][1], j) for j, i in enumerate(ordered)]

def _iapt_dexkey_hard_supervised_enum(
    hidden: bytes,
    fb_start: int,
    fb_stop: int,
    so_data: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    manual_post_key: Optional[bytes],
    manual_key_xor: Optional[bytes],
    args,
) -> Optional[int]:
    """Hard watchdog dexkey enum.

    Workers test small ranges and report the exact current key before probing.
    If a worker stops reporting for longer than --dexkey-probe-timeout-ms, the
    parent kills the process and resumes from current_key+1.  This handles hangs
    that signal/alarm cannot interrupt, including native code stalls.
    """
    import multiprocessing as _mp
    import queue as _queue
    fb_start = int(fb_start)
    fb_stop = int(fb_stop)
    total = max(0, fb_stop - fb_start + 1)
    if total <= 0:
        return None
    workers = int(getattr(args, "enum_workers", 0) or 0)
    if workers <= 0:
        workers = max(1, min(8, os.cpu_count() or 1))
    raw_chunk = int(getattr(args, "enum_chunk_size", 0) or 0)
    # Keep chunks small enough that a killed worker does not waste a lot of
    # already-built cache, but large enough to avoid rebuilding per key.
    chunk_size = raw_chunk if raw_chunk and raw_chunk != 4096 else 64
    chunk_size = max(1, min(chunk_size, 512))
    timeout_ms = _iapt_dexkey_probe_timeout_ms(args)
    if timeout_ms <= 0:
        timeout_ms = 300
    timeout_s = max(0.001, timeout_ms / 1000.0)
    verbose_each = bool(getattr(args, "dexkey_verbose_each", False))
    enum_quiet = bool(getattr(args, "enum_quiet", False))
    try:
        progress_every = max(1, int(getattr(args, "dexkey_progress_every", 1000) or 1000))
    except Exception:
        progress_every = 1000
    state: Dict[str, object] = {
        "so_data": so_data,
        "hidden": hidden,
        "container": container,
        "package": str(package),
        "version_name": str(version_name),
        "version_code": version_code,
        "app_label": str(app_label),
        "manual_post_key": manual_post_key,
        "manual_key_xor": manual_key_xor,
        "mode": args.mode,
        "outer_mode": args.outer_mode,
        "use_c": bool(args.use_c),
        "c_path": str(args.c_lib),
        "fast_c": str(args.fast_c),
        "debug_candidates": bool(args.debug_candidates),
        "extra_outer_env": dict(_EXTRA_OUTER_ENV),
        "apk_native_so_candidates": list(_APK_NATIVE_SO_CANDIDATES),
        "no_dynamic_key": bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)),
        "main_file": MUST_HAVE_MAIN,
        "dexkey_probe_timeout_ms": int(timeout_ms),
        "dexkey_verbose_each": verbose_each,
        "dexkey_progress_every": progress_every,
        "enum_quiet": enum_quiet,
        "dexkey_max_so_keysets": int(getattr(args, "dexkey_max_so_keysets", 16) or 16),
    }

    # v101: try the requested full-C/C-batch enum BEFORE printing/building the
    # Python hard-watchdog path.  Older v100 printed "dexkey hard enum" first,
    # which made it look like C was not used even when --full-c-enum was present.
    if bool(getattr(args, "dexkey_c_batch", False)) or bool(getattr(args, "full_c_enum", False)) or bool(getattr(args, "no_python_fallback", False)):
        if not enum_quiet:
            print("[+] dexkey FULL-C path requested; trying C enum before Python watchdog", flush=True)
        _cbatch_hit = _iapt_try_dexkey_cbatch_fixed(hidden, fb_start, fb_stop, so_data, container, package, version_name, version_code, app_label, manual_post_key, manual_key_xor, args)
        if _cbatch_hit is not None:
            return int(_cbatch_hit)
        if bool(getattr(args, "no_python_fallback", False)):
            raise RuntimeError("dexkey C-batch/full-C did not return a verified key and --no-python-fallback is set; Python watchdog enum is disabled")

    if not enum_quiet:
        print(f"[+] dexkey HARD watchdog = {timeout_ms} ms/key; hung worker will be killed and resumed at next key", flush=True)
        print(f"[+] dexkey hard enum = workers={workers} chunk={chunk_size} total={total}", flush=True)
    # v94: build SO-derived keysets and reusable outer candidates once in the
    # parent, then pass the plan to all respawned workers.  This avoids seeing
    # "selected native so / SO key extraction" on every timeout/restart.
    try:
        if not enum_quiet:
            print("[+] dexkey prebuild SO probe plan once in parent ...", flush=True)
        t_prebuild = time.perf_counter()
        state["probe_plan_prebuilt"] = _iapt_dexkey_build_cached_probe_plan(state)
        if not enum_quiet:
            print(f"[+] dexkey prebuilt SO probe plan ready in {ms_since(t_prebuild):.3f} ms", flush=True)
    except Exception as e:
        state["probe_plan_prebuilt"] = {}
        if not enum_quiet:
            print(f"[!] dexkey prebuild SO probe plan failed; workers may re-analyze SO: {type(e).__name__}: {e}", flush=True)
    if verbose_each and not enum_quiet:
        print("[+] dexkey verbose = every key try/fail/timeout will be printed", flush=True)

    # C-batch/full-C was already attempted above before the Python watchdog logs.
    # Build chunk queue only when Python fallback is allowed.
    scan_strategy = str(getattr(args, "dexkey_scan_strategy", "linear") or "linear")
    pending: List[Tuple[int, int, int]] = _iapt_build_dexkey_chunk_jobs(fb_start, fb_stop, chunk_size, scan_strategy)
    if scan_strategy == "quad-sweep":
        preview = ", ".join(f"{a}-{b}" for a, b, _ in pending[:min(8, len(pending))])
        if not enum_quiet:
            print(f"[+] dexkey scan strategy = quad-sweep; first chunks: {preview}", flush=True)
    else:
        if not enum_quiet:
            print("[+] dexkey scan strategy = linear", flush=True)
    active: Dict[int, Dict[str, object]] = {}
    tested = 0
    timeouts = 0
    done_chunks = 0
    t0 = time.perf_counter()

    def _spawn(job: Tuple[int, int, int]):
        nonlocal active
        start, stop, job_id = job
        q = _mp.Queue()
        p = _mp.Process(target=_iapt_dexkey_hard_batch_worker, args=(state, int(start), int(stop), int(job_id), q))
        p.daemon = False
        p.start()
        active[p.pid] = {
            "proc": p, "queue": q, "start": int(start), "stop": int(stop), "job_id": int(job_id),
            "current_key": None, "current_idx": 0, "last_try_ts": time.time(), "started_ts": time.time(),
            "last_seen_ts": time.time(),
        }

    while pending and len(active) < workers:
        _spawn(pending.pop(0))

    try:
        while active:
            now = time.time()
            # Read messages.
            for pid, rec in list(active.items()):
                q = rec["queue"]
                while True:
                    try:
                        msg = q.get_nowait()
                    except _queue.Empty:
                        break
                    except Exception:
                        break
                    rec["last_seen_ts"] = time.time()
                    ev = msg.get("event")
                    if ev == "try":
                        rec["current_key"] = int(msg.get("key"))
                        rec["current_idx"] = int(msg.get("idx") or 0)
                        rec["last_try_ts"] = float(msg.get("ts") or time.time())
                        if verbose_each:
                            if not enum_quiet:
                                print(f"[+] dexkey try worker={msg.get('job_id')} idx={msg.get('idx')} key={msg.get('key')}", flush=True)
                    elif ev == "fail":
                        tested += 1
                        key = int(msg.get("key"))
                        dt = float(msg.get("ms") or 0)
                        err = str(msg.get("err") or "")
                        if (not enum_quiet) and (verbose_each or tested <= 8 or tested % progress_every == 0):
                            print(f"[!] dexkey fail tested={tested}/{total} worker={msg.get('job_id')} key={key} {dt:.3f} ms {err}", flush=True)
                    elif ev == "ok":
                        key = int(msg.get("key"))
                        print(f"[+] dexkey OK key={key} worker={msg.get('job_id')} tested≈{tested+1}/{total} {float(msg.get('ms') or 0):.3f} ms", flush=True)
                        for r in list(active.values()):
                            try:
                                r["proc"].terminate()
                            except Exception:
                                pass
                        for r in list(active.values()):
                            try:
                                r["proc"].join(timeout=1)
                            except Exception:
                                pass
                        return key
                    elif ev == "done":
                        done_chunks += 1
                        proc = rec["proc"]
                        try:
                            proc.join(timeout=0.05)
                        except Exception:
                            pass
                        active.pop(pid, None)
                        if pending:
                            _spawn(pending.pop(0))
                        if done_chunks <= workers or done_chunks % max(1, (len(pending)+done_chunks)//20 or 1) == 0:
                            pct = tested / total * 100.0 if total else 0
                            if not enum_quiet:
                                print(f"[+] dexkey hard prog = {pct:.2f}% tested≈{tested}/{total} chunks_done={done_chunks} active={len(active)} timeouts={timeouts} elapsed={time.perf_counter()-t0:.1f}s", flush=True)
                    elif ev == "crash":
                        err = str(msg.get("err") or "")
                        if not enum_quiet:
                            print(f"[!] dexkey worker crash job={msg.get('job_id')} range={msg.get('start')}-{msg.get('stop')}: {err}", flush=True)
                        cur = rec.get("current_key")
                        resume = int(cur) + 1 if cur is not None else int(rec["start"])
                        stop = int(rec["stop"])
                        active.pop(pid, None)
                        try:
                            rec["proc"].terminate(); rec["proc"].join(timeout=0.5)
                        except Exception:
                            pass
                        if resume <= stop:
                            pending.insert(0, (resume, stop, int(rec["job_id"])))
                        if pending:
                            _spawn(pending.pop(0))
            # Kill hung workers.
            for pid, rec in list(active.items()):
                cur = rec.get("current_key")
                if cur is None:
                    # If worker never even reported a first key, give it a bit more time
                    # for cache preparation.
                    if now - float(rec.get("started_ts") or now) <= max(3.0, timeout_s * 5):
                        continue
                    cur = int(rec["start"])
                    rec["current_key"] = cur
                if now - float(rec.get("last_try_ts") or now) > timeout_s:
                    timeouts += 1
                    tested += 1
                    cur_key = int(cur)
                    if not enum_quiet:
                        print(f"[!] dexkey HARD timeout tested={tested}/{total} worker={rec.get('job_id')} key={cur_key} >{timeout_ms}ms; kill worker and resume at {cur_key+1}", flush=True)
                    try:
                        rec["proc"].terminate()
                        rec["proc"].join(timeout=0.5)
                        if rec["proc"].is_alive():
                            try:
                                rec["proc"].kill()
                                rec["proc"].join(timeout=0.5)
                            except Exception:
                                pass
                    except Exception:
                        pass
                    active.pop(pid, None)
                    resume = cur_key + 1
                    stop = int(rec["stop"])
                    if resume <= stop:
                        pending.insert(0, (resume, stop, int(rec["job_id"])))
                    if pending:
                        _spawn(pending.pop(0))
            # Spawn to fill slots.
            while pending and len(active) < workers:
                _spawn(pending.pop(0))
            time.sleep(0.01)
    except KeyboardInterrupt:
        for rec in list(active.values()):
            try:
                rec["proc"].terminate()
            except Exception:
                pass
        raise
    print(f"[!] dexkey hard enum no hit tested≈{tested}/{total} timeouts={timeouts} elapsed={time.perf_counter()-t0:.1f}s", flush=True)
    return None
def try_dexkey_enum_parallel_outer_probe(
    hidden: bytes,
    fb_start: int,
    fb_stop: int,
    so_data: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    manual_post_key: Optional[bytes],
    manual_key_xor: Optional[bytes],
    args,
) -> Optional[int]:
    """Parallel dexkey enum: split range across processes and stop on hit."""
    # v92: default to a parent-supervised hard watchdog.  The previous soft
    # signal watchdog can miss hangs inside native/C code; the hard watchdog
    # kills the whole worker process and resumes from the next key.
    if bool(getattr(args, "dexkey_hard_watchdog", True)):
        return _iapt_dexkey_hard_supervised_enum(
            hidden, fb_start, fb_stop, so_data, container, package, version_name,
            version_code, app_label, manual_post_key, manual_key_xor, args
        )
    import multiprocessing as _mp
    fb_start = int(fb_start)
    fb_stop = int(fb_stop)
    total = max(0, fb_stop - fb_start + 1)
    if total <= 0:
        return None
    workers = int(getattr(args, "enum_workers", 0) or 0)
    if workers <= 0:
        workers = max(1, min(8, os.cpu_count() or 1))
    # For dexkey, keep chunks reasonably small so stop-on-hit is responsive even
    # when a single probe is slow.  Users can override --enum-chunk-size.
    raw_chunk = int(getattr(args, "enum_chunk_size", 0) or 0)
    chunk_size = raw_chunk if raw_chunk and raw_chunk != 4096 else 256
    chunk_size = max(16, min(chunk_size, 8192))
    if workers <= 1:
        return None
    jobs: List[Tuple[int, int, int]] = []
    jid = 0
    for start in range(fb_start, fb_stop + 1, chunk_size):
        stop = min(fb_stop, start + chunk_size - 1)
        jobs.append((start, stop, jid))
        jid += 1
    state: Dict[str, object] = {
        "so_data": so_data,
        "hidden": hidden,
        "container": container,
        "package": str(package),
        "version_name": str(version_name),
        "version_code": version_code,
        "app_label": str(app_label),
        "manual_post_key": manual_post_key,
        "manual_key_xor": manual_key_xor,
        "mode": args.mode,
        "outer_mode": args.outer_mode,
        "use_c": bool(args.use_c),
        "c_path": str(args.c_lib),
        "fast_c": str(args.fast_c),
        "debug_candidates": bool(args.debug_candidates),
        "extra_outer_env": dict(_EXTRA_OUTER_ENV),
        "apk_native_so_candidates": list(_APK_NATIVE_SO_CANDIDATES),
        "no_dynamic_key": bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)),
        "main_file": MUST_HAVE_MAIN,
        "dexkey_probe_timeout_ms": _iapt_dexkey_probe_timeout_ms(args),
        "dexkey_verbose_each": bool(getattr(args, "dexkey_verbose_each", False)),
        "dexkey_progress_every": int(getattr(args, "dexkey_progress_every", 1000) or 1000),
        "enum_quiet": bool(getattr(args, "enum_quiet", False)),
    }
    if not bool(getattr(args, "enum_quiet", False)):
        print(f"[+] dexkey watchdog = {state['dexkey_probe_timeout_ms']} ms per candidate; timeout means skip this dexkey")
    if state.get("dexkey_verbose_each"):
        print("[+] dexkey verbose = every candidate result will be printed from workers")
    print(f"[+] dexkey mp enum = workers={workers} chunk={chunk_size} jobs={len(jobs)} total={total}")
    t0 = time.perf_counter()
    tested = 0
    done_jobs = 0
    pool = _mp.Pool(processes=workers, initializer=_iapt_dexkey_mp_init, initargs=(state,))
    try:
        for res in pool.imap_unordered(_iapt_dexkey_mp_probe_range, jobs, chunksize=1):
            done_jobs += 1
            tested += int(res.get("tested") or 0)
            if res.get("timeouts"):
                try:
                    print(f"[!] dexkey mp chunk timeout count job={res.get('job_id')} timeouts={res.get('timeouts')}", flush=True)
                except Exception:
                    pass
            if res.get("ok"):
                fb = int(res["fb"])
                print(f"[+] dexkey mp hit  = {fb} job={res.get('job_id')} range={res.get('start')}-{res.get('stop')} tested≈{tested}/{total} elapsed={time.perf_counter()-t0:.1f}s")
                pool.terminate()
                pool.join()
                return fb
            if done_jobs <= workers or done_jobs % max(1, len(jobs)//20) == 0 or done_jobs == len(jobs):
                pct = (tested / total * 100.0) if total else 0.0
                print(f"[+] dexkey mp prog = {pct:.2f}% chunks={done_jobs}/{len(jobs)} tested≈{tested}/{total} elapsed={time.perf_counter()-t0:.1f}s")
        pool.close()
        pool.join()
    except KeyboardInterrupt:
        pool.terminate()
        pool.join()
        raise
    except BaseException:
        pool.terminate()
        pool.join()
        raise
    print(f"[!] dexkey mp enum no hit tested≈{tested}/{total} elapsed={time.perf_counter()-t0:.1f}s")
    return None
# IAPT_DEXKEY_MP_OUTER_PROBE_END

def main():
    t_total_start = time.perf_counter()
    ap = argparse.ArgumentParser(description="iApp static auto decryptor")
    ap.add_argument("--apk", type=Path, help="APK path")
    ap.add_argument("--native-so", type=Path, help="external libygsiyu.so path for non-APK/container-only input; APK mode uses the SO inside the APK by default")
    ap.add_argument("--container", type=Path, help="encrypted assets/lib.so path")
    ap.add_argument("--package", help="package name")
    ap.add_argument("--version-name", help="versionName")
    ap.add_argument("--version-code", help="versionCode, decimal or hex")
    ap.add_argument("--app-label", help="app label used by sample")
    ap.add_argument("--fb", help="com.iapp.app.f.b() return value, decimal or hex")
    ap.add_argument("--user-password", help="password required when assets/userencryption.xml contains <ok>true</ok>; used as idbfj input")
    ap.add_argument("--deep-password-scan", action="store_true", help="force full DEX scan for app-specific password salt; auto retry uses this if fast salt fails")
    ap.add_argument("--signature-mode", choices=("auto", "skip", "verify"), default="auto", help="signature branch: auto reads assets/extra_conf1g.xml; skip uses p24=slky(p19,p19); verify also tries p24=slky(apk_signature,p19)")
    ap.add_argument("--signature-bytes-hex", help="manual Android Signature.toByteArray() DER certificate bytes as hex; used when signature verification is enabled")
    ap.add_argument("--post-key", help="manual SLKY_POST_KEY hex")
    ap.add_argument("--key-xor", help="manual KEY_XOR_CONST hex")
    ap.add_argument("--hidden", help="manual hidden value, ASCII form or hex:<hex>; exact value, no enumeration")
    ap.add_argument("--hidden-enum", action="store_true", help="explicit hidden brute-force/enumeration mode for missing/encrypted SO hidden strings; never enabled automatically and never scans SO for hidden candidates")
    ap.add_argument("--hidden-prefix", default="", help="10-byte hidden prefix or mask for --hidden-enum; '?' marks unknown chars; full hidden value is also accepted")
    ap.add_argument("--hidden-charset", default="0123456789ABCDEF", help="charset for '?' positions in --hidden-prefix/--hidden-candidates masks")
    ap.add_argument("--hidden-candidates", action="append", default=[], help="comma/semicolon/newline separated hidden candidates, 10-byte prefixes, or 10-byte masks; can be repeated")
    ap.add_argument("--hidden-candidates-file", type=Path, help="file containing hidden candidates/prefixes/masks, one per line")
    ap.add_argument("--max-hidden-candidates", type=int, default=100000, help="maximum explicit hidden enum candidates to generate/test; protects against accidental 62^10 brute force")
    ap.add_argument("--sokey-enum", action="store_true", help="enumerate sokey from bsh/util/lib/ ZIP mtime: MD5(milliseconds)[:10].upper()+QQQQQQQQQQWWWWWWWWWWEE")
    # IAPT_SERVER_SOKEY_STATIC_V280_ARG_BEGIN
    ap.add_argument(
        "--server-sokey-static",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    # IAPT_SERVER_SOKEY_STATIC_V280_ARG_END
    ap.add_argument("--sokey-enum-seconds", type=int, default=180, help="backward seconds to enumerate from the newest bsh/util/lib ZIP mtime; default 180 = 3 minutes = 180000 candidates")
    ap.add_argument("--sokey-enum-files", type=int, default=1, help="maximum unique bsh/util/lib/ mtime seconds used for --sokey-enum; default 1")
    ap.add_argument("--sokey-max-candidates", type=int, default=0, help="maximum sokey candidates after generation; 0=automatic (seconds*1000*selected mtime files), default 0")
    ap.add_argument("--sokey-scan-strategy", choices=("linear", "quad-sweep"), default="quad-sweep", help="sokey enum order: linear=old order; quad-sweep=N balanced shards with alternating directions")
    ap.add_argument("--sokey-base-ts", type=int, default=0, help="manual sokey timestamp source; pass 13-digit millisecond timestamp to try it first, or 10-digit second timestamp as the first window")
    ap.add_argument("--sokey-list-mtimes", action="store_true", help="print all bsh/util/lib/ ZIP mtimes used for sokey enum debugging")
    ap.add_argument("--sokey-enum-start-index", type=int, default=0, help="start index inside generated sokey candidate list; useful for verifying a suspected range")
    ap.add_argument("--sokey-enum-stop-index", type=int, default=-1, help="inclusive stop index inside generated sokey candidate list; -1 means last candidate")
    ap.add_argument("--sokey-safe-full-probe", action="store_true", help="disable tiny sokey prefilter and use the original outer resolver + mian.iyu probe for every candidate; slower but avoids tiny-plan false negatives")
    ap.add_argument("--sokey-probe-timeout-ms", type=int, default=300, help="per-sokey candidate watchdog timeout in milliseconds; default 300, use 0 to disable")
    ap.add_argument("--sokey-verbose-each", action="store_true", help="print every sokey failure; off by default because queue/log I/O can dominate enumeration")
    ap.add_argument("--sokey-progress-every", type=int, default=100, help="sokey worker progress interval when --sokey-verbose-each is off; default 100")
    ap.add_argument("--dexkey-probe-timeout-ms", type=int, default=300, help="per-dexkey candidate watchdog timeout in milliseconds; default 300, use 0 to disable")
    ap.add_argument("--dexkey-hard-watchdog", dest="dexkey_hard_watchdog", action="store_true", default=True, help="hard-kill hung dexkey worker processes and resume from next key; default on")
    ap.add_argument("--no-dexkey-hard-watchdog", dest="dexkey_hard_watchdog", action="store_false", help="use old soft watchdog/pool mode instead")
    ap.add_argument("--dexkey-verbose-each", action="store_true", help="print every dexkey probe result from workers; very noisy for large ranges")
    ap.add_argument("--dexkey-progress-every", type=int, default=1000, help="worker-side dexkey progress interval when --dexkey-verbose-each is off; default 1000")
    ap.add_argument("--enum-quiet", action="store_true", help="suppress dexkey/sokey enum fail/timeout/cache chatter; still prints hits and final result")
    ap.add_argument("--no-python-fallback", action="store_true", help="when --dexkey-c-batch/--sokey-c-batch is requested, fail immediately if C-batch is unavailable or finds no verified key; do not fall back to Python watchdog/per-key enum")
    ap.add_argument("--allow-slow-python-fallback", action="store_true", help="explicitly allow very slow Python per-candidate fallback after C enum no-hit; disabled by default for enum stability")
    ap.add_argument("--dexkey-scan-strategy", choices=("linear", "quad-sweep"), default="quad-sweep", help="dexkey enum order: linear=balanced ascending shards; quad-sweep=N balanced shards with alternating directions")
    ap.add_argument("--dexkey-c-batch", action="store_true", help="try full-C/broad C batch scan before Python per-key probes; hit is verified by original Python decrypt path")
    ap.add_argument("--sokey-c-batch", action="store_true", help="try full-C/broad C batch scan for sokey candidates before Python per-key probes; hit is verified by original Python decrypt path")
    ap.add_argument("--full-c-enum", action="store_true", help="use the slower broad C formula set; default enum first uses the much faster fixed-formula C batch, then Python fallback")
    ap.add_argument("--enum-workers", type=int, default=0, help="workers for explicit enum tasks; 0=auto multi-core for --hidden-enum/--dex-enum windows")
    ap.add_argument("--joint-dex-chunk-size", type=int, default=512, help="joint enum dexkey tile/chunk size; lower values can stop sooner but add scheduling overhead")
    ap.add_argument("--joint-hidden-lanes", type=int, default=0, help="number of hidden/sokey candidates processed per native joint lane; 0=auto")
    ap.add_argument("--joint-dex-hint-first", dest="joint_dex_hint_first", action="store_true", default=True, help="joint enum: first verify dexkey/f.b() extracted from classes*.dex against the complete sokey list; a miss continues exhaustive enum")
    ap.add_argument("--no-joint-dex-hint-first", dest="joint_dex_hint_first", action="store_false", help="disable the verified DEX-hint priority probe for joint enum")
    ap.add_argument("--joint-fast-hidden-limit", type=int, default=256, help="joint enum: number of top-priority sokey candidates scanned hidden-major before diagonal exhaustive fallback; 0 disables")
    ap.add_argument("--joint-fast-hidden-batch-size", type=int, default=8, help="joint enum: sokey candidates per hidden-major native batch; smaller stops sooner, larger has less call overhead")
    ap.add_argument("--joint-no-hint-hidden-major", dest="joint_no_hint_hidden_major", action="store_true", default=True, help="joint enum: exact no-metadata mode; scan the full dex range once per sokey in native workers")
    ap.add_argument("--no-joint-no-hint-hidden-major", dest="joint_no_hint_hidden_major", action="store_false", help="disable exact no-hint hidden-major scheduling and use the legacy 2-D tile scheduler")
    ap.add_argument("--joint-no-hint-min-hidden", type=int, default=16, help="minimum sokey candidate count for no-hint hidden-major scheduling")
    ap.add_argument("--dexkey-enum-lanes", type=int, default=0, help="logical C dexkey search lanes; 0=auto (uses 4 lanes with a 2-CPU budget to keep start/middle/end active), maximum 32")
    ap.add_argument("--dexkey-mian-prefix-kb", type=int, default=64, help="fallback C validation prefix in KiB after the tail-marker pass; default 64 KiB, 0 disables. A no-hit automatically retries full-container verification")
    ap.add_argument("--dexkey-max-so-keysets", type=int, default=16, help="cap noisy fallback SO post/xor keysets in dexkey/joint C enum; 0 = unlimited")
    ap.add_argument("--dexkey-tail-marker-gate", dest="dexkey_tail_marker_gate", action="store_true", default=True, help="first scan using the final <package>.project marker and one AES data block; default on")
    ap.add_argument("--no-dexkey-tail-marker-gate", dest="dexkey_tail_marker_gate", action="store_false", help="disable the strict tail-marker first pass")
    ap.add_argument("--enum-chunk-size", type=int, default=4096, help="candidate count per process task for explicit hidden enumeration")
    ap.add_argument("--find", action="append", default=[], help="manual member filename; when present, only these files are decrypted after mian.iyu unless --find-recursive is set")
    ap.add_argument("--find-recursive", action="store_true", help="old --find behavior: decrypt all discovered members and recursively follow references")
    ap.add_argument("--main-file", default="mian.iyu", help="encrypted entry member to verify/decrypt first; default mian.iyu")
    ap.add_argument("--max-output-files", type=int, default=0, help="maximum member source files to write, including mian.iyu; 0 means unlimited")
    ap.add_argument("--outdir", type=Path, default=Path("out"), help="base output directory; by default files are written under --outdir/<package>")
    ap.add_argument("--flat-outdir", action="store_true", help="write directly to --outdir instead of --outdir/<package>")
    ap.add_argument("--no-key-cache", action="store_true", help="disable per-sample outer key cache under outdir/<package>/.tmp")
    ap.add_argument("--strict-manual-key", action="store_true", help="verify only --post-key/--key-xor; disable pool/generic/SO/cache fallback")
    ap.add_argument("--mode", choices=("auto", "fast", "advanced"), default="auto", help="key-constant mode: auto: try generic then advanced; fast: generic/manual only; advanced: SO table extraction only")
    ap.add_argument("--outer-mode", choices=("fixed", "static", "auto"), default="auto", help="outer key algorithm mode: fixed=old formula only; static=SO static IR only; auto=fixed first, then static IR fallback")

    ap.add_argument("--no-dynamic-key", action="store_true", help="disable dynamic key fetch/cache only; keep outer-mode auto")
    ap.add_argument("--key-pool-file", type=Path, help="private server-side JSON key pool; values are never returned to the client")
    ap.add_argument("--redact-selected-keys", action="store_true", help="do not print selected post/xor key bytes; print only the opaque pool ref")

    ap.add_argument("--dump-static-ir", action="store_true", help="dump SO static call IR to out/outer_static_ir.txt")
    ap.add_argument("--dump-outer-candidates", action="store_true", help="dump outer candidate formulas to out/outer_candidates.txt; off by default for speed")
    ap.add_argument("--trace-slky-args", action="store_true", help="trace slky/operator+ argument sources in the SO static analyzer")
    ap.add_argument("--trace-asendn-args", action="store_true", help="trace asendn argument sources in the SO static analyzer")
    ap.add_argument("--threads", type=int, default=0, help="member decrypt threads; 0=auto (default, 4-16)")
    ap.add_argument("--normal-workers", type=int, default=0, help="server-controlled normal decrypt worker count; compatibility alias that overrides --threads when greater than 0")
    ap.add_argument("--debug-candidates", action="store_true", help="print more key candidates and verification failures")
    ap.add_argument("--restore-fn-names", choices=("auto", "on", "off"), default="auto", help="restore decimal iApp function names from DEX reflection tables after member decrypt: auto=cheap mian.iyu gate default, off=normal decrypt only, on=force")
    ap.add_argument("--dex-enum", action="store_true", help="explicit DEX function-order enumeration for restore when decimal IDs are absent/encrypted in DEX; maps --dex-enum-start+i to the i-th DEX function name")
    ap.add_argument("--dex-enum-start", type=int, default=1000000, help="first generated decimal ID for --dex-enum (default: 1000000)")
    ap.add_argument("--dex-enum-limit", type=int, default=9000000, help="maximum DEX function names to enumerate per candidate table")
    ap.add_argument("--dex-enum-windows", type=int, default=1, help="number of DEX numeric start windows to score; starts are start + n*limit, default 1")
    ap.add_argument("--dexkey-enum", action="store_true", help="enumerate dexkey/f.b() value one by one")
    ap.add_argument("--dexkey-enum-start", type=int, default=1736417, help="first dexkey/f.b() value for --dexkey-enum")
    ap.add_argument("--dexkey-enum-stop", type=int, default=5936417, help="last dexkey/f.b() value for --dexkey-enum")
    ap.add_argument("--no-dexkey-dex-hint", action="store_true", help="disable direct classes.dex f.b() candidate hint and force range enumeration")
    ap.add_argument("--allow-known-enum-seeds", action="store_true", help="compatibility escape hatch for dexkey enum: allow DEX/--fb dexkey hints. Default is strict: enum targets must be scanned.")
    ap.add_argument("--restore-backup", action="store_true", help="write _fn_restore_backup files before function-name restore; off by default for speed")
    ap.add_argument("--anti-iapec-encryption", action="store_true", help="restore iAPEC efficient-encrypted source before recursive filename discovery and file output")
    ap.add_argument("--verbose-members", action="store_true", help="print per-member decrypt/ref-scan timing; off by default for speed")
    ap.add_argument("--member-name-scan", choices=("hybrid", "direct", "regex"), default="hybrid", help="member reference scanner: hybrid=exact extension scan with regex validation (default), regex=old broad FILE_RE, direct=token scan only")
    ap.add_argument("--member-batch-size", type=int, default=8, help="member decrypt result batch size; larger reduces Python scheduling overhead in C-index member mode")
    ap.add_argument("--member-marker-mode", choices=("legacy", "wave", "cindex", "process", "proc", "auto"), default="auto", help="member marker locator: auto=default, C batch index for large containers and legacy find for tiny cases; cindex=force C batch scan; legacy=parallel per-name bytes.find")
    ap.add_argument("--member-marker-wave-size", type=int, default=128, help="candidate filenames per marker wave scan; larger reduces repeated container scans, smaller discovers recursive names sooner")
    ap.add_argument("--defer-member-writes", choices=("auto", "on", "off"), default="auto", help="delay source member writes until after recursion; auto=on for faster normal decrypt and restore paths")
    ap.add_argument("--fast-c", choices=("auto", "on", "off"), default="on", help="C fast core; on=default, use C for slky/key and AES/XOR hot paths; auto keeps tiny member AES on Python; off=Python/cryptography fallback")
    ap.add_argument("--use-c", action="store_true", help="use external C core slky only (legacy libiapp_core.so path)")
    ap.add_argument("--c-lib", default="./libiapp_core.so", help="external C core path for --use-c")
    args = ap.parse_args()
    global IAPT_SERVER_KEY_POOL, IAPT_REDACT_SELECTED_KEYS, IAPT_ANTI_IAPEC_ENABLED
    IAPT_ANTI_IAPEC_ENABLED = bool(getattr(args, "anti_iapec_encryption", False))
    if IAPT_ANTI_IAPEC_ENABLED:
        print("[IAPT_ANTI_IAPEC_CORE] enabled=true", flush=True)
    IAPT_SERVER_KEY_POOL = _iapt_load_server_key_pool(getattr(args, "key_pool_file", None)) if getattr(args, "key_pool_file", None) else []
    IAPT_REDACT_SELECTED_KEYS = bool(getattr(args, "redact_selected_keys", False))
    if IAPT_SERVER_KEY_POOL:
        print(f"[+] server dynamic key pool loaded: {len(IAPT_SERVER_KEY_POOL)} entries")
    # v102-cfix: enum modes try C first by default.
    # --no-python-fallback still decides whether to stop if C cannot verify.
    if getattr(args, "dexkey_enum", False):
        args.dexkey_c_batch = True
    if getattr(args, "sokey_enum", False):
        args.sokey_c_batch = True
    if (getattr(args, "sokey_enum", False) or getattr(args, "dexkey_enum", False)) and not bool(getattr(args, "allow_slow_python_fallback", False)):
        args.no_python_fallback = True

    joint_enum_requested = bool(getattr(args, "sokey_enum", False) and (getattr(args, "dexkey_enum", False) or getattr(args, "dex_enum", False)))
    if joint_enum_requested:
        # v144: joint enum is restored. It remains strict: no SO-exact hidden, no DEX/--fb shortcut.
        args.dexkey_c_batch = True
        args.sokey_c_batch = True
        if not getattr(args, "enum_workers", 0):
            # Phone-friendly default: avoid thermal throttling; user can pass --enum-workers 4/8.
            args.enum_workers = 2
    if bool(getattr(args, "sokey_enum", False)) and bool(getattr(args, "hidden", None)):
        raise SystemExit("--sokey-enum 和 --hidden 不能同时使用；要么枚举，要么手动指定 so密钥")
    if bool(getattr(args, "dexkey_enum", False) or getattr(args, "dex_enum", False)) and bool(getattr(args, "fb", None)):
        raise SystemExit("dexkey枚举 和 --fb 不能同时使用；要么枚举，要么手动指定 dex密钥")

    global MUST_HAVE_MAIN
    main_file = str(getattr(args, "main_file", "") or "mian.iyu").strip().replace("\\", "/").lstrip("/")
    if not main_file:
        main_file = "mian.iyu"
    if ".." in main_file or not re.fullmatch(r"[A-Za-z0-9_./\-\u0080-\uffff]+\.(?:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)", main_file, flags=re.I):
        raise SystemExit("invalid --main-file, e.g. mian.iyu or main.iyu")
    MUST_HAVE_MAIN = main_file
    if MUST_HAVE_MAIN != "mian.iyu":
        print("[+] main file     =", MUST_HAVE_MAIN)

    # IAPT_V119_NO_DYNAMIC_PARSE_BEGIN
    globals()["IAPT_NO_DYNAMIC_KEY"] = bool(getattr(args, "no_dynamic_key", False))
    if globals().get("IAPT_NO_DYNAMIC_KEY", False):
        print("[IAPT_V119] no-dynamic-key=True; dynamic key/cache blocked; outer-mode=" + str(getattr(args, "outer_mode", "")))
    # IAPT_V119_NO_DYNAMIC_PARSE_END

    # IAPT_V3_PARSE_NO_DYNAMIC_V92
    set_fast_c_mode(args.fast_c)
    if args.fast_c in ("on", "auto"):
        _load_c_fast_core(verbose=True)
    if args.restore_fn_names == "auto":
        print("[+] fn-restore default: auto (cheap mian.iyu gate; use --restore-fn-names off for normal-only decrypt)")
        print(f"[+] c-fast mode: {args.fast_c}")
    if int(getattr(args, "normal_workers", 0) or 0) > 0:
        args.threads = max(1, min(32, int(args.normal_workers)))
        print(f"[+] normal workers = {args.threads} (server controlled)")
    elif not args.threads or args.threads <= 0:
        args.threads = max(4, min(16, (os.cpu_count() or 4)))
    find_names = normalize_find_names(args.find)

    t_load_start = time.perf_counter()
    static_requested = bool(args.dump_static_ir or args.trace_slky_args or args.trace_asendn_args or args.outer_mode == "static")
    manifest, dex, so_data, container = load_inputs(
        args.apk, args.native_so, args.container, require_container=not static_requested,
        allow_missing_so=bool(args.hidden or args.hidden_enum or (args.post_key and args.key_xor) or IAPT_SERVER_KEY_POOL),
    )
    t_load_end = time.perf_counter()
    log_timing("load/input", t_load_start)

    if static_requested and container is None:
        run_static_outer_analysis(so_data, args.outdir, True, args.trace_slky_args or args.outer_mode == "static", args.trace_asendn_args or args.outer_mode == "static")
        print("[+] static-only run finished; no container was provided, so decrypt/verify was skipped")
        return

    t_params_start = time.perf_counter()
    params = {}
    if manifest:
        try:
            params = parse_axml_manifest(manifest)
        except Exception as e:
            print("[!] manifest parse failed:", e)
    package = args.package or params.get("package")
    version_name = args.version_name or params.get("versionName")
    version_code = args.version_code or params.get("versionCode")
    app_label = args.app_label or params.get("appLabel")
    # Resolve @7f.... application labels from resources.arsc when the APK is available.
    if app_label and str(app_label).startswith("@") and args.apk:
        try:
            _arsc = _apk_read_cached(args.apk, "resources.arsc")
            if _arsc is not None:
                    resolved_label = resolve_arsc_string_ref(_arsc, str(app_label))
                    if resolved_label:
                        print(f"[+] resolved appLabel {app_label} -> {resolved_label}")
                        app_label = resolved_label
        except Exception as e:
            print("[!] resources.arsc label resolve failed:", e)

    log_timing("manifest/resources", t_params_start)

    global _APK_DISCOVERED_MEMBER_CANDIDATES
    _main_candidates, _APK_DISCOVERED_MEMBER_CANDIDATES = discover_apk_source_candidates(
        args.apk, str(app_label or ""), str(package or ""), MUST_HAVE_MAIN
    )
    set_main_file_probe_candidates(_main_candidates)
    print("[+] main probes   = " + ", ".join(_enum_main_probe_name_list()[:12]))
    if _APK_DISCOVERED_MEMBER_CANDIDATES:
        print(f"[+] DEX member seeds = {len(_APK_DISCOVERED_MEMBER_CANDIDATES)}")

    t_extra_start = time.perf_counter()
    global _EXTRA_OUTER_ENV, _PASSWORD_DEEP_SCAN
    _PASSWORD_DEEP_SCAN = bool(args.deep_password_scan)
    _EXTRA_OUTER_ENV = load_apk_extra_env(args.apk, args.user_password, args.signature_mode, args.signature_bytes_hex)
    if _EXTRA_OUTER_ENV.get("user_encryption_required") == b"true" and not _EXTRA_OUTER_ENV.get("user_password"):
        raise SystemExit("assets/userencryption.xml has <ok>true</ok>; please provide --user-password")
    if _EXTRA_OUTER_ENV.get("signature_mode") == b"verify" and not _EXTRA_OUTER_ENV.get("signature"):
        print("[!] signature-mode=verify but APK signature bytes were not extracted; pass --signature-bytes-hex if this sample needs signature verification")
    if _EXTRA_OUTER_ENV:
        def _fmt_extra(k, v):
            if k in ("signature", "apk_signature"):
                return f"{k}=<DER {len(v)} bytes sha1={hashlib.sha1(v).hexdigest()}>"
            if k.startswith("user_password") or k in ("password",):
                return f"{k}=<provided {len(v)} bytes>"
            return f"{k}={v[:32].hex()}"
        print("[+] extra outer env:", ", ".join(_fmt_extra(k, v) for k, v in _EXTRA_OUTER_ENV.items()))
    log_timing("extra env", t_extra_start)

    t_fb_start = time.perf_counter()
    dexkey_enum_requested = bool(getattr(args, "dexkey_enum", False) or getattr(args, "dex_enum", False))
    fb_value = args.fb
    if dexkey_enum_requested and fb_value is not None and not bool(getattr(args, "allow_known_enum_seeds", False)):
        print(f"[+] strict dexkey enum = ignoring supplied --fb={fb_value}; dexkey must be found by scanning")
        fb_value = None
    if fb_value is None and not dexkey_enum_requested:
        fb_auto = extract_fb_from_apk_dexes(args.apk, dex)
        if fb_auto is not None:
            fb_value = str(fb_auto)
    # This exact native wrapper hides com.iapp.app.f from every APK DEX.  Once
    # the inner module has proved its hidden constant and normal-decrypt tables,
    # recover f.b() with the fixed C mian.iyu verifier.  No candidate is accepted
    # merely for producing valid AES padding.
    if fb_value is None and not dexkey_enum_requested and _IAPT_PACKED_NATIVE_PROFILE:
        _packed_hidden=list(_IAPT_PACKED_NATIVE_PROFILE.get("hidden_candidates") or [])
        _packed_pairs=list(_IAPT_PACKED_NATIVE_PROFILE.get("key_pairs") or [])
        try:
            _fb_start=max(0,int(os.environ.get("IAPT_PACKED_FB_START","100000") or 100000))
            _fb_stop=max(_fb_start,int(os.environ.get("IAPT_PACKED_FB_STOP","20000000") or 20000000))
        except Exception:
            _fb_start,_fb_stop=100000,20000000
        for _hidden_value in _packed_hidden[:4]:
            for _packed_pair in _packed_pairs[:16]:
                try:
                    _post_value,_xor_value=bytes(_packed_pair[0]),bytes(_packed_pair[1])
                except Exception:
                    continue
                _fb_hit=_cfast_fixed_dexkey_scan_mian(
                    container,bytes(_hidden_value),str(package),str(version_name),version_code,str(app_label),
                    _fb_start,_fb_stop,1,_post_value,_xor_value,MUST_HAVE_MAIN,
                )
                if _fb_hit is None:
                    continue
                fb_value=str(int(_fb_hit))
                _IAPT_PACKED_NATIVE_PROFILE["selected_hidden"]=bytes(_hidden_value)
                _IAPT_PACKED_NATIVE_PROFILE["selected_key_pair"]=(_post_value,_xor_value)
                print(
                    "[IAPT_BMP_RC4_ZLIB] verified_fb=%s range=%d..%d" % (fb_value,_fb_start,_fb_stop),
                    flush=True,
                )
                break
            if fb_value is not None:
                break
    fb_enum_enabled = bool(dexkey_enum_requested and fb_value is None)
    log_timing("fb resolve", t_fb_start)
    missing = []
    if package is None: missing.append("--package")
    if version_name is None: missing.append("--version-name")
    if version_code is None: missing.append("--version-code")
    if app_label is None: missing.append("--app-label")
    if fb_value is None and not fb_enum_enabled: missing.append("--fb")
    if missing:
        if static_requested and args.outer_mode == "static":
            run_static_outer_analysis(so_data, args.outdir, True, True, True)
            print("[+] static-only run finished; missing decrypt parameters, so decrypt/verify was skipped:", ", ".join(missing))
            return
        raise SystemExit("missing parameters: " + ", ".join(missing))
    if fb_enum_enabled:
        if bool(getattr(args, "dexkey_enum", False)):
            args.dexkey_enum_start = int(getattr(args, "dexkey_enum_start", 1736417) or 1736417)
            args.dexkey_enum_stop = int(getattr(args, "dexkey_enum_stop", 5936417) or 5936417)
            if args.dexkey_enum_start > args.dexkey_enum_stop:
                raise SystemExit("--dexkey-enum-start must be <= --dexkey-enum-stop")
            print(f"[+] dexkey enum  = on start={args.dexkey_enum_start} stop={args.dexkey_enum_stop} total={args.dexkey_enum_stop - args.dexkey_enum_start + 1}")
        else:
            args.dex_enum_start = max(1000000, int(args.dex_enum_start or 1000000))
            args.dex_enum_limit = max(1, int(args.dex_enum_limit or 9000000))
            args.dex_enum_windows = max(1, int(args.dex_enum_windows or 1))
            print(f"[+] f.b() enum   = on start={args.dex_enum_start} limit={args.dex_enum_limit} windows={args.dex_enum_windows}")

    # Keep each sample isolated: --outdir is a base directory, and normal
    # decrypt output goes under --outdir/<package>.  Use --flat-outdir for the
    # old direct-write layout.
    base_outdir = args.outdir
    package_dir_name = safe_dir_name(package)
    if not args.flat_outdir:
        args.outdir = base_outdir / package_dir_name
    print("[+] output base  =", base_outdir)
    print("[+] output dir   =", args.outdir)

    if container is None:
        raise SystemExit("container not found. Use --apk or --container")

    t_hidden_start = time.perf_counter()
    explicit_hidden_enum = bool((args.hidden_enum and not args.hidden) or getattr(args, "sokey_enum", False))
    if args.hidden:
        hidden_candidates = [parse_hidden_value(args.hidden)]
        hidden_enum_note = "manual-exact"
    elif getattr(args, "sokey_enum", False):
        hidden_candidates = build_sokey_timestamp_candidates_from_apk(
            args.apk, seconds=int(getattr(args, "sokey_enum_seconds", 180) or 180),
            max_files=int(getattr(args, "sokey_enum_files", 1) or 1),
            base_ts=int(getattr(args, "sokey_base_ts", 0) or 0) or None,
            list_mtimes=bool(getattr(args, "sokey_list_mtimes", False)),
            max_candidates=int(getattr(args, "sokey_max_candidates", 0) or 0),
        )
        _orig_sokey_total = len(hidden_candidates)
        _si = max(0, int(getattr(args, "sokey_enum_start_index", 0) or 0))
        _ei_raw = getattr(args, "sokey_enum_stop_index", -1)
        _ei = int(-1 if _ei_raw is None else _ei_raw)
        if _ei < 0 or _ei >= _orig_sokey_total:
            _ei = _orig_sokey_total - 1
        if _si > _ei:
            raise SystemExit(f"invalid sokey index range: start={_si} stop={_ei} total={_orig_sokey_total}")
        if _si != 0 or _ei != _orig_sokey_total - 1:
            hidden_candidates = hidden_candidates[_si:_ei + 1]
            print(f"[+] sokey enum slice = original[{_si}:{_ei}] -> {len(hidden_candidates)} candidates")
            for _dbg_i, _dbg_h in enumerate(hidden_candidates[:8], start=_si):
                print(f"    sokey[{_dbg_i}] = {_dbg_h.decode('ascii','replace')}")
            if len(hidden_candidates) > 8:
                print(f"    ... {len(hidden_candidates)-8} more sliced candidates")
        # v133 strict enum: do NOT inject SO-exact hidden/sokey values when
        # --sokey-enum is enabled.  Enumeration must prove the key by scanning
        # generated timestamp candidates.  Use normal non-enum mode if you want
        # to trust the exact hidden extracted from SO.
        _so_seed = []
        if bool(getattr(args, "sokey_safe_full_probe", False)):
            print("[+] sokey safe mode = original resolver + mian.iyu probe for every candidate; tiny-plan disabled")
        hidden_enum_note = "sokey-mtime-enum-strict"
    elif args.hidden_enum:
        # Explicit brute-force/list mode.  Do not inspect SO for hidden values:
        # this mode is intended for missing/encrypted SO hidden strings.
        hidden_candidates = build_explicit_hidden_candidates(args)
        hidden_enum_note = "explicit-bruteforce"
    else:
        # Normal fast path: exact SO string first.  Protected QuiShui/Tosks
        # builds move the hidden value out of libygsiyu.so; only under that
        # statically verified protector chain use a narrow timestamp window.
        hidden_candidates = extract_hidden_candidates(so_data, 1)
        hidden_enum_note = "so-exact"
        if not hidden_candidates:
            hidden_candidates = build_quishui_sokey_priority_candidates(args.apk)
            if hidden_candidates:
                hidden_enum_note = "quishui-static-mtime-priority"
                # Keep the ordinary resolver loop, but mark the statically proven
                # protector chain so key selection can use its two exact formulas.
                explicit_hidden_enum = False
                globals()["_QUISHUI_STATIC_SOKEY_ACTIVE"] = True
            else:
                raise ValueError("hidden not found; pass --hidden, --sokey-enum, or explicit --hidden-enum with candidates/mask")
    hidden = hidden_candidates[0]
    log_timing("hidden resolve", t_hidden_start)
    manual_post_key = bytes.fromhex(args.post_key) if args.post_key else None
    manual_key_xor = bytes.fromhex(args.key_xor) if args.key_xor else None
    if bool(getattr(args, "strict_manual_key", False)) and not (manual_post_key and manual_key_xor):
        raise SystemExit("--strict-manual-key requires both --post-key and --key-xor")
    _quishui_auto_quiet = bool(
        globals().get("_QUISHUI_STATIC_SOKEY_ACTIVE", False)
        and not bool(getattr(args, "debug_candidates", False))
    )
    if _quishui_auto_quiet:
        _priority_count = min(256, len(hidden_candidates))
        print(
            f"[+] hidden enum  = {hidden_enum_note}, priority={_priority_count}, "
            f"fallback={max(0, len(hidden_candidates) - _priority_count)}"
        )
        print("[+] QuiShui sokey probe = staged; progress every 64 candidates; failed-key diagnostics suppressed")
    else:
        print(f"[+] hidden enum  = {hidden_enum_note}, candidates={len(hidden_candidates)}")
        for _idx, _h in enumerate(hidden_candidates[:8]):
            print(f"    hidden[{_idx}] = {_h.decode('ascii', 'replace')}")
        if len(hidden_candidates) > 8:
            print(f"    ... {len(hidden_candidates) - 8} more hidden candidates")
    print("[+] package      =", package)
    print("[+] versionName  =", version_name)
    print("[+] versionCode  =", parse_int_auto(version_code))
    print("[+] appLabel     =", app_label)
    if fb_enum_enabled:
        print("[+] f.b()        = <enum>")
    else:
        print("[+] f.b()        =", parse_int_auto(fb_value))
    print("[+] mode         =", args.mode)
    print("[+] outer-mode   =", args.outer_mode)
    print("[+] build        =", STATIC_OUTER_BUILD)
    print("[+] patch        = fast-v146: true no-hint joint exhaustive; one hidden setup per full dex scan; exact fallback preserved")
    if find_names:
        print("[+] find targets =", ", ".join(find_names))
        print("[+] find mode    =", "recursive/all" if args.find_recursive else "only explicit --find targets")
    if args.max_output_files:
        if args.max_output_files < 1:
            raise SystemExit("--max-output-files must be 0/unlimited or >= 1")
        print("[+] max outputs  =", args.max_output_files, "member source file(s), including mian.iyu")

    args.outdir.mkdir(parents=True, exist_ok=True)
    tmp_dir = args.outdir / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)

    t_key_start = time.perf_counter()
    cache_fingerprint = None
    cache_path = tmp_dir / "outer_key_cache.json"
    shared_cache_path = None
    cached_outer = None
    post_key = key_xor = outer_key = container_plain = trace = None
    last_key_error: Optional[BaseException] = None
    selected_hidden_index = -1

    def _select_with_hidden(hidden_try: bytes, fb_try=None, shell_probe_only: bool = False):
        
        nonlocal cache_fingerprint, shared_cache_path, cached_outer, last_key_error
        fb_for_try = str(fb_try) if fb_try is not None else fb_value
        cache_fingerprint = None
        shared_cache_path = None
        cached_outer = None
        if (not args.no_key_cache) and (not bool(getattr(args, "strict_manual_key", False))) and (not explicit_hidden_enum) and (not shell_probe_only):
            t_cache_fp = time.perf_counter()
            cache_fingerprint = outer_cache_fingerprint(
                so_data, container, hidden_try, package, version_name, version_code, app_label, fb_for_try,
                args.mode, args.outer_mode, _EXTRA_OUTER_ENV,
            )
            print(f"[T] outer cache fingerprint {ms_since(t_cache_fp):.3f} ms hidden={hidden_try.decode('ascii', 'replace')}")
            shared_cache_path = shared_outer_cache_path(cache_fingerprint)
            cached_outer = load_cached_outer_result(cache_path, cache_fingerprint, container, hidden_try, fb_for_try, args.use_c, args.c_lib)
            if cached_outer is None and shared_cache_path != cache_path:
                cached_outer = load_cached_outer_result(shared_cache_path, cache_fingerprint, container, hidden_try, fb_for_try, args.use_c, args.c_lib)
                if cached_outer is not None:
                    print(f"[+] shared outer cache hit: {shared_cache_path}")
        if cached_outer is not None:
            return cached_outer
        try:
            return auto_select_keys(
                so_data, hidden_try, container, package, version_name, version_code, app_label, fb_for_try,
                manual_post_key, manual_key_xor, mode=args.mode, outer_mode=args.outer_mode, outdir=args.outdir,
                dump_static_ir=args.dump_static_ir, trace_slky_args=args.trace_slky_args, trace_asendn_args=args.trace_asendn_args,
                use_c=args.use_c, c_path=args.c_lib, debug_candidates=args.debug_candidates,
                dump_outer_candidates=(args.dump_outer_candidates or args.debug_candidates),
                shell_probe_only=shell_probe_only,
                strict_manual_key=bool(getattr(args, "strict_manual_key", False)),
            )
        except RuntimeError as e:
            if args.user_password and not _PASSWORD_DEEP_SCAN:
                print("[!] fast password salt path failed; retrying with deep DEX salt scan")
                globals()["_PASSWORD_DEEP_SCAN"] = True
                t_extra_retry = time.perf_counter()
                globals()["_EXTRA_OUTER_ENV"] = load_apk_extra_env(args.apk, args.user_password, args.signature_mode, args.signature_bytes_hex)
                print(f"[T] extra env deep retry   {ms_since(t_extra_retry):.3f} ms")
                if not args.no_key_cache:
                    cache_fingerprint = outer_cache_fingerprint(
                        so_data, container, hidden_try, package, version_name, version_code, app_label, fb_for_try,
                        args.mode, args.outer_mode, _EXTRA_OUTER_ENV,
                    )
                    shared_cache_path = shared_outer_cache_path(cache_fingerprint)
                return auto_select_keys(
                    so_data, hidden_try, container, package, version_name, version_code, app_label, fb_for_try,
                    manual_post_key, manual_key_xor, mode=args.mode, outer_mode=args.outer_mode, outdir=args.outdir,
                    dump_static_ir=args.dump_static_ir, trace_slky_args=args.trace_slky_args, trace_asendn_args=args.trace_asendn_args,
                    use_c=args.use_c, c_path=args.c_lib, debug_candidates=args.debug_candidates,
                    dump_outer_candidates=(args.dump_outer_candidates or args.debug_candidates),
                    shell_probe_only=shell_probe_only,
                    strict_manual_key=bool(getattr(args, "strict_manual_key", False)),
                )
            last_key_error = e
            raise

    enum_shell_probe_only = bool(getattr(args, "sokey_enum", False) or getattr(args, "dexkey_enum", False) or getattr(args, "dex_enum", False))
    if enum_shell_probe_only:
        print("[+] enum probe    = full-C/quad if requested; otherwise outer-shell only Python fallback")
    _sokey_probe_timeout_ms = _iapt_probe_timeout_ms(args) if bool(getattr(args, "sokey_enum", False)) else 0
    if bool(getattr(args, "sokey_enum", False)) and _sokey_probe_timeout_ms > 0:
        print(f"[+] sokey watchdog = {_sokey_probe_timeout_ms} ms per candidate; timeout means skip this sokey")
    if bool(getattr(args, "dexkey_enum", False) or getattr(args, "dex_enum", False)):
        _dex_timeout_ms = _iapt_dexkey_probe_timeout_ms(args)
        if _dex_timeout_ms > 0:
            print(f"[+] dexkey watchdog = {_dex_timeout_ms} ms per candidate; timeout means skip this dexkey")


    if joint_enum_requested:
        print(f"[+] joint enum    = enabled strict sokey+dexkey C scan workers={int(getattr(args, 'enum_workers', 0) or 0)} hidden={len(hidden_candidates)} dex={int(args.dexkey_enum_start)}..{int(args.dexkey_enum_stop)}")
        _joint_shortcut_done = False
        # v133 strict enum: no SO-exact hidden shortcut when --sokey-enum is enabled.
        if False and str(hidden_enum_note).startswith("sokey-so-seeded") and hidden_candidates:
            print("[+] joint shortcut = SO-exact hidden seed -> dexkey C enum")
            _dex_hit = _iapt_try_dexkey_cbatch_fixed(
                hidden_candidates[0], int(args.dexkey_enum_start), int(args.dexkey_enum_stop),
                so_data, container, package, version_name, version_code, app_label,
                manual_post_key, manual_key_xor, args,
            )
            if _dex_hit is not None:
                selected_hidden_index = 0
                hidden = hidden_candidates[0]
                fb_value = str(int(_dex_hit))
                post_key, key_xor, outer_key, container_plain, trace = _select_with_hidden(hidden, fb_value, shell_probe_only=True)
                trace, _enum_main_plain = finalize_outer_shell_probe(container_plain, post_key, key_xor, hidden, fb_value, trace, use_c=args.use_c, c_path=args.c_lib)
                print(f"[+] joint selected hidden[0] = {hidden.decode('ascii','replace')}")
                print(f"[+] selected f.b() = {fb_value}")
                _joint_shortcut_done = True
        if not _joint_shortcut_done:
            _joint_hit=_iapt_try_joint_sokey_dexkey_cbatch(
                hidden_candidates,int(args.dexkey_enum_start),int(args.dexkey_enum_stop),so_data,container,
                package,version_name,version_code,app_label,manual_post_key,manual_key_xor,args)
            if _joint_hit is None:
                raise RuntimeError("fused sokey+dexkey C enumeration completed without a verified hit")
            selected_hidden_index,_joint_fb=_joint_hit
            hidden=hidden_candidates[selected_hidden_index];fb_value=str(_joint_fb)
            post_key,key_xor,outer_key,container_plain,trace=_select_with_hidden(hidden,_joint_fb,shell_probe_only=True)
            trace,_enum_main_plain=finalize_outer_shell_probe(container_plain,post_key,key_xor,hidden,fb_value,trace,use_c=args.use_c,c_path=args.c_lib)
            print(f"[+] joint selected hidden[{selected_hidden_index}] = {hidden.decode('ascii','replace')}")
            print(f"[+] selected f.b() = {fb_value}")

    # sokey 枚举热路径缓存：sokey/hidden 会变，但 APK/SO bytes、动态库 key
    # 提取结果、priority outer algorithms、template candidates 都不变。旧版每个
    # hidden 都重新 auto_select_keys()，这里改成一次建 probe_plan，循环里只换
    # hidden + fb env 做外壳探测。
    local_cached_enum_probe = False
    if bool(getattr(args, "sokey_enum", False)) and not bool(getattr(args, "dexkey_enum", False)) and not bool(getattr(args, "sokey_safe_full_probe", False)):
        try:
            _local_state: Dict[str, object] = {
                "so_data": so_data,
                "hidden": hidden_candidates[0] if hidden_candidates else b"",
                "container": container,
                "package": str(package),
                "version_name": str(version_name),
                "version_code": version_code,
                "app_label": str(app_label),
                "manual_post_key": manual_post_key,
                "manual_key_xor": manual_key_xor,
                "mode": args.mode,
                "outer_mode": args.outer_mode,
                "use_c": bool(args.use_c),
                "c_path": str(args.c_lib),
                "fast_c": str(args.fast_c),
                "extra_outer_env": dict(_EXTRA_OUTER_ENV),
                "apk_native_so_candidates": list(_APK_NATIVE_SO_CANDIDATES),
                "no_dynamic_key": bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)),
                "main_file": MUST_HAVE_MAIN,
                "sokey_strict_main_probe": True,
                "outer_plain_cache_max": 32,
            }
            _iapt_dexkey_mp_init(_local_state)
            local_cached_enum_probe = bool(_IAPT_DEXKEY_MP_STATE.get("probe_plan"))
            if local_cached_enum_probe:
                print("[+] sokey enum cache = on; balanced no-skip plan + original mian.iyu-only decrypt probe enabled")
        except Exception as _cache_err:
            print(f"[!] sokey enum cache disabled: {type(_cache_err).__name__}: {_cache_err}")
            local_cached_enum_probe = False

    # sokey 四向并发枚举：4 个进程分别从开头、结尾、中间向前、中间向后扫。
    # 只用于 cached probe path；安全 full-probe 仍走下面的旧单进程循环，避免行为变化。
    if bool(getattr(args, "sokey_enum", False)) and local_cached_enum_probe and not fb_enum_enabled and str(getattr(args, "sokey_scan_strategy", "linear") or "linear") == "quad-sweep":
        try:
            _sokey_state = {
                "so_data": so_data,
                "hidden": hidden_candidates[0] if hidden_candidates else b"",
                "container": container,
                "package": str(package),
                "version_name": str(version_name),
                "version_code": version_code,
                "app_label": str(app_label),
                "manual_post_key": manual_post_key,
                "manual_key_xor": manual_key_xor,
                "mode": args.mode,
                "outer_mode": args.outer_mode,
                "use_c": bool(args.use_c),
                "c_path": str(args.c_lib),
                "fast_c": str(args.fast_c),
                "extra_outer_env": dict(_EXTRA_OUTER_ENV),
                "apk_native_so_candidates": list(_APK_NATIVE_SO_CANDIDATES),
                "no_dynamic_key": bool(globals().get("IAPT_NO_DYNAMIC_KEY", False)),
                "main_file": MUST_HAVE_MAIN,
                "sokey_strict_main_probe": True,
                "outer_plain_cache_max": 32,
                "probe_plan_prebuilt": dict(_IAPT_DEXKEY_MP_STATE.get("probe_plan") or {}),
            }
            _sokey_hit = _iapt_try_sokey_cbatch_fixed(hidden_candidates, fb_value, _sokey_state, args)
            if _sokey_hit is None:
                if bool(getattr(args, "no_python_fallback", False)):
                    raise RuntimeError("sokey C-batch did not return a verified key and --no-python-fallback is set; Python quad probe is disabled")
                _sokey_hit = _iapt_sokey_quad_parallel_probe(hidden_candidates, fb_value, _sokey_state, args)
            if _sokey_hit is not None:
                selected_hidden_index, hidden, post_key, key_xor, outer_key, container_plain, trace = _sokey_hit
                cached_outer = None
            else:
                raise RuntimeError("sokey quad-sweep completed but no key passed mian.iyu probe")
        except RuntimeError as e:
            last_key_error = e
            raise

    if explicit_hidden_enum and not bool(getattr(args, "sokey_enum", False)):
        enum_workers = int(args.enum_workers or max(1, min(8, os.cpu_count() or 1)))
        print(f"[+] hidden enum mp = workers={enum_workers} chunk={int(args.enum_chunk_size or 4096)}")
        fixed_fast = try_explicit_hidden_enum_parallel(
            hidden_candidates, container, package, version_name, version_code, app_label, fb_value,
            manual_post_key, manual_key_xor, args.mode, "xor",
            workers=enum_workers, chunk_size=int(args.enum_chunk_size or 4096), fast_c_mode=args.fast_c,
        )
        if fixed_fast is not None:
            selected_hidden_index, hidden, post_key, key_xor, outer_key, container_plain, trace = fixed_fast
            cached_outer = None
        else:
            raise RuntimeError("explicit --hidden-enum found no valid hidden in fast segmented verifier; provide --post-key/--key-xor or a narrower candidate range")

    _hidden_idx = 0
    _hidden_auto_expanded = False
    while selected_hidden_index < 0 and _hidden_idx < len(hidden_candidates):
        _hidden_try = hidden_candidates[_hidden_idx]
        _hidden_t0 = time.perf_counter()
        if len(hidden_candidates) > 1:
            if _quishui_auto_quiet:
                _probe_no = _hidden_idx + 1
                if _probe_no == 1 or (_probe_no % 64) == 0:
                    _stage = "priority" if _probe_no <= 256 else "fallback"
                    print(
                        f"[+] QuiShui sokey progress: tested={_probe_no}/{len(hidden_candidates)} stage={_stage}",
                        flush=True,
                    )
            else:
                print(
                    f"[+] try hidden[{_hidden_idx + 1}/{len(hidden_candidates)}] "
                    f"{_hidden_try.decode('ascii', 'replace')}",
                    flush=True,
                )
        if fb_enum_enabled and bool(getattr(args, "dexkey_enum", False)):
            fb_start = int(args.dexkey_enum_start)
            fb_stop = int(args.dexkey_enum_stop)
        else:
            fb_start = int(args.dex_enum_start)
            fb_limit = int(args.dex_enum_limit)
            fb_windows = int(args.dex_enum_windows)
            fb_stop = min(9999999, fb_start + fb_limit * fb_windows - 1)
        if fb_enum_enabled and bool(getattr(args, "dexkey_enum", False)) and int(getattr(args, "enum_workers", 0) or 0) != 1:
            _mp_fb_hit = try_dexkey_enum_parallel_outer_probe(
                _hidden_try, fb_start, fb_stop, so_data, container, package, version_name, version_code, app_label,
                manual_post_key, manual_key_xor, args,
            )
            if _mp_fb_hit is not None:
                _fb_try = int(_mp_fb_hit)
                try:
                    if bool(getattr(args, "sokey_enum", False)) and local_cached_enum_probe and not fb_enum_enabled:
                        _fb_for_cached = fb_value
                        with _IaptSoftTimeoutMs(_sokey_probe_timeout_ms, f"sokey[{_hidden_idx}] cached probe"):
                            _cached_hit = _iapt_dexkey_cached_probe_one(_fb_for_cached, hidden_override=_hidden_try)
                        if _cached_hit is None:
                            raise RuntimeError("cached sokey outer-shell probe failed")
                        post_key, key_xor, outer_key, container_plain, trace = _cached_hit
                    else:
                        _verified_cbatch = _iapt_take_cbatch_verified_result(_fb_try, _hidden_try)
                        if _verified_cbatch is not None:
                            post_key, key_xor, outer_key, container_plain, trace = _verified_cbatch
                            print("[+] using C-batch verified arm/native key tuple for final selection", flush=True)
                        else:
                            with _IaptSoftTimeoutMs(_sokey_probe_timeout_ms, f"sokey[{_hidden_idx}] select probe"):
                                post_key, key_xor, outer_key, container_plain, trace = _select_with_hidden(_hidden_try, _fb_try, shell_probe_only=enum_shell_probe_only)
                    if enum_shell_probe_only:
                        if isinstance(trace, dict) and trace.get("enum_shell_probe_finalized") == b"1":
                            _enum_main_plain = b""
                            print(f"[+] enum shell hit already verified: {MUST_HAVE_MAIN}", flush=True)
                        else:
                            with _IaptSoftTimeoutMs(_sokey_probe_timeout_ms, f"sokey[{_hidden_idx}] mian probe"):
                                trace, _enum_main_plain = finalize_outer_shell_probe(
                                    container_plain, post_key, key_xor, _hidden_try, str(_fb_try), trace,
                                    use_c=args.use_c, c_path=args.c_lib,
                                )
                            print(f"[+] enum shell hit finalized: {MUST_HAVE_MAIN} {len(_enum_main_plain)} bytes")
                    hidden = _hidden_try
                    selected_hidden_index = _hidden_idx
                    fb_value = str(_fb_try)
                    print(f"[+] selected f.b() = {fb_value}")
                    if cache_fingerprint is not None and cached_outer is None:
                        save_cached_outer_result(cache_path, cache_fingerprint, post_key, key_xor, outer_key, trace)
                        if shared_cache_path is not None and shared_cache_path != cache_path:
                            save_cached_outer_result(shared_cache_path, cache_fingerprint, post_key, key_xor, outer_key, trace)
                    break
                except RuntimeError as e:
                    last_key_error = e
                    print(f"[!] dexkey mp selected candidate failed final check: {_fb_try} ({type(e).__name__}: {e})")
            raise last_key_error or RuntimeError("dexkey枚举完成但没有找到可解外壳/主文件的 dexkey")
        fb_candidates = range(fb_start, fb_stop + 1) if fb_enum_enabled else (None,)
        try:
            for _fb_idx, _fb_try in enumerate(fb_candidates):
                if fb_enum_enabled and (_fb_idx < 8 or _fb_try == fb_stop or (_fb_idx % 10000) == 0):
                    print(f"[+] try f.b()[{_fb_idx}] {_fb_try}")
                try:
                    if bool(getattr(args, "sokey_enum", False)) and local_cached_enum_probe and not fb_enum_enabled:
                        with _IaptSoftTimeoutMs(_sokey_probe_timeout_ms, f"sokey[{_hidden_idx}] cached probe"):
                            _cached_hit = _iapt_dexkey_cached_probe_one(fb_value, hidden_override=_hidden_try)
                        if _cached_hit is None:
                            raise RuntimeError("cached sokey mian.iyu probe failed")
                        post_key, key_xor, outer_key, container_plain, trace = _cached_hit
                    else:
                        with _IaptSoftTimeoutMs(_sokey_probe_timeout_ms, f"sokey[{_hidden_idx}] select probe"):
                            if _quishui_auto_quiet:
                                with contextlib.redirect_stdout(io.StringIO()):
                                    post_key, key_xor, outer_key, container_plain, trace = _select_with_hidden(
                                        _hidden_try, _fb_try, shell_probe_only=enum_shell_probe_only
                                    )
                            else:
                                post_key, key_xor, outer_key, container_plain, trace = _select_with_hidden(
                                    _hidden_try, _fb_try, shell_probe_only=enum_shell_probe_only
                                )
                    if enum_shell_probe_only:
                        # Cached sokey path has already verified mian.iyu using the original member
                        # decrypt path.  Do not run the same verification twice.
                        if isinstance(trace, dict) and trace.get("enum_shell_probe_finalized") == b"1":
                            pass
                        else:
                            try:
                                with _IaptSoftTimeoutMs(_sokey_probe_timeout_ms, f"sokey[{_hidden_idx}] mian probe"):
                                    trace, _enum_main_plain = finalize_outer_shell_probe(
                                        container_plain, post_key, key_xor, _hidden_try,
                                        str(_fb_try) if _fb_try is not None else fb_value,
                                        trace, use_c=args.use_c, c_path=args.c_lib,
                                    )
                                print(f"[+] enum shell hit finalized: {MUST_HAVE_MAIN} {len(_enum_main_plain)} bytes")
                            except Exception as _enum_final_err:
                                raise RuntimeError(str(_enum_final_err))
                    hidden = _hidden_try
                    selected_hidden_index = _hidden_idx
                    # IAPT_SERVER_SOKEY_STATIC_V280_BRANCH_BEGIN
                    if bool(getattr(args, "server_sokey_static", False)):
                        hidden, _iapt_v280_sokey_meta = _iapt_v280_extract_sokey_from_apk(args.apk)
                        hidden_candidates = [hidden]
                        hidden_enum_note = "server-so-static"
                        print(
                            "[IAPT_V280] server sokey recovered from libygsiyu.so: "
                            "strategy=%s entries=%s"
                            % (
                                _iapt_v280_sokey_meta.get("strategy"),
                                ",".join(_iapt_v280_sokey_meta.get("successful_entries") or []),
                            ),
                            flush=True,
                        )
                    # IAPT_SERVER_SOKEY_STATIC_V280_BRANCH_END
                    elif bool(getattr(args, "sokey_enum", False)):
                        print(
                            f"[+] sokey candidate OK [{_hidden_idx + 1}/{len(hidden_candidates)}] "
                            f"{ms_since(_hidden_t0):.3f} ms hidden={_hidden_try.decode('ascii', 'replace')}",
                            flush=True,
                        )
                    if fb_enum_enabled:
                        fb_value = str(_fb_try)
                        print(f"[+] selected f.b() = {fb_value}")
                    if cache_fingerprint is not None and cached_outer is None:
                        save_cached_outer_result(cache_path, cache_fingerprint, post_key, key_xor, outer_key, trace)
                        if shared_cache_path is not None and shared_cache_path != cache_path:
                            save_cached_outer_result(shared_cache_path, cache_fingerprint, post_key, key_xor, outer_key, trace)
                    break
                except RuntimeError as e:
                    last_key_error = e
                    if not fb_enum_enabled:
                        raise
                    if _fb_idx < 8 or _fb_try == fb_stop or (_fb_idx % 10000) == 0:
                        print(f"[!] f.b() candidate failed: {_fb_try} ({type(e).__name__}: {e})")
            if selected_hidden_index >= 0:
                break
            raise last_key_error or RuntimeError("no f.b() candidate could decrypt outer shell/main file")
        except RuntimeError as e:
            last_key_error = e
            if bool(getattr(args, "sokey_enum", False)):
                # verbose enum log: print EVERY failed sokey candidate with elapsed time.
                print(
                    f"[!] sokey candidate failed [{_hidden_idx + 1}/{len(hidden_candidates)}] "
                    f"{ms_since(_hidden_t0):.3f} ms hidden={_hidden_try.decode('ascii', 'replace')}: "
                    f"{type(e).__name__}: {e}",
                    flush=True,
                )
            elif _quishui_auto_quiet:
                pass
            elif (not explicit_hidden_enum) or _hidden_idx < 8 or _hidden_idx == len(hidden_candidates) - 1 or (_hidden_idx % 1000) == 0:
                print(f"[!] hidden candidate failed: {_hidden_try.decode('ascii', 'replace')} ({type(e).__name__}: {e})")
            _hidden_idx += 1
            # v46: no automatic hidden expansion.  Hidden enumeration is explicit
            # and candidate lists/masks are fully prepared before this loop.
            continue
    if selected_hidden_index < 0:
        if last_key_error:
            raise last_key_error
        raise RuntimeError("no hidden candidate could decrypt outer shell/main file")
    assert post_key is not None and key_xor is not None and outer_key is not None and container_plain is not None and trace is not None
    print(f"[+] selected hidden = hidden[{selected_hidden_index}] {hidden.decode('ascii', 'replace')}")
    t_key_end = time.perf_counter()
    print(f"[T] key selection/cache    {(t_key_end - t_key_start) * 1000.0:.3f} ms")
    _pool_match_ref = _iapt_server_pool_match(post_key, key_xor)
    if _pool_match_ref:
        print("[+] SERVER_KEY_POOL_MATCH =", _pool_match_ref)
    if trace.get("key_source"):
        print("[+] KEY_SOURCE =", trace["key_source"].decode("utf-8", "replace"))
    if IAPT_REDACT_SELECTED_KEYS and _pool_match_ref:
        print("[+] SLKY_POST_KEY = [server-pool-redacted]")
        print("[+] KEY_XOR_CONST = [server-pool-redacted]")
    else:
        print("[+] SLKY_POST_KEY =", post_key.hex())
        print("[+] KEY_XOR_CONST =", key_xor.hex())
    print("[+] base          =", trace.get("base", b"").decode("utf-8", "replace"))
    if trace.get("p19"):
        print("[+] p19           =", trace["p19"].hex())
    if trace.get("p24"):
        print("[+] p24           =", trace["p24"].hex())
    if trace.get("p25"):
        print("[+] p25           =", trace["p25"].hex())
    if trace.get("algorithm"):
        print("[+] outer algo    =", trace["algorithm"].decode("utf-8", "replace"))
    if trace.get("idbfj_pick"):
        print("[+] idbfj pick    =", trace["idbfj_pick"].decode("utf-8", "replace"))
    if trace.get("idbfj_input") is not None:
        print("[+] idbfj input   =", trace.get("idbfj_input", b"").hex())
    if trace.get("idbfj_second"):
        print("[+] idbfj second  =", trace["idbfj_second"].decode("utf-8", "replace"))
    if trace.get("signature_mode"):
        print("[+] sig mode      =", trace["signature_mode"].decode("utf-8", "replace"))
    if trace.get("signature_len"):
        print("[+] sig len       =", trace["signature_len"].decode("utf-8", "replace"))
    if trace.get("signature_sha1"):
        print("[+] sig sha1      =", trace["signature_sha1"].decode("utf-8", "replace"))
    if trace.get("timing_outer_key_ms"):
        print("[T] outer_key derive      ", trace["timing_outer_key_ms"].decode("utf-8", "replace"), "ms")
    if trace.get("timing_outer_decrypt_ms"):
        print("[T] outer/container decrypt", trace["timing_outer_decrypt_ms"].decode("utf-8", "replace"), "ms")
    if trace.get("timing_mian_candidate_verify_ms"):
        print("[T] candidate mian verify ", trace["timing_mian_candidate_verify_ms"].decode("utf-8", "replace"), "ms")
    print("[+] outer_key     =", outer_key.hex())

    args.outdir.mkdir(parents=True, exist_ok=True)
    tmp_dir = args.outdir / ".tmp"
    tmp_dir.mkdir(parents=True, exist_ok=True)
    t_container_write = time.perf_counter()
    container_out = tmp_dir / "container_plain.bin"
    if trace.get("container_plain_from_cache") == b"1" and container_out.exists():
        print(f"[+] container decrypted: {len(container_plain)} bytes write=0.000 ms cached -> {container_out}")
    else:
        container_out.write_bytes(container_plain)
        print(f"[+] container decrypted: {len(container_plain)} bytes write={ms_since(t_container_write):.3f} ms -> {container_out}")
    # v14: keep a second, durable hardlink outside the task output tree.
    # The API uses this only for shell-find/owner metadata. It is never indexed
    # or added to the downloadable ZIP.
    _iapt_durable_shell_dir = str(os.environ.get("IAPT_DURABLE_SHELL_DIR") or "").strip()
    if _iapt_durable_shell_dir:
        try:
            _durable_dir = Path(_iapt_durable_shell_dir)
            _durable_dir.mkdir(parents=True, exist_ok=True)
            _durable_plain = _durable_dir / "container_plain.bin"
            if _durable_plain.exists():
                try:
                    if _durable_plain.stat().st_size != container_out.stat().st_size:
                        _durable_plain.unlink()
                except Exception:
                    _durable_plain.unlink(missing_ok=True)
            if not _durable_plain.exists():
                try:
                    os.link(container_out, _durable_plain)
                except Exception:
                    _tmp_durable = _durable_plain.with_name(_durable_plain.name + ".tmp." + str(os.getpid()))
                    _tmp_durable.write_bytes(container_plain)
                    os.replace(_tmp_durable, _durable_plain)
            _reuse_v14 = {
                "version": 14,
                "post_key": post_key.hex(),
                "key_xor": key_xor.hex(),
                "outer_key": outer_key.hex(),
                "hidden_hex": hidden.hex(),
                "fb": str(fb_value),
                "member_ctx": (trace.get("member_ctx", b"post").decode("utf-8", "replace") if isinstance(trace.get("member_ctx", b"post"), bytes) else str(trace.get("member_ctx", "post"))),
                "member_key_mode": (trace.get("member_key_mode", b"xor").decode("utf-8", "replace") if isinstance(trace.get("member_key_mode", b"xor"), bytes) else str(trace.get("member_key_mode", "xor"))),
                "package": str(package),
                "container_size": len(container_plain),
            }
            (_durable_dir / "reuse_session_v14.json").write_text(
                json.dumps(_reuse_v14, ensure_ascii=False, sort_keys=True, indent=2),
                encoding="utf-8",
            )
            print(f"[+] durable shell retained: {_durable_plain}")
        except Exception as _durable_err:
            print(f"[!] durable shell retain failed: {type(_durable_err).__name__}: {_durable_err}")

    # Populate the shared plain-container cache with a hardlink after the normal
    # output write.  This makes warm runs cheap without double-writing 4–5 MB in
    # the cold key-selection path.  If hardlinking is not supported, skip it
    # rather than slowing down the current run with a full copy.
    try:
        if (not args.no_key_cache) and shared_cache_path is not None:
            shared_plain = shared_cache_path.parent / "container_plain.bin"
            if not shared_plain.exists() and container_out.exists():
                shared_cache_path.parent.mkdir(parents=True, exist_ok=True)
                os.link(container_out, shared_plain)
    except Exception:
        pass

    member_ctx_name = trace.get("member_ctx", b"post") if isinstance(trace, dict) else b"post"
    if isinstance(member_ctx_name, bytes):
        member_ctx_name_s = member_ctx_name.decode("utf-8", "replace")
    else:
        member_ctx_name_s = str(member_ctx_name)
    member_key_mode = trace.get("member_key_mode", b"xor") if isinstance(trace, dict) else b"xor"
    if isinstance(member_key_mode, bytes):
        member_key_mode_s = member_key_mode.decode("utf-8", "replace")
    else:
        member_key_mode_s = str(member_key_mode)
    if member_ctx_name_s == "nopost":
        ctx = NoPostSlkyContext()
    else:
        ctx = SlkyContext(post_key, use_c=args.use_c, c_path=args.c_lib)
    print(f"[+] member ctx    = {member_ctx_name_s}")
    print(f"[+] member key    = {member_key_mode_s}")

    t_mian_start = time.perf_counter()
    if isinstance(trace, dict):
        _trace_main = trace.get("main_file") or trace.get("verified_member") or trace.get("enum_main_file")
        if isinstance(_trace_main, bytes):
            _trace_main = _trace_main.decode("utf-8", "replace")
        _trace_main = _safe_root_source_name(str(_trace_main or ""))
        if _trace_main:
            MUST_HAVE_MAIN = _trace_main
    _verified_main_name, mian_plain = verify_main_or_fail(container_plain, ctx, key_xor, hidden, fb_value, member_key_mode_s)
    MUST_HAVE_MAIN = _verified_main_name
    # IAPT_V175_ROOT_CAUSE_SCOPE_FIX: keep the whitelist probe inside main().
    # IAPT_WHITELIST_PACKAGE_SIGNATURE_TOOL_V168_BEGIN
    # At this location only the single verified main member has been decrypted.
    # Other project metadata and other encrypted members have not been touched.
    #
    # The check is containment, not equality:
    #     expected_signature in main_plaintext
    #
    # Text before/after the signature (for example "sss.") is irrelevant.
    # A compact second pass ignores spaces, tabs and line breaks inserted by an
    # editor into the Base64 text.
    import re as _v168_re
    import shutil as _v168_shutil

    _v168_probe_raw = str(
        os.environ.get(
            'IAPT_WHITELIST_PACKAGE_SIGNATURES_V168'
        )
        or ''
    ).strip()

    if _v168_probe_raw:
        try:
            _v168_probe_path = Path(
                _v168_probe_raw
            )
            _v168_probe = json.loads(
                _v168_probe_path.read_text(
                    'utf-8'
                )
            )
            _v168_records = (
                _v168_probe.get('records')
                if isinstance(
                    _v168_probe,
                    dict,
                )
                else []
            )
            if not isinstance(
                _v168_records,
                list,
            ):
                _v168_records = []

            if isinstance(
                mian_plain,
                bytes,
            ):
                _v168_main_bytes = mian_plain
            elif isinstance(
                mian_plain,
                bytearray,
            ):
                _v168_main_bytes = bytes(
                    mian_plain
                )
            elif isinstance(
                mian_plain,
                memoryview,
            ):
                _v168_main_bytes = (
                    mian_plain.tobytes()
                )
            else:
                _v168_main_bytes = str(
                    mian_plain
                ).encode(
                    'utf-8',
                    'surrogatepass',
                )

            _v168_main_compact = (
                _v168_re.sub(
                    rb'[\x09-\x0d\x20]+',
                    b'',
                    _v168_main_bytes,
                )
            )

            _v168_hit = None
            _v168_hit_mode = ''
            _v168_checks = []

            for _v168_record in _v168_records:
                if not isinstance(
                    _v168_record,
                    dict,
                ):
                    continue

                _v168_signature = str(
                    _v168_record.get(
                        'signature_base64'
                    )
                    or ''
                ).strip()

                if not _v168_signature:
                    continue

                try:
                    _v168_needle = (
                        _v168_signature.encode(
                            'ascii'
                        )
                    )
                except Exception:
                    continue

                # Direct containment. main plaintext never has to equal the key.
                _v168_direct = (
                    _v168_needle
                    in _v168_main_bytes
                )

                _v168_compact_needle = (
                    _v168_re.sub(
                        rb'[\x09-\x0d\x20]+',
                        b'',
                        _v168_needle,
                    )
                )
                _v168_compact = (
                    bool(
                        _v168_compact_needle
                    )
                    and _v168_compact_needle
                    in _v168_main_compact
                )

                _v168_checks.append({
                    'id': (
                        _v168_record.get('id')
                    ),
                    'package_name': (
                        _v168_record.get(
                            'package_name'
                        )
                    ),
                    'signature_length': len(
                        _v168_needle
                    ),
                    'signature_prefix': (
                        _v168_signature[:16]
                    ),
                    'signature_suffix': (
                        _v168_signature[-16:]
                    ),
                    'direct_contains': (
                        _v168_direct
                    ),
                    'compact_contains': (
                        _v168_compact
                    ),
                })

                if _v168_direct:
                    _v168_hit = dict(
                        _v168_record
                    )
                    _v168_hit_mode = (
                        'direct_contains'
                    )
                    break

                if _v168_compact:
                    _v168_hit = dict(
                        _v168_record
                    )
                    _v168_hit_mode = (
                        'whitespace_compact_contains'
                    )
                    break

            _v168_result_raw = str(
                os.environ.get(
                    'IAPT_WHITELIST_PACKAGE_SIGNATURES_RESULT_V168'
                )
                or _v168_probe.get(
                    'result_path'
                )
                or ''
            ).strip()

            _v168_diagnostic = {
                'version': 167,
                'blocked': (
                    _v168_hit
                    is not None
                ),
                'user_id': (
                    _v168_probe.get(
                        'user_id'
                    )
                ),
                'feature7': False,
                'package_filter': False,
                'main_file': str(
                    MUST_HAVE_MAIN
                ),
                'main_size': len(
                    _v168_main_bytes
                ),
                'main_compact_size': len(
                    _v168_main_compact
                ),
                'record_count': len(
                    _v168_records
                ),
                'match_mode': (
                    _v168_hit_mode
                ),
                'checks': (
                    _v168_checks
                ),
                'other_members_decrypted': 0,
            }

            if _v168_result_raw:
                try:
                    _v168_result_path = Path(
                        _v168_result_raw
                    )
                    _v168_result_path.parent.mkdir(
                        parents=True,
                        exist_ok=True,
                    )
                    _v168_tmp = (
                        _v168_result_path.with_name(
                            _v168_result_path.name
                            + '.tmp.'
                            + str(os.getpid())
                        )
                    )
                    _v168_tmp.write_text(
                        json.dumps(
                            _v168_diagnostic,
                            ensure_ascii=False,
                            indent=2,
                            default=str,
                        ) + '\n',
                        encoding='utf-8',
                    )
                    os.replace(
                        _v168_tmp,
                        _v168_result_path,
                    )
                except Exception as _v168_result_error:
                    print(
                        '[IAPT_WL_V168_RESULT_WRITE_WARN]',
                        repr(
                            _v168_result_error
                        ),
                        flush=True,
                    )

            if _v168_hit is not None:
                _v168_expire = str(
                    _v168_hit.get(
                        'expire_at'
                    )
                    or ''
                )
                _v168_package = str(
                    _v168_hit.get(
                        'package_name'
                    )
                    or ''
                )

                _v168_message = (
                    '这是白名单样本，'
                    '主文件包含当前包名的有效签名，'
                    '保护期内禁止解密'
                )
                if _v168_package:
                    _v168_message += (
                        '，记录包名 '
                        + _v168_package
                    )
                if _v168_expire:
                    _v168_message += (
                        '，到期 '
                        + _v168_expire
                    )
                else:
                    _v168_message += '，永久'

                _v168_message += (
                    '，主文件 '
                    + str(MUST_HAVE_MAIN)
                    + '，匹配方式 '
                    + _v168_hit_mode
                )

                # No decrypted output may be published after a hit.
                try:
                    for _v168_child in list(
                        args.outdir.iterdir()
                    ):
                        if (
                            _v168_child.name
                            == '.tmp'
                        ):
                            continue
                        if (
                            _v168_child.is_dir()
                            and not _v168_child.is_symlink()
                        ):
                            _v168_shutil.rmtree(
                                _v168_child
                            )
                        else:
                            _v168_child.unlink(
                                missing_ok=True
                            )
                except Exception as _v168_cleanup_error:
                    print(
                        '[IAPT_WL_V168_CLEAN_WARN]',
                        repr(
                            _v168_cleanup_error
                        ),
                        flush=True,
                    )

                try:
                    (
                        args.outdir
                        / '.tmp'
                        / 'container_plain.bin'
                    ).unlink(
                        missing_ok=True
                    )
                except Exception:
                    pass

                try:
                    _v168_durable_raw = str(
                        os.environ.get(
                            'IAPT_DURABLE_SHELL_DIR'
                        )
                        or ''
                    ).strip()
                    if _v168_durable_raw:
                        _v168_durable = Path(
                            _v168_durable_raw
                        )
                        (
                            _v168_durable
                            / 'container_plain.bin'
                        ).unlink(
                            missing_ok=True
                        )
                        (
                            _v168_durable
                            / 'reuse_session_v14.json'
                        ).unlink(
                            missing_ok=True
                        )
                except Exception:
                    pass

                if _v168_result_raw:
                    try:
                        _v168_result_path = Path(
                            _v168_result_raw
                        )
                        _v168_diagnostic.update({
                            'message': (
                                _v168_message
                            ),
                            'row_id': (
                                _v168_hit.get('id')
                            ),
                            'matched_package_name': (
                                _v168_package
                            ),
                            'final_sha256': (
                                _v168_hit.get(
                                    'final_sha256'
                                )
                            ),
                            'expire_at': (
                                _v168_expire
                            ),
                        })
                        _v168_tmp = (
                            _v168_result_path.with_name(
                                _v168_result_path.name
                                + '.tmp.'
                                + str(os.getpid())
                            )
                        )
                        _v168_tmp.write_text(
                            json.dumps(
                                _v168_diagnostic,
                                ensure_ascii=False,
                                indent=2,
                                default=str,
                            ) + '\n',
                            encoding='utf-8',
                        )
                        os.replace(
                            _v168_tmp,
                            _v168_result_path,
                        )
                    except Exception as _v168_result_error:
                        print(
                            '[IAPT_WL_V168_RESULT_WRITE_WARN]',
                            repr(
                                _v168_result_error
                            ),
                            flush=True,
                        )

                print(
                    '[IAPT_WL_V168_ACTIVE_SIGNATURE_BLOCK] '
                    + _v168_message,
                    flush=True,
                )
                raise SystemExit(93)

            print(
                '[IAPT_WL_V168_MAIN_MISS] '
                'main=%s size=%s active_signatures=%s'
                % (
                    MUST_HAVE_MAIN,
                    len(_v168_main_bytes),
                    len(_v168_records),
                ),
                flush=True,
            )

        except SystemExit:
            raise
        except Exception as _v168_probe_error:
            # Fail closed: a broken whitelist probe must not silently release
            # the rest of the encrypted members.
            print(
                '[IAPT_WL_V168_MAIN_PROBE_ERROR]',
                repr(_v168_probe_error),
                flush=True,
            )
            raise
    # IAPT_WHITELIST_PACKAGE_SIGNATURE_TOOL_V168_END
    # The exact key pair is now authoritative: the original member decryptor
    # successfully opened mian.iyu.  Emit a dedicated handoff record here rather
    # than hoping a later stdout parser sees a particular log line.
    _iapt_write_verified_dynamic_key_result(
        args.outdir, post_key, key_xor, trace,
        str(locals().get("cache_fingerprint") or ""),
    )
    t_mian_end = time.perf_counter()
    members: Dict[str, bytes] = {MUST_HAVE_MAIN: mian_plain}
    mian_out = args.outdir / MUST_HAVE_MAIN
    mian_out.parent.mkdir(parents=True, exist_ok=True)
    t_mian_write = time.perf_counter()
    mian_out.write_bytes(mian_plain)
    print(f"[+] entry verified: {MUST_HAVE_MAIN} {len(mian_plain)} bytes verify={(t_mian_end - t_mian_start) * 1000.0:.3f} ms write={ms_since(t_mian_write):.3f} ms -> {mian_out}")

    try:
        project_meta = decrypt_iapt_project_meta(container_plain, ctx, key_xor, hidden, fb_value, str(package), member_key_mode_s, args.apk)
        project_file_meta = _iapt_v91_write_project_member_to_outdir(container_plain, ctx, key_xor, hidden, fb_value, str(package), member_key_mode_s, args.outdir)
        if project_file_meta:
            _iapt_merge_project_meta(project_meta, project_file_meta)
        if project_meta:
            print("[IAPT_PROJECT_META_JSON] " + json.dumps(project_meta, ensure_ascii=False, sort_keys=True))
            brief = []
            for _k, _label in (("packer_id", "打包者id"), ("uuid", "uuid"), ("device_model", "设备型号"), ("build_time", "打包时间")):
                if project_meta.get(_k):
                    brief.append(_label + "=" + str(project_meta.get(_k)))
            print("[+] project meta  = " + ("; ".join(brief) if brief else "decrypted"))
    except Exception as e:
        print("[!] project meta skipped:", type(e).__name__, e)

    t_members_start = time.perf_counter()
    max_new_members = None
    if args.max_output_files:
        max_new_members = max(0, args.max_output_files - len(members))
    # When the caller limits output count, avoid scanning the whole native SO for
    # every possible member name.  Start from mian.iyu references and stop as soon
    # as the requested number of files is written.  Full/unlimited runs still scan
    # SO + mian for maximum recovery.
    _seed_blob = b"\n".join(
        name.encode("utf-8", "replace") for name in _APK_DISCOVERED_MEMBER_CANDIDATES[:256]
    )
    member_scan_blob = mian_plain if args.max_output_files else (so_data + b"\n" + mian_plain)
    if _seed_blob:
        member_scan_blob += b"\n" + _seed_blob
    defer_member_writes = (args.defer_member_writes == "on") or (args.defer_member_writes == "auto")
    if defer_member_writes:
        print("[+] member writes deferred until after fn-restore")
    more_members = decrypt_members_recursive(
        container_plain, ctx, key_xor, hidden, fb_value, member_scan_blob,
        args.outdir, find_names, skip_existing=set(members.keys()), threads=args.threads,
        member_key_mode=member_key_mode_s, only_manual=bool(find_names) and not args.find_recursive,
        max_new_members=max_new_members, verbose=args.verbose_members, scan_mode=args.member_name_scan,
        member_batch_size=args.member_batch_size,
        member_marker_mode=args.member_marker_mode, member_marker_wave_size=args.member_marker_wave_size,
        defer_writes=defer_member_writes,
    )
    members.update(more_members)
    members_time_ms = ms_since(t_members_start)
    print(f"[T] member decrypt phase  {members_time_ms:.3f} ms")
    t_restore_start = time.perf_counter()
    restore_stats = maybe_restore_numeric_function_names(
        args.apk, args.outdir, args.restore_fn_names,
        backup=args.restore_backup, member_sources=members, primary_dex=dex, threads=args.threads,
        dex_enum=bool(args.dex_enum), dex_enum_start=int(args.dex_enum_start), dex_enum_limit=int(args.dex_enum_limit),
        dex_enum_windows=int(args.dex_enum_windows), enum_workers=int(args.enum_workers or max(1, min(8, os.cpu_count() or 1))),
    )
    restore_time_ms = ms_since(t_restore_start)
    print(f"[T] fn-restore phase       {restore_time_ms:.3f} ms")
    deferred_write_ms = 0.0
    if defer_member_writes:
        t_deferred_write = time.perf_counter()
        wrote_deferred = 0
        for _name, _data in members.items():
            _p = args.outdir / safe_out_name(_name)
            if _p.exists():
                continue
            _p.parent.mkdir(parents=True, exist_ok=True)
            _p.write_bytes(_data)
            wrote_deferred += 1
        deferred_write_ms = ms_since(t_deferred_write)
        print(f"[T] deferred member write {deferred_write_ms:.3f} ms files={wrote_deferred}")
    print(f"[+] main entry decrypted OK: {MUST_HAVE_MAIN}")

    t_total_end = time.perf_counter()
    total_time = t_total_end - t_total_start
    load_time_ms = (t_load_end - t_load_start) * 1000.0
    key_time_ms = (t_key_end - t_key_start) * 1000.0
    total_time_ms = total_time * 1000.0
    total_bytes = len(container_plain) + sum(len(x) for x in members.values()) + int(restore_stats.get("restore_output_bytes_delta", 0) or 0)
    total_mb = total_bytes / 1024 / 1024
    avg_speed = total_mb / total_time if total_time > 0 else 0
    print("[+] slky cache:", ctx.cache_info())
    print("[+] marker cache size:", len(_MEMBER_MARKER_CACHE))
    print("[+] member key cache size:", len(_MEMBER_KEY_CACHE))
    print("[+] outer key cache size:", len(_OUTER_KEY_CACHE))
    print("[+] idbfj prep cache size:", len(_IDBFJ_PREP_CACHE))
    print("[+] filename scan cache size:", len(_FILE_NAME_SCAN_CACHE))
    print("[+] xor table cache size:", len(_XOR_TRANSLATE_CACHE))
    print("[+] timing summary:")
    print(f"    load/input      : {load_time_ms:.3f} ms")
    print(f"    key/cache       : {key_time_ms:.3f} ms")
    print(f"    member decrypt  : {members_time_ms:.3f} ms")
    print(f"    fn-restore      : {restore_time_ms:.3f} ms")
    if defer_member_writes:
        print(f"    deferred write  : {deferred_write_ms:.3f} ms")
    print(f"    script total    : {total_time_ms:.3f} ms")
    print(f"    output bytes    : {total_bytes}")
    print(f"    avg speed       : {avg_speed:.2f} MB/s")
    print("[+] done. members:", len(members))




# IAPT_V131_EXTRACT_GUARD_BEGIN
try:
    _IAPT_V131_ORIG_AUTO_EXTRACT_KEY_CANDIDATES_FROM_SO = auto_extract_key_candidates_from_so
    def auto_extract_key_candidates_from_so(so_data):
        if globals().get("IAPT_NO_DYNAMIC_KEY", False):
            raise RuntimeError("IAPT_V131 no-dynamic-key: SO key extraction disabled")
        return _IAPT_V131_ORIG_AUTO_EXTRACT_KEY_CANDIDATES_FROM_SO(so_data)
except Exception as _iapt_v131_wrap_e:
    print("[IAPT_V131] extract guard install warn:", _iapt_v131_wrap_e)
# IAPT_V131_EXTRACT_GUARD_END


# IAPT_SEPARATE_TASK_OUTPUT_V276_BEGIN
def _iapt_v276_find_cli_value(argv, name):
    prefix = name + "="
    for index, value in enumerate(list(argv)):
        if value == name and index + 1 < len(argv):
            return index + 1, argv[index + 1]
        if value.startswith(prefix):
            return index, value[len(prefix):]
    return None, None


def _iapt_v276_set_cli_value(argv, name, value):
    index, old = _iapt_v276_find_cli_value(argv, name)
    if index is None:
        argv.extend([name, str(value)])
        return

    if index > 0 and argv[index - 1] == name:
        argv[index] = str(value)
    else:
        argv[index] = name + "=" + str(value)


def _iapt_v276_internal_file(relative_path):
    relative_path = Path(relative_path)
    parts = [str(part) for part in relative_path.parts]
    lower_parts = [part.lower() for part in parts]
    name = relative_path.name.lower()

    if any(part.startswith(".") for part in parts):
        return True
    if name == ".project" or ".project" in lower_parts:
        return True

    exact_internal = {
        "container_plain.bin",
        "outer_cache.json",
        "static_outer_ir.json",
        "static_ir.json",
        "member_offset_cache.json",
        "fn_restore_cache.json",
        "server_key_pool.json",
        "decrypt_diag.json",
        "decrypt_diagnostics.json",
        "candidate_keys.json",
        "selected_keys.json",
        "project.meta",
        "project_metadata.json",
    }
    if name in exact_internal:
        return True

    internal_suffixes = (
        ".tmp",
        ".temp",
        ".part",
        ".partial",
        ".cache",
        ".lock",
        ".pyc",
        ".pyo",
    )
    if name.endswith(internal_suffixes):
        return True

    if (
        name.startswith("cache_")
        or name.startswith("tmp_")
        or name.startswith("debug_")
        or name.endswith("_cache.json")
        or name.endswith("_cache.bin")
    ):
        return True

    return False


def _iapt_v276_publish_final_files(work_root, public_root):
    import shutil

    work_root = Path(work_root).resolve()
    public_root = Path(public_root).resolve()
    publish_root = public_root.parent / (
        ".iapt-publish-" + public_root.name + "-" + str(os.getpid())
    )

    if publish_root.exists():
        shutil.rmtree(publish_root, ignore_errors=True)
    publish_root.mkdir(parents=True, exist_ok=True)

    published = []
    try:
        if work_root.exists():
            for current, directories, files in os.walk(str(work_root)):
                current_path = Path(current)
                directories[:] = [
                    item for item in directories
                    if not item.startswith(".")
                ]

                for filename in files:
                    source_file = current_path / filename
                    try:
                        relative = source_file.relative_to(work_root)
                    except Exception:
                        continue

                    if _iapt_v276_internal_file(relative):
                        continue

                    target = publish_root / relative
                    target.parent.mkdir(parents=True, exist_ok=True)

                    try:
                        os.replace(str(source_file), str(target))
                    except OSError:
                        shutil.copy2(str(source_file), str(target))
                        try:
                            source_file.unlink()
                        except Exception:
                            pass

                    published.append(relative.as_posix())

        public_root.mkdir(parents=True, exist_ok=True)

        for current, directories, files in os.walk(str(publish_root)):
            current_path = Path(current)
            relative_dir = current_path.relative_to(publish_root)
            destination_dir = public_root / relative_dir
            destination_dir.mkdir(parents=True, exist_ok=True)

            for filename in files:
                source_file = current_path / filename
                destination = destination_dir / filename
                os.replace(str(source_file), str(destination))

        for current, directories, files in os.walk(
            str(public_root), topdown=False
        ):
            current_path = Path(current)
            if current_path == public_root:
                continue
            try:
                if not any(current_path.iterdir()):
                    current_path.rmdir()
            except Exception:
                pass

        print(
            "[IAPT_V276] final output published: files=%d public=%s"
            % (len(published), public_root),
            flush=True,
        )
        return published
    finally:
        shutil.rmtree(publish_root, ignore_errors=True)


def _iapt_v276_run_main():
    import shutil

    _index, original_outdir_value = _iapt_v276_find_cli_value(
        sys.argv, "--outdir"
    )

    if not original_outdir_value:
        return main()

    public_root = Path(original_outdir_value).expanduser().resolve()
    work_root = public_root.parent / (
        ".iapt-work-" + public_root.name + "-" + str(os.getpid())
    )

    shutil.rmtree(work_root, ignore_errors=True)
    work_root.mkdir(parents=True, exist_ok=True)

    _iapt_v276_set_cli_value(sys.argv, "--outdir", str(work_root))

    print(
        "[IAPT_V276] isolated work dir: %s; public output: %s"
        % (work_root, public_root),
        flush=True,
    )

    succeeded = False
    try:
        result = main()
        succeeded = True
        _iapt_v276_publish_final_files(work_root, public_root)
        return result
    except SystemExit as exc:
        code = exc.code
        successful_exit = code is None or code == 0
        if successful_exit:
            succeeded = True
            _iapt_v276_publish_final_files(work_root, public_root)
        raise
    finally:
        shutil.rmtree(work_root, ignore_errors=True)
        if not succeeded:
            print(
                "[IAPT_V276] task failed/cancelled; isolated work dir removed",
                flush=True,
            )
# IAPT_SEPARATE_TASK_OUTPUT_V276_END

# IAPT_PACKED_DYNAMIC_RUNTIME_V282_BEGIN
try:
    from .iapt_packed_dynamic_v282 import (
        container_variants as _iapt_v282_container_variants,
        extract_pair_from_so_bytes as _iapt_v282_extract_pair_from_so_bytes,
    )
    from .iapt_obfuscated_apk_probe_v1 import (
        locate_container as _iapt_v282_locate_container,
    )
except (ImportError, ValueError):
    _iapt_v282_tool_dir = str(Path(__file__).resolve().parent)
    if _iapt_v282_tool_dir not in sys.path:
        sys.path.insert(0, _iapt_v282_tool_dir)
    from iapt_packed_dynamic_v282 import (
        container_variants as _iapt_v282_container_variants,
        extract_pair_from_so_bytes as _iapt_v282_extract_pair_from_so_bytes,
    )
    from iapt_obfuscated_apk_probe_v1 import (
        locate_container as _iapt_v282_locate_container,
    )

_iapt_v282_legacy_auto_extract = auto_extract_key_candidates_from_so

def auto_extract_key_candidates_from_so(so_data: bytes):
    try:
        _post, _xor, _meta = _iapt_v282_extract_pair_from_so_bytes(so_data)
        print(
            "[IAPT_V282] packed symbol dataflow pair recovered: "
            "post=%d xor=%d post_strategy=%s xor_strategy=%s"
            % (
                len(_post), len(_xor),
                _meta.get("post_strategy"),
                _meta.get("xor_strategy"),
            ),
            flush=True,
        )
        return [_post], [_xor]
    except Exception as _packed_error:
        print(
            "[IAPT_V282] packed symbol parser fallback: %s: %s"
            % (type(_packed_error).__name__, _packed_error),
            flush=True,
        )
        return _iapt_v282_legacy_auto_extract(so_data)

if "_iapt_v275_extract_pair_bytes" in globals():
    _iapt_v282_v275_extract_original = globals()["_iapt_v275_extract_pair_bytes"]
    def _iapt_v282_v275_extract_pair_bytes(so_data: bytes):
        try:
            return _iapt_v282_extract_pair_from_so_bytes(so_data)
        except Exception:
            return _iapt_v282_v275_extract_original(so_data)
    globals()["_iapt_v275_extract_pair_bytes"] = _iapt_v282_v275_extract_pair_bytes

_iapt_v282_outer_resolve_original = OuterResolver.resolve

def _iapt_v282_outer_resolve(self, *args, **kwargs):
    _original_container = self.container
    _variants = _iapt_v282_container_variants(_original_container)
    if not _variants:
        return _iapt_v282_outer_resolve_original(self, *args, **kwargs)
    try:
        for _label, _candidate in _variants:
            self.container = _candidate
            try:
                _result = _iapt_v282_outer_resolve_original(self, *args, **kwargs)
            except Exception as _variant_error:
                print(
                    "[IAPT_V282] container variant error %s: %s: %s"
                    % (_label, type(_variant_error).__name__, _variant_error),
                    flush=True,
                )
                continue
            if _result:
                try:
                    _result[2]["container_variant"] = _label.encode("ascii", "replace")
                except Exception:
                    pass
                if _label != "raw":
                    print(
                        "[IAPT_V282] QiuShui container envelope verified: %s"
                        % _label,
                        flush=True,
                    )
                return _result
        return None
    finally:
        self.container = _original_container

OuterResolver.resolve = _iapt_v282_outer_resolve

_iapt_v282_verify_key_pair_original = verify_key_pair

def verify_key_pair(
    post_key: bytes,
    key_xor: bytes,
    hidden: bytes,
    container: bytes,
    package: str,
    version_name: str,
    version_code,
    app_label: str,
    fb_value,
    use_c: bool = False,
    c_path: str = "./libiapp_core.so",
    diag=None,
    tag: str = "",
):
    for _label, _candidate in _iapt_v282_container_variants(container):
        _result = _iapt_v282_verify_key_pair_original(
            post_key, key_xor, hidden, _candidate,
            package, version_name, version_code, app_label, fb_value,
            use_c=use_c, c_path=c_path, diag=diag, tag=tag,
        )
        if _result:
            try:
                _result[2]["container_variant"] = _label.encode("ascii", "replace")
            except Exception:
                pass
            return _result
    return None
# IAPT_PACKED_DYNAMIC_RUNTIME_V282_END

# Main entry is intentionally deferred until all late patch blocks below are loaded.
# IAPT_DYNAMIC_KEY_DECRYPT_DATAFLOW_V275_MODULE_BEGIN
# IAPT_DYNAMIC_KEY_DATAFLOW_IMPORT_V2751_BEGIN
try:
    # 作为 app.tools 包模块启动时使用。
    from .iapt_static_key_v41 import (
        extract_pair_bytes as _iapt_v275_extract_pair_bytes,
    )
except (ImportError, ValueError):
    # Worker 当前是直接执行 app/tools/iapp_auto_decrypt.py。
    # 此时没有父包，显式把当前脚本目录加入 sys.path。
    _iapt_v275_tool_dir = str(Path(__file__).resolve().parent)
    if _iapt_v275_tool_dir not in sys.path:
        sys.path.insert(0, _iapt_v275_tool_dir)
    from iapt_static_key_v41 import (
        extract_pair_bytes as _iapt_v275_extract_pair_bytes,
    )
# IAPT_DYNAMIC_KEY_DATAFLOW_IMPORT_V2751_END

# If v2.7.4 was installed, keep its pointer to the real legacy parser.
# Otherwise capture the parser that existed before this patch.
_iapt_v275_legacy_auto_extract = globals().get(
    "_iapt_v274_original_auto_extract",
    auto_extract_key_candidates_from_so,
)
_IAPT_V275_MULTIABI_CACHE = {}

# Keep the strict v3 parser, but accept it only when the legacy symbol/dataflow
# parser independently sees the same bytes.  v3's generic NUL/high-entropy
# fallback can otherwise mistake instruction streams, exception strings or
# literal-pool neighbours for a key (especially on NDK r28 multi-ABI builds).
_iapt_v275_strict_extract_pair_bytes = _iapt_v275_extract_pair_bytes

def _iapt_v275_legacy_primary_pair(so_blob: bytes):
    posts, xors = _iapt_v275_legacy_auto_extract(so_blob)
    posts = list(posts or [])
    xors = list(xors or [])
    if not posts or not xors:
        raise ValueError("legacy parser found no complete dynamic key pair")
    # A real slky/xor pair is normally constructed as two tables of the same
    # length.  Prefer that structural agreement before the legacy length rank;
    # the latter can rank a neighbouring 20-byte ASCII/literal tail above the
    # actual 16-byte table on AArch64.
    selected_post = selected_xor = None
    for xor_item in xors:
        same_length = [post_item for post_item in posts if len(post_item) == len(xor_item)]
        if same_length:
            selected_post = same_length[0]
            selected_xor = xor_item
            break
    if selected_post is None or selected_xor is None:
        try:
            primary_posts, primary_xors = _primary_so_key_candidates(posts, xors)
        except Exception:
            primary_posts, primary_xors = posts[:1], xors[:1]
        primary_posts = list(primary_posts or posts[:1])
        primary_xors = list(primary_xors or xors[:1])
        if not primary_posts or not primary_xors:
            raise ValueError("legacy parser found no primary dynamic key pair")
        selected_post, selected_xor = primary_posts[0], primary_xors[0]
    return (
        bytes(selected_post),
        bytes(selected_xor),
        [bytes(x) for x in posts if x],
        [bytes(x) for x in xors if x],
    )

def _iapt_v275_validated_extract_pair_bytes(so_blob: bytes):
    legacy_post, legacy_xor, legacy_posts, legacy_xors = _iapt_v275_legacy_primary_pair(so_blob)
    strict_error = None
    try:
        strict_post, strict_xor, strict_meta = _iapt_v275_strict_extract_pair_bytes(so_blob)
        if strict_post in legacy_posts and strict_xor in legacy_xors:
            meta = dict(strict_meta or {})
            meta["validation"] = "legacy-candidate-agreement"
            return strict_post, strict_xor, meta
        strict_error = (
            "strict pair disagrees with symbol parser: post=%s xor=%s"
            % (strict_post.hex(), strict_xor.hex())
        )
    except Exception as exc:
        strict_error = "%s: %s" % (type(exc).__name__, exc)

    try:
        elf = MiniELF(so_blob)
        machine = int(getattr(elf, "e_machine", 0) or 0)
        bits = int(getattr(elf, "bits", 0) or 0)
        arch = {3: "x86", 40: "armeabi-v7a", 62: "x86_64", 183: "arm64-v8a"}.get(machine, "unknown")
    except Exception:
        machine = bits = 0
        arch = "unknown"
    return legacy_post, legacy_xor, {
        "extractor_build": "multiabi-symbol-validated-v4",
        "status": "extracted-symbol-validated",
        "arch": arch,
        "machine": machine,
        "bits": bits,
        "post_key_bytes": len(legacy_post),
        "xor_key_bytes": len(legacy_xor),
        "post_candidate_count": len(set(legacy_posts)),
        "xor_candidate_count": len(set(legacy_xors)),
        "post_candidate_values": [legacy_post.hex()],
        "xor_candidate_values": [legacy_xor.hex()],
        "ambiguous": False,
        "strict_dataflow_rejected": strict_error or "unknown",
        "validation": "legacy-primary-fallback",
    }

_iapt_v275_extract_pair_bytes = _iapt_v275_validated_extract_pair_bytes


def _iapt_v275_so_signature(so_blob: bytes):
    raw = bytes(so_blob or b"")
    if not raw:
        return (0, b"")
    return (
        len(raw),
        hashlib.sha256(raw[:65536] + raw[-65536:]).digest(),
    )


def _iapt_v275_consensus_pair(extract_sources):
    unique_sources = []
    seen = set()
    for label, blob in list(extract_sources or []):
        sig = _iapt_v275_so_signature(blob)
        if sig in seen:
            continue
        seen.add(sig)
        unique_sources.append((str(label), bytes(blob or b"")))

    cache_key = tuple(_iapt_v275_so_signature(blob) for _label, blob in unique_sources)
    cached = _IAPT_V275_MULTIABI_CACHE.get(cache_key)
    if cached is not None:
        return cached

    successes = []
    errors = []
    for label, blob in unique_sources:
        try:
            post_key, xor_key, meta = _iapt_v275_extract_pair_bytes(blob)
            successes.append((label, post_key, xor_key, dict(meta or {})))
        except Exception as exc:
            errors.append("%s: %s: %s" % (label, type(exc).__name__, exc))

    if not successes:
        result = (None, tuple(errors))
        _IAPT_V275_MULTIABI_CACHE[cache_key] = result
        return result

    grouped = {}
    for label, post_key, xor_key, meta in successes:
        grouped.setdefault((post_key, xor_key), []).append((label, meta))

    if len(grouped) != 1:
        details = []
        for (post_key, xor_key), rows in grouped.items():
            details.append(
                "%s => post=%s xor=%s" % (
                    ",".join(label for label, _meta in rows),
                    post_key.hex(),
                    xor_key.hex(),
                )
            )
        raise RuntimeError(
            "multi-ABI dataflow key mismatch; refusing mixed keys: "
            + " | ".join(details)
        )

    (post_key, xor_key), rows = next(iter(grouped.items()))
    meta = {
        "extractor_build": "multiabi-dataflow-v3",
        "status": "extracted-dataflow",
        "consensus_count": len(rows),
        "consensus_labels": [label for label, _meta in rows],
        "successful_abis": [
            str((row_meta or {}).get("arch") or label)
            for label, row_meta in rows
        ],
        "post_key_bytes": len(post_key),
        "xor_key_bytes": len(xor_key),
    }
    result = ((post_key, xor_key, meta), tuple(errors))
    _IAPT_V275_MULTIABI_CACHE[cache_key] = result
    return result


def auto_extract_key_candidates_from_so(so_data: bytes):
    # Single-SO callers also receive the complete reconstructed pair.
    # Unsupported layouts retain the previous compatibility parser.
    try:
        post_key, xor_key, meta = _iapt_v275_extract_pair_bytes(so_data)
        print(
            "[IAPT_V275] complete SO dataflow pair: arch=%s post=%d xor=%d strategy=%s"
            % (
                meta.get("arch"),
                len(post_key),
                len(xor_key),
                meta.get("xor_strategy"),
            ),
            flush=True,
        )
        return [post_key], [xor_key]
    except Exception as exc:
        print(
            "[IAPT_V275] dataflow unsupported; legacy fallback: %s: %s"
            % (type(exc).__name__, exc),
            flush=True,
        )
        return _iapt_v275_legacy_auto_extract(so_data)
# IAPT_DYNAMIC_KEY_DECRYPT_DATAFLOW_V275_MODULE_END

# IAPT_DYNAMIC_KEY_CANDIDATE_FALLBACK_V1_BEGIN
# Restore the proven pre-dataflow behavior for decrypt tasks: collect every
# symbol/table candidate and let the outer-container verifier select the pair.
# The standalone key-pool/SO extraction route is intentionally untouched; it
# still calls _iapt_v275_validated_extract_pair_bytes directly.
_IAPT_DYNAMIC_KEY_CANDIDATE_EXTRACTOR = globals().get(
    '_IAPT_V131_ORIG_AUTO_EXTRACT_KEY_CANDIDATES_FROM_SO'
)
if not callable(_IAPT_DYNAMIC_KEY_CANDIDATE_EXTRACTOR):
    _IAPT_DYNAMIC_KEY_CANDIDATE_EXTRACTOR = globals().get(
        '_iapt_v282_legacy_auto_extract'
    )


def auto_extract_key_candidates_from_so(so_data: bytes):
    if globals().get('IAPT_NO_DYNAMIC_KEY', False):
        raise RuntimeError('IAPT no-dynamic-key: SO key extraction disabled')

    # QiuShui-protected AArch64 libraries must be unpacked and recovered from
    # the actual slky/burden1b symbol dataflow.  The generic legacy candidate
    # scanner sees only the packer stub and either returns no XOR table or
    # unrelated decoys.  Keep this branch new-iApp-only; old four-character
    # sokey projects never enter dynamic-key extraction.
    _packed_extractor = globals().get('_iapt_v282_extract_pair_from_so_bytes')
    if callable(_packed_extractor):
        try:
            _post, _xor, _meta = _packed_extractor(so_data)
            print(
                '[IAPT_V282] packed SO candidates: post=%d xor=%d strategy=%s/%s'
                % (
                    len(_post), len(_xor),
                    (_meta or {}).get('post_strategy'),
                    (_meta or {}).get('xor_strategy'),
                ),
                flush=True,
            )
            return [bytes(_post)], [bytes(_xor)]
        except Exception as _packed_exc:
            print(
                '[IAPT_V282] packed SO candidate parser skipped: %s: %s'
                % (type(_packed_exc).__name__, _packed_exc),
                flush=True,
            )

    if not callable(_IAPT_DYNAMIC_KEY_CANDIDATE_EXTRACTOR):
        raise RuntimeError('legacy dynamic-key candidate extractor unavailable')
    posts, xors = _IAPT_DYNAMIC_KEY_CANDIDATE_EXTRACTOR(so_data)
    posts = uniq_bytes_list([bytes(x) for x in (posts or []) if x])
    xors = uniq_bytes_list([bytes(x) for x in (xors or []) if x])
    if not posts or not xors:
        raise RuntimeError('legacy dynamic-key candidate extractor returned no complete candidates')
    print(
        '[IAPT_CANDIDATE_FALLBACK] SO candidates: post=%d xor=%d'
        % (len(posts), len(xors)),
        flush=True,
    )
    return posts, xors


# The V275 fast block calls this helper before the candidate loop. Returning no
# authoritative pair makes it continue into the existing post×xor verification
# loop instead of aborting on a wrong single-pair guess or multi-ABI mismatch.
def _iapt_v275_consensus_pair(extract_sources):
    return None, ('candidate fallback enabled; authoritative single-pair shortcut disabled',)
# IAPT_DYNAMIC_KEY_CANDIDATE_FALLBACK_V1_END

# IAPT_V201_EXACT_FIRST_CANDIDATE_FALLBACK_BEGIN
# Standalone extraction uses the deterministic V200/V201 effective-C-string
# parser. V3 decrypt tries that exact pair first, then preserves every legacy
# structured candidate as a compatibility fallback verified by real decryption.
_IAPT_V201_CANDIDATE_BASE = auto_extract_key_candidates_from_so
_IAPT_V201_EXACT_MULTIABI_CACHE = {}


def _iapt_v201_exact_module():
    try:
        from app.tools.iapt_v10 import iapt_dynamic_key_exact_v201 as module
        return module
    except Exception:
        _here = str(Path(__file__).resolve().parent)
        if _here not in sys.path:
            sys.path.insert(0, _here)
        import iapt_dynamic_key_exact_v201 as module
        return module


def _iapt_v201_exact_extract_one(so_blob: bytes):
    module = _iapt_v201_exact_module()
    result = module.extract(sys.modules[__name__], bytes(so_blob or b''))
    selected = dict((result or {}).get('selected') or {})
    if str((result or {}).get('status') or '') != 'extracted' or not selected:
        raise ValueError(str((result or {}).get('diagnostic') or 'deterministic static parser unresolved'))
    post = bytes.fromhex(str(selected.get('post_key') or ''))
    xor = bytes.fromhex(str(selected.get('xor_key') or ''))
    if not post or not xor:
        raise ValueError('deterministic static parser returned an empty key')
    meta = {
        'extractor_build': str((result or {}).get('parser_build') or 'V201-server-effective-cstring-four-abi-static'),
        'status': 'extracted-exact-static',
        'arch': str((result or {}).get('arch') or 'unknown'),
        'post_key_bytes': len(post),
        'xor_key_bytes': len(xor),
        'source': str(selected.get('source') or 'effective-cstring-static-dataflow'),
    }
    return post, xor, meta


def _iapt_v275_consensus_pair(extract_sources):
    unique_sources = []
    seen = set()
    for label, blob in list(extract_sources or []):
        raw = bytes(blob or b'')
        sig = (len(raw), hashlib.sha256(raw[:65536] + raw[-65536:]).digest() if raw else b'')
        if sig in seen:
            continue
        seen.add(sig)
        unique_sources.append((str(label), raw))

    cache_key = tuple((label, len(raw), hashlib.sha256(raw).digest()) for label, raw in unique_sources)
    cached = _IAPT_V201_EXACT_MULTIABI_CACHE.get(cache_key)
    if cached is not None:
        return cached

    successes = []
    errors = []
    for label, raw in unique_sources:
        try:
            post, xor, meta = _iapt_v201_exact_extract_one(raw)
            successes.append((label, post, xor, meta))
        except Exception as exc:
            errors.append('%s: %s: %s' % (label, type(exc).__name__, exc))

    if not successes:
        result = (None, tuple(errors or ['V201 exact static parser returned no result']))
        _IAPT_V201_EXACT_MULTIABI_CACHE[cache_key] = result
        return result

    grouped = {}
    for label, post, xor, meta in successes:
        grouped.setdefault((post, xor), []).append((label, meta))
    if len(grouped) != 1:
        details = []
        for (post, xor), rows in grouped.items():
            details.append('%s=>post=%s/xor=%s' % (
                ','.join(label for label, _meta in rows), post.hex(), xor.hex()
            ))
        result = (None, tuple(errors + ['exact ABI mismatch; use candidate verifier: ' + ' | '.join(details)]))
        _IAPT_V201_EXACT_MULTIABI_CACHE[cache_key] = result
        return result

    (post, xor), rows = next(iter(grouped.items()))
    meta = {
        'extractor_build': 'V201-exact-first-candidate-fallback',
        'status': 'extracted-exact-static',
        'consensus_count': len(rows),
        'consensus_labels': [label for label, _meta in rows],
        'successful_abis': [str((_meta or {}).get('arch') or label) for label, _meta in rows],
        'post_key_bytes': len(post),
        'xor_key_bytes': len(xor),
    }
    result = ((post, xor, meta), tuple(errors))
    _IAPT_V201_EXACT_MULTIABI_CACHE[cache_key] = result
    return result


def auto_extract_key_candidates_from_so(so_data: bytes):
    if globals().get('IAPT_NO_DYNAMIC_KEY', False):
        raise RuntimeError('IAPT no-dynamic-key: SO key extraction disabled')
    exact_posts = []
    exact_xors = []
    try:
        post, xor, meta = _iapt_v201_exact_extract_one(so_data)
        exact_posts.append(post)
        exact_xors.append(xor)
        print('[IAPT_V201] exact static candidate: arch=%s post=%d xor=%d' % (
            meta.get('arch'), len(post), len(xor)
        ), flush=True)
    except Exception as exc:
        print('[IAPT_V201] exact static parser unresolved; candidate fallback continues: %s: %s' % (
            type(exc).__name__, exc
        ), flush=True)

    legacy_posts = []
    legacy_xors = []
    try:
        legacy_posts, legacy_xors = _IAPT_V201_CANDIDATE_BASE(so_data)
    except Exception as exc:
        if not exact_posts or not exact_xors:
            raise
        print('[IAPT_V201] legacy candidate parser unavailable after exact result: %s: %s' % (
            type(exc).__name__, exc
        ), flush=True)

    posts = uniq_bytes_list(exact_posts + [bytes(x) for x in (legacy_posts or []) if x])
    xors = uniq_bytes_list(exact_xors + [bytes(x) for x in (legacy_xors or []) if x])
    if not posts or not xors:
        raise RuntimeError('V201 exact and legacy candidate parsers returned no complete candidates')
    print('[IAPT_V201] candidate lists exact-first: post=%d xor=%d' % (len(posts), len(xors)), flush=True)
    return posts, xors
# IAPT_V201_EXACT_FIRST_CANDIDATE_FALLBACK_END

# Run only after every late compatibility/dataflow patch above has been defined.

if __name__ == "__main__":
    _iapt_v276_run_main()
