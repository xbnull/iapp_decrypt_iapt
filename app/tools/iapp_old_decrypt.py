#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Old-iApp project container decryptor.

This module is intentionally separate from the V3 post_key/key_xor pipeline.
Old projects use a four-character sokey and an ASCII-Base64 assets/lib.so.
No dynamic key is involved.
"""
from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import itertools
import json
import multiprocessing as mp
import os
import re
import shutil
import string
import subprocess
import tempfile
import time
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

OLD_HEADER_DELIMITER = b"=/eyVRDWJWJF4zIwoyZyZPfQ=="
OLD_SIGN_SALT = "mmpygs93"
OLD_START_SALT = "ysiapp"
OLD_END_SALT = "iapp"
TEXT_EXTENSIONS = (
    "iyu", "myu", "mjava", "ijava", "mlua", "ilua", "mjs", "ijs",
    "txt", "xml", "json", "html", "htm", "css", "js", "java", "lua",
)
_LEGACY_SOKEY_RE = re.compile(rb"^[A-Za-z0-9]{4}$")
_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/]*={0,2}$")
_NAME_EXT_PATTERN = "|".join(re.escape(x) for x in TEXT_EXTENSIONS)
_NAME_CANDIDATE_RE = re.compile(
    r"(?<![\w./\\-])([\w\- .()\u4e00-\u9fff]{1,120}\.(?:"
    + _NAME_EXT_PATTERN + r"))(?!\w)", re.I
)
try:
    from Crypto.Cipher import AES as _FAST_AES  # type: ignore
except Exception:
    _FAST_AES = None


class OldIappError(RuntimeError):
    pass


def md5_hex(value: str | bytes) -> str:
    if isinstance(value, str):
        value = value.encode("utf-8")
    return hashlib.md5(value).hexdigest()


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    if not data:
        raise OldIappError("AES plaintext is empty")
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
        raise OldIappError("invalid AES PKCS#5/7 padding")
    return data[:-n]


def _aes_cbc_decrypt(ciphertext: bytes, key_ascii: str, unpad: bool = True) -> bytes:
    """AES-CBC through a native backend, without re-importing it per member."""
    key = key_ascii.encode("ascii")
    if len(key) != 16:
        raise OldIappError("old-iApp AES key must be 16 ASCII bytes")
    if not ciphertext or len(ciphertext) % 16:
        raise OldIappError("old-iApp AES ciphertext is not block aligned")
    if _FAST_AES is not None:
        plain = _FAST_AES.new(key, _FAST_AES.MODE_CBC, key).decrypt(ciphertext)
    else:
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
            dec = Cipher(algorithms.AES(key), modes.CBC(key)).decryptor()
            plain = dec.update(ciphertext) + dec.finalize()
        except Exception as exc:
            raise OldIappError("AES backend unavailable; install pycryptodome or cryptography") from exc
    return pkcs7_unpad(plain) if unpad else plain


def _aes_padding_maybe_valid(ciphertext: bytes, key_ascii: str) -> bool:
    if len(ciphertext) < 16 or len(ciphertext) % 16:
        return False
    key = key_ascii.encode("ascii")
    try:
        if _FAST_AES is None:
            return bool(pkcs7_unpad(_aes_cbc_decrypt(ciphertext, key_ascii, unpad=False)))
        # CBC final block only: D(C_n) xor C_(n-1), or IV for one block.
        prev = ciphertext[-32:-16] if len(ciphertext) >= 32 else key
        dec = _FAST_AES.new(key, _FAST_AES.MODE_ECB).decrypt(ciphertext[-16:])
        last = bytes(a ^ b for a, b in zip(dec, prev))
        n = last[-1]
        return 1 <= n <= 16 and last[-n:] == bytes([n]) * n
    except Exception:
        return False



def _b64decode_loose(data: bytes) -> bytes:
    compact = re.sub(rb"\s+", b"", bytes(data or b""))
    compact = compact.rstrip(b"=")
    compact += b"=" * ((4 - (len(compact) % 4)) % 4)
    return base64.b64decode(compact, validate=False)

def normalize_base64_blob(data: bytes) -> bytes:
    compact = re.sub(rb"\s+", b"", bytes(data or b""))
    if not compact or len(compact) % 4 or not _BASE64_RE.fullmatch(compact):
        raise OldIappError("assets/lib.so is not old-iApp ASCII Base64")
    try:
        decoded = base64.b64decode(compact, validate=True)
    except binascii.Error as exc:
        raise OldIappError("assets/lib.so Base64 is invalid") from exc
    if not decoded or len(decoded) % 16:
        raise OldIappError("old-iApp outer ciphertext is not AES aligned")
    return decoded


def detect_old_iapp_apk(apk_path: Path | str) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    result: Dict[str, Any] = {"old_iapp": False, "reason": ""}
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            info = next((x for x in zf.infolist() if not x.is_dir() and x.filename.replace("\\", "/").lower() == "assets/lib.so"), None)
            if info is None:
                result["reason"] = "assets/lib.so missing"
                return result
            data = zf.read(info)
            decoded = normalize_base64_blob(data)
            result.update({
                "old_iapp": True,
                "reason": "base64-aes-container",
                "assets_lib_size": len(data),
                "decoded_size": len(decoded),
            })
            return result
    except Exception as exc:
        result["reason"] = f"{type(exc).__name__}: {exc}"
        return result


def _iter_nul_strings(data: bytes, min_len: int = 2, max_len: int = 160) -> Iterable[Tuple[int, bytes]]:
    start = 0
    n = len(data)
    while start < n:
        end = data.find(b"\x00", start)
        if end < 0:
            break
        size = end - start
        if min_len <= size <= max_len:
            value = data[start:end]
            if all(0x20 <= b <= 0x7E for b in value):
                yield start, value
        start = end + 1


def extract_legacy_sokey_from_so_bytes(data: bytes, label: str = "libygsiyu.so") -> Tuple[str, Dict[str, Any]]:
    strings = list(_iter_nul_strings(bytes(data)))
    candidates: List[Tuple[int, int, str, int]] = []
    for idx, (off, value) in enumerate(strings):
        if value.lower() != b"lib.so":
            continue
        # Observed old Aid_String::loadfilecode string order:
        #   <four-char sokey>, "aa", "lib.so".
        for back in range(1, 9):
            j = idx - back
            if j < 0:
                break
            cand_off, cand = strings[j]
            if off - cand_off > 256:
                break
            if not _LEGACY_SOKEY_RE.fullmatch(cand):
                continue
            text = cand.decode("ascii")
            if text.lower() in {"iapp", "true", "null", "main", "utf8", "java", "html"}:
                continue
            score = 100 - back * 4
            if j + 1 < len(strings) and strings[j + 1][1] == b"aa":
                score += 60
            nearby = data[max(0, cand_off - 8192): min(len(data), off + 8192)]
            if b"versionName" in nearby and b"versionCode" in nearby:
                score += 20
            candidates.append((score, cand_off, text, off))
    if not candidates:
        raise OldIappError(f"{label}: no four-character old-iApp sokey near lib.so")
    candidates.sort(key=lambda row: (-row[0], row[1], row[2]))
    best = candidates[0]
    tied = {row[2] for row in candidates if row[0] == best[0]}
    if len(tied) > 1:
        raise OldIappError(f"{label}: conflicting old-iApp sokey candidates: {sorted(tied)}")
    return best[2], {
        "family": "old-iapp-4char",
        "strategy": "nul-string-sequence-before-lib.so-v1",
        "offset": best[1],
        "lib_string_offset": best[3],
        "score": best[0],
        "label": label,
        "so_sha256": hashlib.sha256(data).hexdigest(),
    }


def _abi_from_name(name: str) -> str:
    parts = name.replace("\\", "/").lower().split("/")
    for part in parts:
        if part in ("arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64"):
            return part
    return "unknown"


def extract_legacy_sokey_from_apk(apk_path: Path | str) -> Tuple[str, Dict[str, Any]]:
    apk_path = Path(apk_path)
    rows: List[Tuple[str, str, Dict[str, Any]]] = []
    errors: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        infos = [x for x in zf.infolist() if not x.is_dir() and x.filename.replace("\\", "/").lower().endswith("/libygsiyu.so")]
        if not infos:
            infos = [x for x in zf.infolist() if not x.is_dir() and x.filename.replace("\\", "/").lower() == "libygsiyu.so"]
        for info in infos:
            try:
                value, meta = extract_legacy_sokey_from_so_bytes(zf.read(info), info.filename)
                rows.append((value, _abi_from_name(info.filename), meta))
            except Exception as exc:
                errors.append(f"{info.filename}: {type(exc).__name__}: {exc}")
    if not rows:
        raise OldIappError("legacy sokey extraction failed: " + " | ".join(errors))
    weights = {"arm64-v8a": 8, "armeabi-v7a": 8, "armeabi": 6, "x86": 4, "x86_64": 1, "unknown": 1}
    totals: Dict[str, int] = {}
    for value, abi, _ in rows:
        totals[value] = totals.get(value, 0) + weights.get(abi, 1)
    selected = sorted(totals, key=lambda x: (-totals[x], x))[0]
    mobile = {v for v, abi, _ in rows if abi in ("arm64-v8a", "armeabi-v7a", "armeabi")}
    if len(mobile) > 1:
        raise OldIappError("mobile ABI legacy sokey mismatch: " + ", ".join(sorted(mobile)))
    if mobile:
        selected = next(iter(mobile))
    return selected, {
        "family": "old-iapp-4char",
        "strategy": "multi-abi-mobile-consensus-v1",
        "sokey": selected,
        "candidates": [{"value": v, "abi": abi, **m} for v, abi, m in rows],
        "failed_entries": errors,
        "weighted_totals": totals,
    }



def _old_signature_required_from_apk(apk_path: Path) -> bool:
    """Return True when old-iApp extra_conf1g.xml says APK signature participates.

    Observed iApp rule is compatible with the Android client detector:
    missing assets/extra_conf1g.xml => no signature branch; empty file after
    removing BOM/NUL/whitespace => signature branch; non-empty text => skip.
    """
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            info = next((x for x in zf.infolist() if not x.is_dir() and x.filename.replace("\\", "/").lower() == "assets/extra_conf1g.xml"), None)
            if info is None:
                return False
            raw = zf.read(info)[:1024 * 1024]
    except Exception:
        return False
    try:
        text = raw.decode("utf-8", "ignore").replace("\ufeff", "").replace("\x00", "").strip()
    except Exception:
        text = bytes(raw or b"").replace(b"\x00", b"").strip().decode("utf-8", "ignore").strip()
    return len(text) == 0

def _old_signature_candidates(apk_path: Path, signature_mode: str, signature_bytes_hex: str = "") -> List[Tuple[str, Optional[bytes]]]:
    mode = str(signature_mode or "auto").strip().lower()
    required = _old_signature_required_from_apk(apk_path)
    if mode in ("verify", "server", "on", "true", "1"):
        return [("verify", _extract_signature_der(apk_path, signature_bytes_hex))]
    if mode == "skip" and not required and not str(signature_bytes_hex or "").strip():
        return [("skip", None)]
    # For ancient tasks, old clients historically sent signature_mode=skip even
    # when extra_conf1g.xml required the signing certificate.  Prefer the detected
    # branch, then keep the other branch as a cheap fallback for explicit dexkey.
    out: List[Tuple[str, Optional[bytes]]] = []
    if required or str(signature_bytes_hex or "").strip() or mode == "auto":
        try:
            out.append(("verify", _extract_signature_der(apk_path, signature_bytes_hex)))
        except Exception:
            if mode in ("verify", "server", "on", "true", "1"):
                raise
    out.append(("skip", None))
    seen = set()
    dedup: List[Tuple[str, Optional[bytes]]] = []
    for label, der in out:
        key = (label, hashlib.sha256(der or b"").hexdigest())
        if key in seen:
            continue
        seen.add(key)
        dedup.append((label, der))
    return dedup

def _extract_signature_der(apk_path: Path, signature_bytes_hex: str = "") -> bytes:
    if signature_bytes_hex:
        try:
            return bytes.fromhex(re.sub(r"\s+", "", signature_bytes_hex))
        except Exception as exc:
            raise OldIappError("signature_bytes_hex is invalid") from exc
    with zipfile.ZipFile(apk_path, "r") as zf:
        cert_infos = [
            x for x in zf.infolist() if not x.is_dir()
            and x.filename.replace("\\", "/").upper().startswith("META-INF/")
            and x.filename.upper().endswith((".RSA", ".DSA", ".EC", ".CER", ".CRT"))
        ]
        if not cert_infos:
            raise OldIappError("signature verification requested but no V1 certificate was uploaded")
        blob = zf.read(cert_infos[0])
    try:
        from cryptography.hazmat.primitives.serialization import Encoding
        from cryptography.hazmat.primitives.serialization.pkcs7 import load_der_pkcs7_certificates
        certs = load_der_pkcs7_certificates(blob)
        if certs:
            return certs[0].public_bytes(Encoding.DER)
    except Exception:
        pass
    # Direct DER certificate fallback.
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        cert = x509.load_der_x509_certificate(blob)
        return cert.public_bytes(Encoding.DER)
    except Exception as exc:
        raise OldIappError("could not parse APK signing certificate") from exc


def _apk_meta(apk_path: Path) -> Dict[str, str]:
    # Dependency-free parser first. This avoids loading the full V3 engine and
    # cuts ancient-task startup time and resident memory substantially.
    try:
        try:
            from .apk_meta_fast import read_apk_meta  # type: ignore
        except Exception:
            try:
                from iapt_v10.apk_meta_fast import read_apk_meta  # type: ignore
            except Exception:
                from apk_meta_fast import read_apk_meta  # type: ignore
        return read_apk_meta(apk_path)
    except Exception:
        pass
    try:
        try:
            from app.tools import iapp_auto_decrypt as tool  # type: ignore
        except Exception:
            import iapp_auto_decrypt as tool  # type: ignore
        with zipfile.ZipFile(apk_path, "r") as zf:
            names = set(zf.namelist())
            if "AndroidManifest.xml" not in names:
                raise OldIappError("APK misses AndroidManifest.xml")
            params = tool.parse_axml_manifest(zf.read("AndroidManifest.xml")) or {}
            label = params.get("appLabel")
            if label and str(label).startswith("@") and "resources.arsc" in names and hasattr(tool, "resolve_arsc_string_ref"):
                try:
                    label = tool.resolve_arsc_string_ref(zf.read("resources.arsc"), str(label)) or label
                except Exception:
                    pass
            return {
                "package_name": str(params.get("package") or ""),
                "version_name": str(params.get("versionName") or ""),
                "version_code": str(params.get("versionCode") or ""),
                "app_name": str(label or ""),
            }
    except OldIappError:
        raise
    except Exception as exc:
        raise OldIappError("APK metadata parser unavailable") from exc


def _password_key_candidates(raw: Optional[str]) -> List[Tuple[str, str]]:
    if raw is None or str(raw) == "":
        return [("empty", "")]
    text = str(raw)
    rows = [
        ("raw", text),
        ("md5", md5_hex(text)),
    ]
    # Preserve order while removing duplicates.
    out: List[Tuple[str, str]] = []
    seen = set()
    for label, value in rows:
        if value in seen:
            continue
        seen.add(value)
        out.append((label, value))
    return out


def derive_old_keys(
    app_name: str, version_name: str, package_name: str, version_code: str,
    sokey: str, dexkey: str | int, signature_der: Optional[bytes],
    password_key: str,
) -> Dict[str, str]:
    app_key = md5_hex(f"{app_name}{version_name}{package_name}{version_code}")
    cert_md5 = md5_hex(signature_der or b"") if signature_der is not None else ""
    sign_key = md5_hex(cert_md5 + OLD_SIGN_SALT + sokey) if signature_der is not None else "null"
    lib_key = md5_hex(f"{dexkey}{sokey}{app_key}{sign_key}{password_key}")[16:32]
    return {
        "app_key": app_key,
        "certificate_md5": cert_md5,
        "sign_key": sign_key,
        "password_key": password_key,
        "lib_key": lib_key,
    }


def _outer_is_valid(plain: bytes) -> bool:
    pos = plain.find(OLD_HEADER_DELIMITER)
    if pos <= 0:
        return False
    header = plain[:pos]
    if len(header) > 4 * 1024 * 1024:
        return False
    parts = header.split(b"/")
    if not (1 <= len(parts) <= 100000):
        return False
    try:
        for part in parts[: min(16, len(parts))]:
            value = _b64decode_loose(part)
            if not re.fullmatch(rb"[0-9a-f]{32}", value):
                return False
    except Exception:
        return False
    return True



_FAST_ENUM_C_SOURCE = r"""
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <stdatomic.h>
#include <openssl/md5.h>
#include <openssl/aes.h>

typedef struct {
    const unsigned char *ct;
    size_t ct_len;
    int mode; /* 1=dex, 2=sokey */
    long long start;
    long long stop;
    const char *alphabet;
    size_t alphabet_len;
    int fixed_dex;
    const char *fixed_sokey;
    const char *app_key;
    const char *fixed_sign_key;
    const char *cert_md5;
    int signature_enabled;
    const char *sign_salt;
    char **passwords;
    int pw_count;
    int thread_id;
    int thread_count;
    atomic_int *found;
    pthread_mutex_t *result_lock;
    long long *result_dex;
    char *result_sokey;
    int *result_pw;
    char *result_key;
} worker_ctx;

static void hex_md5(const unsigned char *data, size_t len, char out[33]) {
    unsigned char md[16];
    MD5(data, len, md);
    static const char *hx = "0123456789abcdef";
    for (int i = 0; i < 16; i++) {
        out[i * 2] = hx[md[i] >> 4];
        out[i * 2 + 1] = hx[md[i] & 15];
    }
    out[32] = 0;
}

static int outer_valid_quick(const unsigned char *plain, size_t n) {
    const unsigned char delim[] = "=/eyVRDWJWJF4zIwoyZyZPfQ==";
    const size_t dlen = sizeof(delim) - 1;
    size_t pos = (size_t)-1;
    size_t limit = n < 4194304 ? n : 4194304;
    for (size_t i = 1; i + dlen <= limit; i++) {
        if (memcmp(plain + i, delim, dlen) == 0) { pos = i; break; }
    }
    if (pos == (size_t)-1 || pos == 0) return 0;
    size_t begin = 0;
    int parts = 0;
    for (size_t i = 0; i <= pos; i++) {
        if (i == pos || plain[i] == '/') {
            size_t len = i - begin;
            if (len == 0 || len > 96) return 0;
            for (size_t j = begin; j < i; j++) {
                unsigned char c = plain[j];
                if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                      (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=')) return 0;
            }
            parts++;
            if (parts >= 4) return 1;
            begin = i + 1;
        }
    }
    return parts >= 1;
}

static void index_to_sokey(uint64_t index, const char *alphabet, size_t n, char out[5]) {
    for (int i = 3; i >= 0; i--) {
        out[i] = alphabet[index % n];
        index /= n;
    }
    out[4] = 0;
}

static int try_key(worker_ctx *ctx, long long dex, const char sokey[5], int pw_index,
                   unsigned char *plain_buf, char out_key[17]) {
    char sign_key[33] = {0};
    if (ctx->mode == 1) {
        snprintf(sign_key, sizeof(sign_key), "%s", ctx->fixed_sign_key ? ctx->fixed_sign_key : "");
    } else if (ctx->signature_enabled) {
        char sign_input[256];
        int n = snprintf(sign_input, sizeof(sign_input), "%s%s%s",
                         ctx->cert_md5 ? ctx->cert_md5 : "",
                         ctx->sign_salt ? ctx->sign_salt : "", sokey);
        if (n <= 0 || n >= (int)sizeof(sign_input)) return 0;
        hex_md5((const unsigned char*)sign_input, (size_t)n, sign_key);
    } else {
        /* Native old-iApp uses the literal string "null" when the
           certificate branch is disabled; an empty string produces the wrong key. */
        snprintf(sign_key, sizeof(sign_key), "%s", "null");
    }

    char input[4096];
    int input_len = snprintf(input, sizeof(input), "%lld%s%s%s%s", dex, sokey,
                             ctx->app_key ? ctx->app_key : "", sign_key,
                             ctx->passwords[pw_index] ? ctx->passwords[pw_index] : "");
    if (input_len <= 0 || input_len >= (int)sizeof(input)) return 0;
    char md[33];
    hex_md5((const unsigned char*)input, (size_t)input_len, md);
    unsigned char key[16];
    memcpy(key, md + 16, 16);
    AES_KEY aes_key;
    if (AES_set_decrypt_key(key, 128, &aes_key) != 0) return 0;

    unsigned char dec[16], last[16];
    AES_decrypt(ctx->ct + ctx->ct_len - 16, dec, &aes_key);
    const unsigned char *prev = ctx->ct_len >= 32 ? ctx->ct + ctx->ct_len - 32 : key;
    for (int i = 0; i < 16; i++) last[i] = dec[i] ^ prev[i];
    int pad = last[15];
    if (pad < 1 || pad > 16) return 0;
    for (int i = 0; i < pad; i++) if (last[15 - i] != pad) return 0;

    unsigned char iv[16];
    memcpy(iv, key, 16);
    AES_cbc_encrypt(ctx->ct, plain_buf, ctx->ct_len, &aes_key, iv, AES_DECRYPT);
    if (!outer_valid_quick(plain_buf, ctx->ct_len - (size_t)pad)) return 0;
    memcpy(out_key, md + 16, 16);
    out_key[16] = 0;
    return 1;
}

static void *worker_main(void *arg) {
    worker_ctx *ctx = (worker_ctx*)arg;
    unsigned char *plain = (unsigned char*)malloc(ctx->ct_len);
    if (!plain) return NULL;
    if (ctx->mode == 1) {
        for (long long dex = ctx->start + ctx->thread_id;
             dex < ctx->stop && !atomic_load(ctx->found);
             dex += ctx->thread_count) {
            for (int pi = 0; pi < ctx->pw_count && !atomic_load(ctx->found); pi++) {
                char key[17];
                if (try_key(ctx, dex, ctx->fixed_sokey, pi, plain, key)) {
                    int expected = 0;
                    if (atomic_compare_exchange_strong(ctx->found, &expected, 1)) {
                        pthread_mutex_lock(ctx->result_lock);
                        *ctx->result_dex = dex;
                        snprintf(ctx->result_sokey, 5, "%s", ctx->fixed_sokey);
                        *ctx->result_pw = pi;
                        snprintf(ctx->result_key, 17, "%s", key);
                        pthread_mutex_unlock(ctx->result_lock);
                    }
                    break;
                }
            }
        }
    } else {
        uint64_t total = 1;
        for (int i = 0; i < 4; i++) total *= (uint64_t)ctx->alphabet_len;
        for (uint64_t idx = (uint64_t)ctx->thread_id;
             idx < total && !atomic_load(ctx->found);
             idx += (uint64_t)ctx->thread_count) {
            char sokey[5];
            index_to_sokey(idx, ctx->alphabet, ctx->alphabet_len, sokey);
            for (int pi = 0; pi < ctx->pw_count && !atomic_load(ctx->found); pi++) {
                char key[17];
                if (try_key(ctx, ctx->fixed_dex, sokey, pi, plain, key)) {
                    int expected = 0;
                    if (atomic_compare_exchange_strong(ctx->found, &expected, 1)) {
                        pthread_mutex_lock(ctx->result_lock);
                        *ctx->result_dex = ctx->fixed_dex;
                        snprintf(ctx->result_sokey, 5, "%s", sokey);
                        *ctx->result_pw = pi;
                        snprintf(ctx->result_key, 17, "%s", key);
                        pthread_mutex_unlock(ctx->result_lock);
                    }
                    break;
                }
            }
        }
    }
    free(plain);
    return NULL;
}

static unsigned char *read_cipher(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long n = ftell(f);
    if (n <= 0 || (n % 16) != 0) { fclose(f); return NULL; }
    rewind(f);
    unsigned char *buf = (unsigned char*)malloc((size_t)n);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { free(buf); fclose(f); return NULL; }
    fclose(f);
    *out_len = (size_t)n;
    return buf;
}

int main(int argc, char **argv) {
    if (argc < 10) {
        fprintf(stderr, "usage: %s dex cipher threads start stop sokey app_key sign_key pw...\n"
                        "   or: %s sokey cipher threads alphabet dex app_key cert_md5 sign_enabled sign_salt pw...\n",
                argv[0], argv[0]);
        return 2;
    }
    int mode = strcmp(argv[1], "dex") == 0 ? 1 : (strcmp(argv[1], "sokey") == 0 ? 2 : 0);
    if (!mode) { fprintf(stderr, "bad mode\n"); return 2; }
    const char *cipher_path = argv[2];
    int threads = atoi(argv[3]);
    if (threads < 1) threads = 1;
    if (threads > 64) threads = 64;
    size_t ct_len = 0;
    unsigned char *ct = read_cipher(cipher_path, &ct_len);
    if (!ct) { fprintf(stderr, "cannot read cipher\n"); return 2; }

    worker_ctx base;
    memset(&base, 0, sizeof(base));
    base.ct = ct; base.ct_len = ct_len; base.mode = mode; base.thread_count = threads;
    int pw_arg = 0;
    if (mode == 1) {
        base.start = atoll(argv[4]); base.stop = atoll(argv[5]);
        base.fixed_sokey = argv[6]; base.app_key = argv[7]; base.fixed_sign_key = argv[8];
        pw_arg = 9;
        if (base.start < 0 || base.stop <= base.start || strlen(base.fixed_sokey) != 4) {
            fprintf(stderr, "bad dex arguments\n"); free(ct); return 2;
        }
    } else {
        base.alphabet = argv[4]; base.alphabet_len = strlen(base.alphabet);
        base.fixed_dex = atoi(argv[5]); base.app_key = argv[6]; base.cert_md5 = argv[7];
        base.signature_enabled = atoi(argv[8]) != 0; base.sign_salt = argv[9];
        pw_arg = 10;
        if (base.alphabet_len < 1 || base.alphabet_len > 80 || base.fixed_dex < 0) {
            fprintf(stderr, "bad sokey arguments\n"); free(ct); return 2;
        }
    }
    base.passwords = argv + pw_arg;
    base.pw_count = argc - pw_arg;
    if (base.pw_count < 1) { fprintf(stderr, "password candidate required\n"); free(ct); return 2; }

    atomic_int found;
    atomic_init(&found, 0);
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    long long result_dex = -1;
    char result_sokey[5] = {0};
    int result_pw = -1;
    char result_key[17] = {0};
    base.found = &found; base.result_lock = &lock; base.result_dex = &result_dex;
    base.result_sokey = result_sokey; base.result_pw = &result_pw; base.result_key = result_key;

    pthread_t *ids = (pthread_t*)calloc((size_t)threads, sizeof(pthread_t));
    worker_ctx *ctxs = (worker_ctx*)calloc((size_t)threads, sizeof(worker_ctx));
    if (!ids || !ctxs) { free(ids); free(ctxs); free(ct); return 2; }
    int created = 0;
    for (int i = 0; i < threads; i++) {
        ctxs[i] = base; ctxs[i].thread_id = i;
        if (pthread_create(&ids[i], NULL, worker_main, &ctxs[i]) == 0) created++;
        else break;
    }
    for (int i = 0; i < created; i++) pthread_join(ids[i], NULL);
    free(ids); free(ctxs); free(ct);
    if (atomic_load(&found)) {
        printf("FOUND mode=%s dex=%lld sokey=%s pw_index=%d key=%s threads=%d\n",
               mode == 1 ? "dex" : "sokey", result_dex, result_sokey, result_pw, result_key, threads);
        return 0;
    }
    puts("NOTFOUND");
    return 1;
}
"""

def _fast_enum_binary() -> Optional[Path]:
    if str(os.environ.get("IAPT_OLD_FAST_ENUM", "1")).strip().lower() in ("0", "false", "no", "off"):
        return None
    cc = shutil.which(os.environ.get("CC", "")) if os.environ.get("CC") else None
    if not cc:
        cc = shutil.which("gcc") or shutil.which("cc")
    if not cc:
        return None
    cache_dir = Path(os.environ.get("IAPT_OLD_FAST_ENUM_CACHE") or (Path(__file__).resolve().parent / "__pycache__"))
    try:
        cache_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        return None
    exe = cache_dir / "iapt_old_dex_enum_fast"
    marker = cache_dir / "iapt_old_dex_enum_fast.sha256"
    src_hash = hashlib.sha256(_FAST_ENUM_C_SOURCE.encode("utf-8")).hexdigest()
    if exe.is_file() and os.access(exe, os.X_OK):
        try:
            if marker.read_text(encoding="ascii", errors="ignore").strip() == src_hash:
                return exe
        except Exception:
            pass
    try:
        proc = subprocess.run(
            [cc, "-O3", "-pthread", "-x", "c", "-", "-o", str(exe), "-lcrypto"],
            input=_FAST_ENUM_C_SOURCE,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=45,
        )
        if proc.returncode != 0:
            return None
        try:
            exe.chmod(0o755)
        except Exception:
            pass
        marker.write_text(src_hash, encoding="ascii")
        return exe if exe.is_file() and os.access(exe, os.X_OK) else None
    except Exception:
        return None


def _old_enum_workers(value: int = 0) -> int:
    raw = value or os.environ.get("IAPT_OLD_ENUM_WORKERS") or os.environ.get("IAPT_ENUM_WORKERS") or 0
    try:
        workers = int(raw or 0)
    except Exception:
        workers = 0
    return max(1, min(64, workers or (os.cpu_count() or 1)))


def _run_fast_keysearch(args: List[str], ciphertext: bytes, timeout: int) -> Tuple[str, str]:
    exe = _fast_enum_binary()
    if exe is None:
        return "unavailable", ""
    tmp_name = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="iapt_old_cipher_", suffix=".bin", delete=False) as fp:
            fp.write(ciphertext)
            tmp_name = fp.name
        proc = subprocess.run(
            [str(exe)] + [tmp_name if x == "__CIPHER__" else x for x in args],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout,
        )
        output = (proc.stdout or "") + "\n" + (proc.stderr or "")
        if proc.returncode == 0 and "FOUND" in output:
            return "found", output
        if proc.returncode == 1 or "NOTFOUND" in output:
            return "notfound", output
        return "error", output
    except subprocess.TimeoutExpired:
        return "timeout", ""
    except Exception:
        return "error", ""
    finally:
        if tmp_name:
            try: os.unlink(tmp_name)
            except Exception: pass


def _try_fast_enumerate_dexkey(
    ciphertext: bytes, sokey: str, app_key: str, sign_key: str,
    password_keys: List[Tuple[str, str]], start: int, stop: int, workers: int,
) -> Tuple[str, Optional[Tuple[int, str, str, bytes]]]:
    pw_values = [str(v) for _, v in password_keys] or [""]
    workers = _old_enum_workers(workers)
    timeout = max(60, min(1800, int((int(stop) - int(start)) / max(1, workers * 180000)) + 60))
    status, output = _run_fast_keysearch(
        ["dex", "__CIPHER__", str(workers), str(int(start)), str(int(stop)),
         str(sokey), str(app_key), str(sign_key)] + pw_values,
        ciphertext, timeout,
    )
    if status == "found":
        m = re.search(r"FOUND\s+mode=dex\s+dex=(\d+)\s+sokey=([A-Za-z0-9]{4})\s+pw_index=(\d+)\s+key=([0-9a-f]{16})", output)
        if not m: return "error", None
        dex, pw_index = int(m.group(1)), int(m.group(3))
        if pw_index < 0 or pw_index >= len(password_keys): return "error", None
        pw_label, pw = password_keys[pw_index]
        lib_key = md5_hex(f"{dex}{sokey}{app_key}{sign_key}{pw}")[16:32]
        outer = _aes_cbc_decrypt(ciphertext, lib_key)
        return ("found", (dex, pw_label, lib_key, outer)) if _outer_is_valid(outer) else ("error", None)
    return status, None


def _try_fast_enumerate_sokey(
    ciphertext: bytes, dexkey: int, app_key: str, signature_der: Optional[bytes],
    password_keys: List[Tuple[str, str]], alphabet: str, workers: int,
) -> Tuple[str, Optional[Tuple[str, str, str, bytes]]]:
    alphabet = "".join(dict.fromkeys(str(alphabet or "")))
    if not alphabet or len(alphabet) > 80:
        raise OldIappError("invalid old sokey alphabet")
    workers = _old_enum_workers(workers)
    cert_md5 = md5_hex(signature_der or b"") if signature_der is not None else ""
    pw_values = [str(v) for _, v in password_keys] or [""]
    total = len(alphabet) ** 4
    timeout = max(60, min(1800, int(total / max(1, workers * 120000)) + 60))
    status, output = _run_fast_keysearch(
        ["sokey", "__CIPHER__", str(workers), alphabet, str(int(dexkey)), str(app_key),
         cert_md5, "1" if signature_der is not None else "0", OLD_SIGN_SALT] + pw_values,
        ciphertext, timeout,
    )
    if status == "found":
        m = re.search(r"FOUND\s+mode=sokey\s+dex=(\d+)\s+sokey=([A-Za-z0-9]{4})\s+pw_index=(\d+)\s+key=([0-9a-f]{16})", output)
        if not m: return "error", None
        sokey, pw_index = m.group(2), int(m.group(3))
        if pw_index < 0 or pw_index >= len(password_keys): return "error", None
        pw_label, pw = password_keys[pw_index]
        keys = derive_old_keys("", "", "", "", sokey, dexkey, signature_der, pw)
        # derive_old_keys cannot reuse a precomputed app_key when metadata strings are unavailable.
        sign_key = md5_hex(cert_md5 + OLD_SIGN_SALT + sokey) if signature_der is not None else "null"
        lib_key = md5_hex(f"{dexkey}{sokey}{app_key}{sign_key}{pw}")[16:32]
        outer = _aes_cbc_decrypt(ciphertext, lib_key)
        return ("found", (sokey, pw_label, lib_key, outer)) if _outer_is_valid(outer) else ("error", None)
    return status, None

_ENUM_STATE: Dict[str, Any] = {}


def _enum_init(ciphertext: bytes, sokey: str, app_key: str, sign_key: str, password_keys: List[Tuple[str, str]]) -> None:
    _ENUM_STATE.clear()
    _ENUM_STATE.update({
        "ciphertext": ciphertext,
        "sokey": sokey,
        "app_key": app_key,
        "sign_key": sign_key,
        "password_keys": password_keys,
    })


def _enum_chunk(bounds: Tuple[int, int]) -> Optional[Tuple[int, str, str, bytes]]:
    start, stop = bounds
    ct = _ENUM_STATE["ciphertext"]
    sokey = _ENUM_STATE["sokey"]
    app_key = _ENUM_STATE["app_key"]
    sign_key = _ENUM_STATE["sign_key"]
    pws = _ENUM_STATE["password_keys"]
    for dex in range(start, stop):
        for pw_label, pw in pws:
            lib_key = md5_hex(f"{dex}{sokey}{app_key}{sign_key}{pw}")[16:32]
            if not _aes_padding_maybe_valid(ct, lib_key):
                continue
            try:
                plain = _aes_cbc_decrypt(ct, lib_key)
            except Exception:
                continue
            if _outer_is_valid(plain):
                return dex, pw_label, lib_key, plain
    return None


def enumerate_dexkey(
    ciphertext: bytes, sokey: str, app_key: str, sign_key: str,
    password_keys: List[Tuple[str, str]], start: int = 3_100_000,
    stop: int = 10_000_000, workers: int = 0, chunk_size: int = 20_000,
) -> Tuple[int, str, str, bytes]:
    start, stop = int(start), int(stop)
    if start < 0 or stop <= start:
        raise OldIappError("invalid old dexkey enumeration range")
    workers = _old_enum_workers(workers)
    fast_status, fast_hit = _try_fast_enumerate_dexkey(ciphertext, sokey, app_key, sign_key, password_keys, start, stop, workers)
    if fast_status == "found" and fast_hit is not None:
        return fast_hit
    if fast_status == "notfound":
        raise OldIappError("old dexkey enumeration exhausted without a valid container")
    # IAPT_V130_NO_PY_FALLBACK_GUARD
    if str(os.environ.get("IAPT_OLD_NO_PYTHON_FALLBACK", "0")).strip().lower() in ("1", "true", "yes", "on"):
        raise OldIappError("old dexkey C enumeration unavailable/failed/timeout; no_python_fallback is enabled; status=" + str(fast_status))
    chunk_size = max(1000, int(chunk_size or 20000))
    chunks = [(x, min(stop, x + chunk_size)) for x in range(start, stop, chunk_size)]
    if workers <= 1 or len(chunks) <= 1:
        _enum_init(ciphertext, sokey, app_key, sign_key, password_keys)
        for bounds in chunks:
            hit = _enum_chunk(bounds)
            if hit:
                return hit
        raise OldIappError("old dexkey enumeration exhausted without a valid container")
    ctx = mp.get_context("fork" if hasattr(os, "fork") else "spawn")
    pool = ctx.Pool(
        processes=workers,
        initializer=_enum_init,
        initargs=(ciphertext, sokey, app_key, sign_key, password_keys),
    )
    try:
        for hit in pool.imap_unordered(_enum_chunk, chunks, chunksize=1):
            if hit:
                pool.terminate()
                return hit
    finally:
        pool.close()
        pool.join()
    raise OldIappError("old dexkey enumeration exhausted without a valid container")


def _sokey_enum_candidates(alphabet: str = string.ascii_letters + string.digits) -> Iterable[str]:
    alphabet = "".join(dict.fromkeys(alphabet))
    if not alphabet or len(alphabet) > 80:
        raise OldIappError("invalid old sokey alphabet")
    for chars in itertools.product(alphabet, repeat=4):
        yield "".join(chars)


def _read_outer_cipher(apk_path: Path) -> Tuple[bytes, bytes]:
    with zipfile.ZipFile(apk_path, "r") as zf:
        info = next((x for x in zf.infolist() if not x.is_dir() and x.filename.replace("\\", "/").lower() == "assets/lib.so"), None)
        if info is None:
            raise OldIappError("old-iApp APK misses assets/lib.so")
        raw = zf.read(info)
    return raw, normalize_base64_blob(raw)


def _safe_filename(name: str) -> Optional[str]:
    name = name.replace("\\", "/").strip().lstrip("/")
    if not name or "\x00" in name:
        return None
    parts = [x for x in name.split("/") if x not in ("", ".")]
    if any(x == ".." for x in parts):
        return None
    if len(name) > 240:
        return None
    return "/".join(parts)


_V3_FILENAME_PARSER = None


def _load_v3_filename_parser():
    """Use the sibling normal-V3 member-reference parser verbatim.

    iapp_old_decrypt.py is executed from both app/tools and app/tools/iapt_v10.
    Relative import selects the matching V3 engine in either location; direct
    script execution falls back to the same-directory module.
    """
    global _V3_FILENAME_PARSER
    if _V3_FILENAME_PARSER is not None:
        return _V3_FILENAME_PARSER
    try:
        from .iapp_auto_decrypt import extract_file_names_from_blob
    except Exception:
        from iapp_auto_decrypt import extract_file_names_from_blob
    _V3_FILENAME_PARSER = extract_file_names_from_blob
    return _V3_FILENAME_PARSER


def _extract_name_candidates_from_bytes(data: bytes) -> List[str]:
    out: List[str] = []
    seen = set()

    # Exact same parser as normal V3.  This resolves, among others:
    # call(null,"mjava","set1.set",activity,1) -> set1.mjava
    # call(null,"mlua","a.b",activity,1)       -> a.mlua
    try:
        parser = _load_v3_filename_parser()
        for raw in sorted(parser(bytes(data or b""), scan_mode="hybrid") or ()):
            value = _safe_filename(str(raw or ""))
            if value and value not in seen:
                seen.add(value)
                out.append(value)
    except Exception:
        # Keep old decryption usable if a future V3 module cannot be imported.
        pass

    # Supplemental legacy matcher for names with spaces/parentheses that the
    # strict V3 grammar intentionally excludes.
    text = data.decode("utf-8", "ignore")
    for m in _NAME_CANDIDATE_RE.finditer(text):
        value = _safe_filename(m.group(1))
        if value and value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _standard_names() -> List[str]:
    # Common old-iApp member names plus names recovered from the supported
    # WebCat 5.21 sample.  The container stores only MD5(sokey+"ysiapp"+name),
    # so a broad deterministic dictionary materially improves exact naming.
    return [
        "mian.iyu", "main.iyu", "home.iyu", "loading.iyu", "menu.iyu",
        "import.mjs", "import.mlua", "import.myu", "main.myu", "mian.myu",
        "about.iyu", "setting.iyu", "login.iyu", "register.iyu", "index.iyu",
        "tool.mjava", "tool.mlua", "tool.myu", "shared.mjava", "aes.mjava",
        "encrypt.mjava", "a.mjava",
        "alert.iyu", "announce.iyu", "bookmarklist.iyu", "bookmarkutw.iyu",
        "cmd.mjava", "colorutil.myu", "complement.myu", "daoru.iyu",
        "daorulist.iyu", "darkcolor.myu", "doc.mjava", "edit.myu",
        "edithome.iyu", "editor.iyu", "editpage.iyu", "edittabtitle.iyu",
        "filelist.iyu", "filerename.iyu", "fileutil.myu", "frameadmin.iyu",
        "framelist.iyu", "gramlist.iyu", "grammar.myu", "image_png.iyu",
        "imagetool.mjava", "left.iyu", "menu.myu", "music_mp3.iyu",
        "newfile.iyu", "newproject.iyu", "outweb.mjava", "pact.iyu",
        "projectlist.iyu", "projectrename.iyu", "shell.mjava",
        "showwebcode.iyu", "sort.mlua", "source.myu", "space.iyu",
        "spacedetail.iyu", "tagcode.iyu", "tool_chinaz.iyu",
        "tool_getcode.iyu", "tool_getip.iyu", "tool_getport.iyu",
        "tools.iyu", "toolslist.iyu", "tsvs.iyu", "upload.iyu",
        "uploadlist.iyu", "uri.mjava", "utw.iyu", "utwuploadlist.iyu",
        "versionupdate.iyu", "visu.myu", "visu_editor_attr.iyu",
        "visu_editor_htmlcode.iyu", "visu_editor_jscode.iyu",
        "visu_item.iyu", "visu_layout_head.iyu", "visu_layout_in.iyu",
        "vpn.myu", "web.iyu", "webcat.myu", "webutil.mjava",
    ]


def _collect_apk_name_candidates(apk_path: Path, explicit: Sequence[str]) -> List[str]:
    rows: List[str] = list(explicit) + _standard_names()
    # Compiled res/*.xml files are binary resources and were the dominant old
    # hot path. Source filenames live in libygsiyu.so, DEX strings, or small
    # plain assets, so scan only those and cap aggregate reads.
    scanned_bytes = 0
    scan_limit = 48 * 1024 * 1024
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or info.file_size < 0 or info.file_size > 24 * 1024 * 1024:
                    continue
                low = info.filename.replace("\\", "/").lower()
                likely_native = low.endswith("libygsiyu.so")
                likely_dex = low.endswith(".dex")
                likely_text_asset = low.startswith("assets/") and low.endswith((".xml", ".txt", ".json", ".js")) and info.file_size <= 2 * 1024 * 1024
                if not (likely_native or likely_dex or likely_text_asset):
                    continue
                if scanned_bytes + int(info.file_size) > scan_limit:
                    continue
                try:
                    data = zf.read(info)
                    scanned_bytes += len(data)
                    rows.extend(_extract_name_candidates_from_bytes(data))
                except Exception:
                    pass
    except Exception:
        pass
    out: List[str] = []
    seen = set()
    for raw in rows:
        value = _safe_filename(str(raw))
        if value and value.lower() not in seen:
            seen.add(value.lower())
            out.append(value)
    return out


def _parse_find(options: Dict[str, Any]) -> List[str]:
    raw = options.get("find") or options.get("search_filename") or options.get("search_filenames") or []
    if isinstance(raw, str):
        raw = re.split(r"[,;\n\r]+", raw)
    if not isinstance(raw, (list, tuple)):
        raw = [raw]
    out = []
    for item in raw:
        value = _safe_filename(str(item or "").strip())
        if value and value not in out:
            out.append(value)
    return out



def _main_file_case_variants(name: str) -> List[str]:
    value = _safe_filename(str(name or ""))
    if not value:
        value = "mian.iyu"
    p = Path(value)
    stem = p.stem
    suf = p.suffix
    candidates = [
        value,
        value.lower(),
        value.upper(),
        stem + suf.lower(),
        stem.lower() + suf.lower(),
        stem.upper() + suf.lower(),
        stem[:1].upper() + stem[1:] + suf.lower() if stem else value,
        stem[:1].lower() + stem[1:] + suf.lower() if stem else value,
    ]
    out: List[str] = []
    seen = set()
    for c in candidates:
        c = _safe_filename(c)
        k = c.lower()
        if c and k not in seen:
            seen.add(k); out.append(c)
    return out

def _parse_main_file(options: Dict[str, Any]) -> str:
    raw = str(options.get("main_file") or "mian.iyu").strip()
    value = _safe_filename(raw)
    if not value or not re.fullmatch(r"[A-Za-z0-9_./\-\u0080-\uffff]+\.(?:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)", value, re.I):
        raise OldIappError("invalid ancient-scheme main_file; example: mian.iyu or main.iyu")
    return value


def decrypt_members(
    outer: bytes, sokey: str, apk_path: Path, out_dir: Path,
    find_names: Sequence[str] = (), find_only: bool = False, main_file: str = "mian.iyu",
) -> Dict[str, Any]:
    delimiter_pos = outer.find(OLD_HEADER_DELIMITER)
    if delimiter_pos <= 0:
        raise OldIappError("old-iApp member header delimiter not found")
    header = outer[:delimiter_pos]
    try:
        name_hashes = [_b64decode_loose(x).decode("ascii") for x in header.split(b"/")]
    except Exception as exc:
        raise OldIappError("old-iApp member-name hash header is invalid") from exc
    if any(not re.fullmatch(r"[0-9a-f]{32}", x) for x in name_hashes):
        raise OldIappError("old-iApp member-name hash header contains invalid values")

    explicit = list(find_names)
    requested_main_file = _safe_filename(main_file) or "mian.iyu"
    main_file = requested_main_file
    main_hash = md5_hex(sokey + OLD_START_SALT + main_file)
    if main_hash not in name_hashes:
        for candidate in _main_file_case_variants(requested_main_file):
            cand_hash = md5_hex(sokey + OLD_START_SALT + candidate)
            if cand_hash in name_hashes:
                main_file = candidate
                main_hash = cand_hash
                break
        else:
            raise OldIappError(f"custom main file not found in ancient container: {requested_main_file}")
    name_candidates = _collect_apk_name_candidates(apk_path, [main_file, requested_main_file] + explicit)
    hash_to_name: Dict[str, str] = {}
    for name in name_candidates:
        value = md5_hex(sokey + OLD_START_SALT + name)
        if value in name_hashes and value not in hash_to_name:
            hash_to_name[value] = name

    member_rows: List[Dict[str, Any]] = []
    member_plain: Dict[int, bytes] = {}
    search_hashes = {md5_hex(sokey + OLD_START_SALT + x): x for x in explicit}
    marker_cursor = delimiter_pos + len(OLD_HEADER_DELIMITER)
    for index, name_hash in enumerate(name_hashes):
        if find_only and explicit and name_hash not in search_hashes:
            continue
        start_raw = md5_hex(f"{sokey}{OLD_START_SALT}{index}")
        end_raw = md5_hex(f"{sokey}{OLD_END_SALT}{index}")
        start_marker = base64.b64encode(start_raw.encode("ascii"))
        end_marker = base64.b64encode(end_raw.encode("ascii"))
        start = outer.find(start_marker, marker_cursor)
        if start < 0:
            # Compatibility fallback for unusual containers whose markers are not ordered.
            start = outer.find(start_marker, delimiter_pos)
        if start < 0:
            raise OldIappError(f"start marker missing for member {index}")
        data_start = start + len(start_marker)
        end = outer.find(end_marker, data_start)
        if end < 0:
            raise OldIappError(f"end marker missing for member {index}")
        marker_cursor = end + len(end_marker)
        try:
            member_ct = _b64decode_loose(outer[data_start:end])
        except Exception as exc:
            raise OldIappError(f"member {index} Base64 is invalid") from exc
        member_key = md5_hex(sokey + start_raw + name_hash)[16:32]
        plain = _aes_cbc_decrypt(member_ct, member_key)
        member_plain[index] = plain
        member_rows.append({
            "index": index,
            "name_hash": name_hash,
            "member_key": member_key,
            "marker_start": start,
            "marker_end": end,
            "cipher_size": len(member_ct),
            "plain_size": len(plain),
            "sha256": hashlib.sha256(plain).hexdigest(),
        })

    # Decrypted source references often reveal names omitted from SO strings.
    for plain in member_plain.values():
        for name in _extract_name_candidates_from_bytes(plain):
            value = md5_hex(sokey + OLD_START_SALT + name)
            if value in name_hashes and value not in hash_to_name:
                hash_to_name[value] = name

    src = out_dir / "src"
    unknown = src / "_unknown"
    src.mkdir(parents=True, exist_ok=True)
    unknown.mkdir(parents=True, exist_ok=True)
    written = 0
    total = 0
    for row in member_rows:
        index = int(row["index"])
        name_hash = str(row["name_hash"])
        plain = member_plain[index]
        resolved = hash_to_name.get(name_hash) or search_hashes.get(name_hash)
        if resolved:
            rel = _safe_filename(resolved) or f"_unknown/{index:04d}_{name_hash}.bin"
            target = src / rel
            row["resolved_name"] = rel
        else:
            target = unknown / f"{index:04d}_{name_hash}.bin"
            row["resolved_name"] = ""
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists() and target.read_bytes() != plain:
            target = target.with_name(f"{target.stem}_{index}{target.suffix}")
        target.write_bytes(plain)
        row["output"] = str(target.relative_to(out_dir)).replace("\\", "/")
        written += 1
        total += len(plain)

    if explicit:
        missing = [x for x in explicit if md5_hex(sokey + OLD_START_SALT + x) not in name_hashes]
    else:
        missing = []

    # Project record is normally a comma-separated ASCII tail after the last marker.
    project_record = ""
    if member_rows:
        last_end = max(int(x["marker_end"]) for x in member_rows)
        tail = outer[last_end:last_end + 4096].decode("utf-8", "ignore")
        match = re.search(r"\d{1,12},[0-9a-fA-F]{8,64},[^,\r\n]{1,80},\d{10,20}", tail)
        if match:
            project_record = match.group(0)
            (src / "project_metadata.txt").write_text(project_record + "\n", encoding="utf-8")

    return {
        "member_count": len(name_hashes),
        "decrypted_count": len(member_rows),
        "written_count": written,
        "total_plain_bytes": total,
        "resolved_name_count": sum(1 for x in member_rows if x.get("resolved_name")),
        "unknown_name_count": sum(1 for x in member_rows if not x.get("resolved_name")),
        "main_file": main_file,
        "main_file_hash": main_hash,
        "main_file_index": name_hashes.index(main_hash),
        "find_names": list(explicit),
        "missing_find_names": missing,
        "project_record": project_record,
        "members": member_rows,
    }


def _old_truthy(value: Any) -> bool:
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in ("1", "true", "yes", "on", "y")


def _extract_old_dexkey_auto(apk_path: Path) -> Optional[int]:
    """Resolve the old f.b()/dexkey statically from the uploaded APK.

    This is the normal "dexkey parameter" path, not brute-force enumeration.
    The compact client uploads the target classes*.dex when its local parser
    cannot resolve the constant.  Both package and standalone imports are
    supported because the V10 ancient engine runs as an isolated script.
    """
    extractor = None
    try:
        from .iapp_auto_decrypt import extract_fb_from_apk_dexes as extractor  # type: ignore
    except Exception:
        try:
            from iapp_auto_decrypt import extract_fb_from_apk_dexes as extractor  # type: ignore
        except Exception:
            extractor = None
    if extractor is None:
        return None
    try:
        value = extractor(apk_path, None)
    except TypeError:
        value = extractor(apk_path)
    except Exception:
        return None
    if value is None:
        return None
    try:
        return int(value)
    except Exception:
        return None


def decrypt_old_iapp_apk(apk_path: Path | str, out_dir: Path | str, options: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    started = time.perf_counter()
    apk_path, out_dir = Path(apk_path), Path(out_dir)
    options = dict(options or {})
    out_dir.mkdir(parents=True, exist_ok=True)
    meta = _apk_meta(apk_path)
    app_name = str(options.get("app_name") or meta.get("app_name") or "")
    package_name = str(options.get("package_name") or meta.get("package_name") or "")
    version_name = str(options.get("version_name") or meta.get("version_name") or "")
    version_code = str(options.get("version_code") or meta.get("version_code") or "")
    if not all((app_name, package_name, version_name, version_code)):
        raise OldIappError(f"APK metadata incomplete: {meta}")

    raw_lib, ciphertext = _read_outer_cipher(apk_path)
    # Ancient sokey is exactly four alphanumeric characters.  Ignore modern
    # 10/32-byte hidden values instead of passing them into the old algorithm.
    explicit_sokey = ""
    for _key in ("old_sokey", "sokey", "hidden", "client_sokey"):
        _candidate = str(options.get(_key) or "").strip()
        if _LEGACY_SOKEY_RE.fullmatch(_candidate.encode("ascii", "ignore")):
            explicit_sokey = _candidate
            break
    server_sokey = _old_truthy(options.get("server_sokey"))
    sokey_enum = _old_truthy(options.get("sokey_enum"))
    if explicit_sokey:
        sokey_candidates = [("parameter", explicit_sokey)]
        sokey_meta: Dict[str, Any] = {"strategy": "parameter", "length": 4}
    elif sokey_enum:
        alphabet = str(options.get("old_sokey_alphabet") or (string.ascii_letters + string.digits))
        sokey_candidates = []
        sokey_meta = {"strategy": "c-multichannel-enumeration", "alphabet": alphabet, "workers": _old_enum_workers(int(options.get("enum_workers") or 0))}
    else:
        # Static extraction is the default ancient path.  It reads all
        # libygsiyu.so ABIs and uses mobile-ABI consensus, so an x86_64 decoy
        # cannot override the real four-character key.
        value, sokey_meta = extract_legacy_sokey_from_apk(apk_path)
        sokey_candidates = [("server-static-auto" if not server_sokey else "server-static", value)]

    signature_mode = str(options.get("signature_mode") or "auto").strip().lower()
    signature_candidates = _old_signature_candidates(apk_path, signature_mode, str(options.get("signature_bytes_hex") or ""))

    password_candidates = _password_key_candidates(options.get("user_password") if "user_password" in options else options.get("password"))
    explicit_dex = ""
    for _key in ("fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"):
        _candidate = str(options.get(_key) or "").strip()
        if _candidate:
            explicit_dex = _candidate
            break
    dex_enum = _old_truthy(options.get("dexkey_enum")) or _old_truthy(options.get("dex_enum"))
    dexkey_auto = (
        _old_truthy(options.get("dexkey_auto"))
        or _old_truthy(options.get("client_dexkey_auto"))
        or _old_truthy(options.get("client_fb_dex_fallback"))
    )
    auto_dex = None
    if not explicit_dex and not dex_enum and dexkey_auto:
        auto_dex = _extract_old_dexkey_auto(apk_path)
        if auto_dex is not None:
            explicit_dex = str(auto_dex)

    selected: Optional[Dict[str, Any]] = None
    last_error = ""
    for sig_label, signature_der in signature_candidates:
        app_key = md5_hex(f"{app_name}{version_name}{package_name}{version_code}")
        if sokey_enum:
            if not explicit_dex:
                if dex_enum:
                    # A blind 4-char × 7-million Cartesian search is not practical.
                    # Use the mobile-ABI static value as the bootstrap channel, then C-enumerate dexkey.
                    try:
                        bootstrap_sokey, bootstrap_meta = extract_legacy_sokey_from_apk(apk_path)
                        sokey_candidates = [("server-static-joint-bootstrap", bootstrap_sokey)]
                        sokey_meta["joint_bootstrap"] = bootstrap_meta
                    except Exception as exc:
                        last_error = "joint ancient enumeration requires one known key: " + str(exc)
                        continue
                else:
                    last_error = "sokey enumeration requires a dexkey parameter or APK-static dexkey"
                    continue
            else:
                dex_match = re.search(r"\d+", explicit_dex)
                if not dex_match:
                    last_error = "old dexkey parameter does not contain a number"
                    continue
                dex_value = int(dex_match.group(0))
                status, hit_sokey = _try_fast_enumerate_sokey(
                    ciphertext, dex_value, app_key, signature_der, password_candidates,
                    str(options.get("old_sokey_alphabet") or (string.ascii_letters + string.digits)),
                    int(options.get("enum_workers") or 0),
                )
                if status == "found" and hit_sokey is not None:
                    sokey, pw_label, lib_key, outer = hit_sokey
                    pw = next(value for label, value in password_candidates if label == pw_label)
                    keys = derive_old_keys(app_name, version_name, package_name, version_code, sokey, dex_value, signature_der, pw)
                    selected = {
                        "sokey": sokey, "sokey_source": "c-multichannel-enumeration",
                        "dexkey": dex_value, "dexkey_source": "apk-static-auto" if auto_dex is not None and dex_value == int(auto_dex) else "parameter",
                        "password_mode": pw_label, "password_key": pw, "lib_key": lib_key,
                        "outer": outer, "keys": keys, "signature_candidate": sig_label,
                    }
                    break
                last_error = f"sig={sig_label} C sokey enum: {status}"
                continue
        for sokey_source, sokey in sokey_candidates:
            cert_md5 = md5_hex(signature_der or b"") if signature_der is not None else ""
            sign_key = md5_hex(cert_md5 + OLD_SIGN_SALT + sokey) if signature_der is not None else "null"
            app_key = md5_hex(f"{app_name}{version_name}{package_name}{version_code}")
            try:
                if explicit_dex:
                    dex_match = re.search(r"\d+", explicit_dex)
                    if not dex_match:
                        raise OldIappError("old dexkey parameter does not contain a number")
                    dex_values = [int(dex_match.group(0))]
                    hit = None
                    for dex in dex_values:
                        for pw_label, pw in password_candidates:
                            keys = derive_old_keys(app_name, version_name, package_name, version_code, sokey, dex, signature_der, pw)
                            if not _aes_padding_maybe_valid(ciphertext, keys["lib_key"]):
                                continue
                            outer = _aes_cbc_decrypt(ciphertext, keys["lib_key"])
                            if _outer_is_valid(outer):
                                hit = (dex, pw_label, keys["lib_key"], outer, pw, keys)
                                break
                        if hit:
                            break
                    if not hit:
                        raise OldIappError("provided old dexkey/password did not decrypt the container")
                elif dex_enum:
                    start = int(options.get("dexkey_enum_start") or options.get("dex_enum_start") or 3_100_000)
                    stop = int(options.get("dexkey_enum_stop") or 10_000_000)
                    workers = int(options.get("enum_workers") or 0)
                    dex, pw_label, lib_key, outer = enumerate_dexkey(
                        ciphertext, sokey, app_key, sign_key, password_candidates,
                        start=start, stop=stop, workers=workers,
                        chunk_size=int(options.get("enum_chunk_size") or 20_000),
                    )
                    pw = next(value for label, value in password_candidates if label == pw_label)
                    keys = derive_old_keys(app_name, version_name, package_name, version_code, sokey, dex, signature_der, pw)
                    hit = (dex, pw_label, lib_key, outer, pw, keys)
                else:
                    raise OldIappError("old-iApp dexkey parameter is missing; provide dexkey or manually enable dexkey enumeration")
                dex, pw_label, lib_key, outer, pw, keys = hit
                selected = {
                    "sokey": sokey,
                    "sokey_source": sokey_source,
                    "dexkey": int(dex),
                    "dexkey_source": "apk-static-auto" if auto_dex is not None and int(dex) == int(auto_dex) else ("enumeration" if dex_enum else "parameter"),
                    "password_mode": pw_label,
                    "password_key": pw,
                    "lib_key": lib_key,
                    "outer": outer,
                    "keys": keys,
                    "signature_candidate": sig_label,
                }
                break
            except Exception as exc:
                last_error = f"sig={sig_label} sokey={sokey}: {type(exc).__name__}: {exc}"
                if not sokey_enum:
                    continue
                continue
        if selected is not None:
            break
    if selected is None:
        raise OldIappError("old-iApp key search failed: " + last_error)

    tmp = out_dir / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    outer = selected.pop("outer")
    (tmp / "old_outer_container.bin").write_bytes(outer)
    main_file = _parse_main_file(options)
    find_names = _parse_find(options)
    member_report = decrypt_members(
        outer, selected["sokey"], apk_path, out_dir,
        find_names=find_names,
        find_only=bool(find_names) and not bool(options.get("find_recursive")),
        main_file=main_file,
    )
    # V150: old/ancient-iApp may still use randomized numeric command tables.
    # Run the restore only when explicitly requested; normal fixed 145001→f tables are ignored by the mapping extractor.
    restore_mode = str(options.get("restore_fn_names") or "off").strip().lower()
    restore_enabled = (
        _old_truthy(options.get("ancient_dynamic_restore"))
        or _old_truthy(options.get("numeric_restore"))
        or _old_truthy(options.get("dynamic_restore"))
        or restore_mode in ("auto", "on", "true", "1")
    )
    if restore_enabled:
        try:
            try:
                from .iapp_auto_decrypt import maybe_restore_numeric_function_names
            except Exception:
                from iapp_auto_decrypt import maybe_restore_numeric_function_names  # type: ignore
            restore_stats = maybe_restore_numeric_function_names(
                apk_path,
                out_dir,
                mode="on" if restore_mode not in ("auto",) else "auto",
                backup=False,
                threads=max(1, int(options.get("threads") or 4)),
            )
            restore_stats["enabled"] = True
            restore_stats["engine"] = "ancient-randomized-numeric-command-table"
        except Exception as exc:
            restore_stats = {"enabled": True, "ok": False, "error": str(exc), "engine": "ancient-randomized-numeric-command-table"}
            raise
    else:
        restore_stats: Dict[str, Any] = {"enabled": False, "engine": "off"}
    report: Dict[str, Any] = {
        "ok": True,
        "family": "old-iapp-4char-v1",
        "algorithm": "Base64 -> AES/CBC/PKCS5 outer -> old member markers -> AES/CBC/PKCS5 members",
        "app_name": app_name,
        "package_name": package_name,
        "version_name": version_name,
        "version_code": version_code,
        "assets_lib_size": len(raw_lib),
        "outer_cipher_size": len(ciphertext),
        "outer_plain_size": len(outer),
        "signature_mode": "verify" if signature_der is not None else "skip",
        "sokey_metadata": sokey_meta,
        **{k: v for k, v in selected.items() if k != "keys"},
        **selected["keys"],
        **member_report,
        "dynamic_restore": restore_stats,
        "total_ms": (time.perf_counter() - started) * 1000.0,
    }
    report_path = out_dir / "old_iapp_report.json"
    report_path.write_text(json.dumps(report, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    text_lines = [
        "IAPT old-iApp decrypt report",
        f"app={app_name}", f"package={package_name}", f"version={version_name}/{version_code}",
        f"sokey={report['sokey']}", f"dexkey={report['dexkey']}",
        f"appKey={report['app_key']}", f"signKey={report['sign_key']}",
        f"passwordMode={report['password_mode']}", f"libKey={report['lib_key']}",
        f"mainFile={report['main_file']}",
        f"members={report['decrypted_count']}/{report['member_count']}",
        f"resolvedNames={report['resolved_name_count']}", f"unknownNames={report['unknown_name_count']}",
        f"totalMs={report['total_ms']:.2f}",
    ]
    (out_dir / "analysis_report.txt").write_text("\n".join(text_lines) + "\n", encoding="utf-8")
    return report


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Decrypt old four-character-sokey iApp projects")
    ap.add_argument("--apk", required=True, type=Path)
    ap.add_argument("--outdir", required=True, type=Path)
    ap.add_argument("--sokey")
    ap.add_argument("--dexkey")
    ap.add_argument("--dexkey-enum", action="store_true")
    ap.add_argument("--server-sokey", action="store_true")
    ap.add_argument("--signature-mode", choices=("skip", "verify"), default="skip")
    ap.add_argument("--signature-bytes-hex", default="")
    ap.add_argument("--password", default=None)
    ap.add_argument("--main-file", default="mian.iyu")
    ap.add_argument("--find", action="append", default=[])
    ap.add_argument("--find-recursive", action="store_true")
    ap.add_argument("--sokey-enum", action="store_true")
    ap.add_argument("--dexkey-enum-start", type=int, default=None)
    ap.add_argument("--dexkey-enum-stop", type=int, default=None)
    ap.add_argument("--enum-workers", type=int, default=None)
    ap.add_argument("--enum-chunk-size", type=int, default=None)
    ap.add_argument("--no-python-fallback", action="store_true")
    args = ap.parse_args(argv)
    options = {
        "legacy_iapp": True,
        "hidden": args.sokey or "",
        "fb": args.dexkey or "",
        "dexkey_enum": args.dexkey_enum,
        "dexkey_enum_start": getattr(args, "dexkey_enum_start", None),
        "dexkey_enum_stop": getattr(args, "dexkey_enum_stop", None),
        "enum_workers": getattr(args, "enum_workers", None),
        "enum_chunk_size": getattr(args, "enum_chunk_size", None),
        "no_python_fallback": getattr(args, "no_python_fallback", False),
        "server_sokey": args.server_sokey,
        "sokey_enum": getattr(args, "sokey_enum", False),
        "signature_mode": args.signature_mode,
        "signature_bytes_hex": args.signature_bytes_hex,
        "user_password": args.password,
        "main_file": args.main_file,
        "find": args.find,
        "find_recursive": args.find_recursive,
    }
    report = decrypt_old_iapp_apk(args.apk, args.outdir, options)
    summary = {k: report.get(k) for k in (
        "ok", "family", "app_name", "package_name", "sokey", "dexkey",
        "member_count", "decrypted_count", "written_count", "total_ms"
    )}
    print(json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

IAPT_OLD_ENGINE_V130 = True

IAPT_OLD_ENGINE_V133_SKIP_SIGNATURE_NULL = True
