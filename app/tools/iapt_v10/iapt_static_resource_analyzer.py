#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static resource-encryption analysis and restoration for protected iApp APKs.

This module is deliberately separate from the normal iApp container decryptor.
It never enumerates or changes client supplied hidden/f.b()/post/xor/signature
parameters.  Its only job is to recover the resource layer and produce either:

* a normalized APK containing the original resource tree and assets/lib.so; or
* the restored assets/lib.so by itself.

The analysis is two-stage:

1. Fast feature matching for fully specified, structurally verified formats.
2. A full native/DEX inventory when no feature handler matches.  The fallback
   records the resource consumer, referenced paths, primitive indicators and
   byte-operation evidence.  It executes only recipes that are proved by both
   code evidence and complete output validation; unsupported algorithms fail
   closed with a detailed report instead of starting parameter enumeration.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
if str(HERE) not in os.sys.path:
    os.sys.path.insert(0, str(HERE))

import iapt_hidden_resource_restore as low

ANALYZER_BUILD = "static-resource-analyzer-v2-feature-then-full-so"
_MAX_NATIVE_SIZE = 96 * 1024 * 1024
_MAX_DISASSEMBLY_BYTES = 24 * 1024 * 1024
_MAX_REPORT_STRINGS = 160
_MAX_RESOURCE_CANDIDATES = 24


class StaticResourceAnalysisError(RuntimeError):
    def __init__(self, message: str, report: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.report = dict(report or {})


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normal_name(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def _short_name(value: Any, limit: int = 220) -> str:
    text = _normal_name(value)
    if len(text) <= limit:
        return text
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return "<path length=%d depth=%d sha256=%s tail=%r>" % (
        len(text), text.count("/"), digest, text[-72:]
    )


def _truthy(options: Optional[Dict[str, Any]], key: str) -> bool:
    value = (options or {}).get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y"}


def _canonical_info(zf: zipfile.ZipFile) -> Optional[zipfile.ZipInfo]:
    for info in zf.infolist():
        if not info.is_dir() and _normal_name(info.filename).lower() == "assets/lib.so":
            if int(info.file_size or 0) >= 64:
                return info
    return None


def _copy_identity_apk(apk: Path, output: Path, options: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    if apk.resolve() != output.resolve():
        shutil.copy2(apk, output)
    with zipfile.ZipFile(output, "r") as zf:
        info = _canonical_info(zf)
        if info is None:
            raise StaticResourceAnalysisError("identity APK has no usable assets/lib.so")
        blob = zf.read(info)
    return {
        "normalized": True,
        "normalizer": "identity-canonical-container",
        "source_apk": apk.name,
        "normalized_apk": str(output),
        "normalized_apk_size": output.stat().st_size,
        "normalized_apk_sha256": _sha256_bytes(output.read_bytes()),
        "container_size": len(blob),
        "container_sha256": _sha256_bytes(blob),
        "lib_only": bool(_truthy(options, "no_decrypt_resource_files") or _truthy(options, "skip_anti_resources")),
        "ordinary_resources_restored": False,
        "resource_plan": {
            "strategy": "identity",
            "input": "assets/lib.so",
            "operations": [],
            "output": "assets/lib.so",
            "confidence": "certain",
        },
    }


def _extract_ascii_strings(data: bytes, min_len: int = 4, max_items: int = _MAX_REPORT_STRINGS) -> List[str]:
    rows: List[str] = []
    seen = set()
    for match in re.finditer(rb"[\x20-\x7e]{%d,}" % max(3, int(min_len)), data):
        text = match.group(0).decode("ascii", "replace")
        if text in seen:
            continue
        seen.add(text)
        rows.append(text[:512])
        if len(rows) >= max_items:
            break
    return rows


_CRYPTO_TOKENS: Tuple[Tuple[bytes, str], ...] = (
    (b"DES/ECB/PKCS5Padding", "DES/ECB/PKCS5Padding"),
    (b"DESede", "3DES"),
    (b"AES/CBC/PKCS5Padding", "AES/CBC/PKCS5Padding"),
    (b"AES/ECB/PKCS5Padding", "AES/ECB/PKCS5Padding"),
    (b"AES/GCM", "AES/GCM"),
    (b"ARC4", "RC4"),
    (b"RC4", "RC4"),
    (b"MessageDigest", "MessageDigest"),
    (b"Cipher", "Java-Cipher"),
    (b"inflate", "zlib/inflate"),
    (b"ZipInputStream", "ZIP"),
    (b"3LKs", "3LKs"),
    (b".ArmEpic", "ArmEpic-VM"),
    (b"QuiShui", "QuiShui"),
    (b"Tosks", "Tosks"),
    (b"dex_protection_xor_key", "EPIC-DEX-XOR"),
)

_RESOURCE_TOKENS: Tuple[bytes, ...] = (
    b"assets/lib.so", b"lib.so", b"AssetManager", b"AAssetManager",
    b"LuaStateFactory", b"com/iapp/app", b"getAssets", b"openFd",
)


def _classify_native(name: str, blob: bytes) -> str:
    low_name = _normal_name(name).lower()
    if b"dex_protection_xor_key" in blob and (b".Epic" in blob or b"Epic.vm" in blob):
        return "epic-dex-protector"
    if b".ArmEpic" in blob or b"QuiShui" in blob:
        return "qiushui-vm-protector"
    if b"Tosks" in blob:
        return "tosks-dex-protector"
    if b"lib.so" in blob and (b"LuaStateFactory" in blob or b"com/iapp/app" in blob):
        return "iapp-container-consumer"
    if any(token in low_name for token in ("protect", "shell", "guard", "jiagu", "epic", "lianyi", "ly", "xskm")):
        return "protector-or-helper"
    return "other-native"


def _run_tool(command: Sequence[str], timeout: int = 25) -> str:
    try:
        proc = subprocess.run(
            list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            check=False, timeout=timeout,
        )
    except Exception:
        return ""
    return proc.stdout.decode("utf-8", "replace")


def _disassembly_features(path: Path) -> Dict[str, Any]:
    tool = shutil.which("llvm-objdump") or shutil.which("objdump")
    if not tool or path.stat().st_size > _MAX_DISASSEMBLY_BYTES:
        return {"available": False, "reason": "tool-missing-or-file-too-large"}
    text = _run_tool([tool, "-d", "--no-show-raw-insn", str(path)], timeout=35).lower()
    if not text:
        return {"available": False, "reason": "disassembly-failed"}
    immediate_ops: Dict[str, List[int]] = {"xor": [], "add": [], "sub": [], "rol": [], "ror": []}
    patterns = {
        "xor": r"\b(?:eor|xor[a-z]*)\b[^\n]*(?:#|\$)(?:0x([0-9a-f]+)|([0-9]+))",
        "add": r"\badd[a-z]*\b[^\n]*(?:#|\$)(?:0x([0-9a-f]+)|([0-9]+))",
        "sub": r"\bsub[a-z]*\b[^\n]*(?:#|\$)(?:0x([0-9a-f]+)|([0-9]+))",
        "rol": r"\brol[a-z]*\b[^\n]*(?:#|\$)(?:0x([0-9a-f]+)|([0-9]+))",
        "ror": r"\bror[a-z]*\b[^\n]*(?:#|\$)(?:0x([0-9a-f]+)|([0-9]+))",
    }
    for kind, pattern in patterns.items():
        values = []
        for match in re.finditer(pattern, text):
            raw = match.group(1) or match.group(2)
            try:
                value = int(raw, 16 if match.group(1) else 10)
            except Exception:
                continue
            if 0 <= value <= 0xFF and value not in values:
                values.append(value)
            if len(values) >= 24:
                break
        immediate_ops[kind] = values
    return {
        "available": True,
        "instruction_lines": text.count("\n"),
        "immediate_byte_operations": immediate_ops,
        "rc4_shape": bool(
            ("0x100" in text or "$256" in text or "#256" in text)
            and (text.count("xor") + text.count("eor") >= 2)
            and (text.count("and") >= 2)
        ),
    }


def _native_inventory(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    infos = [
        info for info in zf.infolist()
        if not info.is_dir()
        and _normal_name(info.filename).lower().startswith("lib/")
        and _normal_name(info.filename).lower().endswith(".so")
        and 4096 <= int(info.file_size or 0) <= _MAX_NATIVE_SIZE
    ]
    rows: List[Dict[str, Any]] = []
    with tempfile.TemporaryDirectory(prefix="iapt-native-scan-") as tmp:
        root = Path(tmp)
        for index, info in enumerate(sorted(infos, key=lambda item: (item.file_size, item.filename))):
            try:
                blob = zf.read(info)
            except Exception:
                continue
            strings = _extract_ascii_strings(blob)
            crypto = sorted({label for token, label in _CRYPTO_TOKENS if token in blob})
            resource_tokens = [token.decode("ascii", "replace") for token in _RESOURCE_TOKENS if token in blob]
            path = root / ("%03d-%s" % (index, Path(_normal_name(info.filename)).name))
            try:
                path.write_bytes(blob)
                disasm = _disassembly_features(path)
            except Exception:
                disasm = {"available": False, "reason": "temporary-write-failed"}
            score = 0
            scope = _classify_native(info.filename, blob)
            if scope == "iapp-container-consumer":
                score += 100
            elif scope in {"qiushui-vm-protector", "tosks-dex-protector", "protector-or-helper"}:
                score += 40
            score += 10 * len(resource_tokens)
            score += 4 * len(crypto)
            rows.append({
                "entry": _normal_name(info.filename),
                "size": len(blob),
                "sha256": _sha256_bytes(blob),
                "scope": scope,
                "consumer_score": score,
                "resource_tokens": resource_tokens,
                "crypto_indicators": crypto,
                "interesting_strings": [
                    s for s in strings
                    if any(token in s.lower() for token in (
                        "asset", "lib.so", "3lks", "epic", "qiushui", "tosks",
                        "cipher", "aes", "des", "rc4", "zip", "lua", "iapp"
                    ))
                ][:_MAX_REPORT_STRINGS],
                "disassembly": disasm,
            })
    rows.sort(key=lambda row: (-int(row.get("consumer_score") or 0), row.get("entry") or ""))
    return rows


def _dex_inventory(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for info in zf.infolist():
        low_name = _normal_name(info.filename).lower()
        if info.is_dir() or not re.search(r"(?:^|/)classes\d*\.dex$", low_name):
            continue
        try:
            blob = zf.read(info)
        except Exception:
            continue
        strings = _extract_ascii_strings(blob, min_len=5, max_items=240)
        interesting = [
            s for s in strings
            if any(token in s.lower() for token in (
                "assets/", "lib.so", "3lks", "qiushui", "tosks", "epic",
                "cipher", "aes", "des", "rc4", "zipinputstream", "assetmanager"
            ))
        ]
        rows.append({
            "entry": _normal_name(info.filename),
            "size": len(blob),
            "sha256": _sha256_bytes(blob),
            "valid_dex_header": blob.startswith(b"dex\n"),
            "interesting_strings": interesting[:_MAX_REPORT_STRINGS],
        })
    return rows


def _resource_entry_candidates(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        name = _normal_name(info.filename)
        low_name = name.lower()
        if low_name.startswith("lib/") or low_name.startswith("meta-inf/"):
            continue
        size = int(info.file_size or 0)
        if size < 64 * 1024:
            continue
        score = 0
        if low_name == "assets/lib.so":
            score += 1000
        if low_name.startswith("assets/"):
            score += 20
        if len(name) >= 256:
            score += 60
        if name.count("/") >= 16:
            score += 45
        if sum(1 for ch in name if ord(ch) > 127) >= 16:
            score += 35
        if size >= 1024 * 1024:
            score += 20
        if size >= 4 * 1024 * 1024:
            score += 15
        if info.compress_size and float(info.compress_size) / max(1.0, float(size)) >= 0.80:
            score += 15
        if score:
            rows.append({
                "entry": _short_name(name),
                "entry_raw": name,
                "size": size,
                "compressed_size": int(info.compress_size or 0),
                "score": score,
                "block_aligned_8": size % 8 == 0,
                "block_aligned_16": size % 16 == 0,
            })
    rows.sort(key=lambda row: (-int(row["score"]), -int(row["size"]), row["entry_raw"]))
    return rows[:_MAX_RESOURCE_CANDIDATES]


def _cross_reference_resources(native_rows: List[Dict[str, Any]], resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    result: List[Dict[str, Any]] = []
    for resource in resources:
        raw_name = str(resource.get("entry_raw") or "")
        base = raw_name.rsplit("/", 1)[-1]
        refs = []
        for native in native_rows:
            strings = "\n".join(native.get("interesting_strings") or [])
            if raw_name and raw_name in strings:
                refs.append({"native": native["entry"], "match": "full-path"})
            elif base and len(base) >= 4 and base in strings:
                refs.append({"native": native["entry"], "match": "basename"})
            elif raw_name.lower() == "assets/lib.so" and "lib.so" in strings:
                refs.append({"native": native["entry"], "match": "canonical-name"})
        if refs:
            result.append({"resource": _short_name(raw_name), "references": refs})
    return result



def _zip_plaintext(blob: bytes) -> Optional[Tuple[bytes, Dict[str, Any]]]:
    """Return a fully validated resource ZIP, including nested 3LKs recovery."""
    data = bytes(blob or b"")
    offsets = [0]
    for magic in (b"PK\x03\x04", b"PK\x05\x06"):
        pos = data.find(magic, 1, min(len(data), 8192))
        if pos > 0:
            offsets.append(pos)
    failures = []
    for offset in sorted(set(offsets)):
        candidate = data[offset:]
        try:
            nested, nested_meta = low._restore_nested_3lks_zip(candidate)
            meta = low._inspect_inner_zip(nested)
            return nested, {"zip_offset": offset, **nested_meta, **meta}
        except Exception as exc:
            failures.append("%d:%s" % (offset, exc))
    return None


def _overlay_inner_zip(
    apk: Path,
    inner_bytes: bytes,
    output: Path,
    options: Optional[Dict[str, Any]],
    base_report: Dict[str, Any],
) -> Dict[str, Any]:
    """Overlay a statically recovered resource ZIP without executing APK code."""
    lib_only = bool(_truthy(options, "no_decrypt_resource_files") or _truthy(options, "skip_anti_resources"))
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk, "r") as outer, zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner:
        inner_infos = [x for x in inner.infolist() if not x.is_dir()]
        inner_names = {_normal_name(x.filename).lower() for x in inner_infos}
        written = set()
        with zipfile.ZipFile(output, "w", allowZip64=True) as out:
            def allow_inner(low_name: str) -> bool:
                if lib_only:
                    return (
                        low_name == "assets/lib.so"
                        or low_name.startswith("bsh/quishui/")
                        or low_name.startswith("bsh/util/lib/")
                        or (low_name.startswith("assets/libtosks") and low_name.endswith(".so"))
                        or low_name in {
                            "assets/extra_conf1g.xml",
                            "assets/userencryption.xml",
                            "assets/.jgapp",
                            "assets/jgapp",
                            "epic.vm",
                        }
                    )
                base = low_name.rsplit("/", 1)[-1]
                return not low_name.startswith("lib/") and not (base.startswith("classes") and base.endswith(".dex"))

            overlay_names = {x for x in inner_names if allow_inner(x)}
            for info in outer.infolist():
                if info.is_dir():
                    continue
                name = _normal_name(info.filename)
                low_name = name.lower()
                base = low_name.rsplit("/", 1)[-1]
                preserve_code = low_name.startswith("lib/") or (base.startswith("classes") and base.endswith(".dex"))
                if (low_name in overlay_names and not preserve_code) or low._drop_signature(name):
                    continue
                if (
                    lib_only
                    and low_name.startswith("assets/")
                    and low_name not in {
                        "assets/lib.so",
                        "assets/extra_conf1g.xml",
                        "assets/userencryption.xml",
                        "assets/.jgapp",
                        "assets/jgapp",
                    }
                    and not (low_name.startswith("assets/libtosks") and low_name.endswith(".so"))
                ):
                    continue
                if len(name) > 2048 or name.count("/") > 128 or not low._safe_zip_name(name) or low_name in written:
                    continue
                out.writestr(low._clone_zipinfo(info, name), outer.read(info))
                written.add(low_name)
            for info in inner_infos:
                name = _normal_name(info.filename)
                low_name = name.lower()
                if not allow_inner(low_name) or low._drop_signature(name) or not low._safe_zip_name(name) or low_name in written:
                    continue
                out.writestr(low._clone_zipinfo(info, name), inner.read(info))
                written.add(low_name)
            marker_info = zipfile.ZipInfo(low._MARKER_NAME, date_time=(1980, 1, 1, 0, 0, 0))
            marker_info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(marker_info, json.dumps(base_report, ensure_ascii=False, indent=2).encode("utf-8"))
    with zipfile.ZipFile(output, "r") as check:
        info = _canonical_info(check)
        if info is None:
            raise StaticResourceAnalysisError("native-derived resource ZIP has no assets/lib.so", base_report)
        lib_data = check.read(info)
        report = dict(base_report)
        report.update({
            "normalized": True,
            "normalizer": "full-native-static-recipe",
            "normalized_apk": str(output),
            "normalized_apk_size": output.stat().st_size,
            "normalized_apk_sha256": _sha256_bytes(output.read_bytes()),
            "normalized_entry_count": len(check.infolist()),
            "container_size": len(lib_data),
            "container_sha256": _sha256_bytes(lib_data),
            "lib_only": lib_only,
            "ordinary_resources_restored": not lib_only,
        })
        return report


def _rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty RC4 key")
    sbox = list(range(256))
    j = 0
    for i in range(256):
        j = (j + sbox[i] + key[i % len(key)]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
    i = j = 0
    out = bytearray(len(data))
    for pos, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + sbox[i]) & 0xFF
        sbox[i], sbox[j] = sbox[j], sbox[i]
        out[pos] = value ^ sbox[(sbox[i] + sbox[j]) & 0xFF]
    return bytes(out)


def _pkcs7_unpad_any(data: bytes, block_size: int) -> Optional[bytes]:
    if not data:
        return None
    n = data[-1]
    if 1 <= n <= block_size and data[-n:] == bytes([n]) * n:
        return data[:-n]
    return None


def _aes_decrypt(ciphertext: bytes, key: bytes, mode: str, iv: Optional[bytes] = None) -> Optional[bytes]:
    if len(key) not in (16, 24, 32) or len(ciphertext) % 16:
        return None
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        cipher_mode = modes.ECB() if mode == "ECB" else modes.CBC(bytes(iv or b""))
        decryptor = Cipher(algorithms.AES(key), cipher_mode).decryptor()
        plain = decryptor.update(ciphertext) + decryptor.finalize()
        return _pkcs7_unpad_any(plain, 16) or plain
    except Exception:
        return None


def _literal_material_near_tokens(blob: bytes, tokens: Sequence[bytes]) -> List[bytes]:
    """Extract bounded literal key candidates from the same SO as a primitive."""
    ranges: List[Tuple[int, int]] = []
    for token in tokens:
        start = 0
        while True:
            pos = blob.find(token, start)
            if pos < 0:
                break
            ranges.append((max(0, pos - 8192), min(len(blob), pos + len(token) + 8192)))
            start = pos + 1
            if len(ranges) >= 16:
                break
    if not ranges:
        return []
    found: List[bytes] = []
    seen = set()
    for left, right in ranges:
        chunk = blob[left:right]
        for match in re.finditer(rb"[\x20-\x7e]{8,64}", chunk):
            raw = match.group(0)
            values = [raw]
            text = raw.strip()
            if len(text) in (16, 32, 48, 64) and re.fullmatch(rb"[0-9A-Fa-f]+", text):
                try:
                    values.append(bytes.fromhex(text.decode("ascii")))
                except Exception:
                    pass
            for value in values:
                if len(value) not in (5, 8, 16, 24, 32) or value in seen:
                    continue
                if any(token in value for token in (b"Padding", b"Cipher", b"AES/", b"DES/", b"assets/")):
                    continue
                seen.add(value)
                found.append(value)
                if len(found) >= 48:
                    return found
    return found


def _consumer_native_blobs(zf: zipfile.ZipFile, native_rows: List[Dict[str, Any]]) -> List[Tuple[Dict[str, Any], bytes]]:
    by_name = {_normal_name(info.filename): info for info in zf.infolist() if not info.is_dir()}
    result = []
    for row in native_rows:
        if int(row.get("consumer_score") or 0) < 40:
            continue
        info = by_name.get(str(row.get("entry") or ""))
        if info is None:
            continue
        try:
            result.append((row, zf.read(info)))
        except Exception:
            continue
    return result


def _single_byte_transform_from_native(
    zf: zipfile.ZipFile,
    native_rows: List[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    """Prove one byte transform from consumer code plus complete control files."""
    immediate: Dict[str, set] = {"xor": set(), "add": set(), "sub": set(), "rol": set(), "ror": set()}
    for row in native_rows:
        if int(row.get("consumer_score") or 0) < 70:
            continue
        ops = ((row.get("disassembly") or {}).get("immediate_byte_operations") or {})
        for kind in immediate:
            immediate[kind].update(int(v) & 0xFF for v in ops.get(kind) or [])
    transforms = []
    transforms += [{"kind": "xor-repeat", "key": bytes([v])} for v in sorted(immediate["xor"]) if v]
    transforms += [{"kind": "add-byte", "value": (-v) & 0xFF} for v in sorted(immediate["add"]) if v]
    transforms += [{"kind": "add-byte", "value": v} for v in sorted(immediate["sub"]) if v]
    transforms += [{"kind": "ror-byte", "value": v & 7} for v in sorted(immediate["rol"]) if v & 7]
    transforms += [{"kind": "rol-byte", "value": v & 7} for v in sorted(immediate["ror"]) if v & 7]
    accepted = []
    controls = [
        info for info in zf.infolist()
        if not info.is_dir() and _normal_name(info.filename).lower() in low._STATIC_WRAPPER_CONTROL_NAMES
    ]
    for transform in transforms[:96]:
        proof = []
        for info in controls:
            raw = zf.read(info)
            before, _ = low._decoded_asset_quality(info.filename, raw)
            try:
                decoded = low._apply_static_transform(raw, transform)
            except Exception:
                continue
            after, reason = low._decoded_asset_quality(info.filename, decoded)
            if after >= 14 and after > before:
                proof.append({"entry": _normal_name(info.filename), "reason": reason, "quality": after})
        if proof:
            accepted.append((transform, proof))
    if len(accepted) != 1:
        return None
    transform, proof = accepted[0]
    return {
        "transform": transform,
        "score": 200 + sum(int(x["quality"]) for x in proof),
        "evidence": ["%s:%s" % (x["entry"], x["reason"]) for x in proof],
        "native_evidence": ["all-native-scan:consumer-immediate-operation"],
    }


def _attempt_literal_cipher_recovery(
    apk: Path,
    output: Path,
    zf: zipfile.ZipFile,
    full_report: Dict[str, Any],
    options: Optional[Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    native_rows = list(full_report.get("native_libraries") or [])
    consumers = _consumer_native_blobs(zf, native_rows)
    resources = _resource_entry_candidates(zf)[:8]
    if not consumers or not resources:
        return None

    # Canonical lib.so wrapper: constants must come from actual container
    # consumers and restore a complete iApp control file.
    if _canonical_info(zf) is not None:
        row = _single_byte_transform_from_native(zf, native_rows)
        if row is not None:
            report = low.build_static_wrapper_normalized_apk(apk, output, row, options)
            report.update({
                "analysis_phase": "full-native-scan",
                "analyzer_build": ANALYZER_BUILD,
                "resource_plan": {
                    "strategy": "native-proved-byte-transform",
                    "input": "assets/lib.so",
                    "operations": [report.get("transform")],
                    "evidence": report.get("evidence") or [],
                    "output": "assets/lib.so",
                    "confidence": "certain",
                },
                "native_scan_summary": {
                    "scanned_so_count": len(native_rows),
                    "primitive_indicators": full_report.get("primitive_indicators") or [],
                },
            })
            return report
        return None

    # Unknown hidden-resource format: try only literal keys located near an
    # explicitly indicated primitive in a likely resource-consumer SO.  Every
    # result must open as a complete resource ZIP containing assets/lib.so.
    by_name = {_normal_name(info.filename): info for info in zf.infolist() if not info.is_dir()}
    for native_row, native_blob in consumers:
        indicators = set(native_row.get("crypto_indicators") or [])
        token_list = [token for token, label in _CRYPTO_TOKENS if label in indicators]
        materials = _literal_material_near_tokens(native_blob, token_list)
        if not materials:
            continue
        for resource in resources:
            raw_name = str(resource.get("entry_raw") or "")
            info = by_name.get(raw_name)
            if info is None:
                continue
            ciphertext = zf.read(info)
            attempts: List[Tuple[str, bytes, Dict[str, Any]]] = []
            if "DES/ECB/PKCS5Padding" in indicators and len(ciphertext) % 8 == 0:
                for key in materials:
                    if len(key) != 8:
                        continue
                    try:
                        padded = low._des_ecb_decrypt(ciphertext, key)
                        plain = low._pkcs7_unpad(padded, 8)
                        attempts.append(("DES/ECB/PKCS5Padding", plain, {"key_sha256": _sha256_bytes(key)}))
                    except Exception:
                        continue
            if "AES/CBC/PKCS5Padding" in indicators and len(ciphertext) % 16 == 0:
                keys = [x for x in materials if len(x) in (16, 24, 32)]
                ivs = [x for x in materials if len(x) == 16]
                for key in keys[:16]:
                    for iv in ([key[:16], bytes(16)] + ivs[:12]):
                        plain = _aes_decrypt(ciphertext, key, "CBC", iv)
                        if plain is not None:
                            attempts.append(("AES/CBC/PKCS5Padding", plain, {"key_sha256": _sha256_bytes(key), "iv_sha256": _sha256_bytes(iv)}))
            if "AES/ECB/PKCS5Padding" in indicators and len(ciphertext) % 16 == 0:
                for key in [x for x in materials if len(x) in (16, 24, 32)][:24]:
                    plain = _aes_decrypt(ciphertext, key, "ECB")
                    if plain is not None:
                        attempts.append(("AES/ECB/PKCS5Padding", plain, {"key_sha256": _sha256_bytes(key)}))
            if "RC4" in indicators:
                for key in [x for x in materials if 5 <= len(x) <= 32][:32]:
                    attempts.append(("RC4", _rc4(ciphertext, key), {"key_sha256": _sha256_bytes(key)}))

            # Validation is intentionally before accepting any key.  Stop on a
            # single complete resource archive, not on padding or a magic prefix.
            successes = []
            for algorithm, plain, key_meta in attempts:
                valid = _zip_plaintext(plain)
                if valid is None:
                    continue
                inner, inner_meta = valid
                successes.append((algorithm, inner, key_meta, inner_meta))
            if len(successes) != 1:
                continue
            algorithm, inner, key_meta, inner_meta = successes[0]
            base_report = {
                "build": ANALYZER_BUILD,
                "status": "restored",
                "analysis_phase": "full-native-scan",
                "source_apk": apk.name,
                "cipher_entry": _short_name(raw_name),
                "cipher_size": len(ciphertext),
                "cipher_sha256": _sha256_bytes(ciphertext),
                "consumer_so": native_row.get("entry"),
                "algorithm": algorithm,
                "key_provenance": "literal-near-primitive-in-consumer-so",
                **key_meta,
                **inner_meta,
                "resource_plan": {
                    "strategy": "native-literal-cipher",
                    "input": _short_name(raw_name),
                    "consumer_so": native_row.get("entry"),
                    "operations": [algorithm, str(inner_meta.get("nested_algorithm") or "")],
                    "output": "full-resource-apk",
                    "confidence": "certain",
                },
                "native_scan_summary": {
                    "scanned_so_count": len(native_rows),
                    "primitive_indicators": full_report.get("primitive_indicators") or [],
                },
            }
            return _overlay_inner_zip(apk, inner, output, options, base_report)
    return None


def _full_static_report(apk: Path, zf: zipfile.ZipFile, prior_errors: List[str]) -> Dict[str, Any]:
    native = _native_inventory(zf)
    dex = _dex_inventory(zf)
    resources = _resource_entry_candidates(zf)
    xrefs = _cross_reference_resources(native, resources)
    primitives = sorted({p for row in native for p in row.get("crypto_indicators") or []})
    return {
        "build": ANALYZER_BUILD,
        "status": "analyzed-unsupported",
        "phase": "full-native-scan",
        "source_apk": apk.name,
        "source_apk_sha256": _sha256_bytes(apk.read_bytes()),
        "prior_feature_errors": prior_errors,
        "resource_candidates": [
            {k: v for k, v in row.items() if k != "entry_raw"}
            for row in resources
        ],
        "resource_cross_references": xrefs,
        "primitive_indicators": primitives,
        "native_libraries": native,
        "dex_files": dex,
        "failure_policy": (
            "No statically proved recipe produced a complete validated resource tree. "
            "The analyzer did not enumerate client crypto parameters or execute APK code."
        ),
    }



def _canonical_needs_full_scan(zf: zipfile.ZipFile) -> Tuple[bool, List[str]]:
    """Cheaply decide whether a canonical lib.so still needs native analysis."""
    reasons: List[str] = []
    for info in zf.infolist():
        if info.is_dir():
            continue
        low_name = _normal_name(info.filename).lower()
        if low_name in low._STATIC_WRAPPER_CONTROL_NAMES:
            try:
                blob = zf.read(info)
                score, _reason = low._decoded_asset_quality(low_name, blob)
            except Exception:
                score = 0
            if score == 0:
                reasons.append("opaque-control:" + low_name)
        if low_name.startswith("lib/") and low_name.endswith(".so"):
            base = low_name.rsplit("/", 1)[-1]
            if any(token in base for token in ("protect", "shell", "guard", "jiagu", "epic", "lianyi", "libly", "xskm", "tosks", "qiushui")):
                reasons.append("protector-native:" + base)
    return bool(reasons), sorted(set(reasons))


def _fast_feature_restore(
    apk: Path,
    output: Path,
    options: Optional[Dict[str, Any]],
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    errors: List[str] = []
    with zipfile.ZipFile(apk, "r") as zf:
        canonical = _canonical_info(zf)
        if canonical is not None:
            try:
                rows = low.probe_static_asset_wrappers(zf)
            except Exception as exc:
                rows = []
                errors.append("static-wrapper-probe: %s: %s" % (type(exc).__name__, exc))
            if rows:
                # Feature matching is deterministic.  Ambiguous transforms are
                # not emitted as candidates; the full native scan must disambiguate.
                if len(rows) > 1:
                    top = int(rows[0].get("score") or 0)
                    second = int(rows[1].get("score") or 0)
                    if top - second < 25:
                        errors.append("static-wrapper-probe: ambiguous transforms (%d vs %d)" % (top, second))
                    else:
                        rows = rows[:1]
                if len(rows) == 1:
                    report = low.build_static_wrapper_normalized_apk(apk, output, rows[0], options)
                    report["analysis_phase"] = "feature-match"
                    report["analyzer_build"] = ANALYZER_BUILD
                    report["resource_plan"] = {
                        "strategy": "static-asset-wrapper",
                        "input": "assets/lib.so",
                        "operations": [report.get("transform")],
                        "evidence": report.get("evidence") or [],
                        "native_evidence": report.get("native_evidence") or [],
                        "output": "assets/lib.so",
                        "confidence": "certain",
                    }
                    return report, errors

            # A plain current-family APK can stop here.  If opaque controls or
            # protector helpers are present, however, the lack of a fast feature
            # match triggers the full all-SO/DEX scan before identity is accepted.
            needs_scan, reasons = _canonical_needs_full_scan(zf)
            if needs_scan:
                errors.extend("canonical-full-scan:" + reason for reason in reasons)
                return None, errors
            return _copy_identity_apk(apk, output, options), errors

    # No canonical lib.so: first try the strict EPIC / By.LianYi transport
    # handler.  It requires a zero-byte assets/lib.so placeholder, protector
    # native evidence, an exact XOR signature marker, one structurally valid
    # restored DEX, and one unique high-entropy AES-block-aligned container.
    # Nothing from the APK is executed.
    try:
        from iapt_epic_lianyi_restore import restore_if_supported
        report = restore_if_supported(apk, output, options)
        if report is not None:
            report["analyzer_build"] = ANALYZER_BUILD
            return report, errors
    except Exception as exc:
        errors.append("epic-lianyi-handler: %s: %s" % (type(exc).__name__, exc))

    # Other hidden-resource formats use the existing complete-format parsers.
    # They validate DES sidecars, ZIP structures, cyclic stream consistency and
    # nested 3LKs bounds.
    try:
        report = low.build_normalized_apk(apk, output, options)
        report["analysis_phase"] = "feature-match"
        report["analyzer_build"] = ANALYZER_BUILD
        report["resource_plan"] = {
            "strategy": str(report.get("algorithm") or report.get("normalizer") or "hidden-resource"),
            "input": report.get("cipher_entry"),
            "key_source": report.get("sidecar_entry"),
            "operations": [
                str(report.get("algorithm") or ""),
                str(report.get("nested_algorithm") or ""),
            ],
            "output": "full-resource-apk" if not report.get("lib_only") else "assets/lib.so",
            "confidence": "certain",
        }
        return report, errors
    except Exception as exc:
        errors.append("hidden-resource-handlers: %s: %s" % (type(exc).__name__, exc))
    return None, errors


def analyze_and_restore(
    apk_path: Path | str,
    output_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Analyze resource protection and restore one deterministic output.

    There is no candidate list and no normal-container parameter recovery here.
    The function either returns one structurally proved normalized APK or raises
    :class:`StaticResourceAnalysisError` with the full native/DEX report.
    """
    started = time.perf_counter()
    apk = Path(apk_path)
    output = Path(output_path)
    if not apk.is_file() or not zipfile.is_zipfile(apk):
        raise StaticResourceAnalysisError("input is not a readable APK/ZIP")
    output.parent.mkdir(parents=True, exist_ok=True)

    report, feature_errors = _fast_feature_restore(apk, output, options)
    if report is not None:
        report = dict(report)
        report["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        report["client_parameter_policy"] = "untouched"
        return report

    with zipfile.ZipFile(apk, "r") as zf:
        full = _full_static_report(apk, zf, feature_errors)
        recovered = _attempt_literal_cipher_recovery(apk, output, zf, full, options)
    if recovered is not None:
        recovered["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        recovered["client_parameter_policy"] = "untouched"
        return recovered

    # A direct iApp container consumer plus no proved transport operation means
    # the canonical assets/lib.so is the resource-layer output.  This is how VM
    # helpers such as LianYi coexist with an unchanged container path.  The
    # normal decryptor, using client parameters, remains the final validator.
    direct_consumers = [
        row for row in full.get("native_libraries") or []
        if row.get("scope") == "iapp-container-consumer"
        and "lib.so" in (row.get("resource_tokens") or [])
    ]
    with zipfile.ZipFile(apk, "r") as check_zip:
        canonical_exists = _canonical_info(check_zip) is not None
    if canonical_exists and direct_consumers:
        identity = _copy_identity_apk(apk, output, options)
        identity.update({
            "analysis_phase": "full-native-scan",
            "analyzer_build": ANALYZER_BUILD,
            "resource_plan": {
                "strategy": "identity-after-native-scan",
                "input": "assets/lib.so",
                "consumer_so": direct_consumers[0].get("entry"),
                "operations": [],
                "output": "assets/lib.so",
                "confidence": "validated-by-client-normal-decryptor",
            },
            "native_scan_summary": {
                "scanned_so_count": len(full.get("native_libraries") or []),
                "primitive_indicators": full.get("primitive_indicators") or [],
                "no_proved_resource_transport": True,
            },
        })
        identity["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
        identity["client_parameter_policy"] = "untouched"
        return identity

    full["elapsed_ms"] = round((time.perf_counter() - started) * 1000.0, 3)
    raise StaticResourceAnalysisError(
        "unknown resource protection: full native scan completed but no proved decrypt recipe was found",
        full,
    )


def analyze_and_restore_candidates(
    apk_path: Path | str,
    output_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Return one or more normalized APK candidates.

    Hidden-container APKs first run the cheap, fully specified handlers and
    then the generic transport graph.  The expensive all-SO disassembly path is
    retained only as a final diagnostic/legacy fallback.  Canonical lib.so APKs
    keep the original analyzer ordering because wrapper transforms can depend on
    native data-flow evidence.
    """
    apk = Path(apk_path)
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    canonical = False
    try:
        with zipfile.ZipFile(apk, "r") as check:
            canonical = _canonical_info(check) is not None
    except Exception:
        pass

    known_error: Optional[StaticResourceAnalysisError] = None
    prior: Dict[str, Any] = {}

    if not canonical:
        # Keep the proven EPIC/LianYi fast path, but run the generic transport
        # graph before the older exhaustive hidden-resource/native analyzers.
        # The latter can take minutes on large APKs and are now a final fallback.
        feature_errors: List[str] = []
        # OnDev v3 must be unwrapped before EPIC/iApp container discovery.
        # Otherwise assets/ondev/p (an encrypted ODEX transport) looks like the
        # largest high-entropy resource and is falsely promoted to assets/lib.so.
        try:
            from iapt_ondev_epic_restore import restore_if_supported as restore_ondev_epic
            fast_report = restore_ondev_epic(apk, output, options)
            if fast_report is not None:
                fast_report = dict(fast_report)
                fast_report.setdefault("analyzer_build", ANALYZER_BUILD)
                return [fast_report]
        except Exception as exc:
            feature_errors.append("ondev-epic-handler: %s: %s" % (type(exc).__name__, exc))
        try:
            from iapt_epic_lianyi_restore import restore_if_supported
            fast_report = restore_if_supported(apk, output, options)
            if fast_report is not None:
                fast_report = dict(fast_report)
                fast_report.setdefault("analyzer_build", ANALYZER_BUILD)
                return [fast_report]
        except Exception as exc:
            feature_errors.append("epic-lianyi-handler: %s: %s" % (type(exc).__name__, exc))
        prior = {
            "status": "fast-feature-no-match",
            "feature_errors": feature_errors,
        }
        known_error = StaticResourceAnalysisError(
            "no fully specified hidden-resource handler matched",
            prior,
        )
    else:
        try:
            return [analyze_and_restore(apk, output, options)]
        except StaticResourceAnalysisError as exc:
            known_error = exc
            prior = dict(getattr(exc, "report", {}) or {})

    root = output.parent / (output.stem + "-generic")
    try:
        from iapt_generic_anti_restore import (
            GenericAntiRestoreError,
            build_candidates,
        )
        rows = build_candidates(apk, root, options, prior_report=prior)
    except GenericAntiRestoreError as generic_error:
        # Preserve the old full native/literal-cipher path after generic failure.
        if not canonical:
            try:
                return [analyze_and_restore(apk, output, options)]
            except StaticResourceAnalysisError as full_error:
                merged = {
                    "build": ANALYZER_BUILD,
                    "known_analyzer_error": str(full_error),
                    "known_analyzer_report": dict(getattr(full_error, "report", {}) or {}),
                    "generic_analyzer_error": str(generic_error),
                    "generic_analyzer_report": dict(getattr(generic_error, "report", {}) or {}),
                }
                raise StaticResourceAnalysisError(
                    str(full_error) + "; generic fallback: " + str(generic_error),
                    merged,
                ) from generic_error
        merged = {
            "build": ANALYZER_BUILD,
            "known_analyzer_error": str(known_error or "known analyzer failed"),
            "known_analyzer_report": prior,
            "generic_analyzer_error": str(generic_error),
            "generic_analyzer_report": dict(getattr(generic_error, "report", {}) or {}),
        }
        raise StaticResourceAnalysisError(
            str(known_error or "known analyzer failed") + "; generic fallback: " + str(generic_error),
            merged,
        ) from generic_error
    if not rows:
        raise StaticResourceAnalysisError(
            str(known_error or "known analyzer failed") + "; generic fallback returned no candidates",
            prior,
        )
    for index, row in enumerate(rows, 1):
        row["analyzer_build"] = ANALYZER_BUILD
        row["candidate_index"] = index
        row["candidate_count"] = len(rows)
        row["known_analyzer_error"] = str(known_error or "no known handler matched")
    return rows


def restore_output(
    apk_path: Path | str,
    output_path: Path | str,
    *,
    output_mode: str = "apk",
    lib_only: bool = False,
    report_path: Optional[Path | str] = None,
) -> Dict[str, Any]:
    apk = Path(apk_path)
    output = Path(output_path)
    mode = str(output_mode or "apk").lower()
    if mode not in {"apk", "lib"}:
        raise ValueError("output_mode must be apk or lib")
    options = {
        "anti_encrypted_sample": True,
        "no_decrypt_resource_files": bool(lib_only or mode == "lib"),
        "skip_anti_resources": bool(lib_only or mode == "lib"),
    }
    temp_output = output
    cleanup_dir: Optional[Path] = None
    if mode == "lib":
        cleanup_dir = Path(tempfile.mkdtemp(prefix="iapt-resource-output-"))
        temp_output = cleanup_dir / "normalized.apk"
    try:
        report = analyze_and_restore(apk, temp_output, options)
        if mode == "lib":
            with zipfile.ZipFile(temp_output, "r") as zf:
                info = _canonical_info(zf)
                if info is None:
                    raise StaticResourceAnalysisError("normalized APK has no assets/lib.so", report)
                blob = zf.read(info)
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(blob)
            report = dict(report)
            report["output_mode"] = "lib"
            report["output_file"] = str(output)
            report["output_size"] = len(blob)
            report["output_sha256"] = _sha256_bytes(blob)
        else:
            report["output_mode"] = "apk"
            report["output_file"] = str(output)
        if report_path:
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            Path(report_path).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        return report
    except StaticResourceAnalysisError as exc:
        if report_path and exc.report:
            Path(report_path).parent.mkdir(parents=True, exist_ok=True)
            Path(report_path).write_text(json.dumps(exc.report, ensure_ascii=False, indent=2), encoding="utf-8")
        raise
    finally:
        if cleanup_dir is not None:
            shutil.rmtree(cleanup_dir, ignore_errors=True)


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Static APK resource-encryption analyzer and restorer")
    p.add_argument("apk", type=Path)
    p.add_argument("output", type=Path)
    p.add_argument("--output-mode", choices=("apk", "lib"), default="apk")
    p.add_argument("--lib-only", action="store_true", help="restore only assets/lib.so into the normalized APK")
    p.add_argument("--report", type=Path)
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    try:
        report = restore_output(
            args.apk, args.output,
            output_mode=args.output_mode,
            lib_only=bool(args.lib_only),
            report_path=args.report,
        )
    except StaticResourceAnalysisError as exc:
        print("[IAPT_STATIC_RESOURCE] failed: " + str(exc), flush=True)
        if exc.report:
            print(json.dumps(exc.report, ensure_ascii=False, indent=2), flush=True)
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
