#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Evidence-driven generic resource transport recovery for protected iApp APKs.

This module is the bounded fallback used after all known format handlers fail.
It does not execute APK bytecode or native libraries and does not enumerate
numeric sokey/dexkey ranges.  Instead it:

* inventories every plausible opaque APK member;
* derives byte transforms from complete known plaintext structures;
* restores structurally valid DEX/ELF/VM/control objects;
* ranks opaque AES-block-aligned container candidates in the same transport
  domain as the proven transform;
* emits a small list of normalized APK candidates; and
* relies on the normal iApp main-entry decryptor as the final validator.

The implementation intentionally produces multiple candidates when evidence is
strong but the container is ambiguous.  It never turns a weak magic-prefix hit
into a published result by itself.
"""
from __future__ import annotations

import bz2
import gzip
import hashlib
import io
import json
import lzma
import math
import os
import re
import shutil
import struct
import tempfile
import zipfile
import zlib
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
if str(HERE) not in os.sys.path:
    os.sys.path.insert(0, str(HERE))

import iapt_hidden_resource_restore as low

BUILD = "generic-static-transport-v183"
MAX_ENTRY = 64 * 1024 * 1024
MAX_FULL_PROBES = 220
MAX_SMALL_PROBES = 2048
MAX_CONTAINER_CANDIDATES = 10
MAX_DEX_CANDIDATES = 6
MAX_ELF_CANDIDATES = 12
MAX_VM_CANDIDATES = 4
MAX_DECOMPRESSED = 96 * 1024 * 1024
SOKEY_RE = re.compile(rb"[A-Za-z0-9]{10}Q{10}W{10}EE")


class GenericAntiRestoreError(RuntimeError):
    def __init__(self, message: str, report: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.report = dict(report or {})


def _norm(value: Any) -> str:
    return str(value or "").replace("\\", "/")


def _safe_name(value: str) -> bool:
    value = _norm(value)
    if not value or value.startswith("/") or "\x00" in value:
        return False
    return all(part not in ("", ".", "..") for part in PurePosixPath(value).parts)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    sample = bytes(data[: min(len(data), 262144)])
    if not sample:
        return 0.0
    counts = Counter(sample)
    total = float(len(sample))
    return -sum((count / total) * math.log2(count / total) for count in counts.values())


def _printable_ratio(data: bytes) -> float:
    sample = bytes(data[: min(len(data), 8192)])
    if not sample:
        return 0.0
    return sum(value in (9, 10, 13) or 32 <= value < 127 for value in sample) / float(len(sample))


def _scope(name: str) -> str:
    parts = [part for part in _norm(name).split("/") if part]
    if not parts:
        return ""
    if parts[0].lower() == "assets" and len(parts) >= 2:
        return "/".join(parts[:2]).lower()
    return parts[0].lower()


def _timestamp_seconds(info: zipfile.ZipInfo) -> int:
    try:
        import datetime
        return int(datetime.datetime(*info.date_time).timestamp())
    except Exception:
        return 0


def _clone_info(info: zipfile.ZipInfo, filename: Optional[str] = None) -> zipfile.ZipInfo:
    clone = zipfile.ZipInfo(filename or _norm(info.filename), date_time=info.date_time)
    clone.compress_type = info.compress_type
    clone.comment = info.comment
    clone.extra = info.extra
    clone.create_system = info.create_system
    clone.create_version = info.create_version
    clone.extract_version = info.extract_version
    clone.flag_bits = info.flag_bits
    clone.internal_attr = info.internal_attr
    clone.external_attr = info.external_attr
    return clone


def _transform_public(transform: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(transform.get("kind") or "identity")
    result: Dict[str, Any] = {"kind": kind}
    if kind == "xor-repeat":
        key = bytes(transform.get("key") or b"")
        result.update({"key_hex": key.hex(), "key_length": len(key)})
    elif kind != "identity":
        result["value"] = int(transform.get("value") or 0) & 0xFF
    return result


def _transform_id(transform: Dict[str, Any]) -> str:
    public = _transform_public(transform)
    return json.dumps(public, sort_keys=True, separators=(",", ":"))


def _apply_transform(data: bytes, transform: Dict[str, Any]) -> bytes:
    if str(transform.get("kind") or "identity") == "identity":
        return bytes(data)
    return low._apply_static_transform(bytes(data), transform)


def _infer(raw: bytes, prefix: bytes) -> List[Dict[str, Any]]:
    result = [{"kind": "identity"}] if bytes(raw[: len(prefix)]) == bytes(prefix) else []
    try:
        result.extend(low._infer_transform_from_prefix(raw, prefix))
    except Exception:
        pass
    unique: Dict[str, Dict[str, Any]] = {}
    for row in result:
        unique[_transform_id(row)] = row
    return list(unique.values())


def _valid_dex(data: bytes) -> Tuple[bool, Dict[str, Any]]:
    data = bytes(data)
    if len(data) < 0x70 or not re.match(rb"dex\n0(?:3[5-9]|4[0-1])\x00", data[:8]):
        return False, {}
    try:
        checksum = struct.unpack_from("<I", data, 8)[0]
        signature = data[12:32]
        file_size, header_size, endian = struct.unpack_from("<III", data, 0x20)
        map_off = struct.unpack_from("<I", data, 0x34)[0]
        string_count, string_off = struct.unpack_from("<II", data, 0x38)
        type_count, type_off = struct.unpack_from("<II", data, 0x40)
        method_count, method_off = struct.unpack_from("<II", data, 0x58)
    except Exception:
        return False, {}
    if file_size != len(data) or header_size != 0x70 or endian != 0x12345678:
        return False, {}
    if map_off and not (0x70 <= map_off < len(data)):
        return False, {}
    for count, offset, width in ((string_count, string_off, 4), (type_count, type_off, 4), (method_count, method_off, 8)):
        if count and (offset < 0x70 or offset + count * width > len(data)):
            return False, {}
    sha_ok = hashlib.sha1(data[32:]).digest() == signature
    adler_ok = (zlib.adler32(data[12:]) & 0xFFFFFFFF) == checksum
    needles = {
        "iapp_f": b"Lcom/iapp/app/f;" in data or b"com/iapp/app/f" in data,
        "iapp": b"com/iapp/app" in data,
        "mian": b"mian.iyu" in data or b"main.iyu" in data,
    }
    score = 90 + (18 if sha_ok else 0) + (12 if adler_ok else 0)
    score += 20 if needles["iapp_f"] else 0
    score += 8 if needles["iapp"] else 0
    return True, {
        "type": "dex",
        "score": score,
        "sha1_valid": sha_ok,
        "adler32_valid": adler_ok,
        "file_size": len(data),
        **needles,
    }


def _valid_elf(data: bytes) -> Tuple[bool, Dict[str, Any]]:
    data = bytes(data)
    if len(data) < 52 or data[:4] != b"\x7fELF" or data[5] not in (1, 2):
        return False, {}
    cls = int(data[4])
    endian = "<" if data[5] == 1 else ">"
    try:
        if cls == 1:
            fields = struct.unpack_from(endian + "16sHHIIIIIHHHHHH", data, 0)
            machine, phoff, shoff, ehsize, phentsize, phnum = fields[2], fields[5], fields[6], fields[8], fields[9], fields[10]
            minimum = 52
        elif cls == 2:
            fields = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", data, 0)
            machine, phoff, shoff, ehsize, phentsize, phnum = fields[2], fields[5], fields[6], fields[8], fields[9], fields[10]
            minimum = 64
        else:
            return False, {}
    except Exception:
        return False, {}
    if ehsize < minimum or phnum > 256 or phentsize > 256:
        return False, {}
    if phnum and (phoff <= 0 or phoff + phentsize * phnum > len(data)):
        return False, {}
    machine_names = {3: "x86", 40: "armeabi-v7a", 62: "x86_64", 183: "arm64-v8a"}
    sokeys = sorted({match.group(0).decode("ascii", "replace") for match in SOKEY_RE.finditer(data)})
    iapp_consumer = b"LuaStateFactory" in data or b"com/iapp/app" in data or b"lib.so" in data
    score = 70 + (35 if sokeys else 0) + (18 if iapp_consumer else 0)
    return True, {
        "type": "elf",
        "score": score,
        "class": cls,
        "machine": int(machine),
        "abi": machine_names.get(int(machine), "unknown"),
        "sokeys": sokeys[:4],
        "iapp_consumer": iapp_consumer,
        "file_size": len(data),
    }


def _valid_zip(data: bytes) -> Tuple[bool, Dict[str, Any]]:
    data = bytes(data)
    if not data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
        return False, {}
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            infos = [info for info in zf.infolist() if not info.is_dir()]
            if not infos or any(not _safe_name(info.filename) for info in infos):
                return False, {}
            names = [_norm(info.filename).lower() for info in infos]
            has_container = "assets/lib.so" in names
            has_dex = any(re.search(r"(?:^|/)classes\d*\.dex$", name) for name in names)
            score = 55 + (45 if has_container else 0) + (15 if has_dex else 0)
            return True, {
                "type": "zip",
                "score": score,
                "entry_count": len(infos),
                "has_container": has_container,
                "has_dex": has_dex,
            }
    except Exception:
        return False, {}


def _valid_vm(data: bytes) -> Tuple[bool, Dict[str, Any]]:
    data = bytes(data)
    if not data.startswith(b"Epic") or len(data) < 32:
        return False, {}
    iapp = b"com/iapp/app/f" in data or b"com.iapp.app.f" in data
    int_records = 0
    for match in re.finditer(rb"\x14\x00(.{4})\x0f\x00", data, flags=re.S):
        value = int.from_bytes(match.group(1), "little", signed=True)
        if 100_000 <= value <= 20_000_000:
            int_records += 1
    if not iapp and int_records == 0:
        return False, {}
    return True, {
        "type": "vm",
        "score": 65 + (25 if iapp else 0) + min(20, 4 * int_records),
        "iapp_f": iapp,
        "int_record_count": int_records,
    }


def _valid_control(data: bytes) -> Tuple[bool, Dict[str, Any]]:
    data = bytes(data)
    stripped = data[:1024 * 1024].strip(b"\xef\xbb\xbf\x00\t\r\n ")
    if stripped == b"<signature>1</signature>":
        return True, {"type": "control", "score": 110, "control": "signature-xml-exact"}
    if not stripped.startswith(b"<") or not stripped.endswith(b">"):
        return False, {}
    try:
        root = ET.fromstring(stripped.decode("utf-8", "strict"))
    except Exception:
        return False, {}
    tag = str(root.tag or "").split("}")[-1].lower()
    if tag == "signature" and str(root.text or "").strip() == "1":
        return True, {"type": "control", "score": 110, "control": "signature-xml"}
    if tag == "ok":
        return True, {"type": "control", "score": 92, "control": "user-encryption-xml"}
    if tag in {"config", "resources", "manifest"}:
        return True, {"type": "control", "score": 65, "control": "xml:" + tag}
    return False, {}


def _classify(data: bytes) -> Tuple[Optional[str], Dict[str, Any]]:
    for validator in (_valid_dex, _valid_elf, _valid_zip, _valid_vm, _valid_control):
        ok, meta = validator(data)
        if ok:
            return str(meta.get("type")), meta
    head = bytes(data[:64]).lstrip(b"\x00\t\r\n ")
    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image", {"type": "image", "score": 30, "format": "png"}
    if head.startswith((b"GIF87a", b"GIF89a", b"\xff\xd8\xff", b"RIFF")):
        return "media", {"type": "media", "score": 20}
    if head.startswith(b"SQLite format 3\x00"):
        return "sqlite", {"type": "sqlite", "score": 30}
    return None, {}


_PREFIXES: Tuple[Tuple[str, bytes], ...] = (
    ("signature", b"<signature>1</signature>"),
    ("user-xml", b"<ok>"),
    ("xml", b"<?xml"),
    ("epic-vm", b"Epic"),
    ("elf", b"\x7fELF"),
    ("zip", b"PK\x03\x04"),
    ("dex035", b"dex\n035\x00"),
    ("dex036", b"dex\n036\x00"),
    ("dex037", b"dex\n037\x00"),
    ("dex038", b"dex\n038\x00"),
    ("dex039", b"dex\n039\x00"),
    ("dex040", b"dex\n040\x00"),
    ("dex041", b"dex\n041\x00"),
)


def _dex_head_plausible(head: bytes, total_size: int) -> bool:
    if len(head) < 0x70 or not re.match(rb"dex\n0(?:3[5-9]|4[0-1])\x00", head[:8]):
        return False
    try:
        file_size, header_size, endian = struct.unpack_from("<III", head, 0x20)
    except Exception:
        return False
    return file_size == int(total_size) and header_size == 0x70 and endian == 0x12345678


def _elf_head_plausible(head: bytes, total_size: int) -> bool:
    if len(head) < 52 or head[:4] != b"\x7fELF" or head[4] not in (1, 2) or head[5] not in (1, 2):
        return False
    endian = "<" if head[5] == 1 else ">"
    try:
        if head[4] == 1:
            fields = struct.unpack_from(endian + "16sHHIIIIIHHHHHH", head, 0)
            phoff, ehsize, phentsize, phnum = fields[5], fields[8], fields[9], fields[10]
            minimum = 52
        else:
            if len(head) < 64:
                return False
            fields = struct.unpack_from(endian + "16sHHIQQQIHHHHHH", head, 0)
            phoff, ehsize, phentsize, phnum = fields[5], fields[8], fields[9], fields[10]
            minimum = 64
    except Exception:
        return False
    return ehsize >= minimum and phnum <= 256 and phentsize <= 256 and (not phnum or (phoff > 0 and phoff + phentsize * phnum <= int(total_size)))


def _prefix_gate(label: str, decoded_head: bytes, total_size: int) -> bool:
    if label.startswith("dex"):
        return _dex_head_plausible(decoded_head, total_size)
    if label == "elf":
        return _elf_head_plausible(decoded_head, total_size)
    if label == "epic-vm":
        return int(total_size) <= 16 * 1024 * 1024 and decoded_head.startswith(b"Epic")
    if label == "signature":
        return int(total_size) <= 4096 and decoded_head.startswith(b"<signature>1</signature>")
    if label in {"user-xml", "xml"}:
        return int(total_size) <= 1024 * 1024 and decoded_head.lstrip(b"\xef\xbb\xbf\x00\t\r\n ").startswith(b"<")
    if label == "zip":
        return int(total_size) <= 32 * 1024 * 1024 and decoded_head.startswith(b"PK\x03\x04")
    return False


def _decompress_layers(data: bytes) -> List[Tuple[List[str], bytes]]:
    """Return identity plus one bounded standard decompression layer."""
    rows: List[Tuple[List[str], bytes]] = [([], bytes(data))]
    raw = bytes(data)
    attempts: List[Tuple[str, Any]] = []
    if raw.startswith(b"\x1f\x8b\x08"):
        attempts.append(("gzip", gzip.decompress))
    if raw.startswith(b"BZh"):
        attempts.append(("bz2", bz2.decompress))
    if raw.startswith(b"\xfd7zXZ\x00"):
        attempts.append(("xz", lzma.decompress))
    if len(raw) >= 2 and raw[0] == 0x78:
        attempts.append(("zlib", zlib.decompress))
    for label, fn in attempts:
        try:
            decoded = bytes(fn(raw))
        except Exception:
            continue
        if 0 < len(decoded) <= MAX_DECOMPRESSED:
            rows.append(([label], decoded))
    return rows


@dataclass
class Evidence:
    entry: str
    scope: str
    transform: Dict[str, Any]
    operations: List[str]
    decoded_type: str
    decoded: bytes
    meta: Dict[str, Any]
    timestamp: int
    raw_size: int

    @property
    def transform_id(self) -> str:
        return _transform_id(self.transform)

    @property
    def score(self) -> int:
        return int(self.meta.get("score") or 0)


@dataclass
class ContainerCandidate:
    entry: str
    scope: str
    transform: Dict[str, Any]
    decoded: bytes
    score: int
    evidence: List[Evidence] = field(default_factory=list)
    reason: List[str] = field(default_factory=list)

    @property
    def digest(self) -> str:
        return _sha256(self.decoded)


def _probe_infos(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    rows = []
    for info in zf.infolist():
        if info.is_dir() or not _safe_name(info.filename):
            continue
        name = _norm(info.filename)
        low_name = name.lower()
        size = int(info.file_size or 0)
        if size < 4 or size > MAX_ENTRY:
            continue
        if low_name.startswith("meta-inf/") or low_name == "androidmanifest.xml" or low_name == "resources.arsc":
            continue
        score = 0
        if size <= 4096:
            score += 60
        if low_name.startswith("assets/"):
            score += 35
        if not low_name.startswith("res/"):
            score += 10
        if low_name.endswith((".epic", ".vm", ".dex", ".so", ".bin", ".dat", ".enc")):
            score += 35
        if size >= 64 * 1024:
            score += 20
        if size % 16 == 0 and size >= 64 * 1024:
            score += 20
        if info.compress_size and float(info.compress_size) / max(1, size) >= 0.78:
            score += 15
        if len(name) > 80 or name.count("/") >= 4:
            score += 15
        rows.append((score, info))
    rows.sort(key=lambda row: (-row[0], -int(row[1].file_size or 0), _norm(row[1].filename)))
    # Always keep small files because they can prove the transport key.
    small = [info for _score, info in rows if int(info.file_size or 0) <= 4096]
    large = [info for _score, info in rows if int(info.file_size or 0) > 4096]
    selected: List[zipfile.ZipInfo] = []
    seen = set()
    for info in small[:MAX_SMALL_PROBES] + large[:MAX_FULL_PROBES]:
        name = _norm(info.filename).lower()
        if name not in seen:
            seen.add(name)
            selected.append(info)
    return selected[: MAX_FULL_PROBES + MAX_SMALL_PROBES]


def _collect_evidence(zf: zipfile.ZipFile, infos: Sequence[zipfile.ZipInfo]) -> Tuple[List[Evidence], List[Dict[str, Any]]]:
    evidence: List[Evidence] = []
    errors: List[Dict[str, Any]] = []
    seen = set()
    for info in infos:
        name = _norm(info.filename)
        try:
            raw = zf.read(info)
        except Exception as exc:
            errors.append({"entry": name, "error": type(exc).__name__ + ": " + str(exc)})
            continue

        def add_decoded(transform: Dict[str, Any], decoded: bytes, operations: List[str]) -> None:
            decoded_type, meta = _classify(decoded)
            if decoded_type is None:
                return
            if decoded_type in {"image", "media", "sqlite"} and str(transform.get("kind") or "identity") == "identity":
                return
            key = (name.lower(), _transform_id(transform), tuple(operations), _sha256(decoded))
            if key in seen:
                return
            seen.add(key)
            evidence.append(Evidence(
                entry=name,
                scope=_scope(name),
                transform=dict(transform),
                operations=[_transform_id(transform)] + list(operations),
                decoded_type=decoded_type,
                decoded=decoded,
                meta=dict(meta),
                timestamp=_timestamp_seconds(info),
                raw_size=len(raw),
            ))

        # Identity is evaluated once.  Standard compression layers are tried
        # only when their own magic is present.
        for decompress_ops, decoded in _decompress_layers(raw):
            add_decoded({"kind": "identity"}, decoded, decompress_ops)

        head_size = min(len(raw), 0x100)
        raw_head = raw[:head_size]
        tried = set()
        for label, prefix in _PREFIXES:
            # Large arbitrary entries can always be algebraically mapped to a
            # short prefix.  A strict decoded-header gate must pass before the
            # O(file-size) transform is allowed.
            for transform in _infer(raw_head, prefix):
                if str(transform.get("kind") or "identity") == "identity":
                    continue
                if str(transform.get("kind") or "") == "xor-repeat" and len(bytes(transform.get("key") or b"")) > 8:
                    # A long XOR key can algebraically map one arbitrary header
                    # to any known plaintext.  Such keys require native/data-flow
                    # corroboration and are handled by the older full analyzer.
                    continue
                tid = _transform_id(transform)
                pair = (label, tid)
                if pair in tried:
                    continue
                tried.add(pair)
                try:
                    decoded_head = _apply_transform(raw_head, transform)
                except Exception:
                    continue
                if not _prefix_gate(label, decoded_head, len(raw)):
                    continue
                try:
                    transformed = _apply_transform(raw, transform)
                except Exception:
                    continue
                for decompress_ops, decoded in _decompress_layers(transformed):
                    add_decoded(transform, decoded, decompress_ops)
    evidence.sort(key=lambda row: (-row.score, row.entry, row.transform_id))
    return evidence, errors


def _native_strings(zf: zipfile.ZipFile) -> bytes:
    chunks = []
    budget = 24 * 1024 * 1024
    for info in zf.infolist():
        name = _norm(info.filename).lower()
        if info.is_dir() or not name.startswith("lib/") or not name.endswith(".so"):
            continue
        if int(info.file_size or 0) < 4096 or int(info.file_size or 0) > 32 * 1024 * 1024:
            continue
        try:
            blob = zf.read(info)
        except Exception:
            continue
        chunks.append(blob)
        budget -= len(blob)
        if budget <= 0:
            break
    return b"\n".join(chunks)


def _known_type(data: bytes) -> bool:
    decoded_type, _meta = _classify(data)
    return decoded_type is not None


def _native_vm_transport_transforms(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """Recover bounded byte-transport keys from native VM registration blobs.

    Several protectors move a Java ``static native int getKey()`` method into a
    small, architecture-independent VM program embedded in every ABI build.
    The VM encoding observed in these protectors stores a const-int followed by
    an integer return as::

        94 01 72 00 <imm32-le> 8e 00

    This function never scans arbitrary immediates.  It requires JNI/protector
    registration evidence (``classesInit0``, ``getKey`` and ``()I``), a unique
    VM const-return record per library, and cross-ABI agreement whenever more
    than one ABI is present.  Only the low byte is proposed as a transport XOR
    key; the normal ``mian.iyu`` decrypt/verification remains authoritative.
    """
    groups: Dict[str, List[Tuple[str, bytes]]] = defaultdict(list)
    for info in zf.infolist():
        name = _norm(info.filename)
        low_name = name.lower()
        if info.is_dir() or not low_name.startswith("lib/") or not low_name.endswith(".so"):
            continue
        if not 4096 <= int(info.file_size or 0) <= 64 * 1024 * 1024:
            continue
        try:
            blob = zf.read(info)
        except Exception:
            continue
        if not (b"classesInit0" in blob and b"getKey" in blob and b"()I" in blob):
            continue
        groups[low_name.rsplit("/", 1)[-1]].append((name, blob))

    rows: List[Dict[str, Any]] = []
    pattern = re.compile(rb"\x94\x01\x72\x00(.{4})\x8e\x00", re.S)
    for family, members in sorted(groups.items()):
        per_member: List[Tuple[str, int, int]] = []
        for name, blob in members:
            matches = [(match.start(), int.from_bytes(match.group(1), "little", signed=False)) for match in pattern.finditer(blob)]
            # Multiple VM const-return records are ambiguous; do not guess.
            if len(matches) != 1:
                continue
            offset, value = matches[0]
            per_member.append((name, value, offset))
        if not per_member:
            continue
        counts = Counter(value for _name, value, _offset in per_member)
        value, votes = counts.most_common(1)[0]
        if len(counts) != 1:
            continue
        # Multi-ABI packages require at least two agreeing copies.  A single ABI
        # remains usable only because the VM method/type evidence is exact and
        # the resulting APK is still cryptographically/main-entry verified.
        if len(members) > 1 and votes < 2:
            continue
        key_byte = int(value) & 0xFF
        if key_byte == 0:
            continue
        transform = {"kind": "xor-repeat", "key": bytes([key_byte])}
        rows.append({
            "family": family,
            "method": "getKey()I",
            "value": int(value),
            "low_byte": key_byte,
            "transform": transform,
            "votes": votes,
            "members": [
                {"entry": name, "offset": offset, "value": member_value}
                for name, member_value, offset in per_member
            ],
            "evidence": "native-vm-const-int-return-cross-abi",
        })
    return rows


def _candidate_containers(
    zf: zipfile.ZipFile,
    infos: Sequence[zipfile.ZipInfo],
    evidence: Sequence[Evidence],
    native_vm_transforms: Sequence[Dict[str, Any]] = (),
) -> List[ContainerCandidate]:
    native_blob = _native_strings(zf)
    by_group: Dict[Tuple[str, str], List[Evidence]] = defaultdict(list)
    for row in evidence:
        if row.decoded_type in {"control", "dex", "elf", "vm", "zip"}:
            by_group[(row.scope, row.transform_id)].append(row)

    results: List[ContainerCandidate] = []
    seen_digests = set()
    for (scope, transform_id), proofs in by_group.items():
        transform = dict(proofs[0].transform)
        # Require a strong complete object, not just a generic file prefix.
        proof_score = max(row.score for row in proofs)
        strong = any(
            row.decoded_type in {"dex", "elf"}
            or (row.decoded_type == "control" and row.score >= 80)
            or (row.decoded_type == "zip" and bool(row.meta.get("has_container")))
            for row in proofs
        )
        if not strong:
            continue
        for info in infos:
            name = _norm(info.filename)
            if _scope(name) != scope:
                continue
            size = int(info.file_size or 0)
            if size < 64 * 1024 or size > MAX_ENTRY or size % 16 != 0:
                continue
            try:
                decoded = _apply_transform(zf.read(info), transform)
            except Exception:
                continue
            if _known_type(decoded):
                continue
            entropy = _entropy(decoded)
            if entropy < 7.78:
                continue
            digest = _sha256(decoded)
            if digest in seen_digests:
                continue
            score = 90 + int(proof_score)
            reasons = ["same-scope-proven-transform", "aes-block-aligned", "high-entropy:%.4f" % entropy]
            if entropy >= 7.92:
                score += 25
            distances = [abs(_timestamp_seconds(info) - row.timestamp) for row in proofs if row.timestamp]
            if distances:
                nearest = min(distances)
                if nearest <= 60:
                    score += 18
                    reasons.append("zip-stage-distance:%d" % nearest)
            encoded_name = name.encode("utf-8", "ignore")
            basename = name.rsplit("/", 1)[-1].encode("utf-8", "ignore")
            if (encoded_name and encoded_name in native_blob) or (len(basename) >= 6 and basename in native_blob):
                score += 22
                reasons.append("native-resource-reference")
            results.append(ContainerCandidate(
                entry=name,
                scope=scope,
                transform=transform,
                decoded=decoded,
                score=score,
                evidence=list(proofs),
                reason=reasons,
            ))
            seen_digests.add(digest)

    # Native VM transport-key fallback.  The key is not guessed from ciphertext:
    # it is recovered from an exact, cross-ABI const-int-return VM record tied to
    # a registered ``getKey()I`` method.  Restrict application to opaque,
    # block-aligned resources whose path/basename is referenced by native code.
    # The decrypted iApp main entry is still the final validator.
    for vm_row in native_vm_transforms:
        transform = dict(vm_row.get("transform") or {})
        if str(transform.get("kind") or "") != "xor-repeat" or len(bytes(transform.get("key") or b"")) != 1:
            continue
        for info in infos:
            name = _norm(info.filename)
            size = int(info.file_size or 0)
            if size < 64 * 1024 or size > MAX_ENTRY or size % 16 != 0:
                continue
            try:
                raw = zf.read(info)
            except Exception:
                continue
            if _known_type(raw) or _entropy(raw) < 7.78:
                continue
            encoded_name = name.encode("utf-8", "ignore")
            basename = name.rsplit("/", 1)[-1].encode("utf-8", "ignore")
            referenced = bool((encoded_name and encoded_name in native_blob) or (len(basename) >= 6 and basename in native_blob))
            if not referenced:
                continue
            try:
                decoded = _apply_transform(raw, transform)
            except Exception:
                continue
            if decoded == raw or _known_type(decoded) or _entropy(decoded) < 7.78:
                continue
            digest = _sha256(decoded)
            if digest in seen_digests:
                continue
            reasons = [
                "native-vm-getKey-low-byte",
                "cross-abi-votes:%d" % int(vm_row.get("votes") or 0),
                "native-resource-reference",
                "aes-block-aligned",
            ]
            results.append(ContainerCandidate(
                entry=name,
                scope=_scope(name),
                transform=transform,
                decoded=decoded,
                score=245 + min(40, 8 * int(vm_row.get("votes") or 0)),
                evidence=[],
                reason=reasons,
            ))
            seen_digests.add(digest)

    # Conservative identity fallback: use it only when one opaque candidate is
    # referenced by native code or when there is a single candidate in a scope
    # that also contains a structurally recovered DEX/ELF.
    strong_scopes = {
        row.scope for row in evidence
        if row.decoded_type in {"dex", "elf"} and row.score >= 70
    }
    identity_rows: List[ContainerCandidate] = []
    for info in infos:
        name = _norm(info.filename)
        size = int(info.file_size or 0)
        if size < 64 * 1024 or size > MAX_ENTRY or size % 16 != 0:
            continue
        try:
            raw = zf.read(info)
        except Exception:
            continue
        if _known_type(raw) or _entropy(raw) < 7.90:
            continue
        encoded_name = name.encode("utf-8", "ignore")
        basename = name.rsplit("/", 1)[-1].encode("utf-8", "ignore")
        referenced = bool((encoded_name and encoded_name in native_blob) or (len(basename) >= 6 and basename in native_blob))
        if not referenced and _scope(name) not in strong_scopes:
            continue
        identity_rows.append(ContainerCandidate(
            entry=name,
            scope=_scope(name),
            transform={"kind": "identity"},
            decoded=raw,
            score=95 + (30 if referenced else 0),
            evidence=[row for row in evidence if row.scope == _scope(name) and row.decoded_type in {"dex", "elf"}],
            reason=["identity-high-entropy", "native-resource-reference" if referenced else "single-transport-scope"],
        ))
    by_scope = defaultdict(list)
    for row in identity_rows:
        by_scope[row.scope].append(row)
    for rows in by_scope.values():
        rows.sort(key=lambda row: (-row.score, -len(row.decoded), row.entry))
        if len(rows) == 1 or rows[0].score > rows[1].score:
            if rows[0].digest not in seen_digests:
                results.append(rows[0])
                seen_digests.add(rows[0].digest)

    results.sort(key=lambda row: (-row.score, row.entry, row.digest))
    return results[:MAX_CONTAINER_CANDIDATES]


def _dedupe_evidence(rows: Sequence[Evidence], limit: int) -> List[Evidence]:
    result = []
    seen = set()
    for row in sorted(rows, key=lambda item: (-item.score, item.entry, item.transform_id)):
        digest = _sha256(row.decoded)
        if digest in seen:
            continue
        seen.add(digest)
        result.append(row)
        if len(result) >= limit:
            break
    return result


def _abi_for_elf(row: Evidence) -> str:
    return str(row.meta.get("abi") or "unknown")


def _build_candidate_apk(
    apk: Path,
    output: Path,
    container: ContainerCandidate,
    dex_rows: Sequence[Evidence],
    elf_rows: Sequence[Evidence],
    vm_rows: Sequence[Evidence],
    index: int,
    prior_report: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(apk, "r") as src:
        infos = [info for info in src.infolist() if not info.is_dir()]
        names_lower = {_norm(info.filename).lower() for info in infos}
        recovered_sokey_by_abi = {
            _abi_for_elf(row): row
            for row in elf_rows
            if row.meta.get("sokeys") and _abi_for_elf(row) != "unknown"
        }
        consumed_elf_digests = set()
        existing_dex_hashes = set()
        existing_elf_hashes = set()
        for info in infos:
            low_name = _norm(info.filename).lower()
            if re.search(r"(?:^|/)classes\d*\.dex$", low_name) or (low_name.startswith("lib/") and low_name.endswith(".so")):
                try:
                    digest = _sha256(src.read(info))
                except Exception:
                    continue
                if low_name.endswith(".dex"):
                    existing_dex_hashes.add(digest)
                else:
                    existing_elf_hashes.add(digest)

        fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
        os.close(fd)
        temp = Path(temp_name)
        added: List[Dict[str, Any]] = []
        try:
            written = set()
            with zipfile.ZipFile(temp, "w", allowZip64=True) as dst:
                for info in infos:
                    name = _norm(info.filename)
                    low_name = name.lower()
                    if low_name == "meta-inf/iapt/generic_anti_restore.json":
                        continue
                    ygsiyu_match = re.match(r"^lib/([^/]+)/libygsiyu\.so$", low_name)
                    if ygsiyu_match and ygsiyu_match.group(1) in recovered_sokey_by_abi:
                        original = src.read(info)
                        if not SOKEY_RE.search(original):
                            row = recovered_sokey_by_abi[ygsiyu_match.group(1)]
                            dst.writestr(_clone_info(info, name), row.decoded)
                            written.add(low_name)
                            digest = _sha256(row.decoded)
                            consumed_elf_digests.add(digest)
                            existing_elf_hashes.add(digest)
                            added.append({"type": "elf", "source": row.entry, "target": name, "sha256": digest, "abi": ygsiyu_match.group(1), "replaced_invalid_libygsiyu": True})
                            continue
                    if low_name == "assets/lib.so":
                        if low_name in written:
                            continue
                        dst.writestr(_clone_info(info, "assets/lib.so"), container.decoded)
                        written.add(low_name)
                        continue
                    if low_name in written:
                        continue
                    dst.writestr(_clone_info(info, name), src.read(info))
                    written.add(low_name)
                if "assets/lib.so" not in written:
                    zi = zipfile.ZipInfo("assets/lib.so", date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_STORED
                    dst.writestr(zi, container.decoded)
                    written.add("assets/lib.so")

                dex_index = 90
                for row in dex_rows:
                    digest = _sha256(row.decoded)
                    if digest in existing_dex_hashes:
                        continue
                    while ("classes%d.dex" % dex_index).lower() in written:
                        dex_index += 1
                    target = "classes%d.dex" % dex_index
                    zi = zipfile.ZipInfo(target, date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    dst.writestr(zi, row.decoded)
                    written.add(target.lower())
                    existing_dex_hashes.add(digest)
                    added.append({"type": "dex", "source": row.entry, "target": target, "sha256": digest})
                    dex_index += 1

                valid_existing_vm = False
                for info in infos:
                    if _norm(info.filename).lower() == "epic.vm":
                        try:
                            valid_existing_vm = bool(_valid_vm(src.read(info))[0])
                        except Exception:
                            pass
                if not valid_existing_vm and vm_rows:
                    row = vm_rows[0]
                    target = "Epic.vm"
                    zi = zipfile.ZipInfo(target, date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    dst.writestr(zi, row.decoded)
                    written.add(target.lower())
                    added.append({"type": "vm", "source": row.entry, "target": target, "sha256": _sha256(row.decoded)})

                so_counter = 1
                existing_sokey_lib = False
                for info in infos:
                    low_name = _norm(info.filename).lower()
                    if not (low_name.endswith("/libygsiyu.so") or low_name == "libygsiyu.so"):
                        continue
                    try:
                        if SOKEY_RE.search(src.read(info)):
                            existing_sokey_lib = True
                            break
                    except Exception:
                        pass
                if consumed_elf_digests:
                    existing_sokey_lib = True
                for row in elf_rows:
                    digest = _sha256(row.decoded)
                    if digest in existing_elf_hashes or digest in consumed_elf_digests:
                        continue
                    abi = _abi_for_elf(row)
                    if abi == "unknown":
                        continue
                    original_base = Path(_norm(row.entry)).name
                    if not original_base.lower().endswith(".so"):
                        original_base = "libiapt_recovered_%d.so" % so_counter
                    if row.meta.get("sokeys") and not existing_sokey_lib:
                        original_base = "libygsiyu.so"
                        existing_sokey_lib = True
                    target = "lib/%s/%s" % (abi, original_base)
                    while target.lower() in written:
                        stem = Path(original_base).stem
                        target = "lib/%s/%s_%d.so" % (abi, stem, so_counter)
                        so_counter += 1
                    zi = zipfile.ZipInfo(target, date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    dst.writestr(zi, row.decoded)
                    written.add(target.lower())
                    existing_elf_hashes.add(digest)
                    added.append({"type": "elf", "source": row.entry, "target": target, "sha256": digest, "abi": abi})
                    so_counter += 1

                marker = {
                    "build": BUILD,
                    "candidate_index": index,
                    "source_apk": apk.name,
                    "container": {
                        "source": container.entry,
                        "scope": container.scope,
                        "transform": _transform_public(container.transform),
                        "score": container.score,
                        "size": len(container.decoded),
                        "sha256": container.digest,
                        "reason": container.reason,
                        "evidence": [
                            {
                                "entry": row.entry,
                                "type": row.decoded_type,
                                "score": row.score,
                                "transform": _transform_public(row.transform),
                            }
                            for row in container.evidence[:16]
                        ],
                    },
                    "added_objects": added,
                    "prior_analyzer": dict(prior_report or {}),
                    "policy": {
                        "protector_code_executed": False,
                        "numeric_key_range_enumerated": False,
                        "final_validation": "normal-iapp-main-entry-decryptor",
                    },
                }
                zi = zipfile.ZipInfo("META-INF/iapt/generic_anti_restore.json", date_time=(1980, 1, 1, 0, 0, 0))
                zi.compress_type = zipfile.ZIP_DEFLATED
                dst.writestr(zi, json.dumps(marker, ensure_ascii=False, indent=2).encode("utf-8"))
            with zipfile.ZipFile(temp, "r") as check:
                restored = check.read("assets/lib.so")
                if restored != container.decoded or len(restored) < 64:
                    raise GenericAntiRestoreError("normalized candidate container self-check failed")
            os.replace(temp, output)
        finally:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                pass

    report = {
        "normalized": True,
        "normalizer": BUILD,
        "analysis_phase": "generic-evidence-fallback",
        "source_apk": apk.name,
        "normalized_apk": str(output),
        "normalized_apk_size": output.stat().st_size,
        "normalized_apk_sha256": _sha256(output.read_bytes()),
        "container_transport_entry": container.entry,
        "container_transform": _transform_public(container.transform),
        "container_score": container.score,
        "container_size": len(container.decoded),
        "container_sha256": container.digest,
        "added_objects": added,
        "resource_plan": {
            "strategy": "generic-evidence-candidate",
            "input": container.entry,
            "operations": [_transform_id(container.transform)],
            "output": "assets/lib.so",
            "confidence": "candidate-requires-main-entry-validation",
        },
    }
    return report


def build_candidates(
    apk_path: Path | str,
    output_root: Path | str,
    options: Optional[Dict[str, Any]] = None,
    prior_report: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    apk = Path(apk_path)
    root = Path(output_root)
    root.mkdir(parents=True, exist_ok=True)
    report: Dict[str, Any] = {
        "build": BUILD,
        "source_apk": apk.name,
        "source_apk_sha256": _sha256(apk.read_bytes()),
        "errors": [],
        "policy": {
            "protector_code_executed": False,
            "numeric_key_range_enumerated": False,
            "max_candidates": MAX_CONTAINER_CANDIDATES,
        },
    }
    if not apk.is_file() or not zipfile.is_zipfile(apk):
        raise GenericAntiRestoreError("generic analyzer input is not an APK/ZIP", report)

    with zipfile.ZipFile(apk, "r") as zf:
        unsafe = [info.filename for info in zf.infolist() if not info.is_dir() and not _safe_name(info.filename)]
        if unsafe:
            report["unsafe_entries"] = unsafe[:20]
            raise GenericAntiRestoreError("APK contains unsafe ZIP paths", report)
        infos = _probe_infos(zf)
        evidence, errors = _collect_evidence(zf, infos)
        report["errors"].extend(errors)
        dex_rows = _dedupe_evidence([row for row in evidence if row.decoded_type == "dex"], MAX_DEX_CANDIDATES)
        elf_rows = _dedupe_evidence([row for row in evidence if row.decoded_type == "elf"], MAX_ELF_CANDIDATES)
        vm_rows = _dedupe_evidence([row for row in evidence if row.decoded_type == "vm"], MAX_VM_CANDIDATES)
        native_vm_transforms = _native_vm_transport_transforms(zf)
        containers = _candidate_containers(zf, infos, evidence, native_vm_transforms)

    report.update({
        "probed_entries": len(infos),
        "evidence_count": len(evidence),
        "evidence_summary": {
            kind: sum(1 for row in evidence if row.decoded_type == kind)
            for kind in sorted({row.decoded_type for row in evidence})
        },
        "dex_candidates": [
            {"entry": row.entry, "score": row.score, "transform": _transform_public(row.transform), "sha256": _sha256(row.decoded), **row.meta}
            for row in dex_rows
        ],
        "elf_candidates": [
            {"entry": row.entry, "score": row.score, "transform": _transform_public(row.transform), "sha256": _sha256(row.decoded), **row.meta}
            for row in elf_rows
        ],
        "vm_candidates": [
            {"entry": row.entry, "score": row.score, "transform": _transform_public(row.transform), "sha256": _sha256(row.decoded), **row.meta}
            for row in vm_rows
        ],
        "native_vm_transport_transforms": [
            {
                "family": row.get("family"),
                "method": row.get("method"),
                "value": row.get("value"),
                "low_byte": row.get("low_byte"),
                "transform": _transform_public(dict(row.get("transform") or {})),
                "votes": row.get("votes"),
                "members": row.get("members"),
                "evidence": row.get("evidence"),
            }
            for row in native_vm_transforms
        ],
        "container_candidates": [
            {
                "entry": row.entry,
                "scope": row.scope,
                "score": row.score,
                "transform": _transform_public(row.transform),
                "size": len(row.decoded),
                "sha256": row.digest,
                "reason": row.reason,
            }
            for row in containers
        ],
    })
    diagnostic_path = root / "generic_analysis_report.json"
    diagnostic_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")

    if not containers:
        raise GenericAntiRestoreError(
            "generic analyzer found no evidence-backed assets/lib.so candidate; report=" + str(diagnostic_path),
            report,
        )
    if not dex_rows and not elf_rows and not vm_rows:
        raise GenericAntiRestoreError(
            "generic analyzer found container candidates but no recoverable DEX/ELF/VM evidence; report=" + str(diagnostic_path),
            report,
        )

    results = []
    for index, container in enumerate(containers, 1):
        output = root / ("generic-candidate-%02d.apk" % index)
        candidate_report = _build_candidate_apk(
            apk,
            output,
            container,
            dex_rows,
            elf_rows,
            vm_rows,
            index,
            prior_report,
        )
        candidate_report["generic_report"] = str(diagnostic_path)
        candidate_report["candidate_count"] = len(containers)
        results.append(candidate_report)
    return results


__all__ = ["BUILD", "GenericAntiRestoreError", "build_candidates"]
