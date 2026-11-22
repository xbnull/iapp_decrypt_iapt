#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static unpacker for the BMP-parity -> RC4 -> zlib native wrapper family.

The wrapper keeps the real iApp native module as an encrypted compressed blob
inside libygsiyu.so.  A small embedded BMP stores the RC4 key in the parity of
pixel bytes.  This module never executes APK code.  It restores only the inner
native bytes and extracts exact normal-decrypt constants when their construction
is structurally visible.
"""
from __future__ import annotations

import hashlib
import math
import re
import struct
import zipfile
import zlib
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

_BUILD = "bmp-parity-rc4-zlib-native-v1"
_HIDDEN_RE = re.compile(rb"[A-Za-z0-9]{10}Q{10}W{10}EE")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _rc4(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty RC4 key")
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xFF
        s[i], s[j] = s[j], s[i]
    out = bytearray(len(data))
    i = j = 0
    for pos, value in enumerate(data):
        i = (i + 1) & 0xFF
        j = (j + s[i]) & 0xFF
        s[i], s[j] = s[j], s[i]
        out[pos] = value ^ s[(s[i] + s[j]) & 0xFF]
    return bytes(out)


def _valid_zlib_header(cmf: int, flg: int) -> bool:
    return (cmf & 0x0F) == 8 and ((cmf << 8) | flg) % 31 == 0


def _iter_bmp_keys(data: bytes) -> Iterable[Tuple[int, int, bytes, Dict[str, int]]]:
    """Yield (offset, size, key, metadata) for structurally valid key BMPs."""
    pos = data.find(b"BM")
    while pos >= 0:
        try:
            if pos + 54 > len(data):
                raise ValueError
            size = struct.unpack_from("<I", data, pos + 2)[0]
            key_len = struct.unpack_from("<H", data, pos + 6)[0]
            pixel_off = struct.unpack_from("<I", data, pos + 10)[0]
            dib = struct.unpack_from("<I", data, pos + 14)[0]
            width = struct.unpack_from("<i", data, pos + 18)[0]
            height = struct.unpack_from("<i", data, pos + 22)[0]
            planes = struct.unpack_from("<H", data, pos + 26)[0]
            bpp = struct.unpack_from("<H", data, pos + 28)[0]
            if not (54 <= size <= len(data) - pos):
                raise ValueError
            if dib not in (40, 52, 56, 108, 124) or planes != 1:
                raise ValueError
            if not (1 <= abs(width) <= 4096 and 1 <= abs(height) <= 4096):
                raise ValueError
            if bpp not in (8, 16, 24, 32):
                raise ValueError
            if not (1 <= key_len <= 64 and pixel_off + key_len * 8 <= size):
                raise ValueError
            pixels = data[pos + pixel_off:pos + size]
            key = bytearray()
            for index in range(key_len):
                value = 0
                for pixel_byte in pixels[index * 8:(index + 1) * 8]:
                    value = (value << 1) | (int(pixel_byte).bit_count() & 1)
                key.append(value)
            if not key or len(set(key)) < 3:
                raise ValueError
            yield pos, size, bytes(key), {
                "width": width,
                "height": height,
                "bpp": bpp,
                "pixel_offset": pixel_off,
                "key_length": key_len,
            }
        except Exception:
            pass
        pos = data.find(b"BM", pos + 1)


def _unpack_blob_with_key(data: bytes, key: bytes) -> Optional[Tuple[int, bytes, int]]:
    """Find the unique RC4 stream whose plaintext is <u32 size> + zlib."""
    prefix_stream = _rc4(b"\x00" * 6, key)
    candidates: List[Tuple[int, int]] = []
    end = len(data) - 6
    for off in range(max(0, end)):
        expected_size = int.from_bytes(
            bytes(data[off + i] ^ prefix_stream[i] for i in range(4)),
            "little",
        )
        if not (4096 <= expected_size <= 64 * 1024 * 1024):
            continue
        cmf = data[off + 4] ^ prefix_stream[4]
        flg = data[off + 5] ^ prefix_stream[5]
        if cmf == 0x78 and _valid_zlib_header(cmf, flg):
            candidates.append((off, expected_size))
    for off, expected_size in candidates:
        decrypted = _rc4(data[off:], key)
        if int.from_bytes(decrypted[:4], "little") != expected_size:
            continue
        try:
            obj = zlib.decompressobj()
            plain = obj.decompress(decrypted[4:], expected_size + 1)
            plain += obj.flush()
        except Exception:
            continue
        if not obj.eof or len(plain) != expected_size:
            continue
        consumed = len(decrypted[4:]) - len(obj.unused_data)
        if len(plain) < 0x1000:
            continue
        return off, plain, 4 + consumed
    return None


def _arm64_mov_imm_w(insn: int) -> Optional[Tuple[int, int]]:
    if (insn & 0x7F800000) == 0x52800000:  # MOVZ Wd,#imm
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 3
        return rd, ((imm16 << (16 * hw)) & 0xFFFFFFFF) & 0xFF
    if (insn & 0x7F800000) == 0x12800000:  # MOVN Wd,#imm
        rd = insn & 0x1F
        imm16 = (insn >> 5) & 0xFFFF
        hw = (insn >> 21) & 3
        return rd, (~(imm16 << (16 * hw)) & 0xFFFFFFFF) & 0xFF
    return None


def _arm64_strb_unsigned(insn: int) -> Optional[Tuple[int, int, int]]:
    if (insn & 0xFFC00000) != 0x39000000:
        return None
    return insn & 0x1F, (insn >> 5) & 0x1F, (insn >> 10) & 0xFFF


def _high_entropy_key(blob: bytes) -> bool:
    if not (16 <= len(blob) <= 96) or b"\x00" in blob:
        return False
    unique = len(set(blob))
    if unique < min(12, len(blob) // 2):
        return False
    counts = Counter(blob)
    entropy = -sum((n / len(blob)) * math.log2(n / len(blob)) for n in counts.values())
    return entropy >= 3.5


def _extract_arm64_constructed_tables(data: bytes) -> List[Dict[str, object]]:
    """Recover NUL-terminated byte tables built with MOV/MOVN + STRB."""
    registers: Dict[int, int] = {}
    stores: List[Tuple[int, int, int, int, int]] = []
    for off in range(0, len(data) - 3, 4):
        insn = struct.unpack_from("<I", data, off)[0]
        moved = _arm64_mov_imm_w(insn)
        if moved is not None:
            registers[moved[0]] = moved[1]
            continue
        stored = _arm64_strb_unsigned(insn)
        if stored is None:
            continue
        rt, rn, imm = stored
        if rt == 31:
            value = 0
        elif rt in registers:
            value = registers[rt]
        else:
            continue
        stores.append((off // 4, rn, imm, value & 0xFF, off))

    occurrences: List[Tuple[int, int, bytes]] = []
    seen_occurrence = set()
    for start in range(len(stores)):
        base_index, base_register, _imm, _value, _va = stores[start]
        values: Dict[int, int] = {}
        locations: Dict[int, int] = {}
        for insn_index, rn, imm, value, va in stores[start:]:
            if insn_index - base_index > 420:
                break
            if rn != base_register:
                continue
            values[imm] = value
            locations[imm] = va
        if len(values) < 17:
            continue
        offsets = sorted(values)
        runs: List[List[int]] = []
        current: List[int] = []
        last = None
        for item in offsets:
            if last is None or item == last + 1:
                current.append(item)
            else:
                if current:
                    runs.append(current)
                current = [item]
            last = item
        if current:
            runs.append(current)
        for run in runs:
            if len(run) < 17:
                continue
            raw = bytes(values[item] for item in run)
            if not raw.endswith(b"\x00"):
                continue
            key = raw[:-1]
            if not _high_entropy_key(key):
                continue
            first_va = min(locations[item] for item in run)
            occurrence_key = (first_va, key)
            if occurrence_key in seen_occurrence:
                continue
            seen_occurrence.add(occurrence_key)
            occurrences.append((first_va, base_register, key))

    counts = Counter(key for _va, _base_register, key in occurrences)
    first_va: Dict[bytes, int] = {}
    base_registers: Dict[bytes, set] = {}
    for va, base_register, key in occurrences:
        first_va[key] = min(first_va.get(key, va), va)
        base_registers.setdefault(key, set()).add(int(base_register))
    rows = [
        {
            "key": key,
            "length": len(key),
            "occurrences": int(count),
            "first_offset": int(first_va[key]),
            "base_registers": sorted(base_registers.get(key) or []),
        }
        for key, count in counts.items()
    ]
    rows.sort(key=lambda row: (-int(row["occurrences"]), -int(row["length"]), int(row["first_offset"])))
    # Starting the local data-flow window at a later STRB can reconstruct a
    # strict suffix of the same C-string.  Keep only maximal tables for the
    # same storage class so suffixes cannot become fake key candidates.
    maximal=[]
    for row in rows:
        key=bytes(row["key"])
        regs=tuple(row.get("base_registers") or [])
        if any(
            tuple(other.get("base_registers") or []) == regs
            and len(bytes(other["key"])) > len(key)
            and bytes(other["key"]).endswith(key)
            for other in rows
        ):
            continue
        maximal.append(row)
    return maximal


def _select_key_pairs(tables: List[Dict[str, object]]) -> List[Tuple[bytes, bytes]]:
    if not tables:
        return []
    # In this wrapper family the SLKY post table is materialized in a stack
    # C-string (STRB base register SP/x31), while burden1b's repeating XOR
    # table is materialized in a heap buffer.  This structural distinction is
    # stable across duplicated overloads and avoids ranking by occurrence count.
    posts = [row for row in tables if 31 in (row.get("base_registers") or [])]
    xors = [row for row in tables if any(int(reg) != 31 for reg in (row.get("base_registers") or []))]
    if not posts:
        posts = tables[:2]
    if not xors:
        xors = [row for row in tables if row not in posts] or tables
    pairs: List[Tuple[bytes, bytes]] = []
    for post in posts[:4]:
        for xor in xors[:8]:
            p = bytes(post["key"])
            x = bytes(xor["key"])
            if p == x:
                continue
            pair = (p, x)
            if pair not in pairs:
                pairs.append(pair)
    return pairs


def unpack_native_wrapper(data: bytes) -> Optional[Dict[str, object]]:
    """Return exact inner-module/profile evidence, or None when unsupported."""
    if not data or len(data) < 0x10000:
        return None
    for bmp_offset, bmp_size, rc4_key, bmp_meta in _iter_bmp_keys(data):
        unpacked = _unpack_blob_with_key(data, rc4_key)
        if unpacked is None:
            continue
        blob_offset, inner, encrypted_size = unpacked
        hidden_candidates: List[bytes] = []
        for match in _HIDDEN_RE.finditer(inner):
            value = match.group(0)
            if value not in hidden_candidates:
                hidden_candidates.append(value)
        tables = _extract_arm64_constructed_tables(inner)
        key_pairs = _select_key_pairs(tables)
        # The family is accepted only when the compressed module, normal hidden
        # constant and two distinct constructed normal-decrypt tables all agree.
        if not hidden_candidates or not key_pairs:
            continue
        return {
            "build": _BUILD,
            "inner_data": inner,
            "inner_size": len(inner),
            "inner_sha256": _sha256(inner),
            "blob_offset": blob_offset,
            "encrypted_stream_size": encrypted_size,
            "bmp_offset": bmp_offset,
            "bmp_size": bmp_size,
            "bmp": bmp_meta,
            "rc4_key": rc4_key,
            "rc4_key_sha256": _sha256(rc4_key),
            "hidden_candidates": hidden_candidates,
            "tables": tables,
            "key_pairs": key_pairs,
        }
    return None


def inspect_apk(apk_path: Path | str) -> Optional[Dict[str, object]]:
    apk = Path(apk_path)
    if not apk.is_file() or not zipfile.is_zipfile(apk):
        return None
    with zipfile.ZipFile(apk, "r") as archive:
        names = [
            info.filename for info in archive.infolist()
            if not info.is_dir() and info.filename.replace("\\", "/").lower().endswith("/libygsiyu.so")
        ]
        preferred = sorted(names, key=lambda name: (0 if "arm64-v8a" in name.lower() else 1, name))
        for name in preferred:
            data = archive.read(name)
            result = unpack_native_wrapper(data)
            if result is None:
                continue
            return {
                "build": _BUILD,
                "native_entry": name,
                "native_sha256": _sha256(data),
                "inner_size": int(result["inner_size"]),
                "inner_sha256": str(result["inner_sha256"]),
                "blob_offset": int(result["blob_offset"]),
                "encrypted_stream_size": int(result["encrypted_stream_size"]),
                "bmp_offset": int(result["bmp_offset"]),
                "bmp_size": int(result["bmp_size"]),
                "rc4_key_length": len(bytes(result["rc4_key"])),
                "rc4_key_sha256": str(result["rc4_key_sha256"]),
                "hidden_count": len(result["hidden_candidates"]),
                "table_count": len(result["tables"]),
                "key_pair_count": len(result["key_pairs"]),
            }
    return None
