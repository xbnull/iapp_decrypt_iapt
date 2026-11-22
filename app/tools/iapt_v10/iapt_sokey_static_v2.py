#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static sokey extractor for iApp libygsiyu.so.

The server-sokey feature uses this module. It never generates timestamp
candidates and never invokes the 180000-item manual enumeration path.

Supported paths:
1. Plain ELF: find the exact 32-byte sokey in the file image.
2. QiuShui/Tosks packed AArch64 ELF: unpack the embedded UPX-like first LOAD
   segment in a constrained Unicorn emulator, then find the exact sokey.

The packed path emulates only the decompressor dispatcher extracted from the
packer stub. It does not execute the APK, JNI code, constructors, or the
unpacked application code.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import lzma
import os
import re
import struct
import sys
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

SOKEY_SUFFIX = b"Q" * 10 + b"W" * 10 + b"EE"
SOKEY_STRICT_RE = re.compile(rb"[A-F0-9]{10}Q{10}W{10}EE")
SOKEY_RELAXED_RE = re.compile(rb"[A-Za-z0-9]{10}Q{10}W{10}EE")
MAX_SO_SIZE = 128 * 1024 * 1024
MAX_FIRST_LOAD = 128 * 1024 * 1024
MAX_STAGE1_SIZE = 2 * 1024 * 1024

_CACHE: Dict[str, Tuple[bytes, Dict[str, object]]] = {}


class SokeyStaticError(RuntimeError):
    pass


def _align_up(value: int, alignment: int = 0x1000) -> int:
    return (int(value) + alignment - 1) & ~(alignment - 1)


def _find_exact_sokeys(data: bytes) -> List[Tuple[bytes, int]]:
    rows: List[Tuple[bytes, int]] = []
    seen = set()
    for regex in (SOKEY_STRICT_RE, SOKEY_RELAXED_RE):
        for match in regex.finditer(data):
            value = bytes(match.group(0))
            if value in seen:
                continue
            seen.add(value)
            rows.append((value, int(match.start())))
    return rows


def _nrv2_like_decompress(source: bytes, max_output: int) -> bytes:
    """Translate the packer's AArch64 method-2 NRV decoder."""
    source = bytes(source)
    ip = 0
    output = bytearray()
    bit_state = 0x80000000
    last_offset = -1

    def get_bit() -> int:
        nonlocal ip, bit_state
        total = bit_state + bit_state
        carry = 1 if total > 0xFFFFFFFF else 0
        bit_state = total & 0xFFFFFFFF
        if bit_state != 0:
            return carry
        if ip + 4 > len(source):
            raise SokeyStaticError("packed NRV stream ended in a bit word")
        word = struct.unpack_from("<I", source, ip)[0]
        ip += 4
        total = word + word + carry
        carry2 = 1 if total > 0xFFFFFFFF else 0
        bit_state = total & 0xFFFFFFFF
        return carry2

    def get_gamma() -> int:
        value = 1
        while True:
            value = ((value << 1) + get_bit()) & 0xFFFFFFFF
            if get_bit() == 1:
                return value

    steps = 0
    while True:
        steps += 1
        if steps > 20_000_000:
            raise SokeyStaticError("packed NRV stream exceeded step limit")
        if get_bit() == 1:
            if ip >= len(source):
                raise SokeyStaticError("packed NRV stream ended in a literal")
            output.append(source[ip])
            ip += 1
            if len(output) > max_output:
                raise SokeyStaticError("packed NRV output exceeded limit")
            continue

        value = get_gamma()
        if value >= 3:
            if ip >= len(source):
                raise SokeyStaticError("packed NRV stream ended in an offset")
            encoded = source[ip] | ((value - 3) << 8)
            ip += 1
            raw_offset = (~encoded) & 0xFFFFFFFF
            if raw_offset == 0:
                break
            last_offset = (
                raw_offset - (1 << 32)
                if raw_offset & 0x80000000
                else raw_offset
            )

        offset = last_offset
        length = (get_bit() << 1) | get_bit()
        if length == 0:
            length = get_gamma() + 2
        if offset < -0xD00:
            length += 1

        count = length + 1
        for _ in range(count):
            source_index = len(output) + offset
            if source_index < 0 or source_index >= len(output):
                raise SokeyStaticError(
                    "packed NRV stream referenced an invalid back offset"
                )
            output.append(output[source_index])
            if len(output) > max_output:
                raise SokeyStaticError("packed NRV output exceeded limit")

    return bytes(output)


def _parse_elf64_aarch64(data: bytes) -> Dict[str, object]:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise SokeyStaticError("not an ELF file")
    if data[4] != 2 or data[5] != 1:
        raise SokeyStaticError("only little-endian ELF64 is supported here")
    fields = struct.unpack_from("<16sHHIQQQIHHHHHH", data, 0)
    machine = int(fields[2])
    if machine != 183:
        raise SokeyStaticError("packed static unpack currently expects AArch64")
    phoff = int(fields[5])
    phentsize = int(fields[9])
    phnum = int(fields[10])
    if phentsize < 56 or phnum <= 0 or phnum > 128:
        raise SokeyStaticError("invalid ELF program-header table")
    if phoff + phentsize * phnum > len(data):
        raise SokeyStaticError("ELF program-header table is truncated")
    phdrs = []
    for index in range(phnum):
        offset = phoff + index * phentsize
        phdrs.append(struct.unpack_from("<IIQQQQQQ", data, offset))
    return {
        "entry": int(fields[4]),
        "phdrs": phdrs,
    }


def _find_stage1(so_data: bytes, entry: int) -> Tuple[bytes, Dict[str, int]]:
    scan_start = max(0, int(entry))
    scan_end = min(len(so_data) - 12, scan_start + 0x5000)
    for offset in range(scan_start, max(scan_start, scan_end) + 1, 4):
        out_size, compressed_size, method_word = struct.unpack_from(
            "<III", so_data, offset
        )
        if (method_word & 0xFF) != 2:
            continue
        if not (0x400 <= out_size <= MAX_STAGE1_SIZE):
            continue
        if not (64 <= compressed_size <= len(so_data) - offset - 12):
            continue
        try:
            stage = _nrv2_like_decompress(
                so_data[offset + 12 : offset + 12 + compressed_size],
                max_output=out_size,
            )
        except Exception:
            continue
        if len(stage) != out_size:
            continue
        dispatcher = _find_unpack_dispatcher(stage)
        if dispatcher is None:
            continue
        return stage, {
            "stage_header_offset": offset,
            "stage_output_size": out_size,
            "stage_compressed_size": compressed_size,
            "dispatcher_offset": dispatcher,
        }
    raise SokeyStaticError("UPX-like AArch64 decompressor stage was not found")


def _find_unpack_dispatcher(stage: bytes) -> Optional[int]:
    cmp_method2 = b"\x9f\x08\x00\x71"  # cmp w4, #2
    cmp_method14 = b"\x9f\x38\x00\x71"  # cmp w4, #14
    start = 0
    while True:
        pos = stage.find(cmp_method2, start)
        if pos < 0:
            return None
        second = stage.find(cmp_method14, pos + 4, min(len(stage), pos + 0x200))
        if second >= 0:
            return pos
        start = pos + 4



def _decompress_method14_lzma(compressed: bytes, expected_output: int) -> bytes:
    """Decode the packer method-14 raw LZMA1 stream from its stage format."""
    raw = bytes(compressed or b"")
    if len(raw) < 3:
        raise SokeyStaticError("packed LZMA method 14 stream is truncated")
    prop0, prop1 = raw[0], raw[1]
    pb = prop0 & 0x07
    sum_lclp = prop0 >> 3
    lc = prop1 & 0x0F
    lp = prop1 >> 4
    if pb > 4 or lc > 8 or lp > 4 or lc + lp != sum_lclp or lc + lp > 4:
        raise SokeyStaticError("packed LZMA method 14 properties are invalid")
    if expected_output <= 0 or expected_output > MAX_FIRST_LOAD:
        raise SokeyStaticError("packed LZMA output size is outside the safety limit")
    dict_size = 1 << max(20, (int(expected_output) - 1).bit_length())
    dict_size = min(dict_size, 1 << 28)
    try:
        decoder = lzma.LZMADecompressor(
            format=lzma.FORMAT_RAW,
            filters=[{
                "id": lzma.FILTER_LZMA1,
                "dict_size": dict_size,
                "lc": lc,
                "lp": lp,
                "pb": pb,
            }],
        )
        output = decoder.decompress(raw[2:], max_length=int(expected_output))
    except lzma.LZMAError as exc:
        raise SokeyStaticError("packed LZMA method 14 decode failed") from exc
    if len(output) != int(expected_output):
        raise SokeyStaticError(
            "packed LZMA method 14 returned %d bytes, expected %d"
            % (len(output), int(expected_output))
        )
    return output

def _emulate_unpack_method(
    stage: bytes,
    dispatcher_offset: int,
    compressed: bytes,
    expected_output: int,
    method: int,
) -> bytes:
    try:
        from unicorn import (
            Uc,
            UC_ARCH_ARM64,
            UC_HOOK_INTR,
            UC_MODE_ARM,
            UC_PROT_ALL,
        )
        from unicorn.arm64_const import (
            UC_ARM64_REG_PC,
            UC_ARM64_REG_SP,
            UC_ARM64_REG_W1,
            UC_ARM64_REG_W4,
            UC_ARM64_REG_X0,
            UC_ARM64_REG_X2,
            UC_ARM64_REG_X3,
            UC_ARM64_REG_X30,
        )
    except ModuleNotFoundError:
        # The decryptor is intentionally launched with ``python -S``.  In that
        # mode venv site-packages are not added automatically, so expose only
        # this interpreter's own purelib/platlib directories and retry.
        import sysconfig

        version_dir = "python%d.%d" % (sys.version_info.major, sys.version_info.minor)
        executable_prefix = Path(sys.executable).parent.parent
        candidates = {
            sysconfig.get_paths().get("purelib"),
            sysconfig.get_paths().get("platlib"),
            str(executable_prefix / "lib" / version_dir / "site-packages"),
            str(executable_prefix / "lib64" / version_dir / "site-packages"),
        }
        virtual_env = os.environ.get("VIRTUAL_ENV")
        if virtual_env:
            candidates.add(str(Path(virtual_env) / "lib" / version_dir / "site-packages"))
            candidates.add(str(Path(virtual_env) / "lib64" / version_dir / "site-packages"))
        for candidate in candidates:
            if candidate and Path(candidate).is_dir() and candidate not in sys.path:
                sys.path.append(candidate)
        try:
            from unicorn import (
                Uc,
                UC_ARCH_ARM64,
                UC_HOOK_INTR,
                UC_MODE_ARM,
                UC_PROT_ALL,
            )
            from unicorn.arm64_const import (
                UC_ARM64_REG_PC,
                UC_ARM64_REG_SP,
                UC_ARM64_REG_W1,
                UC_ARM64_REG_W4,
                UC_ARM64_REG_X0,
                UC_ARM64_REG_X2,
                UC_ARM64_REG_X3,
                UC_ARM64_REG_X30,
            )
        except Exception as exc:
            raise SokeyStaticError(
                "packed libygsiyu.so requires the bundled unicorn runtime"
            ) from exc
    except Exception as exc:
        raise SokeyStaticError(
            "packed libygsiyu.so requires the bundled unicorn runtime"
        ) from exc

    if expected_output <= 0 or expected_output > MAX_FIRST_LOAD:
        raise SokeyStaticError("packed output size is outside the safety limit")

    code_base = 0x01000000
    stack_base = 0x03000000
    source_base = 0x05000000
    output_base = 0x08000000
    length_base = 0x10000000
    stop_base = 0x11000000

    emulator = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    emulator.mem_map(code_base, _align_up(len(stage)), UC_PROT_ALL)
    emulator.mem_map(stack_base - 0x200000, 0x400000, UC_PROT_ALL)
    emulator.mem_map(source_base, _align_up(len(compressed)), UC_PROT_ALL)
    emulator.mem_map(output_base, _align_up(expected_output), UC_PROT_ALL)
    emulator.mem_map(length_base, 0x1000, UC_PROT_ALL)
    emulator.mem_map(stop_base, 0x1000, UC_PROT_ALL)

    emulator.mem_write(code_base, stage)
    emulator.mem_write(source_base, compressed)
    emulator.mem_write(length_base, struct.pack("<I", expected_output))
    emulator.mem_write(stop_base, struct.pack("<I", 0xD4200000))  # brk #0

    emulator.reg_write(UC_ARM64_REG_X0, source_base)
    emulator.reg_write(UC_ARM64_REG_W1, len(compressed))
    emulator.reg_write(UC_ARM64_REG_X2, output_base)
    emulator.reg_write(UC_ARM64_REG_X3, length_base)
    emulator.reg_write(UC_ARM64_REG_W4, int(method))
    emulator.reg_write(UC_ARM64_REG_SP, stack_base)
    emulator.reg_write(UC_ARM64_REG_X30, stop_base)

    interrupt = {"number": None, "pc": None}

    def _on_interrupt(uc, number, _user):
        interrupt["number"] = int(number)
        interrupt["pc"] = int(uc.reg_read(UC_ARM64_REG_PC))
        uc.emu_stop()

    emulator.hook_add(UC_HOOK_INTR, _on_interrupt)
    emulator.emu_start(
        code_base + int(dispatcher_offset),
        stop_base,
        timeout=20_000_000,
        count=120_000_000,
    )

    pc = int(emulator.reg_read(UC_ARM64_REG_PC))
    actual = struct.unpack("<I", bytes(emulator.mem_read(length_base, 4)))[0]
    if interrupt["number"] is not None:
        raise SokeyStaticError(
            "packed decompressor aborted at pc=0x%x interrupt=%s"
            % (int(interrupt["pc"] or 0), interrupt["number"])
        )
    if pc != stop_base:
        raise SokeyStaticError(
            "packed decompressor timed out or exceeded its instruction limit"
        )
    if actual != expected_output:
        raise SokeyStaticError(
            "packed decompressor returned %d bytes, expected %d"
            % (actual, expected_output)
        )
    return bytes(emulator.mem_read(output_base, actual))


def _unpack_qiushui_first_load(so_data: bytes) -> Tuple[bytes, Dict[str, object]]:
    outer = _parse_elf64_aarch64(so_data)
    entry = int(outer["entry"])
    if entry < 0x10 or entry > len(so_data):
        raise SokeyStaticError("packed ELF entry point is invalid")

    metadata_offset = entry - 0x10
    if metadata_offset + 16 > len(so_data):
        raise SokeyStaticError("packed ELF metadata is truncated")
    meta0, _original_entry, packed_start, packed_start_copy = struct.unpack_from(
        "<IIII", so_data, metadata_offset
    )
    if meta0 != metadata_offset or packed_start != packed_start_copy:
        raise SokeyStaticError("UPX-like packed metadata signature did not match")
    if packed_start < 0x40 or packed_start + 0x24 > len(so_data):
        raise SokeyStaticError("packed payload offset is invalid")

    stage, stage_meta = _find_stage1(so_data, entry)

    header_offset = packed_start + 0x18
    header_output, header_compressed, header_method_word = struct.unpack_from(
        "<III", so_data, header_offset
    )
    if (header_method_word & 0xFF) != 2:
        raise SokeyStaticError("packed original ELF header is not method 2")
    header_payload_start = header_offset + 12
    header_payload_end = header_payload_start + header_compressed
    if header_payload_end > len(so_data):
        raise SokeyStaticError("packed original ELF header is truncated")
    original_header = _nrv2_like_decompress(
        so_data[header_payload_start:header_payload_end],
        max_output=header_output,
    )
    if len(original_header) != header_output:
        raise SokeyStaticError("original ELF header output size did not match")

    original = _parse_elf64_aarch64(original_header)
    first_load = next(
        (row for row in original["phdrs"] if int(row[0]) == 1),
        None,
    )
    if first_load is None:
        raise SokeyStaticError("original ELF does not contain a PT_LOAD")
    first_vaddr = int(first_load[3])
    first_filesz = int(first_load[5])
    if first_filesz <= 0 or first_filesz > MAX_FIRST_LOAD:
        raise SokeyStaticError("original first PT_LOAD size is invalid")

    body_header_offset = header_payload_end
    if body_header_offset + 12 > len(so_data):
        raise SokeyStaticError("packed original body header is truncated")
    body_output, body_compressed, body_method_word = struct.unpack_from(
        "<III", so_data, body_header_offset
    )
    body_method = body_method_word & 0xFF
    body_payload_start = body_header_offset + 12
    body_payload_end = body_payload_start + body_compressed
    if body_payload_end > len(so_data):
        raise SokeyStaticError("packed original body is truncated")

    target_offset = first_vaddr + first_filesz - int(body_output)
    if target_offset < 0 or target_offset > first_filesz:
        raise SokeyStaticError("packed original body target offset is invalid")

    if body_method == 2:
        unpacked_body = _nrv2_like_decompress(
            so_data[body_payload_start:body_payload_end],
            max_output=body_output,
        )
    elif body_method == 14:
        unpacked_body = _decompress_method14_lzma(
            so_data[body_payload_start:body_payload_end],
            int(body_output),
        )
    else:
        unpacked_body = _emulate_unpack_method(
            stage,
            int(stage_meta["dispatcher_offset"]),
            so_data[body_payload_start:body_payload_end],
            int(body_output),
            int(body_method),
        )
    if len(unpacked_body) != body_output:
        raise SokeyStaticError("packed original body output size did not match")

    first_image = bytearray(first_filesz)
    # Rebuild a parseable view of the original first PT_LOAD.  Older versions
    # only kept the packed outer prefix because sokey extraction scanned raw
    # bytes and did not need ELF metadata.  Dynamic-key recovery does need the
    # original ELF/program/section headers, so prefer the decompressed original
    # header and only use outer bytes for any uncovered gap.
    header_length = min(target_offset, len(original_header), first_filesz)
    first_image[:header_length] = original_header[:header_length]
    if header_length < target_offset:
        gap_end = min(target_offset, len(so_data), first_filesz)
        first_image[header_length:gap_end] = so_data[header_length:gap_end]
    first_image[target_offset : target_offset + len(unpacked_body)] = unpacked_body

    metadata: Dict[str, object] = {
        "strategy": "packed-upx-aarch64-first-load-v2",
        "outer_entry": entry,
        "packed_start": packed_start,
        "original_first_load_size": first_filesz,
        "unpacked_body_size": len(unpacked_body),
        "unpacked_body_offset": target_offset,
        "body_method": body_method,
    }
    metadata.update(stage_meta)
    return bytes(first_image), metadata


def extract_sokey_from_so_bytes(
    so_data: bytes,
    label: str = "libygsiyu.so",
) -> Tuple[bytes, Dict[str, object]]:
    so_data = bytes(so_data)
    if not so_data or len(so_data) > MAX_SO_SIZE:
        raise SokeyStaticError("libygsiyu.so size is invalid")

    digest = hashlib.sha256(so_data).hexdigest()
    cached = _CACHE.get(digest)
    if cached is not None:
        value, metadata = cached
        return value, dict(metadata)

    plain = _find_exact_sokeys(so_data)
    if plain:
        unique = {row[0] for row in plain}
        if len(unique) != 1:
            raise SokeyStaticError(
                "%s contains multiple conflicting plaintext sokeys" % label
            )
        value = next(iter(unique))
        offset = next(row[1] for row in plain if row[0] == value)
        metadata = {
            "strategy": "plain-elf-string-v2",
            "offset": offset,
            "so_sha256": digest,
            "label": label,
        }
        _CACHE[digest] = (value, dict(metadata))
        return value, metadata

    # Old iApp has no 32-byte Q/W suffix key.  Its four-character sokey is a
    # plaintext NUL string immediately before the old loadfilecode "aa", "lib.so"
    # sequence.  Keep this branch separate from all V3 extraction logic.
    try:
        try:
            from .iapp_old_decrypt import extract_legacy_sokey_from_so_bytes
        except Exception:
            from iapp_old_decrypt import extract_legacy_sokey_from_so_bytes  # type: ignore
        legacy_value, legacy_meta = extract_legacy_sokey_from_so_bytes(so_data, label)
        value = legacy_value.encode("ascii")
        metadata = dict(legacy_meta)
        metadata.setdefault("so_sha256", digest)
        metadata.setdefault("label", label)
        _CACHE[digest] = (value, dict(metadata))
        return value, metadata
    except Exception:
        pass

    unpacked, unpack_meta = _unpack_qiushui_first_load(so_data)
    rows = _find_exact_sokeys(unpacked)
    if not rows:
        raise SokeyStaticError(
            "%s was unpacked but no exact sokey was found" % label
        )
    unique = {row[0] for row in rows}
    if len(unique) != 1:
        raise SokeyStaticError(
            "%s unpacked to multiple conflicting sokeys" % label
        )
    value = next(iter(unique))
    offset = next(row[1] for row in rows if row[0] == value)
    metadata = {
        **unpack_meta,
        "offset": offset,
        "so_sha256": digest,
        "label": label,
    }
    _CACHE[digest] = (value, dict(metadata))
    return value, metadata


def _ygsiyu_entries(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    rows = []
    for info in zf.infolist():
        name = info.filename.replace("\\", "/").lower()
        if info.is_dir():
            continue
        if name == "libygsiyu.so" or (
            name.startswith("lib/") and name.endswith("/libygsiyu.so")
        ):
            rows.append(info)
    abi_priority = {
        "x86": 0,
        "x86_64": 1,
        "armeabi-v7a": 2,
        "arm64-v8a": 3,
    }

    def order(info: zipfile.ZipInfo):
        parts = info.filename.replace("\\", "/").split("/")
        abi = parts[-2].lower() if len(parts) >= 2 else ""
        return (abi_priority.get(abi, 99), info.filename.lower())

    rows.sort(key=order)
    return rows


def extract_sokey_from_apk(
    apk_path: Path | str,
) -> Tuple[bytes, Dict[str, object]]:
    apk_path = Path(apk_path)
    results: List[Tuple[bytes, Dict[str, object]]] = []
    errors: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        entries = _ygsiyu_entries(zf)
        if not entries:
            raise SokeyStaticError("APK does not contain libygsiyu.so")
        for info in entries:
            if info.file_size <= 0 or info.file_size > MAX_SO_SIZE:
                errors.append("%s: invalid size" % info.filename)
                continue
            try:
                value, metadata = extract_sokey_from_so_bytes(
                    zf.read(info),
                    label=info.filename,
                )
                metadata["apk_entry"] = info.filename
                results.append((value, metadata))
            except Exception as exc:
                errors.append(
                    "%s: %s: %s"
                    % (info.filename, type(exc).__name__, exc)
                )

    if not results:
        raise SokeyStaticError(
            "server static sokey analysis failed: " + " | ".join(errors)
        )
    # New V3 keys must normally agree across ABIs.  Old iApp APKs sometimes
    # ship a stale x86_64 fallback library (for example atv6) while every mobile
    # ABI and x86 use the real four-character key.  Select a mobile consensus
    # only for the explicitly identified old family; never apply that rule to
    # the 32-byte V3 key format.
    families = {str((meta or {}).get("family") or "") for _, meta in results}
    legacy = families and all(f == "old-iapp-4char" for f in families)
    if legacy:
        weights = {"arm64-v8a": 8, "armeabi-v7a": 8, "armeabi": 6, "x86": 4, "x86_64": 1, "unknown": 1}
        totals = {}
        mobile = set()
        def _abi(meta):
            name = str((meta or {}).get("apk_entry") or "").replace("\\", "/").lower()
            for part in name.split("/"):
                if part in weights:
                    return part
            return "unknown"
        for item, meta in results:
            abi = _abi(meta)
            totals[item] = totals.get(item, 0) + weights.get(abi, 1)
            if abi in ("arm64-v8a", "armeabi-v7a", "armeabi"):
                mobile.add(item)
        if len(mobile) > 1:
            raise SokeyStaticError("mobile ABI old-iApp sokey mismatch")
        value = next(iter(mobile)) if mobile else sorted(totals, key=lambda x: (-totals[x], x))[0]
        selected = dict(next(meta for item, meta in results if item == value))
        selected["strategy"] = "old-iapp-multi-abi-mobile-consensus-v1"
        selected["weighted_totals"] = {k.decode("ascii", "replace"): v for k, v in totals.items()}
        selected["mismatched_entries"] = [
            "%s=%s" % (meta.get("apk_entry"), item.decode("ascii", "replace"))
            for item, meta in results if item != value
        ]
    else:
        unique = {row[0] for row in results}
        if len(unique) != 1:
            details = [
                "%s=%s"
                % (row[1].get("apk_entry"), row[0].decode("ascii", "replace"))
                for row in results
            ]
            raise SokeyStaticError(
                "multi-ABI sokey mismatch: " + " | ".join(details)
            )
        value = next(iter(unique))
        selected = dict(next(metadata for item, metadata in results if item == value))
    selected["successful_entries"] = [
        metadata.get("apk_entry") for item, metadata in results if item == value
    ]
    selected["failed_entries"] = errors
    selected["sokey"] = value.decode("ascii", "replace")
    return value, selected


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--so", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    if args.so:
        value, metadata = extract_sokey_from_so_bytes(
            args.input.read_bytes(), label=args.input.name
        )
    else:
        value, metadata = extract_sokey_from_apk(args.input)
    result = {
        "sokey": value.decode("ascii", "replace"),
        "metadata": metadata,
    }
    if args.json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    else:
        print(result["sokey"])


if __name__ == "__main__":
    main()
