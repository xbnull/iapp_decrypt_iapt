#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import hashlib
import json
import math
import re
import struct
import sys
import zipfile
from collections import Counter, defaultdict
from pathlib import Path
from typing import Dict, List, Tuple

BUILD = "packed-dynamic-aarch64-v282"
MAX_SO_SIZE = 128 * 1024 * 1024


class PackedDynamicError(ValueError):
    pass


def _load_unpacker():
    try:
        from .iapt_sokey_static_v2 import _unpack_qiushui_first_load
        return _unpack_qiushui_first_load
    except (ImportError, ValueError):
        tool_dir = str(Path(__file__).resolve().parent)
        if tool_dir not in sys.path:
            sys.path.insert(0, tool_dir)
        from iapt_sokey_static_v2 import _unpack_qiushui_first_load
        return _unpack_qiushui_first_load


def _cstr(data: bytes, pos: int, limit: int = 512) -> bytes:
    if pos < 0 or pos >= len(data):
        return b""
    end = data.find(b"\0", pos, min(len(data), pos + limit))
    if end < 0:
        return b""
    return data[pos:end]


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = float(len(data))
    return -sum(
        (count / total) * math.log(count / total, 2)
        for count in Counter(data).values()
    )


def _find_symbol_strings(image: bytes, needle: bytes) -> List[Tuple[int, bytes]]:
    rows = []
    for match in re.finditer(re.escape(needle), image):
        name = _cstr(image, match.start())
        if name.startswith(needle):
            rows.append((match.start(), name))
    return rows


def _infer_dynsym_symbols(image: bytes) -> Dict[str, Dict[str, object]]:
    targets = []
    for key, needle in (
        ("slky", b"_ZN4iapp4slky"),
        ("burden1b", b"_ZN4iapp6burden1b"),
    ):
        for pos, name in _find_symbol_strings(image, needle):
            targets.append((key, pos, name))
    if not any(row[0] == "slky" for row in targets):
        raise PackedDynamicError("unpacked image does not contain slky symbol")
    if not any(row[0] == "burden1b" for row in targets):
        raise PackedDynamicError("unpacked image does not contain burden1b symbol")

    by_base = defaultdict(list)
    for offset in range(0, len(image) - 24, 8):
        st_name = struct.unpack_from("<I", image, offset)[0]
        info = image[offset + 4]
        shndx = struct.unpack_from("<H", image, offset + 6)[0]
        value, size = struct.unpack_from("<QQ", image, offset + 8)
        if not st_name or st_name > len(image):
            continue
        if (info & 0x0F) != 2 or (info >> 4) not in (1, 2):
            continue
        if not shndx or value <= 0 or size <= 0:
            continue
        if value >= len(image) or size > len(image):
            continue
        if value + min(size, 4) > len(image):
            continue
        for key, string_pos, full_name in targets:
            base = string_pos - st_name
            if base < 0 or base >= len(image) or image[base] != 0:
                continue
            if _cstr(image, base + st_name) != full_name:
                continue
            by_base[base].append(
                {
                    "key": key,
                    "name": full_name.decode("ascii", "replace"),
                    "entry_offset": offset,
                    "value": int(value),
                    "size": int(size),
                    "info": int(info),
                    "shndx": int(shndx),
                }
            )

    ranked = []
    for base, rows in by_base.items():
        keys = {row["key"] for row in rows}
        if not {"slky", "burden1b"}.issubset(keys):
            continue
        distinct_names = {row["name"] for row in rows}
        score = len(distinct_names) * 100
        score += sum(20 for row in rows if row["info"] == 0x22)
        score -= base / float(max(1, len(image)))
        ranked.append((score, base, rows))
    if not ranked:
        raise PackedDynamicError("could not reconstruct packed dynsym/dynstr mapping")
    ranked.sort(key=lambda row: (-row[0], row[1]))
    _score, dynstr_base, rows = ranked[0]

    result: Dict[str, Dict[str, object]] = {
        "dynstr_base": {"value": dynstr_base}
    }
    for key in ("slky", "burden1b"):
        matches = [row for row in rows if row["key"] == key]
        matches.sort(key=lambda row: (-row["size"], row["value"], row["name"]))
        if matches:
            result[key] = matches[0]
    if "slky" not in result or "burden1b" not in result:
        raise PackedDynamicError("packed symbol mapping is incomplete")
    return result


def _quality_key(blob: bytes) -> bool:
    return (
        16 <= len(blob) <= 64
        and len(set(blob)) >= 10
        and _entropy(blob) >= 3.5
    )


def _decode_move_wide(insn: int, regs: Dict[int, int]) -> bool:
    # MOVN/MOVZ/MOVK, including aliases such as `mov w2, #-0x1e`.
    if (insn & 0x1F800000) != 0x12800000:
        return False
    sf = (insn >> 31) & 1
    opc = (insn >> 29) & 3
    hw = (insn >> 21) & 3
    imm16 = (insn >> 5) & 0xFFFF
    rd = insn & 31
    bits = 64 if sf else 32
    if not sf and hw >= 2:
        return False
    shift = hw * 16
    mask = (1 << bits) - 1
    if opc == 0:  # MOVN
        value = (~(imm16 << shift)) & mask
    elif opc == 2:  # MOVZ
        value = (imm16 << shift) & mask
    elif opc == 3:  # MOVK
        old = regs.get(rd, 0)
        value = (old & ~(0xFFFF << shift)) | (imm16 << shift)
        value &= mask
    else:
        return False
    regs[rd] = value
    return True


def _is_control_boundary(insn: int) -> bool:
    # B / BL
    if (insn & 0x7C000000) == 0x14000000:
        return True
    # B.cond
    if (insn & 0xFF000010) == 0x54000000:
        return True
    # CBZ / CBNZ
    if (insn & 0x7E000000) == 0x34000000:
        return True
    # TBZ / TBNZ
    if (insn & 0x7E000000) == 0x36000000:
        return True
    # BR / BLR / RET
    masked = insn & 0xFFFFFC1F
    if masked in (0xD61F0000, 0xD63F0000, 0xD65F0000):
        return True
    return False


def _segment_immediate_byte_tables(
    image: bytes,
    symbol: Dict[str, object],
    role: str,
) -> List[Tuple[float, bytes, Dict[str, object]]]:
    start = int(symbol["value"])
    size = int(symbol["size"])
    code = image[start : min(len(image), start + size)]
    if len(code) < 32:
        raise PackedDynamicError(f"{role} symbol code is truncated")

    candidates: List[Tuple[float, bytes, Dict[str, object]]] = []
    segment_start = 0

    # Split at control-flow boundaries.  Both protected constants are assembled
    # in straight-line blocks between calls.  This prevents unrelated earlier
    # writes to the same stack offsets/registers from being merged.
    for segment_end in range(0, len(code) + 4, 4):
        boundary = segment_end >= len(code)
        if not boundary:
            insn = struct.unpack_from("<I", code, segment_end)[0]
            boundary = _is_control_boundary(insn)
        if not boundary:
            continue

        regs: Dict[int, int] = {}
        writes: Dict[int, Dict[int, Tuple[int, int]]] = defaultdict(dict)
        for pos in range(segment_start, segment_end, 4):
            insn = struct.unpack_from("<I", code, pos)[0]
            if _decode_move_wide(insn, regs):
                continue
            # STRB Wt, [Xn|SP, #imm12]
            if (insn & 0xFFC00000) != 0x39000000:
                continue
            rt = insn & 31
            rn = (insn >> 5) & 31
            offset = (insn >> 10) & 0xFFF
            value = 0 if rt == 31 else regs.get(rt)
            if value is None:
                continue
            writes[rn][offset] = (int(value) & 0xFF, start + pos)

        for base_reg, table in writes.items():
            for terminator_offset, (terminator_value, terminator_pc) in table.items():
                if terminator_value != 0:
                    continue
                first = terminator_offset
                while first > 0 and (first - 1) in table:
                    first -= 1
                length = terminator_offset - first
                if not 16 <= length <= 64:
                    continue
                if not all(index in table for index in range(first, terminator_offset)):
                    continue
                blob = bytes(table[index][0] for index in range(first, terminator_offset))
                if not _quality_key(blob):
                    continue

                # Prefer a maximal contiguous table, then entropy.  The former
                # avoids choosing a 16/17/18-byte suffix of a 20-byte constant.
                score = length * 10.0 + _entropy(blob)
                if base_reg == 31 and role == "post":
                    score += 10.0  # slky commonly builds its post table on stack
                if base_reg == 0 and role == "xor":
                    score += 10.0  # burden1b commonly writes into allocator result x0

                candidates.append(
                    (
                        score,
                        blob,
                        {
                            f"{role}_strategy": (
                                "arm64-slky-immediate-strb-table"
                                if role == "post"
                                else "arm64-burden1b-immediate-strb-table"
                            ),
                            f"{role}_symbol_vaddr": start,
                            f"{role}_segment_start": start + segment_start,
                            f"{role}_segment_end": start + segment_end,
                            f"{role}_base_reg": base_reg,
                            f"{role}_base_offset": first,
                            f"{role}_terminator_offset": terminator_offset,
                            f"{role}_terminator_pc": terminator_pc,
                            f"{role}_bytes": length,
                            f"{role}_score": round(score, 3),
                        },
                    )
                )

        segment_start = segment_end + 4

    return candidates


def _extract_symbol_table(
    image: bytes,
    symbol: Dict[str, object],
    role: str,
) -> Tuple[bytes, Dict[str, object]]:
    candidates = _segment_immediate_byte_tables(image, symbol, role)
    if not candidates:
        raise PackedDynamicError(
            f"{role} immediate-byte table was not found in {role == 'post' and 'slky' or 'burden1b'}"
        )
    candidates.sort(key=lambda row: (-row[0], -len(row[1]), row[1]))
    score, blob, meta = candidates[0]
    unique = {candidate for _score, candidate, _meta in candidates}
    meta[f"{role}_candidates_seen"] = len(unique)
    return blob, meta


def extract_pair_from_so_bytes(
    so_data: bytes,
    label: str = "libygsiyu.so",
) -> Tuple[bytes, bytes, Dict[str, object]]:
    so_data = bytes(so_data or b"")
    if not so_data or len(so_data) > MAX_SO_SIZE:
        raise PackedDynamicError("libygsiyu.so size is invalid")

    unpack = _load_unpacker()
    image, unpack_meta = unpack(so_data)
    symbols = _infer_dynsym_symbols(image)

    # Important: do not globally rank random high-entropy NUL blobs.  Packed
    # images contain many such blobs.  Recover each constant only from the
    # actual symbol's immediate STRB construction dataflow.
    post_key, post_meta = _extract_symbol_table(image, symbols["slky"], "post")
    xor_key, xor_meta = _extract_symbol_table(image, symbols["burden1b"], "xor")

    if post_key == xor_key:
        raise PackedDynamicError("post_key and xor_key unexpectedly match")

    meta: Dict[str, object] = {
        "extractor_build": BUILD,
        "status": "extracted-packed-symbol-dataflow",
        "label": label,
        "so_sha256": hashlib.sha256(so_data).hexdigest(),
        "unpacked_image_sha256": hashlib.sha256(image).hexdigest(),
        "post_key_bytes": len(post_key),
        "xor_key_bytes": len(xor_key),
        "dynstr_base": int(symbols["dynstr_base"]["value"]),
        "slky_vaddr": int(symbols["slky"]["value"]),
        "burden1b_vaddr": int(symbols["burden1b"]["value"]),
    }
    meta.update(unpack_meta)
    meta.update(post_meta)
    meta.update(xor_meta)
    return post_key, xor_key, meta


def _ygs_entries(zf: zipfile.ZipFile):
    rows = []
    for info in zf.infolist():
        name = info.filename.replace("\\", "/").lower()
        if info.is_dir():
            continue
        if name == "libygsiyu.so" or (
            name.startswith("lib/") and name.endswith("/libygsiyu.so")
        ):
            rows.append(info)
    order = {"x86": 0, "x86_64": 1, "armeabi-v7a": 2, "arm64-v8a": 3}
    rows.sort(
        key=lambda item: (
            order.get(
                item.filename.replace("\\", "/").split("/")[-2].lower(),
                99,
            ),
            item.filename.lower(),
        )
    )
    return rows


def extract_pair_from_apk(
    apk_path: Path | str,
) -> Tuple[bytes, bytes, Dict[str, object]]:
    apk_path = Path(apk_path)
    successes = []
    errors = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        entries = _ygs_entries(zf)
        if not entries:
            raise PackedDynamicError("APK does not contain libygsiyu.so")
        for info in entries:
            try:
                post, xor, meta = extract_pair_from_so_bytes(
                    zf.read(info), info.filename
                )
                successes.append((post, xor, meta))
            except Exception as exc:
                errors.append(
                    "%s: %s: %s"
                    % (info.filename, type(exc).__name__, exc)
                )
    if not successes:
        raise PackedDynamicError(
            "packed dynamic analysis failed: " + " | ".join(errors)
        )
    pairs = {(post, xor) for post, xor, _meta in successes}
    if len(pairs) != 1:
        raise PackedDynamicError("multi-ABI packed dynamic key mismatch")
    post, xor = next(iter(pairs))
    selected = next(
        dict(meta)
        for p, x, meta in successes
        if p == post and x == xor
    )
    selected["successful_entries"] = [
        meta.get("label")
        for p, x, meta in successes
        if p == post and x == xor
    ]
    selected["failed_entries"] = errors
    return post, xor, selected


def container_variants(container: bytes) -> List[Tuple[str, bytes]]:
    raw = bytes(container or b"")
    if not raw:
        return []
    rows: List[Tuple[str, bytes]] = []
    seen = set()

    def add(label: str, value: bytes):
        if value and len(value) % 16 == 0 and value not in seen:
            seen.add(value)
            rows.append((label, value))

    add("raw", raw)
    remainder = len(raw) % 16
    if remainder:
        add("strip-prefix-%d" % remainder, raw[remainder:])
        add("strip-suffix-%d" % remainder, raw[:-remainder])
    if len(raw) > 8:
        add("strip-prefix-8", raw[8:])
        add("strip-suffix-8", raw[:-8])
    return rows


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("--so", action="store_true")
    parser.add_argument("--container", action="store_true")
    args = parser.parse_args()

    if args.container:
        data = args.input.read_bytes()
        print(
            json.dumps(
                [
                    {
                        "label": label,
                        "size": len(value),
                        "sha256": hashlib.sha256(value).hexdigest(),
                    }
                    for label, value in container_variants(data)
                ],
                indent=2,
            )
        )
        return

    if args.so:
        post, xor, meta = extract_pair_from_so_bytes(
            args.input.read_bytes(), args.input.name
        )
    else:
        post, xor, meta = extract_pair_from_apk(args.input)
    print(
        json.dumps(
            {
                "post_key": post.hex(),
                "xor_key": xor.hex(),
                "metadata": meta,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
