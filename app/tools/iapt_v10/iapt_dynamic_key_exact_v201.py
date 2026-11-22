from __future__ import annotations

import struct
from collections import Counter, defaultdict
from typing import Any

try:
    from . import iapt_arch_static_v198 as structural
except (ImportError, ValueError):
    import iapt_arch_static_v198 as structural

BUILD = "V201-server-effective-cstring-four-abi-static"
ARCH_NAMES = {3: "x86", 40: "armeabi-v7a", 62: "x86_64", 183: "arm64-v8a"}


def _ror32(value: int, shift: int) -> int:
    shift &= 31
    if shift == 0:
        return value & 0xFFFFFFFF
    return ((value >> shift) | (value << (32 - shift))) & 0xFFFFFFFF


def _thumb_expand_imm(i_bit: int, imm3: int, imm8: int) -> int:
    imm12 = ((i_bit & 1) << 11) | ((imm3 & 7) << 8) | (imm8 & 0xFF)
    if (imm12 >> 10) == 0:
        mode = (imm12 >> 8) & 3
        if mode == 0:
            return imm8
        if mode == 1:
            return (imm8 << 16) | imm8
        if mode == 2:
            return (imm8 << 24) | (imm8 << 8)
        return (imm8 << 24) | (imm8 << 16) | (imm8 << 8) | imm8
    unrotated = 0x80 | (imm12 & 0x7F)
    rotate = (imm12 >> 7) & 0x1F
    return _ror32(unrotated, rotate)


def _key_like(value: bytes, min_len: int = 4, max_len: int = 128, allow_printable: bool = False) -> bool:
    value = bytes(value or b"")
    if not (min_len <= len(value) <= max_len) or not any(value):
        return False
    printable = sum(0x20 <= b < 0x7F for b in value)
    high = sum(b >= 0x80 for b in value)
    distinct = len(set(value))
    # Exact immediate stores inside slky/burden1b are strong role evidence and
    # may legitimately contain printable-only keys. Referenced rodata still
    # rejects ordinary JNI names/method signatures.
    if not allow_printable and printable / len(value) > 0.78 and high == 0:
        return False
    return distinct >= min(4, len(value))


def _temporal_clusters(stores, max_gap: int = 0x90):
    by_base = defaultdict(list)
    for row in stores or []:
        pos, base, offset, value = row
        by_base[base].append((int(pos), base, int(offset), int(value) & 0xFF))
    for base, rows in by_base.items():
        rows.sort(key=lambda row: row[0])
        cluster = []
        previous = None
        for row in rows:
            if cluster and previous is not None and row[0] - previous > max_gap:
                yield base, cluster
                cluster = []
            cluster.append(row)
            previous = row[0]
        if cluster:
            yield base, cluster


def _effective_cstring_runs(stores, min_len: int = 4, max_len: int = 128):
    """Recover only the bytes actually consumed by the native C-string path.

    The iApp implementations allocate/copy a table, write an explicit NUL, then
    call strlen. Bytes after the first NUL belong to adjacent constants or dead
    initializer tail and are not part of the effective key.
    """
    values = []
    evidence = defaultdict(list)
    for base, cluster in _temporal_clusters(stores):
        mapping = {}
        for pos, _base, offset, value in cluster:
            mapping[offset] = value
        offsets = sorted(mapping)
        runs = []
        current = []
        previous = None
        for offset in offsets:
            if previous is None or offset == previous + 1:
                current.append(offset)
            else:
                if current:
                    runs.append(current)
                current = [offset]
            previous = offset
        if current:
            runs.append(current)
        for run in runs:
            if len(run) < min_len + 1:
                continue
            raw = bytes(mapping[offset] for offset in run[: max_len + 1])
            terminal = raw.find(b"\0")
            if terminal < min_len or terminal > max_len:
                continue
            value = raw[:terminal]
            if not _key_like(value, min_len=min_len, max_len=max_len, allow_printable=True):
                continue
            values.append(value)
            evidence[value].append({
                "kind": "effective-cstring-first-nul",
                "destination": str(base),
                "start_offset": int(run[0]),
                "terminal_offset": int(run[0] + terminal),
                "length": int(terminal),
                "first_instruction_offset": int(cluster[0][0]),
                "last_instruction_offset": int(cluster[-1][0]),
            })
    return values, evidence


def _decode_x86_immediate_stores(code: bytes, bits: int):
    stores = []
    cursor = 0
    size = len(code)
    while cursor < size - 2:
        pos = cursor
        rex = 0
        while pos < size and (
            code[pos] in (0x66, 0x67, 0xF2, 0xF3)
            or (bits == 64 and 0x40 <= code[pos] <= 0x4F)
        ):
            if bits == 64 and 0x40 <= code[pos] <= 0x4F:
                rex = code[pos]
            pos += 1
        if pos + 2 >= size or code[pos] not in (0xC6, 0xC7):
            cursor += 1
            continue
        opcode = code[pos]
        modrm = code[pos + 1]
        if ((modrm >> 3) & 7) != 0:
            cursor += 1
            continue
        mod = modrm >> 6
        rm = modrm & 7
        if mod == 3:
            cursor += 1
            continue
        q = pos + 2
        base: Any = rm | ((((rex & 1) != 0) << 3) if bits == 64 else 0)
        absolute = False
        if rm == 4:
            if q >= size:
                cursor += 1
                continue
            sib = code[q]
            q += 1
            sib_base = sib & 7
            if mod == 0 and sib_base == 5:
                absolute = True
            else:
                base = sib_base | ((((rex & 1) != 0) << 3) if bits == 64 else 0)
        displacement = 0
        if mod == 0:
            if (rm == 5 and rm != 4) or absolute:
                if q + 4 > size:
                    cursor += 1
                    continue
                q += 4
                absolute = True
        elif mod == 1:
            if q + 1 > size:
                cursor += 1
                continue
            displacement = struct.unpack_from("b", code, q)[0]
            q += 1
        elif mod == 2:
            if q + 4 > size:
                cursor += 1
                continue
            displacement = struct.unpack_from("<i", code, q)[0]
            q += 4
        if absolute:
            cursor += 1
            continue
        immediate_size = 1 if opcode == 0xC6 else 4
        if q + immediate_size > size:
            cursor += 1
            continue
        immediate = code[q:q + immediate_size]
        for relative, value in enumerate(immediate):
            stores.append((cursor, ("reg", int(base)), displacement + relative, value))
        cursor = q + immediate_size
    return stores


def _decode_arm64_immediate_stores(engine, code: bytes):
    registers = {}
    pointer_aliases = {}
    stores = []
    for pos in range(0, len(code) - 3, 4):
        instruction = struct.unpack_from("<I", code, pos)[0]
        moved = engine.arm64_mov_imm_w(instruction)
        if moved:
            registers[int(moved[0])] = int(moved[1]) & 0xFF
            continue
        if (instruction & 0xFFC00000) == 0xF9400000:
            destination = instruction & 0x1F
            base = (instruction >> 5) & 0x1F
            offset = ((instruction >> 10) & 0xFFF) * 8
            if base == 31:
                pointer_aliases[destination] = ("stack-pointer-slot", offset)
            elif base in pointer_aliases:
                pointer_aliases[destination] = ("loaded-pointer", pointer_aliases[base], offset)
            continue
        stored = engine.arm64_strb_unsigned(instruction)
        if not stored:
            continue
        source, base, offset = stored
        if source == 31:
            value = 0
        elif source in registers:
            value = registers[source]
        else:
            continue
        destination_identity = pointer_aliases.get(base, ("x", int(base)))
        stores.append((pos, destination_identity, int(offset), value))
    return stores


def _decode_thumb_immediate_stores(code: bytes):
    registers = {}
    stores = []
    pos = 0
    while pos + 2 <= len(code):
        first = struct.unpack_from("<H", code, pos)[0]
        if pos + 4 <= len(code):
            second = struct.unpack_from("<H", code, pos + 2)[0]
            if (first & 0xFBEF) == 0xF04F and (second & 0x8000) == 0:
                destination = (second >> 8) & 0xF
                registers[destination] = _thumb_expand_imm(
                    (first >> 10) & 1,
                    (second >> 12) & 7,
                    second & 0xFF,
                ) & 0xFF
                pos += 4
                continue
            if (first & 0xFBF0) == 0xF240 and (second & 0x8000) == 0:
                destination = (second >> 8) & 0xF
                immediate = (
                    ((first & 0xF) << 12)
                    | (((first >> 10) & 1) << 11)
                    | (((second >> 12) & 7) << 8)
                    | (second & 0xFF)
                )
                registers[destination] = immediate & 0xFF
                pos += 4
                continue
            if (first & 0xFFF0) == 0xF880:
                base = first & 0xF
                source = (second >> 12) & 0xF
                offset = second & 0xFFF
                if source == 15:
                    value = 0
                elif source in registers:
                    value = registers[source]
                else:
                    pos += 4
                    continue
                stores.append((pos, ("r", base), offset, value))
                pos += 4
                continue
        if (first & 0xF800) == 0x2000:
            registers[(first >> 8) & 7] = first & 0xFF
            pos += 2
            continue
        if (first & 0xF800) == 0x7000:
            offset = (first >> 6) & 0x1F
            base = (first >> 3) & 7
            source = first & 7
            if source in registers:
                stores.append((pos, ("r", base), offset, registers[source]))
            pos += 2
            continue
        pos += 2
    return stores


def _arm_expand_imm12(instruction: int) -> int:
    immediate8 = instruction & 0xFF
    rotate = ((instruction >> 8) & 0xF) * 2
    if rotate == 0:
        return immediate8
    return ((immediate8 >> rotate) | (immediate8 << (32 - rotate))) & 0xFFFFFFFF


def _decode_arm32_immediate_stores(code: bytes):
    registers = {}
    stores = []
    for pos in range(0, len(code) - 3, 4):
        instruction = struct.unpack_from("<I", code, pos)[0]
        if (instruction & 0x0FF00000) == 0x03000000:
            destination = (instruction >> 12) & 0xF
            immediate = (((instruction >> 16) & 0xF) << 12) | (instruction & 0xFFF)
            registers[destination] = immediate & 0xFF
            continue
        if (instruction & 0x0FE00000) == 0x03A00000:
            destination = (instruction >> 12) & 0xF
            registers[destination] = _arm_expand_imm12(instruction) & 0xFF
            continue
        if (instruction & 0x0E500000) == 0x04400000 and ((instruction >> 24) & 1):
            base = (instruction >> 16) & 0xF
            source = (instruction >> 12) & 0xF
            offset = instruction & 0xFFF
            if not ((instruction >> 23) & 1):
                offset = -offset
            if source in registers:
                stores.append((pos, ("r", base), offset, registers[source]))
    return stores


def _stores_for_symbol(engine, elf, symbol):
    start = int(symbol.get("value") or 0) & ~1
    offset = elf.vaddr_to_offset(start)
    if offset is None:
        return []
    code = elf.data[offset:offset + int(symbol.get("size") or 0x12000)]
    machine = int(getattr(elf, "e_machine", 0) or 0)
    if machine in (3, 62):
        return _decode_x86_immediate_stores(code, int(getattr(elf, "bits", 0) or (64 if machine == 62 else 32)))
    if machine == 183:
        return _decode_arm64_immediate_stores(engine, code)
    if machine == 40:
        if int(symbol.get("value") or 0) & 1:
            return _decode_thumb_immediate_stores(code)
        return _decode_arm32_immediate_stores(code)
    return []


def _symbols(elf, needle: str):
    out = []
    seen = set()
    for symbol, _code in elf.get_symbols_contains(needle, 0x12000):
        identity = (str(symbol.get("name") or ""), int(symbol.get("value") or 0) & ~1)
        if identity in seen:
            continue
        seen.add(identity)
        out.append(symbol)
    return out


def _role_store_values(engine, elf, needle: str):
    support = Counter()
    evidence = defaultdict(list)
    rows = []
    for symbol in _symbols(elf, needle):
        stores = _stores_for_symbol(engine, elf, symbol)
        occurrences, local_evidence = _effective_cstring_runs(stores)
        for value in occurrences:
            support[value] += 1
            evidence[value].extend(local_evidence.get(value, []))
            evidence[value].append({
                "kind": "role-symbol",
                "symbol": str(symbol.get("name") or ""),
                "symbol_vaddr": int(symbol.get("value") or 0) & ~1,
            })
        rows.append({
            "symbol": str(symbol.get("name") or ""),
            "vaddr": int(symbol.get("value") or 0) & ~1,
            "store_count": len(stores),
            "effective_lengths": sorted({len(value) for value in occurrences}),
        })
    return support, evidence, rows


def _post_reference_values(elf):
    support = Counter()
    evidence = defaultdict(list)
    rows = []
    for symbol in _symbols(elf, "_ZN4iapp4slky"):
        start = int(symbol.get("value") or 0) & ~1
        offset = elf.vaddr_to_offset(start)
        if offset is None:
            continue
        code = elf.data[offset:offset + int(symbol.get("size") or 0x12000)]
        refs, hints = structural._symbol_refs(elf, symbol, code)
        local_seen = set()
        local = []
        for address in sorted(set(int(ref) for ref in refs)):
            raw = structural._read(elf, address, 129)
            terminal = raw.find(b"\0")
            if terminal < 4 or terminal > 128:
                continue
            value = raw[:terminal]
            if not _key_like(value):
                continue
            if value in local_seen:
                continue
            local_seen.add(value)
            local.append(value)
            support[value] += 1
            evidence[value].append({
                "kind": "slky-effective-cstring-reference",
                "symbol": str(symbol.get("name") or ""),
                "address": address,
                "length": terminal,
            })
        rows.append({
            "symbol": str(symbol.get("name") or ""),
            "vaddr": start,
            "reference_count": len(refs),
            "length_hints": sorted(set(int(hint) for hint in hints if 0 < int(hint) <= 128)),
            "effective_lengths": sorted({len(value) for value in local}),
        })
    return support, evidence, rows


def _merge_support(primary, primary_evidence, secondary, secondary_evidence):
    out = Counter(primary)
    evidence = defaultdict(list)
    for value, rows in primary_evidence.items():
        evidence[value].extend(rows)
    for value, count in secondary.items():
        out[value] += count
    for value, rows in secondary_evidence.items():
        evidence[value].extend(rows)
    return out, evidence


def _pick_unique(counter: Counter, role: str):
    if not counter:
        return None, "none"
    best_support = max(counter.values())
    best = [value for value, support in counter.items() if support == best_support]
    # Repeated across both slky overloads or repeated branches is authoritative.
    # When support ties, prefer the longest complete first-NUL string only when
    # every shorter tied value is its suffix; otherwise refuse to guess.
    if len(best) == 1:
        return best[0], "unique"
    best.sort(key=lambda value: (-len(value), value))
    longest = best[0]
    if all(longest.endswith(value) for value in best[1:]):
        return longest, "unique-longest-over-suffixes"
    return None, f"{role}-tie"


def extract(engine, data: bytes) -> dict[str, Any]:
    elf = engine.MiniELF(data)
    machine = int(getattr(elf, "e_machine", 0) or 0)
    arch = ARCH_NAMES.get(machine, "machine-%s" % machine)
    if machine not in ARCH_NAMES:
        return {
            "status": "unsupported",
            "arch": arch,
            "selected": None,
            "diagnostic": "暂不支持该 ELF 架构",
            "parser_build": BUILD,
        }

    post_store, post_store_ev, post_store_rows = _role_store_values(engine, elf, "_ZN4iapp4slky")
    post_ref, post_ref_ev, post_ref_rows = _post_reference_values(elf)
    post_support, post_evidence = _merge_support(post_store, post_store_ev, post_ref, post_ref_ev)
    xor_support, xor_evidence, xor_rows = _role_store_values(engine, elf, "_ZN4iapp6burden1b")

    post_value, post_reason = _pick_unique(post_support, "post")
    xor_value, xor_reason = _pick_unique(xor_support, "xor")
    if post_value is None or xor_value is None:
        return {
            "status": "not-applicable" if not post_support or not xor_support else "unresolved",
            "arch": arch,
            "selected": None,
            "diagnostic": (
                "未同时还原出唯一的有效 C 字符串 post_key/xor_key；交给旧式固定向量解析器"
                if not post_support or not xor_support
                else "同一架构的有效 C 字符串存在不可消解冲突，解析器拒绝猜测"
            ),
            "post_reason": post_reason,
            "xor_reason": xor_reason,
            "post_store_rows": post_store_rows,
            "post_reference_rows": post_ref_rows,
            "xor_rows": xor_rows,
            "parser_build": BUILD,
        }

    selected = {
        "post_key": post_value.hex(),
        "xor_key": xor_value.hex(),
        "post_bytes": len(post_value),
        "xor_bytes": len(xor_value),
        "bytes": len(post_value) if len(post_value) == len(xor_value) else None,
        "post_support": int(post_support[post_value]),
        "xor_support": int(xor_support[xor_value]),
        "post_evidence": post_evidence.get(post_value, []),
        "xor_evidence": xor_evidence.get(xor_value, []),
        "source": "effective-cstring-static-dataflow",
    }
    return {
        "status": "extracted",
        "arch": arch,
        "selected": selected,
        "diagnostic": "",
        "post_store_rows": post_store_rows,
        "post_reference_rows": post_ref_rows,
        "xor_rows": xor_rows,
        "parser_build": BUILD,
    }
