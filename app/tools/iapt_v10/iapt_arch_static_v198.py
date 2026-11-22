from __future__ import annotations

import contextlib
import io
import struct
from collections import Counter, defaultdict
from typing import Any

BUILD = "V198-four-abi-structural-static"
ARCH_NAMES = {3: "x86", 40: "armeabi-v7a", 62: "x86_64", 183: "arm64-v8a"}
CANONICAL_LENGTHS = (16, 20, 24, 32, 38, 39, 40, 48, 64, 72, 80, 84, 96, 112, 128)


def _sign(v: int, bits: int) -> int:
    top = 1 << (bits - 1)
    return v - (1 << bits) if v & top else v


def _uniq(values):
    out = []
    seen = set()
    for v in values or []:
        b = bytes(v or b"")
        if not b or b in seen:
            continue
        seen.add(b)
        out.append(b)
    return out


def _mapped(elf, addr: int) -> bool:
    try:
        return elf.vaddr_to_offset(int(addr)) is not None
    except Exception:
        return False


def _read(elf, addr: int, size: int) -> bytes:
    try:
        off = elf.vaddr_to_offset(int(addr))
        if off is None or off < 0:
            return b""
        return bytes(elf.data[off:off + int(size)])
    except Exception:
        return b""


def _section_for(elf, addr: int):
    for sec in getattr(elf, "sections", []) or []:
        start = int(sec.get("addr") or 0)
        size = int(sec.get("size") or 0)
        if start <= addr < start + size:
            return sec
    return None


def _object_candidate(elf, addr: int):
    for sym in getattr(elf, "read_symbols")():
        size = int(sym.get("size") or 0)
        start = int(sym.get("value") or 0) & ~1
        st_type = int(sym.get("info") or 0) & 0xF
        if st_type != 1 or not (16 <= size <= 129):
            continue
        if start <= addr < start + size:
            raw = _read(elf, start, size)
            if raw.endswith(b"\0") and 16 <= len(raw) - 1 <= 128:
                raw = raw[:-1]
            if 16 <= len(raw) <= 128:
                return start, raw, sym.get("name") or ""
    return None


def _candidate_blobs(elf, addresses, length_hints=()):
    refs = sorted(set(int(a) for a in addresses if _mapped(elf, int(a))))
    hints = sorted(set(int(x) for x in length_hints if 16 <= int(x) <= 128))
    bases = set(refs)
    # Consecutive vector references often point at +0x10/+0x20/... within one table.
    for i, addr in enumerate(refs):
        cluster = [addr]
        for nxt in refs[i + 1:]:
            if nxt - cluster[-1] > 32 or nxt - addr > 128:
                break
            cluster.append(nxt)
        if len(cluster) >= 2:
            bases.add(min(cluster))
    values = []
    evidence = defaultdict(list)
    for base in sorted(bases):
        obj = _object_candidate(elf, base)
        exact_cap = None
        if obj:
            start, blob, name = obj
            values.append(blob)
            exact_cap = len(blob)
            evidence[blob].append({"kind": "object-symbol", "address": start, "symbol": name})
        raw = _read(elf, base, 129)
        if len(raw) < 16:
            continue
        zero = raw.find(b"\0", 16)
        if 16 <= zero <= 128:
            blob = raw[:zero]
            values.append(blob)
            exact_cap = zero if exact_cap is None else min(exact_cap, zero)
            evidence[blob].append({"kind": "nul-terminated-reference", "address": base})
        for n in hints:
            if len(raw) >= n and (exact_cap is None or n <= exact_cap):
                blob = raw[:n]
                values.append(blob)
                evidence[blob].append({"kind": "copy-length", "address": base, "length": n})
        cap = min(len(raw), exact_cap if exact_cap is not None else 128)
        for n in CANONICAL_LENGTHS:
            if cap >= n:
                blob = raw[:n]
                values.append(blob)
                evidence[blob].append({"kind": "referenced-prefix", "address": base, "length": n})
    return _uniq(values), evidence


def _x64_refs(start: int, code: bytes):
    refs = []
    hints = []
    p = 0
    while p < len(code):
        q = p
        while q < len(code) and (code[q] in (0x66, 0xF2, 0xF3) or 0x40 <= code[q] <= 0x4F):
            q += 1
        # RIP-relative SIMD/mov/lea: opcode [0f xx] or 8d/8b, ModRM mod=00 rm=101.
        if q + 7 <= len(code) and code[q] == 0x0F and code[q + 1] in (0x10, 0x11, 0x28, 0x29, 0x6F, 0x7F):
            modrm = code[q + 2]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", code, q + 3)[0]
                refs.append(start + q + 7 + disp)
                p = q + 7
                continue
        if q + 6 <= len(code) and code[q] in (0x8D, 0x8B):
            modrm = code[q + 1]
            if (modrm & 0xC7) == 0x05:
                disp = struct.unpack_from("<i", code, q + 2)[0]
                refs.append(start + q + 6 + disp)
                p = q + 6
                continue
        # Immediate tail store: c7 47 disp8 imm32 / c7 87 disp32 imm32.
        if q + 7 <= len(code) and code[q] == 0xC7:
            modrm = code[q + 1]
            mod = modrm >> 6
            if mod == 1:
                off = struct.unpack_from("b", code, q + 2)[0]
                if off >= 0:
                    hints.append(off + 4)
            elif mod == 2 and q + 10 <= len(code):
                off = struct.unpack_from("<i", code, q + 2)[0]
                if off >= 0:
                    hints.append(off + 4)
        p += 1
    return refs, hints


def _x86_thunk_reg(elf, target: int):
    raw = _read(elf, target, 8)
    # mov (%esp),reg; ret. 8b 04/0c/14/1c/24/2c/34/3c 24 c3
    if len(raw) >= 4 and raw[0] == 0x8B and raw[2] == 0x24 and raw[3] == 0xC3:
        modrm = raw[1]
        if (modrm & 0xC7) == 0x04:
            return (modrm >> 3) & 7
    return None


def _x86_refs(elf, start: int, code: bytes):
    refs = []
    hints = []
    regs = {}
    p = 0
    while p < len(code):
        # call rel32 followed by pop reg, or call a get_pc_thunk.
        if p + 5 <= len(code) and code[p] == 0xE8:
            rel = struct.unpack_from("<i", code, p + 1)[0]
            next_pc = start + p + 5
            target = next_pc + rel
            if p + 6 <= len(code) and 0x58 <= code[p + 5] <= 0x5F:
                regs[code[p + 5] - 0x58] = next_pc
                p += 6
                continue
            treg = _x86_thunk_reg(elf, target)
            if treg is not None:
                regs[treg] = next_pc
            p += 5
            continue
        # add imm32/imm8 to a general register.
        if p + 6 <= len(code) and code[p] == 0x81 and 0xC0 <= code[p + 1] <= 0xC7:
            reg = code[p + 1] - 0xC0
            if reg in regs:
                regs[reg] = (regs[reg] + struct.unpack_from("<i", code, p + 2)[0]) & 0xFFFFFFFF
            p += 6
            continue
        if p + 3 <= len(code) and code[p] == 0x83 and 0xC0 <= code[p + 1] <= 0xC7:
            reg = code[p + 1] - 0xC0
            if reg in regs:
                regs[reg] = (regs[reg] + struct.unpack_from("b", code, p + 2)[0]) & 0xFFFFFFFF
            p += 3
            continue
        # SIMD load with disp32/disp8(base).
        if p + 3 <= len(code) and code[p] == 0x0F and code[p + 1] in (0x10, 0x28, 0x6F):
            modrm = code[p + 2]
            mod, rm = modrm >> 6, modrm & 7
            if mod == 2 and p + 7 <= len(code) and rm in regs:
                refs.append((regs[rm] + struct.unpack_from("<i", code, p + 3)[0]) & 0xFFFFFFFF)
                p += 7
                continue
            if mod == 1 and p + 4 <= len(code) and rm in regs:
                refs.append((regs[rm] + struct.unpack_from("b", code, p + 3)[0]) & 0xFFFFFFFF)
                p += 4
                continue
            if mod == 0 and rm == 5 and p + 7 <= len(code):
                refs.append(struct.unpack_from("<I", code, p + 3)[0])
                p += 7
                continue
        # lea/mov disp(base) can carry a table pointer.
        if p + 2 <= len(code) and code[p] in (0x8D, 0x8B):
            modrm = code[p + 1]
            mod, rm = modrm >> 6, modrm & 7
            if mod == 2 and p + 6 <= len(code) and rm in regs:
                refs.append((regs[rm] + struct.unpack_from("<i", code, p + 2)[0]) & 0xFFFFFFFF)
                p += 6
                continue
        if p + 4 <= len(code) and code[p] == 0xC7:
            modrm = code[p + 1]
            mod = modrm >> 6
            if mod == 1 and p + 7 <= len(code):
                off = struct.unpack_from("b", code, p + 2)[0]
                if off >= 0:
                    hints.append(off + 4)
            elif mod == 2 and p + 10 <= len(code):
                off = struct.unpack_from("<i", code, p + 2)[0]
                if off >= 0:
                    hints.append(off + 4)
        p += 1
    return refs, hints


def _arm64_adr(pc: int, insn: int) -> int:
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    return pc + _sign((immhi << 2) | immlo, 21)


def _arm64_adrp(pc: int, insn: int) -> int:
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7FFFF
    return (pc & ~0xFFF) + (_sign((immhi << 2) | immlo, 21) << 12)


def _arm64_refs(start: int, code: bytes):
    refs = []
    hints = []
    regs = {}
    for pos in range(0, len(code) - 3, 4):
        pc = start + pos
        insn = struct.unpack_from("<I", code, pos)[0]
        rd = insn & 31
        if (insn & 0x9F000000) == 0x10000000:  # ADR
            regs[rd] = _arm64_adr(pc, insn)
            continue
        if (insn & 0x9F000000) == 0x90000000:  # ADRP
            regs[rd] = _arm64_adrp(pc, insn)
            continue
        if (insn & 0x7F000000) == 0x11000000:  # ADD immediate
            rn = (insn >> 5) & 31
            if rn in regs:
                imm = ((insn >> 10) & 0xFFF) << (12 if ((insn >> 22) & 1) else 0)
                regs[rd] = regs[rn] + imm
            continue
        kind = insn & 0xFFC00000
        if kind in (0x3DC00000, 0xFD400000, 0xBD400000, 0xF9400000, 0xB9400000):
            rn = (insn >> 5) & 31
            if rn in regs:
                scale = {0x3DC00000: 16, 0xFD400000: 8, 0xBD400000: 4, 0xF9400000: 8, 0xB9400000: 4}[kind]
                refs.append(regs[rn] + (((insn >> 10) & 0xFFF) * scale))
            continue
        # Load pair: record referenced base+signed offset. Covers LDP q/q and x/x.
        if ((insn >> 27) & 0x7) == 0b101 and ((insn >> 22) & 1):
            rn = (insn >> 5) & 31
            if rn in regs:
                opc = (insn >> 30) & 3
                scale = 16 if opc == 2 else 8 if opc == 1 else 4
                imm7 = _sign((insn >> 15) & 0x7F, 7)
                refs.append(regs[rn] + imm7 * scale)
            continue
        # Store immediate to destination reveals total copied length.
        if (insn & 0xFFC00000) in (0xB9000000, 0xF9000000, 0x39000000, 0x3D800000):
            kind = insn & 0xFFC00000
            scale = {0xB9000000: 4, 0xF9000000: 8, 0x39000000: 1, 0x3D800000: 16}[kind]
            off = ((insn >> 10) & 0xFFF) * scale
            hints.append(off + scale)
    return refs, hints


def _thumb_refs(elf, start: int, code: bytes):
    refs = []
    hints = []
    regs = {}
    p = 0
    while p + 2 <= len(code):
        pc = start + p
        hw1 = struct.unpack_from("<H", code, p)[0]
        # LDR literal T1.
        if (hw1 & 0xF800) == 0x4800:
            rt = (hw1 >> 8) & 7
            lit_addr = ((pc + 4) & ~3) + ((hw1 & 0xFF) << 2)
            raw = _read(elf, lit_addr, 4)
            if len(raw) == 4:
                regs[rt] = struct.unpack("<i", raw)[0]
                regs[("literal", rt)] = lit_addr
        # ADR T1.
        if (hw1 & 0xF800) == 0xA000:
            rd = (hw1 >> 8) & 7
            regs[rd] = ((pc + 4) & ~3) + ((hw1 & 0xFF) << 2)
            refs.append(regs[rd])
        # MOVS Rd,#imm8, useful memcpy length hint.
        if (hw1 & 0xF800) == 0x2000:
            rd = (hw1 >> 8) & 7
            regs[rd] = hw1 & 0xFF
            if rd == 2 and 16 <= regs[rd] <= 128:
                hints.append(regs[rd])
        # ADD high register, including ADD Rd,PC.
        if (hw1 & 0xFF00) == 0x4400:
            rm = (hw1 >> 3) & 0xF
            rd = ((hw1 >> 4) & 8) | (hw1 & 7)
            if rm == 15 and rd in regs:
                target = pc + 4 + int(regs[rd])
                regs[rd] = target
                refs.append(target)
            elif rd == 15 and rm in regs:
                refs.append(pc + 4 + int(regs[rm]))
        if p + 4 <= len(code):
            hw2 = struct.unpack_from("<H", code, p + 2)[0]
            # LDR.W literal T2: f8df Rt, #imm12.
            if hw1 == 0xF8DF:
                rt = (hw2 >> 12) & 0xF
                lit_addr = ((pc + 4) & ~3) + (hw2 & 0xFFF)
                raw = _read(elf, lit_addr, 4)
                if len(raw) == 4:
                    regs[rt] = struct.unpack("<i", raw)[0]
                    regs[("literal", rt)] = lit_addr
                p += 4
                continue
            # ADR.W / ADDW Rd,PC,#imm12.
            if (hw1 & 0xFBFF) == 0xF20F:
                rd = (hw2 >> 8) & 0xF
                imm12 = (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF)
                target = ((pc + 4) & ~3) + imm12
                regs[rd] = target
                refs.append(target)
                p += 4
                continue
            # MOVW/MOVT immediate; track low/high halves and memcpy length in r2.
            if (hw1 & 0xFBF0) in (0xF240, 0xF2C0):
                rd = (hw2 >> 8) & 0xF
                imm = ((hw1 & 0xF) << 12) | (((hw1 >> 10) & 1) << 11) | (((hw2 >> 12) & 7) << 8) | (hw2 & 0xFF)
                if (hw1 & 0xFBF0) == 0xF240:
                    regs[rd] = (int(regs.get(rd, 0)) & 0xFFFF0000) | imm
                else:
                    regs[rd] = (int(regs.get(rd, 0)) & 0xFFFF) | (imm << 16)
                if rd == 2 and 16 <= int(regs[rd]) <= 128:
                    hints.append(int(regs[rd]))
                p += 4
                continue
        p += 2
    return refs, hints


def _arm_imm12(insn: int) -> int:
    imm8 = insn & 0xFF
    rot = ((insn >> 8) & 0xF) * 2
    if rot == 0:
        return imm8
    return ((imm8 >> rot) | (imm8 << (32 - rot))) & 0xFFFFFFFF


def _arm32_refs(elf, start: int, code: bytes):
    refs = []
    hints = []
    regs = {}
    for p in range(0, len(code) - 3, 4):
        pc = start + p
        insn = struct.unpack_from("<I", code, p)[0]
        # LDR literal (immediate, pre-index, no writeback, Rn=PC).
        if ((insn >> 26) & 3) == 1 and not ((insn >> 25) & 1) and ((insn >> 24) & 1) and not ((insn >> 21) & 1) and ((insn >> 20) & 1) and ((insn >> 16) & 0xF) == 15:
            rt = (insn >> 12) & 0xF
            imm = insn & 0xFFF
            addr = pc + 8 + (imm if ((insn >> 23) & 1) else -imm)
            raw = _read(elf, addr, 4)
            if len(raw) == 4:
                regs[rt] = struct.unpack("<i", raw)[0]
        # Data processing ADD/SUB immediate with Rn=PC (ADR).
        if ((insn >> 26) & 3) == 0 and ((insn >> 25) & 1):
            opcode = (insn >> 21) & 0xF
            rn = (insn >> 16) & 0xF
            rd = (insn >> 12) & 0xF
            if rn == 15 and opcode in (2, 4):
                imm = _arm_imm12(insn)
                target = pc + 8 + (imm if opcode == 4 else -imm)
                regs[rd] = target
                refs.append(target)
            if opcode == 13:  # MOV immediate
                value = _arm_imm12(insn)
                regs[rd] = value
                if rd == 2 and 16 <= value <= 128:
                    hints.append(value)
        # ADD register where one input is PC and the other holds a literal offset.
        if ((insn >> 26) & 3) == 0 and not ((insn >> 25) & 1) and ((insn >> 21) & 0xF) == 4:
            rn = (insn >> 16) & 0xF
            rd = (insn >> 12) & 0xF
            rm = insn & 0xF
            if rn == 15 and rm in regs:
                target = pc + 8 + int(regs[rm])
                regs[rd] = target
                refs.append(target)
            elif rm == 15 and rn in regs:
                target = pc + 8 + int(regs[rn])
                regs[rd] = target
                refs.append(target)
    return refs, hints


def _symbol_refs(elf, sym, code):
    start = int(sym.get("value") or 0) & ~1
    machine = int(getattr(elf, "e_machine", 0) or 0)
    if machine == 62:
        return _x64_refs(start, code)
    if machine == 3:
        return _x86_refs(elf, start, code)
    if machine == 183:
        return _arm64_refs(start, code)
    if machine == 40:
        if int(sym.get("value") or 0) & 1:
            return _thumb_refs(elf, start, code)
        return _arm32_refs(elf, start, code)
    return [], []


def _engine_symbol_candidates(engine, elf, sym, role):
    vals = []
    try:
        if elf.e_machine == 183:
            vals.extend(engine.extract_arm64_pc_relative_tables(elf, sym))
            _s, code = next((x for x in elf.get_symbols_contains(sym["name"], 0x10000) if int(x[0]["value"]) == int(sym["value"])), (None, b""))
            vals.extend(engine.extract_arm64_strb_tables(code))
        elif elf.e_machine == 62:
            vals.extend(engine.extract_x64_rip_relative_tables(elf, sym))
        elif elf.e_machine == 3:
            vals.extend(engine.extract_x86_pic_rodata_copies(elf, sym))
            vals.extend(engine.extract_x86_sse_rodata_tables(elf, sym))
            off = elf.vaddr_to_offset(int(sym["value"]) & ~1)
            if off is not None:
                vals.extend(engine.extract_x86_mov_tables(elf.data[off:off + int(sym.get("size") or 0x10000)]))
        elif elf.e_machine == 40:
            vals.extend(engine.extract_thumb_pc_relative_tables(elf, sym))
    except Exception:
        pass
    return _uniq([x for x in vals if 16 <= len(x) <= 128])


def _evidence_quality(items):
    score = 0
    for item in items or []:
        kind = str(item.get("kind") or "")
        if kind == "object-symbol": score += 8
        elif kind == "copy-length": score += 6
        elif kind == "nul-terminated-reference": score += 5
        elif kind == "referenced-prefix": score += 2
        elif kind == "compatibility-parser": score += 1
    return score


def _role_candidates(engine, elf, needle: str, role: str):
    raw_symbols = [sym for sym, _code in elf.get_symbols_contains(needle, 0x12000)]
    symbols = []
    seen_symbols = set()
    for sym in raw_symbols:
        key = (str(sym.get("name") or ""), int(sym.get("value") or 0) & ~1)
        if key in seen_symbols:
            continue
        seen_symbols.add(key)
        symbols.append(sym)
    rows = []
    support = Counter()
    quality = Counter()
    evidence = defaultdict(list)
    all_values = []
    for sym in symbols:
        off = elf.vaddr_to_offset(int(sym.get("value") or 0) & ~1)
        if off is None:
            continue
        code = elf.data[off:off + int(sym.get("size") or 0x12000)]
        refs, hints = _symbol_refs(elf, sym, code)
        direct_vals, ev = _candidate_blobs(elf, refs, hints)
        fallback_vals = _engine_symbol_candidates(engine, elf, sym, role)
        for value in _uniq(direct_vals):
            support[value] += 1
            evidence[value].append({
                "symbol": sym.get("name") or "",
                "symbol_vaddr": int(sym.get("value") or 0) & ~1,
                "reference_count": len(refs),
                "length_hints": sorted(set(hints)),
                "kind": "direct-symbol-dataflow",
            })
            evidence[value].extend(ev.get(value, []))
            quality[value] += 10 + _evidence_quality(ev.get(value, []))
            all_values.append(value)
        for value in _uniq(fallback_vals):
            if value not in direct_vals:
                evidence[value].append({"kind": "compatibility-parser", "symbol": sym.get("name") or ""})
                quality[value] += 1
                all_values.append(value)
        rows.append({"symbol": sym.get("name") or "", "vaddr": int(sym.get("value") or 0) & ~1, "refs": refs, "length_hints": hints, "values": _uniq(direct_vals + fallback_vals)})
    return _uniq(all_values), support, quality, evidence, rows


def _maximal_pairs(pairs):
    out = []
    for row in pairs:
        p = bytes.fromhex(row["post_key"])
        x = bytes.fromhex(row["xor_key"])
        dominated = False
        for other in pairs:
            if other is row:
                continue
            op = bytes.fromhex(other["post_key"])
            ox = bytes.fromhex(other["xor_key"])
            if len(op) > len(p) and op.startswith(p) and ox.startswith(x):
                if other["post_support"] >= row["post_support"] and other["xor_support"] >= row["xor_support"]:
                    dominated = True
                    break
        if not dominated:
            out.append(row)
    return out


def extract(engine, data: bytes) -> dict[str, Any]:
    elf = engine.MiniELF(data)
    machine = int(getattr(elf, "e_machine", 0) or 0)
    arch = ARCH_NAMES.get(machine, "machine-%s" % machine)
    if machine not in ARCH_NAMES:
        return {"status": "unsupported", "arch": arch, "pairs": [], "diagnostic": "暂不支持该 ELF 架构"}
    posts, psup, pqual, pev, prows = _role_candidates(engine, elf, "_ZN4iapp4slky", "post")
    xors, xsup, xqual, xev, xrows = _role_candidates(engine, elf, "_ZN4iapp6burden1b", "xor")
    # Compatibility candidate source, kept lower-priority than per-symbol structural refs.
    trace = io.StringIO()
    try:
        with contextlib.redirect_stdout(trace), contextlib.redirect_stderr(trace):
            old_posts, old_xors = engine.auto_extract_key_candidates_from_so(data)
        for value in _uniq(old_posts):
            if 16 <= len(value) <= 128 and value not in psup:
                posts.append(value); psup[value] = 0; pqual[value] += 1; pev[value].append({"kind": "compatibility-parser"})
        for value in _uniq(old_xors):
            if 16 <= len(value) <= 128 and value not in xsup:
                xors.append(value); xsup[value] = 0; xqual[value] += 1; xev[value].append({"kind": "compatibility-parser"})
    except Exception:
        pass
    pairs = []
    for post in _uniq(posts):
        for xor in _uniq(xors):
            if len(post) != len(xor) or not (16 <= len(post) <= 128) or post == xor:
                continue
            pairs.append({
                "post_key": post.hex(), "xor_key": xor.hex(), "bytes": len(post),
                "post_support": int(psup.get(post, 0)), "xor_support": int(xsup.get(xor, 0)),
                "post_quality": int(pqual.get(post, 0)), "xor_quality": int(xqual.get(xor, 0)),
                "post_evidence": pev.get(post, []), "xor_evidence": xev.get(xor, []),
            })
    if not pairs:
        return {
            "status": "unresolved", "arch": arch, "pairs": [], "selected": None,
            "diagnostic": "该架构的 slky/burden1b 中未形成等长静态表对",
            "post_symbol_count": len(prows), "xor_symbol_count": len(xrows),
        }
    # Structural support first; within the same support family keep maximal full tables.
    max_ps = max(r["post_support"] for r in pairs)
    top = [r for r in pairs if r["post_support"] == max_ps]
    max_xs = max(r["xor_support"] for r in top)
    top = [r for r in top if r["xor_support"] == max_xs]
    max_pq = max(r["post_quality"] for r in top)
    top = [r for r in top if r["post_quality"] == max_pq]
    max_xq = max(r["xor_quality"] for r in top)
    top = [r for r in top if r["xor_quality"] == max_xq]
    maximal = _maximal_pairs(top)
    maximal.sort(key=lambda r: (-r["bytes"], r["post_key"], r["xor_key"]))
    selected = maximal[0] if len(maximal) == 1 else None
    status = "extracted" if selected is not None else "multi-variant"
    diagnostic = "" if selected is not None else "同一架构存在多个非前缀静态表对；已完整输出，不自动隐藏或报错"
    return {
        "status": status, "arch": arch, "pairs": maximal[:32], "selected": selected,
        "diagnostic": diagnostic, "post_symbol_count": len(prows), "xor_symbol_count": len(xrows),
        "post_candidate_count": len(posts), "xor_candidate_count": len(xors),
        "parser_build": BUILD,
    }
