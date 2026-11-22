from __future__ import print_function

import math
import struct
from collections import Counter

BUILD = "multiabi-dataflow-v3"


class ELFError(ValueError):
    pass


class MiniELF(object):
    def __init__(self, data):
        self.data = bytes(data or b"")
        if len(self.data) < 52 or self.data[:4] != b"\x7fELF":
            raise ELFError("not an ELF file")
        self.bits = 64 if self.data[4] == 2 else 32 if self.data[4] == 1 else 0
        if not self.bits or self.data[5] != 1:
            raise ELFError("only little-endian ELF32/ELF64 is supported")
        if self.bits == 32:
            vals = struct.unpack_from("<16sHHIIIIIHHHHHH", self.data, 0)
            self.e_machine = vals[2]
            self.e_shoff = vals[6]
            self.e_shentsize = vals[11]
            self.e_shnum = vals[12]
            self.e_shstrndx = vals[13]
        else:
            vals = struct.unpack_from("<16sHHIQQQIHHHHHH", self.data, 0)
            self.e_machine = vals[2]
            self.e_shoff = vals[6]
            self.e_shentsize = vals[11]
            self.e_shnum = vals[12]
            self.e_shstrndx = vals[13]
        self.sections = self._read_sections()
        self.by_name = dict((s.get("name", ""), s) for s in self.sections if s.get("name"))
        self.symbols = self._read_symbols()

    def _read_sections(self):
        raw = []
        for index in range(int(self.e_shnum)):
            off = int(self.e_shoff) + index * int(self.e_shentsize)
            if off < 0 or off + self.e_shentsize > len(self.data):
                break
            if self.bits == 32:
                v = struct.unpack_from("<IIIIIIIIII", self.data, off)
                row = dict(index=index, name_off=v[0], type=v[1], flags=v[2], addr=v[3], offset=v[4], size=v[5], link=v[6], info=v[7], align=v[8], entsize=v[9])
            else:
                v = struct.unpack_from("<IIQQQQIIQQ", self.data, off)
                row = dict(index=index, name_off=v[0], type=v[1], flags=v[2], addr=v[3], offset=v[4], size=v[5], link=v[6], info=v[7], align=v[8], entsize=v[9])
            raw.append(row)
        names = b""
        if 0 <= self.e_shstrndx < len(raw):
            s = raw[self.e_shstrndx]
            names = self.data[s["offset"]:s["offset"] + s["size"]]
        for row in raw:
            row["name"] = _cstr(names, row["name_off"])
        return raw

    def _read_symbols(self):
        out = []
        for sec in self.sections:
            if sec["type"] not in (2, 11) or not sec["entsize"]:
                continue
            if not (0 <= sec["link"] < len(self.sections)):
                continue
            strsec = self.sections[sec["link"]]
            strings = self.data[strsec["offset"]:strsec["offset"] + strsec["size"]]
            count = sec["size"] // sec["entsize"]
            for i in range(int(count)):
                off = sec["offset"] + i * sec["entsize"]
                if off + sec["entsize"] > len(self.data):
                    break
                if self.bits == 32:
                    name, value, size, info, other, shndx = struct.unpack_from("<IIIBBH", self.data, off)
                else:
                    name, info, other, shndx, value, size = struct.unpack_from("<IBBHQQ", self.data, off)
                n = _cstr(strings, name)
                if n:
                    out.append(dict(name=n, value=value, size=size, info=info, shndx=shndx))
        # Prefer the largest duplicate symbol record.
        dedup = {}
        for row in out:
            key = (row["name"], row["value"] & ~1)
            if key not in dedup or row["size"] > dedup[key]["size"]:
                dedup[key] = row
        return list(dedup.values())

    def section(self, name):
        return self.by_name.get(name)

    def vaddr_to_offset(self, addr):
        addr = int(addr)
        for sec in self.sections:
            if sec["type"] == 8:  # NOBITS
                continue
            start = int(sec["addr"])
            end = start + int(sec["size"])
            if start <= addr < end:
                return int(sec["offset"]) + (addr - start)
        return None

    def read_vaddr(self, addr, size):
        off = self.vaddr_to_offset(addr)
        if off is None or off < 0 or off + size > len(self.data):
            return b""
        return self.data[off:off + size]

    def symbol_contains(self, needle):
        rows = [x for x in self.symbols if needle in x["name"] and int(x.get("size") or 0) > 0]
        rows.sort(key=lambda x: (-int(x.get("size") or 0), int(x.get("value") or 0)))
        return rows

    def symbol_bytes(self, sym):
        start = int(sym["value"]) & ~1
        off = self.vaddr_to_offset(start)
        if off is None:
            return start, b""
        size = int(sym.get("size") or 0)
        return start, self.data[off:off + size]


def _cstr(data, off):
    try:
        off = int(off)
    except Exception:
        return ""
    if off < 0 or off >= len(data):
        return ""
    end = data.find(b"\0", off)
    if end < 0:
        end = len(data)
    return data[off:end].decode("utf-8", "replace")


def _sign(value, bits):
    top = 1 << (bits - 1)
    return value - (1 << bits) if value & top else value


def _entropy(blob):
    if not blob:
        return 0.0
    n = float(len(blob))
    return -sum((v / n) * math.log(v / n, 2) for v in Counter(blob).values())


def _printable_ratio(blob):
    return sum(1 for x in blob if 32 <= x < 127) / float(max(1, len(blob)))


def _valid_key(blob, min_len=16, max_len=96):
    blob = bytes(blob or b"")
    if not (min_len <= len(blob) <= max_len) or not any(blob) or b"\0" in blob:
        return False
    if _entropy(blob) < 3.55:
        return False
    if _printable_ratio(blob) > 0.78:
        return False
    return True


def _nul_runs(section_data, section_addr, min_len=20, max_len=64):
    out = []
    n = len(section_data)
    i = 0
    while i < n:
        if section_data[i] == 0:
            i += 1
            continue
        start = i
        while i < n and section_data[i] != 0 and i - start <= max_len:
            i += 1
        length = i - start
        if i < n and section_data[i] == 0 and min_len <= length <= max_len:
            blob = section_data[start:i]
            if _valid_key(blob, min_len, max_len):
                out.append((section_addr + start, blob))
        while i < n and section_data[i] != 0:
            i += 1
    return out


def _arm64_adrp_target(pc, insn):
    immlo = (insn >> 29) & 3
    immhi = (insn >> 5) & 0x7ffff
    imm = _sign((immhi << 2) | immlo, 21) << 12
    return (pc & ~0xfff) + imm


def _arm64_address_refs(elf, symbols):
    refs = set()
    for sym in symbols:
        start, code = elf.symbol_bytes(sym)
        regs = {}
        for pos in range(0, len(code) - 3, 4):
            pc = start + pos
            insn = struct.unpack_from("<I", code, pos)[0]
            if (insn & 0x9f000000) == 0x90000000:  # ADRP
                regs[insn & 31] = _arm64_adrp_target(pc, insn)
                continue
            if (insn & 0x7f000000) == 0x11000000:  # ADD immediate
                rd = insn & 31
                rn = (insn >> 5) & 31
                if rn in regs:
                    imm12 = (insn >> 10) & 0xfff
                    shift = 12 if ((insn >> 22) & 1) else 0
                    regs[rd] = regs[rn] + (imm12 << shift)
                    refs.add(regs[rd])
                continue
            # LDR Q/D/S with unsigned immediate.
            if (insn & 0xffc00000) in (0x3dc00000, 0xfd400000, 0xbd400000):
                rn = (insn >> 5) & 31
                if rn in regs:
                    scale = 16 if (insn & 0xffc00000) == 0x3dc00000 else 8 if (insn & 0xffc00000) == 0xfd400000 else 4
                    refs.add(regs[rn] + (((insn >> 10) & 0xfff) * scale))
    return refs


def _extract_post(elf):
    ro = elf.section(".rodata")
    if not ro:
        raise ValueError("ELF has no .rodata")
    data = elf.data[ro["offset"]:ro["offset"] + ro["size"]]
    runs = _nul_runs(data, ro["addr"], 20, 64)
    if not runs:
        raise ValueError("no post-key-like NUL terminated blob in .rodata")

    refs = set()
    if elf.e_machine == 183:
        refs = _arm64_address_refs(elf, elf.symbol_contains("_ZN4iapp4slky"))

    scored = []
    for addr, blob in runs:
        score = _entropy(blob) * 10.0 - _printable_ratio(blob) * 5.0
        if len(blob) == 35:
            score += 25.0
        elif 24 <= len(blob) <= 48:
            score += 8.0
        if addr in refs:
            score += 120.0
        # DWARF CFI bytecode frequently starts with these runs in merged rodata.
        if blob[:2] in (b"D\x0e", b"D-", b"\x0c\x1f"):
            score -= 60.0
        scored.append((score, addr, blob))
    scored.sort(key=lambda x: (-x[0], x[1]))
    score, addr, blob = scored[0]
    return blob, {"post_vaddr": addr, "post_score": round(score, 3), "post_candidates_seen": len(scored)}


def _extract_xor_arm64(elf, expected_len):
    candidates = []
    for sym in elf.symbol_contains("_ZN4iapp6burden1b"):
        start, code = elf.symbol_bytes(sym)
        regs = {}
        loads = []
        for pos in range(0, len(code) - 3, 4):
            pc = start + pos
            insn = struct.unpack_from("<I", code, pos)[0]
            if (insn & 0x9f000000) == 0x90000000:
                regs[insn & 31] = _arm64_adrp_target(pc, insn)
                continue
            kind = insn & 0xffc00000
            if kind in (0x3dc00000, 0xfd400000):
                rn = (insn >> 5) & 31
                if rn not in regs:
                    continue
                scale = 16 if kind == 0x3dc00000 else 8
                size = 16 if kind == 0x3dc00000 else 8
                addr = regs[rn] + (((insn >> 10) & 0xfff) * scale)
                loads.append((pc, size, addr, elf.read_vaddr(addr, size)))
        for i in range(len(loads)):
            window = [x for x in loads[i:] if x[0] - loads[i][0] <= 32]
            qs = [x for x in window if x[1] == 16]
            ds = [x for x in window if x[1] == 8]
            if len(qs) < 2 or not ds:
                continue
            for q0 in qs:
                for q1 in qs:
                    if q1[0] <= q0[0]:
                        continue
                    for d in ds:
                        if d[0] <= q1[0]:
                            continue
                        raw = q0[3] + q1[3] + d[3]
                        blob = raw.split(b"\0", 1)[0]
                        if _valid_key(blob) and abs(len(blob) - expected_len) <= 8:
                            candidates.append((blob, [q0[2], q1[2], d[2]], q0[0]))
    if not candidates:
        raise ValueError("AArch64 burden1b dataflow did not yield a complete XOR table")
    candidates.sort(key=lambda x: (abs(len(x[0]) - expected_len), -_entropy(x[0]), x[2]))
    blob, addresses, pc = candidates[0]
    return blob, {"xor_strategy": "arm64-adrp-q-q-d-tail", "xor_source_vaddrs": addresses, "xor_code_vaddr": pc}


def _extract_xor_x86(elf, expected_len):
    got = elf.section(".got.plt") or elf.section(".got")
    if not got:
        raise ValueError("x86 ELF has no GOT")
    got_base = int(got["addr"])
    candidates = []
    for sym in elf.symbol_contains("_ZN4iapp6burden1b"):
        start, code = elf.symbol_bytes(sym)
        n = len(code)
        for pos in range(0, n - 10):
            loads = []
            p = pos
            end = min(n, pos + 96)
            while p + 7 <= end:
                prefix = 0
                if code[p] == 0x66 and p + 8 <= end:
                    prefix = 1
                if p + prefix + 7 <= end and code[p + prefix] == 0x0f and code[p + prefix + 1] in (0x10, 0x28, 0x6f):
                    modrm = code[p + prefix + 2]
                    if (modrm & 0xc7) == 0x83:  # disp32(%ebx)
                        disp = struct.unpack_from("<i", code, p + prefix + 3)[0]
                        addr = got_base + disp
                        raw = elf.read_vaddr(addr, 16)
                        if len(raw) == 16:
                            loads.append((p, addr, raw))
                        p += prefix + 7
                        continue
                if p + 7 <= end and code[p:p + 3] == b"\xc7\x40\x20":
                    tail = struct.pack("<I", struct.unpack_from("<I", code, p + 3)[0])
                    if len(loads) >= 2:
                        raw = loads[-2][2] + loads[-1][2] + tail
                        blob = raw.split(b"\0", 1)[0]
                        if _valid_key(blob) and abs(len(blob) - expected_len) <= 8:
                            candidates.append((blob, [loads[-2][1], loads[-1][1]], start + p))
                    break
                p += 1
    if not candidates:
        raise ValueError("x86 burden1b SSE dataflow did not yield a complete XOR table")
    candidates.sort(key=lambda x: (abs(len(x[0]) - expected_len), -_entropy(x[0]), x[2]))
    blob, addresses, pc = candidates[0]
    return blob, {"xor_strategy": "x86-got-sse-sse-tail", "xor_source_vaddrs": addresses, "xor_code_vaddr": pc}


def _extract_xor_x64(elf, expected_len):
    candidates = []
    for sym in elf.symbol_contains("_ZN4iapp6burden1b"):
        start, code = elf.symbol_bytes(sym)
        loads = []
        for p in range(0, len(code) - 7):
            prefix = 1 if code[p] == 0x66 else 0
            if p + prefix + 7 <= len(code) and code[p + prefix] == 0x0f and code[p + prefix + 1] in (0x10, 0x28, 0x6f):
                modrm = code[p + prefix + 2]
                if (modrm & 0xc7) == 0x05:  # RIP+disp32
                    disp = struct.unpack_from("<i", code, p + prefix + 3)[0]
                    next_pc = start + p + prefix + 7
                    addr = next_pc + disp
                    raw = elf.read_vaddr(addr, 16)
                    if len(raw) == 16:
                        loads.append((p, addr, raw))
            if p + 7 <= len(code) and code[p:p + 3] in (b"\xc7\x40\x20", b"\xc7\x41\x20", b"\xc7\x42\x20"):
                tail = code[p + 3:p + 7]
                recent = [x for x in loads if 0 <= p - x[0] <= 96]
                if len(recent) >= 2:
                    blob = (recent[-2][2] + recent[-1][2] + tail).split(b"\0", 1)[0]
                    if _valid_key(blob) and abs(len(blob) - expected_len) <= 8:
                        candidates.append((blob, [recent[-2][1], recent[-1][1]], start + p))
    if not candidates:
        raise ValueError("x86_64 RIP-relative dataflow did not yield a complete XOR table")
    candidates.sort(key=lambda x: (abs(len(x[0]) - expected_len), -_entropy(x[0]), x[2]))
    blob, addresses, pc = candidates[0]
    return blob, {"xor_strategy": "x64-rip-sse-sse-tail", "xor_source_vaddrs": addresses, "xor_code_vaddr": pc}


def _extract_xor_symbol_blob(elf, expected_len):
    candidates = []
    for sym in elf.symbol_contains("_ZN4iapp6burden1b"):
        start, code = elf.symbol_bytes(sym)
        # Scan NUL-terminated high-entropy literals embedded in the function/literal pool.
        for pos in range(len(code)):
            if pos > 0 and code[pos - 1] == 0:
                pass
            for length in range(max(16, expected_len - 8), min(96, expected_len + 8) + 1):
                end = pos + length
                if end >= len(code) or code[end] != 0:
                    continue
                blob = code[pos:end]
                if _valid_key(blob) and abs(len(blob) - expected_len) <= 8:
                    score = _entropy(blob) * 10.0 - abs(len(blob) - expected_len) * 3.0
                    candidates.append((score, start + pos, blob))
    if not candidates:
        raise ValueError("burden1b contains no complete high-entropy XOR literal")
    candidates.sort(key=lambda x: (-x[0], x[1]))
    score, addr, blob = candidates[0]
    return blob, {"xor_strategy": "symbol-literal-pool", "xor_source_vaddrs": [addr], "xor_score": round(score, 3)}


def _extract_xor(elf, expected_len):
    errors = []
    strategies = []
    if elf.e_machine == 183:
        strategies = [_extract_xor_arm64, _extract_xor_symbol_blob]
    elif elf.e_machine == 3:
        strategies = [_extract_xor_x86, _extract_xor_symbol_blob]
    elif elf.e_machine == 62:
        strategies = [_extract_xor_x64, _extract_xor_symbol_blob]
    elif elf.e_machine == 40:
        strategies = [_extract_xor_symbol_blob]
    else:
        strategies = [_extract_xor_symbol_blob]
    for fn in strategies:
        try:
            return fn(elf, expected_len)
        except Exception as exc:
            errors.append("%s: %s" % (fn.__name__, exc))
    raise ValueError("; ".join(errors))


def arch_name(machine, bits):
    if machine == 183:
        return "arm64-v8a"
    if machine == 40:
        return "armeabi-v7a"
    if machine == 3:
        return "x86"
    if machine == 62:
        return "x86_64"
    return "machine-%s-%s" % (machine, bits)


def extract_pair_bytes(so_data):
    elf = MiniELF(so_data)
    post, pmeta = _extract_post(elf)
    xor, xmeta = _extract_xor(elf, len(post))
    if post == xor:
        raise ValueError("post_key and xor_key unexpectedly match")
    if not _valid_key(post) or not _valid_key(xor):
        raise ValueError("reconstructed key failed quality validation")
    meta = {
        "extractor_build": BUILD,
        "status": "extracted-dataflow",
        "arch": arch_name(elf.e_machine, elf.bits),
        "machine": elf.e_machine,
        "bits": elf.bits,
        "post_key_bytes": len(post),
        "xor_key_bytes": len(xor),
        "post_candidate_count": 1,
        "xor_candidate_count": 1,
        "post_candidate_values": [post.hex()],
        "xor_candidate_values": [xor.hex()],
        "ambiguous": False,
    }
    meta.update(pmeta)
    meta.update(xmeta)
    return post, xor, meta


def extract_pair_hex(so_data):
    post, xor, meta = extract_pair_bytes(so_data)
    return post.hex(), xor.hex(), meta


def extract_archive(path_or_bytes):
    import io
    import zipfile
    if isinstance(path_or_bytes, (bytes, bytearray)):
        zf = zipfile.ZipFile(io.BytesIO(bytes(path_or_bytes)))
    else:
        zf = zipfile.ZipFile(path_or_bytes)
    rows = []
    try:
        for name in zf.namelist():
            simple = name.replace("\\", "/").rsplit("/", 1)[-1]
            if simple.lower() != "libygsiyu.so":
                continue
            data = zf.read(name)
            post, xor, meta = extract_pair_hex(data)
            rows.append(dict(entry_name=name, post_key=post, xor_key=xor, **meta))
    finally:
        zf.close()
    return rows


if __name__ == "__main__":
    import json
    import pathlib
    import sys
    p = pathlib.Path(sys.argv[1])
    if p.suffix.lower() in (".zip", ".apk", ".apks"):
        print(json.dumps(extract_archive(str(p)), ensure_ascii=False, indent=2))
    else:
        post, xor, meta = extract_pair_hex(p.read_bytes())
        print(json.dumps(dict(post_key=post, xor_key=xor, **meta), ensure_ascii=False, indent=2))
