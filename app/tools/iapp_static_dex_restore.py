#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pure static iApp/iYU obfuscation restore for server-side use.

Input:  source zip/dir/file plus optional DEX files.
Output: restored zip/dir/file.

Restores, without client hook/runtime:
  1) java(Base64.decode) + javanew(String) + btoo(...) constants
  2) loadjar/cls/javax(...)/hw/hws/tw reflection strings by statically executing
     simple String decrypt methods from supplied DEX files
  3) iApp V3 flat .iyu View closing structure

No Android runtime is used. The tiny DEX interpreter is intentionally conservative;
it handles the common string-decrypt bytecode patterns. Unsupported methods are
left unchanged and reported in static_dex_restore_map.txt.
"""
from __future__ import annotations

import argparse
import base64
import dataclasses
import json
import re
import shutil
import struct
import sys
import tempfile
import unicodedata
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

TEXT_EXTS = {".iyu", ".myu", ".mjava", ".ijava", ".java", ".txt", ".xml", ".json", ".mlua", ".lua", ".mjs", ".js"}
CONTROL_DROP = {"\u200b", "\u200c", "\u200d", "\ufeff", "\u2066", "\u2067", "\u2068", "\u2069", "\u206a"}
IDENT_SRC = r"[A-Za-z0-9_\u0600-\u06ff\u10a0-\u10ff\u4e00-\u9fff\u3400-\u4dbf]+"
TOKEN_RE = re.compile(IDENT_SRC)

# -------------------------- text helpers --------------------------

def decode_text(data: bytes) -> Tuple[str, str]:
    for enc in ("utf-8", "gb18030", "gbk", "latin1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", "replace"), "utf-8"


def strip_bad_controls(s: str) -> str:
    out = []
    for ch in s:
        if ch in "\n\r\t":
            out.append(ch)
        elif ch == "\u00a0":
            out.append(" ")
        elif ch in CONTROL_DROP:
            continue
        elif ord(ch) >= 32 and unicodedata.category(ch) != "Cf":
            out.append(ch)
    return "".join(out)


def is_text_file(p: Path) -> bool:
    return p.suffix.lower() in TEXT_EXTS


def quote_iyu_string(s: str) -> str:
    s = s.replace("\\", "\\\\").replace('"', '\\"')
    s = s.replace("\r", "\\r").replace("\n", "\\n")
    return '"' + s + '"'


def unquote_iyu(s: str) -> str:
    s = (s or "").strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        q = s[0]
        body = s[1:-1]
        try:
            # Preserve non-python escapes approximately.
            return bytes(body, "utf-8").decode("unicode_escape") if "\\" in body else body
        except Exception:
            return body.replace("\\" + q, q).replace("\\n", "\n").replace("\\r", "\r").replace("\\\\", "\\")
    return s


def split_args(s: str) -> List[str]:
    args: List[str] = []
    cur: List[str] = []
    quote: Optional[str] = None
    esc = False
    depth = 0
    for ch in s:
        if quote:
            cur.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == quote:
                quote = None
            continue
        if ch in "\"'":
            quote = ch
            cur.append(ch)
            continue
        if ch in "([{" :
            depth += 1
            cur.append(ch)
            continue
        if ch in ")]}" and depth > 0:
            depth -= 1
            cur.append(ch)
            continue
        if ch == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    args.append("".join(cur).strip())
    return args


def protect_strings(text: str) -> Tuple[str, List[str]]:
    parts: List[str] = []
    def repl(m: re.Match) -> str:
        parts.append(m.group(0))
        return f"@@STR{len(parts)-1}@@"
    masked = re.sub(r'"(?:\\.|[^"\\])*"', repl, text)
    masked = re.sub(r"'(?:\\.|[^'\\])*'", repl, masked)
    return masked, parts


def restore_strings(text: str, parts: List[str]) -> str:
    for i, p in enumerate(parts):
        text = text.replace(f"@@STR{i}@@", p)
    return text


def replace_tokens_outside_strings(text: str, values: Dict[str, str]) -> str:
    if not values:
        return text
    masked, parts = protect_strings(text)
    def repl(m: re.Match) -> str:
        tok = m.group(0)
        if tok in values:
            return quote_iyu_string(values[tok])
        return tok
    return restore_strings(TOKEN_RE.sub(repl, masked), parts)

# -------------------------- V3 flat .iyu repair --------------------------

VIEW_RE = re.compile(r'<View\b', re.I)
UI_OPEN_RE = re.compile(r'<UIEventset\b[^>]*>', re.I)
UI_CLOSE_RE = re.compile(r'</UIEventset>', re.I)
VIEW_CLOSE_RE = re.compile(r'</View>', re.I)
XML_DECL_RE = re.compile(r'^\s*<\?xml[^>]*\?>\s*', re.I | re.S)
EVENT_ITEM_OPEN_RE = re.compile(r'<eventItme\b', re.I)


def index_ci(s: str, needle: str, start: int = 0) -> int:
    return s.lower().find(needle.lower(), start)


def extract_event_items(text: str) -> List[str]:
    out: List[str] = []
    pos = 0
    while True:
        m = EVENT_ITEM_OPEN_RE.search(text, pos)
        if not m:
            break
        st = m.start()
        ed = index_ci(text, "</eventItme>", st)
        if ed < 0:
            break
        ed += len("</eventItme>")
        block = text[st:ed].strip()
        if block and block not in out:
            out.append(block)
        pos = ed
    return out


def repair_flat_iyu(text: str) -> str:
    x = strip_bad_controls(text).replace("\r\n", "\n").replace("\r", "\n")
    x = XML_DECL_RE.sub("", x).strip()
    x = re.sub(r'<xxbj\b[^>]*>|</xxbj>|<_Yu5Src\b[^>]*>|</_Yu5Src>', "", x, flags=re.I | re.S)
    if "<view" not in x.lower():
        body = UI_CLOSE_RE.sub("", UI_OPEN_RE.sub("", x)).strip()
        return "<UIEventset>\n" + (body + "\n" if body else "") + "</UIEventset>\n"

    x = UI_CLOSE_RE.sub("", UI_OPEN_RE.sub("", x)).strip()
    views: List[str] = []
    loose_parts: List[str] = []
    pos = 0
    while True:
        m = VIEW_RE.search(x, pos)
        if not m:
            loose_parts.append(x[pos:])
            break
        st = m.start()
        loose_parts.append(x[pos:st])
        ev_end = index_ci(x, "</event>", st)
        next_m = VIEW_RE.search(x, st + 5)
        next_view = next_m.start() if next_m else -1
        if ev_end >= 0 and (next_view < 0 or ev_end < next_view):
            end = ev_end + len("</event>")
        elif next_view >= 0:
            end = next_view
        else:
            end = len(x)
        block = VIEW_CLOSE_RE.sub("", x[st:end]).strip()
        if block:
            views.append(block)
        pos = end
    global_events: List[str] = []
    for part in loose_parts:
        for ev in extract_event_items(part):
            if ev not in global_events:
                global_events.append(ev)
    out: List[str] = []
    for v in views:
        out.append(v.rstrip())
        out.append("</View>")
    out.append("<UIEventset>")
    out.extend(global_events)
    out.append("</UIEventset>")
    return "\n".join(out).rstrip() + "\n"

# -------------------------- Base64 + btoo restore --------------------------

JAVA_B64_RE = re.compile(r'^\s*java\(\s*(' + IDENT_SRC + r')\s*,\s*null\s*,\s*"android\.util\.Base64\.decode"\s*,\s*"String"\s*,\s*"([^"]*)"\s*,\s*"int"\s*,\s*0\s*\)\s*$')
JAVANEW_STR_RE = re.compile(r'^\s*javanew\(\s*(' + IDENT_SRC + r')\s*,\s*"java\.lang\.String"\s*,\s*"byte\[\]"\s*,\s*(' + IDENT_SRC + r')\s*\)\s*$')
BTOO_RE = re.compile(r'^\s*btoo\(\s*null\s*,\s*(' + IDENT_SRC + r')\s*,\s*(' + IDENT_SRC + r')\s*\)\s*$')


def decode_btoo_b64(b64s: str) -> Optional[str]:
    try:
        raw = base64.b64decode(b64s + "=" * (-len(b64s) % 4))
    except Exception:
        return None
    txt = raw.decode("utf-8", "replace").strip()
    if txt == "":
        return ""
    if re.fullmatch(r"[-+]?\d+(?:\s+[-+]?\d+)*", txt):
        nums = [int(x) for x in txt.split()]
        data = bytes((n & 0xff) for n in nums)
        for enc in ("utf-8", "gb18030", "gbk", "latin1"):
            try:
                return data.decode(enc)
            except Exception:
                pass
        return data.decode("utf-8", "replace")
    return txt


def restore_base64_btoo(text: str) -> Tuple[str, Dict[str, str], int]:
    lines = text.splitlines()
    b64_vars: Dict[str, str] = {}
    str_vars: Dict[str, str] = {}
    values: Dict[str, str] = {}
    remove: set[int] = set()
    for i, line in enumerate(lines):
        m = JAVA_B64_RE.match(line)
        if m:
            val = decode_btoo_b64(m.group(2))
            if val is not None:
                b64_vars[m.group(1)] = val
                remove.add(i)
            continue
        m = JAVANEW_STR_RE.match(line)
        if m and m.group(2) in b64_vars:
            str_vars[m.group(1)] = b64_vars[m.group(2)]
            remove.add(i)
            continue
        m = BTOO_RE.match(line)
        if m and m.group(1) in str_vars:
            values[m.group(2)] = str_vars[m.group(1)]
            remove.add(i)
            continue
    new_lines = [line for i, line in enumerate(lines) if i not in remove]
    out = "\n".join(new_lines)
    out = replace_tokens_outside_strings(out, values)
    if text.endswith("\n"):
        out += "\n"
    return out, values, len(values)

# -------------------------- DEX parser and tiny interpreter --------------------------

class DexError(Exception):
    pass


def u16(data: bytes, off: int) -> int:
    return struct.unpack_from("<H", data, off)[0]

def s16(data: bytes, off: int) -> int:
    return struct.unpack_from("<h", data, off)[0]

def u32(data: bytes, off: int) -> int:
    return struct.unpack_from("<I", data, off)[0]

def s32_from_units(lo: int, hi: int) -> int:
    v = (hi << 16) | lo
    if v & 0x80000000:
        v -= 0x100000000
    return v

def sign8(x: int) -> int:
    x &= 0xff
    return x - 0x100 if x & 0x80 else x

def sign16(x: int) -> int:
    x &= 0xffff
    return x - 0x10000 if x & 0x8000 else x

def sign32(x: int) -> int:
    x &= 0xffffffff
    return x - 0x100000000 if x & 0x80000000 else x

def read_uleb(data: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    p = off
    while True:
        b = data[p]
        p += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            return result, p
        shift += 7
        if shift > 35:
            raise DexError("bad uleb128")


def read_sized_int(data: bytes, off: int, size: int, signed: bool = True) -> int:
    raw = data[off:off+size]
    v = int.from_bytes(raw, "little", signed=False)
    if signed and size > 0 and (raw[-1] & 0x80):
        v -= 1 << (size * 8)
    return v


def parse_type_list(data: bytes, off: int, types: List[str]) -> List[str]:
    if off == 0:
        return []
    size = u32(data, off)
    return [types[u16(data, off + 4 + i * 2)] for i in range(size)]


def human_to_desc(name: str) -> str:
    name = unquote_iyu(name).strip()
    if name.startswith("L") and name.endswith(";"):
        return name
    if name in {"String", "java.lang.String"}:
        return "Ljava/lang/String;"
    if name in {"int", "Integer"}:
        return "I"
    if name in {"boolean", "Boolean"}:
        return "Z"
    if name in {"byte"}:
        return "B"
    if name in {"char"}:
        return "C"
    if name in {"short"}:
        return "S"
    if name in {"long"}:
        return "J"
    if name in {"float"}:
        return "F"
    if name in {"double"}:
        return "D"
    if name.endswith("[]"):
        return "[" + human_to_desc(name[:-2])
    return "L" + name.replace(".", "/") + ";"


def desc_to_human(desc: str) -> str:
    if desc.startswith("L") and desc.endswith(";"):
        return desc[1:-1].replace("/", ".")
    return desc

@dataclasses.dataclass
class FieldRef:
    cls: str
    typ: str
    name: str

@dataclasses.dataclass
class MethodRef:
    cls: str
    name: str
    params: List[str]
    ret: str
    proto_idx: int
    method_idx: int

@dataclasses.dataclass
class MethodImpl:
    ref: MethodRef
    code_off: int
    access_flags: int

@dataclasses.dataclass
class Obj:
    typ: str
    value: Any = None
    fields: Dict[str, Any] = dataclasses.field(default_factory=dict)

class DexFile:
    def __init__(self, data: bytes, name: str = "classes.dex"):
        if not data.startswith(b"dex\n"):
            raise DexError("not a dex file")
        self.data = data
        self.name = name
        self.strings: List[str] = []
        self.types: List[str] = []
        self.protos: List[Tuple[str, List[str]]] = []
        self.fields: List[FieldRef] = []
        self.methods: List[MethodRef] = []
        self.impls: Dict[Tuple[str, str, Tuple[str, ...], str], MethodImpl] = {}
        self.impl_by_idx: Dict[int, MethodImpl] = {}
        self.impl_exact: Dict[Tuple[str, str, Tuple[str, ...]], MethodImpl] = {}
        self.impl_by_owner_name_arity: Dict[Tuple[str, str, int], List[MethodImpl]] = {}
        self._find_method_cache: Dict[Tuple[str, str, Tuple[str, ...]], Optional[MethodImpl]] = {}
        self._inheritance_cache: Dict[str, Tuple[str, ...]] = {}
        self.static_values: Dict[Tuple[str, str], Any] = {}
        self.super_by_class: Dict[str, str] = {}
        self._parse()

    def _read_string(self, off: int) -> str:
        _utf16_len, p = read_uleb(self.data, off)
        end = self.data.find(b"\x00", p)
        if end < 0:
            end = len(self.data)
        return self.data[p:end].decode("utf-8", "replace")

    def _parse_encoded_value(self, off: int) -> Tuple[Any, int]:
        b = self.data[off]
        off += 1
        value_type = b & 0x1f
        value_arg = b >> 5
        size = value_arg + 1
        if value_type == 0x00:  # byte
            return read_sized_int(self.data, off, size, True), off + size
        if value_type in (0x02, 0x04, 0x06):  # short/int/long
            return read_sized_int(self.data, off, size, True), off + size
        if value_type == 0x03:  # char
            return read_sized_int(self.data, off, size, False), off + size
        if value_type == 0x17:  # string
            idx = read_sized_int(self.data, off, size, False)
            return self.strings[idx] if 0 <= idx < len(self.strings) else "", off + size
        if value_type == 0x18:  # type
            idx = read_sized_int(self.data, off, size, False)
            return self.types[idx] if 0 <= idx < len(self.types) else "", off + size
        if value_type == 0x1e:
            return None, off
        if value_type == 0x1f:
            return bool(value_arg), off
        if value_type == 0x1c:  # array
            arr, off = self._parse_encoded_array_at(off)
            return arr, off
        # Unknown value; skip payload bytes.
        return None, off + size

    def _parse_encoded_array_at(self, off: int) -> Tuple[List[Any], int]:
        size, off = read_uleb(self.data, off)
        arr = []
        for _ in range(size):
            v, off = self._parse_encoded_value(off)
            arr.append(v)
        return arr, off

    def _parse(self) -> None:
        d = self.data
        hdr = {name: u32(d, off) for name, off in {
            "string_ids_size": 56, "string_ids_off": 60,
            "type_ids_size": 64, "type_ids_off": 68,
            "proto_ids_size": 72, "proto_ids_off": 76,
            "field_ids_size": 80, "field_ids_off": 84,
            "method_ids_size": 88, "method_ids_off": 92,
            "class_defs_size": 96, "class_defs_off": 100,
        }.items()}
        for i in range(hdr["string_ids_size"]):
            self.strings.append(self._read_string(u32(d, hdr["string_ids_off"] + i * 4)))
        for i in range(hdr["type_ids_size"]):
            self.types.append(self.strings[u32(d, hdr["type_ids_off"] + i * 4)])
        for i in range(hdr["proto_ids_size"]):
            off = hdr["proto_ids_off"] + i * 12
            _shorty_idx = u32(d, off)
            ret = self.types[u32(d, off + 4)]
            params = parse_type_list(d, u32(d, off + 8), self.types)
            self.protos.append((ret, params))
        for i in range(hdr["field_ids_size"]):
            off = hdr["field_ids_off"] + i * 8
            cls_idx, type_idx, name_idx = struct.unpack_from("<HHI", d, off)
            self.fields.append(FieldRef(self.types[cls_idx], self.types[type_idx], self.strings[name_idx]))
        for i in range(hdr["method_ids_size"]):
            off = hdr["method_ids_off"] + i * 8
            cls_idx, proto_idx, name_idx = struct.unpack_from("<HHI", d, off)
            ret, params = self.protos[proto_idx]
            self.methods.append(MethodRef(self.types[cls_idx], self.strings[name_idx], params, ret, proto_idx, i))

        for _i in range(hdr["class_defs_size"]):
            off = hdr["class_defs_off"] + _i * 32
            class_idx, _access, _super, _iface, _source, _ann, class_data_off, static_values_off = struct.unpack_from("<IIIIIIII", d, off)
            cls_desc = self.types[class_idx]
            if _super != 0xFFFFFFFF and 0 <= _super < len(self.types):
                self.super_by_class[cls_desc] = self.types[_super]
            if class_data_off == 0:
                continue
            p = class_data_off
            static_fields_size, p = read_uleb(d, p)
            instance_fields_size, p = read_uleb(d, p)
            direct_methods_size, p = read_uleb(d, p)
            virtual_methods_size, p = read_uleb(d, p)
            static_field_indices = []
            last_field = 0
            for _ in range(static_fields_size):
                diff, p = read_uleb(d, p)
                flags, p = read_uleb(d, p)
                last_field += diff
                static_field_indices.append(last_field)
            for _ in range(instance_fields_size):
                diff, p = read_uleb(d, p)
                flags, p = read_uleb(d, p)
                last_field += diff
            if static_values_off:
                vals, _ = self._parse_encoded_array_at(static_values_off)
                for idx, val in zip(static_field_indices, vals):
                    if 0 <= idx < len(self.fields):
                        f = self.fields[idx]
                        self.static_values[(f.cls, f.name)] = val
            # Method indices are delta-encoded independently for the direct and
            # virtual method lists.  Keeping one accumulator across both lists
            # silently loses most virtual methods (including page on_loading
            # events) in large protected V6 dex files.
            for method_count in (direct_methods_size, virtual_methods_size):
                last_method = 0
                for _ in range(method_count):
                    diff, p = read_uleb(d, p)
                    flags, p = read_uleb(d, p)
                    code_off, p = read_uleb(d, p)
                    last_method += diff
                    if code_off and 0 <= last_method < len(self.methods):
                        ref = self.methods[last_method]
                        impl = MethodImpl(ref, code_off, flags)
                        key = (ref.cls, ref.name, tuple(ref.params), ref.ret)
                        self.impls[key] = impl
                        self.impl_by_idx[ref.method_idx] = impl
                        self.impl_exact.setdefault((ref.cls, ref.name, tuple(ref.params)), impl)
                        self.impl_by_owner_name_arity.setdefault((ref.cls, ref.name, len(ref.params)), []).append(impl)

    def _inheritance_chain(self, cls_desc: str) -> Tuple[str, ...]:
        cached = self._inheritance_cache.get(cls_desc)
        if cached is not None:
            return cached
        chain: List[str] = []
        seen = set()
        cur = cls_desc
        while cur and cur not in seen:
            chain.append(cur)
            seen.add(cur)
            cur = self.super_by_class.get(cur, '')
        out = tuple(chain)
        self._inheritance_cache[cls_desc] = out
        return out

    def find_method(self, class_name: str, method_name: str, param_descs: List[str]) -> Optional[MethodImpl]:
        cls_desc = human_to_desc(class_name)
        params = tuple(param_descs)
        cache_key = (cls_desc, method_name, params)
        if cache_key in self._find_method_cache:
            return self._find_method_cache[cache_key]
        result: Optional[MethodImpl] = None
        for owner in self._inheritance_chain(cls_desc):
            result = self.impl_exact.get((owner, method_name, params))
            if result is not None:
                break
        if result is None:
            arity = len(params)
            for owner in self._inheritance_chain(cls_desc):
                choices = self.impl_by_owner_name_arity.get((owner, method_name, arity))
                if choices:
                    result = choices[0]
                    break
        self._find_method_cache[cache_key] = result
        return result

class DexVM:
    def __init__(self, dexes: List[DexFile], max_steps: int = 20000, max_depth: int = 10):
        self.dexes = dexes
        self.max_steps = max_steps
        self.max_depth = max_depth
        self.cache: Dict[Tuple[str, str, Tuple[str, ...], Tuple[Any, ...]], Any] = {}
        self.failures: List[str] = []

    def find_method(self, class_name: str, method_name: str, params: List[str]) -> Optional[Tuple[DexFile, MethodImpl]]:
        pdesc = [human_to_desc(p) for p in params]
        for dex in self.dexes:
            impl = dex.find_method(class_name, method_name, pdesc)
            if impl:
                return dex, impl
        return None

    def call(self, class_name: str, method_name: str, params: List[str], args: List[Any]) -> Optional[Any]:
        found = self.find_method(class_name, method_name, params)
        if not found:
            self.failures.append(f"method_not_found {class_name}.{method_name}({','.join(params)})")
            return None
        dex, impl = found
        try:
            return self._exec(dex, impl, args, 0)
        except Exception as e:
            self.failures.append(f"exec_failed {desc_to_human(impl.ref.cls)}.{impl.ref.name}: {e}")
            return None

    def _exec(self, dex: DexFile, impl: MethodImpl, args: List[Any], depth: int) -> Any:
        if depth > self.max_depth:
            raise DexError("max recursion depth")
        cache_key = (impl.ref.cls, impl.ref.name, tuple(impl.ref.params), tuple(str(x) for x in args))
        if cache_key in self.cache:
            return self.cache[cache_key]
        d = dex.data
        off = impl.code_off
        registers_size = u16(d, off)
        ins_size = u16(d, off + 2)
        insns_size = u32(d, off + 12)
        insns_off = off + 16
        units = [u16(d, insns_off + i * 2) for i in range(insns_size)]
        regs: List[Any] = [0] * registers_size
        # Parameters live in the last ins_size registers. Non-static methods include `this`.
        start = max(0, registers_size - ins_size)
        params_to_place = args[:]
        if len(params_to_place) < ins_size and not (impl.access_flags & 0x0008):
            params_to_place = [Obj(impl.ref.cls)] + params_to_place
        for i, v in enumerate(params_to_place[-ins_size:]):
            if start + i < registers_size:
                regs[start + i] = v
        pc = 0
        last_result: Any = None
        steps = 0
        while 0 <= pc < len(units):
            steps += 1
            if steps > self.max_steps:
                raise DexError("step limit")
            u0 = units[pc]
            op = u0 & 0xff
            aa = (u0 >> 8) & 0xff
            try:
                if op == 0x00:  # nop / payload skip
                    pc += 1
                elif op in (0x01, 0x07):  # move/object 12x
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf
                    regs[a] = regs[b]; pc += 1
                elif op in (0x02, 0x08):  # move/from16
                    regs[aa] = regs[units[pc+1]]; pc += 2
                elif op in (0x03, 0x09):  # move/16
                    regs[units[pc+1]] = regs[units[pc+2]]; pc += 3
                elif op in (0x0a, 0x0c):
                    regs[aa] = last_result; pc += 1
                elif op == 0x0b:
                    regs[aa] = last_result; pc += 1
                elif op in (0x0e,):
                    self.cache[cache_key] = None; return None
                elif op in (0x0f, 0x10, 0x11):
                    self.cache[cache_key] = regs[aa]; return regs[aa]
                elif op == 0x12:  # const/4
                    a = (u0 >> 8) & 0xf; lit = sign8((u0 >> 12) & 0xf)
                    if lit & 0x8: lit -= 0x10
                    regs[a] = lit; pc += 1
                elif op == 0x13:  # const/16
                    regs[aa] = sign16(units[pc+1]); pc += 2
                elif op == 0x14:  # const
                    regs[aa] = sign32(units[pc+1] | (units[pc+2] << 16)); pc += 3
                elif op == 0x15:
                    regs[aa] = sign32(units[pc+1] << 16); pc += 2
                elif op == 0x16:
                    regs[aa] = sign16(units[pc+1]); pc += 2
                elif op == 0x17:
                    regs[aa] = sign32(units[pc+1] | (units[pc+2] << 16)); pc += 3
                elif op == 0x18:
                    lo = units[pc+1] | (units[pc+2] << 16)
                    hi = units[pc+3] | (units[pc+4] << 16)
                    regs[aa] = (hi << 32) | lo; pc += 5
                elif op == 0x1a:  # const-string
                    idx = units[pc+1]
                    regs[aa] = dex.strings[idx] if idx < len(dex.strings) else ""; pc += 2
                elif op == 0x1b:  # jumbo
                    idx = units[pc+1] | (units[pc+2] << 16)
                    regs[aa] = dex.strings[idx] if idx < len(dex.strings) else ""; pc += 3
                elif op == 0x1c:  # const-class
                    idx = units[pc+1]; regs[aa] = dex.types[idx] if idx < len(dex.types) else ""; pc += 2
                elif op == 0x1f:  # check-cast
                    pc += 2
                elif op == 0x21:  # array-length
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf
                    regs[a] = len(regs[b] or []); pc += 1
                elif op == 0x22:  # new-instance
                    typ = dex.types[units[pc+1]]
                    regs[aa] = Obj(typ); pc += 2
                elif op == 0x23:  # new-array 22c
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf
                    size = int(regs[b] or 0)
                    regs[a] = [0] * max(0, size); pc += 2
                elif op == 0x24:  # filled-new-array 35c
                    count = (u0 >> 12) & 0xf
                    g = (u0 >> 8) & 0xf
                    u2v = units[pc + 2]
                    reg_ids = [
                        u2v & 0xf,
                        (u2v >> 4) & 0xf,
                        (u2v >> 8) & 0xf,
                        (u2v >> 12) & 0xf,
                        g,
                    ][:count]
                    last_result = [regs[r] for r in reg_ids]
                    pc += 3
                elif op == 0x25:  # filled-new-array/range 3rc
                    count = aa
                    start_reg = units[pc + 2]
                    last_result = [regs[start_reg + i] for i in range(count)]
                    pc += 3
                elif op == 0x26:  # fill-array-data
                    a = aa; offset_words = s32_from_units(units[pc+1], units[pc+2])
                    payload = pc + offset_words
                    arr = regs[a]
                    if 0 <= payload + 4 <= len(units):
                        ident = units[payload]
                        elem_width = units[payload+1]
                        size = units[payload+2] | (units[payload+3] << 16)
                        byte_off = insns_off + (payload + 4) * 2
                        vals = []
                        for i in range(size):
                            vals.append(read_sized_int(d, byte_off + i * elem_width, elem_width, True))
                        if isinstance(arr, list):
                            arr[:len(vals)] = vals
                    pc += 3
                elif op in (0x28,):  # goto
                    pc += sign8(aa)
                elif op == 0x29:
                    pc += sign16(units[pc+1])
                elif op == 0x2a:
                    pc += s32_from_units(units[pc+1], units[pc+2])
                elif op in (0x2b, 0x2c):  # packed/sparse-switch 31t
                    payload = pc + s32_from_units(units[pc+1], units[pc+2])
                    key = int(regs[aa] or 0)
                    target = None
                    if 0 <= payload + 2 <= len(units):
                        ident = units[payload]
                        size = units[payload + 1]
                        if ident == 0x0100 and payload + 4 + size * 2 <= len(units):
                            first = s32_from_units(units[payload + 2], units[payload + 3])
                            idx = key - first
                            if 0 <= idx < size:
                                pos = payload + 4 + idx * 2
                                target = s32_from_units(units[pos], units[pos + 1])
                        elif ident == 0x0200 and payload + 2 + size * 4 <= len(units):
                            key_pos = payload + 2
                            tgt_pos = key_pos + size * 2
                            for j in range(size):
                                k = s32_from_units(units[key_pos + j * 2], units[key_pos + j * 2 + 1])
                                if k == key:
                                    target = s32_from_units(units[tgt_pos + j * 2], units[tgt_pos + j * 2 + 1])
                                    break
                    pc += target if target is not None else 3
                elif 0x32 <= op <= 0x37:  # if-test
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf; off16 = sign16(units[pc+1])
                    av, bv = regs[a], regs[b]
                    which = op - 0x32
                    if which == 0: cond = av == bv
                    elif which == 1: cond = av != bv
                    elif which == 2: cond = av < bv
                    elif which == 3: cond = av >= bv
                    elif which == 4: cond = av > bv
                    else: cond = av <= bv
                    pc += off16 if cond else 2
                elif 0x38 <= op <= 0x3d:  # if-testz
                    v = regs[aa]; off16 = sign16(units[pc+1])
                    which = op - 0x38
                    if which == 0: cond = v == 0 or v is None
                    elif which == 1: cond = v != 0 and v is not None
                    elif which == 2: cond = v is not None and v < 0
                    elif which == 3: cond = v is not None and v >= 0
                    elif which == 4: cond = v is not None and v > 0
                    else: cond = v is None or v <= 0
                    pc += off16 if cond else 2
                elif 0x44 <= op <= 0x51:  # aget/aput variants 23x
                    a = aa; b = units[pc+1] & 0xff; c = (units[pc+1] >> 8) & 0xff
                    if 0x44 <= op <= 0x4a:
                        arr = regs[b]
                        try:
                            idx = int(regs[c] or 0)
                        except Exception:
                            idx = 0
                        if isinstance(arr, (list, tuple, bytes, bytearray)) and 0 <= idx < len(arr):
                            regs[a] = arr[idx]
                        else:
                            # Runtime-fed arrays (for example a JSON parser over an HTTP
                            # response) are not statically available.  Continue with a
                            # neutral scalar instead of aborting the whole event method;
                            # concrete side effects before/after this helper can still be
                            # recovered safely.
                            regs[a] = 0
                    else:
                        arr = regs[b]
                        try:
                            idx = int(regs[c] or 0)
                        except Exception:
                            idx = 0
                        if isinstance(arr, list) and 0 <= idx < len(arr):
                            arr[idx] = regs[a]
                    pc += 2
                elif 0x52 <= op <= 0x5f:  # iget/iput 22c
                    # 22c stores vA/vB in the two nibbles of the first code unit;
                    # the second code unit is the field index.  The old parser
                    # treated AA as an 8-bit register and therefore discarded
                    # listener/inner-class state needed by V6 event recovery.
                    a = (u0 >> 8) & 0x0f
                    b = (u0 >> 12) & 0x0f
                    field_idx = units[pc + 1]
                    f = dex.fields[field_idx] if field_idx < len(dex.fields) else None
                    field_name = f.name if f else str(field_idx)
                    obj = regs[b]
                    if op <= 0x58:  # iget variants
                        if isinstance(obj, Obj):
                            regs[a] = obj.fields.get(field_name)
                        elif isinstance(obj, dict):
                            regs[a] = obj.get(field_name)
                        else:
                            regs[a] = None
                    else:  # iput variants
                        if isinstance(obj, Obj):
                            obj.fields[field_name] = regs[a]
                        elif isinstance(obj, dict):
                            obj[field_name] = regs[a]
                    pc += 2
                elif 0x60 <= op <= 0x6d:  # sget/sput 21c
                    field_idx = units[pc+1]
                    f = dex.fields[field_idx] if field_idx < len(dex.fields) else None
                    if op <= 0x66:
                        value = dex.static_values.get((f.cls, f.name)) if f else None
                        if f and value is None and f.typ in ("Ljava/util/Map;", "Ljava/util/HashMap;", "Ljava/util/LinkedHashMap;"):
                            value = Obj(f.typ, {})
                            dex.static_values[(f.cls, f.name)] = value
                        regs[aa] = value
                    else:
                        if f:
                            dex.static_values[(f.cls, f.name)] = regs[aa]
                    pc += 2
                elif op in (0x6e, 0x6f, 0x70, 0x71, 0x72):  # invoke-kind
                    count = (u0 >> 12) & 0xf; g = (u0 >> 8) & 0xf
                    method_idx = units[pc+1]
                    u2v = units[pc+2]
                    regs_idx = [u2v & 0xf, (u2v >> 4) & 0xf, (u2v >> 8) & 0xf, (u2v >> 12) & 0xf, g][:count]
                    args2 = [regs[r] for r in regs_idx]
                    ref = dex.methods[method_idx]
                    last_result = self._invoke(dex, ref, args2, depth)
                    pc += 3
                elif op in (0x74, 0x75, 0x76, 0x77, 0x78):  # invoke-kind/range
                    count = aa; method_idx = units[pc+1]; start_reg = units[pc+2]
                    args2 = [regs[start_reg+i] for i in range(count)]
                    ref = dex.methods[method_idx]
                    last_result = self._invoke(dex, ref, args2, depth)
                    pc += 3
                elif 0x7b <= op <= 0x8f:  # unary conversions 12x
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf
                    v = regs[b]
                    if op == 0x7b: regs[a] = -int(v)
                    elif op == 0x7c: regs[a] = ~int(v)
                    elif op == 0x8a: regs[a] = sign8(int(v))
                    elif op == 0x8b: regs[a] = int(v) & 0xffff
                    elif op == 0x8c: regs[a] = sign16(int(v))
                    else: regs[a] = v
                    pc += 1
                elif 0x90 <= op <= 0xaf:  # binop 23x
                    a = aa; b = units[pc+1] & 0xff; c = (units[pc+1] >> 8) & 0xff
                    regs[a] = self._binop(op, regs[b], regs[c]); pc += 2
                elif 0xb0 <= op <= 0xcf:  # binop/2addr 12x
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf
                    regs[a] = self._binop(0x90 + (op - 0xb0), regs[a], regs[b]); pc += 1
                elif 0xd0 <= op <= 0xd7:  # binop/lit16 22s
                    a = (u0 >> 8) & 0xf; b = (u0 >> 12) & 0xf; lit = sign16(units[pc+1])
                    regs[a] = self._binop(0x90 + (op - 0xd0), regs[b], lit); pc += 2
                elif 0xd8 <= op <= 0xe2:  # binop/lit8 22b
                    a = aa; b = units[pc+1] & 0xff; lit = sign8((units[pc+1] >> 8) & 0xff)
                    map_op = {0xd8:0x90,0xd9:0x91,0xda:0x92,0xdb:0x93,0xdc:0x94,0xdd:0x95,0xde:0x96,0xdf:0x97,0xe0:0x98,0xe1:0x99,0xe2:0x9a}[op]
                    regs[a] = self._binop(map_op, regs[b], lit); pc += 2
                else:
                    # Conservative skip for uncommon formats.
                    pc += self._size_of(op)
            except Exception as e:
                raise DexError(f"pc={pc} op=0x{op:02x}: {e}") from e
        self.cache[cache_key] = None
        return None

    def _size_of(self, op: int) -> int:
        if op in {0x00,0x01,0x04,0x07,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,0x11,0x12,0x1d,0x1e,0x27,0x28,0x7b,0x7c,0x7d,0x7e,0x7f,0x80,0x81,0x82,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8a,0x8b,0x8c}:
            return 1
        if op in set(range(0x02,0x09)) | {0x13,0x15,0x16,0x19,0x1a,0x1c,0x1f,0x20,0x21,0x22,0x23,0x29} | set(range(0x2d,0x3e)) | set(range(0x44,0x6e)) | set(range(0xd0,0xe3)):
            return 2
        if op in {0x03,0x09,0x14,0x1b,0x24,0x25,0x26,0x2a,0x2b,0x2c} | set(range(0x6e,0x79)) | set(range(0x90,0xb0)):
            return 3
        if op == 0x18:
            return 5
        return 1

    def _binop(self, op: int, a: Any, b: Any) -> int:
        a = int(a or 0); b = int(b or 0)
        if op in (0x90, 0x9b, 0xa6): return sign32(a + b)
        if op in (0x91, 0x9c, 0xa7): return sign32(a - b)
        if op in (0x92, 0x9d, 0xa8): return sign32(a * b)
        if op in (0x93, 0x9e, 0xa9): return 0 if b == 0 else sign32(int(a / b))
        if op in (0x94, 0x9f, 0xaa): return 0 if b == 0 else sign32(a % b)
        if op in (0x95, 0xa0, 0xab): return sign32(a & b)
        if op in (0x96, 0xa1, 0xac): return sign32(a | b)
        if op in (0x97, 0xa2, 0xad): return sign32(a ^ b)
        if op in (0x98, 0xa3, 0xae): return sign32(a << (b & 0x1f))
        if op in (0x99, 0xa4, 0xaf): return sign32(a >> (b & 0x1f))
        if op in (0x9a, 0xa5): return (a & 0xffffffff) >> (b & 0x1f)
        return 0

    def _obj_str(self, v: Any) -> str:
        if isinstance(v, Obj):
            return str(v.value or "")
        if isinstance(v, list):
            try:
                return "".join(chr(int(x) & 0xffff) for x in v)
            except Exception:
                return str(v)
        return str(v if v is not None else "")

    def _new_string_from(self, arg: Any, charset: Optional[Any] = None) -> str:
        if isinstance(arg, str):
            return arg
        if isinstance(arg, list):
            # Heuristic: char[] if values exceed byte range, otherwise bytes first.
            if any(isinstance(x, str) for x in arg):
                return "".join(str(x) for x in arg)
            if any(int(x) > 255 or int(x) < -128 for x in arg):
                return "".join(chr(int(x) & 0xffff) for x in arg)
            data = bytes((int(x) & 0xff) for x in arg)
            encs = []
            if charset:
                encs.append(self._obj_str(charset))
            encs += ["utf-8", "gb18030", "gbk", "latin1"]
            for enc in encs:
                try:
                    return data.decode(enc)
                except Exception:
                    pass
            return data.decode("utf-8", "replace")
        return self._obj_str(arg)

    def _invoke(self, dex: DexFile, ref: MethodRef, args: List[Any], depth: int) -> Any:
        cls, name = ref.cls, ref.name
        # LianYi.NB wrapper subclasses inherit a common Object->Object helper.
        # Its String branch is an identity conversion (the other branches read
        # reflected Fields).  Modeling the confirmed String path lets n(int)
        # constant decryptors complete without executing reflection machinery.
        if (cls.startswith("LLianYi/NB/") and ref.params == ["Ljava/lang/Object;"]
                and ref.ret == "Ljava/lang/Object;" and args):
            if isinstance(args[0], str):
                return args[0]
            if isinstance(args[0], Obj) and args[0].typ == "Ljava/lang/String;":
                return self._obj_str(args[0])
        # Constructors mutate the first object and return void.
        if name == "<init>" and args and isinstance(args[0], Obj):
            obj = args[0]
            if cls == "Ljava/lang/StringBuilder;":
                obj.value = [] if len(args) == 1 else [self._obj_str(args[1])]
            elif cls == "Ljava/lang/String;":
                obj.value = self._new_string_from(args[1], args[2] if len(args) > 2 else None) if len(args) > 1 else ""
            elif cls in ("Ljava/util/HashMap;", "Ljava/util/LinkedHashMap;", "Ljava/util/Map;"):
                obj.value = {} if not isinstance(obj.value, dict) else obj.value
            else:
                obj.value = obj.value
            return None
        # Map/HashMap cache helpers used by LianYi.NB one-argument string
        # decryptors.  Their p1/p2/p3 methods are tiny wrappers around Map.get
        # and Map.put; modeling the map allows the VM to execute the real n(int)
        # method instead of returning None at its first cache lookup.
        if cls in {"Ljava/util/Map;", "Ljava/util/HashMap;", "Ljava/util/LinkedHashMap;"}:
            obj = args[0] if args else None
            if isinstance(obj, Obj):
                if not isinstance(obj.value, dict):
                    obj.value = {}
                store = obj.value
            elif isinstance(obj, dict):
                store = obj
            else:
                store = {}
            if name == "get":
                return store.get(args[1] if len(args) > 1 else None)
            if name == "put":
                key = args[1] if len(args) > 1 else None
                value = args[2] if len(args) > 2 else None
                old = store.get(key)
                store[key] = value
                return old
            if name == "containsKey":
                return (args[1] if len(args) > 1 else None) in store
            if name == "remove":
                return store.pop(args[1] if len(args) > 1 else None, None)
            if name == "size":
                return len(store)

        # StringBuilder virtuals
        if cls == "Ljava/lang/StringBuilder;":
            obj = args[0] if args else Obj(cls, [])
            if not isinstance(obj, Obj):
                obj = Obj(cls, [])
            if obj.value is None:
                obj.value = []
            if name == "append":
                obj.value.append(self._obj_str(args[1] if len(args) > 1 else ""))
                return obj
            if name == "toString":
                return "".join(str(x) for x in (obj.value or []))
        # String methods
        if cls == "Ljava/lang/String;":
            s = self._obj_str(args[0]) if args else ""
            if name == "length": return len(s)
            if name == "charAt": return ord(s[int(args[1])])
            if name == "substring":
                a = int(args[1]); b = int(args[2]) if len(args) > 2 else len(s)
                return s[a:b]
            if name == "toCharArray": return [ord(ch) for ch in s]
            if name == "getBytes":
                enc = self._obj_str(args[1]) if len(args) > 1 else "utf-8"
                try: return list(s.encode(enc))
                except Exception: return list(s.encode("utf-8"))
            if name == "split": return s.split(self._obj_str(args[1]))
            if name == "trim": return s.strip()
            if name == "replace" and len(args) >= 3: return s.replace(self._obj_str(args[1]), self._obj_str(args[2]))
            if name == "intern": return args[0] if args else s
            if name == "hashCode":
                h = 0
                for ch in s:
                    h = sign32(31 * h + ord(ch))
                return h
            if name == "equals": return s == self._obj_str(args[1] if len(args) > 1 else "")
            if name == "isEmpty": return len(s) == 0
            if name == "startsWith": return s.startswith(self._obj_str(args[1] if len(args) > 1 else ""))
            if name == "endsWith": return s.endswith(self._obj_str(args[1] if len(args) > 1 else ""))
            if name == "contains": return self._obj_str(args[1] if len(args) > 1 else "") in s
            if name == "valueOf" and len(args) >= 1: return self._obj_str(args[0])
        if cls in {"Ljava/lang/Integer;", "Ljava/lang/Long;", "Ljava/lang/Short;", "Ljava/lang/Byte;"}:
            if name == "parseInt" or name == "parseLong" or name == "valueOf":
                try: return int(self._obj_str(args[0]), int(args[1]) if len(args) > 1 else 10)
                except Exception: return 0
        if cls == "Ljava/lang/Character;" and name == "toString":
            return chr(int(args[0]) & 0xffff)
        if cls == "Ljava/lang/String;" and name == "format":
            return self._obj_str(args[0])
        if cls in {"Landroid/util/Base64;", "Ljava/util/Base64;"} and name in {"decode", "getDecoder"}:
            if name == "decode":
                data = base64.b64decode(self._obj_str(args[0]) + "=" * (-len(self._obj_str(args[0])) % 4))
                return list(data)
        # Same-dex static/direct helper methods.
        impl = dex.impl_by_idx.get(ref.method_idx)
        if impl:
            # Drop receiver for virtual/direct method if present.
            call_args = args
            if not (impl.access_flags & 0x0008) and call_args:
                call_args = call_args[1:]
            return self._exec(dex, impl, call_args, depth + 1)
        return None

# -------------------------- iYU reflection restore --------------------------

CALL_RE = re.compile(r'\b(cls|javax|java|javanew|btoo|hw|hws|tw|loadjar|ss|s)\s*\((.*?)\)', re.S)


def eval_arg(raw: str, values: Dict[str, str]) -> Any:
    raw = raw.strip()
    if len(raw) >= 2 and raw[0] == raw[-1] and raw[0] in "\"'":
        return unquote_iyu(raw)
    if raw in values:
        return values[raw]
    if re.fullmatch(r"-?\d+", raw):
        try: return int(raw)
        except Exception: pass
    if raw in {"true", "false"}:
        return raw == "true"
    if raw == "null":
        return None
    return raw


def restore_reflection_text(text: str, vm: Optional[DexVM]) -> Tuple[str, Dict[str, str], Dict[str, Any]]:
    # First restore Base64/btoo constants so cls/javax names become literal.
    text, btoo_values, btoo_count = restore_base64_btoo(text)
    values: Dict[str, str] = dict(btoo_values)
    class_vars: Dict[str, str] = {}
    remove_spans: List[Tuple[int, int]] = []
    restored: List[Dict[str, Any]] = []
    failed: List[Dict[str, Any]] = []

    for m in CALL_RE.finditer(text):
        fn = m.group(1)
        args = split_args(m.group(2))
        if fn == "cls" and len(args) >= 3:
            class_name = eval_arg(args[1], values)
            dest = args[2].strip()
            if isinstance(class_name, str) and dest:
                class_vars[dest] = class_name
                # Keep cls(...) unless a later successful javax makes it dead; preserving it avoids breaking output when no dex/static result is available.
        elif fn == "javax" and len(args) >= 5:
            out_var = args[0].strip()
            target = eval_arg(args[2], values)
            if isinstance(target, str) and target in class_vars:
                class_name = class_vars[target]
            elif isinstance(target, str):
                class_name = target
            else:
                class_name = ""
            method = eval_arg(args[3], values)
            sig_vals = args[4:]
            param_types: List[str] = []
            param_args: List[Any] = []
            i = 0
            while i + 1 < len(sig_vals):
                typ = eval_arg(sig_vals[i], values)
                val = eval_arg(sig_vals[i + 1], values)
                param_types.append(str(typ))
                param_args.append(val)
                i += 2
            result = None
            if vm and class_name and isinstance(method, str):
                result = vm.call(class_name, method, param_types, param_args)
            if isinstance(result, (str, int, bool)):
                values[out_var] = str(result)
                remove_spans.append(m.span())
                restored.append({"out": out_var, "class": class_name, "method": method, "args": param_args, "result": str(result)})
            else:
                failed.append({"out": out_var, "class": class_name, "method": method, "args": param_args, "reason": "no_static_result"})

    if remove_spans:
        parts = []
        last = 0
        for st, ed in sorted(remove_spans):
            parts.append(text[last:st])
            # Remove a possible empty line only; keep code readable.
            last = ed
        parts.append(text[last:])
        text = "".join(parts)
        text = re.sub(r'^[ \t]*\n(?=[ \t]*\n)', '', text, flags=re.M)

    # Inline values in hw/hws/tw and generally outside strings.
    text = replace_tokens_outside_strings(text, values)
    stats = {"btoo_constants": btoo_count, "reflect_restored": len(restored), "reflect_failed": len(failed), "restored": restored, "failed": failed}
    return text, values, stats

# -------------------------- DEX collection and archive IO --------------------------


def _file_looks_dex(p: Path) -> bool:
    try:
        with p.open("rb") as f:
            return f.read(4) == b"dex\n"
    except Exception:
        return False


def _archive_looks_zip(p: Path) -> bool:
    try:
        return zipfile.is_zipfile(p)
    except Exception:
        return False


def collect_dex_paths(paths: Iterable[Path]) -> List[Path]:
    """Collect usable DEX files from explicit inputs and source-tree extras.

    The caller may pass files with misleading extensions because Android/iApp
    projects often keep helper dex/jar/apk files under apk/lib or upload them
    as a generic multipart part.  Therefore detection is based on file magic
    first, not only on the suffix.  ZIP/APK/JAR inputs are scanned for nested
    *.dex entries; directories are scanned recursively.
    """
    out: List[Path] = []
    for p in paths:
        if not p or not p.exists():
            continue
        if p.is_dir():
            # Include plain dex files and scan apk/zip/jar files under the tree.
            for x in sorted(q for q in p.rglob("*") if q.is_file()):
                if _file_looks_dex(x):
                    out.append(x)
                elif _archive_looks_zip(x) or x.suffix.lower() in {".apk", ".zip", ".jar"}:
                    out.extend(collect_dex_paths([x]))
            continue
        if _file_looks_dex(p):
            out.append(p)
            continue
        if _archive_looks_zip(p) or p.suffix.lower() in {".apk", ".zip", ".jar"}:
            tmp = []
            try:
                with zipfile.ZipFile(p) as z:
                    for n in z.namelist():
                        if n.lower().endswith(".dex"):
                            data = z.read(n)
                            if not data.startswith(b"dex\n"):
                                continue
                            safe = re.sub(r"[^A-Za-z0-9_.-]+", "_", p.stem + "_" + Path(n).name)
                            q = Path(tempfile.gettempdir()) / ("iapp_static_" + safe)
                            q.write_bytes(data)
                            tmp.append(q)
                out.extend(tmp)
            except Exception:
                pass
    # de-dup by sha-ish cheap key: resolved path + size + mtime, enough for temp extraction.
    seen = set(); uniq=[]
    for p in out:
        try:
            key = (str(p.resolve()), p.stat().st_size, int(p.stat().st_mtime))
        except Exception:
            key = (str(p), 0, 0)
        if key not in seen:
            seen.add(key); uniq.append(p)
    return uniq


def copy_explicit_inputs_back(inputs: Iterable[Path], out_dir: Path) -> List[str]:
    """Return explicit dex/lib inputs in the output zip under _iapt_extra_inputs/.

    Files already present in the source zip, such as project apk/lib/*, are copied
    by the main tree walk.  This only preserves separately uploaded DEX/APK/ZIP
    files so they are not lost after processing.
    """
    copied: List[str] = []
    root = out_dir / "_iapt_extra_inputs"
    for src in inputs or []:
        try:
            if not src or not src.exists():
                continue
            if src.is_dir():
                base = root / re.sub(r"[^A-Za-z0-9_.-]+", "_", src.name or "input_dir")
                for p in sorted(q for q in src.rglob("*") if q.is_file()):
                    rel = p.relative_to(src).as_posix()
                    dst = base / rel
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(p, dst)
                    copied.append(dst.relative_to(out_dir).as_posix())
            else:
                name = re.sub(r"[^A-Za-z0-9_.-]+", "_", src.name or "input.bin")
                dst = root / name
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst)
                copied.append(dst.relative_to(out_dir).as_posix())
        except Exception:
            continue
    return copied


def build_vm(dex_paths: List[Path]) -> Tuple[Optional[DexVM], List[str]]:
    dexes: List[DexFile] = []
    logs: List[str] = []
    for p in dex_paths:
        try:
            dexes.append(DexFile(p.read_bytes(), p.name))
            logs.append(f"loaded {p} methods={len(dexes[-1].methods)} impls={len(dexes[-1].impls)}")
        except Exception as e:
            logs.append(f"skip {p}: {e}")
    return (DexVM(dexes) if dexes else None), logs


def restore_tree(input_path: Path, output_path: Path, dex_inputs: List[Path], flat_v3: bool = True) -> Dict[str, Any]:
    tmp_root = Path(tempfile.mkdtemp(prefix="iapp_static_restore_"))
    in_dir = tmp_root / "in"
    out_dir = tmp_root / "out"
    in_dir.mkdir(); out_dir.mkdir()
    try:
        if input_path.is_dir():
            shutil.copytree(input_path, in_dir, dirs_exist_ok=True)
        elif input_path.suffix.lower() == ".zip":
            with zipfile.ZipFile(input_path) as z:
                z.extractall(in_dir)
        else:
            in_dir.joinpath(input_path.name).write_bytes(input_path.read_bytes())

        # Explicit dex/apk/zip/dir inputs are optional.  The source ZIP itself may
        # already contain apk/lib/* files; search that whole source tree too.
        dex_paths = collect_dex_paths(dex_inputs)
        dex_paths.extend(collect_dex_paths([in_dir]))
        vm, dex_logs = build_vm(dex_paths)
        total_stats: Dict[str, Any] = {"files": {}, "dex": dex_logs, "vm_failures": [], "extra_inputs": []}
        try:
            total_stats["extra_inputs"] = copy_explicit_inputs_back(dex_inputs, out_dir)
        except Exception:
            total_stats["extra_inputs"] = []

        for p in sorted(in_dir.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(in_dir)
            dst = out_dir / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if is_text_file(p):
                text = decode_text(p.read_bytes())[0]
                text = strip_bad_controls(text)
                new_text, _vals, stats = restore_reflection_text(text, vm)
                if flat_v3 and p.suffix.lower() == ".iyu":
                    new_text = repair_flat_iyu(new_text)
                dst.write_text(new_text, encoding="utf-8", newline="")
                if stats["btoo_constants"] or stats["reflect_restored"] or stats["reflect_failed"]:
                    total_stats["files"][rel.as_posix()] = stats
            else:
                shutil.copy2(p, dst)
        if vm:
            total_stats["vm_failures"] = vm.failures[-200:]
        (out_dir / "static_dex_restore_map.txt").write_text(json.dumps(total_stats, ensure_ascii=False, indent=2), encoding="utf-8")

        if output_path.suffix.lower() == ".zip" or input_path.suffix.lower() == ".zip" or not input_path.is_file():
            output_path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(output_path, "w", zipfile.ZIP_DEFLATED) as z:
                for p in sorted(out_dir.rglob("*")):
                    if p.is_file():
                        z.write(p, p.relative_to(out_dir).as_posix())
        elif input_path.is_file():
            files = [p for p in out_dir.rglob("*") if p.is_file()]
            if files:
                output_path.write_bytes(files[0].read_bytes())
        return total_stats
    finally:
        shutil.rmtree(tmp_root, ignore_errors=True)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Pure static iApp iYU + DEX reflection deobfuscator")
    ap.add_argument("input", type=Path, help="source zip/dir/file")
    ap.add_argument("-o", "--output", type=Path, default=Path("source_static_restored.zip"), help="output zip/dir/file")
    ap.add_argument("--dex", action="append", type=Path, default=[], help="dex/apk/zip/dir containing decrypt dex; can be repeated")
    ap.add_argument("--no-flat-v3", action="store_true", help="do not normalize .iyu to V3 flat View format")
    ap.add_argument("--print-stats", action="store_true")
    args = ap.parse_args(argv)
    stats = restore_tree(args.input, args.output, args.dex, flat_v3=not args.no_flat_v3)
    print(args.output)
    if args.print_stats:
        print(json.dumps(stats, ensure_ascii=False, indent=2)[:10000])
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
