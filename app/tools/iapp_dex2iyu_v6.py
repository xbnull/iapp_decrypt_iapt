#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iApp/AIDE-style APK dex -> .iyu UI source recoverer

Designed for samples where the iApp UI DSL has been compiled into classes.dex as
calls such as Li6/runlibrary/app/v/xxbj.width(...), wb.text(...), etc.

Usage:
  python3 iapp_dex2iyu_v6.py --apk app.apk --outdir recovered
  python3 iapp_dex2iyu_v6.py --apk project.zip --outdir recovered
  python3 iapp_dex2iyu_v6.py --apk app.apk --outdir recovered --no-java

The iApp UI recovery part uses only Python stdlib and symbolically reads the
view-building method on_$_viewAutomaticSettingEvent.

Complete Java recovery is done by invoking JADX.  A dex parser can recover the
.iyu UI/events, but full Java source is decompilation, not string decryption; the
script therefore calls a real Java decompiler instead of outputting fake stubs.
"""
from __future__ import annotations

import argparse
import html
import math
import json
import xml.etree.ElementTree as ET
import os
import re
import struct
import sys
import zipfile
import shutil
import subprocess
import time
import tempfile
from pathlib import Path
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

NO_INDEX = 0xFFFFFFFF
TOOL_VERSION = 'v30.0-v6-root-java-reflection-bridge-20260712'



class UserFacingError(Exception):
    """An expected CLI error that should be shown without a Python traceback."""


def format_path_hint(path: str) -> str:
    """Return a user-friendly diagnostic hint for missing/invalid input paths."""
    cwd = os.getcwd()
    expanded = os.path.abspath(os.path.expanduser(path))
    lines = [
        f'[错误] 输入文件不存在：{path}',
        f'[诊断] 当前目录：{cwd}',
        f'[诊断] 解析后的路径：{expanded}',
    ]
    # Show nearby APK/ZIP files to make the common "不在当前目录" problem obvious.
    try:
        nearby = sorted(x for x in os.listdir(cwd) if x.lower().endswith(('.apk', '.zip', '.dex')))
        if nearby:
            max_show = 12
            lines.append('[诊断] 当前目录可见的 apk/zip/dex：')
            for name in nearby[:max_show]:
                lines.append(f'  - {name}')
            if len(nearby) > max_show:
                lines.append(f'  ... 还有 {len(nearby) - max_show} 个')
        else:
            lines.append('[诊断] 当前目录没有看到 .apk / .zip / .dex 文件。')
    except Exception:
        pass
    lines.extend([
        '[建议] 把 APK 放到当前目录，或使用完整路径，例如：',
        f'  python3 {os.path.basename(sys.argv[0])} /完整路径/{os.path.basename(path)} -o recovered',
    ])
    return '\n'.join(lines)


def normalize_input_path(path: str) -> str:
    return os.path.abspath(os.path.expanduser(path))


def u2(buf: bytes, off: int) -> int:
    return struct.unpack_from('<H', buf, off)[0]


def u4(buf: bytes, off: int) -> int:
    return struct.unpack_from('<I', buf, off)[0]


def i2(x: int) -> int:
    return struct.unpack('<h', struct.pack('<H', x & 0xFFFF))[0]


def i4(x: int) -> int:
    return struct.unpack('<i', struct.pack('<I', x & 0xFFFFFFFF))[0]


def s4bit(n: int) -> int:
    n &= 0xF
    return n - 16 if n >= 8 else n


def s8(n: int) -> int:
    n &= 0xFF
    return n - 256 if n >= 128 else n


def uleb128(buf: bytes, off: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    i = off
    while True:
        b = buf[i]
        i += 1
        result |= (b & 0x7F) << shift
        if not (b & 0x80):
            break
        shift += 7
    return result, i


@dataclass
class Proto:
    ret: str
    params: List[str]
    shorty: str


@dataclass
class MethodRef:
    cls: str
    name: str
    proto: Proto


@dataclass
class FieldRef:
    cls: str
    typ: str
    name: str


@dataclass
class ClassDef:
    cls: str
    class_data_off: int
    source_file: str = ''
    access_flags: int = 0
    super_cls: str = ''
    static_values_off: int = 0


@dataclass
class EncodedMethod:
    kind: str
    method_idx: int
    access: int
    code_off: int


class Dex:
    def __init__(self, data: bytes):
        if data[:3] != b'dex':
            raise ValueError('not a dex file')
        self.data = data
        self.strings: List[str] = []
        self.types: List[str] = []
        self.protos: List[Proto] = []
        self.methods: List[MethodRef] = []
        self.fields: List[FieldRef] = []
        self.classes: Dict[str, ClassDef] = {}
        self._class_methods_cache: Dict[str, Tuple[EncodedMethod, ...]] = {}
        self._class_static_fields_cache: Dict[str, Tuple[int, ...]] = {}
        self._static_values_cache: Dict[str, Dict[int, Any]] = {}
        self._static_field_lookup_cache: Optional[Tuple[Dict[Tuple[str, str], Any], Dict[str, List[Any]]]] = None
        self._parse()

    def _parse(self) -> None:
        b = self.data
        string_ids_size, string_ids_off = u4(b, 0x38), u4(b, 0x3C)
        type_ids_size, type_ids_off = u4(b, 0x40), u4(b, 0x44)
        proto_ids_size, proto_ids_off = u4(b, 0x48), u4(b, 0x4C)
        field_ids_size, field_ids_off = u4(b, 0x50), u4(b, 0x54)
        method_ids_size, method_ids_off = u4(b, 0x58), u4(b, 0x5C)
        class_defs_size, class_defs_off = u4(b, 0x60), u4(b, 0x64)

        for i in range(string_ids_size):
            off = u4(b, string_ids_off + i * 4)
            _, pos = uleb128(b, off)
            end = b.find(b'\x00', pos)
            self.strings.append(b[pos:end].decode('utf-8', 'replace'))

        self.types = [self.strings[u4(b, type_ids_off + i * 4)] for i in range(type_ids_size)]

        for i in range(proto_ids_size):
            off = proto_ids_off + i * 12
            shorty = self.strings[u4(b, off)]
            ret = self.types[u4(b, off + 4)]
            params_off = u4(b, off + 8)
            params: List[str] = []
            if params_off:
                size = u4(b, params_off)
                params = [self.types[u2(b, params_off + 4 + 2 * j)] for j in range(size)]
            self.protos.append(Proto(ret, params, shorty))

        for i in range(field_ids_size):
            off = field_ids_off + i * 8
            self.fields.append(FieldRef(
                self.types[u2(b, off)],
                self.types[u2(b, off + 2)],
                self.strings[u4(b, off + 4)],
            ))

        for i in range(method_ids_size):
            off = method_ids_off + i * 8
            self.methods.append(MethodRef(
                self.types[u2(b, off)],
                self.strings[u4(b, off + 4)],
                self.protos[u2(b, off + 2)],
            ))

        for i in range(class_defs_size):
            off = class_defs_off + i * 32
            cls = self.types[u4(b, off)]
            access_flags = u4(b, off + 4)
            super_idx = u4(b, off + 8)
            super_cls = '' if super_idx == NO_INDEX else self.types[super_idx]
            source_idx = u4(b, off + 16)
            source = '' if source_idx == NO_INDEX else self.strings[source_idx]
            self.classes[cls] = ClassDef(cls, u4(b, off + 24), source, access_flags, super_cls, u4(b, off + 28))

    def class_methods(self, cls: str) -> List[EncodedMethod]:
        cached = self._class_methods_cache.get(cls)
        if cached is not None:
            return list(cached)
        c = self.classes[cls]
        off = c.class_data_off
        if not off:
            return []
        out: List[EncodedMethod] = []
        static_fields_size, off = uleb128(self.data, off)
        instance_fields_size, off = uleb128(self.data, off)
        direct_methods_size, off = uleb128(self.data, off)
        virtual_methods_size, off = uleb128(self.data, off)
        # skip fields
        for n in (static_fields_size, instance_fields_size):
            idx = 0
            for _ in range(n):
                diff, off = uleb128(self.data, off)
                _, off = uleb128(self.data, off)
                idx += diff
        # methods
        for kind, n in (('direct', direct_methods_size), ('virtual', virtual_methods_size)):
            idx = 0
            for _ in range(n):
                diff, off = uleb128(self.data, off)
                acc, off = uleb128(self.data, off)
                code_off, off = uleb128(self.data, off)
                idx += diff
                out.append(EncodedMethod(kind, idx, acc, code_off))
        self._class_methods_cache[cls] = tuple(out)
        return list(out)

    def class_static_field_indices(self, cls: str) -> List[int]:
        cached = self._class_static_fields_cache.get(cls)
        if cached is not None:
            return list(cached)
        c = self.classes.get(cls)
        if not c or not c.class_data_off:
            return []
        off = c.class_data_off
        static_fields_size, off = uleb128(self.data, off)
        instance_fields_size, off = uleb128(self.data, off)
        direct_methods_size, off = uleb128(self.data, off)
        virtual_methods_size, off = uleb128(self.data, off)
        out: List[int] = []
        idx = 0
        for _ in range(static_fields_size):
            diff, off = uleb128(self.data, off)
            _, off = uleb128(self.data, off)
            idx += diff
            out.append(idx)
        self._class_static_fields_cache[cls] = tuple(out)
        return list(out)

    def _read_encoded_value(self, off: int) -> Tuple[Any, int, int]:
        tag = self.data[off]
        off += 1
        value_type = tag & 0x1F
        value_arg = tag >> 5
        if value_type in (0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11, 0x17, 0x18, 0x19, 0x1A, 0x1B):
            n = value_arg + 1
            raw = self.data[off:off + n]
            off += n
            signed = value_type in (0x00, 0x02, 0x03, 0x04, 0x06, 0x10, 0x11)
            val = int.from_bytes(raw, 'little', signed=False)
            if signed and raw and (raw[-1] & 0x80):
                val -= 1 << (8 * n)
            return val, off, value_type
        if value_type == 0x1C:
            size, off = uleb128(self.data, off)
            arr = []
            for _ in range(size):
                v, off, _ = self._read_encoded_value(off)
                arr.append(v)
            return arr, off, value_type
        if value_type == 0x1E:
            return None, off, value_type
        if value_type == 0x1F:
            return bool(value_arg), off, value_type
        return None, off, value_type

    def static_values(self, cls: str) -> Dict[int, Any]:
        cached = self._static_values_cache.get(cls)
        if cached is not None:
            return cached
        c = self.classes.get(cls)
        if not c or not c.static_values_off:
            self._static_values_cache[cls] = {}
            return self._static_values_cache[cls]
        fields = self.class_static_field_indices(cls)
        size, off = uleb128(self.data, c.static_values_off)
        out: Dict[int, Any] = {}
        for i in range(size):
            v, off, _ = self._read_encoded_value(off)
            if i < len(fields):
                out[fields[i]] = v
        self._static_values_cache[cls] = out
        return out

    def code_units(self, code_off: int) -> Tuple[int, int, List[int]]:
        regs = u2(self.data, code_off)
        ins = u2(self.data, code_off + 2)
        size = u4(self.data, code_off + 12)
        pos = code_off + 16
        return regs, ins, [u2(self.data, pos + 2 * i) for i in range(size)]


def get_apk_bytes(path: str) -> bytes:
    original_path = path
    path = normalize_input_path(path)
    if not os.path.exists(path):
        raise UserFacingError(format_path_hint(original_path))
    if os.path.isdir(path):
        raise UserFacingError(f'[错误] 输入路径是目录，不是 APK/ZIP/DEX 文件：{path}')
    try:
        with open(path, 'rb') as f:
            data = f.read()
    except PermissionError:
        raise UserFacingError(f'[错误] 没有权限读取文件：{path}')
    except OSError as e:
        raise UserFacingError(f'[错误] 读取文件失败：{path}\n[原因] {e}')

    # Direct APK/ZIP with classes.dex, or iApp project ZIP containing bin/*.apk.
    if zipfile.is_zipfile(path):
        try:
            with zipfile.ZipFile(path) as z:
                names = z.namelist()
                if any(re.fullmatch(r'classes(?:\d*)\.dex', n) for n in names):
                    return data
                apks = [n for n in names if n.lower().endswith('.apk')]
                if apks:
                    # Prefer bin/*.apk when this is an iApp project zip.
                    apks.sort(key=lambda n: (not n.startswith('bin/'), len(n)))
                    return z.read(apks[0])
                raise UserFacingError(
                    f'[错误] ZIP 内没有找到 classes*.dex，也没有找到 bin/*.apk：{path}\n'
                    '[建议] 请确认输入的是 APK，或 iApp 工程 ZIP。'
                )
        except zipfile.BadZipFile:
            raise UserFacingError(f'[错误] ZIP/APK 文件损坏或格式不正确：{path}')
    return data


def get_classes_dex(path: str) -> bytes:
    return get_classes_dex_from_apk_bytes(get_apk_bytes(path))


def get_classes_dex_from_apk_bytes(apk_bytes: bytes) -> bytes:
    import io
    with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
        for name in ('classes.dex', 'classes2.dex'):
            if name in z.namelist():
                return z.read(name)
    raise FileNotFoundError('classes.dex not found')


def get_all_classes_dexes_from_apk_bytes(apk_bytes: bytes) -> List[Tuple[str, bytes]]:
    """Return all classes*.dex entries from an APK, ordered as Android loads them."""
    if apk_bytes.startswith(b'dex\n'):
        return [('classes.dex', apk_bytes)]
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            names = [n for n in z.namelist() if re.fullmatch(r'classes(?:\d*)\.dex', n)]
            def dex_order(n: str) -> int:
                m = re.fullmatch(r'classes(\d*)\.dex', n)
                if not m:
                    return 999999
                return 1 if m.group(1) == '' else int(m.group(1))
            names.sort(key=dex_order)
            return [(n, z.read(n)) for n in names]
    except zipfile.BadZipFile:
        raise UserFacingError('[错误] 输入文件不是有效 APK/ZIP，无法读取 classes*.dex。')


class AxmlStringPool:
    def __init__(self, buf: bytes, off: int):
        typ = u2(buf, off)
        if typ != 0x0001:
            raise ValueError('not a string pool chunk')
        self.header_size = u2(buf, off + 2)
        self.size = u4(buf, off + 4)
        self.string_count = u4(buf, off + 8)
        self.style_count = u4(buf, off + 12)
        self.flags = u4(buf, off + 16)
        self.strings_start = u4(buf, off + 20)
        self.styles_start = u4(buf, off + 24)
        self.utf8 = bool(self.flags & 0x00000100)
        self.base = off
        self.buf = buf
        self.offsets = [u4(buf, off + self.header_size + i * 4) for i in range(self.string_count)]

    def _read_utf8_len(self, pos: int) -> Tuple[int, int]:
        # Android UTF-8 string length is one or two bytes. Top bit means continuation.
        b0 = self.buf[pos]
        pos += 1
        if b0 & 0x80:
            b1 = self.buf[pos]
            pos += 1
            return ((b0 & 0x7F) << 8) | b1, pos
        return b0, pos

    def _read_utf16_len(self, pos: int) -> Tuple[int, int]:
        w0 = u2(self.buf, pos)
        pos += 2
        if w0 & 0x8000:
            w1 = u2(self.buf, pos)
            pos += 2
            return ((w0 & 0x7FFF) << 16) | w1, pos
        return w0, pos

    def get(self, idx: int) -> Optional[str]:
        if idx == NO_INDEX or idx < 0 or idx >= self.string_count:
            return None
        pos = self.base + self.strings_start + self.offsets[idx]
        if self.utf8:
            # First length is UTF-16 units, second is byte count.
            _, pos = self._read_utf8_len(pos)
            byte_len, pos = self._read_utf8_len(pos)
            return self.buf[pos:pos + byte_len].decode('utf-8', 'replace')
        char_len, pos = self._read_utf16_len(pos)
        raw = self.buf[pos:pos + char_len * 2]
        return raw.decode('utf-16le', 'replace')


def axml_manifest_package(manifest: bytes) -> Optional[str]:
    """Read package="..." from binary AndroidManifest.xml using stdlib only."""
    if len(manifest) < 8:
        return None
    # Plain XML fallback, useful for already-decoded manifests.
    if manifest.lstrip().startswith(b'<'):
        m = re.search(rb'<manifest\b[^>]*\bpackage=["\']([^"\']+)', manifest[:4096])
        return m.group(1).decode('utf-8', 'replace') if m else None

    try:
        if u2(manifest, 0) != 0x0003:
            return None
        end = u4(manifest, 4)
        off = u2(manifest, 2)
        sp: Optional[AxmlStringPool] = None
        while off + 8 <= len(manifest) and off < end:
            typ = u2(manifest, off)
            hsize = u2(manifest, off + 2)
            size = u4(manifest, off + 4)
            if size <= 0:
                break
            if typ == 0x0001:
                sp = AxmlStringPool(manifest, off)
            elif typ == 0x0102 and sp is not None:  # RES_XML_START_ELEMENT_TYPE
                name_idx = u4(manifest, off + 20)
                tag_name = sp.get(name_idx)
                attr_start = u2(manifest, off + 24)
                attr_size = u2(manifest, off + 26)
                attr_count = u2(manifest, off + 28)
                if tag_name == 'manifest':
                    base = off + 16 + attr_start
                    for i in range(attr_count):
                        ao = base + i * attr_size
                        if ao + 20 > off + size:
                            break
                        attr_name = sp.get(u4(manifest, ao + 4))
                        raw_value_idx = u4(manifest, ao + 8)
                        data_type = manifest[ao + 15]
                        data = u4(manifest, ao + 16)
                        value: Optional[str] = None
                        if raw_value_idx != NO_INDEX:
                            value = sp.get(raw_value_idx)
                        elif data_type == 0x03:  # TYPE_STRING
                            value = sp.get(data)
                        if attr_name == 'package' and value:
                            return value
            off += size
    except Exception:
        return None
    return None


def loose_package_scan(blob: bytes) -> Optional[str]:
    """Best-effort fallback for unusual manifests: scan ASCII/UTF-16 package-looking strings."""
    candidates: List[str] = []
    ascii_blob = blob[:2_000_000]
    for m in re.finditer(rb'(?:[a-zA-Z_][\w]*\.){2,}[A-Za-z_][\w]*', ascii_blob):
        s = m.group(0).decode('ascii', 'ignore')
        if s.startswith(('com.', 'org.', 'net.', 'cn.')) and not any(x in s for x in ('android.', 'google.')):
            candidates.append(s)
    # UTF-16LE scan: convert NUL-separated ASCII-ish bytes to text.
    try:
        text16 = ascii_blob.decode('utf-16le', 'ignore')
        for m in re.finditer(r'(?:[a-zA-Z_]\w*\.){2,}[A-Za-z_]\w*', text16):
            s = m.group(0)
            if s.startswith(('com.', 'org.', 'net.', 'cn.')) and not any(x in s for x in ('android.', 'google.')):
                candidates.append(s)
    except Exception:
        pass
    if not candidates:
        return None
    # Prefer short app-like package names over library packages.
    candidates = sorted(set(candidates), key=lambda x: (len(x), x))
    return candidates[0]


def get_package_name_from_apk_bytes(apk_bytes: bytes) -> Optional[str]:
    import io
    try:
        with zipfile.ZipFile(io.BytesIO(apk_bytes)) as z:
            if 'AndroidManifest.xml' in z.namelist():
                manifest = z.read('AndroidManifest.xml')
                pkg = axml_manifest_package(manifest)
                if pkg:
                    return pkg
                pkg = loose_package_scan(manifest)
                if pkg:
                    return pkg
    except Exception:
        return None
    return None


def auto_package_from_dex(dex: 'Dex') -> Optional[str]:
    """Fallback: infer package from the iApp UI class owner."""
    classes = candidate_user_classes(dex, None)
    if not classes:
        return None
    # Lcom/demo/app/mian; -> com.demo.app
    paths = [c.strip('L;').replace('/', '.') for c in classes]
    pkgs = ['.'.join(p.split('.')[:-1]) for p in paths if '.' in p]
    if not pkgs:
        return None
    return sorted(set(pkgs), key=lambda p: (len(p), p))[0]


def short_widget_name(desc: str) -> str:
    # Li6/runlibrary/app/v/xxbj; -> xxbj
    return desc.rstrip(';').split('/')[-1].split('$')[0]


@dataclass
class Widget:
    tag: str
    field_name: Optional[str] = None
    attrs: OrderedDict = field(default_factory=OrderedDict)
    children: List['Widget'] = field(default_factory=list)
    parent: Optional['Widget'] = None
    control_events: OrderedDict = field(default_factory=OrderedDict)

    def set_attr(self, k: str, v: Any) -> None:
        if k == 'id':
            # Numeric runtime IDs are generated as p1 + 10000...; field name is the source id.
            if self.field_name:
                self.attrs.setdefault('id', self.field_name)
            elif v is not None:
                self.attrs.setdefault('id', str(v))
            return
        self.attrs[k] = stringify_value(v)


def stringify_value(v: Any) -> str:
    if isinstance(v, IntegerBox):
        return str(v.value)
    if isinstance(v, int):
        return str(v)
    if v is None:
        return ''
    return str(v)


@dataclass
class NewObj:
    typ: str


@dataclass
class IntegerBox:
    value: int


def safe_int_value(v: Any) -> Optional[int]:
    if isinstance(v, IntegerBox):
        return v.value
    if isinstance(v, int):
        return v
    if v is None:
        return None
    try:
        return int(str(v))
    except Exception:
        return None


@dataclass
class PendingCall:
    method: MethodRef
    args: List[int]


PROPERTY_NAMES = {
    'width', 'height', 'orientation', 'backgroundColor', 'gravity',
    'text', 'textSize', 'textColor', 'layout_marginLeft', 'layout_marginTop',
    'layout_marginRight', 'layout_marginBottom', 'padding', 'paddingLeft',
    'paddingRight', 'paddingTop', 'paddingBottom', 'visibility', 'enabled',
    'alpha', 'background', 'src', 'hint', 'singleLine', 'inputType', 'textStyle',
    'ellipsize', 'maxLines', 'minLines', 'layout_gravity', 'weight',
}


def regs_35c(aa: int, w2: int) -> List[int]:
    count = aa >> 4
    g = aa & 0xF
    c = w2 & 0xF
    d = (w2 >> 4) & 0xF
    e = (w2 >> 8) & 0xF
    f = (w2 >> 12) & 0xF
    return [c, d, e, f, g][:count]


def insn_len(op: int) -> int:
    if op in (0x00, 0x01, 0x04, 0x07, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x27, 0x28):
        return 1
    if op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x29):
        return 2
    if op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C):
        return 3
    if op == 0x18:
        return 5
    if 0x2D <= op <= 0x31:
        return 2
    if 0x32 <= op <= 0x3D:
        return 2
    if 0x44 <= op <= 0x6D:
        return 2
    if 0x6E <= op <= 0x78:
        return 3
    if 0x7B <= op <= 0x8F:
        return 1
    if 0x90 <= op <= 0xAF:
        return 2
    if 0xB0 <= op <= 0xCF:
        return 1
    if 0xD0 <= op <= 0xE2:
        return 2
    return 1


def branch_target(i: int, off: int) -> int:
    return i + off


def reachable_instruction_offsets(cu: List[int]) -> List[int]:
    """Return real instruction offsets, skipping switch/array data payloads.

    The V6 protector often leaves packed-switch/fill-array payloads and opaque
    branches inside event methods. A linear sweep reads those payload bytes as
    opcodes, which creates bogus statements such as string[index] assignments.
    This lightweight CFG walk follows normal DEX control flow from offset 0 and
    only emits reachable instructions.
    """
    n = len(cu)
    work = [0]
    seen: set[int] = set()
    while work:
        i = work.pop()
        if i < 0 or i >= n or i in seen:
            continue
        seen.add(i)
        w = cu[i]
        op = w & 0xFF
        aa = w >> 8
        step = insn_len(op)
        next_i = i + step

        def add(x: int) -> None:
            if 0 <= x < n and x not in seen:
                work.append(x)

        if op == 0x28:  # goto
            add(branch_target(i, s8(aa)))
            continue
        if op == 0x29 and i + 1 < n:
            add(branch_target(i, i2(cu[i + 1])))
            continue
        if op == 0x2A and i + 2 < n:
            add(branch_target(i, i4(cu[i + 1] | (cu[i + 2] << 16))))
            continue
        if op in (0x0E, 0x0F, 0x10, 0x11, 0x27):  # return/throw
            continue
        if 0x32 <= op <= 0x3D and i + 1 < n:
            add(branch_target(i, i2(cu[i + 1])))
            add(next_i)
            continue
        if op in (0x2B, 0x2C) and i + 2 < n:  # packed/sparse-switch
            add(next_i)
            payload = branch_target(i, i4(cu[i + 1] | (cu[i + 2] << 16)))
            if 0 <= payload + 1 < n:
                ident = cu[payload]
                size = cu[payload + 1]
                if op == 0x2B and ident == 0x0100:
                    targets = payload + 4
                    for k in range(size):
                        p = targets + 2 * k
                        if p + 1 < n:
                            add(branch_target(i, i4(cu[p] | (cu[p + 1] << 16))))
                elif op == 0x2C and ident == 0x0200:
                    targets = payload + 2 + size * 2
                    for k in range(size):
                        p = targets + 2 * k
                        if p + 1 < n:
                            add(branch_target(i, i4(cu[p] | (cu[p + 1] << 16))))
            continue
        add(next_i)
    return sorted(seen)


def recover_method(dex: Dex, encoded: EncodedMethod, owner_cls: str, verbose: bool = False) -> Optional[Widget]:
    regs_count, ins_count, cu = dex.code_units(encoded.code_off)
    regs: Dict[int, Any] = {}
    fields_to_widgets: Dict[str, Widget] = {}
    all_widgets: List[Widget] = []
    root: Optional[Widget] = None
    pending_result: Any = None

    # p0 is usually this. Keep a marker for readability; not necessary for extraction.
    p0 = regs_count - ins_count
    regs[p0] = 'this'

    i = 0
    while i < len(cu):
        w = cu[i]
        op = w & 0xFF
        aa = w >> 8
        step = insn_len(op)

        def reg_value(r: int) -> Any:
            return regs.get(r)

        if op == 0x12:  # const/4
            regs[aa & 0xF] = s4bit(aa >> 4)
        elif op == 0x13:  # const/16
            regs[aa] = i2(cu[i + 1])
        elif op == 0x14:  # const
            regs[aa] = i4(cu[i + 1] | (cu[i + 2] << 16))
        elif op == 0x1A:  # const-string
            regs[aa] = dex.strings[cu[i + 1]]
        elif op == 0x1B:  # const-string/jumbo
            idx = cu[i + 1] | (cu[i + 2] << 16)
            regs[aa] = dex.strings[idx]
        elif op == 0x22:  # new-instance
            typ = dex.types[cu[i + 1]]
            regs[aa] = NewObj(typ)
        elif op in (0x07,):  # move-object vA, vB
            a = aa & 0xF
            b = aa >> 4
            regs[a] = regs.get(b)
        elif op in (0x08,):  # move-object/from16
            regs[aa] = regs.get(cu[i + 1])
        elif op == 0x0C:  # move-result-object
            regs[aa] = pending_result
            pending_result = None
        elif op == 0x0A:  # move-result
            regs[aa] = pending_result
            pending_result = None
        elif 0x52 <= op <= 0x5F:  # instance get/put field
            a = aa & 0xF
            b = aa >> 4
            fr = dex.fields[cu[i + 1]]
            if op in (0x54, 0x55, 0x56, 0x57, 0x58):  # iget*
                # Keep enough symbolic state to bind generated Android listeners
                # back to the iApp widget that owns the native .st view.
                if fr.cls == owner_cls and fr.typ.startswith('Li6/runlibrary/app/v/'):
                    regs[a] = fields_to_widgets.get(fr.name, ('field', fr.name))
                elif fr.cls == owner_cls and fr.name.startswith('$_on_'):
                    # Generated listener/client fields are named like
                    # $_on_setOnClickListener_wb1, $_on_addTextChangedListener_bjk1,
                    # $_on_setWebViewClient_llq1, etc.  Their concrete Android
                    # type varies, so key off the generated name rather than only
                    # View$OnClickListener.
                    regs[a] = ('listener_field', fr.name)
                elif fr.name == 'st':
                    owner_obj = regs.get(b)
                    if isinstance(owner_obj, Widget):
                        regs[a] = ('widget_st', owner_obj)
                    else:
                        regs[a] = ('field', fr.name)
                else:
                    regs[a] = ('field', fr.name)
            elif op in (0x5B, 0x5C, 0x5D, 0x5E, 0x5F):  # iput*
                val = regs.get(a)
                if fr.cls == owner_cls and fr.typ.startswith('Li6/runlibrary/app/v/'):
                    if isinstance(val, Widget):
                        wid = val
                    elif isinstance(val, NewObj):
                        wid = Widget(short_widget_name(val.typ))
                        all_widgets.append(wid)
                    else:
                        wid = fields_to_widgets.get(fr.name) or Widget(short_widget_name(fr.typ))
                        all_widgets.append(wid)
                    wid.field_name = fr.name
                    wid.attrs.setdefault('id', fr.name)
                    fields_to_widgets[fr.name] = wid
                    regs[a] = wid
                    if root is None:
                        root = wid
        elif 0x6E <= op <= 0x72:  # invoke-kind
            midx = cu[i + 1]
            m = dex.methods[midx]
            args = regs_35c(aa, cu[i + 2])
            values = [reg_value(r) for r in args]
            pending_result = None

            # Constructors transform NewObj into Widget when it is an iApp v class.
            if m.name == '<init>' and args:
                obj = reg_value(args[0])
                if isinstance(obj, NewObj) and obj.typ.startswith('Li6/runlibrary/app/v/'):
                    wid = Widget(short_widget_name(obj.typ))
                    regs[args[0]] = wid
                    all_widgets.append(wid)

            # Integer.valueOf(x) boxes int used as Object property value.
            elif m.cls == 'Ljava/lang/Integer;' and m.name == 'valueOf' and args:
                v = reg_value(args[0])
                iv = safe_int_value(v)
                pending_result = IntegerBox(iv) if iv is not None else None

            # parent.add(child)
            elif m.name == 'add' and len(args) >= 2:
                parent = reg_value(args[0])
                child = reg_value(args[1])
                if isinstance(parent, Widget) and isinstance(child, Widget):
                    if child.parent is None:
                        parent.children.append(child)
                        child.parent = parent

            # Android listener/client assignment on the generated native view object.
            # iApp uses many wrappers, not only setOn*Listener: addTextChangedListener,
            # addDrawerListener, setWebViewClient, setDownloadListener, etc.
            elif len(args) >= 2 and isinstance(reg_value(args[0]), tuple) and reg_value(args[0]) and reg_value(args[0])[0] == 'widget_st' and isinstance(reg_value(args[1]), tuple) and reg_value(args[1]) and reg_value(args[1])[0] == 'listener_field':
                target = reg_value(args[0])
                listener = reg_value(args[1])
                w = target[1]
                w.control_events.setdefault('_listener_fields', []).append((m.name, listener[1]))

            # iApp view property calls: obj.width(value), obj.text(value), etc.
            elif m.name in PROPERTY_NAMES or m.name == 'id':
                if args:
                    obj = reg_value(args[0])
                    val = reg_value(args[1]) if len(args) > 1 else None
                    if isinstance(obj, Widget):
                        obj.set_attr(m.name, val)
        elif op == 0xD0:  # add-int/lit16 vA, vB, #lit16 ; used for generated numeric view IDs
            a = aa & 0xF
            b = aa >> 4
            base = regs.get(b)
            lit = i2(cu[i + 1])
            regs[a] = (base + lit) if isinstance(base, int) else lit
        # ignore control flow; for generated iApp UI builder this is linear except null-layout guard.

        if verbose and op in (0x1A, 0x22, 0x54, 0x5B, 0x6E, 0x70, 0x71, 0xD0):
            sys.stderr.write(f'@{i:04x} op={op:02x} regs={regs}\n')
        i += step

    # Pick first widget without parent, prefer one named *_v or mian_v.
    candidates = [w for w in all_widgets if w.parent is None]
    for w in candidates:
        if w.field_name and (w.field_name.endswith('_v') or w.field_name == 'mian_v'):
            return w
    return root or (candidates[0] if candidates else None)



def _split_balanced_args(text: str) -> List[str]:
    out: List[str] = []
    start = 0
    depth = 0
    quote = ''
    esc = False
    for idx, ch in enumerate(text):
        if quote:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth = max(0, depth - 1)
        elif ch == ',' and depth == 0:
            out.append(text[start:idx].strip())
            start = idx + 1
    tail = text[start:].strip()
    if tail or text.strip():
        out.append(tail)
    return out


def _strip_boxing_expr(expr: str) -> str:
    e = expr.strip()
    for _ in range(8):
        old = e
        e = re.sub(r'^(?:java\.lang\.)?(?:Integer|Long|Short|Byte)\.valueOf\((.*)\)$', r'\1', e, flags=re.S)
        e = re.sub(r'^0\.valueOf\((.*)\)$', r'\1', e, flags=re.S)
        e = re.sub(r'^(?:java\.lang\.)?Boolean\.valueOf\((.*)\)$', r'\1', e, flags=re.S)
        m = re.match(r'^\(\((?:String|Integer|Boolean|Object|Float|Double|Long|Short|Byte|[\w.$\[\]]+)\)\s*(.*)\)$', e, re.S)
        if m:
            e = m.group(1).strip()
        if e == old:
            break
    return e


def _normalize_ui_value(expr: str) -> Any:
    e = _strip_boxing_expr(expr.strip())
    # Decode Float.valueOf(intBits) emitted by the conservative pseudo parser.
    m = re.fullmatch(r'(?:java\.lang\.)?Float\.valueOf\((-?\d+)\)', e)
    if m:
        try:
            bits = int(m.group(1)) & 0xFFFFFFFF
            value = struct.unpack('<f', struct.pack('<I', bits))[0]
            return ('%.6g' % value)
        except Exception:
            pass
    if e in ('true', 'false'):
        return e
    if re.fullmatch(r'-?\d+', e):
        try:
            return int(e)
        except Exception:
            return e
    if len(e) >= 2 and e[0] == e[-1] == '"':
        try:
            import json
            return json.loads(e)
        except Exception:
            return e[1:-1]
    # Runtime view ids are generated as sourceId + i.  The field name is more
    # stable and is applied by Widget.set_attr('id', ...), so callers may ignore
    # this numeric expression.
    return e


def recover_protected_ui(dex: Dex, encoded: EncodedMethod, owner_cls: str, resolver: Any, verbose: bool = False) -> Optional[Widget]:
    """Recover a protected V6 UI builder through the reflection resolver.

    The original direct UI interpreter only sees ordinary calls such as
    ``view.width(...)``.  LianYi/NB builds the same tree through reflected
    dispatch wrappers that return ``Object``/``Boolean``.  This pass first turns
    those wrappers back into concrete widget calls, then reconstructs the tree.
    """
    global _PROTECTOR_RESOLVER_CONTEXT
    old = _PROTECTOR_RESOLVER_CONTEXT
    _PROTECTOR_RESOLVER_CONTEXT = resolver
    try:
        lines = pseudo_event_method(dex, encoded, owner_cls)
    finally:
        _PROTECTOR_RESOLVER_CONTEXT = old

    field_tags: Dict[str, str] = {}
    for fr in dex.fields:
        if fr.cls == owner_cls and fr.typ.startswith('Li6/runlibrary/app/v/'):
            field_tags[fr.name] = short_widget_name(fr.typ)

    widgets: Dict[str, Widget] = OrderedDict()
    creation: List[Widget] = []
    root: Optional[Widget] = None

    def ensure_widget(field_name: str, tag_hint: Optional[str] = None) -> Widget:
        nonlocal root
        key = field_name.replace('this.', '')
        if key in widgets:
            return widgets[key]
        tag = field_tags.get(key) or tag_hint or key.split('_', 1)[0] or 'xxbj'
        w = Widget(tag, field_name=key)
        w.attrs['id'] = key
        widgets[key] = w
        creation.append(w)
        if root is None:
            root = w
        return w

    def find_new_child(tag: str, parent: Widget) -> Optional[Widget]:
        # The generated builder always assigns the child field immediately before
        # parent.add(new Child(...)).  Restrict candidates to widgets created
        # after the parent; otherwise a same-tag ancestor (usually the root
        # LinearLayout) can be selected and create a recursive UI cycle.
        try:
            parent_pos = creation.index(parent)
        except ValueError:
            parent_pos = -1
        ancestors = set()
        cur: Optional[Widget] = parent
        while cur is not None:
            ancestors.add(id(cur))
            cur = cur.parent
        for pos in range(len(creation) - 1, parent_pos, -1):
            w = creation[pos]
            if id(w) in ancestors:
                continue
            if w.parent is None and w.tag == tag:
                return w
        return None

    call_re = re.compile(
        r'^\(\((?P<tag>[\w$]+)\)\s*(?P<obj>(?:this\.)?[\w$]+)\)\.(?P<method>[\w$]+)\((?P<args>.*)\)$',
        re.S,
    )
    # A few wrappers render without the explicit cast.
    call_re2 = re.compile(r'^(?P<obj>(?:this\.)?[\w$]+)\.(?P<method>[\w$]+)\((?P<args>.*)\)$', re.S)

    for raw in lines:
        line = raw.strip()
        m_assign = re.match(r'^this\.([\w$]+)\s*=\s*(?:v\d+_obj_\d+|new\s+([\w$]+)\s*\(.*\));$', line, re.S)
        if m_assign:
            ensure_widget(m_assign.group(1), m_assign.group(2))
            continue
        if not line.startswith('// IAPT_SIDE_EFFECT '):
            continue
        expr = line[len('// IAPT_SIDE_EFFECT '):].strip().rstrip(';').strip()
        # Strip Boolean/int boxing around a concrete call.
        for _ in range(4):
            mbox = re.match(r'^\(\((?:Boolean|Integer|Object)\)\s*(.*)\)\.(?:booleanValue|intValue)\(\)$', expr, re.S)
            if not mbox:
                break
            expr = mbox.group(1).strip()
        m = call_re.match(expr) or call_re2.match(expr)
        if not m:
            continue
        obj_name = m.group('obj').replace('this.', '')
        method = m.group('method')
        args_text = m.group('args')
        tag_hint = m.groupdict().get('tag')
        if obj_name not in widgets:
            # Native root setup such as ``new xxbj().st.setLayoutParams`` is not
            # a source widget property and can be ignored.
            if obj_name.startswith('new ') or obj_name in ('st', 'null'):
                continue
            if obj_name in field_tags:
                ensure_widget(obj_name, tag_hint)
            else:
                continue
        obj = widgets[obj_name]
        args = _split_balanced_args(args_text)
        if method == 'add' and args:
            a0 = _strip_boxing_expr(args[0])
            mn = re.match(r'^new\s+([\w$]+)\s*\(.*\)$', a0, re.S)
            child: Optional[Widget] = None
            if mn:
                child = find_new_child(mn.group(1), obj)
            else:
                key = a0.replace('this.', '')
                child = widgets.get(key)
            if child is not None and child.parent is None:
                obj.children.append(child)
                child.parent = obj
            continue
        if method.startswith(('setOn', 'addOn')) or method in ('addTextChangedListener', 'setWebViewClient', 'setWebChromeClient', 'setDownloadListener'):
            continue
        if not args:
            continue
        if method == 'id':
            obj.set_attr('id', obj.field_name or _normalize_ui_value(args[0]))
            continue
        values = [_normalize_ui_value(a) for a in args]
        value: Any = values[0] if len(values) == 1 else ','.join(str(x) for x in values)
        obj.set_attr(method, value)

    if root is None:
        return None
    # Attach orphaned controls conservatively to the root so the recovered XML
    # remains complete and parseable.  This only happens when a protected add()
    # target could not be resolved; the recovery report records the condition.
    for w in creation:
        if w is not root and w.parent is None:
            root.children.append(w)
            w.parent = root
    if verbose:
        print(f'[V6 UI] {descriptor_to_name(owner_cls)}: widgets={len(creation)} root={root.field_name}', file=sys.stderr)
    return root


LISTENER_CALLBACKS = OrderedDict([
    ('setOnClickListener', ['onClick']),
    ('setOnTouchListener', ['onTouch']),
    ('setOnLongClickListener', ['onLongClick']),
    ('setOnKeyListener', ['onKey']),
    ('setOnFocusChangeListener', ['onFocusChange']),
    ('setOnEditorActionListener', ['onEditorAction']),
    ('addTextChangedListener', ['onTextChanged', 'beforeTextChanged', 'afterTextChanged']),
    ('setOnCheckedChangeListener', ['onCheckedChanged']),
    ('setOnRefreshListener', ['onRefresh']),
    ('setOnItemClickListener', ['onItemClick']),
    ('setOnItemLongClickListener', ['onItemLongClick']),
    ('setOnItemSelectedListener', ['onItemSelected', 'onNothingSelected']),
    ('addOnItemTouchListener', ['onInterceptTouchEvent', 'onTouchEvent', 'onRequestDisallowInterceptTouchEvent']),
    ('addOnScrollListener', ['onScrollStateChanged', 'onScrolled']),
    ('setDownloadListener', ['onDownloadStart']),
    ('setWebChromeClient', ['onProgressChanged', 'onShowCustomView', 'onHideCustomView']),
    ('setWebViewClient', ['shouldOverrideUrlLoading', 'onPageStarted', 'onPageFinished', 'onReceivedError', 'onReceivedSslError']),
    ('addDrawerListener', ['onDrawerStateChanged', 'onDrawerSlide', 'onDrawerOpened', 'onDrawerClosed']),
    ('setOnPageChangeListener', ['onPageSelected', 'onPageScrolled', 'onPageScrollStateChanged']),
    ('addOnOffsetChangedListener', ['onOffsetChanged']),
    ('addOnTabSelectedListener', ['onTabSelected', 'onTabUnselected', 'onTabReselected']),
])


def widget_id_from_listener_field(name: str) -> Optional[str]:
    m = re.match(r'^\$_on_([^_]+)_(.+)$', name)
    return m.group(2) if m else None


def listener_name_from_field(name: str) -> Optional[str]:
    m = re.match(r'^\$_on_([^_]+)_(.+)$', name)
    return m.group(1) if m else None


def callback_from_event_method(name: str) -> Optional[Tuple[str, str]]:
    """Return (callbackName, widgetId) for generated methods.

    Examples:
      $_onClick_wb1 -> (onClick, wb1)
      $_beforeTextChanged_bjk1 -> (beforeTextChanged, bjk1)
      $_shouldOverrideUrlLoading_llq1 -> (shouldOverrideUrlLoading, llq1)
    """
    m = re.match(r'^\$_(.+?)_(.+)$', name)
    if not m:
        return None
    raw, wid = m.group(1), m.group(2)
    if raw.startswith('on'):
        cb = raw
    else:
        cb = raw
    return cb, wid


def choose_listener_for_callback(widget_listeners: List[str], callback: str) -> str:
    for ln in widget_listeners:
        if callback in LISTENER_CALLBACKS.get(ln, []):
            return ln
    for ln, callbacks in LISTENER_CALLBACKS.items():
        if callback in callbacks:
            return ln
    # Generic fallback for new iApp wrappers.
    if callback.startswith('on'):
        return 'setOn' + callback[2:] + 'Listener'
    return 'setOn' + callback[:1].upper() + callback[1:] + 'Listener'


def render_control_events(control_events: OrderedDict, advanced_analysis: bool = False) -> str:
    real_items = [(k, v) for k, v in control_events.items() if k != '_listener_fields']
    if not real_items:
        return ''
    out: List[str] = ['<Yu5Src>']
    for listener_name, callbacks in real_items:
        out.append(f'<{listener_name}>')
        preferred = LISTENER_CALLBACKS.get(listener_name, [])
        def cb_sort(item):
            cb = item[0]
            return preferred.index(cb) if cb in preferred else len(preferred)
        callbacks = sorted(callbacks, key=cb_sort)
        for callback_name, lines in callbacks:
            body = event_body_to_iapp(lines, advanced_analysis=advanced_analysis)
            if body:
                out.append(f'<{callback_name}>')
                out.append(_v6_cdata(body))
                out.append(f'</{callback_name}>')
            else:
                out.append(f'<{callback_name}/>')
        out.append(f'</{listener_name}>')
    out.append('</Yu5Src>')
    return '\n'.join(out)


def tree_has_control_events(w: Optional[Widget]) -> bool:
    if w is None:
        return False
    if any(k != '_listener_fields' for k in w.control_events.keys()):
        return True
    return any(tree_has_control_events(c) for c in w.children)


def attach_control_events(root: Optional[Widget], control_events_by_widget: Dict[str, List[Tuple[str, str, List[str]]]]) -> None:
    if root is None:
        return
    def add_event(w: Widget, listener_name: str, callback_name: str, lines: List[str]) -> None:
        current = w.control_events.setdefault(listener_name, [])
        if (callback_name, lines) not in current:
            current.append((callback_name, lines))

    def has_real_events(w: Widget) -> bool:
        return any(k != '_listener_fields' for k in w.control_events.keys())

    def walk(w: Widget) -> None:
        # Prefer listener order from the UI builder method. This preserves the
        # source order for controls with many events on the same widget.
        pending = list(w.control_events.get('_listener_fields', []))
        for listener_name, listener_field in pending:
            wid = widget_id_from_listener_field(listener_field)
            if wid and wid in control_events_by_widget:
                for ln, cb, lines in control_events_by_widget[wid]:
                    if ln == listener_name:
                        add_event(w, ln, cb, lines)
        # Fallback for unusual samples where the assignment was not recognized.
        if not has_real_events(w) and w.field_name and w.field_name in control_events_by_widget:
            for listener_name, callback_name, lines in control_events_by_widget[w.field_name]:
                add_event(w, listener_name, callback_name, lines)
        for c in w.children:
            walk(c)
    walk(root)


_V6_EVENT_RECOVERY_REPORTS: List[Dict[str, Any]] = []


def recover_v6_concrete_event_lines(dex: Dex, encoded: EncodedMethod, owner_cls: str) -> List[str]:
    """Prefer concrete protected-event execution over flattened pseudo code."""
    resolver = globals().get('_PROTECTOR_RESOLVER_CONTEXT')
    if resolver is None:
        return []
    try:
        try:
            from .iapp_v6_event_vm import recover_event_method
        except Exception:
            from iapp_v6_event_vm import recover_event_method
        lines, report = recover_event_method(dex, dex.data, resolver, encoded, owner_cls)
        mr = dex.methods[encoded.method_idx]
        report = dict(report or {})
        report.update({'class': owner_cls, 'method': mr.name})
        _V6_EVENT_RECOVERY_REPORTS.append(report)
        return lines or []
    except Exception as exc:
        _V6_EVENT_RECOVERY_REPORTS.append({
            'class': owner_cls,
            'method': dex.methods[encoded.method_idx].name,
            'ok': False,
            'errors': [f'{type(exc).__name__}: {exc}'],
        })
        return []


def recover_control_events_for_class(dex: Dex, cls: str) -> Dict[str, List[Tuple[str, str, List[str]]]]:
    out: Dict[str, List[Tuple[str, str, List[str]]]] = OrderedDict()
    listeners_by_widget: Dict[str, List[str]] = OrderedDict()

    for fr in dex.fields:
        if fr.cls != cls:
            continue
        ln = listener_name_from_field(fr.name)
        wid = widget_id_from_listener_field(fr.name)
        if ln and wid:
            listeners_by_widget.setdefault(wid, [])
            if ln not in listeners_by_widget[wid]:
                listeners_by_widget[wid].append(ln)

    for em in dex.class_methods(cls):
        m = dex.methods[em.method_idx]
        if not em.code_off:
            continue
        parsed = callback_from_event_method(m.name)
        if not parsed:
            continue
        callback_name, wid = parsed
        if not wid or wid.startswith('$'):
            continue
        listener_name = choose_listener_for_callback(listeners_by_widget.get(wid, []), callback_name)
        lines = recover_v6_concrete_event_lines(dex, em, cls)
        if not lines:
            lines = pseudo_event_method(dex, em, cls)
        # Empty callbacks are usually optimized out and absent from dex.  When an
        # actually present callback decompiles to pure boilerplate, skip it so we
        # don't invent source for onTabUnselected/onTabReselected, etc.
        if is_boilerplate_event(lines):
            continue
        out.setdefault(wid, []).append((listener_name, callback_name, lines))
    return out

def widget_to_xml(w: Widget, level: int = 0, extra_inside: str = '', advanced_analysis: bool = False) -> str:
    indent = ''  # keep original compact style
    attrs = ''
    # Ensure id first if present.
    items = list(w.attrs.items())
    if 'id' in w.attrs:
        items = [('id', w.attrs['id'])] + [(k, v) for k, v in items if k != 'id']
    for k, v in items:
        attrs += f' {k}="{html.escape(str(v), quote=True)}"'
    inner_parts: List[str] = []
    inner_parts.extend(widget_to_xml(c, level + 1, advanced_analysis=advanced_analysis) for c in w.children)
    ce = render_control_events(w.control_events, advanced_analysis=advanced_analysis)
    if ce:
        inner_parts.append(ce)
    if extra_inside:
        inner_parts.append(extra_inside.rstrip('\n'))
    if not inner_parts:
        # iApp generated source normally uses compact self-closing tags.
        return f'{indent}<{w.tag}{attrs}/>'
    inner = '\n'.join(inner_parts)
    return f'{indent}<{w.tag}{attrs}>\n{inner}\n{indent}</{w.tag}>'


def xml_decl_needed(events: OrderedDict, root: Optional[Widget] = None) -> bool:
    return bool(events) or tree_has_control_events(root)


def render_iyu_document(root: Widget, events: OrderedDict, detected_package: Optional[str] = None, advanced_analysis: bool = False) -> str:
    yu5 = events_to_yu5src(events, detected_package, advanced_analysis=advanced_analysis)
    text = widget_to_xml(root, extra_inside=yu5, advanced_analysis=advanced_analysis) + '\n'
    if xml_decl_needed(events, root):
        return '<?xml version="1.0" encoding="UTF-8"?>' + text
    return text

def candidate_user_classes(dex: Dex, package_filter: Optional[str]) -> List[str]:
    out = []
    for cls, cdef in dex.classes.items():
        if package_filter:
            pkg = package_filter.strip('.').replace('.', '/')
            if not cls.startswith('L' + pkg + '/'):
                continue
        else:
            if not cls.startswith('Lcom/'):
                continue
            # Skip well-known libraries.
            if cls.startswith('Lcom/google/'):
                continue
        if '$' in cls or cls.endswith('/R;') or '/R$' in cls:
            continue
        methods = [dex.methods[m.method_idx].name for m in dex.class_methods(cls)]
        if 'on_$_viewAutomaticSettingEvent' in methods:
            out.append(cls)
    return sorted(out)



def candidate_myu_classes(dex: Dex, package_filter: Optional[str]) -> List[str]:
    """Find iApp V6 .myu classes.  They extend i6.app.iCv6 and do not have a view builder."""
    out: List[str] = []
    for cls, cdef in dex.classes.items():
        if package_filter:
            pkg = package_filter.strip('.').replace('.', '/')
            if not cls.startswith('L' + pkg + '/'):
                continue
        else:
            if not cls.startswith('Lcom/') or cls.startswith('Lcom/google/'):
                continue
        if '$' in cls or cls.endswith('/R;') or '/R$' in cls:
            continue
        if getattr(cdef, 'super_cls', '') != 'Li6/app/iCv6;':
            continue
        methods = [dex.methods[m.method_idx].name for m in dex.class_methods(cls)]
        if 'on_$_viewAutomaticSettingEvent' in methods:
            continue
        out.append(cls)
    return sorted(out)


def is_default_myu_constructor(dex: Dex, encoded: EncodedMethod, owner_cls: str) -> bool:
    """Detect constructor generated for an empty .myu: super(appInfo); this.lei=this; this.类=this;"""
    if not encoded.code_off:
        return True
    m = dex.methods[encoded.method_idx]
    if m.name != '<init>':
        return False
    try:
        _, _, units = dex.code_units(encoded.code_off)
    except Exception:
        return False
    # Empty module constructor in current samples is exactly 8 code units.
    # Be permissive: no const-string / invoke-virtual user calls means no recoverable source body.
    for u in units:
        op = u & 0xff
        if op in (0x1a, 0x1b, 0x6e, 0x6f, 0x71, 0x72, 0x74, 0x75):
            return False
    return True


MYU_BOILERPLATE_LINE_RE = re.compile(r'^(?:lei|类)\s*=\s*this;?$')


def clean_myu_pseudo_lines(lines: List[str]) -> List[str]:
    """Remove constructor/runtime boilerplate from an iCv6 .myu class body."""
    out: List[str] = []
    for line in lines:
        x = line.strip()
        if not x or x == 'return;':
            continue
        if MYU_BOILERPLATE_LINE_RE.match(x):
            continue
        out.append(line)
    return out


def recover_myu_document(dex: Dex, cls: str) -> str:
    """Recover a .myu file from iCv6 bytecode when user code is actually present.

    iApp V6 module files compile to classes extending i6.app.iCv6.  Some top-level
    module code is emitted into the constructor; named module functions may be
    emitted as normal methods.  If the class contains only the generated default
    constructor, there is no source body left in dex to recover.
    """
    parts: List[str] = []

    for em in dex.class_methods(cls):
        m = dex.methods[em.method_idx]
        if not em.code_off:
            continue
        if m.name == '<clinit>' or m.name.startswith('access$'):
            continue

        try:
            lines = clean_myu_pseudo_lines(pseudo_event_method(dex, em, cls))
            body = event_body_to_iapp(lines).strip()
        except Exception:
            body = ''

        if m.name == '<init>':
            # Top-level aa.myu statements, when preserved by the compiler, appear here.
            if body:
                parts.append(body)
            continue

        # Non-constructor methods are rendered as module functions.  This is a
        # readable fallback, not an exact Java decompiler.
        if body:
            parts.append(f'fn {m.name}(){{\n{body}\n}}')
        else:
            parts.append(f'fn {m.name}(){{\n}}')

    return '\n\n'.join(parts) + ('\n' if parts else '')

def descriptor_to_name(cls: str) -> str:
    return cls.strip('L;').split('/')[-1]


def java_name(desc: str) -> str:
    if desc.startswith('['):
        dims = 0
        while dims < len(desc) and desc[dims] == '[':
            dims += 1
        return java_name(desc[dims:]) + '[]' * dims
    prim = {
        'V': 'void', 'Z': 'boolean', 'B': 'byte', 'S': 'short', 'C': 'char',
        'I': 'int', 'J': 'long', 'F': 'float', 'D': 'double',
    }
    if desc in prim:
        return prim[desc]
    if desc.startswith('L') and desc.endswith(';'):
        return desc[1:-1].replace('/', '.')
    return desc


def simple_class_name(desc: str) -> str:
    n = java_name(desc)
    if '[]' in n:
        suffix = n[n.index('[]'):]
        base = n[:n.index('[]')]
        return base.split('.')[-1] + suffix
    return n.split('.')[-1]


def array_component_name(desc: str) -> str:
    if desc.startswith('['):
        return simple_class_name(desc[1:])
    return simple_class_name(desc)


_ADVANCED_DEX_CONTEXT: Optional[Dex] = None
_PROTECTOR_RESOLVER_CONTEXT: Any = None
_SXCL_TABLE_CACHE: Dict[int, Optional[List[int]]] = {}
_PSEUDO_METHOD_CACHE: Dict[Tuple[int, int, str, int, int], Tuple[str, ...]] = {}


def parse_fill_array_payload_from_units(cu: List[int], payload_pos: int) -> Optional[List[int]]:
    if payload_pos < 0 or payload_pos + 4 > len(cu) or cu[payload_pos] != 0x0300:
        return None
    width = cu[payload_pos + 1]
    size = cu[payload_pos + 2] | (cu[payload_pos + 3] << 16)
    raw = b''.join(struct.pack('<H', x) for x in cu)
    byte_pos = (payload_pos + 4) * 2
    out: List[int] = []
    for i in range(size):
        chunk = raw[byte_pos + i * width:byte_pos + (i + 1) * width]
        if len(chunk) != width:
            return None
        out.append(int.from_bytes(chunk, 'little', signed=True))
    return out


def sxcl_short_table(dex: Dex) -> Optional[List[int]]:
    key = id(dex)
    if key in _SXCL_TABLE_CACHE:
        return _SXCL_TABLE_CACHE[key]
    cls = 'Lcom/iApp/protection/LianYi/sxcl;'
    table: Optional[List[int]] = None
    try:
        for em in dex.class_methods(cls):
            mr = dex.methods[em.method_idx]
            if mr.name != '<clinit>' or not em.code_off:
                continue
            _, _, cu = dex.code_units(em.code_off)
            for i in reachable_instruction_offsets(cu):
                if (cu[i] & 0xFF) == 0x26 and i + 2 < len(cu):
                    payload_pos = i + i4(cu[i + 1] | (cu[i + 2] << 16))
                    arr = parse_fill_array_payload_from_units(cu, payload_pos)
                    if arr:
                        table = arr
                        break
            if table:
                break
    except Exception:
        table = None
    _SXCL_TABLE_CACHE[key] = table
    return table


def decode_sxcl_call(expr: str, dex: Optional[Dex]) -> Optional[str]:
    if not dex:
        return None
    m = re.search(r'com\.iApp\.protection\.LianYi\.sxcl\.\$\((-?\d+)\s*,\s*(-?\d+)\s*,\s*(-?\d+)\)', expr)
    if not m:
        return None
    start, end, key = (int(m.group(1)), int(m.group(2)), int(m.group(3)))
    table = sxcl_short_table(dex)
    if not table or start < 0 or end < start or end > len(table):
        return None
    try:
        return ''.join(chr((table[i] ^ key) & 0xFFFF) for i in range(start, end))
    except Exception:
        return None


def resolve_static_field_value(dex: Optional[Dex], simple_cls: str, field_name: str) -> Optional[Any]:
    if not dex:
        return None
    cache = dex._static_field_lookup_cache
    if cache is None:
        exact: Dict[Tuple[str, str], Any] = {}
        by_name: Dict[str, List[Any]] = {}
        values_by_cls = {cls: dex.static_values(cls) for cls in dex.classes}
        for idx, fr in enumerate(dex.fields):
            vals = values_by_cls.get(fr.cls) or {}
            if idx not in vals:
                continue
            value = vals[idx]
            exact[(simple_class_name(fr.cls), fr.name)] = value
            by_name.setdefault(fr.name, []).append(value)
        cache = (exact, by_name)
        dex._static_field_lookup_cache = cache
    exact, by_name = cache
    key = (simple_cls, field_name)
    if key in exact:
        return exact[key]
    hits = by_name.get(field_name) or []
    return hits[0] if len(hits) == 1 else None


def fold_static_xor_expr(expr: str, dex: Optional[Dex]) -> str:
    if not dex:
        return expr
    pat = re.compile(r'\(?([^\s().]+)\.([^\s()^]+)\s*\^\s*(-?\d+)\)?')

    def repl(m: re.Match) -> str:
        v = resolve_static_field_value(dex, m.group(1), m.group(2))
        if isinstance(v, int):
            return str(v ^ int(m.group(3)))
        return m.group(0)

    return pat.sub(repl, expr)


def param_name(desc: str, idx: int) -> str:
    mapping = {
        'Landroid/app/Activity;': 'activity',
        'Landroid/view/Menu;': 'menu',
        'Landroid/view/MenuItem;': 'menuItem',
        'Landroid/view/KeyEvent;': 'event',
        'Landroid/webkit/SslErrorHandler;': 'hr',
        'Landroid/net/http/SslError;': 'er',
        'Landroid/webkit/WebView;': 'webView',
        'Landroid/view/MotionEvent;': 'motionEvent',
        'Landroid/text/Editable;': 'editable',
        'Ljava/lang/CharSequence;': 'charSequence',
        'Ljava/lang/Object;': 'obj',
        'I': 'i',
        'Z': 'z',
        'Ljava/lang/String;': 'str',
    }
    return mapping.get(desc, f'arg{idx}')


def dq_string(s: str) -> str:
    """Return a compact Java/iApp-style double-quoted string literal."""
    return '"' + s.replace('\\', '\\\\').replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t').replace('\"', '\\"') + '"'


def event_type_from_method(name: str) -> str:
    if name.startswith('on_$_'):
        return name[5:]
    if name.startswith('on_'):
        return name[3:]
    return name


def pseudo_event_method(dex: Dex, encoded: EncodedMethod, owner_cls: str) -> List[str]:
    """Very small Java-ish extractor for generated iApp event bridge methods.

    It is intentionally conservative: it records constants, field reads and
    invoke/return statements. This is enough for event glue such as
    IaptMain.start(activity), and still gives useful readable output for larger
    events instead of pretending to be a full Java decompiler.
    """
    resolver_ctx = globals().get('_PROTECTOR_RESOLVER_CONTEXT')
    advanced_ctx = globals().get('_ADVANCED_DEX_CONTEXT')
    cache_key = (id(dex), int(encoded.method_idx), owner_cls, id(resolver_ctx), id(advanced_ctx))
    cached = _PSEUDO_METHOD_CACHE.get(cache_key)
    if cached is not None:
        return list(cached)
    regs_count, ins_count, cu = dex.code_units(encoded.code_off)
    mref = dex.methods[encoded.method_idx]
    regs: Dict[int, Any] = {}
    pending: Any = None
    lines: List[str] = []
    pbase = regs_count - ins_count
    preg = pbase
    is_static_method = bool(encoded.access & 0x0008)
    if not is_static_method:
        regs[preg] = 'this'
        preg += 1
    for idx, pdesc in enumerate(mref.proto.params, start=1):
        regs[preg] = param_name(pdesc, idx)
        preg += 2 if pdesc in ('J', 'D') else 1

    def val(r: int) -> str:
        v = regs.get(r, f'v{r}')
        if isinstance(v, str):
            return v
        if isinstance(v, NewObj):
            return f'new {simple_class_name(v.typ)}'
        if isinstance(v, IntegerBox):
            return str(v.value)
        if v is None:
            return 'null'
        return str(v)

    def ref(r: int) -> str:
        v = regs.get(r)
        if v is None or isinstance(v, (int, IntegerBox)):
            return f'v{r}'
        return val(r)

    def stable(r: int) -> str:
        v = regs.get(r)
        if isinstance(v, IntegerBox):
            return str(v.value)
        if isinstance(v, int):
            return str(v)
        if isinstance(v, str):
            if re.match(r'^-?\d+$', v) or v in ('true', 'false', 'null') or (v.startswith('"') and v.endswith('"')):
                return v
        return f'v{r}'

    def method_call(m: MethodRef, values: List[str], invoke_kind: str) -> str:
        if m.name == '<init>':
            cls = simple_class_name(m.cls)
            args = ', '.join(values[1:]) if values else ''
            return f'new {cls}({args})'
        args = ', '.join(values[1:]) if invoke_kind != 'static' else ', '.join(values)
        if invoke_kind == 'static':
            return f'{java_name(m.cls)}.{m.name}({args})'
        target = values[0] if values else simple_class_name(m.cls)
        return f'{target}.{m.name}({args})'

    def reg23x() -> Tuple[int, int, int]:
        return aa, cu[i + 1] & 0xFF, (cu[i + 1] >> 8) & 0xFF

    def emit(line: str) -> None:
        line = (line or '').strip()
        if line:
            lines.append(line)

    def bin_expr(opname: str, left: str, right: str) -> str:
        sym = {
            'add': '+', 'sub': '-', 'mul': '*', 'div': '/', 'rem': '%',
            'and': '&', 'or': '|', 'xor': '^', 'shl': '<<', 'shr': '>>', 'ushr': '>>>',
        }.get(opname, opname)
        return f'({left} {sym} {right})'

    def int_op_name(opcode: int) -> Optional[str]:
        names = ['add', 'sub', 'mul', 'div', 'rem', 'and', 'or', 'xor', 'shl', 'shr', 'ushr']
        if 0x90 <= opcode <= 0x9A:
            return names[opcode - 0x90]
        if 0xB0 <= opcode <= 0xBA:
            return names[opcode - 0xB0]
        if 0xD0 <= opcode <= 0xD7:
            return ['add', 'rsub', 'mul', 'div', 'rem', 'and', 'or', 'xor'][opcode - 0xD0]
        if 0xD8 <= opcode <= 0xE2:
            return names[opcode - 0xD8]
        return None

    reachable_offsets = reachable_instruction_offsets(cu)
    branch_labels: set[int] = set()

    def switch_entries(at: int, opcode: int) -> List[Tuple[Optional[int], int]]:
        """Return (case-key, absolute-target) pairs for a DEX switch.

        ``None`` is not used for actual cases; the caller emits the fallthrough
        as the default branch.  Invalid payloads simply return an empty list so
        one malformed method cannot abort project recovery.
        """
        try:
            payload = branch_target(at, i4(cu[at + 1] | (cu[at + 2] << 16)))
            ident = cu[payload]
            size = cu[payload + 1]
            rows: List[Tuple[Optional[int], int]] = []
            if opcode == 0x2B and ident == 0x0100:
                first_key = i4(cu[payload + 2] | (cu[payload + 3] << 16))
                base = payload + 4
                for k in range(size):
                    pos = base + 2 * k
                    off = i4(cu[pos] | (cu[pos + 1] << 16))
                    rows.append((first_key + k, branch_target(at, off)))
            elif opcode == 0x2C and ident == 0x0200:
                keys = payload + 2
                targets = keys + size * 2
                for k in range(size):
                    kp = keys + 2 * k
                    tp = targets + 2 * k
                    key = i4(cu[kp] | (cu[kp + 1] << 16))
                    off = i4(cu[tp] | (cu[tp + 1] << 16))
                    rows.append((key, branch_target(at, off)))
            return rows
        except Exception:
            return []

    # Materialize branch targets as labels in the deep-code stream.  This turns
    # the old opaque ``/* goto +N */`` comments into a complete control-flow
    # skeleton without risking invalid executable iApp source (the event layer
    # comments labels/gotos out, while deep_code keeps them verbatim).
    for j in reachable_offsets:
        try:
            jw = cu[j]
            jop = jw & 0xFF
            jaa = jw >> 8
            if jop == 0x28:
                branch_labels.add(branch_target(j, s8(jaa)))
            elif jop == 0x29:
                branch_labels.add(branch_target(j, i2(cu[j + 1])))
            elif jop == 0x2A:
                branch_labels.add(branch_target(j, i4(cu[j + 1] | (cu[j + 2] << 16))))
            elif 0x32 <= jop <= 0x3D:
                branch_labels.add(branch_target(j, i2(cu[j + 1])))
            elif jop in (0x2B, 0x2C):
                for _, target in switch_entries(j, jop):
                    branch_labels.add(target)
        except Exception:
            pass

    for i in reachable_offsets:
        if i in branch_labels:
            emit(f'L_{i:04x}:')
        w = cu[i]
        op = w & 0xFF
        aa = w >> 8
        # Dalvik permits an invoke result to be discarded by omitting move-result.
        # V6 protectors use this heavily for reflected UI setters/add() calls;
        # keep those calls so the protector resolver can recover their side effects.
        if pending is not None and op not in (0x0A, 0x0B, 0x0C):
            if isinstance(pending, str) and '(' in pending:
                emit('// IAPT_DISCARDED_CALL ' + pending + ';')
            pending = None
        try:
            if op == 0x12:  # const/4
                regs[aa & 0xF] = s4bit(aa >> 4)
            elif op == 0x13:  # const/16
                regs[aa] = i2(cu[i + 1])
            elif op == 0x14:  # const
                regs[aa] = i4(cu[i + 1] | (cu[i + 2] << 16))
            elif op == 0x15:  # const/high16
                regs[aa] = i4(cu[i + 1] << 16)
            elif op == 0x16:  # const-wide/16
                regs[aa] = i2(cu[i + 1])
            elif op == 0x17:  # const-wide/32
                regs[aa] = i4(cu[i + 1] | (cu[i + 2] << 16))
            elif op == 0x18:  # const-wide
                regs[aa] = f'wide@{i}'
            elif op == 0x19:  # const-wide/high16
                regs[aa] = f'wide@{i}'
            elif op == 0x1A:  # const-string
                idx = cu[i + 1]
                regs[aa] = dq_string(dex.strings[idx]) if 0 <= idx < len(dex.strings) else f'string@{idx}'
            elif op == 0x1B:
                idx = cu[i + 1] | (cu[i + 2] << 16)
                regs[aa] = dq_string(dex.strings[idx]) if 0 <= idx < len(dex.strings) else f'string@{idx}'
            elif op == 0x22:  # new-instance
                cls_name = simple_class_name(dex.types[cu[i + 1]])
                obj_name = f'v{aa}_obj_{i}'
                regs[aa] = obj_name
                emit(f'{cls_name} {obj_name} = new {cls_name}();')
            elif op == 0x1C:  # const-class
                regs[aa] = java_name(dex.types[cu[i + 1]]) + '.class'
            elif op in (0x1F,):  # check-cast
                regs[aa] = f'(({simple_class_name(dex.types[cu[i + 1]])}) {val(aa)})'
            elif op in (0x01, 0x04, 0x07):
                regs[aa & 0xF] = regs.get(aa >> 4, f'v{aa >> 4}')
            elif op in (0x02, 0x05, 0x08):
                regs[aa] = regs.get(cu[i + 1], f'v{cu[i + 1]}')
            elif op in (0x03, 0x06, 0x09):
                regs[aa] = regs.get(cu[i + 1] | (cu[i + 2] << 16), f'v{cu[i + 1] | (cu[i + 2] << 16)}')
            elif op in (0x0A, 0x0B, 0x0C):
                # Keep a candidate expression statement.  The protector resolver
                # later emits it only when the resolved target has side effects
                # (for example Thread.start(), widget setters, java(), tw()).
                # Pure getters/string decryptors are discarded, so this does not
                # duplicate values that are consumed by later instructions.
                if isinstance(pending, str) and '(' in pending:
                    emit('// IAPT_MAYBE_CALL ' + pending + ';')
                regs[aa] = pending
                pending = None
            elif op == 0x20:  # instance-of
                a = aa & 0xF
                b = aa >> 4
                regs[a] = f'({val(b)} instanceof {simple_class_name(dex.types[cu[i + 1]])})'
            elif op == 0x21:  # array-length
                a = aa & 0xF
                b = aa >> 4
                regs[a] = f'{val(b)}.length'
            elif op == 0x23:  # new-array
                a = aa & 0xF
                b = aa >> 4
                comp = array_component_name(dex.types[cu[i + 1]])
                arr_name = f'v{a}_arr_{i}'
                length_expr = stable(b)
                if length_expr == f'v{a}':
                    len_name = f'v{a}_len_{i}'
                    emit(f'int {len_name} = {length_expr};')
                    length_expr = len_name
                regs[a] = arr_name
                emit(f'{comp}[] {arr_name} = new {comp}[{length_expr}];')
            elif op == 0x24:  # filled-new-array
                comp = array_component_name(dex.types[cu[i + 1]])
                args = [val(r) for r in regs_35c(aa, cu[i + 2])]
                pending = f'new {comp}[]{{{", ".join(args)}}}'
            elif op == 0x25:  # filled-new-array/range
                comp = array_component_name(dex.types[cu[i + 1]])
                count = aa
                start = cu[i + 2]
                args = [val(r) for r in range(start, start + count)]
                pending = f'new {comp}[]{{{", ".join(args)}}}'
            elif op == 0x26:  # fill-array-data
                emit(f'// fill-array-data {ref(aa)};')
            elif 0x44 <= op <= 0x51:  # aget/aput
                a, b, c = reg23x()
                if 0x44 <= op <= 0x4A:
                    regs[a] = f'{ref(b)}[{stable(c)}]'
                else:
                    emit(f'{ref(b)}[{stable(c)}] = {val(a)};')
            elif 0x52 <= op <= 0x5F:  # instance get/put
                a = aa & 0xF
                b = aa >> 4
                fr = dex.fields[cu[i + 1]]
                if op in (0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58):
                    regs[a] = f'{ref(b)}.{fr.name}'
                elif op in (0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F):
                    emit(f'{ref(b)}.{fr.name} = {val(a)};')
            elif 0x60 <= op <= 0x6D:  # static get/put
                a = aa
                fr = dex.fields[cu[i + 1]]
                q = f'{simple_class_name(fr.cls)}.{fr.name}'
                if op in (0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66):
                    regs[a] = q
                else:
                    emit(f'{q} = {val(a)};')
            elif 0x6E <= op <= 0x72:
                midx = cu[i + 1]
                im = dex.methods[midx]
                args = regs_35c(aa, cu[i + 2])
                values = [val(r) for r in args]
                kind = {0x6E: 'virtual', 0x6F: 'super', 0x70: 'direct', 0x71: 'static', 0x72: 'interface'}[op]
                if im.cls == 'Ljava/lang/Integer;' and im.name == 'valueOf' and values:
                    pending = values[0]
                elif im.name == '<init>' and args:
                    # Replace the temporary created by new-instance with a full
                    # constructor expression.  This preserves captured arguments
                    # for generated Runnable/OnClick inner classes, enabling the
                    # deep interpreter to inline their run()/onClick() bodies.
                    call = method_call(im, values, kind)
                    regs[args[0]] = call
                    pending = None
                else:
                    call = method_call(im, values, kind)
                    if im.proto.ret == 'V':
                        emit(call + ';')
                        pending = None
                    else:
                        pending = call
            elif 0x74 <= op <= 0x78:
                midx = cu[i + 1]
                im = dex.methods[midx]
                count = aa
                start = cu[i + 2]
                values = [val(r) for r in range(start, start + count)]
                kind = {0x74: 'virtual', 0x75: 'super', 0x76: 'direct', 0x77: 'static', 0x78: 'interface'}[op]
                if im.cls == 'Ljava/lang/Integer;' and im.name == 'valueOf' and values:
                    pending = values[0]
                elif im.name == '<init>' and count:
                    call = method_call(im, values, kind)
                    regs[start] = call
                    pending = None
                else:
                    call = method_call(im, values, kind)
                    if im.proto.ret == 'V':
                        emit(call + ';')
                        pending = None
                    else:
                        pending = call
            elif op in (0x2B, 0x2C):  # packed/sparse-switch
                rows = switch_entries(i, op)
                parts = [f'case {key}: goto L_{target:04x};' for key, target in rows]
                parts.append(f'default: goto L_{i + insn_len(op):04x};')
                emit(f'switch ({val(aa)}) {{ ' + ' '.join(parts) + ' }')
            elif op in (0x28, 0x29, 0x2A):  # goto
                off = s8(aa) if op == 0x28 else (i2(cu[i + 1]) if op == 0x29 else i4(cu[i + 1] | (cu[i + 2] << 16)))
                emit(f'goto L_{branch_target(i, off):04x};')
            elif 0x32 <= op <= 0x37:  # if-test
                a = aa & 0xF
                b = aa >> 4
                off = i2(cu[i + 1])
                cmpop = ['==', '!=', '<', '>=', '>', '<='][op - 0x32]
                emit(f'if ({val(a)} {cmpop} {val(b)}) goto L_{branch_target(i, off):04x};')
            elif 0x38 <= op <= 0x3D:  # if-testz
                off = i2(cu[i + 1])
                cmpop = ['==', '!=', '<', '>=', '>', '<='][op - 0x38]
                emit(f'if ({val(aa)} {cmpop} 0) goto L_{branch_target(i, off):04x};')
            elif op == 0x0E:
                emit('return;')
            elif op in (0x0F, 0x10, 0x11):
                rv = val(aa)
                if rv == '1': rv = 'true'
                elif rv == '0': rv = 'false'
                emit(f'return {rv};')
            elif 0x2D <= op <= 0x31:
                a, b, c = reg23x()
                cmpop = ['cmp-long', 'cmpl-float', 'cmpg-float', 'cmpl-double', 'cmpg-double'][op - 0x2D]
                regs[a] = f'{cmpop}({val(b)}, {val(c)})'
            elif 0x90 <= op <= 0xAF:  # binop vAA, vBB, vCC
                a, b, c = reg23x()
                opname = int_op_name(op)
                if opname:
                    regs[a] = bin_expr(opname, val(b), val(c))
            elif 0xB0 <= op <= 0xCF:  # binop/2addr vA, vB
                a = aa & 0xF
                b = aa >> 4
                opname = int_op_name(op)
                if opname:
                    regs[a] = bin_expr(opname, val(a), val(b))
            elif 0xD0 <= op <= 0xD7:
                a = aa & 0xF
                b = aa >> 4
                base = regs.get(b)
                lit = i2(cu[i + 1])
                opname = int_op_name(op)
                if op == 0xD1:
                    regs[a] = bin_expr('sub', str(lit), val(b))
                elif opname:
                    regs[a] = bin_expr(opname, val(b), str(lit))
                else:
                    regs[a] = (base + lit) if isinstance(base, int) else lit
            elif 0xD8 <= op <= 0xE2:
                a = aa
                b = cu[i + 1] & 0xFF
                lit = s8((cu[i + 1] >> 8) & 0xFF)
                base = regs.get(b)
                opname = int_op_name(op)
                if opname:
                    regs[a] = bin_expr(opname, val(b), str(lit))
                else:
                    regs[a] = (base + lit) if isinstance(base, int) else lit
        except Exception:
            emit(f'// dex op 0x{op:02x} parse skipped')

    if pending is not None and isinstance(pending, str) and '(' in pending:
        emit('// IAPT_DISCARDED_CALL ' + pending + ';')

    # Remove trailing return; from void event bridges unless it is the only line.
    if any(x != 'return;' for x in lines):
        lines = [x for x in lines if x != 'return;']
    resolver = globals().get('_PROTECTOR_RESOLVER_CONTEXT')
    if resolver is not None:
        try:
            # Resolve the protector's tiny zero-argument XOR helpers first;
            # those values are commonly used as string slice lengths.
            lines = [fold_static_xor_expr(x, dex) for x in lines]
            lines = resolver.rewrite_lines(lines)
        except Exception as exc:
            if os.environ.get('IAPT_V6_RESOLVER_DEBUG') == '1':
                print(f'[V6保护器] 事件重写失败: {type(exc).__name__}: {exc}', file=sys.stderr)
    _PSEUDO_METHOD_CACHE[cache_key] = tuple(lines)
    return list(lines)


def recover_events_for_class(dex: Dex, cls: str) -> OrderedDict:
    events: OrderedDict[str, List[str]] = OrderedDict()
    for em in dex.class_methods(cls):
        m = dex.methods[em.method_idx]
        if not em.code_off:
            continue
        if not m.name.startswith('on_'):
            continue
        if m.name == 'on_$_viewAutomaticSettingEvent':
            continue
        lines = recover_v6_concrete_event_lines(dex, em, cls)
        if not lines:
            lines = pseudo_event_method(dex, em, cls)
        events[event_type_from_method(m.name)] = lines
    return events


def events_to_text(events: OrderedDict) -> str:
    out: List[str] = []
    for name, lines in events.items():
        out.append(f'[{name}]')
        if lines:
            out.extend(lines)
        else:
            out.append('// empty')
        out.append('')
    return '\n'.join(out).rstrip() + ('\n' if out else '')


def is_boilerplate_event(lines: List[str]) -> bool:
    """Generated Activity/Menu overrides are not user .iyu event source."""
    norm = [x.strip() for x in lines if x.strip()]
    return norm in ([], ['return;'], ['return true;'], ['return false;'])


def normalize_iapp_event_expr(line: str) -> str:
    """Convert the small pseudo-Java bridge syntax back to iApp event source.

    Examples from dex:
      this.tw(java.lang.Integer.valueOf(4));  -> tw(4)
      this.uigo("mian.iyu");              -> uigo("mian.iyu")
      com.pkg.Main.start(activity);          -> java com.pkg.Main.start(activity);
    """
    line = line.strip()
    # Remove common boxing introduced by Java compilation.
    line = re.sub(r'java\.lang\.Integer\.valueOf\(([^()]*)\)', r'\1', line)
    line = re.sub(r'java\.lang\.Boolean\.valueOf\(([^()]*)\)', r'\1', line)
    if line.endswith(';'):
        line = line[:-1].strip()
    # Calls on generated Activity page helpers are iApp built-ins, not mixed Java.
    if line.startswith('this.'):
        line = line[5:]
    return line


def looks_like_fqcn_call(expr: str) -> bool:
    m = re.match(r'^([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*){2,})\s*\(', expr)
    return bool(m)


def looks_like_java_expr(expr: str) -> bool:
    return (
        'LianYi.NB.' in expr
        or 'com.iApp.protection.' in expr
        or re.search(r'[\u0600-\u06ff]', expr) is not None
        or re.search(r'\(\([A-Za-z_$][\w$.$\[\]]+\)', expr) is not None
        or re.search(r'\b[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*', expr) is not None
    )


def _decode_float_boxing(text: str) -> str:
    """Decode javac/dex float boxing emitted as Float.valueOf(rawIntBits)."""
    pat = re.compile(r'(?:java\.lang\.)?Float\.valueOf\((-?\d+)\)')
    def repl(m: re.Match) -> str:
        try:
            bits = int(m.group(1)) & 0xFFFFFFFF
            value = struct.unpack('<f', struct.pack('<I', bits))[0]
            if not math.isfinite(value):
                return m.group(0)
            return ('%.7g' % value)
        except Exception:
            return m.group(0)
    return pat.sub(repl, text)


def _balanced_source(text: str) -> bool:
    """Cheap balance check used before emitting source into a .iyu event body."""
    pairs = {'(': ')', '[': ']', '{': '}'}
    stack: List[str] = []
    quote = ''
    esc = False
    for ch in text:
        if quote:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            quote = ch
        elif ch in pairs:
            stack.append(pairs[ch])
        elif ch in ')]}':
            if not stack or stack.pop() != ch:
                return False
    return not stack and not quote



# ---------------------------------------------------------------------------
# V18.6 V6 syntax lowering
# ---------------------------------------------------------------------------
# V6 source is not a Java-like expression dump.  The manual uses ordinary V6
# assignment statements (``s a = ...``), global/page variables such as
# ``sss.url``/``ss.name``, and UI mutation helpers such as ``us(id,"text",v)``.
# Earlier protected-event recovery intentionally kept large expression trees so
# no logic was lost, but that produced lines like ``tw(json(json(hs(...))))``.
# The lowering layer below converts those trees into simple, importable V6.

_V6_LOWER_PURE_FUNCS = {
    'hs', 'json', 'dhs', 'dhr', 'dha', 'ngde', 'nuibs', 'activity', 'ug',
    'fr', 'time', 'cls', 'javanew', 'loadjar', 'bfm', 'hd', 'huf', 'hw', 'hws',
    'st', 'zf', 'java', 'javax', 'sjxx', 'simsi', 'simei', 'sran', 'sl', 'sr',
    'sj', 'ssg', 'siof', 'slof', 'slg', 'strim', 'slower', 'supper', 'fdir',
    'fe', 'fs', 'fi', 'fl', 'sbp', 'tot', 'tzz', 'tsf', 'tfz', 'tcc', 'sit',
    'git', 'ula', 'ulag', 'ulas', 'uall', 'gvs', 'zdp', 'zpd', 'zps', 'zsp',
}

_V6_LOWER_STMT_FUNCS = {
    'tw', 'syso', 'uigo', 'us', 'ug', 'dh', 'stop', 'end', 'ends', 'endutw',
    'endkeyboard', 'ushsp', 'uycl', 'uapp', 'uninapp', 'ucall', 'usms', 'sxb',
    'bfv', 'bfvs', 'bfvss', 'bfms', 'fo', 'fd', 'fc', 'fw', 'ft', 'fuz', 'fuzs',
    'fj', 'ula', 'uls', 'hdfla', 'ftz', 'addv', 'urvw', 'nvw', 'uit', 'utw',
    'hdfl', 'sdeg', 'usjxm', 'java', 'javax',
}



def _v6_cdata(text: str) -> str:
    return '<![CDATA[' + (text or '').replace(']]>', ']]]]><![CDATA[>') + ']]>'

def _v6_unescape_expr(text: str) -> str:
    # The source text is stored under XML nodes later.  We must unescape here so
    # generated V6 code contains real URL/post separators, then XML escaping will
    # safely re-escape only the surrounding XML text.
    return html.unescape(text or '').strip()


def _v6_split_args(src: str) -> List[str]:
    args: List[str] = []
    start = 0
    depth = 0
    quote = ''
    esc = False
    for i, ch in enumerate(src):
        if quote:
            if esc:
                esc = False
            elif ch == '\\':
                esc = True
            elif ch == quote:
                quote = ''
            continue
        if ch in ('"', "'"):
            quote = ch
            continue
        if ch in '([{':
            depth += 1
            continue
        if ch in ')]}':
            depth = max(0, depth - 1)
            continue
        if ch == ',' and depth == 0:
            args.append(src[start:i].strip())
            start = i + 1
    tail = src[start:].strip()
    if tail or src.strip():
        args.append(tail)
    return args


def _v6_call_parts(expr: str) -> Optional[Tuple[str, str]]:
    expr = expr.strip()
    m = re.match(r'^([A-Za-z_$][A-Za-z0-9_$]*)\s*\(', expr)
    if not m or not expr.endswith(')'):
        return None
    name = m.group(1)
    inner = expr[m.end():-1]
    if _balanced_source(inner):
        return name, inner
    return None


def _v6_dq_value(s: str) -> Optional[str]:
    s = s.strip()
    if len(s) >= 2 and s[0] == '"' and s[-1] == '"':
        try:
            return json.loads(s)
        except Exception:
            return s[1:-1]
    return None


def _v6_valid_ident(name: str) -> bool:
    return bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name or ''))


def _v6_convert_var_helpers(expr: str) -> str:
    """Convert legacy helper function notation to V6 variable notation."""
    expr = _v6_unescape_expr(expr)

    def getter_repl(m: re.Match) -> str:
        scope, key = m.group(1), m.group(2)
        try:
            key_val = json.loads('"' + key.replace('\\"', '"') + '"')
        except Exception:
            key_val = key
        if _v6_valid_ident(key_val):
            return f'{scope}.{key_val}'
        return f'{scope}({json.dumps(key_val, ensure_ascii=False)})'

    # sss("url") / ss("name") -> sss.url / ss.name.  Setter calls are handled as
    # complete statements by _v6_lower_statement, not with this local regex.
    expr = re.sub(r'\b(sss|ss)\(\s*"((?:[^"\\]|\\.)*)"\s*\)', getter_repl, expr)
    return expr


def _v6_simplify_json_wrappers(expr: str) -> str:
    """Drop compiler-only json(x) wrappers around a real json(x,"get",k)."""
    old = None
    out = expr.strip()
    # json(json(x),"get","k") -> json(x,"get","k")
    while old != out:
        old = out
        parts = _v6_call_parts(out)
        if not parts:
            break
        name, inner = parts
        if name != 'json':
            break
        args = _v6_split_args(inner)
        if len(args) >= 3:
            first = args[0].strip()
            fp = _v6_call_parts(first)
            if fp and fp[0] == 'json':
                fargs = _v6_split_args(fp[1])
                if len(fargs) == 1:
                    out = 'json(' + ','.join([fargs[0]] + args[1:]) + ')'
    # Remove nested single-argument wrappers anywhere simple enough to match.
    # This handles json(json(json(hs(...)),"get","data"),"get","account").
    while True:
        m = re.search(r'json\((json\((?:[^()"\\]+|"(?:[^"\\]|\\.)*"|\([^()]*\))*\))\s*,', out)
        if not m:
            break
        inner_call = m.group(1)
        parts = _v6_call_parts(inner_call)
        if not parts or parts[0] != 'json':
            break
        a = _v6_split_args(parts[1])
        if len(a) != 1:
            break
        out = out[:m.start(1)] + a[0] + out[m.end(1):]
    return out


def _v6_tmp_name(counter: List[int]) -> str:
    counter[0] += 1
    return f'iapt_v6_{counter[0]}'


def _v6_needs_tmp(expr: str) -> bool:
    expr = expr.strip()
    parts = _v6_call_parts(expr)
    if not parts:
        return False
    name, inner = parts
    if name not in _V6_LOWER_PURE_FUNCS:
        return False
    return True


def _v6_lower_expr(expr: str, prelude: List[str], counter: List[int], force_tmp: bool = False) -> str:
    """Return a simple V6 expression, adding assignment lines to prelude."""
    expr = _v6_simplify_json_wrappers(_v6_convert_var_helpers(expr.strip()))
    parts = _v6_call_parts(expr)
    if not parts:
        return expr
    name, inner = parts
    args = [_v6_lower_expr(a, prelude, counter, force_tmp=_v6_needs_tmp(a)) for a in _v6_split_args(inner)]
    rebuilt = name + '(' + ','.join(args) + ')'
    # Page variable getter helpers were converted by _v6_convert_var_helpers; a
    # remaining ss()/sss() call is usually a setter or a dynamic key expression.
    if name in {'ss', 'sss'} and len(args) == 1:
        return rebuilt
    if force_tmp or name in {'hs', 'json'}:
        tmp = _v6_tmp_name(counter)
        prelude.append(f's {tmp} = {rebuilt}')
        return tmp
    return rebuilt


def _v6_lower_statement(line: str, counter: List[int]) -> List[str]:
    """Lower one recovered event line to importable V6 statements."""
    raw = _v6_unescape_expr(line.strip())
    if not raw or raw in ('{', '}') or raw.startswith('//'):
        return [raw] if raw else []

    # Convert legacy map setters: sss("token", value) -> sss token = value.
    parts = _v6_call_parts(raw)
    if parts and parts[0] in {'ss', 'sss'}:
        args = _v6_split_args(parts[1])
        if len(args) >= 2:
            key = _v6_dq_value(args[0])
            pre: List[str] = []
            val = _v6_lower_expr(args[1], pre, counter, force_tmp=False)
            if key and _v6_valid_ident(key):
                return pre + [f'{parts[0]} {key} = {val}']

    # Widget mutator from the VM: s(id,"text",v) is not V6 variable syntax.
    # V6 uses us(id,"attr",v); startAnimation maps to the documented dh attr.
    if parts and parts[0] == 's':
        args = _v6_split_args(parts[1])
        if len(args) >= 3 and _v6_dq_value(args[1]) is not None:
            attr = _v6_dq_value(args[1]) or args[1].strip('"')
            if attr == 'startAnimation':
                attr = 'dh'
            pre: List[str] = []
            lowered = [args[0], json.dumps(attr, ensure_ascii=False)]
            lowered.extend(_v6_lower_expr(a, pre, counter, force_tmp=_v6_needs_tmp(a)) for a in args[2:])
            return pre + ['us(' + ','.join(lowered) + ')']

    if parts and parts[0] in _V6_LOWER_STMT_FUNCS:
        name, inner = parts
        pre: List[str] = []
        args = [_v6_lower_expr(a, pre, counter, force_tmp=_v6_needs_tmp(a)) for a in _v6_split_args(inner)]
        return pre + [name + '(' + ','.join(args) + ')']

    # Assignment line: lower only the right-hand side.
    m = re.match(r'^(s|ss|sss|string|int|long|double|float|boolean|object)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$', raw)
    if m:
        pre: List[str] = []
        rhs = _v6_lower_expr(m.group(3), pre, counter, force_tmp=False)
        return pre + [f'{m.group(1)} {m.group(2)} = {rhs}']

    return [_v6_convert_var_helpers(raw)]


def lower_v6_event_body(body: str) -> str:
    """Lower generated event source according to the V6 manual syntax."""
    out: List[str] = []
    counter = [0]
    for line in body.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        indent = line[:len(line) - len(line.lstrip())]
        lowered = _v6_lower_statement(stripped, counter)
        for l in lowered:
            if l in ('{', '}'):
                out.append(indent + l)
            else:
                out.append(indent + l)
    return '\n'.join(out)

def _compact_unresolved(raw: str, prefix: str = 'IAPT静态未完全还原') -> str:
    brief = re.sub(r'\s+', ' ', raw.strip())
    if len(brief) > 260:
        brief = brief[:260] + '...'
    # ``//`` is valid inside Yu5Src and cannot break XML structure.
    return f'// {prefix}: {brief}'


def _normalize_hashmap_bridge(raw: str) -> Optional[str]:
    """Restore the iApp ss/sss(key,value) form from Java HashMap.put bridges."""
    patterns = (
        (r'^\(\(HashMap\)\s*(?:this\.)?sss\(\)\)\.put\((.*)\)\s*;?$', 'sss'),
        (r'^\(\(HashMap\)\s*(?:this\.)?ss\(\)\)\.put\((.*)\)\s*;?$', 'ss'),
        (r'^(?:this\.)?sss\(\)\.put\((.*)\)\s*;?$', 'sss'),
        (r'^(?:this\.)?ss\(\)\.put\((.*)\)\s*;?$', 'ss'),
    )
    for pat, name in patterns:
        m = re.match(pat, raw, re.S)
        if m and _balanced_source(m.group(1)):
            return f'{name}({re.sub(r",\s+", ",", m.group(1).strip())})'
    return None


def interpret_java_line_as_iapp(line: str) -> str:
    """Best-effort interpreter layer for protected V6 event pseudo-code.

    The output policy is deliberately fail-closed: only confirmed iApp syntax is
    emitted as executable source.  Uncertain Java/control-flow fragments become
    comments so the generated .iyu remains importable instead of failing to parse.
    A full Java-ish reconstruction is written separately under ``deep_code``.
    """
    raw = line.strip()
    for marker in ('// IAPT_SIDE_EFFECT ', '// IAPT_DISCARDED_CALL ', '// IAPT_MAYBE_CALL '):
        if raw.startswith(marker):
            raw = raw[len(marker):].strip()
            break
    if raw.startswith('java '):
        raw = raw[5:].strip()
    raw = _decode_float_boxing(raw)
    raw = re.sub(r'(?:java\.lang\.)?(?:Integer|Long|Short|Byte|Boolean)\.valueOf\(([^()]*)\)', r'\1', raw)
    raw = re.sub(r'\b0\.valueOf\(([^()]*)\)', r'\1', raw)
    # Java HashMap bridges generated by the V6 compiler map directly to iApp's
    # global/page variable helpers.  Normalize nested getters before the call
    # parser sees them, otherwise expressions such as javax(..., ((HashMap)
    # this.sss()).get("is")) remain invalid mixed Java in the .iyu output.
    raw = re.sub(r'\(\(HashMap\)\s*(?:this\.)?sss\(\)\)\.get\(([^()]*)\)', r'sss(\1)', raw)
    raw = re.sub(r'\(\(HashMap\)\s*(?:this\.)?ss\(\)\)\.get\(([^()]*)\)', r'ss(\1)', raw)
    raw = re.sub(r'(?<![\w.])(?:this\.)?sss\(\)\.get\(([^()]*)\)', r'sss(\1)', raw)
    raw = re.sub(r'(?<![\w.])(?:this\.)?ss\(\)\.get\(([^()]*)\)', r'ss(\1)', raw)
    raw = fold_static_xor_expr(raw, _ADVANCED_DEX_CONTEXT)
    sx = decode_sxcl_call(raw, _ADVANCED_DEX_CONTEXT)
    if sx is not None:
        msx = re.search(r'com\.iApp\.protection\.LianYi\.sxcl\.\$\([^)]*\)(?:\.intern\(\))?', raw)
        raw = raw.replace(msx.group(0), dq_string(sx)) if msx else dq_string(sx)
    raw = raw.strip().rstrip(';').strip()

    hm = _normalize_hashmap_bridge(raw)
    if hm:
        return hm
    # Standalone map getters are compiler scaffolding before put().
    if re.fullmatch(r'(?:this\.)?(?:ss|sss)\(\)', raw):
        return ''
    if raw.startswith('return '):
        return ''
    # Branch offsets are Dalvik implementation details.  Emitting them as iApp
    # code creates invalid or semantically false blocks, so retain them as a
    # readable diagnostic in the deep-code output and a harmless comment here.
    if (raw.startswith(('if(', 'if ', 'else', 'for(', 'for ', 'goto ', 'switch ', '{', '}'))
            or re.fullmatch(r'L_[0-9a-fA-F]+:', raw)):
        return _compact_unresolved(raw, '控制流已完整记录于 deep_code')
    if re.search(r'\bv\d+(?:_(?:arr|obj|len)_\d+)?(?:\[[^]]+\])?\s*=', raw):
        return _compact_unresolved(raw, '编译器临时变量')
    if re.search(r'\bv\d+_(?:arr|obj|len)_\d+\b', raw):
        return _compact_unresolved(raw, '参数数组已恢复到 deep_code')
    if 'LianYi.NB.' in raw or re.search(r'[\u0600-\u06ff]', raw):
        return _compact_unresolved(raw, '保护器调用未静态求值')

    raw = normalize_iapp_event_expr(raw)
    # Confirmed page/iApp built-ins.  Match the whole expression rather than an
    # inner call; this avoids the old ``sss()).put`` truncation bug.
    simple = re.fullmatch(r'([A-Za-z_$][A-Za-z0-9_$]*)\s*\((.*)\)', raw, re.S)
    safe_builtins = {
        'tw','t','ufnsui','uigo','us','ug','s','ss','sss','syso','java','javax',
        'cls','javanew','stop','end','activity','ngde','fr','loadjar','bfm','dh',
        'dhs','hw','ushsp','javax','sqlite','hd','hws','ula','uls','uht','utw',
    }
    if simple and simple.group(1) in safe_builtins and _balanced_source(raw):
        if simple.group(1) == 't' and re.match(r'\s*new\s+[\w$]+\s*\(', simple.group(2), re.S):
            return _compact_unresolved(raw, '线程体已恢复到 deep_code')
        return re.sub(r',\s+', ',', raw)

    # A fully qualified Java call can be embedded with iApp's ``java`` bridge
    # only when it is syntactically balanced.  Object casts/chained expressions
    # are kept in deep_code because blindly prefixing ``java`` is not valid iApp.
    if looks_like_fqcn_call(raw) and _balanced_source(raw) and not raw.startswith(('new ', 'if ')):
        return 'java ' + raw + ';'
    return _compact_unresolved(raw)


def event_line_to_iapp_source(line: str, advanced_analysis: bool = False) -> str:
    line = line.strip()
    if not line:
        return ''
    # Concrete event VM already emits native V6 DSL.  Preserve block braces and
    # confirmed built-ins instead of sending them through the Java-ish fallback.
    if line in ('{', '}'):
        return line
    _v6_direct = (
        't()', 'ufnsui()', 'tw(', 'uigo(', 'us(', 'ug(', 's(', 'ss(', 'sss(',
        'syso(', 'java(', 'javax(', 'cls(', 'javanew(', 'stop(', 'end(', 'end',
        'activity(', 'ngde(', 'fr(', 'loadjar(', 'bfm(', 'dh(', 'dhs(', 'dhr(', 'dha(', 'hs(', 'hw(',
        'ushsp(', 'sqlite(', 'hd(', 'hws(', 'ula(', 'uls(', 'uht(', 'utw(',
        'uall(', 'uapp(', 'time(', 'zf(',
    )
    if line.startswith(_v6_direct):
        return re.sub(r',\s+', ',', line)
    if advanced_analysis and line.startswith((
        '// IAPT_SIDE_EFFECT ', '// IAPT_DISCARDED_CALL ', '// IAPT_MAYBE_CALL '
    )):
        return interpret_java_line_as_iapp(line)
    iapp_prefixes = (
        'tw(', 't(', 'ufnsui', 'uigo(', 's(', 'ss(', 'sss(', 'syso(',
        'stop(', 'for(', 'if(', 'else', 'end', 'java ', '//', 'fh '
    )
    # iApp source uses fh shi/fou for boolean returns in menu hooks.
    if line == 'return true;':
        return 'fh shi'
    if line == 'return false;':
        return 'fh fou'
    if line == 'return;':
        return ''
    if line.startswith('return ') and line.endswith(';'):
        rv = line[len('return '):-1].strip()
        if rv == 'true':
            return 'fh shi'
        if rv == 'false':
            return 'fh fou'
        if advanced_analysis:
            return interpret_java_line_as_iapp('return ' + rv + ';')
        if looks_like_java_expr(rv):
            return 'java return ' + rv + ';'
        return 'fh ' + normalize_iapp_event_expr(rv)
    if advanced_analysis and (line.startswith('java ') or looks_like_java_expr(line)):
        return interpret_java_line_as_iapp(line)
    if line.startswith(('java ', '//', 'fh ')):
        return line
    expr = normalize_iapp_event_expr(line)
    if advanced_analysis and not expr.startswith(iapp_prefixes):
        return interpret_java_line_as_iapp(expr)
    if not expr.startswith(iapp_prefixes):
        if (
            expr.startswith(('if ', 'if(', 'new ', 'return ', 'throw '))
            or '=' in expr
            or '[' in expr
            or ';' in expr
            or re.search(r'\b[A-Za-z_$][\w$]*\.[A-Za-z_$][\w$]*', expr)
        ):
            return 'java ' + expr
    # Fully-qualified class calls are mixed Java source. iApp page helper calls
    # such as tw(...), uigo(...) remain plain iApp script lines.
    if looks_like_fqcn_call(expr):
        return 'java ' + expr
    expr = re.sub(r',\s+', ',', expr)
    return expr


def event_body_to_iapp(lines: List[str], advanced_analysis: bool = False) -> str:
    body = [event_line_to_iapp_source(x, advanced_analysis=advanced_analysis) for x in lines]
    body = [x for x in body if x]
    return lower_v6_event_body('\n'.join(body))


def has_mixed_java_source(events: OrderedDict, advanced_analysis: bool = False) -> bool:
    for lines in events.values():
        for line in lines:
            src = event_line_to_iapp_source(line, advanced_analysis=advanced_analysis)
            if src.startswith('java '):
                return True
    return False


def events_to_yu5src(events: OrderedDict, detected_package: Optional[str] = None, advanced_analysis: bool = False) -> str:
    """Render page events in the iApp V6 <_Yu5Src> format.

    In the real iApp V6 src directory, mian.iyu and mixed Java files are flat
    siblings, for example src/mian.iyu and src/IaptMain.java.  Event source is
    stored inside the root view under <_Yu5Src>, not as separate *.events files.
    """
    if not events:
        return ''
    out: List[str] = []
    out.append('<_Yu5Src>')
    if detected_package and has_mixed_java_source(events, advanced_analysis=advanced_analysis):
        out.append('<iClass><iClass><![CDATA[')
        out.append('// Java mixed source is recovered/written beside this .iyu file.')
        out.append(f'// Package: {detected_package}')
        out.append(']]></iClass></iClass>')

    preferred = ['loadingComplete', 'loading', 'createOptionsMenu', 'optionsItemSelected',
                 'keyDown', 'keyUp', 'destroy', 'stop', 'restart', 'start',
                 'resume', 'pause', 'activityResult', 'requestPermissionsResult']
    names = [n for n in preferred if n in events]
    names += [n for n in events.keys() if n not in names]

    for name in names:
        lines = events.get(name, [])
        body = event_body_to_iapp(lines, advanced_analysis=advanced_analysis)
        tag = 'on_' + name
        out.append(f'<{tag}><{tag}>')
        if name == 'loadingComplete' and not body:
            out.append('<![CDATA[\n]]>')
        elif name in ('createOptionsMenu', 'optionsItemSelected'):
            out.append(_v6_cdata(body))
        else:
            if body:
                out.append(_v6_cdata(body))
        out.append(f'</{tag}></{tag}>')
    out.append('</_Yu5Src>')
    return '\n'.join(out)


# Backwards-compatible name used by old callers.
def events_to_iyu_blocks(events: OrderedDict) -> str:
    return events_to_yu5src(events, None) + ('\n' if events else '')



JAVA_IAPTMAIN_TEMPLATE = 'package com.iapt.client;\n\n/*\n * Recovered from classes3.dex / source_file=IaptMain.java.\n * This is a readable reconstruction of the Java entry + crypto/network core.\n * Large UI/admin methods in IaptApp were present in dex but are left as stubs here;\n * the exact executable bytecode is still in classes3.dex.\n */\n\nimport android.app.Activity;\nimport android.content.SharedPreferences;\nimport android.util.Base64;\nimport java.io.*;\nimport java.net.HttpURLConnection;\nimport java.net.URL;\nimport java.security.MessageDigest;\nimport java.security.SecureRandom;\nimport java.util.Locale;\nimport javax.crypto.Cipher;\nimport javax.crypto.Mac;\nimport javax.crypto.spec.IvParameterSpec;\nimport javax.crypto.spec.SecretKeySpec;\nimport org.json.JSONObject;\n\npublic final class IaptMain {\n    public static void start(Activity activity) {\n        new IaptApp(activity).start();\n    }\n\n    public static class Enc {\n        public String data;\n        public String iv;\n    }\n\n    public static class AuthException extends Exception {\n        public AuthException(String msg) {\n            super(msg);\n        }\n    }\n\n    public static class Api {\n        String base;\n        String appId;\n        String secret;\n        SharedPreferences sp;\n        SecureRandom rnd = new SecureRandom();\n\n        public Api(String base, String appId, String secret, SharedPreferences sp) {\n            this.base = trimSlash(base);\n            this.appId = appId;\n            this.secret = secret;\n            this.sp = sp;\n        }\n\n        public static String trimSlash(String s) {\n            if (s == null) return "";\n            while (s.endsWith("/")) s = s.substring(0, s.length() - 1);\n            return s;\n        }\n\n        public String token() {\n            return sp == null ? "" : sp.getString("token", "");\n        }\n\n        public byte[] randomBytes(int n) {\n            byte[] b = new byte[n];\n            rnd.nextBytes(b);\n            return b;\n        }\n\n        public static byte[] sha256Bytes(byte[] in) throws Exception {\n            MessageDigest md = MessageDigest.getInstance("SHA-256");\n            return md.digest(in);\n        }\n\n        public static String sha256Hex(byte[] in) throws Exception {\n            return hex(sha256Bytes(in));\n        }\n\n        public static String hex(byte[] in) {\n            StringBuilder sb = new StringBuilder();\n            for (byte b : in) sb.append(String.format(Locale.US, "%02x", b & 0xff));\n            return sb.toString();\n        }\n\n        public Enc encrypt(String plainText, String salt) throws Exception {\n            byte[] iv = randomBytes(16);\n            byte[] keyBytes = sha256Bytes((secret + "|aes|" + salt).getBytes("UTF-8"));\n            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");\n            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");\n            cipher.init(Cipher.ENCRYPT_MODE, key, new IvParameterSpec(iv));\n            byte[] encBytes = cipher.doFinal(plainText.getBytes("UTF-8"));\n            Enc out = new Enc();\n            out.data = Base64.encodeToString(encBytes, Base64.NO_WRAP);\n            out.iv = Base64.encodeToString(iv, Base64.NO_WRAP);\n            return out;\n        }\n\n        public byte[] decryptZip(byte[] cipherBytes, String token, String taskId, String salt, String ts, String ivB64) throws Exception {\n            byte[] iv = Base64.decode(ivB64, Base64.NO_WRAP);\n            byte[] keyBytes = sha256Bytes((secret + "|zip|" + taskId + "|" + salt + "|" + ts + "|" + token).getBytes("UTF-8"));\n            SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");\n            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");\n            cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(iv));\n            return cipher.doFinal(cipherBytes);\n        }\n\n        public String sign(String method, String path, String timestamp, String nonce, String salt, String bodyHash, String token) throws Exception {\n            if (token == null) token = "";\n            String canonical = method.toUpperCase(Locale.US) + "\\n"\n                    + path + "\\n"\n                    + timestamp + "\\n"\n                    + nonce + "\\n"\n                    + salt + "\\n"\n                    + bodyHash + "\\n"\n                    + token;\n            Mac mac = Mac.getInstance("HmacSHA256");\n            mac.init(new SecretKeySpec(secret.getBytes("UTF-8"), "HmacSHA256"));\n            return Base64.encodeToString(mac.doFinal(canonical.getBytes("UTF-8")), Base64.NO_WRAP);\n        }\n\n        public JSONObject get(String path) throws Exception {\n            return request("GET", path, null, token());\n        }\n\n        public JSONObject getPublic(String path) throws Exception {\n            return request("GET", path, null, "");\n        }\n\n        public JSONObject post(String path, JSONObject body) throws Exception {\n            return request("POST", path, body, token());\n        }\n\n        public JSONObject post(String path, JSONObject body, String token) throws Exception {\n            return request("POST", path, body, token);\n        }\n\n        public JSONObject request(String method, String path, JSONObject body, String token) throws Exception {\n            // Reconstructed high-level flow from dex:\n            // 1. generate salt, nonce, timestamp\n            // 2. AES/CBC encrypt JSON body with key sha256(secret + "|aes|" + salt)\n            // 3. sign canonical request by HmacSHA256(secret)\n            // 4. send X-App-Id, X-Timestamp, X-Nonce, X-Salt, X-Body-Hash, X-Sign\n            // 5. parse JSON response, raising AuthException on 401\n            throw new UnsupportedOperationException("network request body omitted in reconstructed source; see dex for exact bytecode");\n        }\n\n        public File downloadTask(int taskId, File outDir, String name) throws Exception {\n            // Downloads a ZIP, checks x-zip-sha256, then if x-zip-mode starts with "aes-",\n            // decrypts through decryptZip(cipherBytes, token, taskId, salt, ts, iv).\n            throw new UnsupportedOperationException("downloadTask UI/network details omitted");\n        }\n    }\n\n    public static class IaptApp {\n        static final String API_BASE = "https://iapp.xbnb.help/api";\n        static final String APP_ID = "iapt-android";\n        static final String APP_SECRET = "<redacted: embedded in dex; pass it to the Python decrypt script manually>";\n        static final int APP_VERSION_CODE = 1;\n        static final String APP_VERSION_NAME = "1.0";\n\n        final Activity a;\n        final SharedPreferences sp;\n        final Api api;\n\n        public IaptApp(Activity activity) {\n            this.a = activity;\n            this.sp = activity.getSharedPreferences("iapt_client", 0);\n            this.api = new Api(API_BASE, APP_ID, APP_SECRET, sp);\n        }\n\n        public void start() {\n            requestPerms();\n            checkServerGateAndStart();\n        }\n\n        void requestPerms() {\n            requestRuntimeStoragePerms();\n            showAllFilesAccessDialog(false);\n        }\n\n        void checkServerGateAndStart() {\n            // Shows "正在连接服务器并检查软件状态...", then starts background server gate check.\n        }\n\n        void continueAfterGate() {\n            showLogin();\n            validateTokenAndEnter();\n        }\n\n        void validateTokenAndEnter() {\n            // Shows "正在验证登录状态...", then validates stored token and enters app.\n        }\n\n        void requestRuntimeStoragePerms() {}\n        void showAllFilesAccessDialog(boolean force) {}\n        void showLogin() {}\n    }\n}\n'


def extract_java_references(iyu_text: str) -> List[str]:
    refs: List[str] = []
    for m in re.finditer(r'\bjava\s+([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)+)\s*\(', iyu_text):
        q = m.group(1)
        parts = q.split('.')
        if len(parts) >= 3:
            refs.append('.'.join(parts[:-1]))
    return sorted(set(refs))



def find_executable(name: str) -> Optional[str]:
    """Small shutil.which wrapper kept separate for old Python compatibility."""
    return shutil.which(name)


def extract_apk_to_temp(input_path: str, tmpdir: str) -> str:
    """Write the real APK bytes to tmpdir and return its path.

    The input may be a normal APK or an iApp project ZIP that contains bin/*.apk.
    jadx must receive the APK itself, not the outer project ZIP.
    """
    apk_bytes = get_apk_bytes(input_path)
    out = os.path.join(tmpdir, 'input.apk')
    with open(out, 'wb') as f:
        f.write(apk_bytes)
    return out


def run_jadx(input_path: str, jadx_cmd: Optional[str] = None, keep_tmp: Optional[str] = None) -> Tuple[str, str]:
    """Run JADX and return (jadx_output_dir, temp_root).

    This is the only honest way this script can output *complete* Java: iApp UI
    recovery is done by the built-in dex parser, while Java bytecode is delegated
    to a real decompiler.  Without jadx, the script will not pretend that a stub
    is complete Java.
    """
    cmd = jadx_cmd or os.environ.get('JADX') or find_executable('jadx')
    if not cmd:
        raise RuntimeError(
            '完整还原 Java 需要 jadx。请先安装 jadx 并确保命令 jadx 在 PATH，'
            '或使用 --jadx /path/to/jadx 指定路径；如果只要 mian.iyu，可加 --no-java。'
        )
    tmp_root = keep_tmp or tempfile.mkdtemp(prefix='iapp_jadx_')
    apk_path = extract_apk_to_temp(input_path, tmp_root)
    out_dir = os.path.join(tmp_root, 'jadx_out')
    os.makedirs(out_dir, exist_ok=True)
    # --show-bad-code keeps partially recovered methods instead of dropping them.
    # --no-res speeds up Java-only recovery and avoids generating extra resource files.
    args = [cmd, '--show-bad-code', '--no-res', '-d', out_dir, apk_path]
    try:
        proc = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=int(os.environ.get('IAPT_JADX_TIMEOUT','180') or '180'))
    except FileNotFoundError:
        raise RuntimeError(f'找不到 jadx: {cmd}')
    except subprocess.TimeoutExpired:
        raise RuntimeError('jadx 反编译超时；可手动运行 jadx 后用 --jadx-out 指向输出目录。')
    if proc.returncode != 0:
        java_count = 0
        for _root, _dirs, files in os.walk(out_dir):
            java_count += sum(1 for fn in files if fn.endswith('.java'))
            if java_count:
                break
        tail = '\n'.join(line for line in proc.stdout.splitlines()[-40:] if 'ERROR' in line or 'WARN' in line or 'finished with errors' in line)
        if java_count:
            print('[警告] jadx 返回非 0，但已经生成 Java 源码；继续复制可用的 .java 文件。', file=sys.stderr)
            print('[警告] 少数类/方法可能是 JADX 反编译失败的坏代码，建议人工检查对应 Java。', file=sys.stderr)
            if tail:
                print('[诊断] jadx 关键输出：\n' + tail, file=sys.stderr)
        else:
            tail = '\n'.join(proc.stdout.splitlines()[-40:])
            raise RuntimeError('jadx 反编译失败，且没有生成任何 Java 文件：\n' + tail)
    return out_dir, tmp_root


def java_path_for_class(jadx_sources: str, class_name: str) -> Optional[str]:
    """Find a decompiled .java file for a fully-qualified class.

    class_name may point to an inner class.  In that case jadx normally writes the
    outer class file, so com.a.Outer$Inner resolves to com/a/Outer.java.
    """
    outer = class_name.split('$')[0]
    parts = outer.split('.')
    direct = os.path.join(jadx_sources, *parts) + '.java'
    if os.path.exists(direct):
        return direct
    # Some jadx versions sanitize or move files.  Fall back to basename search,
    # but still prefer files whose package declaration matches.
    base = parts[-1] + '.java'
    candidates = []
    for root, _, files in os.walk(jadx_sources):
        if base in files:
            candidates.append(os.path.join(root, base))
    if not candidates:
        return None
    pkg = '.'.join(parts[:-1])
    for c in candidates:
        try:
            head = open(c, 'r', encoding='utf-8', errors='replace').read(2048)
        except Exception:
            continue
        if re.search(r'\bpackage\s+' + re.escape(pkg) + r'\s*;', head):
            return c
    return candidates[0]


def collect_app_java_classes(jadx_sources: str, detected_package: Optional[str]) -> List[str]:
    """Collect all top-level Java classes from the app package in jadx output."""
    if not detected_package:
        return []
    base_dir = os.path.join(jadx_sources, *detected_package.split('.'))
    if not os.path.isdir(base_dir):
        return []
    out: List[str] = []
    for root, _, files in os.walk(base_dir):
        for fn in files:
            if not fn.endswith('.java'):
                continue
            p = os.path.join(root, fn)
            rel = os.path.relpath(p, jadx_sources)[:-5]
            out.append(rel.replace(os.sep, '.'))
    return sorted(set(out))


def copy_jadx_java_files(jadx_out: str, out_dir: str, refs: List[str], detected_package: Optional[str], java_layout: str = 'flat', all_java: bool = False) -> List[str]:
    """Copy decompiled Java files into iApp src layout.

    Default behavior copies only Java classes referenced by recovered .iyu events,
    e.g. `java com.iapt.client.IaptMain.start(activity);` -> src/IaptMain.java.
    With --all-java, every decompiled class under the APK package is copied.
    """
    sources = os.path.join(jadx_out, 'sources')
    if not os.path.isdir(sources):
        # Some jadx versions write sources directly into out_dir.
        sources = jadx_out
    classes = list(refs)
    if all_java:
        classes.extend(collect_app_java_classes(sources, detected_package))
    if detected_package:
        classes = [c for c in classes if c == detected_package or c.startswith(detected_package + '.')]
    classes = sorted(set(c.split('$')[0] for c in classes))
    written: List[str] = []
    missing: List[str] = []
    for cls_name in classes:
        src_path = java_path_for_class(sources, cls_name)
        if not src_path:
            missing.append(cls_name)
            continue
        if java_layout == 'package':
            dst = os.path.join(out_dir, 'src', *cls_name.split('.')) + '.java'
        else:
            dst = os.path.join(out_dir, 'src', cls_name.split('.')[-1] + '.java')
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        shutil.copyfile(src_path, dst)
        written.append(dst)
    if missing:
        print('[!] jadx 未找到这些 Java 类：' + ', '.join(missing), file=sys.stderr)
    return written


def write_referenced_java_files(out_dir: str, iyu_texts: List[str], detected_package: Optional[str], java_layout: str = "flat", input_path: Optional[str] = None, jadx_cmd: Optional[str] = None, jadx_out: Optional[str] = None, all_java: bool = False, require_full_java: bool = True) -> List[str]:
    refs: List[str] = []
    for t in iyu_texts:
        refs.extend(extract_java_references(t))
    refs = sorted(set(refs))
    if not refs and not all_java:
        return []

    if jadx_out:
        return copy_jadx_java_files(jadx_out, out_dir, refs, detected_package, java_layout=java_layout, all_java=all_java)

    if not input_path:
        if require_full_java:
            raise RuntimeError('缺少 input_path，无法调用 jadx 完整还原 Java')
        return []

    jadx_dir, tmp_root = run_jadx(input_path, jadx_cmd=jadx_cmd)
    try:
        return copy_jadx_java_files(jadx_dir, out_dir, refs, detected_package, java_layout=java_layout, all_java=all_java)
    finally:
        # Keep temp only when user supplied --jadx-out.  For normal runs clean it.
        shutil.rmtree(tmp_root, ignore_errors=True)


def _access_words(flags: int, method: bool = True) -> str:
    words: List[str] = []
    for bit, name in ((0x1, 'public'), (0x2, 'private'), (0x4, 'protected'), (0x8, 'static'),
                      (0x10, 'final'), (0x20, 'synchronized'), (0x100, 'native'),
                      (0x400, 'abstract'), (0x800, 'strictfp'), (0x1000, 'synthetic')):
        if flags & bit:
            words.append(name)
    return ' '.join(words)


def _safe_filename_component(name: str) -> str:
    return re.sub(r'[^A-Za-z0-9_$.-]+', '_', name) or 'class'


def _deep_line(line: str) -> str:
    x = _decode_float_boxing(line.strip())
    x = re.sub(r'\b0\.valueOf\(([^()]*)\)', r'\1', x)
    if x.startswith('// IAPT_SIDE_EFFECT '):
        return x[len('// IAPT_SIDE_EFFECT '):].rstrip(';') + ';  // 已确认副作用'
    if x.startswith('// IAPT_DISCARDED_CALL '):
        return x[len('// IAPT_DISCARDED_CALL '):].rstrip(';') + ';  // 返回值被丢弃'
    if x.startswith('// IAPT_MAYBE_CALL '):
        return x[len('// IAPT_MAYBE_CALL '):].rstrip(';') + ';  // 调用候选'
    if x.startswith('// IAPT高级分析未解释: '):
        return '// 静态未完全求值: ' + x.split(': ', 1)[1]
    return x


def _method_param_decls(proto: Proto) -> str:
    return ', '.join(f'{java_name(t)} {param_name(t, i)}' for i, t in enumerate(proto.params, 1))


def _deep_class_text(dex: Dex, cls: str, resolver: Any) -> Tuple[str, Dict[str, Any]]:
    cdef = dex.classes[cls]
    human = java_name(cls)
    package, _, simple = human.rpartition('.')
    superclass = java_name(cdef.super_cls) if cdef.super_cls else 'java.lang.Object'
    out: List[str] = []
    if package:
        out.append(f'package {package};')
        out.append('')
    out.append('/**')
    out.append(' * IAPT V6 深度静态恢复结果。')
    out.append(' * 这是可读伪 Java：已解析反射分发、常量和副作用；动态运行时部分保留注释。')
    out.append(' */')
    out.append(f'class {simple} extends {superclass} {{')
    static_idxs = set(dex.class_static_field_indices(cls))
    class_fields = [(i, f) for i, f in enumerate(dex.fields) if f.cls == cls]
    for idx, fr in class_fields:
        prefix = 'static ' if idx in static_idxs else ''
        out.append(f'    {prefix}{java_name(fr.typ)} {fr.name};')
    if class_fields:
        out.append('')

    method_total = 0
    method_ok = 0
    method_failed = 0
    line_total = 0
    unresolved = 0
    side_effects = 0
    old_ctx = globals().get('_ADVANCED_DEX_CONTEXT')
    old_resolver = globals().get('_PROTECTOR_RESOLVER_CONTEXT')
    globals()['_ADVANCED_DEX_CONTEXT'] = dex
    globals()['_PROTECTOR_RESOLVER_CONTEXT'] = resolver
    try:
        for em in dex.class_methods(cls):
            mr = dex.methods[em.method_idx]
            method_total += 1
            access = _access_words(em.access)
            params = _method_param_decls(mr.proto)
            if mr.name == '<init>':
                sig = f'{access} {simple}({params})'.strip()
            elif mr.name == '<clinit>':
                sig = 'static'
            else:
                sig = f'{access} {java_name(mr.proto.ret)} {mr.name}({params})'.strip()
            out.append(f'    {sig} {{')
            if not em.code_off:
                out.append('        // 无方法体（abstract/native）')
                out.append('    }')
                out.append('')
                continue
            try:
                lines = pseudo_event_method(dex, em, cls)
                method_ok += 1
                if not lines:
                    out.append('        // 空方法')
                for line in lines:
                    x = _deep_line(line)
                    line_total += 1
                    if '未完全' in x or '未解释' in x or 'LianYi.NB.' in x:
                        unresolved += 1
                    if '已确认副作用' in x:
                        side_effects += 1
                    for physical in x.splitlines() or ['']:
                        out.append('        ' + physical)
            except Exception as exc:
                method_failed += 1
                out.append(f'        // 反编译失败但已隔离，不影响其他方法: {type(exc).__name__}: {exc}')
            out.append('    }')
            out.append('')
    finally:
        globals()['_ADVANCED_DEX_CONTEXT'] = old_ctx
        globals()['_PROTECTOR_RESOLVER_CONTEXT'] = old_resolver
    out.append('}')
    return '\n'.join(out) + '\n', {
        'class': human,
        'methods_total': method_total,
        'methods_recovered': method_ok,
        'methods_failed': method_failed,
        'lines': line_total,
        'unresolved_lines': unresolved,
        'side_effect_lines': side_effects,
    }


def write_deep_code(out_dir: str, dexes: List[Tuple[str, Dex]], detected_package: Optional[str],
                    protector_resolvers: Dict[int, Any]) -> Tuple[List[str], Dict[str, Any]]:
    """Write every application class and inner class as resolved pseudo Java.

    This is intentionally independent of JADX, so a standalone DEX still gets a
    complete, non-crashing code dump.  Each method is isolated: one unsupported
    opcode becomes a comment and cannot abort the rest of the project.
    """
    root = os.path.join(out_dir, 'deep_code')
    os.makedirs(root, exist_ok=True)
    pkg_prefix = ''
    if detected_package:
        pkg_prefix = 'L' + detected_package.strip('.').replace('.', '/') + '/'
    classes: List[Tuple[str, Dex, str]] = []
    for dex_name, dx in dexes:
        for cls in sorted(dx.classes):
            if pkg_prefix and not cls.startswith(pkg_prefix):
                continue
            if not pkg_prefix and not cls.startswith('Lcom/'):
                continue
            if cls.endswith('/R;') or '/R$' in cls:
                continue
            classes.append((dex_name, dx, cls))
    written: List[str] = []
    reports: List[Dict[str, Any]] = []
    for dex_name, dx, cls in classes:
        resolver = protector_resolvers.get(id(dx))
        try:
            text, report = _deep_class_text(dx, cls, resolver)
        except Exception as exc:
            text = f'// 整类恢复失败但已隔离: {type(exc).__name__}: {exc}\n'
            report = {'class': java_name(cls), 'methods_total': 0, 'methods_recovered': 0,
                      'methods_failed': 1, 'lines': 0, 'unresolved_lines': 1, 'side_effect_lines': 0}
        report['dex'] = dex_name
        reports.append(report)
        rel = cls.strip('L;').replace('/', os.sep)
        path = os.path.join(root, rel + '.pseudo.java.txt')
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        written.append(path)

    summary = {
        'version': TOOL_VERSION,
        'package': detected_package,
        'classes': len(reports),
        'methods_total': sum(x['methods_total'] for x in reports),
        'methods_recovered': sum(x['methods_recovered'] for x in reports),
        'methods_failed': sum(x['methods_failed'] for x in reports),
        'lines': sum(x['lines'] for x in reports),
        'unresolved_lines': sum(x['unresolved_lines'] for x in reports),
        'side_effect_lines': sum(x['side_effect_lines'] for x in reports),
        'class_reports': reports,
    }
    report_path = os.path.join(root, 'recovery_report.json')
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)
    written.append(report_path)

    # Export the actual reflection/interpreter mapping recovered from the DEX.
    mappings: List[Dict[str, Any]] = []
    constants: List[Dict[str, Any]] = []
    for resolver in protector_resolvers.values():
        for (wrapper, code, arity), target in sorted(resolver._maps.items(), key=lambda x: (x[0][0], x[0][1], x[0][2])):
            if target is None:
                continue
            mappings.append({
                'wrapper': java_name(wrapper), 'code': code, 'arity': arity,
                'target_class': str(target.cls), 'target_name': str(target.name),
                'target_return': str(target.ret), 'target_params': [str(x) for x in target.params],
                'kind': target.kind, 'static': bool(target.is_static),
            })
        for (wrapper, code), value in sorted(getattr(resolver, '_constant_cache', {}).items(), key=lambda x: (x[0][0], x[0][1])):
            if isinstance(value, (str, int, bool)):
                constants.append({'wrapper': java_name(wrapper), 'code': code, 'value': value})
    map_path = os.path.join(root, 'interpreter_map.json')
    with open(map_path, 'w', encoding='utf-8') as f:
        json.dump({'targets': mappings, 'constants': constants}, f, ensure_ascii=False, indent=2)
    written.append(map_path)
    summary['interpreter_targets'] = len(mappings)
    summary['constant_values'] = len(constants)

    # Rewrite the report after interpreter statistics are known.  Earlier
    # versions wrote it too early, so the on-disk JSON omitted these metrics.
    with open(report_path, 'w', encoding='utf-8') as f:
        json.dump(summary, f, ensure_ascii=False, indent=2)

    # Human-readable index: page name -> top-level class and all generated
    # inner classes.  This is especially useful for thread/callback bodies that
    # cannot be emitted safely as executable iApp source.
    by_top: Dict[str, List[str]] = OrderedDict()
    for row in reports:
        full = str(row.get('class') or '')
        simple_name = full.rsplit('.', 1)[-1]
        top = simple_name.split('$', 1)[0]
        by_top.setdefault(top, []).append(full)
    index_lines = [
        '# IAPT V6 深度恢复索引', '',
        f'- 包名：`{detected_package or "未识别"}`',
        f'- 类：{summary["classes"]}',
        f'- 方法：{summary["methods_recovered"]}/{summary["methods_total"]}',
        f'- 方法级隔离失败：{summary["methods_failed"]}',
        f'- 解释器映射：{summary["interpreter_targets"]}',
        f'- 静态常量：{summary["constant_values"]}', '',
        '## 页面/模块与深度代码', '',
    ]
    for top, names in by_top.items():
        page = os.path.join(out_dir, 'src', top + '.iyu')
        marker = '页面' if os.path.isfile(page) else '模块/类'
        index_lines.append(f'### {top}（{marker}）')
        for full in names:
            rel = full.replace('.', '/') + '.pseudo.java.txt'
            index_lines.append(f'- `{rel}`')
        index_lines.append('')
    index_path = os.path.join(root, 'INDEX.md')
    with open(index_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(index_lines).rstrip() + '\n')
    written.append(index_path)
    return written, summary


def validate_recovered_iyu(out_dir: str) -> Dict[str, Any]:
    """Parse every recovered .iyu as XML and flag unsafe executable fragments.

    XML parsing catches malformed event text/UI hierarchy.  The second pass
    inspects decoded text nodes (rather than raw XML entities) and rejects only
    executable leftovers; diagnostic comments remain allowed.
    """
    files = sorted(Path(os.path.join(out_dir, 'src')).glob('*.iyu')) if os.path.isdir(os.path.join(out_dir, 'src')) else []
    result: Dict[str, Any] = {
        'files': len(files), 'xml_ok': 0, 'xml_failed': [], 'unsafe_lines': [],
        'event_nodes': 0, 'nonempty_event_nodes': 0, 'brace_errors': [],
    }
    temp_re = re.compile(r'\bv\d+_(?:arr|obj|len)_\d+\b')

    def inspect_text(file_name: str, text: str, line_base: int = 1) -> None:
        for idx, line in enumerate((text or '').splitlines(), line_base):
            st = line.strip()
            if not st or st.startswith('//'):
                continue
            unsafe = (
                'IAPT_SIDE_EFFECT' in st
                or 'IAPT_DISCARDED_CALL' in st
                or 'IAPT_MAYBE_CALL' in st
                or 'sss()).' in st
                or 'ss()).' in st
                or st.startswith('java if ')
                or 'LianYi.NB.' in st
                or st in {'t(0)', 'ufnsui(0)'}
                or st.startswith('s(null,')
                or 'startAnimation",null' in st
                or bool(temp_re.search(st))
            )
            if unsafe:
                result['unsafe_lines'].append({'file': file_name, 'line': idx, 'text': st[:240]})

    for path in files:
        text = path.read_text(encoding='utf-8', errors='replace')
        try:
            root = ET.fromstring(text)
            result['xml_ok'] += 1
            # ElementTree has decoded &lt;/&gt;/&amp; at this point, so inspect
            # only event/source text nodes and avoid treating XML tags as code.
            for elem in root.iter():
                if elem.text:
                    inspect_text(path.name, elem.text)
                if elem.tail:
                    inspect_text(path.name, elem.tail)
                # Count leaf event nodes only; V6 stores lifecycle tags as a
                # same-name wrapper pair (<on_loading><on_loading>...).
                tag = str(elem.tag)
                is_event = bool(re.match(r'^(?:on_|on[A-Z]|before[A-Z]|after[A-Z]|should[A-Z])', tag))
                if is_event and not any(str(ch.tag) == tag for ch in list(elem)):
                    result['event_nodes'] += 1
                    body = ''.join(elem.itertext()).strip()
                    if body:
                        result['nonempty_event_nodes'] += 1
                    balance = 0
                    bad = False
                    for raw in body.splitlines():
                        code = raw.strip()
                        if not code or code.startswith('//'):
                            continue
                        balance += code.count('{') - code.count('}')
                        if balance < 0:
                            bad = True
                            break
                    if bad or balance != 0:
                        result['brace_errors'].append({'file': path.name, 'event': tag, 'balance': balance})
        except Exception as exc:
            result['xml_failed'].append({'file': path.name, 'error': f'{type(exc).__name__}: {exc}'})
    result['ok'] = (
        not result['xml_failed']
        and not result['unsafe_lines']
        and not result['brace_errors']
        and result['event_nodes'] == result['nonempty_event_nodes']
    )
    path = os.path.join(out_dir, 'deep_code', 'iyu_validation.json')
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(result, f, ensure_ascii=False, indent=2)
    result['report_path'] = path
    return result


def recover(input_path: str, out_dir: str, package_filter: Optional[str] = None, verbose: bool = False, debug_events: bool = False, dump_java: bool = True, java_layout: str = "flat", jadx_cmd: Optional[str] = None, jadx_out: Optional[str] = None, all_java: bool = False, advanced_analysis: bool = False, protector_analysis: bool = True, deep_code: bool = True) -> List[str]:
    _V6_EVENT_RECOVERY_REPORTS.clear()
    _PSEUDO_METHOD_CACHE.clear()
    _SXCL_TABLE_CACHE.clear()
    apk_bytes = get_apk_bytes(input_path)
    dex_blobs = get_all_classes_dexes_from_apk_bytes(apk_bytes)
    if not dex_blobs:
        raise UserFacingError('[错误] APK 内没有找到 classes*.dex。\n[建议] 请确认输入的是未损坏的 APK，或工程 ZIP 中包含 bin/*.apk。')
    dexes = [(name, Dex(data)) for name, data in dex_blobs]
    protector_resolvers: Dict[int, Any] = {}
    if protector_analysis:
        try:
            try:
                from .iapp_v6_protector import ProtectorResolver
            except Exception:
                from iapp_v6_protector import ProtectorResolver
            for _, _dx in dexes:
                if any(c.startswith('LLianYi/NB/') for c in _dx.classes):
                    protector_resolvers[id(_dx)] = ProtectorResolver(_dx)
        except Exception as exc:
            if verbose:
                print(f'[V6保护器] 初始化失败，继续使用保守反编译: {type(exc).__name__}: {exc}', file=sys.stderr)

    detected_package = package_filter or get_package_name_from_apk_bytes(apk_bytes)
    if not detected_package:
        for _, dx in dexes:
            detected_package = auto_package_from_dex(dx)
            if detected_package:
                break

    found: List[Tuple[str, Dex, str]] = []
    for dex_name, dx in dexes:
        classes = candidate_user_classes(dx, detected_package)
        if not classes and detected_package:
            classes = candidate_user_classes(dx, None)
        for cls in classes:
            # Prefer real app package when available; this avoids dumping runtime base classes from classes2.dex.
            if detected_package:
                pkg = detected_package.strip('.').replace('.', '/')
                if cls.startswith('L' + pkg + '/'):
                    found.append((dex_name, dx, cls))
                elif not any(x[2].startswith('L' + pkg + '/') for x in found):
                    found.append((dex_name, dx, cls))
            else:
                found.append((dex_name, dx, cls))

    # If we collected runtime fallback and later found real package classes, discard fallback.
    if detected_package:
        pkg = detected_package.strip('.').replace('.', '/')
        real = [x for x in found if x[2].startswith('L' + pkg + '/')]
        if real:
            found = real

    if not found:
        raise UserFacingError('[错误] 没有在 classes*.dex 里找到 iApp UI 页面类。\n[诊断] 已扫描所有 classes*.dex，但没找到 on_$_viewAutomaticSettingEvent。\n[建议] 确认这是 iApp V6 编译出的 APK；或者尝试不指定 -p，让脚本自动识别包名。')
    if detected_package:
        print(f'[+] package: {detected_package}')

    os.makedirs(os.path.join(out_dir, 'src'), exist_ok=True)
    written: List[str] = []
    iyu_texts: List[str] = []

    myu_found: List[Tuple[str, Dex, str]] = []
    for dex_name, dx in dexes:
        myu_classes = candidate_myu_classes(dx, detected_package)
        if not myu_classes and detected_package:
            myu_classes = candidate_myu_classes(dx, None)
        for cls in myu_classes:
            myu_found.append((dex_name, dx, cls))
    if detected_package:
        pkg = detected_package.strip('.').replace('.', '/')
        real_myu = [x for x in myu_found if x[2].startswith('L' + pkg + '/')]
        if real_myu:
            myu_found = real_myu

    for dex_name, dx, cls in found:
        target_method = None
        for em in dx.class_methods(cls):
            if dx.methods[em.method_idx].name == 'on_$_viewAutomaticSettingEvent':
                target_method = em
                break
        if not target_method or not target_method.code_off:
            continue
        resolver = protector_resolvers.get(id(dx))
        root = None
        if resolver is not None:
            try:
                root = recover_protected_ui(dx, target_method, cls, resolver, verbose=verbose)
            except Exception as exc:
                if verbose:
                    print(f'[V6 UI] 保护器UI恢复失败，回退直接解析 {cls}: {type(exc).__name__}: {exc}', file=sys.stderr)
        if root is None:
            root = recover_method(dx, target_method, cls, verbose=verbose)
        if not root:
            continue
        global _ADVANCED_DEX_CONTEXT, _PROTECTOR_RESOLVER_CONTEXT
        old_ctx = _ADVANCED_DEX_CONTEXT
        old_resolver = _PROTECTOR_RESOLVER_CONTEXT
        _ADVANCED_DEX_CONTEXT = dx if advanced_analysis else None
        _PROTECTOR_RESOLVER_CONTEXT = resolver
        try:
            control_events = recover_control_events_for_class(dx, cls)
            attach_control_events(root, control_events)
            events = recover_events_for_class(dx, cls)
            xml = render_iyu_document(root, events, detected_package, advanced_analysis=advanced_analysis)
        finally:
            _ADVANCED_DEX_CONTEXT = old_ctx
            _PROTECTOR_RESOLVER_CONTEXT = old_resolver
        name = descriptor_to_name(cls)
        path = os.path.join(out_dir, 'src', f'{name}.iyu')
        with open(path, 'w', encoding='utf-8') as f:
            f.write(xml)
        written.append(path)
        iyu_texts.append(xml)

        if debug_events and events:
            ev_path = os.path.join(out_dir, 'src', f'{name}.events.txt')
            with open(ev_path, 'w', encoding='utf-8') as f:
                f.write(events_to_text(events))
            written.append(ev_path)

    for dex_name, dx, cls in myu_found:
        name = descriptor_to_name(cls)
        # Avoid overwriting a page with the same basename; .myu and .iyu are separate sources.
        path = os.path.join(out_dir, 'src', f'{name}.myu')
        text = recover_myu_document(dx, cls)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(text)
        written.append(path)
        if text.strip():
            if verbose:
                print(f'[+] myu: {name}.myu recovered with body from {dex_name}')
        else:
            print(
                f'[警告] {name}.myu 对应 dex 类 {cls} 只有默认模块结构，未发现可恢复的用户指令；已输出空文件。\n'
                f'[诊断] 如果原始 {name}.myu 是 tw(11)，这段顶层代码没有作为 tw 调用保留在当前 APK 的 dex 里，脚本不能凭空还原。',
                file=sys.stderr
            )
            if verbose:
                print(f'[+] myu: {name}.myu appears default/no recoverable body in {dex_name}')

    # V33 exact-target source overlay: extracted project directories only.
    try:
        try:
            from .v6_target_postprocess_v33 import apply_target_postprocess
        except ImportError:
            from v6_target_postprocess_v33 import apply_target_postprocess
        _v33_report = apply_target_postprocess(input_path, out_dir, detected_package)
        if _v33_report.get('applied'):
            written.extend(_v33_report.get('copied', []))
            iyu_texts = [p.read_text(encoding='utf-8') for p in sorted(Path(out_dir, 'src').glob('*.iyu'))]
            print('[V33目标修复] 已输出基于DEX恢复的目录版ProjectTools/V3SrcConfused：' + str(len(_v33_report.get('copied', []))) + ' 个文件，Java源码 ' + str(len(_v33_report.get('java_sources', []))) + '，class ' + str(len(_v33_report.get('class_files', []))))
    except Exception as _v33_exc:
        print('[V33目标修复警告] ' + type(_v33_exc).__name__ + ': ' + str(_v33_exc), file=sys.stderr)

    deep_summary: Dict[str, Any] = {}
    if deep_code:
        deep_written, deep_summary = write_deep_code(out_dir, dexes, detected_package, protector_resolvers)
        written.extend(deep_written)
        validation = validate_recovered_iyu(out_dir)
        written.append(validation['report_path'])
        readme_path = os.path.join(out_dir, '恢复说明.txt')
        with open(readme_path, 'w', encoding='utf-8') as f:
            f.write(
                'IAPT V6 深度静态恢复结果\n'
                '========================\n'
                f'工具版本：{TOOL_VERSION}\n'
                f'包名：{detected_package or "未识别"}\n'
                f'UI 页面：{validation.get("xml_ok", 0)}/{validation.get("files", 0)} 已通过 XML/脚本安全校验\n'
                f'类：{deep_summary.get("classes", 0)}\n'
                f'方法：{deep_summary.get("methods_recovered", 0)}/{deep_summary.get("methods_total", 0)}\n'
                f'方法隔离失败：{deep_summary.get("methods_failed", 0)}\n'
                f'解释器映射：{deep_summary.get("interpreter_targets", 0)}\n'
                f'静态常量：{deep_summary.get("constant_values", 0)}\n\n'
                '目录说明：\n'
                '  src/       可导入/查看的 .iyu/.myu UI 与事件源码。\n'
                '  deep_code/ 全部应用类、内部线程、回调和运行时逻辑的可读伪 Java。\n'
                '  deep_code/INDEX.md 可按页面定位内部类。\n'
                '  deep_code/iyu_validation.json 是 UI/脚本安全校验报告。\n\n'
                '说明：动态网络响应、运行时反射结果、native 返回值或动态加载内容无法仅从静态 DEX 唯一确定。\n'
                '这些部分不会伪造为可执行代码，而会在 deep_code 中保留调用链和注释，避免生成的 .iyu 因错误语法而无法解析。\n'
            )
        written.append(readme_path)
        if verbose or not validation.get('ok'):
            print(f"[V6校验] UI XML {validation.get('xml_ok', 0)}/{validation.get('files', 0)}，不安全可执行行 {len(validation.get('unsafe_lines', []))}", file=sys.stderr)
        print('[V6深度恢复] 类 {classes}，方法 {methods_recovered}/{methods_total}，隔离失败 {methods_failed}，解释器映射 {interpreter_targets}，常量 {constant_values}'.format(**deep_summary))

    if dump_java:
        written.extend(write_referenced_java_files(
            out_dir,
            iyu_texts,
            detected_package,
            java_layout=java_layout,
            input_path=input_path,
            jadx_cmd=jadx_cmd,
            jadx_out=jadx_out,
            all_java=all_java,
            require_full_java=True,
        ))
    if protector_resolvers:
        merged = {'calls_seen': 0, 'calls_resolved': 0, 'strings_decrypted': 0, 'targets_recovered': 0}
        for resolver in protector_resolvers.values():
            for k in merged:
                merged[k] += int(resolver.stats.get(k, 0) or 0)
        print('[V6保护器] 分发调用 {calls_seen}，已解析 {calls_resolved}，静态字符串 {strings_decrypted}，目标映射 {targets_recovered}'.format(**merged))
    if deep_code and _V6_EVENT_RECOVERY_REPORTS:
        event_report_path = os.path.join(out_dir, 'deep_code', 'v6_event_recovery.json')
        os.makedirs(os.path.dirname(event_report_path), exist_ok=True)
        with open(event_report_path, 'w', encoding='utf-8') as f:
            json.dump({
                'tool_version': TOOL_VERSION,
                'methods': _V6_EVENT_RECOVERY_REPORTS,
                'methods_total': len(_V6_EVENT_RECOVERY_REPORTS),
                'methods_with_concrete_source': sum(1 for x in _V6_EVENT_RECOVERY_REPORTS if x.get('ok')),
                'concrete_lines': sum(int(x.get('line_count') or 0) for x in _V6_EVENT_RECOVERY_REPORTS),
            }, f, ensure_ascii=False, indent=2)
        written.append(event_report_path)

    return written



def flatten_src_contents_to_output_root(out_dir: str, written: List[str]) -> List[str]:
    """Move the contents of out_dir/src into out_dir and remove src itself.

    Relative subdirectories below src are preserved (for example,
    src/recovered/helpers/A.java becomes recovered/helpers/A.java).  Existing
    non-identical files are rejected instead of being overwritten silently.
    """
    root = Path(out_dir)
    src_root = root / 'src'
    if not src_root.is_dir():
        return list(written or [])
    mapped: Dict[str, str] = {}
    new_written: List[str] = []
    for source in sorted(src_root.rglob('*')):
        if not source.is_file():
            continue
        rel = source.relative_to(src_root)
        target = root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            try:
                same = target.is_file() and source.read_bytes() == target.read_bytes()
            except Exception:
                same = False
            if not same:
                raise UserFacingError('[错误] src 内容移到输出根目录时发生同名冲突：' + rel.as_posix())
            source.unlink()
        else:
            shutil.move(str(source), str(target))
        mapped[str(source)] = str(target)
        new_written.append(str(target))
    shutil.rmtree(src_root, ignore_errors=True)
    for item in written or []:
        item_s = str(item)
        try:
            item_p = Path(item_s)
            item_p.relative_to(src_root)
            if item_s in mapped:
                continue
            rel = item_p.relative_to(src_root)
            candidate = root / rel
            if candidate.is_file():
                continue
        except Exception:
            pass
        if item_s not in mapped and Path(item_s).is_file():
            new_written.append(item_s)
    return sorted(dict.fromkeys(new_written))

def main() -> None:
    ap = argparse.ArgumentParser(description='iApp V6 静态解密源码恢复')
    ap.add_argument('--version', action='version', version=f'%(prog)s {TOOL_VERSION}')
    ap.add_argument('--apk', dest='apk', default=None, help='APK 或 iApp 工程 ZIP')
    ap.add_argument('input', nargs='?', help='APK 或 iApp 工程 ZIP')
    ap.add_argument('--outdir', '-o', '--out', dest='out', default='recovered_iapp', help='输出目录')
    ap.add_argument('-p', '--package', default=None, help='包名过滤，留空自动识别')
    ap.add_argument('-v', '--verbose', action='store_true')
    ap.add_argument('--debug-events', action='store_true', help='输出事件调试文件')
    ap.add_argument('--no-java', action='store_true', help='只恢复 .iyu/.myu，不输出 Java')
    ap.add_argument('--no-deep-code', action='store_true', help='不输出内置深度伪 Java/解释器映射（默认输出）')
    ap.add_argument('--flat-src-root', action='store_true', help='将 src/ 内部内容移到输出根目录并删除 src/ 文件夹')
    ap.add_argument('--java-layout', choices=('flat', 'package'), default='flat', help='Java 输出布局')
    ap.add_argument('--jadx', default=None, help='jadx 路径')
    ap.add_argument('--jadx-out', default=None, help='复用已有 jadx 输出目录')
    ap.add_argument('--all-java', action='store_true', help='复制包名下所有 Java 类')
    ap.add_argument('--advanced-analysis', '--analyze-interpreter', action='store_true', help='高级分析解释层：尽量把保护器事件还原为 iApp 语句，未知语义不输出假 fh/java')
    ap.add_argument('--protector-analysis', dest='protector_analysis', action='store_true', default=True, help='解析 LianYi/NB 反射分发表并静态解密常量（默认开启）')
    ap.add_argument('--no-protector-analysis', dest='protector_analysis', action='store_false', help='关闭保护器静态解析')
    ap.add_argument('--traceback', action='store_true', help='显示完整异常')
    args = ap.parse_args()
    input_path = args.apk or args.input
    if not input_path:
        ap.error('missing --apk')

    started_at = time.time()
    marker_dir = Path(args.out) / '.tmp'
    marker_path = marker_dir / 'v6_complete.json'
    try:
        marker_path.unlink(missing_ok=True)
    except Exception:
        pass
    try:
        written = recover(
            input_path,
            args.out,
            args.package,
            args.verbose,
            args.debug_events,
            dump_java=not args.no_java,
            java_layout=args.java_layout,
            jadx_cmd=args.jadx,
            jadx_out=args.jadx_out,
            all_java=args.all_java,
            advanced_analysis=args.advanced_analysis,
            protector_analysis=args.protector_analysis,
            deep_code=not args.no_deep_code,
        )
        if args.flat_src_root:
            written = flatten_src_contents_to_output_root(args.out, written)
        # Atomic completion marker: the worker may finalize the task even if a
        # library leaves a non-daemon child or inherited stdout fd alive.
        try:
            marker_dir.mkdir(parents=True, exist_ok=True)
            payload = {
                'ok': True, 'tool_version': TOOL_VERSION,
                'elapsed_ms': int((time.time() - started_at) * 1000),
                'file_count': len(written), 'finished_at': int(time.time()),
            }
            tmp_marker = marker_path.with_suffix('.tmp')
            tmp_marker.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
            os.replace(tmp_marker, marker_path)
        except Exception as marker_exc:
            print(f'[警告] 无法写入完成标记: {marker_exc}', file=sys.stderr)
        for p in written:
            print(p)
    except UserFacingError as e:
        print(str(e), file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('[中断] 用户取消。', file=sys.stderr)
        sys.exit(130)
    except Exception as e:
        if args.traceback or args.verbose:
            raise
        print(f'[错误] 处理失败，但已隐藏 Python traceback。版本：{TOOL_VERSION}', file=sys.stderr)
        print(f'[原因] {type(e).__name__}: {e}', file=sys.stderr)
        print('[建议] 加 --traceback 查看完整异常，或把 APK/ZIP 和这段诊断发给我。', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
