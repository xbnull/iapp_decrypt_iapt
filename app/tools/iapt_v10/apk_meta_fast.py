#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Small Android binary XML/resources parser used by the ancient engine.

Kept dependency-free so an old-project task does not import the much larger
V3 decryptor merely to read four APK metadata strings.
"""
from __future__ import annotations
import struct
import zipfile
from pathlib import Path
from typing import Dict, List, Optional, Tuple

def parse_axml_manifest(axml: bytes) -> Dict[str, str]:
    def u16(off: int) -> int:
        return struct.unpack_from("<H", axml, off)[0]
    def u32(off: int) -> int:
        return struct.unpack_from("<I", axml, off)[0]
    def read_len8(p: int) -> Tuple[int, int]:
        b = axml[p]
        if b & 0x80:
            return ((b & 0x7F) << 8) | axml[p + 1], 2
        return b, 1
    def read_len16(p: int) -> Tuple[int, int]:
        x = u16(p)
        if x & 0x8000:
            return ((x & 0x7FFF) << 16) | u16(p + 2), 4
        return x, 2
    if len(axml) < 16:
        raise ValueError("bad axml")
    off = 8
    ctype, hsize, csize = struct.unpack_from("<HHI", axml, off)
    if ctype != 0x0001:
        raise ValueError("string pool not found")
    string_count, style_count, flags, strings_start, styles_start = struct.unpack_from("<IIIII", axml, off + 8)
    utf8 = bool(flags & 0x100)
    offsets = [u32(off + hsize + i * 4) for i in range(string_count)]
    base = off + strings_start
    strings: List[str] = []
    for string_offset in offsets:
        p = base + string_offset
        if utf8:
            _, n1 = read_len8(p)
            l2, n2 = read_len8(p + n1)
            raw = axml[p + n1 + n2:p + n1 + n2 + l2]
            s = raw.decode("utf-8", "replace")
        else:
            l, n = read_len16(p)
            raw = axml[p + n:p + n + l * 2]
            s = raw.decode("utf-16le", "replace")
        strings.append(s)
    def sx(i: int) -> str:
        if i == 0xFFFFFFFF:
            return ""
        return strings[i] if 0 <= i < len(strings) else ""
    def attr_value(dtype: int, data: int, raw: int) -> str:
        if raw != 0xFFFFFFFF:
            return sx(raw)
        if dtype == 0x03:
            return sx(data)
        if dtype == 0x04:
            value = struct.unpack("<f", struct.pack("<I", data & 0xFFFFFFFF))[0]
            text = format(value, ".8g")
            if value.is_integer() and "e" not in text.lower() and "." not in text:
                text += ".0"
            return text
        if dtype == 0x10:
            return str(data if data < 0x80000000 else data - 0x100000000)
        if dtype == 0x11:
            return str(data)
        if dtype == 0x12:
            return "true" if data else "false"
        if dtype == 0x01:
            return f"@{data:08x}"
        return str(data)
    result: Dict[str, str] = {}
    pos = off + csize
    while pos + 8 <= len(axml):
        typ, head, size = struct.unpack_from("<HHI", axml, pos)
        if size <= 0:
            break
        if typ == 0x0102:
            ns, name, attr_start, attr_size, attr_count, id_idx, cls_idx, style_idx = struct.unpack_from("<IIHHHHHH", axml, pos + 16)
            tag = sx(name)
            attr_off = pos + 16 + attr_start
            attrs: Dict[str, str] = {}
            for i in range(attr_count):
                ns_i, name_i, raw, value_size, zero, dtype, data = struct.unpack_from("<IIIHBBI", axml, attr_off + i * attr_size)
                attrs[sx(name_i)] = attr_value(dtype, data, raw)
            if tag == "manifest":
                for k in ("package", "versionName", "versionCode"):
                    if k in attrs:
                        result[k] = attrs[k]
            elif tag == "application" and "label" in attrs:
                result["appLabel"] = attrs["label"]
        pos += size
    return result



def _arsc_u16(blob: bytes, off: int) -> int:
    return struct.unpack_from("<H", blob, off)[0]


def _arsc_u32(blob: bytes, off: int) -> int:
    return struct.unpack_from("<I", blob, off)[0]


def _arsc_read_len8(blob: bytes, p: int) -> Tuple[int, int]:
    b = blob[p]
    if b & 0x80:
        return ((b & 0x7F) << 8) | blob[p + 1], 2
    return b, 1


def _arsc_read_len16(blob: bytes, p: int) -> Tuple[int, int]:
    x = struct.unpack_from("<H", blob, p)[0]
    if x & 0x8000:
        return ((x & 0x7FFF) << 16) | struct.unpack_from("<H", blob, p + 2)[0], 4
    return x, 2


def _arsc_parse_string_pool(blob: bytes, off: int) -> Tuple[List[str], int]:
    if off + 28 > len(blob):
        raise ValueError("bad resources.arsc string pool offset")
    typ = _arsc_u16(blob, off)
    hsize = _arsc_u16(blob, off + 2)
    size = _arsc_u32(blob, off + 4)
    if typ != 0x0001 or size <= 0 or off + size > len(blob):
        raise ValueError("bad resources.arsc string pool chunk")
    string_count = _arsc_u32(blob, off + 8)
    flags = _arsc_u32(blob, off + 16)
    strings_start = _arsc_u32(blob, off + 20)
    utf8 = bool(flags & 0x100)
    offsets = [_arsc_u32(blob, off + hsize + i * 4) for i in range(string_count)]
    base = off + strings_start
    out: List[str] = []
    for so in offsets:
        p = base + so
        if not (0 <= p < len(blob)):
            out.append("")
            continue
        try:
            if utf8:
                _, n1 = _arsc_read_len8(blob, p)
                l2, n2 = _arsc_read_len8(blob, p + n1)
                raw = blob[p + n1 + n2:p + n1 + n2 + l2]
                out.append(raw.decode("utf-8", "replace"))
            else:
                l, n = _arsc_read_len16(blob, p)
                raw = blob[p + n:p + n + l * 2]
                out.append(raw.decode("utf-16le", "replace"))
        except Exception:
            out.append("")
    return out, size


def resolve_arsc_string_ref(arsc: bytes, ref: str) -> Optional[str]:
    """Resolve simple @7fTTEEEE string resource references from resources.arsc.

    This intentionally implements the small subset needed for iApp labels: global
    string pool + package key/type pools + simple string entries.  It is safe to
    fail closed and return None when the resource table uses a shape we do not
    understand.
    """
    ref = str(ref or "").strip()
    if not ref.startswith("@"):
        return None
    try:
        rid = int(ref[1:], 16)
    except Exception:
        return None
    pkg_id = (rid >> 24) & 0xFF
    type_id = (rid >> 16) & 0xFF
    entry_id = rid & 0xFFFF
    if len(arsc) < 12 or _arsc_u16(arsc, 0) != 0x0002:
        return None
    off = 12
    try:
        global_strings, sp_size = _arsc_parse_string_pool(arsc, off)
    except Exception:
        return None
    off += sp_size
    while off + 8 <= len(arsc):
        ctyp = _arsc_u16(arsc, off)
        hsize = _arsc_u16(arsc, off + 2)
        size = _arsc_u32(arsc, off + 4)
        if size <= 0 or off + size > len(arsc):
            break
        if ctyp != 0x0200:
            off += size
            continue
        try:
            cur_pkg_id = _arsc_u32(arsc, off + 8)
            if pkg_id and cur_pkg_id != pkg_id:
                off += size
                continue
        except Exception:
            off += size
            continue
        p = off + hsize
        while p + 20 <= off + size:
            try:
                ttyp = _arsc_u16(arsc, p)
                thsize = _arsc_u16(arsc, p + 2)
                tsize = _arsc_u32(arsc, p + 4)
            except Exception:
                break
            if tsize <= 0 or p + tsize > off + size:
                break
            if ttyp == 0x0201:
                tid = arsc[p + 8]
                entry_count = _arsc_u32(arsc, p + 12)
                entries_start = _arsc_u32(arsc, p + 16)
                if tid == type_id and entry_id < entry_count:
                    ent_off_pos = p + thsize + entry_id * 4
                    if ent_off_pos + 4 <= len(arsc):
                        ent_off = _arsc_u32(arsc, ent_off_pos)
                        if ent_off != 0xFFFFFFFF:
                            ep = p + entries_start + ent_off
                            if ep + 16 <= len(arsc):
                                flags = _arsc_u16(arsc, ep + 2)
                                if not (flags & 0x0001):
                                    dtype = arsc[ep + 11]
                                    data = _arsc_u32(arsc, ep + 12)
                                    if dtype == 0x03 and data < len(global_strings):
                                        return global_strings[data]
                                    if dtype in (0x10, 0x11):
                                        return str(data if data < 0x80000000 else data - 0x100000000)
            p += tsize
        off += size
    return None



def read_apk_meta(apk_path: Path | str) -> Dict[str, str]:
    apk_path = Path(apk_path)
    with zipfile.ZipFile(apk_path, "r") as zf:
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            raise ValueError("APK misses AndroidManifest.xml")
        params = parse_axml_manifest(zf.read("AndroidManifest.xml")) or {}
        label = params.get("appLabel")
        if label and str(label).startswith("@") and "resources.arsc" in names:
            try:
                label = resolve_arsc_string_ref(zf.read("resources.arsc"), str(label)) or label
            except Exception:
                pass
        return {
            "package_name": str(params.get("package") or ""),
            "version_name": str(params.get("versionName") or ""),
            "version_code": str(params.get("versionCode") or ""),
            "app_name": str(label or ""),
        }
