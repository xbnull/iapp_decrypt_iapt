#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static OnDev v3 + EPIC + iApp resource-layer normalizer.

This handler is deliberately narrow and fail-closed. It never loads APK code or
native libraries. For the supported layout it performs, in order:

1. statically unwrap OnDev OKDF v0x10 and validate the ODEX members;
2. read and RC4-decrypt the ``.ArmEpic`` section from ``libEPIC.so``;
3. use EPIC's JSON configuration for ordinary asset restoration; and
4. recover the hidden iApp container filename and byte transform from the
   original DEX helper ``b(String, Context): byte[]``.

The final step is important: the source container passes through EPIC's global
asset restoration first, then through the DEX helper's own byte transform.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import tempfile
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

BUILD = "ondev-v3-epic-static-v3"
_SIGNATURE_MARKER = b"<signature>1</signature>"
_FIXED_CERT_V10 = bytes.fromhex(
    "69ec6cf599f8e3688f3c6ab8b8ad9818f5d14a0d4a767df33f69bcfeead9a3ef"
)
_MAX_ENTRY = 96 * 1024 * 1024


def _norm(name: str) -> str:
    return str(name or "").replace("\\", "/")


def _safe_zip_name(name: str) -> bool:
    value = _norm(name)
    if not value or "\x00" in value or value.startswith("/"):
        return False
    return all(part not in ("", ".", "..") for part in PurePosixPath(value).parts)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _xor_byte(data: bytes, key: int) -> bytes:
    return bytes(value ^ (int(key) & 0xFF) for value in data)


def _xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty repeating XOR key")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _valid_dex(data: bytes) -> bool:
    magics = tuple(b"dex\n%03d\x00" % value for value in range(35, 42))
    if len(data) < 0x70 or not data.startswith(magics):
        return False
    return (
        int.from_bytes(data[0x20:0x24], "little") == len(data)
        and int.from_bytes(data[0x24:0x28], "little") == 0x70
        and int.from_bytes(data[0x28:0x2C], "little") == 0x12345678
    )


def _hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    out = bytearray()
    block = b""
    counter = 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), hashlib.sha256).digest()
        out.extend(block)
        counter += 1
    return bytes(out[:length])


def _pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError("OnDev payload decrypted to empty data")
    count = data[-1]
    if not 1 <= count <= 16 or data[-count:] != bytes((count,)) * count:
        raise ValueError("OnDev payload has invalid PKCS#7 padding")
    return data[:-count]


def _decrypt_ondev_v10(k_blob: bytes, p_blob: bytes) -> bytes:
    if len(k_blob) != 69 or not k_blob.startswith(b"OKDF") or k_blob[4] != 0x10:
        raise ValueError("unsupported OnDev key blob (only exact OKDF v0x10 is static)")
    prk = hmac.new(k_blob[5:21], _FIXED_CERT_V10, hashlib.sha256).digest()
    okm = _hkdf_expand(prk, b"ondev-dexkey-v2", 48)
    key = bytes(left ^ right for left, right in zip(k_blob[21:53], okm[:32]))
    iv = bytes(left ^ right for left, right in zip(k_blob[53:69], okm[32:48]))
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    return _pkcs7_unpad(decryptor.update(p_blob) + decryptor.finalize())


def _parse_odex(data: bytes) -> Tuple[str, List[bytes]]:
    if not data.startswith(b"ODEX") or len(data) < 10:
        raise ValueError("OnDev plaintext is not an ODEX container")
    pos = 4
    name_len = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    if not 1 <= name_len <= 4096 or pos + name_len + 2 > len(data):
        raise ValueError("invalid ODEX application-class length")
    app_class = data[pos:pos + name_len].decode("utf-8", "strict")
    pos += name_len
    count = int.from_bytes(data[pos:pos + 2], "big")
    pos += 2
    if not 1 <= count <= 32:
        raise ValueError("invalid ODEX DEX count")
    dexes: List[bytes] = []
    for _index in range(count):
        if pos + 4 > len(data):
            raise ValueError("truncated ODEX DEX-size field")
        size = int.from_bytes(data[pos:pos + 4], "big")
        pos += 4
        if not 0x70 <= size <= _MAX_ENTRY or pos + size > len(data):
            raise ValueError("invalid ODEX DEX size")
        dex = bytes(data[pos:pos + size])
        pos += size
        if not _valid_dex(dex):
            raise ValueError("ODEX member failed DEX structural validation")
        dexes.append(dex)
    if pos != len(data):
        raise ValueError("ODEX has unexplained trailing bytes")
    return app_class, dexes


def _rc4_crypt(data: bytes, key: bytes) -> bytes:
    if not key:
        raise ValueError("empty RC4 key")
    state = list(range(256))
    j = 0
    for i in range(256):
        j = (j + state[i] + key[i % len(key)]) & 0xFF
        state[i], state[j] = state[j], state[i]
    out = bytearray()
    i = 0
    j = 0
    for value in data:
        i = (i + 1) & 0xFF
        j = (j + state[i]) & 0xFF
        state[i], state[j] = state[j], state[i]
        out.append(value ^ state[(state[i] + state[j]) & 0xFF])
    return bytes(out)


def _elf_section(blob: bytes, wanted: str) -> Optional[bytes]:
    """Return one named section from a little-endian ELF32/ELF64 image."""
    if len(blob) < 64 or blob[:4] != b"\x7fELF" or blob[5] != 1:
        return None
    elf_class = blob[4]
    try:
        if elf_class == 1:
            e_shoff = struct.unpack_from("<I", blob, 0x20)[0]
            e_shentsize = struct.unpack_from("<H", blob, 0x2E)[0]
            e_shnum = struct.unpack_from("<H", blob, 0x30)[0]
            e_shstrndx = struct.unpack_from("<H", blob, 0x32)[0]
            def row(index: int) -> Tuple[int, int, int]:
                off = e_shoff + index * e_shentsize
                name, _type, _flags, _addr, sec_off, sec_size = struct.unpack_from("<IIIIII", blob, off)
                return name, sec_off, sec_size
        elif elf_class == 2:
            e_shoff = struct.unpack_from("<Q", blob, 0x28)[0]
            e_shentsize = struct.unpack_from("<H", blob, 0x3A)[0]
            e_shnum = struct.unpack_from("<H", blob, 0x3C)[0]
            e_shstrndx = struct.unpack_from("<H", blob, 0x3E)[0]
            def row(index: int) -> Tuple[int, int, int]:
                off = e_shoff + index * e_shentsize
                name, _type, _flags, _addr, sec_off, sec_size = struct.unpack_from("<IIQQQQ", blob, off)
                return name, int(sec_off), int(sec_size)
        else:
            return None
        if not e_shoff or not e_shentsize or not e_shnum or e_shstrndx >= e_shnum:
            return None
        _name, str_off, str_size = row(e_shstrndx)
        if str_off + str_size > len(blob):
            return None
        names = blob[str_off:str_off + str_size]
        for index in range(e_shnum):
            name_off, sec_off, sec_size = row(index)
            if name_off >= len(names) or sec_off + sec_size > len(blob):
                continue
            end = names.find(b"\x00", name_off)
            if end < 0:
                continue
            name = names[name_off:end].decode("utf-8", "replace")
            if name == wanted:
                return bytes(blob[sec_off:sec_off + sec_size])
    except (IndexError, struct.error, ValueError):
        return None
    return None


def _epic_config(zf: zipfile.ZipFile) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    votes: Dict[str, Tuple[Dict[str, Any], List[str], bytes]] = {}
    errors: List[str] = []
    for info in zf.infolist():
        name = _norm(info.filename)
        if info.is_dir() or not name.lower().endswith("/libepic.so"):
            continue
        try:
            section = _elf_section(zf.read(info), ".ArmEpic")
            if not section or len(section) < 17:
                raise ValueError("missing/short .ArmEpic")
            plain = _rc4_crypt(section[16:], section[:16])
            config = json.loads(plain.decode("utf-8"))
            if not isinstance(config, dict):
                raise ValueError("EPIC metadata is not an object")
            digest = _sha256(plain)
            if digest not in votes:
                votes[digest] = (config, [], section)
            votes[digest][1].append(name)
        except Exception as exc:
            errors.append("%s: %s: %s" % (name, type(exc).__name__, exc))
    if not votes:
        raise ValueError("no statically decodable EPIC .ArmEpic metadata: %s" % "; ".join(errors[:3]))
    ranked = sorted(votes.items(), key=lambda item: (-len(item[1][1]), item[0]))
    digest, (config, libraries, section) = ranked[0]
    if len(ranked) > 1 and len(ranked[1][1][1]) == len(libraries):
        raise ValueError("EPIC .ArmEpic metadata is ambiguous across ABIs")
    return config, {
        "plain_sha256": digest,
        "section_sha256": _sha256(section),
        "section_size": len(section),
        "rc4_key_hex": section[:16].hex(),
        "abi_votes": len(libraries),
        "libraries": sorted(libraries),
        "parse_errors": errors,
    }


def _uleb(data: bytes, pos: int) -> Tuple[int, int]:
    result = 0
    shift = 0
    while True:
        if pos >= len(data) or shift > 35:
            raise ValueError("invalid DEX ULEB128")
        value = data[pos]
        pos += 1
        result |= (value & 0x7F) << shift
        if value < 0x80:
            return result, pos
        shift += 7


def _dex_strings_and_header(dex: bytes) -> Tuple[List[str], Dict[str, int]]:
    fields = (
        "string_ids_size", "string_ids_off", "type_ids_size", "type_ids_off",
        "proto_ids_size", "proto_ids_off", "field_ids_size", "field_ids_off",
        "method_ids_size", "method_ids_off", "class_defs_size", "class_defs_off",
    )
    header = dict(zip(fields, struct.unpack_from("<12I", dex, 0x38)))
    strings: List[str] = []
    for index in range(header["string_ids_size"]):
        off = struct.unpack_from("<I", dex, header["string_ids_off"] + index * 4)[0]
        _length, pos = _uleb(dex, off)
        end = dex.find(b"\x00", pos)
        if end < 0:
            raise ValueError("unterminated DEX string")
        strings.append(dex[pos:end].decode("utf-8", "replace"))
    return strings, header


def _dex_instruction_length(insns: Sequence[int], pos: int) -> int:
    word = insns[pos]
    op = word & 0xFF
    if op == 0x00:
        ident = word & 0xFF00
        if ident == 0x0100 and pos + 1 < len(insns):
            return 4 + int(insns[pos + 1]) * 2
        if ident == 0x0200 and pos + 1 < len(insns):
            return 2 + int(insns[pos + 1]) * 4
        if ident == 0x0300 and pos + 3 < len(insns):
            width = int(insns[pos + 1])
            size = int(insns[pos + 2]) | (int(insns[pos + 3]) << 16)
            return 4 + ((width * size + 1) // 2)
        return 1
    if op in (0x01, 0x04, 0x07, *range(0x0A, 0x13), 0x1D, 0x1E, 0x21, 0x27, 0x28,
              *range(0x3E, 0x44), 0x73, 0x79, 0x7A,
              *range(0x7B, 0x90), *range(0xB0, 0xD0)):
        return 1
    if op in (0x02, 0x05, 0x08, 0x13, 0x15, 0x16, 0x19, 0x1A, 0x1C, 0x1F, 0x20,
              0x22, 0x23, 0x29, *range(0x2D, 0x3E), *range(0x44, 0x6E),
              *range(0x90, 0xB0), *range(0xD0, 0xE3), 0xFE, 0xFF):
        return 2
    if op in (0x03, 0x06, 0x09, 0x14, 0x17, 0x1B, 0x24, 0x25, 0x26, 0x2A, 0x2B, 0x2C,
              *range(0x6E, 0x73), *range(0x74, 0x79), 0xFC, 0xFD):
        return 3
    if op in (0xFA, 0xFB):
        return 4
    if op == 0x18:
        return 5
    return 1


def _decode_const_int(insns: Sequence[int], pos: int) -> Optional[int]:
    op = insns[pos] & 0xFF
    if op == 0x12:
        value = (insns[pos] >> 12) & 0xF
        return value - 16 if value & 8 else value
    if op == 0x13 and pos + 1 < len(insns):
        value = int(insns[pos + 1])
        return value - 0x10000 if value & 0x8000 else value
    if op == 0x14 and pos + 2 < len(insns):
        value = int(insns[pos + 1]) | (int(insns[pos + 2]) << 16)
        return value - 0x100000000 if value & 0x80000000 else value
    if op == 0x15 and pos + 1 < len(insns):
        value = int(insns[pos + 1]) << 16
        return value - 0x100000000 if value & 0x80000000 else value
    return None


def _container_recipe_from_dex(dexes: Iterable[bytes], asset_names: set[str]) -> Dict[str, Any]:
    recipes: List[Dict[str, Any]] = []
    for dex_index, dex in enumerate(dexes, 1):
        strings, header = _dex_strings_and_header(dex)
        type_ids = [
            struct.unpack_from("<I", dex, header["type_ids_off"] + index * 4)[0]
            for index in range(header["type_ids_size"])
        ]

        def type_name(index: int) -> str:
            if not 0 <= index < len(type_ids):
                return ""
            string_index = type_ids[index]
            return strings[string_index] if 0 <= string_index < len(strings) else ""

        protos: List[Tuple[str, Tuple[str, ...]]] = []
        for index in range(header["proto_ids_size"]):
            _shorty, return_type, params_off = struct.unpack_from(
                "<III", dex, header["proto_ids_off"] + index * 12
            )
            params: List[str] = []
            if params_off:
                count = struct.unpack_from("<I", dex, params_off)[0]
                for item in range(count):
                    params.append(type_name(struct.unpack_from("<H", dex, params_off + 4 + item * 2)[0]))
            protos.append((type_name(return_type), tuple(params)))
        methods = [
            struct.unpack_from("<HHI", dex, header["method_ids_off"] + index * 8)
            for index in range(header["method_ids_size"])
        ]

        for class_index in range(header["class_defs_size"]):
            off = header["class_defs_off"] + class_index * 32
            class_idx, _flags, _super, _interfaces, _source, _annotations, class_data_off, _values = struct.unpack_from(
                "<8I", dex, off
            )
            class_name = type_name(class_idx)
            if not class_data_off or not class_name.startswith("Lcom/iapp/app/"):
                continue
            pos = class_data_off
            static_fields, pos = _uleb(dex, pos)
            instance_fields, pos = _uleb(dex, pos)
            direct_methods, pos = _uleb(dex, pos)
            virtual_methods, pos = _uleb(dex, pos)
            for _ in range(static_fields + instance_fields):
                _value, pos = _uleb(dex, pos)
                _value, pos = _uleb(dex, pos)
            for method_count in (direct_methods, virtual_methods):
                # DEX method_idx_diff is cumulative separately for direct and
                # virtual method lists, so reset at each list boundary.
                method_index = 0
                for _ in range(method_count):
                    diff, pos = _uleb(dex, pos)
                    access, pos = _uleb(dex, pos)
                    code_off, pos = _uleb(dex, pos)
                    method_index += diff
                    if not code_off or not 0 <= method_index < len(methods):
                        continue
                    owner, proto_index, name_index = methods[method_index]
                    if owner != class_idx or not 0 <= proto_index < len(protos) or not 0 <= name_index < len(strings):
                        continue
                    if strings[name_index] != "b" or protos[proto_index] != (
                        "[B", ("Ljava/lang/String;", "Landroid/content/Context;")
                    ) or not (access & 0x8):
                        continue
                    if code_off + 16 > len(dex):
                        continue
                    _regs, _ins, _outs, _tries, _debug, count = struct.unpack_from("<HHHHII", dex, code_off)
                    insns_off = code_off + 16
                    if insns_off + count * 2 > len(dex):
                        continue
                    insns = list(struct.unpack_from("<%dH" % count, dex, insns_off))
                    referenced_assets: List[str] = []
                    constants: List[int] = []
                    ops: List[Tuple[int, int, int]] = []
                    cursor = 0
                    while cursor < len(insns):
                        op = insns[cursor] & 0xFF
                        if op == 0x1A and cursor + 1 < len(insns):
                            string_index = int(insns[cursor + 1])
                            if 0 <= string_index < len(strings):
                                candidate = "assets/" + strings[string_index].lstrip("/")
                                if candidate in asset_names:
                                    referenced_assets.append(candidate)
                        elif op == 0x1B and cursor + 2 < len(insns):
                            string_index = int(insns[cursor + 1]) | (int(insns[cursor + 2]) << 16)
                            if 0 <= string_index < len(strings):
                                candidate = "assets/" + strings[string_index].lstrip("/")
                                if candidate in asset_names:
                                    referenced_assets.append(candidate)
                        value = _decode_const_int(insns, cursor)
                        if value is not None:
                            constants.append(int(value))
                        if op in (0xDC, 0xE1):
                            literal = (int(insns[cursor + 1]) >> 8) & 0xFF if cursor + 1 < len(insns) else -1
                            ops.append((op, cursor, literal))
                        else:
                            ops.append((op, cursor, -1))
                        cursor += _dex_instruction_length(insns, cursor)
                    assets = sorted(set(referenced_assets))
                    packed = sorted(set(value for value in constants if 0x10000 <= value <= 0xFFFFFF))
                    opcodes = {op for op, _cursor, _literal in ops}
                    rem3 = any(op == 0xDC and literal == 3 for op, _cursor, literal in ops)
                    shifts = {literal for op, _cursor, literal in ops if op == 0xE1}
                    if len(assets) != 1 or len(packed) != 1:
                        continue
                    if not (rem3 and {8, 16}.issubset(shifts) and {0x48, 0x4F, 0x8D, 0xB7}.issubset(opcodes)):
                        continue
                    packed_key = packed[0]
                    # The method's branches select: high byte for i%3==0,
                    # middle byte for i%3==1, low byte for i%3==2.
                    # For 0x37E7F5 the repeating key is 37 E7 F5.
                    key = bytes(((packed_key >> 16) & 0xFF, (packed_key >> 8) & 0xFF, packed_key & 0xFF))
                    recipes.append({
                        "dex_index": dex_index,
                        "class": class_name,
                        "method": "b(String,Context):byte[]",
                        "asset_entry": assets[0],
                        "packed_key": packed_key,
                        "xor_key": key,
                        "code_off": code_off,
                    })
    unique = {
        (row["asset_entry"], bytes(row["xor_key"]), int(row["packed_key"])): row
        for row in recipes
    }
    if len(unique) != 1:
        raise ValueError("iApp DEX container recipe is missing or ambiguous (%d)" % len(unique))
    return next(iter(unique.values()))


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


def restore_if_supported(
    apk_path: Path | str,
    output_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    apk = Path(apk_path)
    output = Path(output_path)
    with zipfile.ZipFile(apk, "r") as source:
        infos = [info for info in source.infolist() if not info.is_dir()]
        by_lower = {_norm(info.filename).lower(): info for info in infos}
        k_info = by_lower.get("assets/ondev/k")
        p_info = by_lower.get("assets/ondev/p")
        has_ondev_so = any(name.endswith("/libondevx.so") for name in by_lower)
        if k_info is None or p_info is None or not has_ondev_so:
            return None
        unsafe = [info.filename for info in source.infolist() if not _safe_zip_name(info.filename)]
        if unsafe:
            raise ValueError("OnDev APK contains unsafe ZIP member names")

        k_blob = source.read(k_info)
        p_blob = source.read(p_info)
        odex = _decrypt_ondev_v10(k_blob, p_blob)
        app_class, dexes = _parse_odex(odex)

        epic, epic_report = _epic_config(source)
        try:
            asset_method = int(epic["asset_protection_method"])
            asset_key = int(epic["asset_protection_xor_key"]) & 0xFF
            rename_map = epic["asset_rename_map"]
        except Exception as exc:
            raise ValueError("EPIC metadata lacks the supported asset fields") from exc
        if asset_method != 0 or not isinstance(rename_map, dict):
            raise ValueError("unsupported EPIC asset protection method/layout")
        physical_assets = {
            _norm(value) for value in rename_map.values()
            if isinstance(value, str) and _norm(value).startswith("assets/")
        }
        marker_info = by_lower.get("assets/extra_conf1g.xml")
        if marker_info is None or _xor_byte(source.read(marker_info), asset_key) != _SIGNATURE_MARKER:
            raise ValueError("EPIC asset XOR key failed the exact signature marker")

        asset_names = {_norm(info.filename) for info in infos if _norm(info.filename).startswith("assets/")}
        recipe = _container_recipe_from_dex(dexes, asset_names)
        container_info = next((info for info in infos if _norm(info.filename) == recipe["asset_entry"]), None)
        if container_info is None:
            raise ValueError("DEX-selected iApp container entry is missing")
        raw_container = source.read(container_info)
        # AssetManager.open() sees EPIC-restored bytes at runtime.  The DEX
        # helper then applies its own repeating XOR.  Both layers are required
        # for the hidden source container; applying only the DEX transform
        # produces block-aligned noise that can cause misleading AES padding
        # false positives later.
        epic_container = (
            _xor_byte(raw_container, asset_key)
            if recipe["asset_entry"] in physical_assets
            else raw_container
        )
        container = _xor_repeat(epic_container, bytes(recipe["xor_key"]))
        if len(container) < 65536 or len(container) % 16:
            raise ValueError("DEX-transformed iApp container failed AES transport shape checks")

        lib_only = bool((options or {}).get("no_decrypt_resource_files") or (options or {}).get("skip_anti_resources"))
        report: Dict[str, Any] = {
            "build": BUILD,
            "normalized": True,
            "normalizer": BUILD,
            "analysis_phase": "feature-match",
            "family": "ondev-v3+epic+iapp",
            "source_apk": apk.name,
            "ondev_key_entry": _norm(k_info.filename),
            "ondev_payload_entry": _norm(p_info.filename),
            "ondev_version": int(k_blob[4]),
            "ondev_application_class": app_class,
            "ondev_dex_count": len(dexes),
            "ondev_dexes": [
                {"index": index, "size": len(dex), "sha256": _sha256(dex)}
                for index, dex in enumerate(dexes, 1)
            ],
            "epic_metadata": epic_report,
            "epic_protection_flag": epic.get("protection_flag"),
            "epic_asset_protection_method": asset_method,
            "epic_asset_xor_key": asset_key,
            "epic_asset_rename_count": len(rename_map),
            "container_transport_entry": recipe["asset_entry"],
            "container_transport_method": "epic-xor-then-dex-repeating-xor",
            "container_transport_class": recipe["class"],
            "container_transport_method_name": recipe["method"],
            "container_transport_packed_key": int(recipe["packed_key"]),
            "container_transport_xor_key_hex": bytes(recipe["xor_key"]).hex(),
            "container_size": len(container),
            "container_sha256": _sha256(container),
            "lib_only": lib_only,
            "ordinary_resources_restored": False,
            "resource_plan": {
                "strategy": "ondev-v3-static-unwrap+armepic-json+dex-container-transform",
                "input": recipe["asset_entry"],
                "operations": [
                    "decrypt:OKDF-v10/AES-256-CBC",
                    "parse:ODEX",
                    "parse:.ArmEpic/RC4/JSON",
                    "ordinary-assets:xor-byte:%02x" % asset_key,
                    "container:epic-xor-byte:%02x" % asset_key,
                    "container:dex-xor-repeat:%s" % bytes(recipe["xor_key"]).hex(),
                    "replace:assets/lib.so",
                    "restore-original-dex",
                ],
                "output": "assets/lib.so",
                "confidence": "certain-dex-and-native-metadata",
            },
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
        os.close(fd)
        temp = Path(temp_name)
        restored_resources = 0
        try:
            written: set[str] = set()
            with zipfile.ZipFile(temp, "w", allowZip64=True) as target:
                for info in source.infolist():
                    if info.is_dir():
                        continue
                    name = _norm(info.filename)
                    low = name.lower()
                    if low in {"assets/lib.so", "meta-inf/iapt/ondev_epic_restore.json"}:
                        continue
                    if low.startswith("classes") and low.endswith(".dex"):
                        continue
                    if low in written:
                        continue
                    raw = source.read(info)
                    data = raw
                    if not lib_only and name != recipe["asset_entry"] and name in physical_assets:
                        data = _xor_byte(raw, asset_key)
                        restored_resources += 1
                    target.writestr(_clone_info(info, name), data)
                    written.add(low)

                for index, dex in enumerate(dexes, 1):
                    dex_name = "classes.dex" if index == 1 else "classes%d.dex" % index
                    zi = zipfile.ZipInfo(dex_name, date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    target.writestr(zi, dex)
                lib_info = zipfile.ZipInfo("assets/lib.so", date_time=(1980, 1, 1, 0, 0, 0))
                lib_info.compress_type = zipfile.ZIP_STORED
                target.writestr(lib_info, container)
                report["ordinary_resources_restored"] = bool(restored_resources)
                report["ordinary_resources_restored_count"] = restored_resources
                marker = zipfile.ZipInfo("META-INF/iapt/ondev_epic_restore.json", date_time=(1980, 1, 1, 0, 0, 0))
                marker.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(marker, json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))

            with zipfile.ZipFile(temp, "r") as check:
                if check.read("assets/lib.so") != container:
                    raise ValueError("OnDev normalized APK container self-check failed")
                for index, dex in enumerate(dexes, 1):
                    dex_name = "classes.dex" if index == 1 else "classes%d.dex" % index
                    restored = check.read(dex_name)
                    if restored != dex or not _valid_dex(restored):
                        raise ValueError("OnDev normalized APK DEX self-check failed")
                if not lib_only and check.read("assets/extra_conf1g.xml") != _SIGNATURE_MARKER:
                    raise ValueError("EPIC ordinary asset restoration self-check failed")
            os.replace(temp, output)
        finally:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                pass

    report["normalized_apk"] = str(output)
    report["normalized_apk_size"] = output.stat().st_size
    with output.open("rb") as handle:
        report["normalized_apk_sha256"] = hashlib.file_digest(handle, "sha256").hexdigest()
    return report
