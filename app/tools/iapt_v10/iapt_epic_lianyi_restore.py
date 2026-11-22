#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Strict static restoration for EPIC / By.LianYi resource transport.

The supported layout is intentionally narrow and evidence-driven:

* ``assets/lib.so`` is a zero/short placeholder;
* one protector namespace (``EPIC/`` or ``LianYi/``) contains resources renamed
  and XORed with one byte;
* the same namespace contains the exact ``<signature>1</signature>`` marker,
  which proves the asset XOR byte;
* one high-entropy, AES-block-aligned payload remains after known file formats
  are excluded; that payload is restored as ``assets/lib.so``;
* one ``assets/.../*.Epic`` payload XORs to a structurally valid DEX and is
  restored as ``classes.dex`` so static f.b() recovery can inspect the original
  app code rather than the tiny protector loader.

No native library or APK bytecode is executed.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import tempfile
import zipfile
from collections import Counter
from pathlib import Path, PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Tuple

BUILD = "epic-lianyi-static-xor-v181"
_SIGNATURE_MARKER = b"<signature>1</signature>"
_MAX_ENTRY = 64 * 1024 * 1024

_LAYOUTS = (
    {
        "family": "epic",
        "root_prefix": "EPIC/",
        "dex_prefix": "assets/EPIC/",
        "native_needles": (b"asset_rename_map", b"asset_protection_xor_key", b"dex_protection_xor_key", b"Epic.vm"),
    },
    {
        "family": "by-lianyi",
        "root_prefix": "LianYi/",
        "dex_prefix": "assets/By.LianYi/",
        "native_needles": (b"asset_rename_map", b"asset_protection_xor_key", b"dex_protection_xor_key", b".Epic"),
    },
)

_KNOWN_MAGICS = (
    b"dex\n",
    b"\x7fELF",
    b"PK\x03\x04",
    b"PK\x05\x06",
    b"\x89PNG\r\n\x1a\n",
    b"\xff\xd8\xff",
    b"RIFF",
    b"GIF87a",
    b"GIF89a",
    b"OggS",
    b"SQLite format 3\x00",
    b"\x1f\x8b",
    b"<?xml",
    b"<!DOCTYPE",
    b"{\"",
    b"[{",
    b"OTTO",
    b"ttcf",
    b"wOFF",
    b"wOF2",
    b"\x00\x01\x00\x00",  # TrueType/OpenType tables and EPIC font chunks.
    _SIGNATURE_MARKER,
)


def _norm(name: str) -> str:
    return str(name or "").replace("\\", "/")


def _safe_zip_name(name: str) -> bool:
    value = _norm(name)
    if not value or "\x00" in value or value.startswith("/"):
        return False
    path = PurePosixPath(value)
    return all(part not in ("", ".", "..") for part in path.parts)


def _xor(data: bytes, key: int) -> bytes:
    return bytes(value ^ int(key) for value in data)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _entropy(data: bytes) -> float:
    sample = bytes(data[: min(len(data), 131072)])
    if not sample:
        return 0.0
    counts = Counter(sample)
    total = float(len(sample))
    value = 0.0
    for count in counts.values():
        probability = count / total
        value -= probability * math.log2(probability)
    return value


def _valid_dex(data: bytes) -> bool:
    if len(data) < 0x70 or not data.startswith((b"dex\n035\x00", b"dex\n036\x00", b"dex\n037\x00", b"dex\n038\x00", b"dex\n039\x00", b"dex\n040\x00", b"dex\n041\x00")):
        return False
    try:
        file_size = int.from_bytes(data[0x20:0x24], "little")
        header_size = int.from_bytes(data[0x24:0x28], "little")
        endian_tag = int.from_bytes(data[0x28:0x2C], "little")
    except Exception:
        return False
    return file_size == len(data) and header_size == 0x70 and endian_tag == 0x12345678


def _find_layout(zf: zipfile.ZipFile) -> Optional[Dict[str, Any]]:
    names = [_norm(info.filename) for info in zf.infolist() if not info.is_dir()]
    for layout in _LAYOUTS:
        root = str(layout["root_prefix"])
        dex_root = str(layout["dex_prefix"])
        root_hits = [name for name in names if name.lower().startswith(root.lower())]
        dex_hits = [name for name in names if name.lower().startswith(dex_root.lower()) and name.lower().endswith(".epic")]
        if not root_hits or not dex_hits:
            continue
        protector_rows = []
        for info in zf.infolist():
            name = _norm(info.filename)
            if info.is_dir() or not name.lower().startswith("lib/") or not name.lower().endswith(".so"):
                continue
            if not (4096 <= int(info.file_size or 0) <= _MAX_ENTRY):
                continue
            try:
                blob = zf.read(info)
            except Exception:
                continue
            if all(needle in blob for needle in layout["native_needles"][:3]) and (b".Epic" in blob or b"Epic.vm" in blob):
                protector_rows.append({"entry": name, "size": len(blob), "sha256": _sha256(blob)})
        if protector_rows:
            return {
                **layout,
                "root_entries": root_hits,
                "dex_entries": dex_hits,
                "protector_libraries": protector_rows,
            }
    return None


def _placeholder_present(zf: zipfile.ZipFile) -> Tuple[bool, int]:
    for info in zf.infolist():
        if not info.is_dir() and _norm(info.filename).lower() == "assets/lib.so":
            return int(info.file_size or 0) < 64, int(info.file_size or 0)
    return False, -1


def _asset_xor_key(zf: zipfile.ZipFile, root_prefix: str) -> Tuple[int, str]:
    hits: List[Tuple[int, str]] = []
    for info in zf.infolist():
        name = _norm(info.filename)
        if info.is_dir() or not name.lower().startswith(root_prefix.lower()):
            continue
        if int(info.file_size or 0) != len(_SIGNATURE_MARKER):
            continue
        raw = zf.read(info)
        key = raw[0] ^ _SIGNATURE_MARKER[0]
        if _xor(raw, key) == _SIGNATURE_MARKER:
            hits.append((key, name))
    unique = {(key, name) for key, name in hits}
    key_values = {key for key, _name in unique}
    if len(key_values) != 1:
        raise ValueError("EPIC/LianYi asset XOR marker is missing or ambiguous")
    key = next(iter(key_values))
    marker_names = sorted(name for row_key, name in unique if row_key == key)
    return int(key), marker_names[0]


def _dex_payload(zf: zipfile.ZipFile, dex_entries: Iterable[str]) -> Tuple[int, str, bytes]:
    hits: List[Tuple[int, str, bytes]] = []
    # The first four DEX bytes are version-independent.  Derive the one-byte
    # transport XOR from ``dex\n`` and let _valid_dex validate versions 035-041.
    expected = b"dex\n"
    for name in dex_entries:
        try:
            raw = zf.read(name)
        except Exception:
            continue
        if not (0x70 <= len(raw) <= _MAX_ENTRY) or len(raw) < len(expected):
            continue
        keys = {raw[index] ^ expected[index] for index in range(len(expected))}
        if len(keys) != 1:
            continue
        key = next(iter(keys))
        decoded = _xor(raw, key)
        if _valid_dex(decoded):
            hits.append((int(key), name, decoded))
    # These two supported families carry one original application DEX.  Refuse
    # ambiguous/multidex layouts until a path map is proven.
    if len(hits) != 1:
        raise ValueError("EPIC/LianYi original DEX is missing or ambiguous")
    return hits[0]


def _known_plaintext(data: bytes) -> bool:
    head = bytes(data[:64]).lstrip(b"\xef\xbb\xbf\x00\t\r\n ")
    return any(head.startswith(magic) for magic in _KNOWN_MAGICS)


def _container_payload(zf: zipfile.ZipFile, root_prefix: str, asset_key: int) -> Tuple[str, bytes, List[Dict[str, Any]]]:
    candidates: List[Tuple[str, bytes, Dict[str, Any]]] = []
    inventory: List[Dict[str, Any]] = []
    for info in zf.infolist():
        name = _norm(info.filename)
        if info.is_dir() or not name.lower().startswith(root_prefix.lower()):
            continue
        size = int(info.file_size or 0)
        if not (64 * 1024 <= size <= _MAX_ENTRY):
            continue
        raw = zf.read(info)
        decoded = _xor(raw, asset_key)
        entropy = _entropy(decoded)
        known = _known_plaintext(decoded)
        row = {
            "entry": name,
            "size": size,
            "block_aligned_16": size % 16 == 0,
            "entropy": round(entropy, 6),
            "known_magic": bool(known),
            "sha256_encrypted": _sha256(raw),
            "sha256_decoded": _sha256(decoded),
        }
        inventory.append(row)
        # The original iApp container is AES ciphertext: block aligned,
        # effectively incompressible/high entropy, and has no ordinary file
        # magic after the outer transport XOR is removed.
        if size % 16 == 0 and entropy >= 7.90 and not known:
            candidates.append((name, decoded, row))
    if len(candidates) != 1:
        raise ValueError("EPIC/LianYi assets/lib.so candidate is missing or ambiguous (%d)" % len(candidates))
    name, decoded, _row = candidates[0]
    return name, decoded, inventory


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


def restore_if_supported(apk_path: Path | str, output_path: Path | str, options: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    apk = Path(apk_path)
    output = Path(output_path)
    with zipfile.ZipFile(apk, "r") as source:
        unsafe = [info.filename for info in source.infolist() if not _safe_zip_name(info.filename)]
        if unsafe:
            raise ValueError("EPIC/LianYi APK contains unsafe ZIP member names")
        placeholder, placeholder_size = _placeholder_present(source)
        if not placeholder:
            return None
        layout = _find_layout(source)
        if not layout:
            return None
        asset_key, marker_entry = _asset_xor_key(source, str(layout["root_prefix"]))
        dex_key, dex_entry, original_dex = _dex_payload(source, layout["dex_entries"])
        container_entry, container, inventory = _container_payload(source, str(layout["root_prefix"]), asset_key)

        report: Dict[str, Any] = {
            "build": BUILD,
            "normalized": True,
            "normalizer": BUILD,
            "analysis_phase": "feature-match",
            "family": layout["family"],
            "source_apk": apk.name,
            "placeholder_size": placeholder_size,
            "asset_xor_key": asset_key,
            "asset_xor_marker_entry": marker_entry,
            "dex_xor_key": dex_key,
            "dex_entry": dex_entry,
            "dex_size": len(original_dex),
            "dex_sha256": _sha256(original_dex),
            "container_transport_entry": container_entry,
            "container_size": len(container),
            "container_sha256": _sha256(container),
            "protector_libraries": layout["protector_libraries"],
            # Keep the public/worker log compact.  The complete scan is used for
            # the decision, but only counts plus the selected row are emitted.
            "candidate_inventory_summary": {
                "total": len(inventory),
                "block_aligned_16": sum(1 for row in inventory if row.get("block_aligned_16")),
                "high_entropy": sum(1 for row in inventory if float(row.get("entropy") or 0.0) >= 7.90),
                "known_magic": sum(1 for row in inventory if row.get("known_magic")),
                "selected": next((row for row in inventory if row.get("entry") == container_entry), None),
            },
            "lib_only": bool((options or {}).get("no_decrypt_resource_files") or (options or {}).get("skip_anti_resources")),
            "ordinary_resources_restored": False,
            "resource_plan": {
                "strategy": "epic-lianyi-static-xor",
                "input": container_entry,
                "operations": ["xor-byte:%02x" % asset_key, "replace:assets/lib.so", "restore-original-dex"],
                "output": "assets/lib.so",
                "confidence": "certain",
            },
        }

        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=output.name + ".", suffix=".tmp", dir=str(output.parent))
        os.close(fd)
        temp = Path(temp_name)
        try:
            written = set()
            with zipfile.ZipFile(temp, "w", allowZip64=True) as target:
                for info in source.infolist():
                    if info.is_dir():
                        continue
                    name = _norm(info.filename)
                    low = name.lower()
                    if low == "meta-inf/iapt/epic_lianyi_restore.json":
                        continue
                    if low == "assets/lib.so":
                        if low in written:
                            continue
                        target.writestr(_clone_info(info, "assets/lib.so"), container)
                        written.add(low)
                        continue
                    if low == "classes.dex":
                        if low in written:
                            continue
                        target.writestr(_clone_info(info, "classes.dex"), original_dex)
                        written.add(low)
                        continue
                    if low in written:
                        continue
                    target.writestr(_clone_info(info, name), source.read(info))
                    written.add(low)
                marker = zipfile.ZipInfo("META-INF/iapt/epic_lianyi_restore.json", date_time=(1980, 1, 1, 0, 0, 0))
                marker.compress_type = zipfile.ZIP_DEFLATED
                target.writestr(marker, json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8"))
            with zipfile.ZipFile(temp, "r") as check:
                restored_container = check.read("assets/lib.so")
                restored_dex = check.read("classes.dex")
                if restored_container != container or not _valid_dex(restored_dex):
                    raise ValueError("EPIC/LianYi normalized APK self-check failed")
                # Preserve certificate bytes: the iApp signature branch derives
                # parameters from META-INF/*.RSA even though the ZIP was rebuilt.
                original_certs = sorted(
                    _norm(info.filename).lower() for info in source.infolist()
                    if not info.is_dir() and _norm(info.filename).lower().startswith("meta-inf/") and _norm(info.filename).lower().endswith((".rsa", ".dsa", ".ec"))
                )
                restored_certs = sorted(
                    _norm(info.filename).lower() for info in check.infolist()
                    if not info.is_dir() and _norm(info.filename).lower().startswith("meta-inf/") and _norm(info.filename).lower().endswith((".rsa", ".dsa", ".ec"))
                )
                if original_certs != restored_certs:
                    raise ValueError("EPIC/LianYi certificate entries were not preserved")
            os.replace(temp, output)
        finally:
            try:
                temp.unlink(missing_ok=True)
            except Exception:
                pass

    report["normalized_apk"] = str(output)
    report["normalized_apk_size"] = output.stat().st_size
    report["normalized_apk_sha256"] = _sha256(output.read_bytes())
    return report
