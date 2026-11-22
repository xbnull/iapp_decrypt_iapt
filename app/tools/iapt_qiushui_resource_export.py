#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Export QiuShui-hidden Android/iApp resources without executing APK code.

For feature-17/anti-QiuShui tasks this module merges:
  * canonical ``res/**`` and hidden ``assets/res/**`` from the DES inner ZIP;
  * ordinary/unmapped ``assets/res/**`` files retained in the outer APK
    (for example iappbox*.html files referenced by iApp sources).

The outer QiuShui ``assets/res/iappbox*.xml/png`` copies that merely replace
compiled ``res/**`` paths are skipped when the canonical inner tree exists.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import shutil
import struct
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

EXPORT_VERSION = 114
MANIFEST_NAME = ".iapt_internal/qiu_shui_resource_export.json"
_MAX_ENTRY_SIZE = 512 * 1024 * 1024
_MAX_TOTAL_SIZE = 1024 * 1024 * 1024
_MAX_ENTRIES = 30000
_MAX_NAME = 16384


class ResourceExportError(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normal_name(name: str) -> str:
    return str(name or "").replace("\\", "/")


def _safe_name(name: str) -> bool:
    name = _normal_name(name)
    if not name or "\x00" in name or name.startswith("/") or len(name) > _MAX_NAME:
        return False
    parts = name.split("/")
    return all(part not in ("", ".", "..") for part in parts)


def _u16(data: bytes, off: int) -> int:
    if off < 0 or off + 2 > len(data):
        raise ResourceExportError("truncated resource table")
    return struct.unpack_from("<H", data, off)[0]


def _u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise ResourceExportError("truncated resource table")
    return struct.unpack_from("<I", data, off)[0]


def _len8(data: bytes, pos: int) -> Tuple[int, int]:
    if pos >= len(data):
        raise ResourceExportError("truncated UTF-8 string length")
    value = data[pos]
    pos += 1
    if value & 0x80:
        if pos >= len(data):
            raise ResourceExportError("truncated UTF-8 string length")
        value = ((value & 0x7F) << 8) | data[pos]
        pos += 1
    return value, pos


def _len16(data: bytes, pos: int) -> Tuple[int, int]:
    value = _u16(data, pos)
    pos += 2
    if value & 0x8000:
        value = ((value & 0x7FFF) << 16) | _u16(data, pos)
        pos += 2
    return value, pos


def _parse_string_pool(data: bytes, off: int) -> Tuple[List[str], int]:
    if _u16(data, off) != 0x0001:
        raise ResourceExportError("not a resource string pool")
    header_size = _u16(data, off + 2)
    chunk_size = _u32(data, off + 4)
    count = _u32(data, off + 8)
    flags = _u32(data, off + 16)
    strings_start = _u32(data, off + 20)
    if header_size < 28 or chunk_size < header_size or off + chunk_size > len(data):
        raise ResourceExportError("invalid resource string pool bounds")
    if count > 1_000_000:
        raise ResourceExportError("excessive resource string count")
    utf8 = bool(flags & 0x100)
    strings: List[str] = []
    for index in range(count):
        rel = _u32(data, off + header_size + index * 4)
        pos = off + strings_start + rel
        if utf8:
            _, pos = _len8(data, pos)
            byte_len, pos = _len8(data, pos)
            if pos + byte_len > off + chunk_size:
                raise ResourceExportError("UTF-8 string exceeds pool")
            text = data[pos : pos + byte_len].decode("utf-8", "replace")
        else:
            char_len, pos = _len16(data, pos)
            byte_len = char_len * 2
            if pos + byte_len > off + chunk_size:
                raise ResourceExportError("UTF-16 string exceeds pool")
            text = data[pos : pos + byte_len].decode("utf-16le", "replace")
        strings.append(text)
    return strings, chunk_size


def arsc_file_paths(data: bytes) -> Set[str]:
    """Return file paths visible in all valid ResStringPool chunks.

    This intentionally does not trust package/type offsets.  QiuShui only needs
    the set of relocated file strings so a bounded aligned chunk scan is both
    simpler and more tolerant of package variations.
    """
    found: Set[str] = set()
    if len(data) < 12:
        return found
    for off in range(0, len(data) - 28, 4):
        try:
            if _u16(data, off) != 0x0001 or _u16(data, off + 2) != 28:
                continue
            chunk_size = _u32(data, off + 4)
            if chunk_size < 28 or off + chunk_size > len(data):
                continue
            strings, _ = _parse_string_pool(data, off)
        except Exception:
            continue
        for value in strings:
            name = _normal_name(value)
            low = name.lower()
            if low.startswith("res/") or low.startswith("assets/res/"):
                found.add(name)
    return found


def _read_resource_members(
    archive: zipfile.ZipFile,
    *,
    include_res: bool,
    include_assets: bool,
    exclude_assets: Optional[Set[str]] = None,
    skip_zero: bool = False,
) -> Tuple[Dict[str, bytes], Dict[str, Dict[str, Any]]]:
    exclude_low = {x.lower() for x in (exclude_assets or set())}
    data_by_name: Dict[str, bytes] = {}
    meta_by_name: Dict[str, Dict[str, Any]] = {}
    total = 0
    infos = archive.infolist()
    if len(infos) > _MAX_ENTRIES:
        raise ResourceExportError("ZIP entry count exceeds safety limit")
    for info in infos:
        if info.is_dir():
            continue
        name = _normal_name(info.filename)
        low = name.lower()
        selected = (include_res and low.startswith("res/")) or (
            include_assets and low.startswith("assets/res/")
        )
        if not selected or not _safe_name(name):
            continue
        if low.startswith("assets/res/") and low in exclude_low:
            continue
        if info.file_size < 0 or info.file_size > _MAX_ENTRY_SIZE:
            raise ResourceExportError("resource member exceeds safety limit: " + name[-120:])
        if skip_zero and info.file_size == 0:
            continue
        total += int(info.file_size)
        if total > _MAX_TOTAL_SIZE:
            raise ResourceExportError("resource tree exceeds safety limit")
        payload = archive.read(info)
        data_by_name[name] = payload
        meta_by_name[name] = {
            "size": len(payload),
            "sha256": _sha256(payload),
        }
    return data_by_name, meta_by_name


def _load_inner_zip(
    apk_path: Path,
    options: Optional[Dict[str, Any]],
) -> Tuple[Optional[bytes], Dict[str, Any]]:
    try:
        # Installed next to this module on the server.
        from .iapt_hidden_resource_restore import restore_hidden_resource_zip  # type: ignore
    except Exception:
        try:
            from iapt_hidden_resource_restore import restore_hidden_resource_zip  # type: ignore
        except Exception:
            try:
                from iapt_hidden_resource_restore_overlay_v3 import restore_hidden_resource_zip  # type: ignore
            except Exception as exc:
                return None, {"inner_available": False, "inner_reason": "restore module unavailable: " + str(exc)}
    try:
        inner, report = restore_hidden_resource_zip(apk_path, options or {})
        return bytes(inner), {
            "inner_available": True,
            "inner_zip_size": len(inner),
            "inner_zip_sha256": _sha256(bytes(inner)),
            "inner_restore": report,
        }
    except Exception as exc:
        return None, {
            "inner_available": False,
            "inner_reason": type(exc).__name__ + ": " + str(exc),
        }


def collect_resources(
    apk_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, bytes], Dict[str, Any]]:
    apk_path = Path(apk_path)
    if not apk_path.is_file() or not zipfile.is_zipfile(apk_path):
        raise ResourceExportError("input is not a readable APK/ZIP")

    inner_bytes, inner_report = _load_inner_zip(apk_path, options)
    merged: Dict[str, bytes] = {}
    origins: Dict[str, str] = {}
    hashes: Dict[str, Dict[str, Any]] = {}
    report: Dict[str, Any] = {
        "version": EXPORT_VERSION,
        "source_apk": apk_path.name,
        "source_apk_sha256": _sha256(apk_path.read_bytes()),
        **inner_report,
    }

    with zipfile.ZipFile(apk_path, "r") as outer:
        outer_mapped_paths: Set[str] = set()
        try:
            arsc_info = next(
                x for x in outer.infolist()
                if not x.is_dir() and _normal_name(x.filename).lower() == "resources.arsc"
            )
            outer_mapped_paths = arsc_file_paths(outer.read(arsc_info))
        except Exception:
            outer_mapped_paths = set()

        # V114 exports only decrypted assets/res/**. APK compiled res/** is not
        # part of the source package and must never enter the public ZIP.
        outer_exclude = outer_mapped_paths if inner_bytes is not None else set()
        outer_data, outer_meta = _read_resource_members(
            outer,
            include_res=False,
            include_assets=True,
            exclude_assets=set(),
            skip_zero=True,
        )
        for name, payload in outer_data.items():
            merged[name] = payload
            origins[name] = "outer"
            hashes[name] = outer_meta[name]
        report.update({
            "outer_arsc_file_path_count": len(outer_mapped_paths),
            "outer_exported_count": len(outer_data),
            "outer_mapped_assets_skipped": len([
                x for x in outer_mapped_paths if x.lower().startswith("assets/res/")
            ]) if inner_bytes is not None else 0,
        })

    if inner_bytes is not None:
        if not zipfile.is_zipfile(io.BytesIO(inner_bytes)):
            raise ResourceExportError("restored inner payload is not a ZIP")
        with zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner:
            inner_data, inner_meta = _read_resource_members(
                inner,
                include_res=False,
                include_assets=True,
                skip_zero=True,
            )
        for name, payload in inner_data.items():
            merged[name] = payload
            origins[name] = "inner"
            hashes[name] = inner_meta[name]
        report["inner_exported_count"] = len(inner_data)
    else:
        report["inner_exported_count"] = 0

    report["exported_count"] = len(merged)
    report["exported_bytes"] = sum(len(x) for x in merged.values())
    report["res_count"] = sum(1 for x in merged if x.lower().startswith("res/"))
    report["assets_res_count"] = sum(1 for x in merged if x.lower().startswith("assets/res/"))
    report["origins"] = {
        "inner": sum(1 for x in origins.values() if x == "inner"),
        "outer": sum(1 for x in origins.values() if x == "outer"),
    }
    report["files"] = [
        {"path": name, "origin": origins[name], **hashes[name]}
        for name in sorted(merged)
    ]
    return merged, report


def export_resources(
    apk_path: Path | str,
    out_dir: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    resources, report = collect_resources(apk_path, options)
    if not resources:
        report["exported"] = False
        report["reason"] = "no resource members found"
        return report

    root = out_dir.resolve()
    written = 0
    unchanged = 0
    for name, payload in resources.items():
        target = (out_dir / name).resolve()
        try:
            target.relative_to(root)
        except Exception as exc:
            raise ResourceExportError("resource path escapes output directory") from exc
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.is_file():
            try:
                if target.read_bytes() == payload:
                    unchanged += 1
                    continue
            except Exception:
                pass
        tmp = target.with_name(target.name + ".iapt-resource-tmp")
        tmp.write_bytes(payload)
        os.replace(tmp, target)
        written += 1

    report["exported"] = True
    report["written_count"] = written
    report["unchanged_count"] = unchanged
    manifest_path = out_dir / MANIFEST_NAME
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    report["manifest"] = str(manifest_path)
    return report


def build_resource_zip(
    apk_path: Path | str,
    output_zip: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    output_zip = Path(output_zip)
    output_zip.parent.mkdir(parents=True, exist_ok=True)
    resources, report = collect_resources(apk_path, options)
    report["exported"] = bool(resources)
    report_bytes = json.dumps(report, ensure_ascii=False, indent=2).encode("utf-8")
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as out:
        for name in sorted(resources):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(info, resources[name])
        info = zipfile.ZipInfo(MANIFEST_NAME, date_time=(1980, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        out.writestr(info, report_bytes)
    report["output_zip"] = str(output_zip)
    report["output_zip_size"] = output_zip.stat().st_size
    report["output_zip_sha256"] = _sha256(output_zip.read_bytes())
    return report


def _self_test() -> int:
    with tempfile.TemporaryDirectory(prefix="iapt_qs_resource_test_") as td:
        root = Path(td)
        apk = root / "test.apk"
        out = root / "out"
        with zipfile.ZipFile(apk, "w", compression=zipfile.ZIP_DEFLATED) as z:
            z.writestr("res/drawable/test.png", b"\x89PNG\r\n\x1a\nTEST")
            z.writestr("assets/res/test.html", b"<html>test</html>")
        report = export_resources(apk, out, {})
        assert report.get("exported") is True
        assert (out / "res/drawable/test.png").read_bytes().startswith(b"\x89PNG")
        assert not (out / "assets").exists()
        assert (out / MANIFEST_NAME).is_file()
    print("self-test ok")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Export anti-QiuShui hidden resources")
    parser.add_argument("apk", nargs="?", type=Path)
    parser.add_argument("output", nargs="?", type=Path)
    parser.add_argument("--zip", action="store_true", help="write one ZIP instead of a directory tree")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)
    if args.self_test:
        return _self_test()
    if args.apk is None or args.output is None:
        parser.error("apk and output are required")
    if args.zip:
        report = build_resource_zip(args.apk, args.output)
    else:
        report = export_resources(args.apk, args.output)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
