#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Restore iAPEC numeric dynamic-dispatch calls in decrypted iApp source.

This is intentionally part of feature 5 (动态修复), not feature 17.  It is
independent from the high-efficiency string decoder.  The existing iAPT
numeric-function restore still runs as well, so both the historical random
numeric table and ``iApEcPro-##########(...)`` are supported by one switch.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any, Iterator

VERSION = "iapec-dynamic-v13-zhaoling-profile+legacy-numeric"
CALL_RE = re.compile(r"\biApEcPro-(\d{10})(?=\s*\()")

# Exact command semantics recovered from the sample's own DynamicEncryption
# dispatcher.  Only IDs actually used by this protection build are included;
# unknown IDs are preserved rather than guessed.
ZHAOLING_DYNAMIC_MAP: dict[str, str] = {
    "0128184420": "hws",
    "0589244614": "tw",
    "0758530254": "end",
    "0804492180": "uigo",
    "1304402679": "sr",
    "1758950485": "iapec_asset_extract",
    "2615907201": "call",
    "2751167783": "sit",
    "3363103160": "tws",
    "3382757016": "addv",
    "3808326450": "dhast",
    "3905055444": "java",
    "3944069003": "sutf8to",
    "4045759550": "ufnsui",
    "4798542220": "iapec_keyevent_dispatch",
    "5011660200": "uit",
    "5728552058": "hs",
    "5749728861": "loadjar",
    "6069637318": "cls",
    "6103445985": "s",
    "6157413686": "usjxm",
    "6741741633": "us",
    "7359267430": "ug",
    "7420335218": "res",
    "7903851016": "ssg",
    "8064808819": "fdir",
    "8126168567": "dh",
    "8662769078": "simei",
    "8702947686": "dhon",
    "9128357958": "javanew",
    "9262107522": "sbp",
    "9822345035": "uapp",
}

_TEXT_SUFFIXES = {
    ".iyu", ".myu", ".mjava", ".ijava", ".mlua", ".ilua", ".mjs",
    ".ijs", ".java", ".lua", ".js", ".txt", ".xml", ".json", ".bin",
}
_SKIP_NAMES = {"classes.dex", "resources.arsc", "androidmanifest.xml"}


def _looks_text(data: bytes) -> bool:
    if not data or b"\x00" in data[: min(len(data), 1024 * 1024)]:
        return False
    sample = data[: min(len(data), 256 * 1024)]
    controls = sum(1 for b in sample if b < 9 or 13 < b < 32)
    return controls <= max(8, len(sample) // 100)


def _iter_text_files(out_dir: str | Path) -> Iterator[Path]:
    root = Path(out_dir)
    source = root / "src" if (root / "src").is_dir() else root
    if not source.is_dir():
        return
    for path in sorted(source.rglob("*"), key=lambda p: str(p).lower()):
        if not path.is_file() or path.name.lower() in _SKIP_NAMES:
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if b"iApEcPro-" not in data:
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES and not _looks_text(data):
            continue
        yield path


def inspect_iapec_dynamic_source(source_path: str | Path | None) -> dict[str, Any]:
    path = Path(source_path) if source_path else Path()
    report: dict[str, Any] = {
        "source_present": bool(path and path.is_file()),
        "detected": False,
        "profile": "",
        "markers": [],
    }
    if not path or not path.is_file():
        return report
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                names = [n.replace("\\", "/") for n in zf.namelist()]
                joined = "\n".join(names).lower()
                if "iapecpro" in joined or "libefficient.so" in joined or "libdestruction.so" in joined:
                    report["detected"] = True
                    report["markers"].append("iapec-apk-members")
                # String-pool scan is bounded and only used as a profile marker.
                for name in names:
                    if not re.fullmatch(r"classes\d*\.dex", Path(name).name, re.I):
                        continue
                    data = zf.read(name)
                    hits = sum(("iApEcPro-" + key + "(").encode() in data for key in ZHAOLING_DYNAMIC_MAP)
                    if hits >= 8:
                        report["detected"] = True
                        report["profile"] = "zhaoling-dynamic-2024"
                        report["markers"].append(f"{name}:known-ids={hits}")
                        break
        else:
            data = path.read_bytes()
            hits = sum(("iApEcPro-" + key + "(").encode() in data for key in ZHAOLING_DYNAMIC_MAP)
            if hits >= 8:
                report.update({"detected": True, "profile": "zhaoling-dynamic-2024"})
                report["markers"].append(f"raw-dex:known-ids={hits}")
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    return report


def restore_iapec_dynamic_text(text: str, mapping: dict[str, str] | None = None) -> tuple[str, dict[str, Any]]:
    mapping = dict(mapping or ZHAOLING_DYNAMIC_MAP)
    counts: dict[str, int] = {}
    unknown: dict[str, int] = {}

    def repl(match: re.Match[str]) -> str:
        ident = match.group(1)
        command = mapping.get(ident)
        if not command:
            unknown[ident] = unknown.get(ident, 0) + 1
            return match.group(0)
        counts[ident] = counts.get(ident, 0) + 1
        return command

    restored = CALL_RE.sub(repl, str(text or ""))
    return restored, {
        "matched_count": sum(counts.values()) + sum(unknown.values()),
        "restored_count": sum(counts.values()),
        "remaining_count": sum(unknown.values()),
        "mapping_count": len(mapping),
        "used_mapping": {key: mapping[key] for key in counts},
        "replacement_counts": counts,
        "unknown_ids": unknown,
    }


def restore_iapec_dynamic_project(
    out_dir: str | Path,
    source_path: str | Path | None = None,
    *,
    enabled: bool = True,
) -> dict[str, Any]:
    root = Path(out_dir)
    source_report = inspect_iapec_dynamic_source(source_path)
    report: dict[str, Any] = {
        "version": VERSION,
        "enabled": bool(enabled),
        "detected": bool(source_report.get("detected")),
        "profile": source_report.get("profile") or "zhaoling-dynamic-2024-source-match",
        "source": source_report,
        "files_scanned": 0,
        "changed_files": 0,
        "matched_count": 0,
        "restored_count": 0,
        "remaining_count": 0,
        "unknown_ids": {},
        "files": [],
    }
    if not enabled or not root.is_dir():
        return report
    for path in _iter_text_files(root):
        report["files_scanned"] += 1
        data = path.read_bytes()
        decoded = None
        encoding = ""
        for candidate in ("utf-8", "gb18030", "gbk"):
            try:
                decoded = data.decode(candidate)
                encoding = candidate
                break
            except UnicodeDecodeError:
                continue
        if decoded is None:
            continue
        restored, local = restore_iapec_dynamic_text(decoded)
        report["matched_count"] += int(local["matched_count"])
        report["restored_count"] += int(local["restored_count"])
        report["remaining_count"] += int(local["remaining_count"])
        for key, value in local["unknown_ids"].items():
            report["unknown_ids"][key] = report["unknown_ids"].get(key, 0) + int(value)
        if restored == decoded:
            continue
        try:
            payload = restored.encode(encoding)
        except UnicodeEncodeError:
            encoding = "utf-8"
            payload = restored.encode("utf-8")
        path.write_bytes(payload)
        report["changed_files"] += 1
        report["files"].append({
            "path": str(path.relative_to(root)).replace("\\", "/"),
            "encoding": encoding,
            "restored_count": int(local["restored_count"]),
            "remaining_count": int(local["remaining_count"]),
        })
    report["detected"] = bool(report["detected"] or report["matched_count"])
    tmp = root / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "iapt_iapec_dynamic_restore.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), "utf-8"
    )
    return report
