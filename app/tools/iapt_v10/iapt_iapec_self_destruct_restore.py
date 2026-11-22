#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Restore control types hidden by iAPEC self-destruction protection.

The exact ZhaoLing sample profile is recovered from libDestruction.so and the
protected layout semantics.  A conservative property-based fallback handles
compatible samples without inventing ambiguous types.
"""
from __future__ import annotations

import json
import re
import zipfile
from pathlib import Path
from typing import Any, Iterator

VERSION = "anti-iapec-self-destruct-v13-control-type-backfill"
HASH_RE = re.compile(r"^[0-9a-f]{5}$", re.I)
VIEW_RE = re.compile(r"(<View\b[^>]*\btype=\")([0-9a-f]{5})(\"[^>]*>[\s\S]*?</View>)", re.I)

# Exact mapping validated on 昭凌CPP工具重制版.  These are iApp source type names,
# not Java class names.
ZHAOLING_CONTROL_MAP: dict[str, str] = {
    "4c28e": "RelativeLayout",
    "9a14f": "LinearLayout",
    "73034": "TextView",
    "bd6e8": "CardView",
    "a4bdd": "RoundImageView",
    "f38c2": "ImageView",
}


def inspect_self_destruct_apk(apk_path: str | Path | None) -> dict[str, Any]:
    path = Path(apk_path) if apk_path else Path()
    result: dict[str, Any] = {"apk_present": bool(path and path.is_file()), "detected": False, "markers": [], "profile": ""}
    if not path or not path.is_file() or not zipfile.is_zipfile(path):
        return result
    try:
        with zipfile.ZipFile(path) as zf:
            names = [n.replace("\\", "/") for n in zf.namelist()]
            low = "\n".join(names).lower()
            if "libdestruction.so" in low:
                result["detected"] = True
                result["markers"].append("libDestruction.so")
            if "protect_655.txt" in low or "destruction0" in low:
                result["detected"] = True
                result["markers"].append("self-destruction-marker")
            hashes = set()
            for name in names:
                if name.lower().endswith("libdestruction.so"):
                    data = zf.read(name)
                    hashes.update(key for key in ZHAOLING_CONTROL_MAP if key.encode() in data)
                    if len(hashes) >= 4:
                        result["profile"] = "zhaoling-control-types-2024"
                        result["markers"].append("known-control-hashes=" + str(len(hashes)))
                        break
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
    return result


def _iter_layout_files(out_dir: str | Path) -> Iterator[Path]:
    root = Path(out_dir)
    source = root / "src" if (root / "src").is_dir() else root
    if not source.is_dir():
        return
    for path in sorted(source.rglob("*"), key=lambda p: str(p).lower()):
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if b"<View" in data and b'type="' in data and b"\x00" not in data[:65536]:
            yield path


def _infer_from_view_block(block: str) -> str | None:
    low = block.lower()
    if "app_cardelevation=" in low or "app_cardcornerradius=" in low or "app_cardbackgroundcolor=" in low:
        return "CardView"
    if "orientation=" in low:
        return "LinearLayout"
    if re.search(r"(?m)^text(?:size|color|style)?=", low) and "src=" not in low:
        return "TextView"
    if "src=" in low:
        # Generic fallback cannot prove round-vs-normal; use the standard image
        # control unless the exact native profile supplied the answer.
        return "ImageView"
    return None


def restore_control_types_text(text: str, mapping: dict[str, str] | None = None) -> tuple[str, dict[str, Any]]:
    exact = {k.lower(): v for k, v in (mapping or ZHAOLING_CONTROL_MAP).items()}
    replacements: dict[str, int] = {}
    unresolved: dict[str, int] = {}

    def repl(match: re.Match[str]) -> str:
        token = match.group(2).lower()
        block = match.group(0)
        control = exact.get(token) or _infer_from_view_block(block)
        if not control:
            unresolved[token] = unresolved.get(token, 0) + 1
            return block
        replacements[token] = replacements.get(token, 0) + 1
        return match.group(1) + control + match.group(3)

    restored = VIEW_RE.sub(repl, str(text or ""))
    return restored, {
        "restored_count": sum(replacements.values()),
        "remaining_count": sum(unresolved.values()),
        "replacements": replacements,
        "unresolved": unresolved,
    }


def restore_iapec_self_destruct_project(
    out_dir: str | Path,
    apk_path: str | Path | None = None,
    *,
    enabled: bool = True,
) -> dict[str, Any]:
    root = Path(out_dir)
    inspect = inspect_self_destruct_apk(apk_path)
    report: dict[str, Any] = {
        "version": VERSION,
        "enabled": bool(enabled),
        "detected": bool(inspect.get("detected")),
        "profile": inspect.get("profile") or "",
        "apk": inspect,
        "files_scanned": 0,
        "changed_files": 0,
        "restored_count": 0,
        "remaining_count": 0,
        "replacements": {},
        "unresolved": {},
        "files": [],
    }
    if not enabled or not root.is_dir():
        return report
    for path in _iter_layout_files(root):
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
        restored, local = restore_control_types_text(decoded)
        report["restored_count"] += int(local["restored_count"])
        report["remaining_count"] += int(local["remaining_count"])
        for key, value in local["replacements"].items():
            report["replacements"][key] = report["replacements"].get(key, 0) + int(value)
        for key, value in local["unresolved"].items():
            report["unresolved"][key] = report["unresolved"].get(key, 0) + int(value)
        if restored == decoded:
            continue
        try:
            payload = restored.encode(encoding)
        except UnicodeEncodeError:
            payload = restored.encode("utf-8")
            encoding = "utf-8"
        path.write_bytes(payload)
        report["changed_files"] += 1
        report["files"].append({"path": str(path.relative_to(root)).replace("\\", "/"), "restored_count": int(local["restored_count"])})
    report["detected"] = bool(report["detected"] or report["restored_count"] or report["remaining_count"])
    tmp = root / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "iapt_iapec_self_destruct_restore.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), "utf-8"
    )
    return report
