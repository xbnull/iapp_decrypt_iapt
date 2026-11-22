from __future__ import annotations

import importlib
import zipfile
from pathlib import Path
from typing import Any, Dict

from . import db

META_COLS = ("app_name", "package_name", "version_name", "version_code")


def _clean(v: Any) -> str | None:
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() in ("none", "null", "undefined"):
        return None
    return s


def merge_meta_nonempty(*metas: Dict[str, Any] | None) -> Dict[str, str]:
    """按顺序合并元信息，只保留第一个非空值。"""
    out: Dict[str, str] = {}
    for meta in metas:
        if not isinstance(meta, dict):
            continue
        for k in META_COLS:
            v = _clean(meta.get(k))
            if v and not out.get(k):
                out[k] = v
    for meta in metas:
        if isinstance(meta, dict):
            v = _clean(meta.get("total_ms"))
            if v and not out.get("total_ms"):
                out["total_ms"] = v
    return out


def extract_v3_apk_meta(apk_path: str | Path) -> Dict[str, str]:
    """直接复用 V3 主 Python 中的 AXML/resources.arsc 分析函数读取 APK 元信息。"""
    apk_path = Path(apk_path)
    if not apk_path.exists() or apk_path.stat().st_size <= 0:
        return {}
    try:
        tool = importlib.import_module("app.tools.iapp_auto_decrypt")
    except Exception:
        return {}
    if not hasattr(tool, "parse_axml_manifest"):
        return {}

    try:
        with zipfile.ZipFile(apk_path, "r") as z:
            names = set(z.namelist())
            if "AndroidManifest.xml" not in names:
                return {}
            params = tool.parse_axml_manifest(z.read("AndroidManifest.xml")) or {}
            label = params.get("appLabel")
            if label and str(label).startswith("@") and "resources.arsc" in names and hasattr(tool, "resolve_arsc_string_ref"):
                try:
                    resolved = tool.resolve_arsc_string_ref(z.read("resources.arsc"), str(label))
                    if resolved:
                        label = resolved
                except Exception:
                    pass
            meta = {
                "package_name": params.get("package"),
                "version_name": params.get("versionName"),
                "version_code": params.get("versionCode"),
                "app_name": label,
            }
            return {k: _clean(v) for k, v in meta.items() if _clean(v)}
    except Exception:
        return {}


def update_task_meta_if_empty(task_id: int, meta: Dict[str, Any] | None, overwrite: bool = False) -> None:
    if not meta:
        return
    sets = []
    vals = []
    for col in META_COLS:
        v = _clean(meta.get(col))
        if not v:
            continue
        if overwrite:
            sets.append(f"{col}=%s")
        else:
            sets.append(f"{col}=CASE WHEN {col} IS NULL OR {col}='' OR {col}='null' THEN %s ELSE {col} END")
        vals.append(v)
    if not sets:
        return
    vals.append(int(task_id))
    db.exec("UPDATE tasks SET " + ",".join(sets) + " WHERE id=%s", tuple(vals))
