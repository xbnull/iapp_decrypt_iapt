#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Canonical source-project layout helpers.

Public source tasks use exactly two roots::

    src/**
    res/**

The helpers below normalize only source-task input/output.  They never scan an
ordinary decrypt task or follow a database alias to another physical file.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Dict, Iterable, List, Sequence, Tuple

SOURCE_SUFFIXES = {
    ".iyu", ".myu", ".mjava", ".ijava",
    ".mlua", ".ilua", ".mjs", ".ijs",
    ".java", ".lua", ".js",
}
AUXILIARY_SOURCE_SUFFIXES = {".txt", ".xml", ".json", ".properties"}
PROJECT_SUFFIX = ".project"
PRIVATE_ROOT_NAMES = {
    ".tmp", ".iapt_internal", "logs", "reports", "analysis",
    "deep_code", "__pycache__", "apk", "assets",
}


class SourceLayoutError(ValueError):
    pass


def _normal_zip_name(value: str) -> str:
    text = str(value or "").replace("\\", "/")
    while text.startswith("./"):
        text = text[2:]
    return text


def _safe_parts(value: str) -> Tuple[str, ...]:
    name = _normal_zip_name(value)
    if not name or name.startswith("/") or "\x00" in name:
        raise SourceLayoutError("源码 ZIP 包含非法绝对路径")
    pure = PurePosixPath(name)
    parts = tuple(str(part) for part in pure.parts if str(part) not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        raise SourceLayoutError("源码 ZIP 包含目录穿越路径：" + name)
    if ":" in parts[0]:
        raise SourceLayoutError("源码 ZIP 包含非法盘符路径：" + name)
    return parts


def _is_zip_symlink(info: zipfile.ZipInfo) -> bool:
    mode = (int(info.external_attr or 0) >> 16) & 0xFFFF
    return stat.S_ISLNK(mode)


def _is_source_name(name: str, include_auxiliary: bool = False) -> bool:
    suffix = Path(str(name)).suffix.lower()
    return (
        suffix in SOURCE_SUFFIXES
        or suffix == PROJECT_SUFFIX
        or (include_auxiliary and suffix in AUXILIARY_SOURCE_SUFFIXES)
    )


def _is_real_source_name(name: str) -> bool:
    return Path(str(name)).suffix.lower() in SOURCE_SUFFIXES


def _safe_target(root: Path, parts: Sequence[str]) -> Path:
    target = root.joinpath(*parts)
    base = root.resolve()
    resolved_parent = target.parent.resolve()
    try:
        resolved_parent.relative_to(base)
    except Exception as exc:
        raise SourceLayoutError("输出路径越界：" + "/".join(parts)) from exc
    return target


def _choose_archive_layout(rows: List[Tuple[zipfile.ZipInfo, Tuple[str, ...]]]) -> Tuple[str, str]:
    """Return ``(mode, wrapper)`` for a source archive."""
    canonical = any(parts and parts[0].lower() == "src" for _info, parts in rows)
    if canonical:
        return "canonical", ""

    wrappers = {
        parts[0]
        for _info, parts in rows
        if len(parts) >= 2 and parts[1].lower() == "src"
    }
    if len(wrappers) == 1:
        return "wrapped-canonical", next(iter(wrappers))
    if len(wrappers) > 1:
        raise SourceLayoutError("源码 ZIP 中存在多个项目 src 根目录，无法安全合并")

    source_rows = [
        (info, parts) for info, parts in rows
        if _is_source_name(parts[-1])
    ]
    if not source_rows:
        raise SourceLayoutError("源码 ZIP 中没有找到 iApp 源码文件")

    direct = any(len(parts) == 1 for _info, parts in source_rows)
    if direct:
        return "legacy-flat", ""

    top_roots = {parts[0] for _info, parts in source_rows}
    if len(top_roots) == 1:
        wrapper = next(iter(top_roots))
        if wrapper.lower() in PRIVATE_ROOT_NAMES:
            raise SourceLayoutError("源码 ZIP 的旧版项目根目录不安全：" + wrapper)
        return "legacy-wrapper", wrapper
    raise SourceLayoutError("源码 ZIP 路径不统一：请使用 src/** 和 res/**")


def _map_archive_member(parts: Tuple[str, ...], mode: str, wrapper: str) -> Tuple[str, ...] | None:
    low = tuple(part.lower() for part in parts)

    if mode == "canonical":
        if low[0] not in ("src", "res"):
            return None
        return parts

    if mode == "wrapped-canonical":
        if parts[0] != wrapper or len(parts) < 3:
            return None
        if low[1] not in ("src", "res"):
            return None
        return parts[1:]

    if mode == "legacy-flat":
        if low[0] == "res" and len(parts) >= 2:
            return parts
        if low[0] == "src" and len(parts) >= 2:
            return parts
        # Old prepareSourceZip archives place source-root children directly at
        # ZIP root.  Do not infer nested arbitrary folders as source output.
        if len(parts) == 1 and _is_source_name(parts[-1], include_auxiliary=True):
            return ("src",) + parts
        return None

    if mode == "legacy-wrapper":
        if parts[0] != wrapper or len(parts) < 2:
            return None
        rel = parts[1:]
        rel_low = tuple(part.lower() for part in rel)
        if rel_low[0] in ("src", "res"):
            return rel
        if _is_source_name(rel[-1], include_auxiliary=True):
            return ("src",) + rel
        return None

    raise SourceLayoutError("未知源码 ZIP 布局：" + mode)


def extract_source_project_zip(
    source_zip: Path,
    out_dir: Path,
    *,
    max_entries: int = 100000,
    max_uncompressed_bytes: int = 512 * 1024 * 1024,
) -> Dict[str, object]:
    """Safely extract a source archive into canonical ``src``/``res`` roots."""
    source_zip = Path(source_zip)
    out_dir = Path(out_dir)
    if not source_zip.is_file() or source_zip.stat().st_size <= 0:
        raise SourceLayoutError("源码 ZIP 不存在或为空")

    out_dir.mkdir(parents=True, exist_ok=True)
    for child in list(out_dir.iterdir()):
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)

    with zipfile.ZipFile(source_zip, "r") as archive:
        infos = [info for info in archive.infolist() if not info.is_dir()]
        if len(infos) > max_entries:
            raise SourceLayoutError("源码 ZIP 文件数量过多")

        rows: List[Tuple[zipfile.ZipInfo, Tuple[str, ...]]] = []
        total_uncompressed = 0
        for info in infos:
            if _is_zip_symlink(info):
                raise SourceLayoutError("源码 ZIP 不允许包含符号链接：" + str(info.filename))
            parts = _safe_parts(info.filename)
            if any(part.startswith(".") for part in parts):
                # Never publish hidden metadata from the uploaded archive.
                continue
            total_uncompressed += max(0, int(info.file_size or 0))
            if total_uncompressed > max_uncompressed_bytes:
                raise SourceLayoutError("源码 ZIP 解压后体积超过限制")
            rows.append((info, parts))

        mode, wrapper = _choose_archive_layout(rows)
        mapped: List[Tuple[zipfile.ZipInfo, Tuple[str, ...]]] = []
        destinations: Dict[str, str] = {}
        for info, parts in rows:
            target_parts = _map_archive_member(parts, mode, wrapper)
            if not target_parts or len(target_parts) < 2:
                continue
            if target_parts[0].lower() not in ("src", "res"):
                continue
            if any(part in ("", ".", "..") or part.startswith(".") for part in target_parts):
                continue
            rel = "/".join(target_parts)
            key = rel.casefold()
            previous = destinations.get(key)
            if previous is not None:
                raise SourceLayoutError("源码 ZIP 存在重复输出路径：" + rel)
            destinations[key] = str(info.filename)
            mapped.append((info, target_parts))

        real_source_count = sum(
            1 for _info, parts in mapped
            if parts[0].lower() == "src" and _is_real_source_name(parts[-1])
        )
        if real_source_count <= 0:
            raise SourceLayoutError("源码 ZIP 中没有实际 iApp 源码文件")

        bytes_written = 0
        src_files = 0
        res_files = 0
        for info, target_parts in mapped:
            target = _safe_target(out_dir, target_parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info, "r") as source_stream, target.open("xb") as output_stream:
                shutil.copyfileobj(source_stream, output_stream, length=1024 * 1024)
            bytes_written += int(target.stat().st_size)
            if target_parts[0].lower() == "src":
                src_files += 1
            else:
                res_files += 1

    report: Dict[str, object] = {
        "version": 173,
        "layout": mode,
        "wrapper": wrapper,
        "source_zip": str(source_zip),
        "src_files": src_files,
        "res_files": res_files,
        "real_source_files": real_source_count,
        "bytes": bytes_written,
    }
    private = out_dir / ".tmp"
    private.mkdir(parents=True, exist_ok=True)
    (private / "source_layout_v173.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return report


def _same_file(left: Path, right: Path) -> bool:
    try:
        if left.stat().st_size != right.stat().st_size:
            return False
        with left.open("rb") as a, right.open("rb") as b:
            while True:
                aa = a.read(1024 * 1024)
                bb = b.read(1024 * 1024)
                if aa != bb:
                    return False
                if not aa:
                    return True
    except Exception:
        return False


def _move_with_conflict(source: Path, target: Path, private_root: Path) -> Tuple[int, int]:
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        if target.is_file() and _same_file(source, target):
            source.unlink(missing_ok=True)
            return 1, 0
        rel = target.name
        conflict = private_root / rel
        conflict.parent.mkdir(parents=True, exist_ok=True)
        index = 2
        while conflict.exists():
            conflict = private_root / (target.stem + "_" + str(index) + target.suffix)
            index += 1
        shutil.move(str(source), str(conflict))
        return 0, 1
    shutil.move(str(source), str(target))
    return 1, 0


def canonicalize_legacy_source_task(root: Path) -> Dict[str, object]:
    """Canonicalize an *existing source-only task* without broad recursion.

    Accepted legacy layouts are immediate root source files, one immediate
    project wrapper containing ``src``/``res``, or one immediate wrapper whose
    files are source members.  Multiple wrappers are deliberately refused.
    """
    root = Path(root)
    if not root.is_dir():
        return {"version": 173, "moved": 0, "conflicts": 0, "reason": "missing-root"}

    src_root = root / "src"
    res_root = root / "res"
    private_root = root / ".iapt_internal" / "layout_v173" / "conflicts"
    moved = conflicts = 0

    direct = [
        item for item in root.iterdir()
        if item.is_file() and not item.is_symlink() and _is_source_name(item.name, include_auxiliary=True)
    ]
    for source in direct:
        a, b = _move_with_conflict(source, src_root / source.name, private_root / "root")
        moved += a
        conflicts += b

    wrappers = []
    for candidate in root.iterdir():
        if not candidate.is_dir() or candidate.is_symlink():
            continue
        if candidate.name.lower() in {"src", "res"} | PRIVATE_ROOT_NAMES or candidate.name.startswith("."):
            continue
        canonical_src = candidate / "src"
        source_members = []
        if canonical_src.is_dir():
            source_members = [
                p for p in canonical_src.rglob("*")
                if p.is_file() and not p.is_symlink()
                and not any(part.startswith(".") for part in p.relative_to(canonical_src).parts)
            ]
        else:
            for path in candidate.rglob("*"):
                try:
                    if not path.is_file() or path.is_symlink():
                        continue
                    rel = path.relative_to(candidate)
                    if any(part.startswith(".") for part in rel.parts):
                        continue
                    if _is_source_name(path.name, include_auxiliary=True):
                        source_members.append(path)
                except Exception:
                    continue

        # A legacy wrapper without an explicit src/ root is accepted only when
        # it looks like an actual iApp project: it must contain mian/main source,
        # or a .project marker together with at least one real source member.
        # This prevents reports/secret.java-style diagnostic trees from being
        # promoted merely because they contain a code-looking suffix.
        real_members = [p for p in source_members if _is_real_source_name(p.name)]
        has_main = any(p.name.lower() in ("mian.iyu", "main.iyu") for p in real_members)
        has_project = any(Path(p.name).suffix.lower() == PROJECT_SUFFIX for p in source_members)
        trusted_wrapper = canonical_src.is_dir() or has_main or (has_project and bool(real_members))
        if source_members and trusted_wrapper:
            wrappers.append((candidate, canonical_src.is_dir(), source_members))

    if len(wrappers) == 1:
        wrapper, has_src_root, members = wrappers[0]
        source_base = wrapper / "src" if has_src_root else wrapper
        for source in members:
            try:
                rel = source.relative_to(source_base)
            except Exception:
                continue
            a, b = _move_with_conflict(source, src_root / rel, private_root / wrapper.name / "src")
            moved += a
            conflicts += b
        wrapped_res = wrapper / "res"
        if wrapped_res.is_dir():
            for source in wrapped_res.rglob("*"):
                if not source.is_file() or source.is_symlink():
                    continue
                rel = source.relative_to(wrapped_res)
                if any(part.startswith(".") or part in ("", ".", "..") for part in rel.parts):
                    continue
                a, b = _move_with_conflict(source, res_root / rel, private_root / wrapper.name / "res")
                moved += a
                conflicts += b
    elif len(wrappers) > 1:
        return {
            "version": 173,
            "moved": moved,
            "conflicts": conflicts,
            "ambiguous_wrappers": [row[0].name for row in wrappers[:8]],
        }

    report = {
        "version": 173,
        "moved": moved,
        "conflicts": conflicts,
        "src_files": sum(1 for p in src_root.rglob("*") if p.is_file()) if src_root.is_dir() else 0,
        "res_files": sum(1 for p in res_root.rglob("*") if p.is_file()) if res_root.is_dir() else 0,
    }
    if moved or conflicts:
        private = root / ".tmp"
        private.mkdir(parents=True, exist_ok=True)
        (private / "legacy_source_layout_v173.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    return report
