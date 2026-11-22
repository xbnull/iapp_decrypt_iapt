#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Final pass for old-iApp output after DEX-backed V3 event backfill.

The old container stores member names as MD5(sokey + "ysiapp" + filename).
Before DEX event recovery, some filenames exist only inside the compiled event
methods, so the first ancient decrypt pass cannot resolve them.  This module
rescans every restored source file after all-file event backfill, resolves those hashes,
renames _unknown members, refreshes old_iapp_report.json, and emits canonical
project metadata used by the normal V3 task-detail UI.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import sys
import unicodedata
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

OLD_START_SALT = "ysiapp"
TEXT_EXTENSIONS = (
    "iyu", "myu", "mjava", "ijava", "mlua", "ilua", "mjs", "ijs",
    "txt", "xml", "json", "html", "htm", "css", "js", "java", "lua",
)
PROJECT_MEMBER_EXTENSIONS = (
    "mjava", "myu", "iyu", "mlua", "mjs", "ijs", "ilua", "ijava",
)
_NAME_EXT_PATTERN = "|".join(re.escape(x) for x in TEXT_EXTENSIONS)
_NAME_CANDIDATE_RE = re.compile(
    r"(?<![\w./\\-])([\w\- .()\u4e00-\u9fff]{1,160}\.(?:"
    + _NAME_EXT_PATTERN + r"))(?!\w)",
    re.I,
)
_V3_DIRECT_NAME_RE = re.compile(
    r"([A-Za-z0-9_./\\\-\u0080-\uffff]{1,240}\.(?:"
    + "|".join(re.escape(x) for x in PROJECT_MEMBER_EXTENSIONS) + r"))(?![A-Za-z])",
    re.I,
)
# Keep the same reference grammar as the normal V3 filename parser.  The
# ancient post-backfill rescan used to omit CALL_MODULE_RE, which meant names
# that existed only in call(null,"mjava","set1.set",...) stayed in _unknown.
_V3_FN_MODULE_RE = re.compile(
    r"(?:^|[^A-Za-z0-9_./\\\-\u0080-\uffff])fn\s+"
    r"([A-Za-z_\u0080-\uffff][A-Za-z0-9_/\\\-\u0080-\uffff]*)\s*\.",
    re.I | re.M,
)
_V3_CALL_MODULE_RE = re.compile(
    r"call\s*\(\s*[^,\r\n)]*?\s*,\s*(['\"])([A-Za-z0-9_]+)\1\s*,\s*"
    r"(['\"])([A-Za-z_\u0080-\uffff][A-Za-z0-9_/\\\-\u0080-\uffff]*)\."
    r"[A-Za-z_\u0080-\uffff][A-Za-z0-9_\u0080-\uffff]*\3",
    re.I | re.S,
)
_V3_UIGO_ARG_RE = re.compile(
    r"(?<![A-Za-z0-9_.$])uigo\s*\(\s*(['\"])([^'\"\r\n]{1,300})\1",
    re.I,
)
_PROJECT_RECORD_RE = re.compile(
    r"^\s*(\d{1,12}),([0-9a-fA-F]{8,64}),([^,\r\n]{1,120}),(\d{10,20})\s*$"
)
_TEXT_SUFFIXES = {"." + x.lower() for x in TEXT_EXTENSIONS}

# V10 targeted hash-oracle candidate mining.  Normal V3 parsing remains the
# first pass.  This supplement is only for old containers, where unused modules
# can have no explicit call()/uigo()/fn reference anywhere in the project.
_IDENTIFIER_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_$]{0,119}|[\u3400-\u9fff]{1,40}", re.U
)
_CAMEL_PART_RE = re.compile(
    r"[A-Z]+(?=[A-Z][a-z]|[0-9]|$)|[A-Z]?[a-z]+|[0-9]+|[\u3400-\u9fff]+"
)
_IDENTIFIER_PREFIXES = (
    "st_", "st", "m_", "s_", "g_", "tmp_", "var_", "obj_", "str_",
)

_V3_FILENAME_EXTRACTOR = None
_V3_FILENAME_EXTRACTOR_SOURCE = ""


def _load_v3_filename_extractor():
    """Load the exact filename parser used by the deployed normal V3 engine.

    The server prefers app/tools/iapt_v10/iapp_auto_decrypt.py for normal V3
    tasks.  Ancient finalization must use that exact parser instead of carrying
    a second copy of its call/fn/uigo regular expressions, otherwise the two
    modes silently diverge after later V3 parser updates.
    """
    global _V3_FILENAME_EXTRACTOR, _V3_FILENAME_EXTRACTOR_SOURCE
    if _V3_FILENAME_EXTRACTOR is not None:
        return _V3_FILENAME_EXTRACTOR
    errors = []
    try:
        from .iapt_v10.iapp_auto_decrypt import extract_file_names_from_blob
        _V3_FILENAME_EXTRACTOR = extract_file_names_from_blob
        _V3_FILENAME_EXTRACTOR_SOURCE = "app.tools.iapt_v10.iapp_auto_decrypt"
        return _V3_FILENAME_EXTRACTOR
    except Exception as exc:
        errors.append(f"iapt_v10:{type(exc).__name__}:{exc}")
    try:
        from .iapp_auto_decrypt import extract_file_names_from_blob
        _V3_FILENAME_EXTRACTOR = extract_file_names_from_blob
        _V3_FILENAME_EXTRACTOR_SOURCE = "app.tools.iapp_auto_decrypt"
        return _V3_FILENAME_EXTRACTOR
    except Exception as exc:
        errors.append(f"tools:{type(exc).__name__}:{exc}")
    # Direct CLI fallback.  Prefer the iapt_v10 sibling because that is also
    # what the production V3 wrapper imports.
    here = Path(__file__).resolve().parent
    for folder in (here / "iapt_v10", here):
        try:
            if str(folder) not in sys.path:
                sys.path.insert(0, str(folder))
            from iapp_auto_decrypt import extract_file_names_from_blob
            _V3_FILENAME_EXTRACTOR = extract_file_names_from_blob
            _V3_FILENAME_EXTRACTOR_SOURCE = str(folder / "iapp_auto_decrypt.py")
            return _V3_FILENAME_EXTRACTOR
        except Exception as exc:
            errors.append(f"{folder}:{type(exc).__name__}:{exc}")
    raise RuntimeError("无法加载新版 V3 文件名解析器：" + " | ".join(errors))


def _extract_v3_member_names(data: bytes) -> set[str]:
    parser = _load_v3_filename_extractor()
    # hybrid is the production V3 default: direct extension scan plus call/fn/uigo.
    return set(parser(bytes(data or b""), scan_mode="hybrid") or ())


def _md5_hex(value: str) -> str:
    return hashlib.md5(value.encode("utf-8")).hexdigest()


def _safe_rel_name(value: str) -> str | None:
    value = unicodedata.normalize("NFC", str(value or "")).replace("\\", "/").strip().lstrip("/")
    if not value or "\x00" in value or len(value) > 320:
        return None
    parts = [part for part in value.split("/") if part not in ("", ".")]
    if not parts or any(part == ".." for part in parts):
        return None
    if any(any(ord(ch) < 32 for ch in part) for part in parts):
        return None
    return "/".join(parts)


def _decode_text(data: bytes) -> str:
    for encoding in ("utf-8", "gb18030", "gbk", "latin1"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


def _member_source_paths(src: Path, report: dict[str, Any]) -> dict[Path, bool]:
    """Return every decrypted member path and whether it is still unresolved."""
    result: dict[Path, bool] = {}
    root = src.parent.resolve()
    members = report.get("members") if isinstance(report.get("members"), list) else []
    for row in members:
        if not isinstance(row, dict):
            continue
        output = str(row.get("output") or "").replace("\\", "/").lstrip("/")
        if not output:
            continue
        path = (src.parent / output).resolve()
        try:
            path.relative_to(root)
        except Exception:
            continue
        if path.is_file():
            result[path] = not bool(str(row.get("resolved_name") or "").strip())
    return result


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[: min(len(data), 1024 * 1024)]
    if b"\x00" in sample:
        return False
    controls = sum(1 for byte in sample if byte < 9 or 13 < byte < 32)
    return controls <= max(8, len(sample) // 100)


def _source_files(src: Path, report: dict[str, Any]) -> list[tuple[Path, bool]]:
    if not src.is_dir():
        return []
    members = _member_source_paths(src, report)
    candidates: dict[Path, bool] = dict(members)
    for path in src.rglob("*"):
        if not path.is_file():
            continue
        unknown = False
        try:
            path.relative_to(src / "_unknown")
            unknown = True
        except Exception:
            pass
        if path.suffix.lower() in _TEXT_SUFFIXES or unknown:
            candidates[path.resolve()] = bool(candidates.get(path.resolve(), False) or unknown)
    rows: list[tuple[Path, bool]] = []
    for path, unknown in candidates.items():
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES and not _looks_textual(data):
            continue
        rows.append((path, unknown))
    rows.sort(key=lambda row: str(row[0]))
    return rows


def _clean_hash_candidate(value: str, default_ext: str | None = None) -> str | None:
    """Validate a hash candidate while preserving slash direction for MD5.

    Ancient containers hash the literal member name.  ``dir/a.mjava`` and
    ``dir\\a.mjava`` therefore need separate hash attempts even though both are
    written back to the same safe POSIX output path.
    """
    raw = unicodedata.normalize("NFC", str(value or "")).replace("\x00", "").strip().strip("\"'")
    if not raw:
        return None
    raw = re.sub(r"^(?:file:)?/*", "", raw, flags=re.I)
    while raw.startswith("./") or raw.startswith(".\\"):
        raw = raw[2:]
    raw = raw.lstrip("/\\").strip()
    if not raw:
        return None
    tail = re.split(r"[/\\]", raw)[-1]
    if default_ext and "." not in tail:
        raw += "." + default_ext.lstrip(".").lower()
    if "." not in raw:
        return None
    stem, ext = raw.rsplit(".", 1)
    ext = ext.lower()
    if ext not in TEXT_EXTENSIONS or not stem:
        return None
    parts = re.split(r"[/\\]+", stem)
    if any(part in ("", ".", "..") for part in parts):
        return None
    if any(any(ord(ch) < 32 for ch in part) for part in parts):
        return None
    return stem + "." + ext


def _hash_candidate_variants(
    value: str,
    default_ext: str | None = None,
    case_fallback: bool = False,
) -> list[tuple[str, str]]:
    """Return ``(literal_hash_name, safe_output_name)`` variants."""
    cleaned = _clean_hash_candidate(value, default_ext=default_ext)
    if not cleaned:
        return []
    raw_variants: list[str] = []
    for candidate in (
        cleaned,
        re.sub(r"[/\\]+", "/", cleaned),
        re.sub(r"[/\\]+", r"\\", cleaned),
    ):
        if candidate not in raw_variants:
            raw_variants.append(candidate)
    if case_fallback:
        for candidate in list(raw_variants):
            stem, ext = candidate.rsplit(".", 1)
            for alt_stem in (
                stem.lower(), stem.upper(), stem[:1].lower() + stem[1:], stem[:1].upper() + stem[1:],
            ):
                alt = alt_stem + "." + ext
                if alt_stem and alt not in raw_variants:
                    raw_variants.append(alt)
    result: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for literal in raw_variants:
        safe = _safe_rel_name(literal)
        if not safe:
            continue
        pair = (literal, safe)
        if pair not in seen:
            seen.add(pair)
            result.append(pair)
        base = Path(safe).name
        if base and base != safe:
            base_pair = (base, base)
            if base_pair not in seen:
                seen.add(base_pair)
                result.append(base_pair)
    return result



def _identifier_stem_variants(value: str) -> set[str]:
    raw = unicodedata.normalize("NFC", str(value or "")).strip().strip("\"'`")
    if not raw or len(raw) > 120:
        return set()
    raw = raw.replace("$", "_")
    seeds: set[str] = {raw}
    for sep in ("/", "\\", ".", ":"):
        for item in list(seeds):
            parts = [part for part in item.split(sep) if part]
            if parts:
                seeds.add(parts[-1]); seeds.add(parts[0])
    for item in list(seeds):
        pieces = [piece for piece in re.split(r"[_\-\s]+", item) if piece]
        seeds.update(pieces)
        if len(pieces) > 1:
            seeds.add("".join(pieces)); seeds.add(pieces[-1])
        low = item.lower()
        for prefix in _IDENTIFIER_PREFIXES:
            if low.startswith(prefix) and len(item) > len(prefix):
                seeds.add(item[len(prefix):])
    for item in list(seeds):
        parts = _CAMEL_PART_RE.findall(item)
        if parts:
            seeds.update(parts)
            seeds.add("".join(parts))
            seeds.add("".join(part.lower() for part in parts))
            if len(parts) > 1:
                seeds.add(parts[0]); seeds.add(parts[-1])
    out: set[str] = set()
    for item in seeds:
        item = item.strip("_-. ")
        if not item or len(item) > 100:
            continue
        for candidate in (
            item, item.lower(), item.upper(),
            item[:1].lower() + item[1:], item[:1].upper() + item[1:],
            re.sub(r"[_\-\s]+", "", item),
        ):
            if candidate and re.fullmatch(r"[A-Za-z0-9_\-\u3400-\u9fff]{1,100}", candidate):
                out.add(candidate)
    return out


def _numbered_family_variants(name: str, max_index: int = 99) -> set[str]:
    cleaned = _clean_hash_candidate(name)
    if not cleaned:
        return set()
    stem, ext = cleaned.rsplit(".", 1)
    directory = ""
    base_name = stem
    if "/" in stem or "\\" in stem:
        pos = max(stem.rfind("/"), stem.rfind("\\"))
        directory, base_name = stem[:pos + 1], stem[pos + 1:]
    base = re.sub(r"\d+$", "", base_name)
    if not base:
        return set()
    out = {f"{directory}{base}.{ext}"}
    for index in range(max(0, int(max_index)) + 1):
        out.add(f"{directory}{base}{index}.{ext}")
    return out


def _collect_candidates(
    src: Path,
    report: dict[str, Any],
    native_report: dict[str, Any],
) -> tuple[list[tuple[str, str]], dict[str, list[str]], dict[str, Any]]:
    ordered: list[tuple[str, str]] = []
    seen_literals: set[str] = set()
    evidence: dict[str, list[str]] = {}
    unknown_sources = 0
    unknown_candidate_hits = 0
    call_reference_hits = 0
    fn_reference_hits = 0
    uigo_reference_hits = 0
    members_for_hash = report.get("members") if isinstance(report.get("members"), list) else []
    unresolved_hashes: set[str] = {
        str(row.get("name_hash") or "").lower()
        for row in members_for_hash
        if isinstance(row, dict) and not str(row.get("resolved_name") or "").strip()
    }
    identifier_hash_attempts = 0
    identifier_hash_matches = 0
    numbered_family_hash_attempts = 0
    numbered_family_hash_matches = 0

    def add(
        name: str,
        source: str,
        from_unknown: bool = False,
        *,
        default_ext: str | None = None,
        case_fallback: bool = False,
    ) -> None:
        nonlocal unknown_candidate_hits
        for literal, safe in _hash_candidate_variants(
            name, default_ext=default_ext, case_fallback=case_fallback
        ):
            if literal not in seen_literals:
                seen_literals.add(literal)
                ordered.append((literal, safe))
            rows = evidence.setdefault(safe, [])
            if source not in rows and len(rows) < 12:
                rows.append(source)
            if from_unknown:
                unknown_candidate_hits += 1

    source_rows = _source_files(src, report)
    for path, from_unknown in source_rows:
        if from_unknown:
            unknown_sources += 1
        try:
            rel = path.relative_to(src).as_posix()
            data = path.read_bytes()
            text = _decode_text(data)
        except Exception:
            continue

        # Use the exact normal-V3 parser on the original bytes.  It owns all
        # production rules for direct names, call(...), fn module.method(),
        # uigo(...), slash variants, UTF-8/GB18030 names and case fallbacks.
        # Do not duplicate those rules here: that was the cause of ancient/V3
        # filename resolution drifting apart.
        try:
            v3_names = _extract_v3_member_names(data)
        except Exception:
            v3_names = set()
        for name in sorted(v3_names):
            add(name, rel, from_unknown)

        # Keep the legacy loose text matcher only as a supplement for old names
        # containing spaces or parentheses that the strict V3 member grammar
        # intentionally rejects.
        for match in _NAME_CANDIDATE_RE.finditer(text):
            add(match.group(1), rel, from_unknown)

        # Internal diagnostics only; user-facing metadata still exposes only
        # the final unknown-file count.
        call_reference_hits += len(_V3_CALL_MODULE_RE.findall(text))
        fn_reference_hits += len(_V3_FN_MODULE_RE.findall(text))
        uigo_reference_hits += len(_V3_UIGO_ARG_RE.findall(text))

    # V10 targeted full-source identifier pass.  Candidates are hashed
    # immediately and retained only when they match an unresolved member hash;
    # this keeps the broad scan fast even on projects with large import files.
    matched_hashes: set[str] = set()

    def try_candidate(name: str, source: str, from_unknown: bool = False, family: bool = False) -> None:
        nonlocal identifier_hash_attempts, identifier_hash_matches
        nonlocal numbered_family_hash_attempts, numbered_family_hash_matches
        if not unresolved_hashes:
            return
        for literal, safe in _hash_candidate_variants(name, case_fallback=True):
            digest = _md5_hex(str(report.get("sokey") or "") + OLD_START_SALT + literal)
            if family:
                numbered_family_hash_attempts += 1
            else:
                identifier_hash_attempts += 1
            if digest not in unresolved_hashes:
                continue
            add(literal, source, from_unknown)
            matched_hashes.add(digest)
            if family:
                numbered_family_hash_matches += 1
            else:
                identifier_hash_matches += 1

    # Numbered helper-module families first: set1.mjava -> set.mjava/set2.mjava.
    for row in members_for_hash:
        if not isinstance(row, dict):
            continue
        seed = str(row.get("resolved_name") or "").strip()
        if not seed:
            continue
        for sibling in _numbered_family_variants(seed):
            try_candidate(sibling, "编号同族:" + seed, family=True)

    # Then mine identifiers from every recovered text member, including files
    # still under _unknown. Examples recovered by this rule include load.mlua,
    # http.mjava, and snake/camel-derived stems such as st_sC -> sc.mlua.
    for path, from_unknown in source_rows:
        try:
            rel = path.relative_to(src).as_posix()
            text = _decode_text(path.read_bytes())
        except Exception:
            continue
        seen_stems: set[str] = set()
        for match in _IDENTIFIER_RE.finditer(text):
            for stem in _identifier_stem_variants(match.group(0)):
                if stem in seen_stems:
                    continue
                seen_stems.add(stem)
                for suffix in PROJECT_MEMBER_EXTENSIONS:
                    try_candidate(f"{stem}.{suffix}", rel + ":identifier", from_unknown)

    # A native-compiled page may never be referenced by another source file.
    # DEX class names under the Manifest package are therefore also tested as
    # ancient member-name candidates (class ``main`` -> ``main.iyu``).
    dex_page_candidates = native_report.get("dex_page_candidates")
    if isinstance(dex_page_candidates, list):
        for page in dex_page_candidates:
            page = str(page or "").strip()
            if page:
                for suffix in PROJECT_MEMBER_EXTENSIONS:
                    add(page, "DEX包名类", default_ext=suffix)

    stats = {
        "source_files_scanned": len(source_rows),
        "unknown_source_files_scanned": unknown_sources,
        "unknown_candidate_hits": unknown_candidate_hits,
        "dex_page_candidate_count": len(dex_page_candidates) if isinstance(dex_page_candidates, list) else 0,
        "call_reference_hits": call_reference_hits,
        "fn_reference_hits": fn_reference_hits,
        "uigo_reference_hits": uigo_reference_hits,
        "v3_filename_parser_source": _V3_FILENAME_EXTRACTOR_SOURCE,
        "identifier_hash_attempts": identifier_hash_attempts,
        "identifier_hash_matches": identifier_hash_matches,
        "numbered_family_hash_attempts": numbered_family_hash_attempts,
        "numbered_family_hash_matches": numbered_family_hash_matches,
    }
    return ordered, evidence, stats

def _unique_target(target: Path, source: Path) -> Path:
    if not target.exists() or target.resolve() == source.resolve():
        return target
    try:
        if target.is_file() and target.read_bytes() == source.read_bytes():
            return target
    except Exception:
        pass
    index = 2
    while True:
        candidate = target.with_name(f"{target.stem}_{index}{target.suffix}")
        if not candidate.exists():
            return candidate
        index += 1


def _move_member(src_root: Path, old_rel: str, new_name: str) -> tuple[str, str] | None:
    old_rel = str(old_rel or "").replace("\\", "/").lstrip("/")
    if old_rel.startswith("src/"):
        old_rel = old_rel[4:]
    old_path = src_root / old_rel
    if not old_path.is_file():
        return None
    safe = _safe_rel_name(new_name)
    if not safe:
        return None
    target = _unique_target(src_root / safe, old_path)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        try:
            if target.read_bytes() == old_path.read_bytes():
                old_path.unlink()
            else:
                return None
        except Exception:
            return None
    else:
        try:
            os.replace(old_path, target)
        except OSError:
            shutil.copy2(old_path, target)
            old_path.unlink()
    # Remove empty _unknown/package directories left by the move.
    parent = old_path.parent
    while parent != src_root:
        try:
            parent.rmdir()
        except OSError:
            break
        parent = parent.parent
    return old_rel, target.relative_to(src_root).as_posix()


def _parse_project_record(report: dict[str, Any], src: Path) -> tuple[str, dict[str, Any]]:
    raw = str(report.get("project_record") or "").strip()
    public_file = src / "project_metadata.txt"
    if not raw and public_file.is_file():
        try:
            for line in public_file.read_text("utf-8", errors="replace").splitlines():
                match = _PROJECT_RECORD_RE.match(line)
                if match:
                    raw = match.group(0).strip()
                    break
        except Exception:
            pass
    match = _PROJECT_RECORD_RE.match(raw)
    if not match:
        return raw, {}
    packer_id, uuid, model, timestamp_raw = match.groups()
    timestamp = int(timestamp_raw)
    timestamp_ms = timestamp * 1000 if timestamp < 100_000_000_000 else timestamp
    meta: dict[str, Any] = {
        "project_decrypted": True,
        "project_file": "src/project_metadata.txt",
        "project_bytes": len(raw.encode("utf-8")),
        "packer_id": packer_id,
        "uuid": uuid,
        "device_model": model.strip(),
        "build_timestamp_ms": timestamp_ms,
        "raw_record": raw,
    }
    try:
        meta["build_time"] = datetime.fromtimestamp(timestamp_ms / 1000.0).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return raw, meta


def _write_project_metadata(
    out_dir: Path,
    src: Path,
    meta: dict[str, Any],
    filename_report: dict[str, Any],
    native_report: dict[str, Any],
) -> dict[str, Any]:
    internal = out_dir / ".tmp" / "meta.json"
    internal.parent.mkdir(parents=True, exist_ok=True)
    canonical = dict(meta)
    canonical.update({
        "project_decrypted": True,
        "project_file": "src/project_metadata.txt",
        "decrypt_scheme": "ancient",
        "unknown_file_count": int(filename_report.get("unknown_remaining") or 0),
    })
    temp = internal.with_suffix(".json.tmp")
    temp.write_text(json.dumps(canonical, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
    temp.replace(internal)

    public_file = src / "project_metadata.txt"
    public_file.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "iAPT V3 项目解密信息",
        "方案=远古兼容模式",
        "project_decrypted=true",
        f"打包者ID={canonical.get('packer_id', '未识别')}",
        f"UUID={canonical.get('uuid', '未识别')}",
        f"打包机型={canonical.get('device_model', '未识别')}",
        f"打包毫秒时间戳={canonical.get('build_timestamp_ms', '')}",
        f"打包时间={canonical.get('build_time', '')}",
        f"未知文件数={canonical.get('unknown_file_count', 0)}",
    ]
    raw_record = str(canonical.get("raw_record") or "").strip()
    if raw_record:
        lines.append("原始记录=" + raw_record)
    public_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return canonical


def finalize_ancient_v3_output(
    out_dir: str | Path,
    native_report: dict[str, Any] | None = None,
) -> dict[str, Any]:
    out_dir = Path(out_dir).resolve()
    src = out_dir / "src"
    report_path = out_dir / "old_iapp_report.json"
    if not report_path.is_file():
        raise RuntimeError("缺少 old_iapp_report.json")
    report = json.loads(report_path.read_text("utf-8", errors="replace"))
    if not isinstance(report, dict) or report.get("ok") is not True:
        raise RuntimeError("old_iapp_report.json 无效")
    native_report = dict(native_report or {})
    sokey = str(report.get("sokey") or "").strip()
    if not sokey:
        raise RuntimeError("old_iapp_report.json 缺少 sokey")

    members = report.get("members") if isinstance(report.get("members"), list) else []
    previous_filename_report = report.get("filename_rescan") if isinstance(report.get("filename_rescan"), dict) else {}
    previous_total = int(previous_filename_report.get("resolved_after_backfill") or 0)
    previous_renamed = previous_filename_report.get("renamed") if isinstance(previous_filename_report.get("renamed"), list) else []

    renamed: list[dict[str, Any]] = []
    scan_stats_acc: dict[str, Any] = {}
    max_candidate_count = int(previous_filename_report.get("candidate_count") or 0)
    max_candidate_hash_count = int(previous_filename_report.get("candidate_hash_count") or 0)
    resolved_this_invocation = 0
    fixpoint_rounds: list[dict[str, Any]] = []

    # A newly restored name can reveal another name in the next pass.  For
    # example set1.mjava is identified from call(...), then its numbered module
    # family reveals set2.mjava.  Run the exact V3 candidate pipeline to a
    # bounded fixpoint before writing metadata and the public file index.
    for round_index in range(1, 6):
        candidates, evidence, scan_stats = _collect_candidates(src, report, native_report)
        candidate_by_hash: dict[str, str] = {}
        for literal_name, output_name in candidates:
            candidate_by_hash.setdefault(_md5_hex(sokey + OLD_START_SALT + literal_name), output_name)

        max_candidate_count = max(max_candidate_count, len(candidates))
        max_candidate_hash_count = max(max_candidate_hash_count, len(candidate_by_hash))
        for key, value in scan_stats.items():
            if isinstance(value, bool):
                scan_stats_acc[key] = bool(scan_stats_acc.get(key, False) or value)
            elif isinstance(value, int):
                scan_stats_acc[key] = max(int(scan_stats_acc.get(key) or 0), value)
            elif value and not scan_stats_acc.get(key):
                scan_stats_acc[key] = value

        round_renamed: list[dict[str, Any]] = []
        for row in members:
            if not isinstance(row, dict):
                continue
            name_hash = str(row.get("name_hash") or "").lower()
            candidate = candidate_by_hash.get(name_hash)
            if not candidate:
                continue
            current_name = str(row.get("resolved_name") or "").strip()
            output = str(row.get("output") or "").strip()
            needs_move = (not current_name) or output.replace("\\", "/").startswith("src/_unknown/")
            if needs_move:
                moved = _move_member(src, output, candidate)
                if moved:
                    old_rel, new_rel = moved
                    row["resolved_name"] = new_rel
                    row["output"] = "src/" + new_rel
                    row["resolved_after_v3_backfill"] = True
                    item = {
                        "name_hash": name_hash,
                        "from": "src/" + old_rel,
                        "to": "src/" + new_rel,
                        "evidence": evidence.get(candidate, []),
                        "fixpoint_round": round_index,
                    }
                    round_renamed.append(item)
                    renamed.append(item)
            elif current_name != candidate:
                row.setdefault("v3_backfill_candidate", candidate)

        resolved_in_round = len(round_renamed)
        resolved_this_invocation += resolved_in_round
        fixpoint_rounds.append({
            "round": round_index,
            "candidate_count": len(candidates),
            "candidate_hash_count": len(candidate_by_hash),
            "resolved": resolved_in_round,
        })
        if resolved_in_round == 0:
            break

    resolved_count = sum(1 for row in members if isinstance(row, dict) and str(row.get("resolved_name") or "").strip())
    unknown_count = max(0, len(members) - resolved_count)
    resolved_total = previous_total + resolved_this_invocation
    renamed_all: list[dict[str, Any]] = []
    renamed_seen: set[str] = set()
    for row in list(previous_renamed) + renamed:
        if not isinstance(row, dict):
            continue
        marker = json.dumps({k: v for k, v in row.items() if k != "fixpoint_round"}, ensure_ascii=False, sort_keys=True, default=str)
        if marker in renamed_seen:
            continue
        renamed_seen.add(marker)
        renamed_all.append(row)
    for key in ("source_files_scanned", "unknown_source_files_scanned", "unknown_candidate_hits", "dex_page_candidate_count", "call_reference_hits", "fn_reference_hits", "uigo_reference_hits", "identifier_hash_attempts", "identifier_hash_matches", "numbered_family_hash_attempts", "numbered_family_hash_matches"):
        scan_stats_acc[key] = max(int(scan_stats_acc.get(key) or 0), int(previous_filename_report.get(key) or 0))
    filename_report = {
        "ok": True,
        "version": "ancient-v3-filename-rescan-v10-real-apk-fixpoint",
        "candidate_count": max_candidate_count,
        "candidate_hash_count": max_candidate_hash_count,
        "resolved_this_round": resolved_this_invocation,
        "resolved_after_backfill": resolved_total,
        "resolved_name_count": resolved_count,
        "unknown_remaining": unknown_count,
        "fixpoint_rounds": fixpoint_rounds,
        "renamed": renamed_all,
        **scan_stats_acc,
    }
    report["members"] = members
    report["resolved_name_count"] = resolved_count
    report["unknown_name_count"] = unknown_count
    report["filename_rescan"] = filename_report
    report["native_compile_restore"] = {
        "enabled": bool(int(native_report.get("replaced_count") or 0) > 0),
        "replaced_count": int(native_report.get("replaced_count") or 0),
        "placeholder_count": int(native_report.get("placeholder_count") or 0),
        "manifest_package": str(native_report.get("manifest_package") or ""),
        "strategy": "manifest-package/exact-token/all-text-members/v3-syntax-backfill-before-filename-rescan",
        "rounds": int(native_report.get("rounds") or 1),
        "unknown_member_files_scanned": int(native_report.get("unknown_member_files_scanned") or 0),
        "unknown_replaced_count": int(native_report.get("unknown_replaced_count") or 0),
        "unknown_unresolved_count": int(native_report.get("unknown_unresolved_count") or 0),
    }

    raw_record, meta = _parse_project_record(report, src)
    if raw_record:
        report["project_record"] = raw_record
    meta = _write_project_metadata(out_dir, src, meta, filename_report, native_report)
    report["project_meta"] = meta

    report_path.write_text(json.dumps(report, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    diag_path = out_dir / ".tmp" / "ancient_v3_finalize.json"
    diag_path.parent.mkdir(parents=True, exist_ok=True)
    result = {
        "ok": True,
        "version": "ancient-v3-finalize-v10-real-apk-fixpoint",
        "filename_rescan": filename_report,
        "project_meta": meta,
        "native_compile_restore": report["native_compile_restore"],
        "old_iapp_report": report,
    }
    diag_path.write_text(json.dumps(result, ensure_ascii=False, sort_keys=True, indent=2), encoding="utf-8")
    return result


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir")
    parser.add_argument("--native-report", default="")
    args = parser.parse_args()
    native = {}
    if args.native_report:
        native = json.loads(Path(args.native_report).read_text("utf-8"))
    print(json.dumps(finalize_ancient_v3_output(args.out_dir, native), ensure_ascii=False, indent=2))
