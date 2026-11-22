#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
iAPT obfuscated APK probe v1

Purpose:
- Locate an iApp encrypted container even when assets/lib.so was renamed to a
  very long/high-entropy APK entry by a packer.
- Preserve sidecar metadata entries that share the long container path.
- Build high-priority server sokey candidates for packed libygsiyu.so samples,
  without requiring the hidden string to be visible in the packed ELF.

No third-party dependencies are required.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import hashlib
import json
import math
import re
import zipfile
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple


_HIDDEN_SUFFIX = b"Q" * 10 + b"W" * 10 + b"EE"
_HIDDEN_RE = re.compile(rb"[A-Za-z0-9]{10}Q{10}W{10}EE")
_HIDDEN_HEX_RE = re.compile(rb"[A-F0-9]{10}Q{10}W{10}EE")

_SOURCE_EXTENSIONS = {
    ".iyu", ".myu", ".mjava", ".mlua", ".mjs", ".ijs", ".ilua", ".ijava",
}
_EXCLUDED_EXTENSIONS = {
    ".dex", ".arsc", ".xml", ".html", ".htm", ".js", ".css", ".json",
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico",
    ".mp3", ".wav", ".ogg", ".m4a", ".mp4", ".mkv", ".avi", ".webm",
    ".ttf", ".otf", ".woff", ".woff2", ".so", ".jar", ".zip", ".apk",
    ".properties", ".mf", ".sf", ".rsa", ".dsa", ".ec",
}
_EXCLUDED_BASENAMES = {
    "androidmanifest.xml",
    "resources.arsc",
    "classes.dex",
    "classes2.dex",
    "classes3.dex",
}
_MAX_CONTAINER_SIZE = 512 * 1024 * 1024
_MIN_CONTAINER_SIZE = 64 * 1024


def _normal_name(value: str) -> str:
    return str(value or "").replace("\\", "/")


def _zip_datetime_epoch_beijing(date_time: Sequence[int]) -> int:
    """Interpret a ZIP timestamp as UTC+8, matching Android/iApp packing time."""
    year, month, day, hour, minute, second = [int(x) for x in date_time[:6]]
    tz = _dt.timezone(_dt.timedelta(hours=8))
    return int(_dt.datetime(year, month, day, hour, minute, second, tzinfo=tz).timestamp())


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = Counter(data)
    total = float(len(data))
    value = 0.0
    for count in counts.values():
        p = count / total
        value -= p * math.log(p, 2)
    return value


def _sample_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, limit: int = 65536) -> bytes:
    with zf.open(info, "r") as stream:
        head = stream.read(limit)
        if info.file_size <= limit * 2:
            return head + stream.read(limit)
        # ZIP streams are forward-only.  Sampling the first 64 KiB is enough for
        # the high-entropy discriminator and avoids inflating a large payload.
        return head


def _is_obvious_non_container(info: zipfile.ZipInfo) -> bool:
    name = _normal_name(info.filename)
    low = name.lower()
    base = low.rsplit("/", 1)[-1]

    if info.is_dir() or info.file_size < _MIN_CONTAINER_SIZE:
        return True
    if info.file_size > _MAX_CONTAINER_SIZE:
        return True
    if base in _EXCLUDED_BASENAMES:
        return True
    if low.startswith("meta-inf/"):
        return True
    if low.startswith("lib/") and low.endswith(".so"):
        return True
    if low.startswith("bsh/"):
        return True
    if low.startswith("res/"):
        return True

    suffix = Path(base).suffix.lower()
    if suffix in _EXCLUDED_EXTENSIONS or suffix in _SOURCE_EXTENSIONS:
        return True
    return False


def _container_score(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    infos: Sequence[zipfile.ZipInfo],
) -> Tuple[int, List[str], List[str], float]:
    name = _normal_name(info.filename)
    low = name.lower()
    reasons: List[str] = []
    score = 0

    if low == "assets/lib.so":
        return 100000, ["canonical assets/lib.so"], [], 0.0

    if low.startswith("assets/"):
        score += 25
        reasons.append("assets entry")

    name_len = len(name)
    if name_len >= 256:
        score += 35
        reasons.append("long name")
    if name_len >= 1024:
        score += 55
        reasons.append("very long name")
    if name_len >= 3000:
        score += 70
        reasons.append("extreme long name")

    depth = name.count("/")
    if depth >= 16:
        score += 25
        reasons.append("deep path")
    if depth >= 64:
        score += 35
        reasons.append("extreme path depth")

    non_ascii = sum(1 for ch in name if ord(ch) > 127)
    if non_ascii >= 16:
        score += 25
        reasons.append("non-ASCII path")
    if non_ascii >= max(32, name_len // 2):
        score += 25
        reasons.append("mostly non-ASCII path")

    if info.file_size >= 1024 * 1024:
        score += 25
        reasons.append("large payload")
    if info.file_size >= 4 * 1024 * 1024:
        score += 20
        reasons.append("multi-megabyte payload")

    if info.file_size:
        ratio = float(info.compress_size) / float(info.file_size)
        if ratio >= 0.80:
            score += 15
            reasons.append("poorly compressible")
        elif ratio >= 0.60:
            score += 7

    base = name.rsplit("/", 1)[-1]
    if "." not in base:
        score += 15
        reasons.append("extensionless")

    sidecars: List[str] = []
    for other in infos:
        if other is info or other.is_dir():
            continue
        other_name = _normal_name(other.filename)
        extra = len(other_name) - len(name)
        if (
            1 <= extra <= 32
            and other_name.startswith(name)
            and other.file_size <= 8192
        ):
            sidecars.append(other.filename)
    if sidecars:
        score += 85
        reasons.append("small path-suffix sidecar")

    sample_entropy = 0.0
    try:
        sample_entropy = _entropy(_sample_entry(zf, info))
        if sample_entropy >= 7.5:
            score += 25
            reasons.append("high entropy")
        elif sample_entropy >= 7.0:
            score += 12
    except Exception:
        pass

    return score, reasons, sidecars, sample_entropy


def locate_container(
    apk_path: Path | str,
    include_data: bool = False,
) -> Dict[str, object]:
    """Locate the encrypted iApp container inside an APK.

    Returns a dictionary with entry_name, sidecar_entries, metadata and optional
    data bytes.  The canonical assets/lib.so always wins.  Otherwise a scored
    structural scan identifies renamed long-path containers.
    """
    apk_path = Path(apk_path)
    with zipfile.ZipFile(apk_path, "r") as zf:
        infos = [item for item in zf.infolist() if not item.is_dir()]
        by_low = {_normal_name(item.filename).lower(): item for item in infos}

        canonical = by_low.get("assets/lib.so")
        if canonical is not None:
            result: Dict[str, object] = {
                "entry_name": canonical.filename,
                "sidecar_entries": [],
                "file_size": int(canonical.file_size),
                "compress_size": int(canonical.compress_size),
                "date_time": list(canonical.date_time),
                "timestamp_beijing": _zip_datetime_epoch_beijing(canonical.date_time),
                "score": 100000,
                "reasons": ["canonical assets/lib.so"],
                "entropy_sample": 0.0,
                "is_obfuscated": False,
                "locator": "canonical-v1",
            }
            if include_data:
                result["data"] = zf.read(canonical)
            return result

        ranked: List[Tuple[int, zipfile.ZipInfo, List[str], List[str], float]] = []
        for info in infos:
            if _is_obvious_non_container(info):
                continue
            score, reasons, sidecars, entropy = _container_score(zf, info, infos)
            ranked.append((score, info, reasons, sidecars, entropy))

        if not ranked:
            raise ValueError("encrypted container not found: no usable APK entry")

        ranked.sort(
            key=lambda row: (
                -row[0],
                -int(row[1].file_size),
                -len(_normal_name(row[1].filename)),
                _normal_name(row[1].filename),
            )
        )
        score, info, reasons, sidecars, entropy = ranked[0]

        # A renamed iApp container has multiple independent signals.  Refuse a
        # weak generic large file rather than silently decrypting the wrong blob.
        if score < 90:
            preview = [
                {
                    "entry": row[1].filename,
                    "size": int(row[1].file_size),
                    "score": int(row[0]),
                    "reasons": row[2],
                }
                for row in ranked[:5]
            ]
            raise ValueError(
                "encrypted container location is ambiguous: "
                + json.dumps(preview, ensure_ascii=False)
            )

        result = {
            "entry_name": info.filename,
            "sidecar_entries": list(sidecars),
            "file_size": int(info.file_size),
            "compress_size": int(info.compress_size),
            "date_time": list(info.date_time),
            "timestamp_beijing": _zip_datetime_epoch_beijing(info.date_time),
            "score": int(score),
            "reasons": list(reasons),
            "entropy_sample": round(float(entropy), 6),
            "is_obfuscated": True,
            "locator": "long-path-sidecar-v1",
        }
        if include_data:
            result["data"] = zf.read(info)
        return result


def _append_hidden(out: List[bytes], seen: Set[bytes], value: bytes) -> None:
    if not value or value in seen or not _HIDDEN_RE.fullmatch(value):
        return
    seen.add(value)
    out.append(value)


def extract_exact_sokeys_from_apk(
    apk_path: Path | str,
    max_candidates: int = 32,
) -> List[bytes]:
    """Find visible exact sokeys in any libygsiyu.so entry."""
    out: List[bytes] = []
    seen: Set[bytes] = set()
    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            name = _normal_name(info.filename).lower()
            if not (
                name == "libygsiyu.so"
                or (name.startswith("lib/") and name.endswith("/libygsiyu.so"))
            ):
                continue
            if info.file_size <= 0 or info.file_size > 128 * 1024 * 1024:
                continue
            data = zf.read(info)
            pos = data.find(_HIDDEN_SUFFIX)
            while pos >= 0:
                if pos >= 10:
                    _append_hidden(
                        out,
                        seen,
                        data[pos - 10 : pos + len(_HIDDEN_SUFFIX)],
                    )
                    if len(out) >= max_candidates:
                        return out
                pos = data.find(_HIDDEN_SUFFIX, pos + 1)
            for regex in (_HIDDEN_HEX_RE, _HIDDEN_RE):
                for match in regex.finditer(data):
                    _append_hidden(out, seen, match.group(0))
                    if len(out) >= max_candidates:
                        return out
    return out


def _sokey_from_ms_timestamp(timestamp_ms: int) -> bytes:
    prefix = hashlib.md5(str(int(timestamp_ms)).encode("ascii")).hexdigest()[:10].upper()
    return prefix.encode("ascii") + _HIDDEN_SUFFIX


def _is_qiushui_longpath_family(apk_path: Path | str) -> bool:
    try:
        container = locate_container(apk_path, include_data=False)
    except Exception:
        return False
    if not bool(container.get("is_obfuscated")):
        return False
    with zipfile.ZipFile(apk_path, "r") as zf:
        names = [_normal_name(item.filename).lower() for item in zf.infolist()]
    return any(name.startswith("bsh/qiushui/") for name in names)


def _priority_offsets(seconds: int, qiushui_family: bool) -> List[int]:
    seconds = max(1, int(seconds or 1))
    preferred = (
        [4, 3, 5, 2, 6, 1, 0, 7, 8, 9, 10, 11, 12]
        if qiushui_family
        else [0, 1, 2, 3, 4, 5, 8, 16, 24, 32, 33, 34, 35, 36, 40]
    )
    out: List[int] = []
    seen: Set[int] = set()
    for value in preferred:
        if 0 <= value < seconds and value not in seen:
            seen.add(value)
            out.append(value)
    for value in range(seconds):
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def _mtime_sources(
    apk_path: Path | str,
    max_files: int,
) -> List[Tuple[int, str]]:
    rows: List[Tuple[int, str, int]] = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        for info in zf.infolist():
            name = _normal_name(info.filename)
            low = name.lower()
            if "bsh/util/lib/" not in low or info.is_dir():
                continue
            rows.append(
                (
                    _zip_datetime_epoch_beijing(info.date_time),
                    info.filename,
                    int(info.file_size),
                )
            )

    # Entries commonly share the same timestamp.  Deduplicate by second while
    # keeping the largest representative file for diagnostics.
    by_sec: Dict[int, Tuple[str, int]] = {}
    for sec, name, size in rows:
        current = by_sec.get(sec)
        if current is None or size > current[1]:
            by_sec[sec] = (name, size)

    ordered = sorted(
        ((sec, name, size) for sec, (name, size) in by_sec.items()),
        key=lambda row: (-row[2], row[1]),
    )
    return [(sec, name) for sec, name, _size in ordered[: max(1, int(max_files or 1))]]


def build_fast_sokey_candidates(
    apk_path: Optional[Path | str],
    seconds: int = 180,
    max_files: int = 1,
    base_ts: Optional[int] = None,
    list_mtimes: bool = False,
    max_candidates: int = 0,
) -> List[bytes]:
    """Build high-priority sokey candidates for server_sokey.

    Order:
    1. Exact visible values from an unpacked/plain libygsiyu.so.
    2. Timestamp-derived candidates.  QiuShui long-path samples prioritize
       four seconds before bsh/util/lib mtime, matching its observed pack order.
    """
    if apk_path is None:
        return []

    apk_path = Path(apk_path)
    seconds = max(1, int(seconds or 180))
    max_files = max(1, int(max_files or 1))
    if int(max_candidates or 0) <= 0:
        max_candidates = seconds * 1000 * max_files + 32
    else:
        max_candidates = max(1, int(max_candidates))

    out: List[bytes] = []
    seen: Set[bytes] = set()

    for item in extract_exact_sokeys_from_apk(apk_path, max_candidates=32):
        _append_hidden(out, seen, item)
        if len(out) >= max_candidates:
            return out

    qiushui = _is_qiushui_longpath_family(apk_path)

    sources: List[Tuple[int, str]] = []
    if base_ts:
        raw = int(base_ts)
        if raw >= 10**12:
            exact = _sokey_from_ms_timestamp(raw)
            _append_hidden(out, seen, exact)
            sources.append((raw // 1000, "manual-ms"))
        else:
            sources.append((raw, "manual-sec"))
    else:
        sources.extend(_mtime_sources(apk_path, max_files))

    if list_mtimes:
        for sec, name in sources:
            print(
                "[IAPT_OBF] sokey mtime source: "
                f"entry={name} sec={sec} family="
                f"{'qiushui-longpath' if qiushui else 'generic'}",
                flush=True,
            )

    offsets = _priority_offsets(seconds, qiushui)
    for base_sec, name in sources:
        for back in offsets:
            second = int(base_sec) - int(back)
            first_ms = second * 1000
            for milli in range(1000):
                candidate = _sokey_from_ms_timestamp(first_ms + milli)
                _append_hidden(out, seen, candidate)
                if len(out) >= max_candidates:
                    return out
    return out


def probe_apk(apk_path: Path | str) -> Dict[str, object]:
    container = locate_container(apk_path, include_data=False)
    exact = extract_exact_sokeys_from_apk(apk_path)
    fast = build_fast_sokey_candidates(
        apk_path,
        seconds=12,
        max_files=1,
        list_mtimes=False,
        max_candidates=12032,
    )
    return {
        "apk": str(Path(apk_path)),
        "container": container,
        "exact_sokeys": [item.decode("ascii", "replace") for item in exact],
        "fast_sokey_count": len(fast),
        "fast_sokey_preview": [
            item.decode("ascii", "replace") for item in fast[:8]
        ],
        "family": (
            "qiushui-longpath"
            if _is_qiushui_longpath_family(apk_path)
            else "generic"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("apk", type=Path)
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--known-sokey", default="")
    args = parser.parse_args()

    result = probe_apk(args.apk)
    if args.known_sokey:
        candidates = build_fast_sokey_candidates(
            args.apk,
            seconds=180,
            max_files=1,
            max_candidates=180032,
        )
        target = args.known_sokey.encode("ascii")
        try:
            result["known_sokey_index"] = candidates.index(target)
        except ValueError:
            result["known_sokey_index"] = -1

    print(json.dumps(result, ensure_ascii=False, indent=2, default=str))


if __name__ == "__main__":
    main()
