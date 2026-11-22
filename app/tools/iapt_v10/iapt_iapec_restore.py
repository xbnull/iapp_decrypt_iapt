#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Restore iAPEC "代码高效加密" strings in decrypted iApp project sources.

This module implements the exact decoder recovered from the sample's own
``libEfficient.so`` / ``libEfficientprotect.so`` implementation:

1. remove ``iApEcPro-代码高效加密-``;
2. map the ten emoji digits back to ASCII digits;
3. Base64-decode;
4. XOR bytes with the repeating UTF-8 key ``ZhaoLingYa``;
5. decode the result as UTF-8.

It is intentionally independent from the outer "反加密样本"/lib.so restore.
The caller decides whether the outer restore is enabled.  This module only
runs when the explicit ``anti_iapec_encryption`` option is true.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Iterable, Iterator

VERSION = "anti-iapec-v1-exact-efficient-native"
PREFIX = "iApEcPro-代码高效加密-"
KEY = "ZhaoLingYa".encode("utf-8")
EMOJI_TO_DIGIT = {
    "🥶": "0",
    "👀": "1",
    "🔞": "2",
    "🈲": "3",
    "🗿": "4",
    "🌞": "5",
    "🌚": "6",
    "👻": "7",
    "👿": "8",
    "💀": "9",
}
DIGIT_TO_EMOJI = {value: key for key, value in EMOJI_TO_DIGIT.items()}

# The encrypted payload is Base64 after emoji digit substitution.  Stop at any
# character which cannot be part of either representation.  This permits raw
# blocks, quoted arguments, XML values and normal iApp source lines.
_PAYLOAD_CHARS = r"A-Za-z0-9+/=_\-🥶👀🔞🈲🗿🌞🌚👻👿💀"
TOKEN_RE = re.compile(re.escape(PREFIX) + r"([" + _PAYLOAD_CHARS + r"]{4,})")

_TEXT_SUFFIXES = {
    ".iyu", ".myu", ".mjava", ".ijava", ".mlua", ".ilua",
    ".mjs", ".ijs", ".java", ".lua", ".js", ".txt", ".xml",
    ".json", ".html", ".htm", ".css", ".properties", ".ini",
    ".cfg", ".conf", ".md", ".bin",
}
_SKIP_DIR_NAMES = {".git", "__pycache__", ".gradle", "build"}
_SKIP_FILE_NAMES = {
    "classes.dex", "resources.arsc", "androidmanifest.xml",
    "iapt_iapec_restore.json",
}


def truthy(value: Any) -> bool:
    if value is True or value == 1:
        return True
    if value is False or value == 0 or value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _normalise_payload(payload: str) -> str:
    value = str(payload or "")
    for emoji, digit in EMOJI_TO_DIGIT.items():
        value = value.replace(emoji, digit)
    return value.strip()


def _decode_base64(payload: str) -> bytes:
    normal = _normalise_payload(payload)
    if not normal:
        raise ValueError("empty iAPEC payload")
    # Java's Base64 decoder accepts ordinary RFC4648.  Some packers omit the
    # terminal padding; add only the mathematically required amount.
    normal += "=" * ((4 - len(normal) % 4) % 4)
    errors: list[str] = []
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            if decoder is base64.b64decode:
                return decoder(normal.encode("ascii"), validate=False)
            return decoder(normal.encode("ascii"))
        except Exception as exc:
            errors.append(f"{type(exc).__name__}:{exc}")
    raise ValueError("invalid iAPEC Base64: " + " | ".join(errors))


def decode_iapec_payload(payload: str) -> str:
    encrypted = _decode_base64(payload)
    plain = bytes(value ^ KEY[index % len(KEY)] for index, value in enumerate(encrypted))
    # Android's default charset is UTF-8.  Strict decoding avoids replacing a
    # random false-positive Base64 token with corrupted source text.
    return plain.decode("utf-8", "strict")


def decode_iapec_string(value: str) -> tuple[str, bool]:
    text = str(value or "").strip()
    if not text.startswith(PREFIX):
        return str(value or ""), False
    payload = text[len(PREFIX):]
    return decode_iapec_payload(payload), True


def encode_iapec_string_for_test(value: str, *, emoji_digits: bool = False) -> str:
    """Inverse encoder used only by regression tests and sample validation."""
    raw = str(value).encode("utf-8")
    encrypted = bytes(byte ^ KEY[index % len(KEY)] for index, byte in enumerate(raw))
    payload = base64.b64encode(encrypted).decode("ascii")
    if emoji_digits:
        payload = "".join(DIGIT_TO_EMOJI.get(ch, ch) for ch in payload)
    return PREFIX + payload


def _replacement(match: re.Match[str], errors: list[dict[str, str]]) -> str:
    payload = match.group(1)
    try:
        return decode_iapec_payload(payload)
    except Exception as exc:
        errors.append({
            "payload_sha256": hashlib.sha256(payload.encode("utf-8", "replace")).hexdigest(),
            "error": f"{type(exc).__name__}: {exc}",
        })
        return match.group(0)


def restore_iapec_text(text: str, *, max_rounds: int = 5) -> tuple[str, dict[str, Any]]:
    current = str(text or "")
    total = 0
    rounds = 0
    errors: list[dict[str, str]] = []
    for round_index in range(1, max(1, int(max_rounds)) + 1):
        matches = list(TOKEN_RE.finditer(current))
        if not matches:
            break
        before = current
        local_errors: list[dict[str, str]] = []
        current = TOKEN_RE.sub(lambda match: _replacement(match, local_errors), current)
        replaced = sum(1 for match in matches if match.group(0) not in current or current != before)
        # Count exact successful replacements instead of merely matches.
        successful = len(matches) - len(local_errors)
        total += successful
        errors.extend(local_errors)
        rounds = round_index
        if successful <= 0 or current == before:
            break
    remaining = len(TOKEN_RE.findall(current))
    return current, {
        "matched_count": total + remaining,
        "restored_count": total,
        "remaining_count": remaining,
        "rounds": rounds,
        "errors": errors[:100],
    }


def restore_iapec_blob(blob: bytes, *, max_rounds: int = 5) -> tuple[bytes, dict[str, Any]]:
    data = bytes(blob or b"")
    if PREFIX.encode("utf-8") not in data:
        return data, {
            "matched_count": 0,
            "restored_count": 0,
            "remaining_count": 0,
            "rounds": 0,
            "encoding": "",
            "errors": [],
        }
    for encoding in ("utf-8", "gb18030", "gbk"):
        try:
            text = data.decode(encoding, "strict")
        except UnicodeDecodeError:
            continue
        restored, report = restore_iapec_text(text, max_rounds=max_rounds)
        report["encoding"] = encoding
        if restored == text:
            return data, report
        # Decrypted Java strings are UTF-8.  Keep the surrounding source's
        # original encoding where possible; fall back to UTF-8 if the restored
        # Chinese/code characters cannot be represented in a legacy codepage.
        try:
            return restored.encode(encoding), report
        except UnicodeEncodeError:
            report["encoding"] = "utf-8"
            return restored.encode("utf-8"), report
    return data, {
        "matched_count": 0,
        "restored_count": 0,
        "remaining_count": 0,
        "rounds": 0,
        "encoding": "binary-or-unknown",
        "errors": [{"error": "source text encoding could not be decoded"}],
    }


def _looks_textual(data: bytes) -> bool:
    if not data:
        return False
    sample = data[: min(len(data), 1024 * 1024)]
    if b"\x00" in sample:
        return False
    controls = sum(1 for byte in sample if byte < 9 or 13 < byte < 32)
    return controls <= max(8, len(sample) // 100)


def iter_project_text_files(out_dir: str | Path) -> Iterator[Path]:
    root = Path(out_dir)
    source_root = root / "src" if (root / "src").is_dir() else root
    if not source_root.is_dir():
        return
    for path in sorted(source_root.rglob("*"), key=lambda item: str(item).lower()):
        if not path.is_file():
            continue
        if any(part.lower() in _SKIP_DIR_NAMES for part in path.relative_to(source_root).parts[:-1]):
            continue
        if path.name.lower() in _SKIP_FILE_NAMES:
            continue
        try:
            data = path.read_bytes()
        except Exception:
            continue
        if PREFIX.encode("utf-8") not in data:
            continue
        if path.suffix.lower() not in _TEXT_SUFFIXES and not _looks_textual(data):
            continue
        yield path


def inspect_iapec_apk(apk_path: str | Path | None) -> dict[str, Any]:
    path = Path(apk_path) if apk_path else Path()
    report = {
        "apk_present": bool(path and path.is_file()),
        "detected": False,
        "markers": [],
        "efficient_native_libraries": [],
        "iapec_libraries": [],
    }
    if not path or not path.is_file() or not zipfile.is_zipfile(path):
        return report
    try:
        with zipfile.ZipFile(path, "r") as archive:
            names = [item.filename.replace("\\", "/") for item in archive.infolist() if not item.is_dir()]
    except Exception:
        return report
    low_map = {name.lower(): name for name in names}
    marker_needles = (
        "assets/iape cpro_protect/protect_代码高效加密.txt".replace(" ", ""),
        "assets/iapecpro_protect/protect_代码混淆加密.txt",
        "assets/iapecpro.so",
    )
    for low, original in low_map.items():
        if "iapecpro" in low:
            report["iapec_libraries"].append(original)
        if "libefficient" in low or "efficientprotect" in low:
            report["efficient_native_libraries"].append(original)
        if any(needle in low for needle in marker_needles):
            report["markers"].append(original)
    report["detected"] = bool(report["markers"] or report["efficient_native_libraries"])
    return report


def restore_iapec_project(
    out_dir: str | Path,
    apk_path: str | Path | None = None,
    *,
    enabled: bool = True,
    max_rounds: int = 5,
    write_report: bool = True,
) -> dict[str, Any]:
    root = Path(out_dir)
    apk_probe = inspect_iapec_apk(apk_path)
    report: dict[str, Any] = {
        "ok": True,
        "version": VERSION,
        "enabled": bool(enabled),
        "detected": bool(apk_probe.get("detected")),
        "apk_probe": apk_probe,
        "files_scanned": 0,
        "files_changed": [],
        "matched_count": 0,
        "restored_count": 0,
        "remaining_count": 0,
        "rounds": 0,
        "errors": [],
    }
    if not enabled:
        report["skipped"] = "option-disabled"
        return report
    if not root.is_dir():
        report.update({"ok": False, "error": "output directory does not exist"})
        return report

    # Repeat the whole tree pass so nested iAPEC strings revealed by a first
    # decode are restored before filename finalisation.
    for project_round in range(1, max(1, int(max_rounds)) + 1):
        changed_this_round = 0
        candidates = list(iter_project_text_files(root))
        report["files_scanned"] += len(candidates)
        for path in candidates:
            try:
                original = path.read_bytes()
                restored, item = restore_iapec_blob(original, max_rounds=max_rounds)
            except Exception as exc:
                report["errors"].append({
                    "file": str(path),
                    "error": f"{type(exc).__name__}: {exc}",
                })
                continue
            report["matched_count"] += int(item.get("matched_count") or 0)
            report["restored_count"] += int(item.get("restored_count") or 0)
            report["remaining_count"] += int(item.get("remaining_count") or 0)
            if restored == original:
                continue
            path.write_bytes(restored)
            changed_this_round += 1
            try:
                rel = str(path.relative_to(root)).replace("\\", "/")
            except Exception:
                rel = str(path)
            report["files_changed"].append(rel)
        report["rounds"] = project_round
        if changed_this_round <= 0:
            break

    # Recompute residual count once, avoiding duplicate counts across passes.
    residual = 0
    for path in iter_project_text_files(root):
        try:
            residual += len(TOKEN_RE.findall(path.read_text("utf-8", errors="ignore")))
        except Exception:
            pass
    report["remaining_count"] = residual
    report["files_changed"] = list(dict.fromkeys(report["files_changed"]))
    report["detected"] = bool(report["detected"] or report["matched_count"] or report["restored_count"])

    if write_report:
        diag = root / ".tmp" / "iapt_iapec_restore.json"
        try:
            diag.parent.mkdir(parents=True, exist_ok=True)
            diag.write_text(json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True), encoding="utf-8")
            report["report_path"] = str(diag)
        except Exception as exc:
            report["errors"].append({"error": f"write-report:{type(exc).__name__}:{exc}"})
    return report


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Restore iAPEC efficient-encrypted project source")
    parser.add_argument("out_dir")
    parser.add_argument("--apk", default="")
    parser.add_argument("--disabled", action="store_true")
    parser.add_argument("--decode", default=None)
    parser.add_argument("--encode-test", default=None)
    parser.add_argument("--emoji-digits", action="store_true")
    args = parser.parse_args(list(argv) if argv is not None else None)
    if args.decode is not None:
        value, changed = decode_iapec_string(args.decode)
        print(json.dumps({"changed": changed, "value": value}, ensure_ascii=False))
        return 0
    if args.encode_test is not None:
        print(encode_iapec_string_for_test(args.encode_test, emoji_digits=args.emoji_digits))
        return 0
    report = restore_iapec_project(args.out_dir, args.apk or None, enabled=not args.disabled)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
