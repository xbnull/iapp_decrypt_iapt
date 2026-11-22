#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Restore iApp event source that was compiled into classes*.dex.

Some iApp "native compile" builds replace an ``<eventItme>`` body with a
12-hex token.  The original event source is still passed to Aid_YuCodeX from a
DEX method whose name is ``<event-type><token>``.  This module reconnects those
methods to every decrypted project source file containing event placeholders.  It supports both:

* newer builds where the iApp source is stored as ordinary DEX strings;
* older builds where strings are sliced from a class-local short[] and decoded
  by ``$(start, end, key)``.

It is intentionally fail-closed: compiler control-flow scaffolding is ignored,
while unresolved placeholders are kept unchanged and listed in a JSON report.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import traceback
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

try:
    from .iapp_dex2iyu_v6 import (
        Dex,
        EncodedMethod,
        dq_string,
        get_all_classes_dexes_from_apk_bytes,
        get_apk_bytes,
        get_package_name_from_apk_bytes,
        i4,
        parse_fill_array_payload_from_units,
        pseudo_event_method,
        reachable_instruction_offsets,
        simple_class_name,
        _split_balanced_args,
    )
except ImportError:  # direct CLI execution
    from iapp_dex2iyu_v6 import (  # type: ignore
        Dex,
        EncodedMethod,
        dq_string,
        get_all_classes_dexes_from_apk_bytes,
        get_apk_bytes,
        get_package_name_from_apk_bytes,
        i4,
        parse_fill_array_payload_from_units,
        pseudo_event_method,
        reachable_instruction_offsets,
        simple_class_name,
        _split_balanced_args,
    )

TOOL_VERSION = "7.0.0-all-text-token-slots-v3-syntax"
TOKEN_RE = re.compile(r"^[0-9a-fA-F]{12}$")
STANDALONE_TOKEN_RE = re.compile(
    r"(?m)^(?P<indent>[ \t]*)(?P<token>[0-9a-fA-F]{12})(?P<semi>[ \t]*;?)(?P<newline>\r?\n|$)"
)
FUNCTION_DECL_RE = re.compile(
    r"^[ \t]*fn[ \t]+(?P<name>[^\r\n(]+?)\s*\(", re.I
)
EVENT_RE = re.compile(
    r"(<eventItme\b(?P<attrs>[^>]*)>)(?P<body>\s*[0-9a-fA-F]{12}\s*)(</eventItme>)",
    re.S,
)
EVENT_TYPE_RE = re.compile(r"\btype\s*=\s*([\"'])(?P<value>.*?)\1", re.S)
DECODER_CALL_RE = re.compile(
    r"(?P<class>[\w$\u0080-\uffff]+(?:\.[\w$\u0080-\uffff]+)+)\.\$\("
    r"\s*(?P<start>-?\d+)\s*,\s*(?P<end>-?\d+)\s*,\s*(?P<key>-?\d+)\s*\)"
    r"(?:\.intern\(\))?"
)
ARG1_CALL_RE = re.compile(
    r"^(?:arg1|this)\.(?P<method>[A-Za-z_$][\w$]*)\((?P<args>.*)\)\s*;?$",
    re.S,
)
METHOD_RE = re.compile(r"^(?P<event>.+?)(?P<token>[0-9a-fA-F]{12})$")
AID_DESC = "Lcom/iapp/app/Aid_YuCodeX;"
SOURCE_ENCODINGS = ("utf-8", "gb18030", "gbk")
MAX_SOURCE_BYTES = 16 * 1024 * 1024

# Runtime/compiler helper calls.  They are not iApp source statements.
IGNORED_BRIDGE_METHODS = {
    "is", "booleanValue", "intValue", "longValue", "floatValue", "doubleValue",
}
METHOD_NAME_MAP = {
    "function": "fn",
    "for_y": "for",
    "if_y": "if",
    "switch_y": "switch",
}

SPACE_FORM_BRIDGE_METHODS = {"s", "ss", "sss", "sl", "dim", "dims"}
ZERO_ARG_COMMANDS = {
    "end", "ends", "break", "continue", "return", "stop", "t", "ufnsui",
}


def _normalize_v3_source(text: str) -> str:
    """Normalize recovered legacy snippets to the V3 call syntax.

    iApp function declarations intentionally use a space (``fn module.call()``),
    while ordinary commands use parentheses.  Old native-compile bridges may
    emit zero-argument commands as bare words or argument commands as
    ``stop 999``; normalize those forms without touching declarations,
    assignments, braces, or ``end fn`` module terminators.
    """
    out: List[str] = []
    for raw in str(text or "").replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        leading = raw[: len(raw) - len(raw.lstrip(" \t"))]
        body = raw.strip()
        low = body.lower()
        if not body:
            out.append(raw)
            continue
        if low.startswith("fn ") or re.match(r"^end\s+fn\b", body, re.I):
            out.append(raw.rstrip())
            continue
        if low in ZERO_ARG_COMMANDS:
            out.append(leading + body + "()")
            continue
        m = re.match(r"^(end|ends|break|continue|return|stop)\s+(.+)$", body, re.I)
        if m and not body.endswith(")"):
            out.append(leading + m.group(1) + "(" + m.group(2).strip() + ")")
            continue
        out.append(raw.rstrip())
    return "\n".join(out).strip()


def _normalize_page_name(value: str) -> str:
    """Normalize page/class names without destroying Chinese identifiers."""
    return re.sub(r"[^0-9A-Za-z_\u0080-\uffff]+", "", str(value or "")).replace("_", "").lower()


@dataclass(frozen=True)
class EventMethod:
    dex_name: str
    dex: Dex
    owner: str
    encoded: EncodedMethod
    event_type: str
    token: str

    @property
    def page(self) -> str:
        return simple_class_name(self.owner)

    @property
    def method_name(self) -> str:
        return self.dex.methods[self.encoded.method_idx].name


class NativeCompileRestorer:
    def __init__(self, apk_path: str | Path, out_dir: str | Path):
        self.apk_path = Path(apk_path)
        self.out_dir = Path(out_dir)
        self.dex_entries: List[Tuple[str, Dex]] = []
        self.methods: List[EventMethod] = []
        self.by_page_key: Dict[Tuple[str, str, str], List[EventMethod]] = defaultdict(list)
        self.by_page_token: Dict[Tuple[str, str], List[EventMethod]] = defaultdict(list)
        self.by_key: Dict[Tuple[str, str], List[EventMethod]] = defaultdict(list)
        self.by_token: Dict[str, List[EventMethod]] = defaultdict(list)
        self.manifest_package: str = ""
        self.manifest_descriptor_prefix: str = ""
        self.package_class_count: int = 0
        self.package_method_candidates: int = 0
        self.package_pages: set[str] = set()
        self.short_tables: Dict[Tuple[int, str], Optional[List[int]]] = {}
        self.errors: List[str] = []
        self.warnings: List[str] = []

    @staticmethod
    def descriptor_from_java_name(name: str) -> str:
        return "L" + name.replace(".", "/") + ";"

    def load(self) -> None:
        apk_bytes = get_apk_bytes(str(self.apk_path))
        try:
            self.manifest_package = str(get_package_name_from_apk_bytes(apk_bytes) or "").strip()
        except Exception as exc:
            self.manifest_package = ""
            self.warnings.append(f"Manifest包名读取失败: {type(exc).__name__}: {exc}")
        if self.manifest_package:
            self.manifest_descriptor_prefix = "L" + self.manifest_package.replace(".", "/") + "/"
        for dex_name, data in get_all_classes_dexes_from_apk_bytes(apk_bytes):
            try:
                dex = Dex(data)
            except Exception as exc:
                self.errors.append(f"{dex_name}: DEX解析失败: {type(exc).__name__}: {exc}")
                continue
            self.dex_entries.append((dex_name, dex))
            for owner in dex.classes:
                in_manifest_package = bool(
                    self.manifest_descriptor_prefix
                    and owner.startswith(self.manifest_descriptor_prefix)
                )
                if in_manifest_package:
                    self.package_class_count += 1
                    page_name = simple_class_name(owner).split("$", 1)[0].strip()
                    if page_name:
                        self.package_pages.add(page_name)
                try:
                    class_methods = dex.class_methods(owner)
                except Exception as exc:
                    self.warnings.append(
                        f"{dex_name}:{owner}: 类方法表读取失败: {type(exc).__name__}: {exc}"
                    )
                    continue
                for encoded in class_methods:
                    if not encoded.code_off:
                        continue
                    method = dex.methods[encoded.method_idx]
                    match = METHOD_RE.match(method.name)
                    if not match or AID_DESC not in method.proto.params:
                        continue
                    event_type = match.group("event")
                    token = match.group("token").lower()
                    item = EventMethod(dex_name, dex, owner, encoded, event_type, token)
                    self.methods.append(item)
                    if in_manifest_package:
                        self.package_method_candidates += 1
                    page_key = _normalize_page_name(item.page)
                    self.by_page_key[(page_key, event_type.lower(), token)].append(item)
                    self.by_page_token[(page_key, token)].append(item)
                    self.by_key[(event_type.lower(), token)].append(item)
                    self.by_token[token].append(item)

    def _old_report_members(self) -> Dict[Path, Dict[str, Any]]:
        """Return decrypted member paths, including extensionless _unknown/*.bin files."""
        result: Dict[Path, Dict[str, Any]] = {}
        report_path = self.out_dir / "old_iapp_report.json"
        if not report_path.is_file():
            return result
        try:
            report = json.loads(report_path.read_text("utf-8", errors="replace"))
        except Exception as exc:
            self.warnings.append(f"old_iapp_report.json读取失败: {type(exc).__name__}: {exc}")
            return result
        members = report.get("members") if isinstance(report, dict) else None
        if not isinstance(members, list):
            return result
        root = self.out_dir.resolve()
        for row in members:
            if not isinstance(row, dict):
                continue
            output = str(row.get("output") or "").replace("\\", "/").lstrip("/")
            if not output:
                continue
            path = (self.out_dir / output).resolve()
            try:
                path.relative_to(root)
            except Exception:
                continue
            if path.is_file():
                result[path] = row
        return result

    @staticmethod
    def _looks_textual(data: bytes) -> bool:
        if not data or len(data) > MAX_SOURCE_BYTES:
            return False
        sample = data[: min(len(data), 1024 * 1024)]
        if b"\x00" in sample:
            return False
        controls = sum(1 for byte in sample if byte < 9 or 13 < byte < 32)
        return controls <= max(8, len(sample) // 100)

    @classmethod
    def _looks_like_project_placeholder_source(cls, data: bytes) -> bool:
        if not data or len(data) > MAX_SOURCE_BYTES or not cls._looks_textual(data):
            return False
        try:
            text, _encoding = cls._decode_source(data)
        except Exception:
            return False
        return bool(EVENT_RE.search(text) or STANDALONE_TOKEN_RE.search(text))

    @staticmethod
    def _decode_source(data: bytes) -> Tuple[str, str]:
        if data.startswith(b"\xef\xbb\xbf"):
            return data.decode("utf-8-sig"), "utf-8-sig"
        for encoding in SOURCE_ENCODINGS:
            try:
                return data.decode(encoding), encoding
            except UnicodeDecodeError:
                continue
        return data.decode("utf-8", errors="replace"), "utf-8"

    @staticmethod
    def _write_source(path: Path, text: str, encoding: str) -> str:
        try:
            path.write_text(text, encoding=encoding)
            return encoding
        except (UnicodeEncodeError, LookupError):
            path.write_text(text, encoding="utf-8")
            return "utf-8"

    def _event_source_files(self) -> List[Tuple[Path, bool, Dict[str, Any]]]:
        """Return every textual project member containing a DEX token slot.

        Both XML page events and module/function bodies are supported.  A
        native-compiled ``.myu`` commonly stores only a standalone 12-hex line
        between ``fn ...`` and ``end fn``; therefore extension and XML markers
        are never used as inclusion requirements.
        """
        report_members = self._old_report_members()
        candidates: Dict[Path, Dict[str, Any]] = dict(report_members)
        src_root = self.out_dir / "src"
        if src_root.exists():
            for path in src_root.rglob("*"):
                if path.is_file():
                    candidates.setdefault(path.resolve(), {})
        rows: List[Tuple[Path, bool, Dict[str, Any]]] = []
        unknown_root = (src_root / "_unknown").resolve()
        for path, member in candidates.items():
            try:
                size = path.stat().st_size
                if size <= 0 or size > MAX_SOURCE_BYTES:
                    continue
                data = path.read_bytes()
            except Exception:
                continue
            if not self._looks_like_project_placeholder_source(data):
                continue
            try:
                path.resolve().relative_to(unknown_root)
                in_unknown_dir = True
            except Exception:
                in_unknown_dir = False
            unresolved_member = bool(member) and not str(member.get("resolved_name") or "").strip()
            rows.append((path, bool(in_unknown_dir or unresolved_member), member))
        rows.sort(key=lambda row: str(row[0]))
        return rows

    @staticmethod
    def _function_context(text: str, offset: int) -> str:
        """Infer the enclosing module function name for a standalone token."""
        before = text[: max(0, offset)]
        for raw in reversed(before.splitlines()[-120:]):
            line = raw.strip()
            if not line:
                continue
            match = FUNCTION_DECL_RE.match(raw)
            if match:
                name = str(match.group("name") or "").strip()
                if "." in name:
                    name = name.rsplit(".", 1)[-1].strip()
                return name
            if re.match(r"^end\s+fn\b", line, re.I):
                break
        return ""

    def _source_placeholders(self, text: str) -> List[Dict[str, Any]]:
        rows: List[Dict[str, Any]] = []
        occupied: List[Tuple[int, int]] = []
        for match in EVENT_RE.finditer(text):
            type_match = EVENT_TYPE_RE.search(match.group("attrs"))
            rows.append({
                "kind": "event",
                "start": match.start(),
                "end": match.end(),
                "token": match.group("body").strip().lower(),
                "event_type": type_match.group("value") if type_match else "",
                "match": match,
            })
            occupied.append((match.start(), match.end()))
        for match in STANDALONE_TOKEN_RE.finditer(text):
            if any(a <= match.start() < b for a, b in occupied):
                continue
            rows.append({
                "kind": "standalone",
                "start": match.start(),
                "end": match.end(),
                "token": match.group("token").lower(),
                "event_type": self._function_context(text, match.start()),
                "match": match,
            })
        rows.sort(key=lambda row: int(row["start"]))
        return rows

    @staticmethod
    def _format_placeholder_body(row: Dict[str, Any], body: str) -> str:
        match = row["match"]
        body = _normalize_v3_source(body)
        if row["kind"] == "event":
            return match.group(1) + body + match.group(4)
        indent = match.group("indent") or ""
        newline = match.group("newline") or ""
        indented = body.replace("\n", "\n" + indent)
        return indent + indented + newline

    def _class_short_table(self, dex: Dex, owner: str) -> Optional[List[int]]:
        cache_key = (id(dex), owner)
        if cache_key in self.short_tables:
            return self.short_tables[cache_key]
        table: Optional[List[int]] = None
        try:
            for encoded in dex.class_methods(owner):
                method = dex.methods[encoded.method_idx]
                if method.name != "<clinit>" or not encoded.code_off:
                    continue
                _, _, code_units = dex.code_units(encoded.code_off)
                for pos in reachable_instruction_offsets(code_units):
                    if (code_units[pos] & 0xFF) != 0x26 or pos + 2 >= len(code_units):
                        continue
                    rel = i4(code_units[pos + 1] | (code_units[pos + 2] << 16))
                    arr = parse_fill_array_payload_from_units(code_units, pos + rel)
                    if arr:
                        table = arr
                        break
                if table:
                    break
        except Exception as exc:
            self.warnings.append(
                f"{simple_class_name(owner)}: 旧版字符串表读取失败: {type(exc).__name__}: {exc}"
            )
        self.short_tables[cache_key] = table
        return table

    def _decode_helper_call(self, dex: Dex, match: re.Match[str]) -> Optional[str]:
        owner = self.descriptor_from_java_name(match.group("class"))
        if owner not in dex.classes:
            return None
        table = self._class_short_table(dex, owner)
        if not table:
            return None
        start = int(match.group("start"))
        end = int(match.group("end"))
        key = int(match.group("key"))
        if start < 0 or end < start or end > len(table):
            return None
        try:
            return "".join(chr((table[idx] ^ key) & 0xFFFF) for idx in range(start, end))
        except Exception:
            return None

    def _resolve_old_strings(self, dex: Dex, text: str) -> Tuple[str, int, int]:
        resolved = 0
        unresolved = 0

        def repl(match: re.Match[str]) -> str:
            nonlocal resolved, unresolved
            value = self._decode_helper_call(dex, match)
            if value is None:
                unresolved += 1
                return match.group(0)
            resolved += 1
            return dq_string(value)

        return DECODER_CALL_RE.sub(repl, text), resolved, unresolved

    @staticmethod
    def _strip_marker(line: str) -> str:
        value = line.strip()
        for marker in (
            "// IAPT_SIDE_EFFECT ",
            "// IAPT_DISCARDED_CALL ",
            "// IAPT_MAYBE_CALL ",
        ):
            if value.startswith(marker):
                return value[len(marker):].strip()
        return value

    @staticmethod
    def _java_string(expr: str) -> Optional[str]:
        value = expr.strip()
        if len(value) < 2 or value[0] != '"' or value[-1] != '"':
            return None
        try:
            parsed = json.loads(value)
            return parsed if isinstance(parsed, str) else None
        except Exception:
            return None

    @staticmethod
    def _emit_bridge_call(method: str, source: str, args: Optional[Sequence[str]] = None) -> str:
        if method in IGNORED_BRIDGE_METHODS:
            return ""
        mapped = METHOD_NAME_MAP.get(method, method)
        src = source or ""

        if method == "dims":
            body = src.strip()
            raw_flag = str((list(args or []) + ["0", "0"])[1]).strip()
            prefix = {"0": "s", "1": "ss", "2": "sss"}.get(raw_flag, "s")
            if re.match(r"^(?:s|ss|sss|sl)\s+", body, re.I):
                return _normalize_v3_source(body)
            return _normalize_v3_source(prefix + " " + body)
        if method == "function":
            body = src.strip()
            return _normalize_v3_source(("fn " + body) if body else "")

        suffix = src.strip()
        if not suffix:
            return mapped + "()"
        if suffix.startswith(("(", "{", "[")):
            return _normalize_v3_source(mapped + suffix)
        if suffix == mapped or suffix.startswith(mapped + "("):
            return _normalize_v3_source(suffix)
        if method in SPACE_FORM_BRIDGE_METHODS or ("=" in suffix and not suffix.startswith("(")):
            return _normalize_v3_source(mapped + " " + suffix)
        return _normalize_v3_source(mapped + "(" + suffix + ")")

    def recover_method(self, item: EventMethod) -> Tuple[str, Dict[str, Any]]:
        lines = pseudo_event_method(item.dex, item.encoded, item.owner)
        output: List[str] = []
        resolved_strings = 0
        unresolved_strings = 0
        seen: set[str] = set()

        for original in lines:
            line = self._strip_marker(original)
            if not line or line == "return;":
                continue
            # Ignore raw branch labels and helper-only decoder expressions.
            if re.fullmatch(r"L_[0-9a-fA-F]+:", line) or line.startswith(("if ", "if(", "goto ")):
                continue
            resolved_line, ok_count, bad_count = self._resolve_old_strings(item.dex, line)
            resolved_strings += ok_count
            unresolved_strings += bad_count
            call = ARG1_CALL_RE.match(resolved_line)
            if not call:
                continue
            method = call.group("method")
            if method in IGNORED_BRIDGE_METHODS:
                continue
            args = _split_balanced_args(call.group("args"))
            if not args:
                source = ""
            else:
                source = self._java_string(args[0])
                if source is None:
                    # An unresolved old-mode decoder or a non-source runtime
                    # expression is not safe to write into the .iyu file.
                    continue
            statement = self._emit_bridge_call(method, source, args)
            normalized = statement.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(statement)

        body = _normalize_v3_source("\n".join(output))
        meaningful_pseudo = []
        for raw_line in lines:
            probe = self._strip_marker(raw_line).strip()
            if not probe or probe == "return;" or re.fullmatch(r"L_[0-9a-fA-F]+:", probe):
                continue
            meaningful_pseudo.append(probe)
        true_empty_method = not meaningful_pseudo
        return body, {
            "class": item.owner,
            "method": item.method_name,
            "dex": item.dex_name,
            "recovery_mode": "exact-method-to-v3",
            "pseudo_line_count": len(lines),
            "statement_count": len(output),
            "empty_method": true_empty_method,
            "resolved_legacy_strings": resolved_strings,
            "unresolved_legacy_strings": unresolved_strings,
        }

    def _prefer_manifest_package(self, hits: Sequence[EventMethod]) -> List[EventMethod]:
        values = list(hits)
        if not self.manifest_descriptor_prefix:
            return values
        package_hits = [x for x in values if x.owner.startswith(self.manifest_descriptor_prefix)]
        return package_hits or values

    def select_method(self, page: str, event_type: str, token: str) -> Tuple[Optional[EventMethod], str]:
        """Resolve one placeholder against the app package class tree.

        Exact page/event matching is preferred, but the 12-hex token is the
        compiler's stable link.  A unique token therefore remains valid when
        the decrypted page filename differs from the DEX class name (for
        example main.iyu versus the original typo mian).
        """
        page_key = _normalize_page_name(page)
        event_key = str(event_type or "").strip().lower()
        token_key = str(token or "").strip().lower()

        page_hits = self._prefer_manifest_package(
            self.by_page_key.get((page_key, event_key, token_key), [])
        )
        if len(page_hits) == 1:
            return page_hits[0], "package-page-event"
        if len(page_hits) > 1:
            return None, "ambiguous-package-page-event"

        page_token_hits = self._prefer_manifest_package(
            self.by_page_token.get((page_key, token_key), [])
        )
        if len(page_token_hits) == 1:
            return page_token_hits[0], "package-page-token"
        if len(page_token_hits) > 1:
            return None, "ambiguous-package-page-token"

        event_hits = self._prefer_manifest_package(
            self.by_key.get((event_key, token_key), [])
        )
        if len(event_hits) == 1:
            return event_hits[0], "package-event-token"

        token_hits = self._prefer_manifest_package(self.by_token.get(token_key, []))
        if len(token_hits) == 1:
            return token_hits[0], "package-token-unique"
        if len(token_hits) > 1:
            # Last deterministic tie-break: compare normalized owner class with
            # the .iyu page name, then compare the method prefix with event type.
            class_hits = [x for x in token_hits if _normalize_page_name(x.page) == page_key]
            if len(class_hits) == 1:
                return class_hits[0], "package-token-page-tiebreak"
            event_class_hits = [x for x in class_hits if x.event_type.lower() == event_key]
            if len(event_class_hits) == 1:
                return event_class_hits[0], "package-token-event-tiebreak"
            return None, "ambiguous-token"
        return None, "missing-token"

    def inspect(self) -> Dict[str, Any]:
        if not self.dex_entries:
            self.load()
        source_files = self._event_source_files()
        placeholders = 0
        matched = 0
        unknown_placeholders = 0
        unknown_matched = 0
        unresolved: List[Dict[str, str]] = []
        for source_path, is_unknown, _member in source_files:
            try:
                text, _encoding = self._decode_source(source_path.read_bytes())
            except Exception:
                continue
            page = "" if is_unknown else source_path.stem
            for row in self._source_placeholders(text):
                placeholders += 1
                if is_unknown:
                    unknown_placeholders += 1
                item, reason = self.select_method(page, row["event_type"], row["token"])
                if item is not None:
                    matched += 1
                    if is_unknown:
                        unknown_matched += 1
                else:
                    unresolved.append({
                        "file": str(source_path.relative_to(self.out_dir)),
                        "page": page,
                        "event_type": str(row["event_type"]),
                        "token": str(row["token"]),
                        "kind": str(row["kind"]),
                        "reason": reason,
                        "unknown_member": str(bool(is_unknown)).lower(),
                    })
        package_pages = sorted(self.package_pages or {
            item.page for item in self.methods
            if not self.manifest_descriptor_prefix or item.owner.startswith(self.manifest_descriptor_prefix)
        })
        return {
            "ok": bool(self.dex_entries),
            "version": TOOL_VERSION,
            "strategy": "manifest-package/exact-token/all-text-files/v3-syntax-backfill",
            "manifest_package": self.manifest_package,
            "manifest_descriptor_prefix": self.manifest_descriptor_prefix,
            "package_class_count": self.package_class_count,
            "package_method_candidates": self.package_method_candidates,
            "dex_page_candidates": package_pages,
            "method_candidates": len(self.methods),
            "source_files": len(source_files),
            "placeholder_count": placeholders,
            "matched_placeholder_count": matched,
            "unknown_placeholder_count": unknown_placeholders,
            "unknown_matched_placeholder_count": unknown_matched,
            "detected": placeholders > 0 and matched > 0,
            "unresolved": unresolved[:100],
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }

    def run(self) -> Dict[str, Any]:
        self.load()
        source_files = self._event_source_files()
        package_pages = sorted(self.package_pages or {
            item.page for item in self.methods
            if not self.manifest_descriptor_prefix or item.owner.startswith(self.manifest_descriptor_prefix)
        })
        report: Dict[str, Any] = {
            "ok": True,
            "tool": "iapp_native_compile_restore",
            "version": TOOL_VERSION,
            "strategy": "manifest-package/exact-token/all-text-files/v3-syntax-backfill",
            "detected": bool(self.methods),
            "manifest_package": self.manifest_package,
            "manifest_descriptor_prefix": self.manifest_descriptor_prefix,
            "package_class_count": self.package_class_count,
            "package_method_candidates": self.package_method_candidates,
            "dex_page_candidates": package_pages,
            "apk": str(self.apk_path),
            "out_dir": str(self.out_dir),
            "dex_entries": [name for name, _ in self.dex_entries],
            "method_candidates": len(self.methods),
            "source_files": len(source_files),
            "iyu_files": sum(1 for path, _, _ in source_files if path.suffix.lower() == ".iyu"),
            "unknown_member_files_scanned": sum(1 for _, unknown, _ in source_files if unknown),
            "placeholder_count": 0,
            "unknown_placeholder_count": 0,
            "replaced_count": 0,
            "unknown_replaced_count": 0,
            "unresolved_count": 0,
            "unknown_unresolved_count": 0,
            "empty_recovery_count": 0,
            "files_changed": [],
            "unknown_files_changed": [],
            "encoding_migrations": [],
            "selection": {},
            "unresolved": [],
            "methods": [],
            "warnings": self.warnings,
            "errors": self.errors,
        }

        method_cache: Dict[Tuple[int, int], Tuple[str, Dict[str, Any]]] = {}
        method_reports: Dict[Tuple[int, int], Dict[str, Any]] = {}

        for source_path, is_unknown, _member in source_files:
            try:
                original, source_encoding = self._decode_source(source_path.read_bytes())
            except Exception as exc:
                report["errors"].append(
                    f"{source_path}: 读取失败: {type(exc).__name__}: {exc}"
                )
                continue
            page = "" if is_unknown else source_path.stem
            placeholders = self._source_placeholders(original)
            if not placeholders:
                continue
            pieces: List[str] = []
            cursor = 0
            changed = False
            for row in placeholders:
                pieces.append(original[cursor:int(row["start"])])
                report["placeholder_count"] += 1
                if is_unknown:
                    report["unknown_placeholder_count"] += 1
                token = str(row["token"])
                event_type = str(row["event_type"] or "")
                item, selection = self.select_method(page, event_type, token)
                replacement = original[int(row["start"]):int(row["end"])]
                if item is None:
                    report["unresolved_count"] += 1
                    if is_unknown:
                        report["unknown_unresolved_count"] += 1
                    report["unresolved"].append({
                        "file": str(source_path.relative_to(self.out_dir)),
                        "page": page,
                        "event_type": event_type,
                        "token": token,
                        "kind": str(row["kind"]),
                        "reason": selection,
                        "unknown_member": bool(is_unknown),
                    })
                else:
                    cache_key = (id(item.dex), item.encoded.method_idx)
                    if cache_key not in method_cache:
                        try:
                            method_cache[cache_key] = self.recover_method(item)
                        except Exception as exc:
                            method_cache[cache_key] = ("", {
                                "class": item.owner,
                                "method": item.method_name,
                                "dex": item.dex_name,
                                "error": f"{type(exc).__name__}: {exc}",
                            })
                    body, method_report = method_cache[cache_key]
                    method_reports[cache_key] = method_report
                    if body or bool(method_report.get("empty_method")):
                        replacement = self._format_placeholder_body(row, body)
                        report["selection"][selection] = int(report["selection"].get(selection, 0)) + 1
                        report["replaced_count"] += 1
                        if is_unknown:
                            report["unknown_replaced_count"] += 1
                        changed = True
                    else:
                        report["empty_recovery_count"] += 1
                        report["unresolved_count"] += 1
                        if is_unknown:
                            report["unknown_unresolved_count"] += 1
                        report["unresolved"].append({
                            "file": str(source_path.relative_to(self.out_dir)),
                            "page": page,
                            "event_type": event_type,
                            "token": token,
                            "kind": str(row["kind"]),
                            "reason": "empty-recovery",
                            "class": item.owner,
                            "method": item.method_name,
                            "unknown_member": bool(is_unknown),
                        })
                pieces.append(replacement)
                cursor = int(row["end"])
            pieces.append(original[cursor:])
            updated = "".join(pieces)
            if changed and updated != original:
                used_encoding = self._write_source(source_path, updated, source_encoding)
                rel = str(source_path.relative_to(self.out_dir))
                report["files_changed"].append(rel)
                if is_unknown:
                    report["unknown_files_changed"].append(rel)
                if used_encoding != source_encoding:
                    report["encoding_migrations"].append({
                        "file": rel, "from": source_encoding, "to": used_encoding,
                    })

        report["methods"] = list(method_reports.values())
        if not self.dex_entries:
            report["ok"] = False
        report["warnings"] = self.warnings
        report["errors"] = self.errors + [x for x in report["errors"] if x not in self.errors]
        report_path = self.out_dir / "native_compile_restore.json"
        self.out_dir.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        report["report_file"] = str(report_path)
        return report


def inspect_native_compiled_events(apk_path: str | Path, out_dir: str | Path) -> Dict[str, Any]:
    """Read-only package-tree probe used by the final server postprocessor."""
    return NativeCompileRestorer(apk_path, out_dir).inspect()


def restore_native_compiled_events(apk_path: str | Path, out_dir: str | Path) -> Dict[str, Any]:
    """Public server integration entry point."""
    return NativeCompileRestorer(apk_path, out_dir).run()


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="修复 iApp 原生编译后留在 DEX 中的事件源码")
    parser.add_argument("--apk", required=True, help="APK/ZIP/DEX 路径")
    parser.add_argument("--outdir", required=True, help="已解密项目输出目录")
    args = parser.parse_args(argv)
    try:
        report = restore_native_compiled_events(args.apk, args.outdir)
    except Exception as exc:
        print(f"[原生编译修复] 失败: {type(exc).__name__}: {exc}", file=sys.stderr)
        if "--debug" in sys.argv or "IAPT_DEBUG" in __import__("os").environ:
            traceback.print_exc()
        return 2
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
