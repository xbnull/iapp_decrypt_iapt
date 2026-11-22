#!/usr/bin/env python3
"""
Lightweight deobfuscator for iApp/iYU source zips.

It is intentionally conservative:
  - obfuscated file names are normalized and references are updated
  - hash-like function names are renamed to fn1, fn2 ...
  - variable identifiers are renamed to a1, b1 ...
  - quoted string contents are protected, except full file-name references
"""
from __future__ import annotations

import argparse
import re
import shutil
import string
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, Iterable, List, Tuple


TEXT_EXTS = {".iyu", ".myu", ".ijava", ".java", ".txt", ".xml", ".json"}
HASH_NAME_RE = re.compile(r"\b[0-9a-fA-F]{16,64}\b")
FN_DEF_RE = re.compile(r"(?m)^(\s*fn\s+)([^\s(]+)(\s*\()")
UI_FN_CALL_RE = re.compile(r"\bfn\s+([^\s(]+)(\s*\()")
IDENT_RE_SRC = r"[A-Za-z_\u0600-\u06ff\u10a0-\u10ff\u4e00-\u9fff][A-Za-z0-9_\u0600-\u06ff\u10a0-\u10ff\u4e00-\u9fff]*"
TOKEN_RE = re.compile(IDENT_RE_SRC)
DECL_RE = re.compile(r"(?m)^\s*(?:s|ss|sss|dim|int|string|boolean|double|long)\s+(" + IDENT_RE_SRC + r")\b")
LOADING_FN_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*|[\u4e00-\u9fffA-Za-z0-9_]+)\.([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NORMAL_FN_CALL_RE = re.compile(r"\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\.([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)")
MATH_ID_RE = re.compile(r"^\s*s([+\-*/])\(\s*(-?\d+)\s*,\s*(-?\d+)\s*,\s*(" + IDENT_RE_SRC + r")\s*\)\s*$")
US_PROP_RE = re.compile(r'^\s*us\(\s*([^,]+?)\s*,\s*"([^"]+)"\s*,\s*"((?:\\.|[^"\\])*)"\s*\)\s*$')

BUILTINS = {
    "fn", "end", "for", "if", "else", "while", "f", "t", "ufnsui",
    "s", "ss", "sss", "sl", "slg", "sran", "stop", "uigo", "tw", "ug", "us",
    "true", "false", "null", "View", "UIEventset", "eventItme", "event",
    "ppt", "type", "id", "did", "ps",
}


def decode_text(data: bytes) -> Tuple[str, str]:
    for enc in ("utf-8", "gb18030", "gbk", "latin1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", "replace"), "utf-8"


def is_text_file(path: Path) -> bool:
    return path.suffix.lower() in TEXT_EXTS


def ugly_score(name: str) -> int:
    score = 0
    for ch in name:
        if "\u0600" <= ch <= "\u06ff":
            score += 3
        elif ord(ch) > 127 and not ("\u4e00" <= ch <= "\u9fff"):
            score += 2
        elif ch in "\u200b\u200c\u200d\ufeff":
            score += 2
    return score


def protect_strings(text: str) -> Tuple[str, List[str]]:
    parts: List[str] = []

    def repl(m: re.Match) -> str:
        parts.append(m.group(0))
        return f"@@STR{len(parts) - 1}@@"

    # iYU files in these samples mostly use double quotes. Protect simple
    # quoted strings so variable renaming does not rewrite user-facing text.
    masked = re.sub(r'"(?:\\.|[^"\\])*"', repl, text)
    masked = re.sub(r"'(?:\\.|[^'\\])*'", repl, masked)
    return masked, parts


def restore_strings(text: str, parts: List[str]) -> str:
    for i, s in enumerate(parts):
        text = text.replace(f"@@STR{i}@@", s)
    return text


def next_name(index: int) -> str:
    letters = string.ascii_lowercase
    return f"{letters[index % 26]}{index // 26 + 1}"


def normalized_file_map(names: Iterable[str]) -> Dict[str, str]:
    out: Dict[str, str] = {}
    page_i = 1
    module_i = 1
    asset_i = 1
    for name in names:
        p = Path(name)
        stem = p.stem
        ext = p.suffix
        parent = "" if str(p.parent) == "." else p.parent.as_posix() + "/"
        if name == "mian.iyu":
            continue
        if ext == ".iyu" and ugly_score(stem) > 0:
            out[name] = f"{parent}page{page_i}.iyu"
            page_i += 1
        elif ext == ".myu" and (ugly_score(stem) > 0 or HASH_NAME_RE.search(stem) or stem.startswith("事件模块集")):
            out[name] = f"{parent}module{module_i}.myu"
            module_i += 1
        elif ugly_score(stem) > 0:
            out[name] = f"{parent}file{asset_i}{ext}"
            asset_i += 1
    return out


def collect_function_map(texts: Dict[str, str]) -> Dict[str, str]:
    names: List[str] = []
    seen = set()
    for text in texts.values():
        for m in FN_DEF_RE.finditer(text):
            full = m.group(2)
            short = full.rsplit(".", 1)[-1]
            if (HASH_NAME_RE.fullmatch(short) or ugly_score(short) > 0) and short not in seen:
                seen.add(short)
                names.append(short)
        for m in UI_FN_CALL_RE.finditer(text):
            full = m.group(1)
            short = full.rsplit(".", 1)[-1]
            if (HASH_NAME_RE.fullmatch(short) or ugly_score(short) > 0) and short not in seen:
                seen.add(short)
                names.append(short)
    return {old: f"fn{i + 1}" for i, old in enumerate(names)}


def collect_var_map(texts: Dict[str, str], fn_map: Dict[str, str], file_map: Dict[str, str]) -> Dict[str, str]:
    candidates: List[str] = []
    seen = set()
    file_stems = {Path(x).stem for x in file_map} | {Path(x).stem for x in file_map.values()}

    def add(tok: str) -> None:
        if not tok or tok in seen:
            return
        if tok in BUILTINS or tok in fn_map or tok in fn_map.values() or tok in file_stems:
            return
        if HASH_NAME_RE.fullmatch(tok):
            return
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", tok):
            # Keep readable XML/HTML-ish identifiers. Short names in code are
            # usually obfuscated iYU variables.
            if len(tok) > 2 and ugly_score(tok) == 0:
                return
        seen.add(tok)
        candidates.append(tok)

    for text in texts.values():
        masked, _ = protect_strings(text)
        for m in DECL_RE.finditer(masked):
            add(m.group(1))
        for m in FN_DEF_RE.finditer(masked):
            args = masked[m.end(): masked.find(")", m.end())]
            for tok in TOKEN_RE.findall(args):
                add(tok)
        for tok in TOKEN_RE.findall(masked):
            if ugly_score(tok) > 0:
                add(tok)

    return {old: next_name(i) for i, old in enumerate(candidates)}


def replace_outside_strings(text: str, mapping: Dict[str, str]) -> str:
    if not mapping:
        return text
    masked, parts = protect_strings(text)
    masked = TOKEN_RE.sub(lambda m: mapping.get(m.group(0), m.group(0)), masked)
    return restore_strings(masked, parts)


def replace_everywhere(text: str, mapping: Dict[str, str]) -> str:
    for old, new in sorted(mapping.items(), key=lambda kv: len(kv[0]), reverse=True):
        text = text.replace(old, new)
    return text


def is_res_file(rel: str) -> bool:
    return rel == "res" or rel.startswith("res/")


def resource_key(rel: str) -> str:
    return rel[4:] if rel.startswith("res/") else rel


def header_ext(data: bytes) -> str:
    h = data[:32]
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if h.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if h.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if len(h) >= 12 and h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return ".webp"
    if len(h) >= 12 and h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return ".wav"
    if h.startswith(b"OggS"):
        return ".ogg"
    if h.startswith(b"ID3") or (len(h) >= 2 and h[0] == 0xff and (h[1] & 0xe0) == 0xe0):
        return ".mp3"
    if len(h) >= 12 and h[4:8] == b"ftyp":
        return ".m4a"
    if h.startswith(b"PK\x03\x04"):
        return ".zip"
    if h.startswith(b"\x00\x01\x00\x00") or h.startswith(b"true"):
        return ".ttf"
    if h.startswith(b"OTTO"):
        return ".otf"
    return ""


def clean_resource_ref(raw: str) -> str:
    s = (raw or "").strip().strip('"').strip("'")
    while s.startswith("@") or s.startswith("$"):
        s = s[1:]
    while s.startswith("/"):
        s = s[1:]
    return s


def collect_resource_hints(texts: Dict[str, str]) -> Dict[str, str]:
    hints: Dict[str, str] = {}

    def add(raw: str, kind: str) -> None:
        key = clean_resource_ref(raw)
        if not key:
            return
        hints.setdefault(key, kind)
        hints.setdefault(Path(key).name, kind)

    for text in texts.values():
        for m in re.finditer(r'(?i)\btypeface\s*=\s*"?([^"\s\r\n<>]+)"?', text):
            add(m.group(1), "font")
        for m in re.finditer(r'(?i)us\([^;\n]*"typeface"\s*,\s*"((?:\\.|[^"\\])*)"', text):
            add(m.group(1), "font")
        for m in re.finditer(r'(?i)\bbfm\s*\(\s*"?([^",)\s]+)', text):
            add(m.group(1), "audio")
        for m in re.finditer(r'(?i)\b(?:src|background|backgroundimage|image|icon)\s*=\s*"?([^"\s\r\n<>]+)"?', text):
            add(m.group(1), "image")
        for m in re.finditer(r'(?i)us\([^;\n]*"(?:src|background|backgroundimage|image|icon)"\s*,\s*"((?:\\.|[^"\\])*)"', text):
            add(m.group(1), "image")
    return hints


def ext_from_hint(kind: str) -> str:
    if kind == "font":
        return ".ttf"
    if kind == "audio":
        return ".mp3"
    if kind == "image":
        return ".png"
    return ".bin"


def build_resource_map(files: List[Path], raw_dir: Path, texts: Dict[str, str]) -> Dict[str, str]:
    res_files = [p for p in files if is_res_file(p.relative_to(raw_dir).as_posix()) and p.is_file()]
    no_suffix = [p for p in res_files if p.suffix == ""]
    if not no_suffix:
        return {}
    hints = collect_resource_hints(texts)
    out: Dict[str, str] = {}
    for i, p in enumerate(sorted(no_suffix, key=lambda x: x.relative_to(raw_dir).as_posix())):
        rel = p.relative_to(raw_dir).as_posix()
        key = resource_key(rel)
        ext = header_ext(p.read_bytes()[:64])
        if not ext:
            ext = ext_from_hint(hints.get(key) or hints.get(Path(key).name) or "")
        parent = p.parent.relative_to(raw_dir).as_posix()
        out[rel] = f"{parent}/{next_name(i)}{ext}"
    return out


def replace_resource_refs(text: str, resource_map: Dict[str, str]) -> str:
    if not resource_map:
        return text
    for old_rel, new_rel in sorted(resource_map.items(), key=lambda kv: len(kv[0]), reverse=True):
        old_key = resource_key(old_rel)
        new_key = resource_key(new_rel)
        pairs = [(old_key, new_key), (Path(old_key).name, Path(new_key).name)]
        for old, new in pairs:
            if not old or old == new:
                continue
            eo = re.escape(old)
            text = text.replace("@" + old, "@" + new)
            text = text.replace("$" + old, "$" + new)
            text = re.sub(r'((?:typeface|src|background|backgroundimage|image|icon)\s*=\s*["\']?)([@$]?)' + eo + r'(?=("|\'|\s|<|>|$))', lambda m: m.group(1) + m.group(2) + new, text, flags=re.I)
            text = re.sub(r'(\bbfm\s*\(\s*["\']?)([@$]?)' + eo + r'(?=("|\'|,|\)|\s|$))', lambda m: m.group(1) + m.group(2) + new, text, flags=re.I)
    return text


def calc_iapp_math(op: str, a: int, b: int) -> int:
    if op == "+":
        return a + b
    if op == "-":
        return a - b
    if op == "*":
        return a * b
    if op == "/":
        if b == 0:
            raise ZeroDivisionError("iApp extracted property division by zero")
        return int(a / b)
    raise ValueError(op)


def extract_function_ranges(text: str) -> Dict[str, Tuple[int, int]]:
    lines = text.splitlines()
    ranges: Dict[str, Tuple[int, int]] = {}
    start = None
    name = None
    for i, line in enumerate(lines):
        m = re.match(r"^\s*fn\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
        if m and start is None:
            start = i
            name = m.group(1)
            continue
        if start is not None and re.match(r"^\s*end\s+fn\s*$", line):
            ranges[str(name)] = (start, i)
            start = None
            name = None
    return ranges


def build_module_index(texts: Dict[str, str]) -> Tuple[Dict[str, Dict[str, Tuple[int, int]]], Dict[str, List[str]], Dict[str, str]]:
    module_ranges: Dict[str, Dict[str, Tuple[int, int]]] = {}
    module_lines: Dict[str, List[str]] = {}
    module_rel: Dict[str, str] = {}
    for rel, text in texts.items():
        if rel.endswith(".myu"):
            mod = Path(rel).stem
            module_ranges[mod] = extract_function_ranges(text)
            module_lines[mod] = text.splitlines()
            module_rel[mod] = rel
    return module_ranges, module_lines, module_rel


def function_body(module_lines: Dict[str, List[str]], module_ranges: Dict[str, Dict[str, Tuple[int, int]]], mod: str, fn_name: str) -> List[str] | None:
    if mod not in module_ranges or fn_name not in module_ranges[mod]:
        return None
    start, end = module_ranges[mod][fn_name]
    return module_lines[mod][start + 1:end]


def expand_function_body(
    module_lines: Dict[str, List[str]],
    module_ranges: Dict[str, Dict[str, Tuple[int, int]]],
    mod: str,
    fn_name: str,
    used: set[Tuple[str, str]] | None = None,
    stack: set[Tuple[str, str]] | None = None,
) -> List[str]:
    used = used if used is not None else set()
    stack = stack if stack is not None else set()
    key = (mod, fn_name)
    body = function_body(module_lines, module_ranges, mod, fn_name)
    if body is None:
        return []
    if key in stack:
        return body[:]
    used.add(key)
    stack.add(key)
    out: List[str] = []
    for line in body:
        m = NORMAL_FN_CALL_RE.fullmatch(line.strip())
        if m and m.group(1) in module_ranges and m.group(2) in module_ranges[m.group(1)]:
            out.extend(expand_function_body(module_lines, module_ranges, m.group(1), m.group(2), used, stack))
        else:
            out.append(line)
    stack.remove(key)
    return out


def expand_event_body_for_ui(
    module_lines: Dict[str, List[str]],
    module_ranges: Dict[str, Dict[str, Tuple[int, int]]],
    mod: str,
    fn_name: str,
    used: set[Tuple[str, str]] | None = None,
    stack: set[Tuple[str, str]] | None = None,
) -> List[str]:
    """Expand UI event calls, but only follow pure wrapper functions.

    If a module function contains real logic plus another module call, the
    nested call is module-internal logic and is left as-is instead of being
    flattened into the interface event.
    """
    used = used if used is not None else set()
    stack = stack if stack is not None else set()
    key = (mod, fn_name)
    body = function_body(module_lines, module_ranges, mod, fn_name)
    if body is None:
        return []
    used.add(key)
    meaningful = [line.strip() for line in body if line.strip()]
    if len(meaningful) == 1:
        m = NORMAL_FN_CALL_RE.fullmatch(meaningful[0])
        if m and (m.group(1), m.group(2)) not in stack:
            stack.add(key)
            out = expand_event_body_for_ui(module_lines, module_ranges, m.group(1), m.group(2), used, stack)
            stack.discard(key)
            return out
    return body[:]


def parse_extracted_props_from_body(body_lines: List[str]) -> Tuple[Dict[int, List[Tuple[str, str]]], set[int]]:
    values: Dict[str, int] = {}
    props: Dict[int, List[Tuple[str, str]]] = {}
    removable: set[int] = set()
    for idx, line in enumerate(body_lines):
        m = MATH_ID_RE.match(line)
        if m:
            try:
                values[m.group(4)] = calc_iapp_math(m.group(1), int(m.group(2)), int(m.group(3)))
                removable.add(idx)
            except Exception:
                pass
            continue
        m = US_PROP_RE.match(line)
        if not m:
            continue
        target = m.group(1).strip()
        # Extracted layout properties use a temporary variable produced by the
        # previous s+/s-/s*/s/ arithmetic line. Direct numeric us(6,...) calls
        # are normal runtime UI changes and must remain in code.
        if re.fullmatch(r"-?\d+", target):
            continue
        view_id = values.get(target)
        if view_id is None:
            continue
        props.setdefault(view_id, []).append((m.group(2), m.group(3)))
        removable.add(idx)
    return props, removable


def merge_props(existing: List[str], new_props: List[Tuple[str, str]]) -> List[str]:
    seen_new = {k for k, _ in new_props}
    out = []
    for line in existing:
        stripped = line.strip()
        if stripped.startswith("ps=") and "属性抽离" in stripped:
            continue
        if stripped == "null":
            continue
        key = stripped.split("=", 1)[0] if "=" in stripped else ""
        if key in seen_new:
            continue
        if stripped:
            out.append(line)
    out.extend(f"{k}={v}" for k, v in new_props)
    return out


def apply_props_to_iyu(text: str, props_by_id: Dict[int, List[Tuple[str, str]]]) -> str:
    if not props_by_id:
        return text

    def repl(m: re.Match) -> str:
        view_id = int(m.group(1))
        props = props_by_id.get(view_id)
        if not props:
            return m.group(0)
        block = m.group(0)
        open_tag = m.group(2)
        body = m.group(3)
        close_tag = m.group(4)
        ppt = re.search(r"<ppt>(.*?)</ppt>", body, flags=re.S)
        if ppt:
            before = body[:ppt.start()]
            after = body[ppt.end():]
            existing = [x for x in ppt.group(1).splitlines() if x.strip()]
            merged = "\n".join(merge_props(existing, props))
            ppt_body = ("\n" + merged + "\n") if merged else ""
            new_ppt = "<ppt>" + ppt_body + "</ppt>"
            return open_tag + before + new_ppt + after + close_tag
        body_lines = body.splitlines()
        cleaned = [
            line for line in body_lines
            if not (line.strip().startswith("ps=") and "属性抽离" in line.strip())
        ]
        prop_lines = [f"{k}={v}" for k, v in props]
        merged = prop_lines + [line for line in cleaned if line.strip()]
        new_body = "\n" + "\n".join(merged) + ("\n" if merged else "")
        return open_tag + new_body + close_tag

    return re.sub(r'(<View\b[^>]*\bid="(\d+)"[^>]*>)(.*?)(</View>)', lambda m: repl(_ViewMatch(m)), text, flags=re.S)


class _ViewMatch:
    """Small adapter so apply_props_to_iyu can keep named groups readable."""
    def __init__(self, m: re.Match):
        self.m = m
    def group(self, idx):
        if idx == 1:
            return self.m.group(2)
        if idx == 2:
            return self.m.group(1)
        if idx == 3:
            return self.m.group(3)
        if idx == 4:
            return self.m.group(4)
        return self.m.group(idx)


def restore_extracted_view_props(texts: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, Dict[int, List[Tuple[str, str]]]]]:
    module_ranges, module_lines, module_rel_by_name = build_module_index(texts)

    page_props: Dict[str, Dict[int, List[Tuple[str, str]]]] = {}
    module_remove: Dict[str, Dict[str, set[int]]] = {}

    for rel, text in list(texts.items()):
        if not rel.endswith(".iyu"):
            continue
        for mod, fn_name in LOADING_FN_RE.findall(text):
            if mod not in module_ranges or fn_name not in module_ranges[mod]:
                continue
            used: set[Tuple[str, str]] = set()
            body = expand_function_body(module_lines, module_ranges, mod, fn_name, used)
            props, removable = parse_extracted_props_from_body(body)
            if props:
                page_props.setdefault(rel, {})
                for vid, pairs in props.items():
                    page_props[rel].setdefault(vid, []).extend(pairs)
                for used_mod, used_fn in used:
                    if used_mod not in module_ranges or used_fn not in module_ranges[used_mod]:
                        continue
                    start, end = module_ranges[used_mod][used_fn]
                    direct_body = module_lines[used_mod][start + 1:end]
                    _, direct_removable = parse_extracted_props_from_body(direct_body)
                    if direct_removable:
                        module_remove.setdefault(used_mod, {}).setdefault(used_fn, set()).update(i + start + 1 for i in direct_removable)

    for rel, props in page_props.items():
        texts[rel] = apply_props_to_iyu(texts[rel], props)

    for mod, by_fn in module_remove.items():
        lines = module_lines[mod]
        remove_idx = set()
        for idxs in by_fn.values():
            remove_idx.update(idxs)
        new_lines = [line for i, line in enumerate(lines) if i not in remove_idx]
        rel_name = module_rel_by_name.get(mod)
        if rel_name:
            texts[rel_name] = "\n".join(new_lines) + ("\n" if texts[rel_name].endswith("\n") else "")
    return texts, page_props


def remove_used_functions_from_modules(texts: Dict[str, str], used: set[Tuple[str, str]]) -> Dict[str, str]:
    if not used:
        return texts
    module_ranges, module_lines, module_rel_by_name = build_module_index(texts)
    remove_by_mod: Dict[str, List[Tuple[int, int]]] = {}
    for mod, fn_name in used:
        if mod in module_ranges and fn_name in module_ranges[mod]:
            start, end = module_ranges[mod][fn_name]
            remove_by_mod.setdefault(mod, []).append((start, end))
    for mod, ranges in remove_by_mod.items():
        rel = module_rel_by_name.get(mod)
        if not rel:
            continue
        remove_idx = set()
        for start, end in ranges:
            remove_idx.update(range(start, end + 1))
        lines = module_lines[mod]
        new_lines = [line for i, line in enumerate(lines) if i not in remove_idx]
        texts[rel] = "\n".join(new_lines) + ("\n" if texts[rel].endswith("\n") else "")
    return texts


def prune_unreferenced_module_functions(texts: Dict[str, str]) -> Dict[str, str]:
    """Drop dead module functions after interface events have been inlined.

    Functions still referenced by `fn module.fn(...)` anywhere are kept. This
    preserves module-internal calls while removing duplicated event handlers
    that were restored into .iyu files.
    """
    changed = True
    while changed:
        changed = False
        module_ranges, module_lines, module_rel_by_name = build_module_index(texts)
        referenced = set((m.group(1), m.group(2)) for text in texts.values() for m in NORMAL_FN_CALL_RE.finditer(text))
        for mod, ranges in list(module_ranges.items()):
            rel = module_rel_by_name.get(mod)
            if not rel:
                continue
            remove_idx = set()
            for fn_name, (start, end) in ranges.items():
                if (mod, fn_name) not in referenced:
                    remove_idx.update(range(start, end + 1))
            if not remove_idx:
                continue
            lines = module_lines[mod]
            new_lines = [line for i, line in enumerate(lines) if i not in remove_idx]
            new_text = "\n".join(new_lines).strip()
            texts[rel] = (new_text + "\n") if new_text else ""
            changed = True
    return texts


def inline_extracted_events(texts: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, List[str]]]:
    module_ranges, module_lines, _ = build_module_index(texts)
    used: set[Tuple[str, str]] = set()
    inlined: Dict[str, List[str]] = {}

    def repl_factory(rel: str):
        def repl(m: re.Match) -> str:
            mod, fn_name = m.group(1), m.group(2)
            if mod not in module_ranges or fn_name not in module_ranges[mod]:
                return m.group(0)
            local_used: set[Tuple[str, str]] = set()
            body = expand_event_body_for_ui(module_lines, module_ranges, mod, fn_name, local_used)
            used.update(local_used)
            inlined.setdefault(rel, []).append(f"{mod}.{fn_name}")
            return "\n".join(body).strip()
        return repl

    for rel, text in list(texts.items()):
        if rel.endswith(".iyu"):
            texts[rel] = NORMAL_FN_CALL_RE.sub(repl_factory(rel), text)

    texts = remove_used_functions_from_modules(texts, used)
    texts = prune_unreferenced_module_functions(texts)
    return texts, inlined


def deobfuscate(
    src_zip: Path,
    out_zip: Path,
    workdir: Path | None = None,
    restore_props: bool = True,
    restore_events: bool = True,
    rename_vars: bool = True,
    rename_files: bool = True,
    rename_functions: bool = True,
    restore_resource_names: bool = True,
    dex_restore: bool = False,
    dex_paths: List[Path] | None = None,
    flat_v3: bool = True,
    dex_only: bool = False,
) -> Path:
    # IAPT_DEOBF_MERGED_STATIC_DEX_BEGIN
    # Same entry script as the original deobfuscator.  When --dex-restore is
    # enabled, first run the pure-static DEX reflector restorer, then optionally
    # pass its output through the normal iApp deobfuscation pipeline below.
    if dex_restore:
        tmp_root_for_dex = Path(tempfile.mkdtemp(prefix="iapp_deobf_dex_", dir=str(workdir) if workdir else None))
        try:
            static_zip = out_zip if dex_only else (tmp_root_for_dex / "static_dex_restored.zip")
            try:
                from .iapp_static_dex_restore import restore_tree
            except Exception:
                # Support direct command-line execution from app/tools.
                from iapp_static_dex_restore import restore_tree  # type: ignore
            restore_tree(src_zip, static_zip, list(dex_paths or []), flat_v3=flat_v3)
            if dex_only:
                return out_zip
            return deobfuscate(
                static_zip,
                out_zip,
                workdir=workdir,
                restore_props=restore_props,
                restore_events=restore_events,
                rename_vars=rename_vars,
                rename_files=rename_files,
                rename_functions=rename_functions,
                restore_resource_names=restore_resource_names,
                dex_restore=False,
                dex_paths=None,
                flat_v3=flat_v3,
                dex_only=False,
            )
        finally:
            shutil.rmtree(tmp_root_for_dex, ignore_errors=True)
    # IAPT_DEOBF_MERGED_STATIC_DEX_END
    tmp_root = Path(tempfile.mkdtemp(prefix="iapp_deobf_", dir=str(workdir) if workdir else None))
    raw_dir = tmp_root / "raw"
    out_dir = tmp_root / "out"
    raw_dir.mkdir()
    out_dir.mkdir()

    with zipfile.ZipFile(src_zip) as z:
        z.extractall(raw_dir)

    files = [p for p in raw_dir.rglob("*") if p.is_file()]
    rel_names = [p.relative_to(raw_dir).as_posix() for p in files]
    file_map = normalized_file_map(rel_names) if rename_files else {}

    texts: Dict[str, str] = {}
    binary_files: List[Path] = []
    for p in files:
        rel = p.relative_to(raw_dir).as_posix()
        if is_text_file(p):
            texts[rel] = decode_text(p.read_bytes())[0]
        else:
            binary_files.append(p)

    # Update file references before variable masking. Full filename replacement
    # is safe inside string literals, e.g. uigo("old.iyu").
    module_name_map = {Path(old).stem: Path(new).stem for old, new in file_map.items()}
    for rel, text in list(texts.items()):
        text = replace_everywhere(text, file_map)
        text = replace_everywhere(text, module_name_map)
        texts[rel] = text

    fn_map = collect_function_map(texts) if rename_functions else {}
    for rel, text in list(texts.items()):
        texts[rel] = replace_everywhere(text, fn_map)

    var_map = collect_var_map(texts, fn_map, file_map) if rename_vars else {}
    for rel, text in list(texts.items()):
        texts[rel] = replace_outside_strings(text, var_map)

    texts = {file_map.get(rel, rel): text for rel, text in texts.items()}
    if restore_props:
        texts, restored_props = restore_extracted_view_props(texts)
    else:
        restored_props = {}
    if restore_events:
        texts, inlined_events = inline_extracted_events(texts)
    else:
        inlined_events = {}

    resource_map = build_resource_map(files, raw_dir, texts) if restore_resource_names else {}
    if resource_map:
        for rel, text in list(texts.items()):
            texts[rel] = replace_resource_refs(text, resource_map)

    map_lines = ["# iApp deobfuscation map", "", "## options"]
    map_lines.append(f"restore_props={int(bool(restore_props))}")
    map_lines.append(f"restore_events={int(bool(restore_events))}")
    map_lines.append(f"rename_vars={int(bool(rename_vars))}")
    map_lines.append(f"rename_files={int(bool(rename_files))}")
    map_lines.append(f"rename_functions={int(bool(rename_functions))}")
    map_lines.append(f"restore_resource_names={int(bool(restore_resource_names))}")
    map_lines += ["", "## files"]
    for old, new in sorted(file_map.items()):
        map_lines.append(f"{old} -> {new}")
    map_lines += ["", "## resources"]
    if resource_map:
        for old, new in sorted(resource_map.items()):
            map_lines.append(f"{old} -> {new}")
    else:
        map_lines.append("(none)")
    map_lines += ["", "## functions"]
    for old, new in sorted(fn_map.items(), key=lambda kv: kv[1]):
        map_lines.append(f"{old} -> {new}")
    map_lines += ["", "## variables"]
    for old, new in sorted(var_map.items(), key=lambda kv: kv[1]):
        map_lines.append(f"{old} -> {new}")
    map_lines += ["", "## restored view properties"]
    if restored_props:
        for rel, by_id in sorted(restored_props.items()):
            map_lines.append(f"[{rel}]")
            for view_id, pairs in sorted(by_id.items()):
                joined = ", ".join(f"{k}={v}" for k, v in pairs)
                map_lines.append(f"View id={view_id}: {joined}")
    else:
        map_lines.append("(none)")
    map_lines += ["", "## inlined events"]
    if inlined_events:
        for rel, calls in sorted(inlined_events.items()):
            map_lines.append(f"[{rel}]")
            for call in calls:
                map_lines.append(call)
    else:
        map_lines.append("(none)")

    def module_has_code(text: str) -> bool:
        for line in text.splitlines():
            s = line.strip()
            if s and not s.startswith("//"):
                return True
        return False

    for rel, text in texts.items():
        if rel.endswith(".myu") and not module_has_code(text):
            continue
        dst = out_dir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(text, encoding="utf-8", newline="")

    for p in binary_files:
        rel = p.relative_to(raw_dir).as_posix()
        new_rel = resource_map.get(rel, file_map.get(rel, rel))
        dst = out_dir / new_rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(p, dst)

    (out_dir / "deobfuscation_map.txt").write_text("\n".join(map_lines) + "\n", encoding="utf-8")

    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_zip, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in sorted(out_dir.rglob("*")):
            if p.is_file():
                z.write(p, p.relative_to(out_dir).as_posix())
    return out_zip


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="Normalize/deobfuscate iApp .iyu/.myu source zip names.")
    ap.add_argument("src_zip", type=Path, help="input source zip")
    ap.add_argument("-o", "--output", type=Path, default=Path("src_deobfuscated.zip"), help="output zip path")
    ap.add_argument("--workdir", type=Path, default=None, help="temporary work directory")
    ap.add_argument("--no-restore-props", action="store_true", help="do not restore extracted View properties")
    ap.add_argument("--no-restore-events", action="store_true", help="do not inline extracted UI events")
    ap.add_argument("--no-rename-vars", action="store_true", help="do not rename obfuscated variables")
    ap.add_argument("--no-rename-files", action="store_true", help="do not rename obfuscated files/pages/modules")
    ap.add_argument("--no-rename-functions", action="store_true", help="do not rename obfuscated function names")
    ap.add_argument("--no-restore-resource-names", action="store_true", help="do not rename extensionless files under res/")
    ap.add_argument("--dex-restore", action="store_true", help="enable pure-static DEX reflection restore before normal deobfuscation")
    ap.add_argument("--dex", action="append", type=Path, default=[], help="dex/apk/zip/dir used by --dex-restore; can be repeated")
    ap.add_argument("--dex-only", action="store_true", help="with --dex-restore, only run static DEX restore and skip normal renaming/inlining")
    ap.add_argument("--no-flat-v3", action="store_true", help="with --dex-restore, do not normalize .iyu into V3 flat View format")
    args = ap.parse_args(argv)
    out = deobfuscate(
        args.src_zip,
        args.output,
        args.workdir,
        restore_props=not args.no_restore_props,
        restore_events=not args.no_restore_events,
        rename_vars=not args.no_rename_vars,
        rename_files=not args.no_rename_files,
        rename_functions=not args.no_rename_functions,
        restore_resource_names=not args.no_restore_resource_names,
        dex_restore=bool(args.dex_restore),
        dex_paths=list(args.dex or []),
        flat_v3=not args.no_flat_v3,
        dex_only=bool(args.dex_only),
    )
    print(out)
    return 0

# IAPT_RESOURCE_SUFFIX_AND_REFS_V15_BEGIN
# V15: do NOT force resources into drawable/raw/font directories.  The previous
# V14 misunderstood the requested behaviour.  This block only normalizes hidden
# or unreadable folder/file names while preserving the visible resource layout:
#   res/3fb5cf.../rawpic      -> res/folder1/rawpic.png
#   res/ۖۥۙ.../abc           -> res/folder2/abc.png
#   res/image27               -> res/image27.png
# Standard Android directories such as res/drawable-mdpi-v4/ are preserved.
# Source references are rewritten to the new relative path under res/.


def header_ext(data: bytes) -> str:
    h = bytes(data or b"")[:4096]
    if h.startswith(b"\x89PNG\r\n\x1a\n"):
        return ".png"
    if h.startswith(b"\xff\xd8\xff"):
        return ".jpg"
    if h.startswith((b"GIF87a", b"GIF89a")):
        return ".gif"
    if len(h) >= 12 and h[:4] == b"RIFF" and h[8:12] == b"WEBP":
        return ".webp"
    if h.startswith(b"BM"):
        return ".bmp"
    if h.startswith(b"\x00\x00\x01\x00"):
        return ".ico"
    if h.startswith(b"%PDF-"):
        return ".pdf"
    if len(h) >= 12 and h[:4] == b"RIFF" and h[8:12] == b"WAVE":
        return ".wav"
    if h.startswith(b"OggS"):
        return ".ogg"
    if h.startswith(b"fLaC"):
        return ".flac"
    if h.startswith(b"#!AMR"):
        return ".amr"
    if h.startswith(b"ID3") or (len(h) >= 2 and h[0] == 0xff and (h[1] & 0xe0) == 0xe0):
        return ".mp3"
    if len(h) >= 12 and h[4:8] == b"ftyp":
        brand = h[8:12].lower()
        return ".m4a" if brand in (b"m4a ", b"m4b ") else ".mp4"
    if h.startswith(b"PK\x03\x04"):
        return ".zip"
    if h.startswith((b"\x00\x01\x00\x00", b"true", b"ttcf")):
        return ".ttf"
    if h.startswith(b"OTTO"):
        return ".otf"
    if len(h) >= 8 and h[0:2] == b"\x03\x00" and h[2:4] in (b"\x08\x00", b"\x0c\x00"):
        return ".xml"
    if len(h) >= 8 and h[0:2] == b"\x02\x00" and h[2:4] in (b"\x0c\x00", b"\x08\x00"):
        return ".arsc"
    sample = h.lstrip(b"\xef\xbb\xbf\x00\x20\x09\x0d\x0a")
    low = sample[:512].lower()
    if low.startswith(b"<svg"):
        return ".svg"
    if low.startswith((b"<!doctype html", b"<html", b"<head", b"<body")):
        return ".html"
    if low.startswith((b"<?xml", b"<resources", b"<selector", b"<shape", b"<layer-list", b"<vector", b"<animated-", b"<bitmap", b"<ripple")):
        return ".xml"
    if low.startswith((b"{", b"[")):
        return ".json"
    try:
        decoded = sample.decode("utf-8")
        if decoded and "\x00" not in decoded:
            stripped = decoded.lstrip()
            if stripped.startswith("<"):
                return ".xml"
            return ".txt"
    except Exception:
        pass
    return ""


def ext_from_hint(kind: str) -> str:
    kind = str(kind or "").strip().lower()
    if kind == "font":
        return ".ttf"
    if kind == "audio":
        return ".mp3"
    if kind == "image":
        return ".png"
    if kind == "html":
        return ".html"
    if kind == "xml":
        return ".xml"
    return ".bin"


def _iapt_resource_v15_clean_stem(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_\-\u4e00-\u9fff]+", "_", str(value or "")).strip("._-")
    return value[:80]


def _iapt_resource_v15_prefix(ext: str, kind: str) -> str:
    ext = str(ext or "").lower()
    kind = str(kind or "").lower()
    if kind == "image" or ext in (".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico"):
        return "image"
    if kind == "audio" or ext in (".mp3", ".wav", ".ogg", ".flac", ".m4a", ".amr"):
        return "audio"
    if kind == "font" or ext in (".ttf", ".otf"):
        return "font"
    if ext == ".html":
        return "page"
    if ext == ".xml":
        return "xml"
    return "file"


def _iapt_resource_v15_existing_ext(path: Path, data: bytes, kind: str) -> str:
    name = path.name
    low = name.lower()
    if low.endswith(".9.png"):
        return ".9.png"
    suffix = path.suffix.lower()
    if suffix:
        return suffix
    return header_ext(data) or ext_from_hint(kind)


def _iapt_resource_v15_name_without_ext(path: Path, ext: str) -> str:
    name = path.name
    if ext and name.lower().endswith(ext.lower()):
        return name[: -len(ext)]
    return path.stem if path.suffix else name


def _iapt_resource_v15_standard_res_segment(seg: str) -> bool:
    seg = str(seg or "").lower()
    base = seg.split("-", 1)[0]
    return base in {
        "drawable", "mipmap", "raw", "xml", "font", "layout", "anim", "animator",
        "color", "menu", "values", "transition", "interpolator",
    }


def _iapt_resource_v15_is_bad_name(name: str) -> bool:
    s = str(name or "")
    clean = _iapt_resource_v15_clean_stem(s)
    if not clean:
        return True
    try:
        if ugly_score(s) > 0:
            return True
    except Exception:
        pass
    try:
        if HASH_NAME_RE.fullmatch(s):
            return True
    except Exception:
        if re.fullmatch(r"[0-9a-fA-F]{16,64}", s):
            return True
    # Treat mostly-hex directory names as obfuscated too, even when length is not exactly 16/32/64.
    body = s.replace("_", "").replace("-", "")
    if len(body) >= 12 and re.fullmatch(r"[0-9a-fA-F]+", body):
        return True
    if len(s) > 80:
        return True
    return False


def _iapt_resource_v15_normalize_parent(parent_rel: str, ext: str, kind: str, folder_map: Dict[str, str], counters: Dict[str, int]) -> str:
    # parent_rel is like "res", "res/3fb...", "res/drawable-mdpi-v4".
    parts = [p for p in str(parent_rel or "res").replace("\\", "/").strip("/").split("/") if p]
    if not parts or parts[0].lower() != "res":
        parts = ["res"] + parts
    out = ["res"]
    for idx, seg in enumerate(parts[1:], start=1):
        key = "/".join(parts[: idx + 1])
        if idx == 1 and _iapt_resource_v15_standard_res_segment(seg):
            out.append(seg)
            continue
        if not _iapt_resource_v15_is_bad_name(seg):
            out.append(_iapt_resource_v15_clean_stem(seg))
            continue
        if key not in folder_map:
            prefix = _iapt_resource_v15_prefix(ext, kind)
            group = prefix + "_folder"
            counters[group] = counters.get(group, 0) + 1
            folder_map[key] = f"{group}{counters[group]}"
        out.append(folder_map[key])
    return "/".join(out)


def build_resource_map(files: List[Path], raw_dir: Path, texts: Dict[str, str]) -> Dict[str, str]:
    res_files = [
        p for p in files
        if p.is_file() and is_res_file(p.relative_to(raw_dir).as_posix())
    ]
    if not res_files:
        return {}
    hints = collect_resource_hints(texts)
    occupied = {p.relative_to(raw_dir).as_posix().lower() for p in res_files}
    counters: Dict[str, int] = {}
    folder_map: Dict[str, str] = {}
    out: Dict[str, str] = {}
    planned_lower = set()

    for p in sorted(res_files, key=lambda x: x.relative_to(raw_dir).as_posix()):
        rel = p.relative_to(raw_dir).as_posix()
        key = resource_key(rel)
        data = p.read_bytes()[:4096]
        kind = hints.get(key) or hints.get(Path(key).name) or ""
        ext = _iapt_resource_v15_existing_ext(p, data, kind)
        if not ext.startswith("."):
            ext = "." + ext

        parent = p.parent.relative_to(raw_dir).as_posix()
        target_parent = _iapt_resource_v15_normalize_parent(parent, ext, kind, folder_map, counters)
        old_base = _iapt_resource_v15_name_without_ext(p, ext)
        clean_base = _iapt_resource_v15_clean_stem(old_base)
        readable = bool(clean_base) and not _iapt_resource_v15_is_bad_name(old_base)
        if readable:
            base = clean_base
        else:
            prefix = _iapt_resource_v15_prefix(ext, kind)
            counters[prefix] = counters.get(prefix, 0) + 1
            base = f"{prefix}{counters[prefix]}"

        candidate = f"{target_parent}/{base}{ext}"
        serial = 2
        while ((candidate.lower() in occupied and candidate.lower() != rel.lower()) or candidate.lower() in planned_lower):
            candidate = f"{target_parent}/{base}_{serial}{ext}"
            serial += 1
        planned_lower.add(candidate.lower())

        if candidate != rel:
            out[rel] = candidate
    return out


def _iapt_resource_v15_replace_one(text: str, old: str, new: str) -> str:
    if not old or old == new:
        return text
    eo = re.escape(old)
    # Prevent basename replacement inside an already-restored path.
    pre = r'(?<![A-Za-z0-9_./-])' if "/" not in old else ""
    boundary = r'(?=[\s"\'\),;<>]|$)'
    text = re.sub(r'([@$])' + pre + eo + boundary, lambda m: m.group(1) + new, text)
    text = re.sub(
        r'((?:typeface|src|background|backgroundimage|image|icon)\s*=\s*["\']?)([@$]?)'
        + pre + eo + r'(?=(?:["\']|\s|<|>|$))',
        lambda m: m.group(1) + m.group(2) + new,
        text,
        flags=re.I,
    )
    text = re.sub(
        r'(\b(?:us|ucnmsb)\s*\([^;\n]*?"(?:typeface|src|background|backgroundimage|image|icon)"\s*,\s*")([@$]?)'
        + pre + eo + r'(")',
        lambda m: m.group(1) + m.group(2) + new + m.group(3),
        text,
        flags=re.I,
    )
    text = re.sub(
        r"(\b(?:us|ucnmsb)\s*\([^;\n]*?'(?:typeface|src|background|backgroundimage|image|icon)'\s*,\s*')([@$]?)"
        + pre + eo + r"(')",
        lambda m: m.group(1) + m.group(2) + new + m.group(3),
        text,
        flags=re.I,
    )
    text = re.sub(
        r'(\b(?:bfm|res|bfs|tot|tzz|tsf|tfz|sutf8to)\s*\(\s*")([@$]?)'
        + pre + eo + r'(")',
        lambda m: m.group(1) + m.group(2) + new + m.group(3),
        text,
        flags=re.I,
    )
    text = re.sub(
        r"(\b(?:bfm|res|bfs|tot|tzz|tsf|tfz|sutf8to)\s*\(\s*')([@$]?)"
        + pre + eo + r"(')",
        lambda m: m.group(1) + m.group(2) + new + m.group(3),
        text,
        flags=re.I,
    )
    return text


def replace_resource_refs(text: str, resource_map: Dict[str, str]) -> str:
    if not resource_map:
        return text
    for old_rel, new_rel in sorted(resource_map.items(), key=lambda kv: len(kv[0]), reverse=True):
        old_key = resource_key(old_rel)
        new_key = resource_key(new_rel)
        pairs = [
            (old_rel, new_rel),
            (old_key, new_key),
            (Path(old_key).name, new_key),
        ]
        # If only folder changed, also rewrite the old folder/name pair before basename fallback.
        if "/" in old_key:
            pairs.insert(2, (old_key, new_key))
        seen = set()
        for old, new in pairs:
            marker = (old, new)
            if marker in seen:
                continue
            seen.add(marker)
            text = _iapt_resource_v15_replace_one(text, old, new)
    return text
# IAPT_RESOURCE_SUFFIX_AND_REFS_V15_END

# IAPT_INLINE_EXTRACTED_PROPS_V16_BEGIN
# V16: restore inline property-extraction pairs that are already present inside
# .iyu files, not only pairs hidden in module functions called from loading.
# Example:
#   s+(-271,272,w3)
#   us(w3,"width","-1")
# becomes a normal <ppt> property on View id=1, and both code lines are removed.
# This is intentionally separate from V15 resource-name restoration.
_IAPT_INLINE_PROPS_V16_PREV_RESTORE = globals().get('restore_extracted_view_props')

_IAPT_INLINE_PROPS_V16_MATH_RE = re.compile(
    r'^\s*s([+\-*/%])\(\s*(-?\d+)\s*,\s*(-?\d+)\s*,\s*(' + IDENT_RE_SRC + r')\s*\)\s*$'
)
_IAPT_INLINE_PROPS_V16_US_RE = re.compile(
    r'^\s*(?:us|ucnmsb)\(\s*([^,]+?)\s*,\s*"([^"]+)"\s*,\s*"((?:\\.|[^"\\])*)"\s*\)\s*$'
)


def _iapt_inline_props_v16_calc(op: str, a: int, b: int) -> int:
    if op == '+':
        return a + b
    if op == '-':
        return a - b
    if op == '*':
        return a * b
    if op == '/':
        if b == 0:
            raise ZeroDivisionError('iApp inline property division by zero')
        return int(a / b)
    if op == '%':
        if b == 0:
            raise ZeroDivisionError('iApp inline property modulo by zero')
        return a % b
    raise ValueError(op)


def _iapt_inline_props_v16_view_ids(text: str) -> set[int]:
    ids: set[int] = set()
    for m in re.finditer(r'<View\b[^>]*\bid\s*=\s*["\']?(-?\d+)["\']?', text, flags=re.I):
        try:
            ids.add(int(m.group(1)))
        except Exception:
            pass
    return ids


def _iapt_inline_props_v16_parse_lines(lines: list[str]) -> tuple[dict[int, list[tuple[str, str]]], set[int]]:
    props: dict[int, list[tuple[str, str]]] = {}
    removable: set[int] = set()
    i = 0
    n = len(lines)
    while i < n:
        m = _IAPT_INLINE_PROPS_V16_MATH_RE.match(lines[i])
        if not m:
            i += 1
            continue
        op, a_s, b_s, temp = m.group(1), m.group(2), m.group(3), m.group(4)
        try:
            view_id = _iapt_inline_props_v16_calc(op, int(a_s), int(b_s))
        except Exception:
            i += 1
            continue

        j = i + 1
        local_props: list[tuple[str, str]] = []
        local_remove: set[int] = {i}
        # Allow blank separator lines, but only consume consecutive property calls
        # that use the just-produced temporary variable.  This avoids deleting
        # unrelated runtime math code elsewhere in page scripts.
        while j < n:
            if not lines[j].strip():
                j += 1
                continue
            um = _IAPT_INLINE_PROPS_V16_US_RE.match(lines[j])
            if not um or um.group(1).strip() != temp:
                break
            local_props.append((um.group(2), um.group(3)))
            local_remove.add(j)
            j += 1
        if local_props:
            props.setdefault(view_id, []).extend(local_props)
            removable.update(local_remove)
            i = j
        else:
            i += 1
    return props, removable


def _iapt_inline_props_v16_remove_lines(text: str, removable: set[int]) -> str:
    if not removable:
        return text
    lines = text.splitlines()
    kept = [line for idx, line in enumerate(lines) if idx not in removable]
    return '\n'.join(kept) + ('\n' if text.endswith('\n') else '')


def _iapt_inline_props_v16_restore_text(text: str) -> tuple[str, dict[int, list[tuple[str, str]]]]:
    lines = text.splitlines()
    props, removable = _iapt_inline_props_v16_parse_lines(lines)
    if not props or not removable:
        return text, {}
    ids = _iapt_inline_props_v16_view_ids(text)
    if ids:
        props = {vid: pairs for vid, pairs in props.items() if vid in ids}
    if not props:
        return text, {}
    # Remove script pairs first, then merge the recovered properties into <ppt>.
    cleaned = _iapt_inline_props_v16_remove_lines(text, removable)
    restored = apply_props_to_iyu(cleaned, props)
    return restored, props


def _iapt_inline_props_v16_merge_report(
    base: dict[str, dict[int, list[tuple[str, str]]]],
    rel: str,
    props: dict[int, list[tuple[str, str]]],
) -> None:
    if not props:
        return
    slot = base.setdefault(rel, {})
    for vid, pairs in props.items():
        slot.setdefault(vid, []).extend(pairs)


def restore_extracted_view_props(texts: Dict[str, str]) -> Tuple[Dict[str, str], Dict[str, Dict[int, List[Tuple[str, str]]]]]:
    prev = _IAPT_INLINE_PROPS_V16_PREV_RESTORE
    if callable(prev):
        texts, restored = prev(texts)
    else:
        restored = {}

    # Existing implementation only followed module functions referenced from
    # loading.  Some protectors place the arithmetic-temp + us(temp,...) pairs
    # directly in the .iyu page event body after deobfuscation/iACT reversal.
    # Handle those direct page-level pairs here.
    for rel, text in list(texts.items()):
        if not rel.endswith('.iyu'):
            continue
        new_text, props = _iapt_inline_props_v16_restore_text(text)
        if props:
            texts[rel] = new_text
            _iapt_inline_props_v16_merge_report(restored, rel, props)
    return texts, restored
# IAPT_INLINE_EXTRACTED_PROPS_V16_END

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
