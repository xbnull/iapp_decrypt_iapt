#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static recovery of metadata semantics used by protected iApp containers.

The normal decryptor already models the idbfj/slky concatenation graph.  This
module supplies the missing layer immediately below that graph: transformations
applied to APK metadata before the fields are concatenated, for example::

    versionName "1.0" -> std::stof -> std::to_string(float) -> "1.000000"

No metadata values are enumerated.  A non-identity operation is accepted only
when it is visible inside an exact iApp idbfj/burden symbol range (or supported
by matching exact ranges from sibling ABIs).  Unsupported transforms are
reported and left unchanged rather than guessed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

HERE = Path(__file__).resolve().parent
if str(HERE) not in os.sys.path:
    os.sys.path.insert(0, str(HERE))

from apk_meta_fast import read_apk_meta

ANALYZER_BUILD = "static-parameter-analyzer-v2-native-exact-format-dataflow"


class StaticParameterAnalysisError(RuntimeError):
    pass


@dataclass
class NativeFunctionEvidence:
    entry: str
    abi: str
    symbol: str
    start: int
    stop: int
    calls: List[str] = field(default_factory=list)
    strings: List[str] = field(default_factory=list)
    operations: List[Dict[str, Any]] = field(default_factory=list)
    unsupported_numeric_calls: List[str] = field(default_factory=list)
    disassembly_sha256: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return {
            "entry": self.entry,
            "abi": self.abi,
            "symbol": self.symbol,
            "range": [hex(self.start), hex(self.stop)],
            "calls": self.calls,
            "strings": self.strings,
            "operations": self.operations,
            "unsupported_numeric_calls": self.unsupported_numeric_calls,
            "disassembly_sha256": self.disassembly_sha256,
        }


def _run(command: Sequence[str], timeout: int = 35) -> str:
    proc = subprocess.run(
        list(command), stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        check=False, timeout=timeout, text=True, errors="replace"
    )
    if proc.returncode != 0 and not proc.stdout:
        raise StaticParameterAnalysisError(
            "command failed: %s: %s" % (" ".join(command), proc.stderr.strip()[:600])
        )
    return proc.stdout


def _tool(name: str, fallbacks: Sequence[str] = ()) -> Optional[str]:
    value = shutil.which(name)
    if value:
        return value
    for item in fallbacks:
        if Path(item).is_file():
            return item
    return None


def _nm_symbols(path: Path) -> List[Tuple[int, str, str]]:
    nm = _tool("nm")
    if not nm:
        raise StaticParameterAnalysisError("nm is required")
    merged: Dict[Tuple[int, str], Tuple[int, str, str]] = {}
    # Dynamic symbols cover ordinary NDK builds; the full symbol table recovers
    # locally bound idbfj/helpers when the protector only hides exports.
    for extra in (("-D",), tuple()):
        try:
            text = _run([nm, *extra, "-n", "-C", str(path)])
        except Exception:
            continue
        for line in text.splitlines():
            m = re.match(r"^\s*([0-9a-fA-F]+)\s+([A-Za-z])\s+(.+?)\s*$", line)
            if not m:
                continue
            try:
                row = (int(m.group(1), 16), m.group(2), m.group(3))
                merged[(row[0], row[2])] = row
            except Exception:
                pass
    rows = list(merged.values())
    rows.sort(key=lambda x: (x[0], x[2]))
    return rows


def _function_ranges(symbols: List[Tuple[int, str, str]], allow_fallback: bool = False) -> List[Tuple[int, int, str]]:
    targets: List[Tuple[int, int, str]] = []
    for i, (address, typ, name) in enumerate(symbols):
        low = name.lower()
        if "idbfj(" not in low and "burden::a(" not in low and "burden::b(" not in low:
            continue
        stop = 0
        for j in range(i + 1, len(symbols)):
            if symbols[j][0] > address:
                stop = symbols[j][0]
                break
        if stop <= address:
            stop = address + 0x8000
        # Protect against aliases and unrelated huge ranges.
        stop = min(stop, address + 0x20000)
        targets.append((address, stop, name))
    if not targets and allow_fallback:
        # Unknown/renamed consumers: analyse exported/local executable symbols,
        # but only after the caller has proved the SO contains metadata and
        # numeric-format primitives.  This is the expensive all-SO fallback.
        for i, (address, typ, name) in enumerate(symbols):
            if typ not in ("T", "t", "W", "w") or address <= 0:
                continue
            stop = 0
            for j in range(i + 1, len(symbols)):
                if symbols[j][0] > address:
                    stop = symbols[j][0]
                    break
            if stop <= address or stop - address > 0x10000:
                continue
            targets.append((address, stop, name))
    return targets


def _load_segments(path: Path) -> List[Tuple[int, int, int]]:
    readelf = _tool("readelf")
    if not readelf:
        return []
    text = _run([readelf, "-lW", str(path)])
    rows: List[Tuple[int, int, int]] = []
    # Type Offset VirtAddr PhysAddr FileSiz MemSiz Flags Align
    for line in text.splitlines():
        m = re.match(
            r"^\s*LOAD\s+(0x[0-9a-fA-F]+)\s+(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+"
            r"(0x[0-9a-fA-F]+)\s+0x[0-9a-fA-F]+\s+.*$",
            line,
        )
        if not m:
            continue
        off, va, size = (int(m.group(k), 16) for k in (1, 2, 3))
        rows.append((va, off, size))
    return rows


def _vaddr_to_offset(vaddr: int, segments: Sequence[Tuple[int, int, int]]) -> Optional[int]:
    for va, off, size in segments:
        if va <= vaddr < va + size:
            return off + (vaddr - va)
    return None


def _read_c_string(blob: bytes, offset: Optional[int], max_len: int = 180) -> Optional[str]:
    if offset is None or offset < 0 or offset >= len(blob):
        return None
    end = offset
    while end < len(blob) and end - offset < max_len and blob[end] != 0:
        b = blob[end]
        if b < 0x20 or b > 0x7E:
            return None
        end += 1
    if end == offset or end >= len(blob) or blob[end] != 0:
        return None
    try:
        return blob[offset:end].decode("ascii")
    except Exception:
        return None


def _referenced_strings(disasm: str, path: Path) -> List[str]:
    blob = path.read_bytes()
    segments = _load_segments(path)
    addresses: List[int] = []
    arm_pages: Dict[str, int] = {}
    for line in disasm.splitlines():
        # llvm-objdump x86 comments: # 0x2e5ce
        for m in re.finditer(r"#\s*(0x[0-9a-fA-F]+)", line):
            addresses.append(int(m.group(1), 16))
        # AArch64 commonly materialises rodata with adrp + add.
        m = re.search(r"\badrp\s+(x[0-9]+),\s*(0x[0-9a-fA-F]+)", line)
        if m:
            arm_pages[m.group(1)] = int(m.group(2), 16)
            continue
        m = re.search(r"\badd\s+(x[0-9]+),\s*(x[0-9]+),\s*#(0x[0-9a-fA-F]+|[0-9]+)", line)
        if m and m.group(2) in arm_pages:
            value = arm_pages[m.group(2)] + int(m.group(3), 0)
            arm_pages[m.group(1)] = value
            addresses.append(value)
            continue
        m = re.search(r"\badr\s+(x[0-9]+),\s*(0x[0-9a-fA-F]+)", line)
        if m:
            value = int(m.group(2), 16)
            arm_pages[m.group(1)] = value
            addresses.append(value)
    out: List[str] = []
    seen = set()
    for va in addresses:
        for candidate in (va, va & ~0xFFF):
            text = _read_c_string(blob, _vaddr_to_offset(candidate, segments))
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    # x86 shared libraries in the supplied families use equal file/vaddr offsets
    # for rodata.  Keep this safe fallback for stripped/malformed program headers.
    if not out:
        for va in addresses:
            text = _read_c_string(blob, va)
            if text and text not in seen:
                seen.add(text)
                out.append(text)
    return out[:160]


def _call_targets(disasm: str) -> List[str]:
    out: List[str] = []
    seen = set()
    for line in disasm.splitlines():
        if not re.search(r"\b(callq?|bl|blx)\b", line):
            continue
        m = re.search(r"<(.+)>\s*$", line.strip())
        if not m:
            continue
        name = m.group(1)
        # Drop offsets only when they are appended outside a template name.
        name = re.sub(r"\+0x[0-9a-fA-F]+$", "", name)
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _normal_call(name: str) -> str:
    return re.sub(r"\s+", "", name.lower())


def _contains_any(calls: Sequence[str], patterns: Sequence[str]) -> List[str]:
    found: List[str] = []
    for call in calls:
        norm = _normal_call(call)
        if any(re.search(pattern, norm) for pattern in patterns):
            found.append(call)
    return found


_PRINTF_FLOAT_RE = re.compile(
    r"%(?!%)(?P<flags>[-+ #0']*)(?P<width>\d+)?(?:\.(?P<precision>\d+))?(?P<length>[lL]?)(?P<conv>[eEfFgG])"
)


def _printf_float_templates(strings: Sequence[str]) -> List[Dict[str, str]]:
    """Return exact one-float printf templates referenced by the SO function.

    Prefix/suffix bytes are retained.  Templates with dynamic width/precision,
    multiple conversions, or an unparsed percent token are rejected rather than
    guessed.
    """
    rows: List[Dict[str, str]] = []
    seen = set()
    for raw in strings:
        text = str(raw)
        if not text or len(text) > 160 or "\x00" in text:
            continue
        matches = list(_PRINTF_FLOAT_RE.finditer(text))
        if len(matches) != 1:
            continue
        match = matches[0]
        remainder = text[:match.start()] + text[match.end():]
        # Remove escaped percent pairs before checking for another conversion.
        if "%" in remainder.replace("%%", ""):
            continue
        spec = match.group(0)
        signature = (text, spec)
        if signature in seen:
            continue
        seen.add(signature)
        rows.append({
            "template": text,
            "conversion": spec,
            "precision": str(match.group("precision") or ""),
            "width": str(match.group("width") or ""),
            "flags": str(match.group("flags") or ""),
            "type": str(match.group("conv") or ""),
        })
    return rows


def _operation_signature(operation: Dict[str, Any]) -> str:
    stable = {
        key: operation.get(key)
        for key in (
            "field", "op", "input_type", "format", "format_template",
            "format_conversion", "precision", "prefix", "suffix",
        )
        if operation.get(key) not in (None, "")
    }
    return json.dumps(stable, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _apply_printf_float(value: str, operation: Dict[str, Any]) -> str:
    template = str(operation.get("format_template") or "")
    conversion = str(operation.get("format_conversion") or "")
    if not template or not conversion or template.count(conversion) != 1:
        raise ValueError("invalid exact printf template")
    if "*" in conversion:
        raise ValueError("dynamic printf width/precision is unsupported")
    match = _PRINTF_FLOAT_RE.fullmatch(conversion)
    if not match:
        raise ValueError("unsupported printf conversion: " + conversion)
    # Python's percent formatter does not accept C's l/L length modifier.
    py_conversion = conversion
    length = str(match.group("length") or "")
    if length:
        start, stop = match.span("length")
        py_conversion = conversion[:start] + conversion[stop:]
    py_template = template.replace(conversion, py_conversion, 1)
    number = float(str(value).strip())
    if str(operation.get("input_type") or "") == "float32":
        number = struct.unpack("<f", struct.pack("<f", number))[0]
    try:
        result = py_template % number
    except Exception as exc:
        raise ValueError("printf format application failed: " + str(exc)) from exc
    if not isinstance(result, str) or len(result) > 512:
        raise ValueError("printf format produced invalid output")
    return result



def _detect_operations(calls: Sequence[str], strings: Sequence[str], symbol: str) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Detect metadata transforms only from exact native evidence.

    The detected format is the literal format/template referenced by the SO;
    no decimal precision or suffix is invented by this analyzer.
    """
    norm_strings = {s.lower() for s in strings}
    symbol_low = symbol.lower()
    has_version_ref = any("versionname" in s for s in norm_strings)
    is_idbfj = "idbfj(" in symbol_low
    runtime_idbfj = is_idbfj and symbol.count("const&") == 1
    generic_metadata_function = (
        has_version_ref
        and any(("packagename" in x or "versioncode" in x or "loadlabel" in x) for x in norm_strings)
    )
    proven_runtime_metadata = runtime_idbfj or generic_metadata_function

    stof = _contains_any(calls, [
        r"(^|::)stof\(", r"4stof", r"stof@", r"strtof(@|\()", r"atof(@|\()",
    ])
    stod = _contains_any(calls, [
        r"(^|::)stod\(", r"4stod", r"stod@", r"strtod(@|\()",
    ])
    stoi = _contains_any(calls, [
        r"(^|::)stoi\(", r"4stoi", r"(^|::)stol\(", r"4stol",
        r"(^|::)stoll\(", r"5stoll", r"atoi(@|\()", r"strtol(l)?(@|\()",
    ])
    to_float = _contains_any(calls, [r"to_string\(float\)", r"9to_stringef(?:@|$)"])
    to_double = _contains_any(calls, [r"to_string\(double\)", r"9to_stringed(?:@|$)"])
    to_int = _contains_any(calls, [
        r"to_string\((unsigned)?(int|long|longlong)\)",
        r"9to_stringe[ijlmxy](?:@|$)",
    ])
    format_calls = _contains_any(calls, [
        r"__to_xstring", r"vsnprintf", r"snprintf", r"sprintf",
    ])
    format_templates = _printf_float_templates(strings)

    operations: List[Dict[str, Any]] = []
    unsupported: List[str] = []
    if proven_runtime_metadata and has_version_ref and stof and to_float:
        operations.append({
            "field": "version_name",
            "op": "cpp_float_to_string",
            "input_type": "float32",
            "format": "fixed-6",
            "format_template": "%.6f",
            "format_conversion": "%.6f",
            "precision": 6,
            "evidence_calls": stof + to_float,
            "reason": "exact idbfj range parses versionName as float and calls std::to_string(float)",
        })
    elif proven_runtime_metadata and has_version_ref and stod and to_double:
        operations.append({
            "field": "version_name",
            "op": "cpp_double_to_string",
            "input_type": "float64",
            "format": "fixed-6",
            "format_template": "%.6f",
            "format_conversion": "%.6f",
            "precision": 6,
            "evidence_calls": stod + to_double,
            "reason": "exact idbfj range parses versionName as double and calls std::to_string(double)",
        })
    elif proven_runtime_metadata and has_version_ref and (stof or stod) and format_calls:
        if len(format_templates) == 1:
            fmt = dict(format_templates[0])
            input_type = "float32" if stof else "float64"
            op_name = "cpp_printf_float" if stof else "cpp_printf_double"
            operations.append({
                "field": "version_name",
                "op": op_name,
                "input_type": input_type,
                "format": "native-printf-template",
                "format_template": fmt["template"],
                "format_conversion": fmt["conversion"],
                "precision": int(fmt["precision"]) if fmt["precision"] else None,
                "prefix": fmt["template"][:fmt["template"].find(fmt["conversion"])],
                "suffix": fmt["template"][fmt["template"].find(fmt["conversion"]) + len(fmt["conversion"]):],
                "evidence_calls": (stof or stod) + format_calls,
                "evidence_strings": [fmt["template"]],
                "reason": "exact SO function parses versionName and formats it with the referenced native printf template",
            })
        elif len(format_templates) > 1:
            unsupported.append(
                "ambiguous versionName printf templates: "
                + json.dumps([row["template"] for row in format_templates], ensure_ascii=False)
            )
    elif runtime_idbfj and stoi and to_int and has_version_ref:
        operations.append({
            "field": "version_name",
            "op": "cpp_integer_to_string",
            "input_type": "integer",
            "format": "canonical-decimal",
            "evidence_calls": stoi + to_int,
            "reason": "exact idbfj range parses versionName as integer before std::to_string",
        })

    numeric = _contains_any(calls, [
        r"stof", r"stod", r"stoi", r"stol", r"stoll",
        r"strtof", r"strtod", r"strtol", r"atoi", r"atof", r"snprintf", r"sprintf",
    ])
    claimed = set()
    for operation in operations:
        claimed.update(operation.get("evidence_calls") or [])
    unsupported.extend([item for item in numeric if item not in claimed])
    return operations, unsupported



def _analyse_so(path: Path, entry: str, allow_fallback: bool = False) -> List[NativeFunctionEvidence]:
    objdump = _tool("llvm-objdump", ("/usr/local/swift/usr/bin/llvm-objdump",)) or _tool("objdump")
    if not objdump:
        raise StaticParameterAnalysisError("llvm-objdump/objdump is required")
    symbols = _nm_symbols(path)
    ranges = _function_ranges(symbols, allow_fallback=allow_fallback)
    abi = ""
    parts = entry.replace("\\", "/").split("/")
    if len(parts) >= 3 and parts[0].lower() == "lib":
        abi = parts[1]
    out: List[NativeFunctionEvidence] = []
    for start, stop, symbol in ranges:
        command = [objdump, "-d", "-r", "-C", "--start-address=" + hex(start), "--stop-address=" + hex(stop), str(path)]
        try:
            disasm = _run(command, timeout=45)
        except Exception:
            continue
        calls = _call_targets(disasm)
        strings = _referenced_strings(disasm, path)
        ops, unsupported = _detect_operations(calls, strings, symbol)
        out.append(NativeFunctionEvidence(
            entry=entry, abi=abi, symbol=symbol, start=start, stop=stop,
            calls=calls, strings=strings, operations=ops,
            unsupported_numeric_calls=unsupported,
            disassembly_sha256=hashlib.sha256(disasm.encode("utf-8", "replace")).hexdigest(),
        ))
    return out


def _cpp_float32_to_string(value: str) -> str:
    number = float(str(value).strip())
    number32 = struct.unpack("<f", struct.pack("<f", number))[0]
    return format(number32, ".6f")


def _cpp_double_to_string(value: str) -> str:
    return format(float(str(value).strip()), ".6f")


def _cpp_integer_to_string(value: str) -> str:
    text = str(value).strip()
    # Match C++ decimal parser semantics for normal version strings, but fail
    # closed for partial parses such as "1.2" rather than silently returning 1.
    if not re.fullmatch(r"[+-]?\d+", text):
        raise ValueError("not a complete integer string: " + text)
    return str(int(text, 10))



def _apply_operation(value: str, operation: Dict[str, Any] | str) -> str:
    if isinstance(operation, str):
        op = operation
        spec: Dict[str, Any] = {"op": operation}
    else:
        spec = dict(operation or {})
        op = str(spec.get("op") or "identity")
    if op == "identity":
        return str(value)
    if op == "cpp_float_to_string":
        return _cpp_float32_to_string(value)
    if op == "cpp_double_to_string":
        return _cpp_double_to_string(value)
    if op == "cpp_integer_to_string":
        return _cpp_integer_to_string(value)
    if op in ("cpp_printf_float", "cpp_printf_double"):
        return _apply_printf_float(value, spec)
    raise ValueError("unsupported metadata operation: " + op)




def _consensus(functions: Sequence[NativeFunctionEvidence]) -> Tuple[Dict[str, Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    votes: Dict[Tuple[str, str], List[Dict[str, Any]]] = {}
    specs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    unsupported: List[str] = []
    for fn in functions:
        for item in fn.unsupported_numeric_calls:
            unsupported.append(fn.entry + ":" + fn.symbol + ":" + item)
        for operation in fn.operations:
            field = str(operation.get("field") or "")
            signature = _operation_signature(operation)
            key = (field, signature)
            specs[key] = dict(operation)
            vote = dict(operation)
            vote["entry"] = fn.entry
            vote["abi"] = fn.abi
            vote["symbol"] = fn.symbol
            votes.setdefault(key, []).append(vote)

    selected: Dict[str, Dict[str, Any]] = {}
    evidence: List[Dict[str, Any]] = []
    by_field: Dict[str, List[Tuple[Dict[str, Any], List[Dict[str, Any]]]]] = {}
    for key, rows in votes.items():
        field, _signature = key
        by_field.setdefault(field, []).append((specs[key], rows))
    for field, choices in by_field.items():
        choices.sort(
            key=lambda item: (
                len({row.get("abi") for row in item[1] if row.get("abi")}),
                len(item[1]),
            ),
            reverse=True,
        )
        best_spec, rows = choices[0]
        if len(choices) > 1:
            top_abis = len({row.get("abi") for row in rows if row.get("abi")})
            next_abis = len({row.get("abi") for row in choices[1][1] if row.get("abi")})
            if next_abis == top_abis:
                unsupported.append(
                    "conflicting proven transforms for %s: %s"
                    % (field, [_operation_signature(choice[0]) for choice in choices])
                )
                continue
        selected[field] = dict(best_spec)
        evidence.extend(rows)
    return selected, evidence, sorted(set(unsupported))




def analyze_parameter_plan(apk_path: Path | str, metadata_override: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    apk_path = Path(apk_path)
    raw = read_apk_meta(apk_path)
    if metadata_override:
        for key in ("package_name", "version_name", "version_code", "app_name"):
            value = metadata_override.get(key)
            if value is not None and str(value) != "":
                raw[key] = str(value)

    functions: List[NativeFunctionEvidence] = []
    errors: List[str] = []
    native_entries: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as zf, tempfile.TemporaryDirectory(prefix="iapt-param-") as td:
        root = Path(td)
        for info in zf.infolist():
            name = info.filename.replace("\\", "/")
            low = name.lower()
            if info.is_dir() or not low.endswith(".so") or not low.startswith("lib/"):
                continue
            blob = zf.read(info)
            exact_named = b"idbfj" in blob or b"Interact5idbfj" in blob
            fallback_candidate = (
                b"versionName" in blob
                and any(token in blob for token in (b"stof", b"stod", b"strtof", b"strtod", b"snprintf", b"sprintf", b"to_string"))
            )
            if not exact_named and not fallback_candidate:
                continue
            native_entries.append(name)
            target = root / (str(len(native_entries)) + "-" + Path(name).name)
            target.write_bytes(blob)
            try:
                functions.extend(_analyse_so(target, name, allow_fallback=not exact_named))
            except Exception as exc:
                errors.append(name + ": " + type(exc).__name__ + ": " + str(exc))

    selected_specs, op_evidence, unsupported = _consensus(functions)
    selected_operations = {
        field: str(spec.get("op") or "identity")
        for field, spec in selected_specs.items()
    }
    fields = {
        "package": ("package_name", "package"),
        "version_name": ("version_name", "versionName"),
        "version_code": ("version_code", "versionCode"),
        "app_label": ("app_name", "appLabel"),
    }
    metadata: Dict[str, Any] = {}
    apply_errors: List[str] = []
    for out_name, (raw_name, core_name) in fields.items():
        raw_value = str(raw.get(raw_name) or "")
        spec = dict(selected_specs.get(out_name) or {})
        effective = raw_value
        if spec:
            try:
                effective = _apply_operation(raw_value, spec)
            except Exception as exc:
                apply_errors.append(out_name + ": " + type(exc).__name__ + ": " + str(exc))
                spec = {}
                effective = raw_value
        candidates = []
        for value in (effective, raw_value):
            if value not in candidates:
                candidates.append(value)
        metadata[out_name] = {
            "core_name": core_name,
            "raw": raw_value,
            "effective": effective,
            "operations": [] if not spec else [str(spec.get("op") or "")],
            "operation_specs": [] if not spec else [spec],
            "candidates": candidates,
            "changed": raw_value != effective,
            "source": "AndroidManifest.xml/resources.arsc",
        }

    transformed_abis = sorted({str(row.get("abi") or "") for row in op_evidence if row.get("abi")})
    confidence = "identity-no-proven-transform"
    if op_evidence:
        confidence = "cross-abi-exact-function" if len(transformed_abis) >= 2 else "single-abi-exact-function"
    if apply_errors:
        confidence = "transform-detected-but-not-applicable"

    return {
        "build": ANALYZER_BUILD,
        "apk": apk_path.name,
        "apk_sha256": hashlib.sha256(apk_path.read_bytes()).hexdigest(),
        "metadata": metadata,
        "selected_operations": selected_operations,
        "selected_operation_specs": selected_specs,
        "confidence": confidence,
        "native_entries": native_entries,
        "operation_evidence": op_evidence,
        "functions": [fn.as_dict() for fn in functions],
        "unsupported_numeric_evidence": unsupported,
        "analysis_errors": errors,
        "apply_errors": apply_errors,
        "outer_expression_engine": {
            "implementation": "iapp_auto_decrypt.StaticOuterAnalyzer/OuterExpr",
            "role": "kept unchanged; SO-derived metadata candidates are injected into its environment",
        },
    }



def effective_metadata(plan: Dict[str, Any]) -> Dict[str, str]:
    meta = dict(plan.get("metadata") or {})
    return {
        "package": str((meta.get("package") or {}).get("effective") or ""),
        "version_name": str((meta.get("version_name") or {}).get("effective") or ""),
        "version_code": str((meta.get("version_code") or {}).get("effective") or ""),
        "app_label": str((meta.get("app_label") or {}).get("effective") or ""),
    }


def metadata_candidates(plan: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return only evidence-derived metadata followed by the original values.

    No guessed decimal padding or arbitrary suffix candidate is generated.
    """
    meta = dict(plan.get("metadata") or {})
    keys = ("package", "version_name", "version_code", "app_label")
    effective = {
        key: str((meta.get(key) or {}).get("effective") or "")
        for key in keys
    }
    raw = {
        key: str((meta.get(key) or {}).get("raw") or "")
        for key in keys
    }
    changed_fields = [key for key in keys if effective[key] != raw[key]]
    rows: List[Dict[str, Any]] = []
    if changed_fields and plan.get("operation_evidence") and not plan.get("apply_errors"):
        rows.append({
            "source": "so-derived",
            "values": effective,
            "changed_fields": changed_fields,
            "operation_specs": plan.get("selected_operation_specs") or {},
        })
    rows.append({
        "source": "original",
        "values": raw,
        "changed_fields": [],
        "operation_specs": {},
    })
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for row in rows:
        values = row.get("values") or {}
        signature = tuple(str(values.get(key) or "") for key in keys)
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(row)
    return deduped


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Static iApp metadata-semantics analyzer")
    p.add_argument("apk", type=Path)
    p.add_argument("--report", type=Path)
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    plan = analyze_parameter_plan(args.apk)
    text = json.dumps(plan, ensure_ascii=False, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
