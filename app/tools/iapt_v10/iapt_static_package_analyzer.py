#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Combined static resource + parameter-semantics normalization for iApp APKs."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
from typing import Iterable, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in os.sys.path:
    os.sys.path.insert(0, str(HERE))

from iapt_static_resource_analyzer import analyze_and_restore
from iapt_static_parameter_analyzer import analyze_parameter_plan, effective_metadata

BUILD = "static-package-analyzer-v1-resource-plus-parameter-semantics"


def analyze_package(apk: Path, normalized_apk: Path, *, lib_only: bool = False) -> dict:
    resource = analyze_and_restore(apk, normalized_apk, {
        "anti_encrypted_sample": True,
        "no_decrypt_resource_files": bool(lib_only),
        "skip_anti_resources": bool(lib_only),
    })
    parameters = analyze_parameter_plan(apk)
    effective = effective_metadata(parameters)
    return {
        "build": BUILD,
        "source_apk": str(apk),
        "normalized_apk": str(normalized_apk),
        "resource_plan": resource,
        "parameter_plan": parameters,
        "effective_core_metadata": effective,
        "core_args": [
            "--package", effective["package"],
            "--version-name", effective["version_name"],
            "--version-code", effective["version_code"],
            "--app-label", effective["app_label"],
        ],
    }


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="Static iApp resource and parameter analyzer")
    p.add_argument("apk", type=Path)
    p.add_argument("normalized_apk", type=Path)
    p.add_argument("--lib-only", action="store_true")
    p.add_argument("--report", type=Path)
    return p


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    report = analyze_package(args.apk.resolve(), args.normalized_apk.resolve(), lib_only=args.lib_only)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
