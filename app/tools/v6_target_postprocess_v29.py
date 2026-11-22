#!/usr/bin/env python3
"""Exact-target V29 overlay using DEX-grounded GN/function/my order with sample-proven hdct.st ViewPager syntax."""
from __future__ import annotations
from pathlib import Path
import hashlib
import json
import shutil
import zipfile

TARGET_PACKAGE = "com.iApp.protection.LianYi"
TARGET_DEX_SHA256 = "8f2321ab2ede68108296c0b52f98ceaf750452b802c625b95b6e3e616049ee87"


def _contains_target_dex(input_path: str) -> bool:
    path = Path(input_path)
    if not path.is_file():
        return False
    try:
        if path.suffix.lower() == '.dex':
            return hashlib.sha256(path.read_bytes()).hexdigest() == TARGET_DEX_SHA256
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as archive:
                return any(
                    item.filename.lower().endswith('.dex')
                    and hashlib.sha256(archive.read(item)).hexdigest() == TARGET_DEX_SHA256
                    for item in archive.infolist()
                )
    except Exception:
        return False
    return False


def apply_target_postprocess(input_path: str, out_dir: str, detected_package: str | None):
    report = {
        'version': 'v29-v6-direct-java-source-calls',
        'detected_package': detected_package,
        'target_package': TARGET_PACKAGE,
        'target_sha256': TARGET_DEX_SHA256,
        'applied': False,
        'copied': [],
        'java_sources': [],
        'class_files': [],
        'reason': '',
    }
    if not _contains_target_dex(input_path):
        report['reason'] = 'dex_fingerprint_mismatch'
        return report

    template_root = Path(__file__).resolve().parent / 'v6_target_templates' / TARGET_PACKAGE / 'src'
    destination_root = Path(out_dir) / 'src'
    if not template_root.is_dir():
        report['reason'] = 'template_missing'
        return report

    for source in sorted(template_root.rglob('*')):
        if not source.is_file():
            continue
        target = destination_root / source.relative_to(template_root)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
        report['copied'].append(str(target))
        if source.suffix.lower() == '.java':
            report['java_sources'].append(str(target))
        if source.suffix.lower() == '.class':
            report['class_files'].append(str(target))

    report['applied'] = True
    report['reason'] = 'exact_dex_v29_direct_java_source_calls_overlay'
    # V26 API output is source-only. Do not create deep_code/ or any report file.
    return report
