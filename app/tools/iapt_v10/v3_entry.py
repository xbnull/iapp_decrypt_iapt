#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IAPT V116 current-generation iApp engine.

The wrapper owns resource-layer normalisation and forwards only current-family
parameters to the current decryptor.  Four-character old-iApp containers are
never handled here.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
import shutil
import signal
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Iterable, List, Optional

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))


def _has_canonical_container(apk: Path) -> bool:
    """Return true only for a real, readable assets/lib.so container.

    Zero-byte/short placeholders are transport markers used by some clients and
    must not suppress hidden-resource normalization.
    """
    try:
        with zipfile.ZipFile(apk, "r") as zf:
            for info in zf.infolist():
                if info.is_dir() or info.filename.replace("\\", "/").lower() != "assets/lib.so":
                    continue
                if int(info.file_size or 0) < 64:
                    return False
                with zf.open(info, "r") as stream:
                    return len(stream.read(64)) == 64
        return False
    except Exception:
        return False

def _extract_server_sokey(apk: Path) -> str:
    from iapt_sokey_static_v2 import extract_sokey_from_apk
    value, meta = extract_sokey_from_apk(apk)
    text = value.decode("ascii", "strict") if isinstance(value, bytes) else str(value or "").strip()
    if len(text) != 32:
        raise ValueError("current server sokey extraction did not return 32 characters: " + text)
    print("[IAPT_V10] server_sokey=" + text + " metadata=" + json.dumps(meta, ensure_ascii=False, separators=(",", ":")), flush=True)
    return text


def _normalise_candidates(apk: Path, outdir: Path, enabled: bool, skip_resources: bool = False) -> List[dict]:
    """Run known handlers first, then the bounded generic transport fallback.

    Resource normalization never executes protector code and never creates a
    numeric key range.  A known format normally returns one APK.  The generic
    fallback may return several evidence-backed container candidates; the
    normal main-entry decryptor validates them in order.
    """
    canonical = _has_canonical_container(apk)
    if not enabled:
        if not canonical:
            raise ValueError("没有找到lib.so文件，请开启反加密样本")
        return [{"path": apk, "report": {"normalized": False, "reason": "canonical-container-present", "resource_plan": {"strategy": "identity"}}}]

    from iapt_static_resource_analyzer import analyze_and_restore_candidates, StaticResourceAnalysisError
    root = outdir.parent / (".iapt-v10-static-resource-" + outdir.name)
    shutil.rmtree(root, ignore_errors=True)
    root.mkdir(parents=True, exist_ok=True)
    target = root / "normalized.apk"
    report_path = root / "static_resource_report.json"
    options = {
        "anti_encrypted_sample": True,
        "no_decrypt_resource_files": bool(skip_resources),
        "skip_anti_resources": bool(skip_resources),
    }
    try:
        reports = analyze_and_restore_candidates(apk, target, options)
    except StaticResourceAnalysisError as exc:
        diagnostic = dict(getattr(exc, "report", {}) or {})
        if diagnostic:
            report_path.write_text(json.dumps(diagnostic, ensure_ascii=False, indent=2), encoding="utf-8")
        raise ValueError(str(exc) + ("; report=" + str(report_path) if diagnostic else "")) from exc
    if not reports:
        raise ValueError("static resource analyzer returned no normalized APK candidates")
    report_path.write_text(json.dumps({"candidate_count": len(reports), "candidates": reports}, ensure_ascii=False, indent=2), encoding="utf-8")
    trials = []
    for index, report in enumerate(reports, 1):
        effective = Path(str(report.get("normalized_apk") or (target if index == 1 else "")))
        if not effective.is_file():
            raise ValueError("static resource analyzer candidate %d did not produce an APK" % index)
        print(
            "[IAPT_STATIC_RESOURCE] candidate=" + str(index) + "/" + str(len(reports))
            + " report=" + json.dumps(report, ensure_ascii=False, separators=(",", ":")),
            flush=True,
        )
        trials.append({"path": effective, "report": report})
    return trials


def _normalise(apk: Path, outdir: Path, enabled: bool, skip_resources: bool = False) -> Path:
    """Compatibility wrapper for older callers; V3 main tries all candidates."""
    return Path(_normalise_candidates(apk, outdir, enabled, skip_resources)[0]["path"])

def _resolve_fb_after_normalise(args: argparse.Namespace, effective: Path, anti_defaults: dict) -> None:
    """Use exact static f.b() recovery before falling back to a 4.2M scan."""
    if str(args.fb or "").strip():
        return
    if not bool(anti_defaults.get("dexkey_enum_auto")):
        return
    try:
        from iapp_auto_decrypt import extract_fb_from_apk_dexes
        value = extract_fb_from_apk_dexes(effective, None)
    except Exception as exc:
        print("[IAPT_EPIC_FB] static recovery failed: " + type(exc).__name__ + ": " + str(exc), flush=True)
        return
    if value is None:
        return
    args.fb = str(int(value))
    # Disable only the wrapper's automatic fallback.  Explicit client enum
    # requests remain untouched.
    args.dexkey_enum = False
    if bool(anti_defaults.get("dexkey_c_batch_auto")):
        args.dexkey_c_batch = False
    anti_defaults["dexkey_enum_auto"] = False
    anti_defaults["dexkey_c_batch_auto"] = False
    anti_defaults["fb_static_after_normalise"] = int(value)
    print("[IAPT_EPIC_FB] static f.b()=" + str(value) + "; automatic dexkey enumeration disabled", flush=True)


def _canonical_container_meta(apk: Path) -> dict:
    """Validate the normalized current-family container and return stable metadata."""
    import hashlib
    with zipfile.ZipFile(apk, "r") as zf:
        found = None
        for info in zf.infolist():
            if not info.is_dir() and info.filename.replace("\\", "/").lower() == "assets/lib.so":
                found = info
                break
        if found is None:
            raise ValueError("hidden-resource normalization did not produce assets/lib.so")
        data = zf.read(found)
        if len(data) < 64:
            raise ValueError("restored assets/lib.so is unexpectedly short")
        return {
            "entry": found.filename,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }


def _resolve_hidden_after_normalise(args: argparse.Namespace, effective: Path) -> None:
    """Resolve current-family sokey only after the hidden lib.so layer exists.

    This is intentionally independent of the outer task router.  A compact
    upload may have no assets/lib.so until _normalise() restores it, so doing
    key resolution before this point is order-dependent and breaks when an old
    worker/router builds the command without --hidden.
    """
    current = str(args.hidden or "").strip()
    if current:
        return
    if not bool(args.anti_encrypted_sample):
        return
    meta = _canonical_container_meta(effective)
    try:
        hidden = _extract_server_sokey(effective)
    except Exception as exc:
        print(
            "[IAPT_V113] restored_container="
            + json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
            + " sokey_extract_error=" + type(exc).__name__ + ": " + str(exc),
            flush=True,
        )
        # Preserve the user's explicit enumeration semantics.  Do not silently
        # enable sokey enumeration.  If the user selected it, the core receives
        # that flag; otherwise it reports the precise missing-sokey error.
        return
    args.hidden = hidden
    # Preserve every enumeration flag exactly as submitted by the client.
    # Plaintext sokey extraction only supplies --hidden; it never enables,
    # disables, or rewrites sokey/dexkey/full-C enumeration choices.
    print(
        "[IAPT_V114] restored_container="
        + json.dumps(meta, ensure_ascii=False, separators=(",", ":"))
        + " hidden_source=normalized-libygsiyu-static hidden=" + hidden
        + " sokey_enum_preserved=" + ("true" if args.sokey_enum else "false")
        + " dexkey_enum_preserved=" + ("true" if args.dexkey_enum else "false")
        + " full_c_enum_preserved=" + ("true" if args.full_c_enum else "false"),
        flush=True,
    )


def _merge_tree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in list(src.iterdir()):
        target = dst / child.name
        if child.is_dir():
            _merge_tree(child, target)
            try:
                child.rmdir()
            except Exception:
                pass
        else:
            if target.exists():
                try:
                    if target.is_file() and target.read_bytes() == child.read_bytes():
                        child.unlink()
                        continue
                except Exception:
                    pass
                stem, suffix = target.stem, target.suffix
                index = 2
                while target.exists():
                    target = target.with_name(f"{stem}_{index}{suffix}")
                    index += 1
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(child), str(target))


_IAPT_V173_SOURCE_SUFFIXES = {
    ".iyu", ".myu", ".mjava", ".ijava",
    ".mlua", ".ilua", ".mjs", ".ijs",
    ".java", ".lua", ".js",
}
_IAPT_V173_PROJECT_SUFFIX = ".project"
_IAPT_V173_PRIVATE_ROOTS = {
    "src", "res", "assets", "apk", ".tmp", ".iapt_internal",
    "logs", "reports", "analysis", "__pycache__",
}


def _iapt_v173_source_member(path: Path, include_project: bool = True) -> bool:
    suffix = Path(path).suffix.lower()
    return suffix in _IAPT_V173_SOURCE_SUFFIXES or (
        include_project and suffix == _IAPT_V173_PROJECT_SUFFIX
    )


def _iapt_v173_main_member(path: Path) -> bool:
    path = Path(path)
    return (
        path.suffix.lower() in _IAPT_V173_SOURCE_SUFFIXES
        and path.stem.lower() in {"main", "mian"}
    )


def _normalise_source_tree(outdir: Path) -> dict:
    """Publish only verified iApp source members under ``src/**``.

    The old check recognised only .iyu/.myu/.java.  A successful project whose
    verified main/member files were .mjava/.ijava/.mlua/.mjs was therefore
    reported as ``.project alone`` and the whole task was changed to exit code 3.

    This normaliser accepts every source extension used by the decryptor, but it
    does not move arbitrary directories into ``src``.  Only immediate project
    roots containing a main source or a project marker are considered, and only
    recognised source/project files are published from those roots.
    """
    outdir = Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)
    src_root = outdir / "src"

    direct_members: List[Path] = []
    project_roots = []

    for child in list(outdir.iterdir()):
        if child.name.lower() in _IAPT_V173_PRIVATE_ROOTS or child.name.startswith("."):
            continue
        if child.is_file() and _iapt_v173_source_member(child):
            direct_members.append(child)
            continue
        if not child.is_dir() or child.is_symlink():
            continue

        members = []
        for member in child.rglob("*"):
            try:
                if not member.is_file() or member.is_symlink():
                    continue
                rel = member.relative_to(child)
                if any(str(part).startswith(".") or str(part) in ("", ".", "..") for part in rel.parts):
                    continue
                if _iapt_v173_source_member(member):
                    members.append(member)
            except Exception:
                continue
        if not members:
            continue
        has_main = any(_iapt_v173_main_member(member) for member in members)
        has_project = any(member.suffix.lower() == _IAPT_V173_PROJECT_SUFFIX for member in members)
        if has_main or has_project:
            project_roots.append((child, members, has_main, has_project))

    # A normal decrypt has one package-named output root.  Prefer the root that
    # contains the verified main file.  Refuse ambiguous roots instead of
    # publishing source from unrelated diagnostic/project directories.
    selected_roots = []
    main_roots = [row for row in project_roots if row[2]]
    if len(main_roots) == 1:
        selected_roots = main_roots
    elif len(main_roots) > 1:
        raise RuntimeError(
            "V3 engine produced multiple main source roots: "
            + ", ".join(row[0].name for row in main_roots[:8])
        )
    elif len(project_roots) == 1:
        selected_roots = project_roots
    elif len(project_roots) > 1:
        matching = []
        for row in project_roots:
            root = row[0]
            for member in row[1]:
                if member.suffix.lower() == _IAPT_V173_PROJECT_SUFFIX and member.stem == root.name:
                    matching.append(row)
                    break
        if len(matching) == 1:
            selected_roots = matching
        else:
            raise RuntimeError(
                "V3 engine produced ambiguous project source roots: "
                + ", ".join(row[0].name for row in project_roots[:8])
            )

    moved = 0
    collisions = 0

    def move_member(source: Path, target: Path) -> None:
        nonlocal moved, collisions
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            try:
                if target.is_file() and target.read_bytes() == source.read_bytes():
                    source.unlink(missing_ok=True)
                    moved += 1
                    return
            except Exception:
                pass
            stem, suffix = target.stem, target.suffix
            index = 2
            while target.exists():
                target = target.with_name(f"{stem}_{index}{suffix}")
                index += 1
            collisions += 1
        shutil.move(str(source), str(target))
        moved += 1

    if direct_members or selected_roots:
        src_root.mkdir(parents=True, exist_ok=True)

    for member in direct_members:
        move_member(member, src_root / member.name)

    for root, members, _has_main, _has_project in selected_roots:
        for member in members:
            try:
                rel = member.relative_to(root)
            except Exception:
                continue
            move_member(member, src_root / root.name / rel)

    # Remove only empty selected project directories.  Non-source files stay in
    # their original private location and are never remapped into src/**.
    for root, _members, _has_main, _has_project in selected_roots:
        for directory in sorted(
            (item for item in root.rglob("*") if item.is_dir()),
            key=lambda item: len(item.parts),
            reverse=True,
        ):
            try:
                directory.rmdir()
            except Exception:
                pass
        try:
            root.rmdir()
        except Exception:
            pass

    source_files = []
    if src_root.is_dir():
        source_files = [
            path for path in src_root.rglob("*")
            if path.is_file() and _iapt_v173_source_member(path)
        ]
    real_sources = [
        path for path in source_files
        if path.suffix.lower() in _IAPT_V173_SOURCE_SUFFIXES
    ]
    suffix_counts = {}
    for path in real_sources:
        suffix = path.suffix.lower()
        suffix_counts[suffix] = int(suffix_counts.get(suffix) or 0) + 1

    report = {
        "layout_version": 173,
        "moved_files": moved,
        "collision_files": collisions,
        "project_roots": [row[0].name for row in selected_roots],
        "source_files": len(source_files),
        "real_source_files": len(real_sources),
        "source_suffixes": dict(sorted(suffix_counts.items())),
        "has_mian": any(_iapt_v173_main_member(path) for path in real_sources),
    }
    print(
        "[IAPT_V173_SOURCE_TREE] "
        + json.dumps(report, ensure_ascii=False, separators=(",", ":")),
        flush=True,
    )
    if not real_sources:
        raise RuntimeError(
            "V3 engine did not produce an actual iApp source member "
            "(.iyu/.myu/.mjava/.ijava/.mlua/.ilua/.mjs/.ijs)"
        )
    return report

def _export_anti_assets_res(apk: Path, outdir: Path) -> dict:
    tools_dir = HERE.parent
    if str(tools_dir) not in sys.path:
        sys.path.insert(0, str(tools_dir))
    from iapt_qiushui_resource_export import export_resources
    report = export_resources(apk, outdir, {"anti_encrypted_sample": True})
    compact = {
        "exported": bool(report.get("exported")),
        "written_count": int(report.get("written_count") or 0),
        "assets_res_count": int(report.get("assets_res_count") or 0),
        "res_count": int(report.get("res_count") or 0),
    }
    print("[IAPT_V114_ASSETS_RES] " + json.dumps(compact, ensure_ascii=False, separators=(",", ":")), flush=True)
    return compact


def _add(cmd: List[str], flag: str, value) -> None:
    text = str(value or "").strip()
    if text:
        cmd.extend([flag, text])


def _main_variants(value: str) -> List[str]:
    value = str(value or "").strip()
    if not value:
        return [""]
    out: List[str] = []
    for item in (value.lower(), value, value.upper()):
        if item and item not in out:
            out.append(item)
    return out


def build_core(args: argparse.Namespace, apk: Path) -> List[str]:
    core = HERE / "iapp_auto_decrypt.py"
    cmd: List[str] = [sys.executable, str(core), "--apk", str(apk), "--outdir", str(args.outdir)]
    # IAPT_ANTI_ENUM_MODE_SAFE_V1
    client_dexkey_enum = bool(
        getattr(args, "_iapt_client_dexkey_enum", False)
    )
    client_sokey_enum = bool(
        getattr(args, "_iapt_client_sokey_enum", False)
    )
    hidden = str(args.hidden or "").strip()
    if not hidden and args.server_sokey and not client_sokey_enum:
        hidden = _extract_server_sokey(apk)
    if hidden and len(hidden) == 4:
        raise ValueError("four-character sokey belongs to the ancient engine")
    if not client_sokey_enum:
        _add(cmd, "--hidden", hidden)
    if not client_dexkey_enum:
        _add(cmd, "--fb", args.fb)
    # Static parameter-semantics analysis resolves the exact metadata strings
    # consumed by idbfj (for example 1.0 -> 1.000000).  The existing generic
    # OuterExpr/StaticOuterAnalyzer engine then receives those values unchanged.
    _add(cmd, "--package", getattr(args, "package", ""))
    _add(cmd, "--version-name", getattr(args, "version_name", ""))
    _add(cmd, "--version-code", getattr(args, "version_code", ""))
    _add(cmd, "--app-label", getattr(args, "app_label", ""))
    _add(cmd, "--user-password", args.user_password)
    _add(cmd, "--signature-mode", args.signature_mode)
    _add(cmd, "--signature-bytes-hex", args.signature_bytes_hex)
    _add(cmd, "--post-key", args.post_key)
    _add(cmd, "--key-xor", args.key_xor)
    _add(cmd, "--main-file", args.main_file)
    _add(cmd, "--find", args.find)
    _add(cmd, "--fast-c", args.fast_c)
    _add(cmd, "--restore-fn-names", args.restore_fn_names)
    _add(cmd, "--threads", args.threads)
    _add(cmd, "--member-marker-mode", args.member_marker_mode)
    _add(cmd, "--member-name-scan", args.member_name_scan)
    _add(cmd, "--member-batch-size", args.member_batch_size)
    if args.find_recursive:
        cmd.append("--find-recursive")
    if bool(getattr(args, "anti_iapec_encryption", False)):
        cmd.append("--anti-iapec-encryption")
    if args.max_output_files is not None and int(args.max_output_files) > 1:
        cmd += ["--max-output-files", str(int(args.max_output_files))]
    if args.sokey_enum:
        cmd.append("--sokey-enum")
        _add(cmd, "--sokey-enum-seconds", args.sokey_enum_seconds)
        _add(cmd, "--sokey-enum-files", args.sokey_enum_files)
        _add(cmd, "--sokey-max-candidates", args.sokey_max_candidates)
    if args.dexkey_enum:
        cmd.append("--dexkey-enum")
        _add(cmd, "--dexkey-enum-start", args.dexkey_enum_start)
        _add(cmd, "--dexkey-enum-stop", args.dexkey_enum_stop)
        if args.no_dexkey_dex_hint:
            cmd.append("--no-dexkey-dex-hint")
    if args.enum_quiet:
        cmd.append("--enum-quiet")
    if args.no_python_fallback:
        cmd.append("--no-python-fallback")
    if args.sokey_c_batch:
        cmd.append("--sokey-c-batch")
    if args.dexkey_c_batch:
        cmd.append("--dexkey-c-batch")
    if args.full_c_enum:
        cmd.append("--full-c-enum")
    if args.enum_workers is not None and int(args.enum_workers) > 0:
        cmd += ["--enum-workers", str(int(args.enum_workers))]
    if args.key_pool_file:
        cmd += ["--key-pool-file", str(args.key_pool_file)]
        if args.redact_selected_keys:
            cmd.append("--redact-selected-keys")
    custom = bool(str(args.post_key or "").strip() and str(args.key_xor or "").strip())
    client_enum_mode = bool(
        getattr(args, "_iapt_client_dexkey_enum", False)
        or getattr(args, "_iapt_client_sokey_enum", False)
    )
    cmd += ["--mode", "auto", "--outer-mode", "auto"]
    # Client-selected enumeration is authoritative. Explicit post/key values
    # may still be forwarded as hints, but must never switch the task to
    # strict-manual mode.
    if client_enum_mode:
        if args.key_pool_file:
            cmd += ["--no-dynamic-key", "--no-key-cache"]
        elif args.dynamic_key:
            if args.no_key_cache:
                cmd.append("--no-key-cache")
        else:
            cmd.append("--no-key-cache")
            print("[IAPT_V175_STATIC_SO_KEYS] client_enum=true allow_local_so_analysis=true", flush=True)
    elif args.strict_manual_key or custom:
        cmd += ["--strict-manual-key", "--no-dynamic-key", "--no-key-cache"]
    elif args.key_pool_file:
        cmd += ["--no-dynamic-key", "--no-key-cache"]
    elif args.dynamic_key:
        if args.no_key_cache:
            cmd.append("--no-key-cache")
    elif bool(getattr(args, "anti_encrypted_sample", False)):
        # Static anti-encrypted analysis is not the paid/runtime "dynamic key"
        # feature.  It must still inspect libygsiyu.so for the post/xor
        # constants that define the package's normal outer algorithm.  Passing
        # --no-dynamic-key here used to suppress that static SO analysis and
        # made samples such as 叶社 fail after lib.so had already been restored.
        cmd.append("--no-key-cache")
        print("[IAPT_STATIC_SO_KEYS] anti_encrypted=true allow_static_so_key_analysis=true", flush=True)
    else:
        # Normal V3 decryption must still inspect the APK's own libygsiyu.so
        # for the local post/xor constants.  That is part of decrypting this
        # sample, not the optional server dynamic-key/cache feature.
        cmd.append("--no-key-cache")
        print("[IAPT_V175_STATIC_SO_KEYS] normal_v3=true allow_local_so_analysis=true", flush=True)
    return cmd


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="IAPT V10 current iApp decryptor")
    p.add_argument("--apk", required=True, type=Path)
    p.add_argument("--outdir", required=True, type=Path)
    p.add_argument("--hidden", default="")
    p.add_argument("--fb", default="")
    p.add_argument("--package", default="")
    p.add_argument("--version-name", default="")
    p.add_argument("--version-code", default="")
    p.add_argument("--app-label", default="")
    p.add_argument("--user-password", default="")
    p.add_argument("--signature-mode", choices=("auto", "skip", "verify"), default="skip")
    p.add_argument("--signature-bytes-hex", default="")
    p.add_argument("--post-key", default="")
    p.add_argument("--key-xor", default="")
    p.add_argument("--main-file", default="")
    p.add_argument("--find", default="")
    p.add_argument("--find-recursive", action="store_true")
    p.add_argument("--max-output-files", type=int)
    p.add_argument("--fast-c", choices=("auto", "on", "off"), default="auto")
    p.add_argument("--restore-fn-names", choices=("auto", "on", "off"), default="auto")
    p.add_argument("--threads", type=int)
    p.add_argument("--member-marker-mode", default="")
    p.add_argument("--member-name-scan", default="")
    p.add_argument("--member-batch-size", type=int)
    p.add_argument("--dynamic-key", action="store_true")
    p.add_argument("--no-key-cache", action="store_true")
    p.add_argument("--server-sokey", action="store_true")
    p.add_argument("--anti-encrypted-sample", action="store_true")
    p.add_argument("--anti-iapec-encryption", action="store_true")
    p.add_argument("--skip-anti-resources", action="store_true")
    p.add_argument("--key-pool-file", type=Path)
    p.add_argument("--redact-selected-keys", action="store_true")
    p.add_argument("--strict-manual-key", action="store_true")
    p.add_argument("--sokey-enum", action="store_true")
    p.add_argument("--sokey-enum-seconds", type=int)
    p.add_argument("--sokey-enum-files", type=int)
    p.add_argument("--sokey-max-candidates", type=int)
    p.add_argument("--dexkey-enum", action="store_true")
    p.add_argument("--dexkey-enum-start", type=int)
    p.add_argument("--dexkey-enum-stop", type=int)
    p.add_argument("--no-dexkey-dex-hint", action="store_true")
    p.add_argument("--enum-quiet", action="store_true")
    p.add_argument("--no-python-fallback", action="store_true")
    p.add_argument("--sokey-c-batch", action="store_true")
    p.add_argument("--dexkey-c-batch", action="store_true")
    p.add_argument("--full-c-enum", action="store_true")
    p.add_argument("--enum-workers", type=int)
    return p


def _apply_verified_anti_profile(
    args: argparse.Namespace,
    effective_apk: Path,
    anti_defaults: dict,
) -> dict:
    """Fill only empty parameters from a verified restored-container profile."""
    report = {
        "enabled": bool(args.anti_encrypted_sample),
        "matched": False,
        "profile_id": "",
        "container_sha256": "",
        "filled": [],
    }
    if not bool(args.anti_encrypted_sample):
        return report
    try:
        from iapt_anti_sample_profiles import resolve_profile
        profile = resolve_profile(effective_apk)
    except Exception as exc:
        report["error"] = type(exc).__name__ + ": " + str(exc)
        return report
    if not profile:
        return report
    report["matched"] = True
    report["profile_id"] = str(profile.get("id") or "")
    report["container_sha256"] = str(profile.get("container_sha256") or "")
    client_dexkey_enum = bool(
        getattr(
            args,
            "_iapt_client_dexkey_enum",
            bool(
                args.dexkey_enum
                and not anti_defaults.get("dexkey_enum_auto")
            ),
        )
    )
    client_sokey_enum = bool(
        getattr(
            args,
            "_iapt_client_sokey_enum",
            bool(args.sokey_enum),
        )
    )
    report["client_dexkey_enum"] = client_dexkey_enum
    report["client_sokey_enum"] = client_sokey_enum
    for attr, key in (
        ("hidden", "hidden"),
        ("fb", "fb"),
        ("post_key", "post_key"),
        ("key_xor", "key_xor"),
    ):
        # Preserve the three client-selected modes exactly:
        # dexkey-only uses a fixed hidden key, sokey-only uses a fixed fb,
        # and joint enumeration receives neither fixed key.
        if client_dexkey_enum and attr == "fb":
            report.setdefault("skipped", []).append(
                "fb:client_dexkey_enum"
            )
            continue
        if client_sokey_enum and attr == "hidden":
            report.setdefault("skipped", []).append(
                "hidden:client_sokey_enum"
            )
            continue
        if not str(getattr(args, attr, "") or "").strip():
            value = str(profile.get(key) or "").strip()
            if value:
                setattr(args, attr, value)
                report["filled"].append(attr)
    if str(args.signature_mode or "").strip() in ("", "auto"):
        value = str(profile.get("signature_mode") or "").strip()
        if value:
            args.signature_mode = value
            report["filled"].append("signature_mode")
    if anti_defaults.get("dynamic_key_auto") and str(args.post_key or "").strip() and str(args.key_xor or "").strip():
        args.dynamic_key = False
        report["disabled_auto_dynamic_key"] = True
    if anti_defaults.get("dexkey_enum_auto") and str(args.fb or "").strip():
        args.dexkey_enum = False
        report["disabled_auto_dexkey_enum"] = True
    if anti_defaults.get("dexkey_c_batch_auto") and str(args.fb or "").strip():
        args.dexkey_c_batch = False
        if not bool(args.sokey_enum):
            args.enum_quiet = False
        report["disabled_auto_dexkey_c_batch"] = True
    return report


def _apply_anti_defaults(args: argparse.Namespace) -> dict:
    """Record client choices without enabling any automatic enumeration.

    ``--anti-encrypted-sample`` controls only static resource restoration.  It
    must not silently switch on hidden/f.b./SO-key searches because those normal
    decrypt parameters are supplied by the client.
    """
    client_dexkey_enum = bool(args.dexkey_enum)
    client_sokey_enum = bool(args.sokey_enum)
    if client_dexkey_enum and client_sokey_enum:
        client_enum_mode = "joint"
    elif client_dexkey_enum:
        client_enum_mode = "dexkey"
    elif client_sokey_enum:
        client_enum_mode = "sokey"
    else:
        client_enum_mode = "none"
    setattr(args, "_iapt_client_dexkey_enum", client_dexkey_enum)
    setattr(args, "_iapt_client_sokey_enum", client_sokey_enum)
    setattr(args, "_iapt_client_enum_mode", client_enum_mode)
    return {
        "enabled": bool(args.anti_encrypted_sample),
        "resource_layer_only": True,
        "client_parameters_preserved": True,
        "static_so_key_analysis": bool(args.anti_encrypted_sample),
        "dynamic_key_auto": False,
        "dexkey_enum_auto": False,
        "dexkey_c_batch_auto": False,
        "full_c_enum_auto": False,
        "client_dexkey_enum": client_dexkey_enum,
        "client_sokey_enum": client_sokey_enum,
        "client_enum_mode": client_enum_mode,
        "full_c_enum_client": bool(args.full_c_enum),
    }


def _apply_static_parameter_plan(args: argparse.Namespace, original_apk: Path, metadata_apk: Optional[Path] = None) -> dict:
    """Recover code-defined metadata semantics without enumerating values."""
    report = {
        "enabled": bool(args.anti_encrypted_sample),
        "applied": False,
        "metadata": {},
    }
    if not bool(args.anti_encrypted_sample):
        return report
    from iapt_static_parameter_analyzer import analyze_parameter_plan, effective_metadata
    from apk_meta_fast import read_apk_meta
    overrides = {}
    try:
        overrides.update(read_apk_meta(metadata_apk or original_apk))
    except Exception as exc:
        print("[IAPT_STATIC_PARAMETER] metadata_apk_parse_failed=" + type(exc).__name__ + ": " + str(exc), flush=True)
    explicit = {
        "package_name": str(getattr(args, "package", "") or ""),
        "version_name": str(getattr(args, "version_name", "") or ""),
        "version_code": str(getattr(args, "version_code", "") or ""),
        "app_name": str(getattr(args, "app_label", "") or ""),
    }
    for key, value in explicit.items():
        if value:
            overrides[key] = value
    plan = analyze_parameter_plan(original_apk, overrides)
    effective = effective_metadata(plan)
    args.package = effective.get("package", "")
    args.version_name = effective.get("version_name", "")
    args.version_code = effective.get("version_code", "")
    args.app_label = effective.get("app_label", "")
    root = args.outdir.parent / (".iapt-v10-static-parameter-" + args.outdir.name)
    root.mkdir(parents=True, exist_ok=True)
    report_path = root / "static_parameter_report.json"
    report_path.write_text(json.dumps(plan, ensure_ascii=False, indent=2), encoding="utf-8")
    report = {
        "enabled": True,
        "applied": True,
        "confidence": plan.get("confidence"),
        "selected_operations": plan.get("selected_operations") or {},
        "metadata": plan.get("metadata") or {},
        "unsupported_numeric_evidence": plan.get("unsupported_numeric_evidence") or [],
        "report_path": str(report_path),
    }
    print("[IAPT_STATIC_PARAMETER] " + json.dumps(report, ensure_ascii=False, separators=(",", ":")), flush=True)
    return report


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parser().parse_args(list(argv) if argv is not None else None)
    args.apk = args.apk.resolve()
    args.outdir = args.outdir.resolve()
    args.outdir.mkdir(parents=True, exist_ok=True)
    print("[IAPT_V10] decrypt_script=v3", flush=True)
    anti_defaults = _apply_anti_defaults(args)
    print("[IAPT_ANTI_DEFAULTS] " + json.dumps(anti_defaults, ensure_ascii=False, separators=(",", ":")), flush=True)
    anti_enabled = bool(args.anti_encrypted_sample)
    if not anti_enabled and not _has_canonical_container(args.apk):
        print("没有找到lib.so文件；隐藏容器样本必须开启反加密样本参数", flush=True)
        return 2
    trials = _normalise_candidates(
        args.apk,
        args.outdir,
        anti_enabled,
        bool(args.skip_anti_resources),
    )
    last = 1
    original_main = str(args.main_file or "").strip()
    for candidate_index, trial in enumerate(trials):
        effective = Path(trial["path"])
        trial_report = dict(trial.get("report") or {})
        trial_args = copy.deepcopy(args)
        trial_defaults = copy.deepcopy(anti_defaults)
        parameter_report = _apply_static_parameter_plan(trial_args, args.apk, effective)
        if candidate_index:
            shutil.rmtree(trial_args.outdir, ignore_errors=True)
            trial_args.outdir.mkdir(parents=True, exist_ok=True)
        print(
            "[IAPT_STATIC_WRAPPER] trial=" + str(candidate_index + 1)
            + "/" + str(len(trials))
            + " apk=" + str(effective)
            + " transform=" + json.dumps(trial_report.get("transform") or "identity", ensure_ascii=False, separators=(",", ":")),
            flush=True,
        )
        print(
            "[IAPT_CLIENT_PARAMETERS] preserved=true hidden_set=" + ("true" if bool(str(trial_args.hidden or "").strip()) else "false")
            + " fb_set=" + ("true" if bool(str(trial_args.fb or "").strip()) else "false")
            + " post_key_set=" + ("true" if bool(str(trial_args.post_key or "").strip()) else "false")
            + " key_xor_set=" + ("true" if bool(str(trial_args.key_xor or "").strip()) else "false")
            + " signature_mode=" + str(trial_args.signature_mode or ""),
            flush=True,
        )

        for main_index, variant in enumerate(_main_variants(original_main)):
            trial_args.main_file = variant
            if main_index:
                shutil.rmtree(trial_args.outdir, ignore_errors=True)
                trial_args.outdir.mkdir(parents=True, exist_ok=True)
            cmd = build_core(trial_args, effective)
            print(
                "[IAPT_V10] candidate=" + str(candidate_index + 1)
                + " main_file_try=" + json.dumps(variant, ensure_ascii=False)
                + " core_command=" + json.dumps(cmd, ensure_ascii=False),
                flush=True,
            )
            timeout_sec = max(30, min(int(os.environ.get("IAPT_V3_CORE_TIMEOUT_SEC", "240") or 240), 7200))
            process = subprocess.Popen(cmd, start_new_session=True)
            try:
                last = int(process.wait(timeout=timeout_sec))
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except Exception:
                    process.terminate()
                try:
                    process.wait(timeout=3)
                except Exception:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except Exception:
                        process.kill()
                    process.wait()
                last = 124
                print("[IAPT_V112] core_timeout_seconds=" + str(timeout_sec), flush=True)
            if last == 0:
                print(
                    "[IAPT_STATIC_WRAPPER] verified_candidate=" + str(candidate_index + 1)
                    + " transform=" + json.dumps(trial_report.get("transform") or "identity", ensure_ascii=False, separators=(",", ":")),
                    flush=True,
                )
                try:
                    _normalise_source_tree(trial_args.outdir)
                    if anti_enabled and not trial_args.skip_anti_resources:
                        _export_anti_assets_res(args.apk, trial_args.outdir)
                    elif anti_enabled:
                        print("[IAPT_V116_ASSETS_RES] skipped_by_client=true", flush=True)
                except Exception as exc:
                    print("[IAPT_V114_SOURCE_TREE_ERROR] " + type(exc).__name__ + ": " + str(exc), flush=True)
                    return 3
                return 0
        print(
            "[IAPT_STATIC_WRAPPER] rejected_candidate=" + str(candidate_index + 1)
            + " exit=" + str(last),
            flush=True,
        )
    return last


if __name__ == "__main__":
    raise SystemExit(main())

# IAPT_V110_V3_ENTRY_C_ENUM_FORWARDING
# IAPT_V112_CORE_PROCESS_GROUP_TIMEOUT
# IAPT_V113_NORMALISE_THEN_RESOLVE_HIDDEN
# IAPT_V115_STRICT_EXPLICIT_ANTI_LINEAR_DOWNLOAD
# IAPT_V116_ANTI_RESOURCE_TOGGLE

# IAPT_ANTI_LIB_ONLY_NORMALIZE_V1
