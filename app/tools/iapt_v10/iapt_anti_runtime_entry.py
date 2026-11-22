#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import copy
import json
import os
import shutil
import signal
import subprocess
import sys
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import v3_entry as v3


WRAPPER_ONLY_FLAGS = {
    "--anti-encrypted-sample",
    "--skip-anti-resources",
    "--server-sokey",
    "--dynamic-key",
}


def _strip_flag(tokens, flag, takes_value=False):
    out = []
    i = 0
    while i < len(tokens):
        if tokens[i] == flag:
            i += 2 if takes_value and i + 1 < len(tokens) else 1
            continue
        out.append(tokens[i])
        i += 1
    return out


def _core_extras(extras):
    out = list(extras)
    for flag in WRAPPER_ONLY_FLAGS:
        out = _strip_flag(out, flag)
    return out


def _apply_client_no_dynamic_key(command, client_requested: bool):
    # build_core contains historical mode defaults that can synthesize
    # --no-dynamic-key for enum/key-pool commands.  Inside this wrapper the
    # final core command must match the current client request exactly.
    out = [
        item for item in command
        if str(item) != "--no-dynamic-key"
    ]
    if bool(client_requested):
        out.append("--no-dynamic-key")
    return out


def _clean_output(outdir: Path) -> None:
    # Worker-generated request inputs live under outdir/.tmp, for example:
    #   .tmp/v10_dynamic_key_pool.json
    # They must survive both stage cleanups.  Only generated output is removed.
    outdir.mkdir(parents=True, exist_ok=True)
    for child in list(outdir.iterdir()):
        if child.name == ".tmp":
            continue
        try:
            if child.is_dir() and not child.is_symlink():
                shutil.rmtree(child, ignore_errors=True)
            else:
                child.unlink(missing_ok=True)
        except Exception:
            pass


def _run(command, timeout: int, label: str) -> int:
    print(
        "[IAPT_ANTI_TWO_STAGE] stage=" + label
        + " command=" + json.dumps(command, ensure_ascii=False),
        flush=True,
    )
    proc = subprocess.Popen(command, start_new_session=True)
    try:
        return int(proc.wait(timeout=timeout))
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                proc.kill()
            proc.wait()
        return 124


def _static_fb_candidates(apk: Path, allow_dex: bool = True):
    """Return only evidence-derived f.b() values; never create a range."""
    try:
        if allow_dex:
            from iapp_auto_decrypt import extract_fb_candidates_from_apk
            values = extract_fb_candidates_from_apk(apk, None)
            source = "dex-native-or-epic-vm"
        else:
            # Explicit dexkey enumeration must not use the restored DEX as a
            # shortcut.  Native/VM evidence remains safe and deterministic.
            from iapp_auto_decrypt import (
                extract_fb_from_lianyi_native,
                extract_fb_from_native_constant_consensus,
                extract_fb_from_quishui_native,
                extract_fb_candidates_from_epic_vm,
            )
            values = []
            source = "native-or-vm-only"
            for resolver in (
                extract_fb_from_lianyi_native,
                extract_fb_from_native_constant_consensus,
                extract_fb_from_quishui_native,
            ):
                value = resolver(apk)
                try:
                    number = int(value)
                except Exception:
                    continue
                if 100_000 <= number <= 20_000_000 and number not in values:
                    values.append(number)
            for value in extract_fb_candidates_from_epic_vm(apk):
                number = int(value)
                if number not in values:
                    values.append(number)
    except Exception as exc:
        print(
            "[IAPT_ANTI_TWO_STAGE] static_fb_error="
            + type(exc).__name__ + ": " + str(exc),
            flush=True,
        )
        return []
    clean = []
    for value in values or []:
        try:
            number = int(value)
        except Exception:
            continue
        if 100_000 <= number <= 20_000_000 and number not in clean:
            clean.append(number)
    print(
        "[IAPT_ANTI_TWO_STAGE] static_fb_mode=" + source
        + " dex_scan=" + ("true" if allow_dex else "false")
        + " values=" + ("none" if not clean else ",".join(str(value) for value in clean)),
        flush=True,
    )
    return clean


def _static_fb(apk: Path, allow_dex: bool = True):
    """Compatibility helper for old callers that can consume one value."""
    values = _static_fb_candidates(apk, allow_dex=allow_dex)
    return values[0] if len(values) == 1 else None

def _has_quishui_evidence(apk: Path) -> bool:
    try:
        with zipfile.ZipFile(apk, "r") as zf:
            names = [
                info.filename.replace("\\", "/").lower()
                for info in zf.infolist()
                if not info.is_dir()
            ]
    except Exception:
        return False
    return any(
        name.startswith("bsh/quishui/")
        or name.startswith("bsh/util/lib/")
        or (name.startswith("assets/libtosks") and name.endswith(".so"))
        for name in names
    )


def _metadata_trials(args, original_apk: Path, effective: Path):
    try:
        from apk_meta_fast import read_apk_meta
        from iapt_static_parameter_analyzer import (
            analyze_parameter_plan,
            metadata_candidates,
        )
        override = {}
        try:
            # The fallback value must be the uploaded APK's own
            # AndroidManifest.xml/resources.arsc metadata.
            override.update(read_apk_meta(original_apk))
        except Exception:
            override.update(read_apk_meta(effective))
        explicit = {
            "package_name": str(getattr(args, "package", "") or ""),
            "version_name": str(getattr(args, "version_name", "") or ""),
            "version_code": str(getattr(args, "version_code", "") or ""),
            "app_name": str(getattr(args, "app_label", "") or ""),
        }
        for key, value in explicit.items():
            if value:
                override[key] = value
        plan = analyze_parameter_plan(original_apk, override)
        trials = metadata_candidates(plan)
        root = args.outdir.parent / (".iapt-v10-static-parameter-" + args.outdir.name)
        root.mkdir(parents=True, exist_ok=True)
        (root / "static_parameter_report.json").write_text(
            json.dumps(plan, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        print(
            "[IAPT_ANTI_TWO_STAGE] parameter_trials="
            + json.dumps(trials, ensure_ascii=False, separators=(",", ":")),
            flush=True,
        )
        return trials
    except Exception as exc:
        print(
            "[IAPT_ANTI_TWO_STAGE] parameter_analysis_error="
            + type(exc).__name__ + ": " + str(exc),
            flush=True,
        )
        return [{
            "source": "original-unanalysed",
            "values": {
                "package": str(getattr(args, "package", "") or ""),
                "version_name": str(getattr(args, "version_name", "") or ""),
                "version_code": str(getattr(args, "version_code", "") or ""),
                "app_label": str(getattr(args, "app_label", "") or ""),
            },
            "changed_fields": [],
        }]


def _so_changed_fields(metadata_trials):
    for row in metadata_trials or []:
        if str((row or {}).get("source") or "") == "so-derived":
            return set((row or {}).get("changed_fields") or [])
    return set()


def _apply_metadata_trial(target, metadata, original_fallback_fields=None):
    row = dict(metadata or {})
    values = dict(row.get("values") or {})
    source = str(row.get("source") or "")
    fields = set(row.get("changed_fields") or [])
    if source == "original":
        # SO-derived version is candidate 1 only.  Candidate 2 explicitly
        # restores the raw resources.arsc/Manifest version.
        fields = set(original_fallback_fields or ()) & {"version_name"}
    for attr in ("package", "version_name", "version_code", "app_label"):
        if attr not in fields:
            continue
        value = str(values.get(attr) or "")
        if value:
            setattr(target, attr, value)
    return target


def _native_signature_participation(apk: Path) -> bool:
    """Return true when native iApp code statically consumes APK signatures.

    This is deliberately an evidence gate rather than a package/protector name
    check.  A candidate ABI must contain the complete Android signature access
    chain used by native ``idbfj`` variants.
    """
    needles = (
        b"getInstalledPackages",
        b"android/content/pm/Signature",
        b"toByteArray",
        b"java/security/MessageDigest",
    )
    try:
        import zipfile
        with zipfile.ZipFile(apk, "r") as archive:
            for info in archive.infolist():
                name = str(info.filename or "").replace("\\", "/").lower()
                if info.is_dir() or not name.startswith("lib/") or not name.endswith(".so"):
                    continue
                if not 4096 <= int(info.file_size or 0) <= 64 * 1024 * 1024:
                    continue
                try:
                    blob = archive.read(info)
                except Exception:
                    continue
                if all(token in blob for token in needles):
                    return True
    except Exception:
        return False
    return False


def _signature_mode_trials(base_args, effective: Path, anti: bool):
    requested = str(getattr(base_args, "signature_mode", "") or "skip").strip().lower()
    if requested not in {"skip", "verify", "auto"}:
        requested = "skip"
    modes = [requested]
    if anti and requested != "verify" and _native_signature_participation(effective):
        # Static native evidence is stronger than the historical client default
        # ``skip``. Try signature verification first; keep the exact requested
        # mode as a bounded fallback for older builds.
        modes = ["verify", requested]
        print(
            "[IAPT_ANTI_SIGNATURE] native_signature_evidence=true "
            "requested=" + requested + " trials=" + json.dumps(modes),
            flush=True,
        )
    return list(dict.fromkeys(modes))


def _prepare_fast_args(base_args, effective: Path, fb_value: int, metadata):
    fast = copy.deepcopy(base_args)
    # This is a temporary static-value attempt only.  The untouched client enum
    # request is executed as stage 2 if this attempt fails.
    fast.dexkey_enum = False
    fast.sokey_enum = False
    fast.full_c_enum = False
    fast.dexkey_c_batch = False
    fast.sokey_c_batch = False
    fast.enum_quiet = False
    fast.no_python_fallback = False
    fast.no_dexkey_dex_hint = False
    setattr(fast, "_iapt_client_dexkey_enum", False)
    setattr(fast, "_iapt_client_sokey_enum", False)
    setattr(fast, "_iapt_client_enum_mode", "none")
    fast.fb = str(int(fb_value))

    _apply_metadata_trial(
        fast,
        metadata,
        getattr(base_args, "_iapt_so_changed_fields", set()),
    )

    # Exact restored-SO key wins only in the temporary pretry.  If exact static
    # extraction is unavailable on a proven QuiShui/Tosks package, clear a stale
    # client hidden so the core uses its APK-evidence priority window.  Stage 2
    # still runs the original client hidden unchanged.
    try:
        exact_hidden = v3._extract_server_sokey(effective)
    except Exception as exc:
        exact_hidden = ""
        print(
            "[IAPT_ANTI_TWO_STAGE] static_hidden_error="
            + type(exc).__name__ + ": " + str(exc),
            flush=True,
        )
    if exact_hidden:
        fast.hidden = exact_hidden
    elif _has_quishui_evidence(effective):
        fast.hidden = ""
    return fast


def _publish_success(args, anti: bool) -> int:
    try:
        v3._normalise_source_tree(args.outdir)
        if anti and not args.skip_anti_resources:
            v3._export_anti_assets_res(args.apk, args.outdir)
    except Exception as exc:
        print(
            "[IAPT_ANTI_TWO_STAGE] source_tree_error="
            + type(exc).__name__ + ": " + str(exc),
            flush=True,
        )
        return 3
    return 0


def main():
    args, extras = v3.parser().parse_known_args()
    args.apk = args.apk.resolve()
    args.outdir = args.outdir.resolve()
    args.outdir.mkdir(parents=True, exist_ok=True)
    core_extras = _core_extras(extras)
    client_no_dynamic_key = "--no-dynamic-key" in {
        str(item) for item in sys.argv[1:]
    }

    print(
        "[IAPT_ANTI_TWO_STAGE] entry=true raw="
        + json.dumps(sys.argv[1:], ensure_ascii=False)
        + " core_extras=" + json.dumps(core_extras, ensure_ascii=False),
        flush=True,
    )

    v3._apply_anti_defaults(args)
    anti = bool(args.anti_encrypted_sample)
    if not anti and not v3._has_canonical_container(args.apk):
        print("没有找到lib.so文件；隐藏容器样本必须开启反加密样本参数", flush=True)
        return 2

    try:
        normalized_trials = v3._normalise_candidates(
            args.apk,
            args.outdir,
            anti,
            bool(args.skip_anti_resources),
        )
    except Exception as exc:
        print(
            "[IAPT_ANTI_TWO_STAGE] normalization_failed="
            + type(exc).__name__ + ": " + str(exc),
            flush=True,
        )
        return 2

    timeout = max(
        30,
        min(int(os.environ.get("IAPT_V3_CORE_TIMEOUT_SEC", "240") or 240), 7200),
    )
    last = 1
    original_main = str(args.main_file or "").strip()

    for candidate_index, normalized in enumerate(normalized_trials, 1):
        effective = Path(normalized["path"])
        candidate_report = dict(normalized.get("report") or {})
        candidate_args = copy.deepcopy(args)
        fallback_args = copy.deepcopy(args)
        client_dexkey_enum = bool(
            getattr(candidate_args, "_iapt_client_dexkey_enum", candidate_args.dexkey_enum)
        )
        if client_dexkey_enum:
            # Explicit enumeration must not consume a restored DEX as a hint.
            fallback_args.no_dexkey_dex_hint = True

        print(
            "[IAPT_GENERIC_CANDIDATE] index=" + str(candidate_index)
            + "/" + str(len(normalized_trials))
            + " apk=" + str(effective)
            + " normalizer=" + str(candidate_report.get("normalizer") or "identity")
            + " container=" + str(candidate_report.get("container_transport_entry") or "assets/lib.so"),
            flush=True,
        )

        explicit_fb = str(getattr(candidate_args, "fb", "") or "").strip()
        if explicit_fb and not client_dexkey_enum:
            try:
                fb_values = [int(explicit_fb, 0)]
            except Exception:
                fb_values = []
        else:
            fb_values = _static_fb_candidates(
                effective,
                allow_dex=not client_dexkey_enum,
            )

        metadata_trials = _metadata_trials(candidate_args, args.apk, effective)
        so_changed_fields = _so_changed_fields(metadata_trials)
        setattr(candidate_args, "_iapt_so_changed_fields", so_changed_fields)
        setattr(fallback_args, "_iapt_so_changed_fields", so_changed_fields)

        # The broad client fallback uses the original ARSC version rather than
        # retaining a failed SO-derived metadata candidate.
        if "version_name" in so_changed_fields:
            for row in metadata_trials:
                if str(row.get("source") or "") != "original":
                    continue
                raw_version = str((row.get("values") or {}).get("version_name") or "")
                if raw_version:
                    fallback_args.version_name = raw_version
                break

        # Stage 1: bounded evidence-derived fixed candidates.  Container, DEX,
        # VM and SO variants are all verified by the real main-entry decryptor.
        if fb_values:
            for fb_index, fb_value in enumerate(fb_values, 1):
                for trial_index, metadata in enumerate(metadata_trials, 1):
                    signature_modes = _signature_mode_trials(candidate_args, effective, anti)
                    for signature_index, signature_mode in enumerate(signature_modes, 1):
                        for main_index, variant in enumerate(v3._main_variants(original_main), 1):
                            fast = _prepare_fast_args(candidate_args, effective, fb_value, metadata)
                            fast.signature_mode = signature_mode
                            fast.main_file = variant
                            _clean_output(args.outdir)
                            cmd = _apply_client_no_dynamic_key(
                                v3.build_core(fast, effective) + core_extras,
                                client_no_dynamic_key,
                            )
                            label = (
                                "candidate:%d/%d:static-pretry:fb:%d/%d:meta:%d/%d:sig:%d/%d:%s:main:%d:source:%s:value:%s"
                                % (
                                    candidate_index,
                                    len(normalized_trials),
                                    fb_index,
                                    len(fb_values),
                                    trial_index,
                                    len(metadata_trials),
                                    signature_index,
                                    len(signature_modes),
                                    signature_mode,
                                    main_index,
                                    str(metadata.get("source") or "unknown"),
                                    fb_value,
                                )
                            )
                            rc = _run(cmd, timeout, label)
                            last = rc
                            if rc == 0:
                                print(
                                    "[IAPT_ANTI_TWO_STAGE] result=static-pretry-success "
                                    "candidate=" + str(candidate_index)
                                    + " verified_fb=" + str(fb_value)
                                    + " signature_mode=" + signature_mode
                                    + " original_client_fallback_executed=false",
                                    flush=True,
                                )
                                return _publish_success(args, anti)
                            if rc == 93:
                                print(
                                    "[IAPT_ANTI_TWO_STAGE] result=whitelist-protected "
                                    "candidate=" + str(candidate_index)
                                    + " verified_fb=" + str(fb_value),
                                    flush=True,
                                )
                                return 93
                            print(
                                "[IAPT_ANTI_TWO_STAGE] static_pretry_failed rc=" + str(rc)
                                + " candidate=" + str(candidate_index)
                                + " fb=" + str(fb_value)
                                + " signature_mode=" + signature_mode,
                                flush=True,
                            )
        else:
            print(
                "[IAPT_ANTI_TWO_STAGE] static_pretry_skipped reason=no-static-fb "
                "candidate=" + str(candidate_index),
                flush=True,
            )

        # Stage 2: preserve the exact client-selected fallback semantics, but
        # execute them for each evidence-backed normalized APK candidate.
        signature_modes = _signature_mode_trials(fallback_args, effective, anti)
        for signature_index, signature_mode in enumerate(signature_modes, 1):
            for main_index, variant in enumerate(v3._main_variants(original_main), 1):
                trial = copy.deepcopy(fallback_args)
                trial.signature_mode = signature_mode
                trial.main_file = variant
                _clean_output(args.outdir)
                cmd = _apply_client_no_dynamic_key(
                    v3.build_core(trial, effective) + core_extras,
                    client_no_dynamic_key,
                )
                last = _run(
                    cmd,
                    timeout,
                    "candidate:%d/%d:original-client-fallback:sig:%d/%d:%s:main:%d"
                    % (candidate_index, len(normalized_trials), signature_index, len(signature_modes), signature_mode, main_index),
                )
                if last == 0:
                    print(
                        "[IAPT_ANTI_TWO_STAGE] result=original-client-fallback-success "
                        "candidate=" + str(candidate_index)
                        + " signature_mode=" + signature_mode,
                        flush=True,
                    )
                    return _publish_success(args, anti)
                if last == 93:
                    print(
                        "[IAPT_ANTI_TWO_STAGE] result=whitelist-protected "
                        "candidate=" + str(candidate_index),
                        flush=True,
                    )
                    return 93
        print(
            "[IAPT_GENERIC_CANDIDATE] rejected index=" + str(candidate_index)
            + " rc=" + str(last),
            flush=True,
        )
    return last


if __name__ == "__main__":
    raise SystemExit(main())
