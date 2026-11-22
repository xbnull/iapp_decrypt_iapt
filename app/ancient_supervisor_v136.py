from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pymysql
from pymysql.cursors import DictCursor

from .config import (
    APP_STORAGE,
    DB_HOST,
    DB_PORT,
    DB_USER,
    DB_PASSWORD,
    DB_NAME,
)

VERSION = "V136-clean-service-ancient-supervisor"
DEFAULT_TIMEOUT = 240


def _truthy(value: Any) -> bool:
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y"}


def _loads(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return dict(raw)
    try:
        obj = json.loads(str(raw or "{}"))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _raw_conn():
    return pymysql.connect(
        host=DB_HOST,
        port=int(DB_PORT),
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        charset="utf8mb4",
        cursorclass=DictCursor,
        autocommit=True,
        connect_timeout=4,
        read_timeout=8,
        write_timeout=8,
    )


def _one(sql: str, args=()):
    c = _raw_conn()
    try:
        with c.cursor() as cur:
            cur.execute(sql, args)
            return cur.fetchone()
    finally:
        c.close()


def _exec(sql: str, args=()) -> int:
    c = _raw_conn()
    try:
        with c.cursor() as cur:
            cur.execute(sql, args)
            return int(cur.lastrowid or 0)
    finally:
        c.close()


def _is_ancient(task: dict[str, Any], options: dict[str, Any]) -> bool:
    for key in ("client_final_scheme", "decrypt_scheme", "task_version", "public_scheme"):
        if str(options.get(key) or "").strip().lower() == "ancient":
            return True
    if str(options.get("client_submission_path") or "").strip().lower() in {"decrypt-ancient", "ancient-decrypt"}:
        return True
    if str(options.get("client_route_lock") or "").strip().lower().startswith("ancient"):
        return True
    if str(options.get("v3_upload_mode") or "").strip().lower().startswith("ancient_"):
        return True
    if _truthy(options.get("legacy_iapp")) or _truthy(options.get("old_iapp")):
        return True
    return str(task.get("decrypt_version") or "").strip().lower() == "ancient"


def _first(options: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = options.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return ""


def _engine_path() -> Path:
    base = Path(__file__).resolve().parent
    candidates = (
        base / "tools" / "iapt_v10" / "iapp_old_decrypt.py",
        base / "tools" / "iapp_old_decrypt.py",
    )
    for path in candidates:
        if path.is_file():
            return path
    raise RuntimeError("找不到远古解密器 iapp_old_decrypt.py")


def _safe_rel(path: Path, root: Path) -> str:
    return path.relative_to(root).as_posix()


def _scan_public(out_dir: Path, options: dict[str, Any]) -> tuple[list[dict[str, Any]], int]:
    include_assets = _truthy(options.get("anti_encrypted_sample")) and not _truthy(
        options.get("skip_anti_resources")
        or options.get("no_decrypt_resources")
        or options.get("skip_resource_decrypt")
    )
    rows: list[dict[str, Any]] = []
    total = 0
    for path in out_dir.rglob("*"):
        if not path.is_file():
            continue
        rel = _safe_rel(path, out_dir)
        low = rel.lower()
        if low.startswith((".tmp/", ".iapt_internal/", "logs/")):
            continue
        if low in {
            "old_iapp_report.json",
            "analysis_report.txt",
            "output_files.json",
            "result.zip",
            "download.zip",
            "decrypt.pid",
            "cancel.request",
        }:
            continue
        public = low.startswith("src/") or (include_assets and low.startswith("assets/res/"))
        if not public:
            continue
        try:
            size = int(path.stat().st_size)
        except OSError:
            continue
        rows.append({"rel_path": rel, "size_bytes": size})
        total += size
    rows.sort(key=lambda row: str(row.get("rel_path") or ""))
    tmp = out_dir / ".tmp"
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "file_index.json").write_text(
        json.dumps(rows, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    (out_dir / "output_files.json").write_text(
        json.dumps(
            {"version": 133, "updated_at": int(time.time()), "files": rows},
            ensure_ascii=False,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    return rows, total


def _fail(task_id: int, message: str, started: float, options: dict[str, Any]) -> dict[str, Any]:
    elapsed = (time.monotonic() - started) * 1000.0
    options = dict(options)
    options["ancient_supervisor"] = VERSION
    options["ancient_stage"] = "failed"
    options["ancient_error"] = str(message)
    try:
        _exec(
            "UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,decrypt_version='ancient',options_json=%s WHERE id=%s",
            (elapsed, str(message)[-4000:], json.dumps(options, ensure_ascii=False, separators=(",", ":")), int(task_id)),
        )
    except Exception as exc:
        print(f"[V136] fail status update error: {exc!r}", flush=True)
    return {"ok": False, "scheme": "ancient", "error": str(message)}


def _build_command(apk: Path, out_dir: Path, options: dict[str, Any]) -> list[str]:
    command = [sys.executable, str(_engine_path()), "--apk", str(apk), "--outdir", str(out_dir)]

    sokey_enum = _truthy(options.get("sokey_enum")) or _truthy(options.get("sokey_c_batch"))
    dexkey_enum = _truthy(options.get("dexkey_enum")) or _truthy(options.get("dex_enum"))
    server_sokey = _truthy(options.get("server_sokey"))

    sokey = _first(options, "old_sokey", "sokey", "client_sokey", "hidden")
    dexkey = _first(options, "dexkey", "fb", "client_dexkey")

    if sokey and not sokey_enum and not server_sokey:
        command += ["--sokey", sokey]
    if sokey_enum:
        command.append("--sokey-enum")
    if server_sokey:
        command.append("--server-sokey")

    if dexkey and not dexkey_enum:
        command += ["--dexkey", dexkey]
    if dexkey_enum:
        command.append("--dexkey-enum")
        if options.get("dexkey_enum_start") not in (None, ""):
            command += ["--dexkey-enum-start", str(options.get("dexkey_enum_start"))]
        if options.get("dexkey_enum_stop") not in (None, ""):
            command += ["--dexkey-enum-stop", str(options.get("dexkey_enum_stop"))]

    workers = str(
        options.get("enum_workers")
        or os.environ.get("IAPT_OLD_ENUM_WORKERS")
        or os.environ.get("IAPT_ENUM_WORKERS")
        or "32"
    )
    command += ["--enum-workers", workers]
    if options.get("enum_chunk_size") not in (None, ""):
        command += ["--enum-chunk-size", str(options.get("enum_chunk_size"))]
    if _truthy(options.get("no_python_fallback")):
        command.append("--no-python-fallback")

    signature_mode = str(options.get("signature_mode") or "skip").strip().lower()
    command += ["--signature-mode", signature_mode if signature_mode in {"skip", "verify"} else "skip"]
    signature_hex = _first(options, "signature_bytes_hex", "signature_hex", "cert_hex")
    if signature_hex:
        command += ["--signature-bytes-hex", signature_hex]

    password = _first(options, "user_password", "password")
    if password:
        command += ["--password", password]
    main_file = _first(options, "main_file", "custom_main_file", "entry_file")
    if main_file:
        command += ["--main-file", main_file]
    return command


# IAPT_NATIVE_COMPILE_DIRECT_V3_BACKFILL_BEGIN
_NATIVE_COMPILE_KEYS = (
    "native_compile_restore",
    "v3_native_compile_restore",
    "ancient_native_compile_restore",
)


def _native_compile_requested(options: dict[str, Any]) -> bool:
    return any(_truthy(options.get(key)) for key in _NATIVE_COMPILE_KEYS)


def _native_compile_feature5_entitled(task: dict[str, Any]) -> bool:
    """Check feature 5 without changing the user's task or surfacing auto-detection."""
    try:
        from .task_feature_guard_v191 import assert_task_entitled
        probe = {
            "id": int(task.get("id") or 0),
            "user_id": task.get("user_id"),
            "feature_id": 0,
            "decrypt_version": "ancient",
            "options_json": json.dumps({"primary_feature_id": 5}, ensure_ascii=False),
        }
        assert_task_entitled(probe, stage="ancient_native_compile_auto_probe")
        return True
    except Exception:
        return False


def _native_compile_log(log_path: Path, label: str, payload: Any) -> None:
    try:
        with log_path.open("a", encoding="utf-8", errors="replace") as fp:
            fp.write("\n[" + str(label) + "] " + json.dumps(
                payload, ensure_ascii=False, sort_keys=True, default=str
            ) + "\n")
    except Exception:
        pass


def _native_compile_merge_reports(reports: list[dict[str, Any]]) -> dict[str, Any]:
    valid = [dict(row) for row in reports if isinstance(row, dict)]
    if not valid:
        return {}
    merged = dict(valid[0])
    merged["rounds"] = len(valid)
    merged["replaced_count"] = sum(int(row.get("replaced_count") or 0) for row in valid)
    merged["unknown_replaced_count"] = sum(int(row.get("unknown_replaced_count") or 0) for row in valid)
    merged["placeholder_count"] = int(valid[0].get("placeholder_count") or 0)
    merged["unknown_placeholder_count"] = int(valid[0].get("unknown_placeholder_count") or 0)
    merged["unresolved_count"] = int(valid[-1].get("unresolved_count") or 0)
    merged["unknown_unresolved_count"] = int(valid[-1].get("unknown_unresolved_count") or 0)
    merged["unknown_member_files_scanned"] = max(
        int(row.get("unknown_member_files_scanned") or row.get("unknown_member_files") or 0)
        for row in valid
    )
    for key in ("files_changed", "unknown_files_changed", "encoding_migrations", "dex_page_candidates"):
        values = []
        seen = set()
        for row in valid:
            items = row.get(key)
            if not isinstance(items, list):
                continue
            for item in items:
                marker = json.dumps(item, ensure_ascii=False, sort_keys=True, default=str)
                if marker in seen:
                    continue
                seen.add(marker)
                values.append(item)
        merged[key] = values
    merged["round_reports"] = [{
        "round": index + 1,
        "replaced_count": int(row.get("replaced_count") or 0),
        "unknown_replaced_count": int(row.get("unknown_replaced_count") or 0),
        "unresolved_count": int(row.get("unresolved_count") or 0),
        "unknown_unresolved_count": int(row.get("unknown_unresolved_count") or 0),
        "files_changed": row.get("files_changed") or [],
    } for index, row in enumerate(valid)]
    return merged


def _native_compile_restore_after_ancient(
    task: dict[str, Any],
    options: dict[str, Any],
    apk: Path,
    out_dir: Path,
    log_path: Path,
) -> dict[str, Any] | None:
    """Backfill every project source file, including modules and src/_unknown members."""
    requested = _native_compile_requested(options)
    try:
        from .tools.iapp_native_compile_restore import (
            inspect_native_compiled_events,
            restore_native_compiled_events,
        )
        probe = inspect_native_compiled_events(apk, out_dir)
    except Exception as exc:
        if requested:
            raise RuntimeError("原生编译修复探测失败：" + str(exc)) from exc
        _native_compile_log(log_path, "IAPT_NATIVE_COMPILE_ANCIENT_PROBE_ERROR", {
            "error": f"{type(exc).__name__}: {exc}",
        })
        return None

    placeholder_count = int(probe.get("placeholder_count") or 0)
    if placeholder_count <= 0:
        return None
    detected = bool(probe.get("detected"))
    if not requested and not detected:
        return None

    if not _native_compile_feature5_entitled(task):
        if requested:
            raise RuntimeError("原生编译修复需要功能5")
        return None

    report = restore_native_compiled_events(apk, out_dir)
    _native_compile_log(log_path, "IAPT_NATIVE_COMPILE_ANCIENT_V3_BACKFILL", report)
    if report.get("ok") is not True:
        if requested:
            raise RuntimeError("原生编译修复器未能读取有效 DEX")
        return report

    replaced = int(report.get("replaced_count") or 0)
    options["native_compile_restore"] = True
    options["ancient_native_compile_restore"] = True
    options["v3_native_compile_restore"] = False
    options["native_compile_direct_v3_backfill"] = True
    options["native_compile_restore_strategy"] = "manifest-package/exact-token/all-text-files/v3-syntax-backfill+exact-normal-v3-filename-parser"
    if not requested:
        options["native_compile_restore_auto_enabled"] = True
    options["native_compile_replaced_count"] = replaced
    options["native_compile_unknown_files_scanned"] = int(report.get("unknown_member_files_scanned") or 0)
    options["native_compile_unknown_replaced_count"] = int(report.get("unknown_replaced_count") or 0)
    options["native_compile_manifest_package"] = str(report.get("manifest_package") or "")
    return report
# IAPT_NATIVE_COMPILE_DIRECT_V3_BACKFILL_END


def run_ancient_task(task_id: int) -> dict[str, Any]:
    from .task_feature_guard_v191 import enforce_task_or_mark_failed
    if not enforce_task_or_mark_failed(int(task_id), stage='ancient_supervisor_v136_ancient'):
        return {'ok': False, 'scheme': 'ancient', 'error': 'task feature denied'}
    started = time.monotonic()
    task = _one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return {"ok": False, "error": "任务不存在"}
    options = _loads(task.get("options_json"))
    task_no = str(task.get("task_no") or "")
    apk = Path(APP_STORAGE) / "uploads" / f"{task_no}.apk"
    out_dir = Path(APP_STORAGE) / "tasks" / task_no
    log_path = Path(APP_STORAGE) / "tasks" / f"{task_no}.log"
    pid_path = Path(APP_STORAGE) / "tasks" / f"{task_no}.ancient.pid"

    options.update(
        {
            "decrypt_scheme": "ancient",
            "decrypt_version": "ancient",
            "task_version": "ancient",
            "public_scheme": "ancient",
            "ancient_supervisor": VERSION,
            "ancient_stage": "preflight",
        }
    )

    if not apk.is_file():
        return _fail(task_id, f"上传文件不存在：{apk}", started, options)

    probe = options.get("old_sokey_probe") if isinstance(options.get("old_sokey_probe"), dict) else {}
    probe_error = str(probe.get("error") or "").strip()
    manual_sokey = _truthy(options.get("client_ancient_sokey_manual")) or _truthy(options.get("manual_sokey"))
    wants_sokey_enum = _truthy(options.get("sokey_enum")) or _truthy(options.get("sokey_c_batch"))
    wants_server_sokey = _truthy(options.get("server_sokey"))
    auto_sokey = _truthy(options.get("client_ancient_sokey_auto"))

    # V132: the final client parameters are authoritative. Ancient compact uploads
    # deliberately omit libygsiyu.so, so a server-side old_sokey_probe error is
    # expected and must not invalidate an explicit four-character client sokey.
    explicit_sokey = _first(options, "old_sokey", "sokey", "client_sokey", "hidden")
    explicit_sokey_valid = len(explicit_sokey) == 4 and explicit_sokey.isalnum() and explicit_sokey.isascii()
    if explicit_sokey_valid:
        options["ancient_sokey_preflight"] = "client-parameter"
        options["ancient_sokey_probe_ignored"] = bool(probe_error)
    elif explicit_sokey and not wants_sokey_enum and not wants_server_sokey:
        return _fail(task_id, "客户端提交的远古sokey无效：必须是4位字母或数字", started, options)
    elif probe_error and auto_sokey and not manual_sokey and not wants_sokey_enum and not wants_server_sokey:
        return _fail(task_id, "远古sokey提取失败：" + probe_error, started, options)

    command = _build_command(apk, out_dir, options)
    timeout = max(30, int(options.get("ancient_timeout") or os.environ.get("IAPT_ANCIENT_TIMEOUT_SEC") or DEFAULT_TIMEOUT))
    options["ancient_stage"] = "spawn"
    options["actual_ancient_command"] = command
    options["ancient_timeout_sec"] = timeout

    import shutil
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    _exec(
        "UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='ancient',options_json=%s WHERE id=%s",
        (str(out_dir), str(log_path), json.dumps(options, ensure_ascii=False, separators=(",", ":")), int(task_id)),
    )

    env = os.environ.copy()
    env.update(
        {
            "PYTHONIOENCODING": "utf-8",
            "PYTHONUTF8": "1",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "IAPT_OLD_FAST_ENUM": "1",
            "IAPT_OLD_ENUM_WORKERS": str(options.get("enum_workers") or env.get("IAPT_ENUM_WORKERS") or "32"),
            "IAPT_OLD_NO_PYTHON_FALLBACK": "1" if _truthy(options.get("no_python_fallback")) else "0",
        }
    )

    with log_path.open("w", encoding="utf-8", errors="replace") as log:
        log.write(f"[V136] supervisor={VERSION}\n")
        log.write("command=" + json.dumps(command, ensure_ascii=False) + "\n")
        log.write("options=" + json.dumps(options, ensure_ascii=False, separators=(",", ":")) + "\n")
        log.flush()
        process = subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            env=env,
            start_new_session=True,
            text=True,
        )
        pid_path.write_text(str(process.pid), encoding="ascii")
        deadline = time.monotonic() + timeout
        while process.poll() is None:
            if time.monotonic() >= deadline:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except Exception:
                    try:
                        process.kill()
                    except Exception:
                        pass
                try:
                    process.wait(timeout=5)
                except Exception:
                    pass
                log.write(f"\n[V131_TIMEOUT] {timeout}s\n")
                log.flush()
                try:
                    pid_path.unlink()
                except OSError:
                    pass
                return _fail(task_id, f"远古解密超时：{timeout}秒", started, options)
            time.sleep(0.5)
        return_code = int(process.returncode or 0)
        log.write(f"\n[V131_EXIT] code={return_code}\n")
        log.flush()

    try:
        pid_path.unlink()
    except OSError:
        pass

    if return_code != 0:
        try:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-6000:]
        except Exception:
            tail = ""
        return _fail(task_id, f"远古解密器退出码 {return_code}：{tail}", started, options)

    report_path = out_dir / "old_iapp_report.json"
    report: dict[str, Any] = {}
    if report_path.is_file():
        try:
            report = _loads(report_path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            report = {}
    if report.get("ok") is not True:
        return _fail(task_id, "远古解密器未生成有效 old_iapp_report.json", started, options)

    # IAPT_NATIVE_COMPILE_DIRECT_V3_BACKFILL_CALL_BEGIN
    # Restore every XML event token and every standalone 12-hex token line in
    # all textual project members (.iyu/.myu/.mjava/.mlua/.mjs and _unknown).
    # Filename traversal is deliberately delayed until the token backfill pass
    # has no unresolved methods left; a post-rename retry handles rare class-name
    # ambiguities, then the final metadata/file index is rebuilt.
    native_report = None
    native_round_reports = []
    try:
        native_report = _native_compile_restore_after_ancient(task, options, apk, out_dir, log_path)
        if isinstance(native_report, dict):
            native_round_reports.append(native_report)
    except Exception as exc:
        return _fail(task_id, "原生编译修复失败：" + str(exc), started, options)

    try:
        from .tools.iapp_ancient_v3_finalize import finalize_ancient_v3_output
        from .tools.iapp_native_compile_restore import restore_native_compiled_events

        # iAPEC is an independent inner-source layer. Decode it before the V3
        # filename fixpoint so call()/uigo()/fn references revealed by the
        # plaintext can resolve old-container _unknown members. This does not
        # require or imply the outer anti_encrypted_sample option.
        iapec_report = {}
        if _truthy(options.get("anti_iapec_encryption")):
            from .tools.iapt_v10.iapt_iapec_restore import restore_iapec_project
            iapec_report = restore_iapec_project(out_dir, apk, enabled=True)
            options["anti_iapec_detected"] = bool(iapec_report.get("detected"))
            options["anti_iapec_restored_count"] = int(iapec_report.get("restored_count") or 0)
            options["anti_iapec_remaining_count"] = int(iapec_report.get("remaining_count") or 0)
            _native_compile_log(log_path, "IAPT_ANTI_IAPEC_ANCIENT_RESTORE", iapec_report)

        # Complete the source-token pass first. Normally one pass resolves all
        # tokens because the 12-hex suffix is unique; retries are only for files
        # that appeared or became textual during the previous pass.
        if native_round_reports:
            for round_index in range(2, 6):
                last_native = native_round_reports[-1]
                if int(last_native.get("unresolved_count") or 0) <= 0:
                    break
                rerun = restore_native_compiled_events(apk, out_dir)
                _native_compile_log(log_path, f"IAPT_NATIVE_COMPILE_FULL_SOURCE_ROUND_{round_index}", rerun)
                if not isinstance(rerun, dict) or rerun.get("ok") is not True:
                    break
                native_round_reports.append(rerun)
                if (
                    int(rerun.get("replaced_count") or 0) <= 0
                    and int(rerun.get("unresolved_count") or 0) >= int(last_native.get("unresolved_count") or 0)
                ):
                    break
            native_report = _native_compile_merge_reports(native_round_reports)

        # Only now traverse and rename old-container members.
        finalize_report = finalize_ancient_v3_output(out_dir, native_report or {})
        filename_round = finalize_report.get("filename_rescan") if isinstance(finalize_report, dict) else {}

        # Renaming can supply a page/module stem for a previously ambiguous DEX
        # token. Retry after renaming, then rebuild filename metadata once more.
        if native_round_reports and (
            int((filename_round or {}).get("resolved_this_round") or 0) > 0
            or int((native_report or {}).get("unresolved_count") or 0) > 0
        ):
            for round_index in range(6, 10):
                rerun = restore_native_compiled_events(apk, out_dir)
                _native_compile_log(log_path, f"IAPT_NATIVE_COMPILE_POST_RENAME_ROUND_{round_index}", rerun)
                if not isinstance(rerun, dict) or rerun.get("ok") is not True:
                    break
                native_round_reports.append(rerun)
                if int(rerun.get("unresolved_count") or 0) <= 0:
                    break
                if int(rerun.get("replaced_count") or 0) <= 0:
                    break
            native_report = _native_compile_merge_reports(native_round_reports)
            finalize_report = finalize_ancient_v3_output(out_dir, native_report)

        if native_round_reports:
            native_report = _native_compile_merge_reports(native_round_reports)
            options["native_compile_replaced_count"] = int(native_report.get("replaced_count") or 0)
            options["native_compile_restore_rounds"] = int(native_report.get("rounds") or 1)
            # Rebuild one final time after all source and rename passes.
            finalize_report = finalize_ancient_v3_output(out_dir, native_report)

        updated_report = finalize_report.get("old_iapp_report")
        if isinstance(updated_report, dict):
            report = updated_report
        filename_report = finalize_report.get("filename_rescan")
        if isinstance(filename_report, dict):
            options["ancient_filename_rescan"] = True
            options["ancient_filename_unknown_remaining"] = int(filename_report.get("unknown_remaining") or 0)
        project_meta = finalize_report.get("project_meta")
        if isinstance(project_meta, dict) and project_meta:
            options["project_meta_decrypted"] = True
            _native_compile_log(log_path, "IAPT_PROJECT_META_JSON", project_meta)
        _native_compile_log(log_path, "IAPT_ANCIENT_V3_FINALIZE", {
            "unknown_file_count": int((filename_report or {}).get("unknown_remaining") or 0),
            "project_meta": project_meta or {},
        })
    except Exception as exc:
        return _fail(task_id, "远古 V3 最终整理失败：" + str(exc), started, options)
    # IAPT_NATIVE_COMPILE_DIRECT_V3_BACKFILL_CALL_END

    rows, total_bytes = _scan_public(out_dir, options)
    source_count = sum(
        1
        for row in rows
        if str(row.get("rel_path") or "").lower().endswith((".iyu", ".myu", ".java", ".mjava", ".ijava"))
    )
    if source_count <= 0:
        return _fail(task_id, f"远古解密未产生源码文件；公开文件={len(rows)}", started, options)

    total_ms = float(report.get("total_ms") or ((time.monotonic() - started) * 1000.0))
    options["ancient_stage"] = "done"
    _exec(
        "UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,file_count=%s,total_bytes=%s,decrypt_version='ancient',error_text=NULL,options_json=%s WHERE id=%s",
        (
            total_ms,
            str(report.get("app_name") or task.get("app_name") or ""),
            str(report.get("package_name") or task.get("package_name") or ""),
            str(report.get("version_name") or task.get("version_name") or ""),
            str(report.get("version_code") or task.get("version_code") or ""),
            len(rows),
            total_bytes,
            json.dumps(options, ensure_ascii=False, separators=(",", ":")),
            int(task_id),
        ),
    )
    try:
        from .quota import settle_decrypt_quota_once
        settle_decrypt_quota_once(int(task_id))
    except Exception as exc:
        print(f"[V136] quota settle warning: {exc!r}", flush=True)
    return {"ok": True, "scheme": "ancient", "files": len(rows), "bytes": total_bytes}


def dispatch_task(task_id: int):
    from .task_feature_guard_v191 import enforce_task_or_mark_failed
    if not enforce_task_or_mark_failed(int(task_id), stage='ancient_supervisor_v136_dispatch'):
        return {'ok': False, 'error': 'task feature denied'}
    task = _one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return None
    options = _loads(task.get("options_json"))
    if _is_ancient(task, options):
        return run_ancient_task(int(task_id))

    # Publish the worker claim before importing/initialising the large runner
    # module.  The client polls this field, so leaving it queued during startup
    # made active jobs look permanently stuck in the queue.  Ancient jobs are
    # excluded because their supervisor owns its own running transition.
    _exec(
        "UPDATE tasks SET status='running',error_text=NULL "
        "WHERE id=%s AND status IN ('queued','pending')",
        (int(task_id),),
    )
    fresh = _one("SELECT status FROM tasks WHERE id=%s", (int(task_id),)) or {}
    if str(fresh.get("status") or "").strip().lower() in {"done", "failed", "cancelled"}:
        return {"ok": True, "terminal": True}

    from . import decrypt_runner
    return decrypt_runner.run_task(int(task_id))


def describe() -> dict[str, Any]:
    return {
        "version": VERSION,
        "queue_level_dispatch": True,
        "ancient_process_group_timeout": True,
        "raw_db_status_updates": True,
        "client_sokey_authoritative": True,
        "skip_signature_component": "literal-null",
        "engine_fix": "native-old-iapp-getf-compatible",
        "server_probe_error_ignored_when_client_sokey_present": True,
        "timeout_sec": int(os.environ.get("IAPT_ANCIENT_TIMEOUT_SEC") or DEFAULT_TIMEOUT),
        "enum_workers": int(os.environ.get("IAPT_ENUM_WORKERS") or 32),
    }

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD
