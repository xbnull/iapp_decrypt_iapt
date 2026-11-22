from __future__ import annotations

import json
import time
from typing import Any

from . import db

VERSION = "V191.4-live-db-feature-guard-signed-user-id"
FEATURE_BASIC = 1
FEATURE_DEX_ENUM = 2
FEATURE_DYNAMIC_KEY = 4
FEATURE_NUMERIC_FN_RESTORE = 5
FEATURE_V6_STATIC = 6
FEATURE_WHITELIST_BYPASS = 7
FEATURE_SOURCE_RESTORE = 8
FEATURE_JOINT_KEY_ENUM = 14
FEATURE_SERVER_SOKEY = 15
FEATURE_DYNAMIC_KEY_POOL = 15
FEATURE_DYNAMIC_KEY_POOL_ENUM = 16
FEATURE_ANTI_QIUSHUI = 17
FEATURE_ULTIMATE_ALL = 999
EXACT_ONLY_FEATURES = {FEATURE_WHITELIST_BYPASS, FEATURE_JOINT_KEY_ENUM, FEATURE_ANTI_QIUSHUI}
TERMINAL_STATUSES = {"done", "failed", "cancelled", "canceled"}

_SCHEMA_CACHE: dict[str, tuple[float, set[str]]] = {}
_SCHEMA_TTL = 60.0


class TaskFeatureDenied(PermissionError):
    def __init__(self, message: str, *, user_id: int = 0, task_id: int = 0, feature_ids=()):
        super().__init__(message)
        self.user_id = int(user_id or 0)
        self.task_id = int(task_id or 0)
        self.feature_ids = tuple(sorted({int(x) for x in feature_ids if int(x) > 0}))


class TaskFeatureSchemaError(RuntimeError):
    pass


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


def _ints(raw: Any) -> set[int]:
    if raw is None or raw == "":
        return set()
    if isinstance(raw, dict):
        raw = list(raw.keys())
    elif not isinstance(raw, (list, tuple, set)):
        text = str(raw).strip()
        if not text:
            return set()
        try:
            raw = json.loads(text)
        except Exception:
            import re
            raw = re.split(r"[^0-9]+", text)
    if not isinstance(raw, (list, tuple, set)):
        raw = [raw]
    out: set[int] = set()
    for item in raw:
        try:
            value = int(str(item).strip())
            if value >= 0:
                out.add(value)
        except Exception:
            pass
    return out


def _q(name: str) -> str:
    return "`" + str(name).replace("`", "``") + "`"


def _columns(table: str) -> set[str]:
    now = time.monotonic()
    cached = _SCHEMA_CACHE.get(table)
    if cached and now - cached[0] < _SCHEMA_TTL:
        return set(cached[1])
    try:
        rows = db.all(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s",
            (str(table),),
        ) or []
        cols = {str(r.get("COLUMN_NAME") or r.get("column_name") or "") for r in rows}
        cols.discard("")
    except Exception:
        cols = set()
    _SCHEMA_CACHE[table] = (now, cols)
    return set(cols)


def _pick(cols: set[str], *names: str) -> str | None:
    lowered = {c.lower(): c for c in cols}
    for name in names:
        if name.lower() in lowered:
            return lowered[name.lower()]
    return None


def _task_layout() -> dict[str, str | None]:
    cols = _columns("tasks")
    return {
        "id": _pick(cols, "id", "task_id"),
        "user_id": _pick(cols, "user_id", "uid", "account_id", "owner_id", "created_by", "creator_id", "member_id"),
        "feature_id": _pick(cols, "feature_id", "function_id", "func_id", "permission_id"),
        "decrypt_version": _pick(cols, "decrypt_version", "decrypt_mode", "version", "mode"),
        "status": _pick(cols, "status", "state", "task_status"),
        "options_json": _pick(cols, "options_json", "options", "params_json", "request_json", "config_json", "params"),
        "error_text": _pick(cols, "error_text", "error", "fail_reason", "message"),
    }


def _select_alias(col: str | None, alias: str, default_sql: str) -> str:
    if col:
        return f"{_q(col)} AS {_q(alias)}"
    return f"{default_sql} AS {_q(alias)}"


def required_feature_ids(task: dict[str, Any]) -> set[int]:
    """Resolve every entitlement used by one task, including additive modifiers."""
    options = _loads(task.get("options_json"))
    required: set[int] = set()

    for value in (task.get("feature_id"), options.get("feature_id"), options.get("primary_feature_id")):
        try:
            fid = int(value or 0)
            if fid > 0:
                required.add(fid)
        except Exception:
            pass

    for key in (
        "required_feature_ids",
        "requested_feature_ids",
        "requested_features",
        "feature_ids",
        "feature_scope",
    ):
        required.update(x for x in _ints(options.get(key)) if x > 0)

    cache_scope = options.get("_cache_scope")
    if isinstance(cache_scope, dict):
        required.update(x for x in _ints(cache_scope.get("requested_feature_sub_ids")) if x > 0)
        required.update(x for x in _ints(cache_scope.get("required_feature_ids")) if x > 0)

    pool_mode = str(options.get("server_key_pool_mode") or "").strip().lower()
    if pool_mode == "enum":
        required.add(FEATURE_DYNAMIC_KEY_POOL_ENUM)
    elif pool_mode == "selected" or str(options.get("server_key_pool_ref") or "").strip():
        required.add(FEATURE_DYNAMIC_KEY_POOL)

    if _truthy(options.get("dynamic_key")):
        required.add(FEATURE_DYNAMIC_KEY)
    if _truthy(options.get("dex_enum")) or _truthy(options.get("dexkey_enum")):
        required.add(FEATURE_DEX_ENUM)
    if _truthy(options.get("server_sokey")):
        required.add(FEATURE_SERVER_SOKEY)
    if _truthy(options.get("joint_key_enum")) or (
        (_truthy(options.get("sokey_enum")) or _truthy(options.get("sokey_c_batch")))
        and (_truthy(options.get("dexkey_enum")) or _truthy(options.get("dex_enum")))
    ):
        required.add(FEATURE_JOINT_KEY_ENUM)
    if (_truthy(options.get("anti_qiushui")) or _truthy(options.get("hidden_resource_restore"))
            or _truthy(options.get("anti_encrypted_sample")) or _truthy(options.get("anti_iapec_encryption"))
            or _truthy(options.get("anti_iapec_self_destruct"))):
        required.add(FEATURE_ANTI_QIUSHUI)
    if _truthy(options.get("source_restore")) or _truthy(options.get("dex_static_restore")):
        required.add(FEATURE_SOURCE_RESTORE)
    if _truthy(options.get("numeric_source_restore")) or str(options.get("restore_fn_names") or "").strip().lower() in {"auto", "on"}:
        required.add(FEATURE_NUMERIC_FN_RESTORE)
    # IAPT_NATIVE_COMPILE_RESTORE_FEATURE_GUARD_BEGIN
    if any(_truthy(options.get(key)) for key in (
        "native_compile_restore", "v3_native_compile_restore", "ancient_native_compile_restore"
    )):
        required.add(FEATURE_NUMERIC_FN_RESTORE)
    # IAPT_NATIVE_COMPILE_RESTORE_FEATURE_GUARD_END

    version = str(options.get("decrypt_version") or task.get("decrypt_version") or "").strip().lower()
    if version in {"v6", "6", "static_v6", "v6_static"}:
        required.add(FEATURE_V6_STATIC)

    if not required:
        required.add(FEATURE_BASIC)
    return required


def _feature_supported(features_json: Any, feature_id: int) -> bool:
    ids = _ints(features_json)
    fid = int(feature_id)
    if FEATURE_ULTIMATE_ALL in ids:
        return True
    if fid in EXACT_ONLY_FEATURES:
        return fid in ids
    if fid in ids:
        return True
    if 0 in ids:
        return True
    if fid == FEATURE_BASIC and not ids:
        return True
    return False


def _load_task(task_id: int) -> dict[str, Any] | None:
    layout = _task_layout()
    id_col = layout.get("id")
    if not id_col:
        raise TaskFeatureSchemaError("tasks 表没有可识别的 id/task_id 字段")
    fields = [
        _select_alias(layout.get("id"), "id", "0"),
        _select_alias(layout.get("user_id"), "user_id", "NULL"),
        _select_alias(layout.get("feature_id"), "feature_id", "0"),
        _select_alias(layout.get("decrypt_version"), "decrypt_version", "''"),
        _select_alias(layout.get("status"), "status", "''"),
        _select_alias(layout.get("options_json"), "options_json", "'{}'"),
    ]
    return db.one(
        f"SELECT {','.join(fields)} FROM `tasks` WHERE {_q(id_col)}=%s LIMIT 1",
        (int(task_id),),
    )


def _user_state(user_id: int) -> dict[str, Any] | None:
    cols = _columns("users")
    id_col = _pick(cols, "id", "user_id", "uid")
    if not id_col:
        raise TaskFeatureSchemaError("users 表没有可识别的 id/user_id/uid 字段")
    banned_col = _pick(cols, "banned", "is_banned", "disabled", "is_disabled", "locked")
    return db.one(
        f"SELECT {_q(id_col)} AS id,{_q(banned_col) if banned_col else '0'} AS banned "
        f"FROM `users` WHERE {_q(id_col)}=%s LIMIT 1",
        (int(user_id),),
    )


def _live_subscription_rows(user_id: int) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    s_cols = _columns("subscriptions")
    s_id = _pick(s_cols, "sub_id", "id", "subscription_id")
    s_features = _pick(s_cols, "features_json", "features", "feature_ids", "permissions_json", "feature_list")
    if not s_id or not s_features:
        raise TaskFeatureSchemaError("subscriptions 表没有可识别的订阅ID或功能字段")
    s_name = _pick(s_cols, "sub_name", "name", "subscription_name")
    s_quota = _pick(s_cols, "daily_quota", "quota", "daily_limit")

    select_head = (
        f"s.{_q(s_id)} AS sub_id,"
        f"{('s.' + _q(s_name)) if s_name else "''"} AS sub_name,"
        f"s.{_q(s_features)} AS features_json,"
        f"{('s.' + _q(s_quota)) if s_quota else '0'} AS daily_quota"
    )

    us_cols = _columns("user_subscriptions")
    us_user = _pick(us_cols, "user_id", "uid", "account_id")
    us_sub = _pick(us_cols, "sub_id", "subscription_id", "id")
    us_expire = _pick(us_cols, "expire_at", "expires_at", "subscription_expire", "end_at")
    if us_user and us_sub:
        expiry = f" AND (us.{_q(us_expire)} IS NULL OR us.{_q(us_expire)}>NOW())" if us_expire else ""
        rows.extend(list(db.all(
            f"SELECT {select_head},"
            f"{('us.' + _q(us_expire)) if us_expire else 'NULL'} AS bind_expire_at,"
            f"'user_subscriptions' AS bind_source "
            f"FROM `user_subscriptions` us JOIN `subscriptions` s ON s.{_q(s_id)}=us.{_q(us_sub)} "
            f"WHERE us.{_q(us_user)}=%s{expiry}",
            (int(user_id),),
        ) or []))

    u_cols = _columns("users")
    u_id = _pick(u_cols, "id", "user_id", "uid")
    u_sub = _pick(u_cols, "subscription_id", "sub_id", "current_sub_id")
    u_expire = _pick(u_cols, "subscription_expire", "subscription_expires_at", "expire_at", "sub_expire_at")
    if u_id and u_sub:
        expiry = f" AND (u.{_q(u_expire)} IS NULL OR u.{_q(u_expire)}>NOW())" if u_expire else ""
        rows.extend(list(db.all(
            f"SELECT {select_head},"
            f"{('u.' + _q(u_expire)) if u_expire else 'NULL'} AS bind_expire_at,"
            f"'users.subscription_id' AS bind_source "
            f"FROM `users` u JOIN `subscriptions` s ON s.{_q(s_id)}=u.{_q(u_sub)} "
            f"WHERE u.{_q(u_id)}=%s AND COALESCE(u.{_q(u_sub)},0)<>0{expiry}",
            (int(user_id),),
        ) or []))

    default = db.one(
        f"SELECT {select_head},NULL AS bind_expire_at,'default' AS bind_source "
        f"FROM `subscriptions` s WHERE s.{_q(s_id)}=0 LIMIT 1"
    )
    if default:
        rows.append(default)
    return rows


def _task_user_id(task: dict[str, Any]) -> int:
    """Return the exact signed integer owner ID; existence is decided only by the database."""
    for key in ("user_id", "uid", "account_id", "owner_id", "created_by", "creator_id", "member_id"):
        if key not in task:
            continue
        raw = task.get(key)
        if raw is None or str(raw).strip() == "":
            raise TaskFeatureDenied("任务没有有效用户字段，已拒绝执行")
        try:
            # Convert to an integer before it reaches SQL. Negative and zero IDs are
            # valid candidates and must be looked up rather than rejected locally.
            return int(str(raw).strip(), 10)
        except Exception as exc:
            raise TaskFeatureDenied("任务用户ID格式无效，已拒绝执行") from exc
    raise TaskFeatureDenied("任务没有用户字段，已拒绝执行")


def assert_task_entitled(task: dict[str, Any], *, stage: str = "execute") -> dict[str, Any]:
    task_id = int(task.get("id") or task.get("task_id") or 0)
    required = required_feature_ids(task)
    try:
        user_id = _task_user_id(task)
    except TaskFeatureDenied as exc:
        exc.task_id = task_id
        exc.feature_ids = tuple(sorted(required))
        raise

    user = _user_state(user_id)
    if not user:
        raise TaskFeatureDenied("任务用户不存在，已拒绝执行", user_id=user_id, task_id=task_id, feature_ids=required)
    if int(user.get("banned") or 0) != 0:
        raise TaskFeatureDenied("账号已封禁，任务已拒绝执行", user_id=user_id, task_id=task_id, feature_ids=required)

    rows = _live_subscription_rows(user_id)
    grants: dict[int, int] = {}
    denied: list[int] = []
    for fid in sorted(required):
        matched = next((row for row in rows if _feature_supported(row.get("features_json"), fid)), None)
        if matched is None:
            denied.append(fid)
        else:
            grants[int(fid)] = int(matched.get("sub_id") or 0)

    if denied:
        text = ",".join(str(x) for x in denied)
        raise TaskFeatureDenied(
            f"当前账号没有任务所需功能：{text}",
            user_id=user_id,
            task_id=task_id,
            feature_ids=denied,
        )
    return {
        "ok": True,
        "version": VERSION,
        "stage": str(stage),
        "task_id": task_id,
        "user_id": user_id,
        "required_feature_ids": sorted(required),
        "grant_sub_ids": {str(k): int(v) for k, v in grants.items()},
    }


def load_and_assert(task_id: int, *, stage: str = "execute") -> tuple[dict[str, Any], dict[str, Any]]:
    task = _load_task(int(task_id))
    if not task:
        raise TaskFeatureDenied("任务不存在", task_id=int(task_id))
    return task, assert_task_entitled(task, stage=stage)


def _update_task(task_id: int, *, status: str | None = None, error_text: str | None = None, options: dict[str, Any] | None = None) -> None:
    layout = _task_layout()
    id_col = layout.get("id")
    if not id_col:
        return
    sets: list[str] = []
    args: list[Any] = []
    if status is not None and layout.get("status"):
        sets.append(f"{_q(layout['status'])}=%s")
        args.append(str(status))
    if error_text is not None and layout.get("error_text"):
        sets.append(f"{_q(layout['error_text'])}=%s")
        args.append(str(error_text)[:4000])
    if options is not None and layout.get("options_json"):
        sets.append(f"{_q(layout['options_json'])}=%s")
        args.append(json.dumps(options, ensure_ascii=False, separators=(",", ":")))
    if not sets:
        return
    args.append(int(task_id))
    db.exec(f"UPDATE `tasks` SET {','.join(sets)} WHERE {_q(id_col)}=%s", tuple(args))


def enforce_task_or_mark_failed(task_id: int, *, stage: str = "execute") -> bool:
    task_id = int(task_id)
    try:
        task, report = load_and_assert(task_id, stage=stage)
        if str(task.get("status") or "").strip().lower() in TERMINAL_STATUSES:
            return True
        options = _loads(task.get("options_json"))
        options["task_feature_guard"] = report
        try:
            _update_task(task_id, options=options)
        except Exception:
            pass
        return True
    except (TaskFeatureDenied, TaskFeatureSchemaError) as exc:
        denied_ids = list(getattr(exc, "feature_ids", ()))
        user_id = int(getattr(exc, "user_id", 0) or 0)
        try:
            task = _load_task(task_id) or {}
            options = _loads(task.get("options_json"))
            options["task_feature_guard"] = {
                "ok": False,
                "version": VERSION,
                "stage": str(stage),
                "task_id": task_id,
                "user_id": user_id,
                "denied_feature_ids": denied_ids,
                "reason": str(exc)[:500],
            }
            _update_task(task_id, status="failed", error_text=str(exc), options=options)
        except Exception as update_exc:
            print(f"[IAPT_V191_FEATURE_GUARD] failed to mark task={task_id}: {update_exc!r}", flush=True)
        print(f"[IAPT_V191_FEATURE_GUARD] denied task={task_id} stage={stage}: {exc}", flush=True)
        return False
    except Exception as exc:
        # Fail closed: database lookup errors must never become authorization success.
        try:
            _update_task(task_id, status="failed", error_text=f"功能权限数据库校验失败：{exc}")
        except Exception:
            pass
        print(f"[IAPT_V191_FEATURE_GUARD] database error task={task_id} stage={stage}: {exc!r}", flush=True)
        return False


def describe() -> dict[str, Any]:
    return {
        "version": VERSION,
        "database_lookup_per_task": True,
        "checks_user_exists": True,
        "checks_banned": True,
        "checks_subscription_expiry": True,
        "checks_primary_and_additive_features": True,
        "execution_guard": True,
        "adaptive_column_names": True,
        "supports_zero_user_id": True,
        "supports_signed_user_id": True,
        "user_lookup_uses_bound_parameters": True,
        "fail_closed_on_database_error": True,
        "exact_only_features": sorted(EXACT_ONLY_FEATURES),
        "ultimate_feature": FEATURE_ULTIMATE_ALL,
    }
