# -*- coding: utf-8 -*-
from __future__ import annotations
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Request
from . import db
from .auth import current_user, require_permission, PERM_WHITELIST_MANAGE
from .quota import active_subscription, FEATURE_WHITELIST_BYPASS
from .secure import read_secure_json

router = APIRouter()
TABLE = 'decrypt_whitelist'


def _columns() -> set[str]:
    try:
        rows = db.all("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s", (TABLE,)) or []
        return {str(r.get('COLUMN_NAME')) for r in rows}
    except Exception:
        return set()


def _has_col(name: str) -> bool:
    return name in _columns()


def _add_col(name: str, ddl: str):
    try:
        if not _has_col(name):
            db.exec(f"ALTER TABLE {TABLE} ADD COLUMN {ddl}")
            print('[白名单] ADD COLUMN', name)
    except Exception as e:
        print('[白名单] ADD COLUMN skipped', name, e)


def ensure_whitelist_schema():
    """IAPT_V111_WHITELIST_SCHEMA_ONCE: schema migration runs during deployment, never in a request."""
    return None


def _safe_update(sql: str):
    try:
        db.exec(sql)
    except Exception as e:
        print('[白名单] normalize skipped:', e)


def _normalize_legacy_columns():
    cols = _columns()
    for c in ('package', 'pkg', 'pkg_name', 'app_package', 'packageName'):
        if c in cols:
            _safe_update(f"UPDATE {TABLE} SET package_name=`{c}` WHERE (package_name IS NULL OR package_name='') AND `{c}` IS NOT NULL AND `{c}`<>''")
    for c in ('code_sha256', 'file_hash', 'apk_sha256', 'hash', 'sha256'):
        if c in cols:
            _safe_update(f"UPDATE {TABLE} SET code_hash=LOWER(`{c}`) WHERE (code_hash IS NULL OR code_hash='') AND `{c}` IS NOT NULL AND `{c}`<>''")
    for c in ('expires_at', 'expire_time', 'end_time'):
        if c in cols:
            _safe_update(f"UPDATE {TABLE} SET expire_at=`{c}` WHERE expire_at IS NULL AND `{c}` IS NOT NULL")


def _body_value(body: dict, *names, default=None):
    for n in names:
        if isinstance(body, dict) and n in body and body[n] is not None:
            return body[n]
    return default


async def _read_body(request: Request):
    token = ''
    auth = request.headers.get('authorization') or ''
    if auth.lower().startswith('bearer '):
        token = auth.split(' ', 1)[1].strip()
    try:
        return await read_secure_json(request, token, verify=False)
    except Exception:
        try:
            return await request.json()
        except Exception:
            return {}


def _pick(r: dict, *names, default=''):
    for n in names:
        if n in r and r.get(n) not in (None, ''):
            return r.get(n)
    return default


def _public_row(r: dict) -> dict:
    h = str(_pick(r, 'code_hash', 'code_sha256', 'file_hash', 'apk_sha256', 'hash', 'sha256', default='') or '').strip().lower()
    pkg = str(_pick(r, 'package_name', 'package', 'pkg', 'pkg_name', 'app_package', 'packageName', default='') or '').strip()
    exp = _pick(r, 'expire_at', 'expires_at', 'expire_time', 'end_time', default='')
    item = {
        'id': int(r.get('id') or 0),
        'package_name': pkg,
        'package': pkg,
        'pkg': pkg,
        'code_hash': h,
        'code_sha256': h,
        'file_hash': h,
        'apk_sha256': h,
        'hash': h,
        'sha256': h,
        'expire_at': str(exp or ''),
        'expires_at': str(exp or ''),
        'expire_time': str(exp or ''),
        'note': str(_pick(r, 'note', 'remark', default='') or ''),
        'created_at': str(r.get('created_at') or ''),
        'updated_at': str(r.get('updated_at') or ''),
    }
    # 客户端状态显示：空到期时间代表永久保护；有未来时间代表生效。
    item['active'] = 1 if _is_active_expire(item.get('expire_at')) else 0
    return item


def _is_active_expire(exp) -> bool:
    if not exp or str(exp).lower() in ('none', 'null'):
        return True
    try:
        dt = datetime.fromisoformat(str(exp).replace('Z','').replace('T',' ')[:19])
        return datetime.now() < dt
    except Exception:
        return True


def _all_rows(limit: int = 500):
    ensure_whitelist_schema()
    try:
        rows = db.all(f"SELECT * FROM {TABLE} ORDER BY id DESC LIMIT %s", (int(limit),)) or []
    except Exception as e:
        raise HTTPException(500, '白名单读取失败：' + str(e))
    return [_public_row(dict(r)) for r in rows]


def _response(items):
    # 顶层 items/list/rows/data 都返回数组，兼容客户端各种解析。
    return {
        'ok': True,
        'success': True,
        'table': TABLE,
        'items': items,
        'list': items,
        'rows': items,
        'records': items,
        'whitelist': items,
        'whitelists': items,
        'data': items,
        'result': {'items': items, 'list': items, 'rows': items},
        'total': len(items),
        'count': len(items),
    }


def user_can_bypass_whitelist(user_id: int) -> bool:
    try:
        return active_subscription(int(user_id), FEATURE_WHITELIST_BYPASS) is not None
    except Exception:
        return False


def find_active_block(package_name: str, code_hash: str, user_id: int | None = None):
    """Exact indexed lookup; do not read thousands of whitelist rows for every upload."""
    pkg = (package_name or '').strip()
    h = (code_hash or '').strip().lower()
    if not pkg or not h:
        return None
    if user_id is not None and user_can_bypass_whitelist(int(user_id)):
        return None
    try:
        row = db.one(
            f"SELECT * FROM {TABLE} WHERE package_name=%s AND LOWER(code_hash)=%s "
            "AND (expire_at IS NULL OR expire_at > NOW()) ORDER BY id DESC LIMIT 1",
            (pkg, h),
        )
    except Exception as exc:
        raise HTTPException(503, '白名单检查暂时不可用：' + str(exc))
    return _public_row(dict(row)) if row else None


def assert_not_whitelisted(package_name: str, code_hash: str, user_id: int | None = None):
    row = find_active_block(package_name, code_hash, user_id)
    if row:
        exp = str(row.get('expire_at') or '永久')
        raise HTTPException(403, f'该应用在白名单保护中，到期前禁止解密：{package_name} / {code_hash[:12]}... / {exp}')


@router.get('/api/admin/whitelist')
def admin_whitelist_api(keyword: str = '', limit: int = 500, user=Depends(current_user)):
    require_permission(user, PERM_WHITELIST_MANAGE)
    kw = (keyword or '').strip().lower()
    items = _all_rows(max(1, min(int(limit or 500), 5000)))
    if kw:
        items = [x for x in items if kw in ((x.get('package_name','') + ' ' + x.get('code_hash','') + ' ' + x.get('note','')).lower())]
    return _response(items)


@router.get('/admin/whitelist')
def admin_whitelist_plain(keyword: str = '', limit: int = 500, user=Depends(current_user)):
    return admin_whitelist_api(keyword, limit, user)


@router.post('/api/admin/whitelist/save')
async def admin_whitelist_save_api(request: Request, user=Depends(current_user)):
    require_permission(user, PERM_WHITELIST_MANAGE)
    ensure_whitelist_schema()
    body = await _read_body(request)
    wid = int(_body_value(body, 'id', 'whitelist_id', default=0) or 0)
    pkg = str(_body_value(body, 'package_name', 'package', 'pkg', default='') or '').strip()
    h = str(_body_value(body, 'code_hash', 'code_sha256', 'file_hash', 'hash', 'apk_sha256', 'sha256', default='') or '').strip().lower()
    exp = str(_body_value(body, 'expire_at', 'expires_at', 'expire_time', default='') or '').strip()
    note = str(_body_value(body, 'note', 'remark', default='') or '').strip()[:255]
    if not pkg or not h:
        raise HTTPException(400, '包名和代码Hash不能为空')
    exp_val = None if exp in ('', 'null', 'None') else exp.replace('T', ' ')[:19]
    if wid > 0:
        db.exec(f'UPDATE {TABLE} SET package_name=%s,code_hash=%s,expire_at=%s,note=%s WHERE id=%s', (pkg, h, exp_val, note, wid))
    else:
        wid = db.exec(f'INSERT INTO {TABLE}(package_name,code_hash,expire_at,note) VALUES(%s,%s,%s,%s)', (pkg, h, exp_val, note))
    return {'ok': True, 'success': True, 'id': wid, 'item': _public_row({'id': wid, 'package_name': pkg, 'code_hash': h, 'expire_at': exp_val, 'note': note})}


@router.post('/admin/whitelist/save')
async def admin_whitelist_save_plain(request: Request, user=Depends(current_user)):
    return await admin_whitelist_save_api(request, user)


@router.post('/api/admin/whitelist/delete')
async def admin_whitelist_delete_api(request: Request, user=Depends(current_user)):
    require_permission(user, PERM_WHITELIST_MANAGE)
    ensure_whitelist_schema()
    body = await _read_body(request)
    wid = int(_body_value(body, 'id', 'whitelist_id', default=0) or 0)
    if wid <= 0:
        raise HTTPException(400, '缺少白名单ID')
    db.exec(f'DELETE FROM {TABLE} WHERE id=%s', (wid,))
    return {'ok': True, 'success': True}


@router.post('/admin/whitelist/delete')
async def admin_whitelist_delete_plain(request: Request, user=Depends(current_user)):
    return await admin_whitelist_delete_api(request, user)

# IAPT_WHITELIST_SIGNATURE_UPLOAD_DEFER_V163_BEGIN
# Old upload-time package/hash guard is disabled. V163 verifies only during the
# decrypt worker run, after the uploaded APK can be scanned for the embedded
# Base64 signature.
def assert_not_whitelisted(package_name, code_hash, user_id):
    return None
# IAPT_WHITELIST_SIGNATURE_UPLOAD_DEFER_V163_END
