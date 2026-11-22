import hashlib
import secrets
import threading
import time
from datetime import datetime, timedelta
from fastapi import Header, HTTPException, Request
from . import db
from .config import TOKEN_EXPIRE_MINUTES
from .secure import verify_request

# 后台权限 ID：每个后台按钮/接口都对应一个独立权限。
PERM_SUPER_ADMIN = 999
PERM_ADMIN_VIEW = 100
PERM_USER_LIST = 101
PERM_USER_CREATE = 102
PERM_USER_BALANCE = 103
PERM_USER_BAN = 104
PERM_USER_SUBSCRIPTION = 105
PERM_CARD_CREATE = 201
PERM_CARD_LIST = 202
PERM_CARD_MANAGE = 203
PERM_SUBSCRIPTION_MANAGE = 301
PERM_DYNAMIC_KEY_POOL_MANAGE = 302
PERM_TASK_VIEW_ALL = 401
PERM_WHITELIST_MANAGE = 602
PERM_TASK_MANAGE = 603
PERM_CLEAR_UPLOADS = 604
PERM_CLEAR_TASK_FILES = 605
PERM_CLEAR_TASK_RECORDS = 606
PERM_REGISTER_MANAGE = 501
PERM_ANNOUNCEMENT_MANAGE = 502
PERM_UPDATE_MANAGE = 503
PERM_APP_SWITCH_MANAGE = 504

ADMIN_PERMISSION_DEFS = [
    (PERM_ADMIN_VIEW, '进入后台', '允许进入后台页面'),
    (PERM_USER_LIST, '查看用户列表', '查看用户、余额、订阅、封禁状态'),
    (PERM_USER_CREATE, '创建普通用户', '创建普通用户账号；创建管理员仍需要超级管理员'),
    (PERM_USER_BALANCE, '修改余额', '修改用户余额'),
    (PERM_USER_BAN, '封禁账号', '封禁或解封用户'),
    (PERM_USER_SUBSCRIPTION, '修改订阅', '给用户增加或修改订阅'),
    (PERM_CARD_CREATE, '生成卡密', '生成余额卡或订阅卡'),
    (PERM_CARD_LIST, '查看卡密', '查看卡密使用情况'),
    (PERM_CARD_MANAGE, '操作卡密', '作废/恢复/清除使用记录/删除卡密'),
    (PERM_SUBSCRIPTION_MANAGE, '管理订阅类型', '新增/修改订阅类型、日额度和功能列表'),
    (PERM_DYNAMIC_KEY_POOL_MANAGE, '管理动态密钥池', '查看、添加、修改、启停、验证或删除服务器动态密钥'),
    (PERM_TASK_VIEW_ALL, '查看全部任务', '查看全站任务；普通用户只能看自己的任务'),
    (PERM_WHITELIST_MANAGE, '白名单管理', '添加、删除、修改保护白名单'),
    (PERM_TASK_MANAGE, '任务操作', '删除任务、下载任务源码'),
    (PERM_CLEAR_UPLOADS, '清空上传文件', '一键清空 storage/uploads 上传文件'),
    (PERM_CLEAR_TASK_FILES, '清空任务文件', '一键清空任务输出文件和临时 ZIP'),
    (PERM_CLEAR_TASK_RECORDS, '清空任务记录', '只清空任务/下载/缓存数据库记录并重置任务ID，不删除文件'),
    (PERM_REGISTER_MANAGE, '注册开关', '开启或关闭用户自助注册'),
    (PERM_ANNOUNCEMENT_MANAGE, '公告管理', '设置客户端公告内容'),
    (PERM_UPDATE_MANAGE, '更新发布', '发布版本更新和强制更新'),
    (PERM_APP_SWITCH_MANAGE, '软件开关', '开启或关闭客户端进入'),
    (PERM_SUPER_ADMIN, '超级管理员', '拥有全部权限，可创建/编辑其他管理员账号和权限'),
]


def sha256_password(pw: str) -> str:
    return hashlib.sha256((pw or '').encode('utf-8')).hexdigest()


def make_token(user_id: int) -> str:
    token = secrets.token_hex(32)
    exp = datetime.now() + timedelta(minutes=TOKEN_EXPIRE_MINUTES)
    db.exec('INSERT INTO sessions(token,user_id,expire_at) VALUES(%s,%s,%s)', (token, user_id, exp))
    return token


# IAPT_V111_AUTH_CACHE_BEGIN
_IAPT_V111_SESSION_TOUCH_SECONDS = 300.0
_IAPT_V111_PERMISSION_CACHE_SECONDS = 10.0
_IAPT_V111_SESSION_TOUCH = {}
_IAPT_V111_PERMISSION_CACHE = {}
_IAPT_V111_AUTH_LOCK = threading.RLock()


def _iapt_v111_touch_session(token: str) -> None:
    now = time.monotonic()
    with _IAPT_V111_AUTH_LOCK:
        previous = float(_IAPT_V111_SESSION_TOUCH.get(token, 0.0) or 0.0)
        if now - previous < _IAPT_V111_SESSION_TOUCH_SECONDS:
            return
        _IAPT_V111_SESSION_TOUCH[token] = now
        if len(_IAPT_V111_SESSION_TOUCH) > 4096:
            cutoff = now - (_IAPT_V111_SESSION_TOUCH_SECONDS * 2.0)
            for key, value in list(_IAPT_V111_SESSION_TOUCH.items()):
                if float(value or 0.0) < cutoff:
                    _IAPT_V111_SESSION_TOUCH.pop(key, None)
    try:
        db.exec(
            'UPDATE sessions SET expire_at=%s WHERE token=%s',
            (datetime.now() + timedelta(minutes=TOKEN_EXPIRE_MINUTES), token),
        )
    except Exception as exc:
        print('[IAPT_V111_SESSION_TOUCH_WARN]', repr(exc), flush=True)


def _iapt_v111_permission_ids(user_id: int) -> set[int]:
    uid = int(user_id)
    now = time.monotonic()
    with _IAPT_V111_AUTH_LOCK:
        cached = _IAPT_V111_PERMISSION_CACHE.get(uid)
        if cached and now - float(cached[0]) < _IAPT_V111_PERMISSION_CACHE_SECONDS:
            return set(cached[1])
    rows = db.all('SELECT permission_id FROM admin_permissions WHERE user_id=%s', (uid,)) or []
    ids = {int(r['permission_id']) for r in rows}
    with _IAPT_V111_AUTH_LOCK:
        _IAPT_V111_PERMISSION_CACHE[uid] = (now, tuple(sorted(ids)))
        if len(_IAPT_V111_PERMISSION_CACHE) > 2048:
            _IAPT_V111_PERMISSION_CACHE.clear()
    return ids
# IAPT_V111_AUTH_CACHE_END

def current_user(request: Request, authorization: str | None = Header(default=None)):
    if not authorization or not authorization.lower().startswith('bearer '):
        raise HTTPException(401, '未登录')
    token = authorization.split(' ', 1)[1].strip()
    verify_request(request, token)
    row = db.one('''
        SELECT u.* FROM sessions s JOIN users u ON s.user_id=u.id
        WHERE s.token=%s AND s.expire_at>NOW()
    ''', (token,))
    if not row:
        raise HTTPException(401, '登录失效')
    _iapt_v111_touch_session(token)
    if row.get('banned'):
        raise HTTPException(403, '账号已封禁')
    return row


def user_permission_ids(user_id: int) -> set[int]:
    return _iapt_v111_permission_ids(int(user_id))


def is_super_admin(user) -> bool:
    # 超级管理员只按后台权限 ID 999 判断，不再用 users.permission >= 9。
    # users.permission 只作为“是否管理员账号”的粗粒度标记：0普通，1管理员。
    if not user:
        return False
    return PERM_SUPER_ADMIN in user_permission_ids(int(user['id']))


def has_permission(user, permission_id: int) -> bool:
    if is_super_admin(user):
        return True
    if not user:
        return False
    # 兼容老数据：permission=1 代表管理员账号；真正授权看 admin_permissions.permission_id。
    return int(permission_id) in user_permission_ids(int(user['id']))


def permission_name(permission_id: int) -> str:
    for i, n, _ in ADMIN_PERMISSION_DEFS:
        if int(i) == int(permission_id):
            return n
    return str(permission_id)


def require_permission(user, permission_id: int):
    if not has_permission(user, permission_id):
        raise HTTPException(403, f'无后台权限：{permission_name(permission_id)}')
    return user


def require_any_admin(user):
    if is_super_admin(user):
        return user
    ids = user_permission_ids(int(user['id'])) if user else set()
    if PERM_ADMIN_VIEW in ids:
        return user
    raise HTTPException(403, '无后台权限')


def require_super_admin(user):
    if not is_super_admin(user):
        raise HTTPException(403, '需要超级管理员权限')
    return user


def admin_user(user=None):
    # 兼容旧代码：只判断是否能进入后台。
    return require_any_admin(user)


def admin_permissions_public(user):
    super_flag = is_super_admin(user)
    # 服务器始终返回数据库里真实保存的权限 ID；不要把超级管理员展开成“虚拟全部ID”。
    ids = sorted(list(user_permission_ids(int(user['id'])))) if user else []
    return {
        'is_admin': bool(user and (int(user.get('permission') or 0) >= 1 or len(ids) > 0)),
        'is_super_admin': super_flag,
        'permission_ids': ids,
        'permission_names': [permission_name(i) for i in ids],
        'defs': [{'id': i, 'name': n, 'desc': d} for i, n, d in ADMIN_PERMISSION_DEFS],
    }
