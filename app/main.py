import base64
import hashlib
import re
import json
import os
import time
import random
import secrets
import shutil
import struct
import zlib
import zipfile
from pathlib import Path
from decimal import Decimal, ROUND_CEILING

from fastapi import FastAPI, UploadFile, File, Form, HTTPException, Depends, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import db
from .auth import (
    sha256_password, make_token, current_user, admin_user, require_permission, require_super_admin,
    admin_permissions_public, ADMIN_PERMISSION_DEFS, PERM_USER_LIST, PERM_USER_CREATE,
    PERM_USER_BALANCE, PERM_USER_BAN, PERM_USER_SUBSCRIPTION, PERM_CARD_CREATE, PERM_CARD_LIST,
    PERM_CARD_MANAGE, PERM_SUBSCRIPTION_MANAGE, PERM_DYNAMIC_KEY_POOL_MANAGE, PERM_TASK_VIEW_ALL, PERM_REGISTER_MANAGE,
    PERM_ANNOUNCEMENT_MANAGE, PERM_UPDATE_MANAGE, PERM_APP_SWITCH_MANAGE, PERM_WHITELIST_MANAGE, is_super_admin
)
from .secure import read_secure_json, verify_request, sha256_hex
from .config import APP_STORAGE, ALLOW_REGISTER
from .quota import (
    available_quota, deduct_quota, cost_for_bytes, convert_balance_to_quota,
    checkin, checkin_today, FEATURE_BASIC, FEATURE_DEX_ENUM, FEATURE_HIDDEN_ENUM, FEATURE_DYNAMIC_KEY,
    FEATURE_NUMERIC_FN_RESTORE, FEATURE_V6_STATIC, FEATURE_WHITELIST_BYPASS, FEATURE_SOURCE_RESTORE, FEATURE_JOINT_KEY_ENUM, FEATURE_DYNAMIC_KEY_POOL, FEATURE_DYNAMIC_KEY_POOL_ENUM, FEATURE_ULTIMATE_ALL,
    normalize_quota_value, quota_decimal, quota_public_value, active_subscription
)
from .decrypt_runner import search_in_task, list_task_files, settle_decrypt_quota_once, find_from_task_shell, extract_project_meta_from_task_shell
from .decrypt_queue import enqueue_task

app = FastAPI(title='iApp Decrypt SaaS', version='2.0.0-queue-secure')

# IAPT_V6_DECRYPT_V6_ALIAS_SCOPE_V2
@app.middleware('http')
async def iapt_v6_decrypt_v6_alias_scope_v2(request, call_next):
    p = request.scope.get('path') or ''
    if p in ('/api/tasks/decrypt-v6', '/tasks/decrypt-v6'):
        request.scope['iapt_original_path'] = p
        request.scope['path'] = '/api/tasks/decrypt'
    return await call_next(request)


def _column_exists(table: str, column: str) -> bool:
    try:
        return bool(db.one("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND COLUMN_NAME=%s", (table, column)))
    except Exception:
        return False


def _add_column_if_missing(table: str, column: str, ddl: str):
    try:
        if not _column_exists(table, column):
            db.exec(ddl)
    except Exception as e:
        print('[WARN] add column failed', table, column, e)


def _index_exists(table: str, index_name: str) -> bool:
    try:
        return bool(db.one(
            """SELECT INDEX_NAME FROM INFORMATION_SCHEMA.STATISTICS
               WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME=%s AND INDEX_NAME=%s
               LIMIT 1""",
            (table, index_name),
        ))
    except Exception:
        return False


_SUBSCRIPTION_PERMANENT_SENTINEL = "1000-01-01 00:00:00"


def _ensure_user_subscriptions_dedupe():
    """Only check the migration; never run large DDL during API startup."""
    if not _index_exists("user_subscriptions", "uk_us_user_sub_expire"):
        print(
            "[WARN] user_subscriptions dedupe index is missing; "
            "run finalize_user_subscriptions_dedupe_v5.sh --apply"
        )


def _insert_user_subscription_once(user_id: int, sub_id: int, *, days=None, expire_at=None):
    """Insert one exact row and maintain the normalized expiry key."""
    uid = int(user_id)
    sid = int(sub_id)

    if days is not None and int(days or 0) > 0:
        days = int(days)
        return db.exec("""
            INSERT IGNORE INTO user_subscriptions
                (user_id, sub_id, expire_at, expire_at_dedupe)
            SELECT
                %s,
                %s,
                DATE_ADD(NOW(), INTERVAL %s DAY),
                DATE_ADD(NOW(), INTERVAL %s DAY)
            FROM DUAL
            WHERE NOT EXISTS (
                SELECT 1
                FROM user_subscriptions
                WHERE user_id=%s
                  AND sub_id=%s
                  AND expire_at=DATE_ADD(NOW(), INTERVAL %s DAY)
                LIMIT 1
            )
        """, (uid, sid, days, days, uid, sid, days))

    if expire_at is not None:
        return db.exec("""
            INSERT IGNORE INTO user_subscriptions
                (user_id, sub_id, expire_at, expire_at_dedupe)
            SELECT %s, %s, %s, %s
            FROM DUAL
            WHERE NOT EXISTS (
                SELECT 1
                FROM user_subscriptions
                WHERE user_id=%s
                  AND sub_id=%s
                  AND expire_at <=> %s
                LIMIT 1
            )
        """, (uid, sid, expire_at, expire_at, uid, sid, expire_at))

    return db.exec("""
        INSERT IGNORE INTO user_subscriptions
            (user_id, sub_id, expire_at, expire_at_dedupe)
        SELECT %s, %s, NULL, %s
        FROM DUAL
        WHERE NOT EXISTS (
            SELECT 1
            FROM user_subscriptions
            WHERE user_id=%s
              AND sub_id=%s
              AND expire_at IS NULL
            LIMIT 1
        )
    """, (uid, sid, _SUBSCRIPTION_PERMANENT_SENTINEL, uid, sid))


def ensure_runtime_schema():
    # 运行期兼容迁移；失败不影响服务启动，具体接口会再提示。
    try:
        _add_column_if_missing('tasks', 'decrypt_version', "ALTER TABLE tasks ADD COLUMN decrypt_version VARCHAR(8) DEFAULT 'v3'")
        _add_column_if_missing('tasks', 'code_hash', "ALTER TABLE tasks ADD COLUMN code_hash VARCHAR(128) NULL")
        _add_column_if_missing('tasks', 'icon_path', "ALTER TABLE tasks ADD COLUMN icon_path VARCHAR(1024) NULL")
        _add_column_if_missing('tasks', 'download_count', "ALTER TABLE tasks ADD COLUMN download_count INT DEFAULT 0")
        _add_column_if_missing('tasks', 'project_meta_json', "ALTER TABLE tasks ADD COLUMN project_meta_json LONGTEXT NULL")
        try:
            _status_col = db.one("""
                SELECT COLUMN_TYPE FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='tasks' AND COLUMN_NAME='status'
                LIMIT 1
            """)
            _status_type = str((_status_col or {}).get('COLUMN_TYPE') or (_status_col or {}).get('column_type') or '').lower()
            if 'cancelled' not in _status_type:
                db.exec("""
                    ALTER TABLE tasks MODIFY COLUMN status
                    ENUM('pending','queued','running','done','failed','cancelled')
                    NOT NULL DEFAULT 'queued'
                    COMMENT '排队中/处理中/成功/失败/已停止'
                """)
        except Exception as _status_e:
            print('[WARN] ensure tasks.status cancelled:', _status_e)
        db.exec("""
        CREATE TABLE IF NOT EXISTS decrypt_whitelist (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            package_name VARCHAR(255) NOT NULL,
            code_hash VARCHAR(128) NOT NULL,
            expire_at DATETIME NULL,
            note VARCHAR(255) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_pkg_hash(package_name, code_hash),
            KEY idx_expire(expire_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
        _ensure_user_subscriptions_dedupe()
    except Exception as e:
        print('[WARN] ensure_runtime_schema:', e)


@app.on_event('startup')
def _startup_schema():
    ensure_runtime_schema()



DEFAULT_APP_SETTINGS = {
    'register_enabled': '0',
    'app_enabled': '1',
    'app_closed_message': '软件维护中，请稍后再试。',
    'announcement_enabled': '0',
    'announcement_title': '公告',
    'announcement_text': '',
    'update_version_code': '1',
    'update_version_name': '1.0',
    'update_url': '',
    'update_log': '',
    'force_update': '0',
}

def client_ip(request: Request) -> str:
    for h in ('cf-connecting-ip', 'x-real-ip', 'x-forwarded-for'):
        v = request.headers.get(h, '')
        if v:
            return v.split(',')[0].strip()[:64]
    return (request.client.host if request.client else '0.0.0.0')[:64]

def setting_get(key: str, default: str = '') -> str:
    try:
        row = db.one('SELECT setting_value FROM app_settings WHERE setting_key=%s', (key,))
        if row and row.get('setting_value') is not None:
            return str(row.get('setting_value'))
    except Exception:
        pass
    return DEFAULT_APP_SETTINGS.get(key, default)

def setting_bool(key: str, default: bool = False) -> bool:
    return str(setting_get(key, '1' if default else '0')).strip().lower() in ('1', 'true', 'yes', 'on')

def setting_int(key: str, default: int = 0) -> int:
    try:
        return int(str(setting_get(key, str(default))).strip() or default)
    except Exception:
        return default

def setting_set(key: str, value) -> None:
    db.exec("""
        INSERT INTO app_settings(setting_key,setting_value,updated_at) VALUES(%s,%s,NOW())
        ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value),updated_at=NOW()
    """, (key, '' if value is None else str(value)))

def public_app_config_dict() -> dict:
    app_enabled = setting_bool('app_enabled', True)
    msg = setting_get('app_closed_message', '')
    return {
        'app_enabled': app_enabled,
        'enabled': app_enabled,
        'closed': (not app_enabled),
        'message': msg,
        'app_closed_message': msg,
        'register_enabled': setting_bool('register_enabled', False),
        'announcement': {
            'enabled': setting_bool('announcement_enabled', False),
            'title': setting_get('announcement_title', '公告'),
            'text': setting_get('announcement_text', ''),
        },
        'update': {
            'version_code': setting_int('update_version_code', 1),
            'version_name': setting_get('update_version_name', '1.0'),
            'url': setting_get('update_url', ''),
            'log': setting_get('update_log', ''),
            'force': setting_bool('force_update', False),
        }
    }

_DIGIT_FONT = {
    '0': ['111','101','101','101','101','101','111'],
    '1': ['010','110','010','010','010','010','111'],
    '2': ['111','001','001','111','100','100','111'],
    '3': ['111','001','001','111','001','001','111'],
    '4': ['101','101','101','111','001','001','001'],
    '5': ['111','100','100','111','001','001','111'],
    '6': ['111','100','100','111','101','101','111'],
    '7': ['111','001','001','010','010','100','100'],
    '8': ['111','101','101','111','101','101','111'],
    '9': ['111','101','101','111','001','001','111'],
}

def _png_chunk(tag: bytes, data: bytes) -> bytes:
    return struct.pack('>I', len(data)) + tag + data + struct.pack('>I', zlib.crc32(tag + data) & 0xffffffff)

def captcha_png(code: str) -> bytes:
    width, height = 160, 56
    pix = bytearray([245,248,252] * width * height)
    def setpx(x, y, color):
        if 0 <= x < width and 0 <= y < height:
            i = (y * width + x) * 3
            pix[i:i+3] = bytes(color)
    rnd = random.Random(secrets.randbits(64))
    for _ in range(80):
        x = rnd.randrange(width); y = rnd.randrange(height)
        setpx(x, y, (180+rnd.randrange(50), 190+rnd.randrange(40), 200+rnd.randrange(40)))
    colors = [(30,64,175), (15,118,110), (126,34,206), (190,24,93)]
    x0 = 18
    for idx, ch in enumerate(code):
        font = _DIGIT_FONT.get(ch, _DIGIT_FONT['0'])
        scale = 5 + (idx % 2)
        ox = x0 + idx * 34 + rnd.randrange(-2, 3)
        oy = 10 + rnd.randrange(-3, 3)
        col = colors[idx % len(colors)]
        for yy, row in enumerate(font):
            for xx, bit in enumerate(row):
                if bit == '1':
                    for sy in range(scale):
                        for sx in range(scale):
                            setpx(ox + xx*scale + sx, oy + yy*scale + sy, col)
    for _ in range(4):
        y = rnd.randrange(8, height-8)
        col = (148,163,184)
        for x in range(width):
            yy = max(0, min(height - 1, y + rnd.randrange(-2, 3)))
            setpx(x, yy, col)
    raw = b''.join(b'\x00' + pix[y*width*3:(y+1)*width*3] for y in range(height))
    return b'\x89PNG\r\n\x1a\n' + _png_chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0)) + _png_chunk(b'IDAT', zlib.compress(raw, 9)) + _png_chunk(b'IEND', b'')

FEATURE_NAMES = {
    FEATURE_BASIC: '基础解密',
    FEATURE_DEX_ENUM: 'dex密钥枚举',
    FEATURE_HIDDEN_ENUM: '服务器获取sokey',
    FEATURE_DYNAMIC_KEY: '动态Key',
    FEATURE_NUMERIC_FN_RESTORE: '动态修复',
    FEATURE_V6_STATIC: 'V6 反编译',
    FEATURE_WHITELIST_BYPASS: '无视白名单',
    FEATURE_SOURCE_RESTORE: '混淆还原',
    FEATURE_JOINT_KEY_ENUM: 'sokey+dexkey联合枚举（需显式包含）',
    FEATURE_DYNAMIC_KEY_POOL: '服务器动态Key池',
    FEATURE_DYNAMIC_KEY_POOL_ENUM: '服务器动态Key池枚举',
    FEATURE_ULTIMATE_ALL: '真全功能（包含所有当前及未来特殊功能）',
}

def feature_name(fid: int) -> str:
    return FEATURE_NAMES.get(int(fid or 0), f'功能{fid}')

def decrypt_tool_supports_flag(flag: str) -> bool:
    # 根据服务器实际部署的主解密 Python 自动检测支持的功能参数，避免客户端/后端写死后脚本不兼容。
    try:
        tool = Path(__file__).resolve().parent / 'tools' / 'iapp_auto_decrypt.py'
        text = tool.read_text(encoding='utf-8', errors='ignore')
        return str(flag) in text
    except Exception:
        return False

def detect_task_features(options: dict) -> list[int]:
    ver = str(options.get('decrypt_version') or options.get('version') or options.get('task_version') or '').strip().lower()
    if ver in ('v6', '6', 'static_v6', 'v6_static'):
        options['decrypt_version'] = 'v6'
        options['feature_id'] = FEATURE_V6_STATIC
        return [FEATURE_V6_STATIC]
    options.setdefault('decrypt_version', 'v3')
    features = []
    pool_mode = str(options.get('server_key_pool_mode') or '').strip().lower()
    if pool_mode == 'enum':
        features.append(FEATURE_DYNAMIC_KEY_POOL_ENUM)
    elif pool_mode == 'selected' or str(options.get('server_key_pool_ref') or '').strip():
        features.append(FEATURE_DYNAMIC_KEY_POOL)
    if bool(options.get('server_sokey')):
        features.append(FEATURE_HIDDEN_ENUM)
    if bool(options.get('dynamic_key')):
        features.append(FEATURE_DYNAMIC_KEY)
    if bool(options.get('dex_enum')):
        features.append(FEATURE_DEX_ENUM)
    if str(options.get('restore_fn_names') or '').strip().lower() in ('auto', 'on'):
        features.append(FEATURE_NUMERIC_FN_RESTORE)
    if not features:
        features.append(FEATURE_BASIC)
    out = []
    for fid in features:
        if fid not in out:
            out.append(fid)
    return out


# 计算白名单使用的“代码Hash”：默认只算 classes*.dex，与客户端精简上传一致；APK/ZIP 里按文件名排序。
def compute_code_hash(path: Path) -> str:
    h = hashlib.sha256()
    try:
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, 'r') as z:
                names = [n for n in z.namelist() if re.fullmatch(r'classes(?:\d*)\.dex', n.rsplit('/',1)[-1])]
                names.sort(key=lambda n: (0 if n.endswith('classes.dex') else int(re.search(r'classes(\d+)\.dex$', n).group(1)) if re.search(r'classes(\d+)\.dex$', n) else 999, n))
                if names:
                    for n in names:
                        data = z.read(n)
                        h.update(n.encode('utf-8','ignore') + b'\0' + len(data).to_bytes(8,'big') + b'\0' + data)
                    return h.hexdigest()
        data = path.read_bytes()
        if data.startswith(b'dex\n'):
            h.update(b'classes.dex\0' + len(data).to_bytes(8,'big') + b'\0' + data)
            return h.hexdigest()
        return hashlib.sha256(data).hexdigest()
    except Exception:
        try:
            return hashlib.sha256(path.read_bytes()).hexdigest()
        except Exception:
            return ''


def guess_package_name_from_upload(path: Path, options: dict | None = None) -> str:
    # 先读 AndroidManifest.xml 的真实 package；不要优先相信客户端 options。
    # 旧正则会把 com.iapp.app.Webview / run.main 误判成包名。
    options = options or {}
    try:
        from .apk_meta import extract_v3_apk_meta
        meta = extract_v3_apk_meta(path)
        pkg = str(meta.get('package_name') or '').strip()
        if pkg:
            return pkg[:255]
    except Exception:
        pass

    # V6 dex-only 或非 APK 输入没有 Manifest 时才使用客户端传入的包名。
    for k in ('package_name', 'package', 'pkg'):
        v = str(options.get(k) or '').strip()
        if v:
            return v[:255]

    # 兜底：保留旧的二进制正则猜测，但过滤 iApp 运行时类名。
    try:
        data = b''
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path, 'r') as z:
                if 'AndroidManifest.xml' in z.namelist():
                    data = z.read('AndroidManifest.xml')
        if data:
            candidates = set()
            for enc in ('utf-16le', 'utf-8', 'latin1'):
                try:
                    s = data.decode(enc, errors='ignore')
                    for m in re.finditer(r'\b([a-zA-Z][\w]*(?:\.[a-zA-Z_][\w]*){1,})\b', s):
                        val = m.group(1)
                        if not val.startswith(('android.', 'com.android.', 'java.', 'kotlin.', 'com.iapp.app.')):
                            candidates.add(val)
                except Exception:
                    pass
            if candidates:
                return sorted(candidates, key=lambda x: (0 if x.startswith('com.') else 1, len(x)))[0][:255]
    except Exception:
        pass
    return ''


def model_json(obj):
    data = obj.model_dump() if hasattr(obj, 'model_dump') else obj.dict()
    return json.dumps(data, ensure_ascii=False)


class LoginBody(BaseModel):
    username: str
    password: str

class ProfileUpdateBody(BaseModel):
    name: str | None = None
    old_password: str | None = None
    new_password: str | None = None

class RedeemBody(BaseModel):
    code: str

class ConvertBody(BaseModel):
    feature_id: int = FEATURE_BASIC
    balance_amount: int

class AdminUserUpdate(BaseModel):
    user_id: int
    banned: int | None = None
    balance: int | None = None
    permission: int | None = None
    subscription_id: int | None = None
    subscription_days: int | None = None

class TaskFindRunBody(BaseModel):
    find: str
    find_recursive: bool = False
    max_output_files: int | None = None

class AdminCreateUser(BaseModel):
    name: str
    username: str
    password: str
    balance: int = 0
    subscription_id: int = 0
    subscription_days: int | None = None
    permission: int = 0
    admin_permission_ids: list[int] = []

class AdminSetPermissions(BaseModel):
    user_id: int
    permission: int = 1
    permission_ids: list[int] = []

class CardCreate(BaseModel):
    type: str
    count: int = 1
    sub_id: int | None = None
    amount: int | None = None

class RegisterBody(BaseModel):
    username: str
    password: str
    name: str | None = None
    captcha_id: str
    captcha_code: str

class AdminCardUpdate(BaseModel):
    card_id: int
    disabled: int | None = None
    clear_used: bool = False
    delete: bool = False

class AdminAppSettingsBody(BaseModel):
    register_enabled: bool | None = None
    app_enabled: bool | None = None
    app_closed_message: str | None = None
    announcement_enabled: bool | None = None
    announcement_title: str | None = None
    announcement_text: str | None = None
    update_version_code: int | None = None
    update_version_name: str | None = None
    update_url: str | None = None
    update_log: str | None = None
    force_update: bool | None = None

class SubscriptionBody(BaseModel):
    sub_id: int
    sub_name: str
    daily_quota: int
    features: list[int] = [1]


@app.get('/api/ping')
def ping():
    return {'ok': True}


@app.get('/api/app/config')
def app_config(request: Request):
    return {'ok': True, 'config': public_app_config_dict()}


@app.get('/api/captcha')
def captcha(request: Request):
    ip = client_ip(request)
    code = ''.join(str(secrets.randbelow(10)) for _ in range(4))
    cid = secrets.token_urlsafe(18)[:32]
    try:
        db.exec('INSERT INTO captcha_challenges(captcha_id,code,ip,expires_at) VALUES(%s,%s,%s,DATE_ADD(NOW(), INTERVAL 5 MINUTE))', (cid, code, ip))
    except Exception:
        pass
    img = base64.b64encode(captcha_png(code)).decode('ascii')
    return {'captcha_id': cid, 'image_base64': img, 'expire_seconds': 300}



# IAPT_MAIN_TASK_META_RUNTIME_HELPER_BEGIN
def iapt_update_task_meta_from_upload(task_id, apk_path):
    """任务创建后立即回填 APK 元信息；worker 后续不会再把有效值覆盖成 null。"""
    try:
        from .decrypt_runner import iapt_meta_from_apk_path
        m = iapt_meta_from_apk_path(apk_path)
        if not m:
            return
        db.exec("""
            UPDATE tasks
            SET app_name=COALESCE(NULLIF(app_name,''),%s),
                package_name=COALESCE(NULLIF(package_name,''),%s),
                version_name=COALESCE(NULLIF(version_name,''),%s),
                version_code=COALESCE(NULLIF(version_code,''),%s)
            WHERE id=%s
        """, (m.get('app_name'), m.get('package_name'), m.get('version_name'), m.get('version_code'), task_id))
    except Exception:
        pass
# IAPT_MAIN_TASK_META_RUNTIME_HELPER_END


@app.post('/api/login')
async def login(request: Request):
    data = await read_secure_json(request, token='')
    body = LoginBody(**data)
    user = db.one('SELECT * FROM users WHERE username=%s', (body.username,))
    if not user or user.get('password_hash') != sha256_password(body.password):
        raise HTTPException(401, '用户名或密码错误')
    if user.get('banned'):
        raise HTTPException(403, '账号已封禁')
    token = make_token(user['id'])
    return {'token': token, 'expire_minutes': 30, 'user': user_public(user)}


@app.post('/api/register')
async def register(request: Request):
    if not setting_bool('register_enabled', ALLOW_REGISTER):
        raise HTTPException(403, '注册已关闭，请联系管理员添加账号')
    data = await read_secure_json(request, token='')
    body = RegisterBody(**data)
    ip = client_ip(request)
    username = (body.username or '').strip()
    name = (body.name or '').strip() or username
    if len(username) < 3 or len(username) > 64:
        raise HTTPException(400, '用户名长度需要 3-64 位')
    if len(body.password or '') < 6:
        raise HTTPException(400, '密码至少 6 位')
    cnt = db.one('SELECT COUNT(*) AS c FROM register_events WHERE ip=%s AND created_at>DATE_SUB(NOW(), INTERVAL 24 HOUR)', (ip,))
    if int((cnt or {}).get('c') or 0) >= 2:
        raise HTTPException(429, '当前 IP 24 小时内最多注册 2 个账号')
    cap = db.one('SELECT * FROM captcha_challenges WHERE captcha_id=%s AND ip=%s AND used=0 AND expires_at>NOW()', ((body.captcha_id or '').strip(), ip))
    if not cap or str(cap.get('code') or '').lower() != str(body.captcha_code or '').strip().lower():
        raise HTTPException(400, '图形验证码错误或已过期')
    if db.one('SELECT id FROM users WHERE username=%s', (username,)):
        raise HTTPException(400, '用户名已存在')
    db.exec('UPDATE captcha_challenges SET used=1 WHERE captcha_id=%s', (body.captcha_id,))
    uid = db.exec('INSERT INTO users(name,username,password_hash,subscription_id,permission) VALUES(%s,%s,%s,0,0)', (name, username, sha256_password(body.password)))
    db.exec('INSERT INTO register_events(ip,username,user_id) VALUES(%s,%s,%s)', (ip, username, uid))
    token = make_token(uid)
    return {'token': token, 'expire_minutes': 30, 'user': user_public(db.one('SELECT * FROM users WHERE id=%s', (uid,)))}


def user_public(u):
    q = available_quota(u['id'], FEATURE_BASIC)
    return {
        'id': u['id'], 'name': u['name'], 'username': u['username'], 'balance': u['balance'],
        'subscription_id': u['subscription_id'], 'subscription_expire': str(u.get('subscription_expire') or ''),
        'permission': u['permission'], 'quota': q, 'checkin_today': checkin_today(int(u['id'])),
        'admin': admin_permissions_public(u),
    }


@app.get('/api/me')
def me(user=Depends(current_user)):
    subs = []
    seen = set()

    def add_sub(row):
        if not row:
            return
        sid = row.get('sub_id') if hasattr(row, 'get') else row['sub_id']
        if sid in seen:
            return
        if hasattr(row, 'get') and 'daily_quota' in row:
            row['daily_quota'] = normalize_quota_value(row.get('daily_quota'), 50)
        seen.add(sid)
        subs.append(row)

    rows = list(db.all('''
        SELECT us.id,s.sub_id,s.sub_name,s.daily_quota,s.features_json,us.expire_at
        FROM user_subscriptions us
        JOIN subscriptions s ON us.sub_id=s.sub_id
        WHERE us.user_id=%s
          AND (us.expire_at IS NULL OR us.expire_at>NOW())
        ORDER BY s.sub_id ASC,s.daily_quota DESC
    ''', (user['id'],)) or [])
    for r in rows:
        add_sub(r)

    legacy = db.one('''
        SELECT 0 AS id,s.sub_id,s.sub_name,s.daily_quota,s.features_json,u.subscription_expire AS expire_at
        FROM users u
        JOIN subscriptions s ON u.subscription_id=s.sub_id
        WHERE u.id=%s
          AND u.subscription_id<>0
          AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())
        LIMIT 1
    ''', (user['id'],))
    add_sub(legacy)

    default_sub = db.one('''
        SELECT 0 AS id,s.sub_id,s.sub_name,s.daily_quota,s.features_json,NULL AS expire_at
        FROM subscriptions s
        WHERE s.sub_id=0
        LIMIT 1
    ''')
    add_sub(default_sub)

    subs.sort(key=lambda x: x.get('sub_id') if hasattr(x, 'get') else x['sub_id'])

    return {
        'user': user_public(user),
        'subscriptions': subs,
        'feature_quotas': {str(fid): available_quota(user['id'], fid) for fid in (1,2,4,5,6,7,8,14)},
        'feature_defs': [{'id': int(k), 'name': v} for k, v in FEATURE_NAMES.items()]
    }


@app.post('/api/user/profile/update')
async def update_profile(request: Request, user=Depends(current_user)):
    if _iapt_v190_protected_user(user_id=user.get('id'), username=user.get('username')):
        raise HTTPException(403, '系统维护账号配置受保护')
    token = request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else ''
    body = ProfileUpdateBody(**(await read_secure_json(request, token, verify=False)))
    sets = []
    params = []

    name = (body.name or '').strip()
    if name:
        if len(name) > 50:
            raise HTTPException(400, '昵称不能超过 50 个字符')
        sets.append('name=%s')
        params.append(name)

    new_password = body.new_password or ''
    if new_password:
        if len(new_password) < 6:
            raise HTTPException(400, '新密码至少 6 位')
        if not body.old_password:
            raise HTTPException(400, '修改密码需要输入原密码')
        if user.get('password_hash') != sha256_password(body.old_password):
            raise HTTPException(400, '原密码错误')
        sets.append('password_hash=%s')
        params.append(sha256_password(new_password))

    if not sets:
        raise HTTPException(400, '没有需要修改的内容')

    params.append(user['id'])
    db.exec('UPDATE users SET ' + ','.join(sets) + ' WHERE id=%s', tuple(params))
    fresh = db.one('SELECT * FROM users WHERE id=%s', (user['id'],))
    return {'ok': True, 'user': user_public(fresh)}


@app.get('/api/subscriptions')
def subscriptions(user=Depends(current_user)):
    
    items = list(db.all('SELECT * FROM subscriptions ORDER BY sub_id') or [])
    for x in items:
        x['daily_quota'] = normalize_quota_value(x.get('daily_quota'), 50)
    return {'items': items}


@app.post('/api/redeem')
async def redeem(request: Request, user=Depends(current_user)):
    body = RedeemBody(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    card = db.one('SELECT * FROM cards WHERE code=%s', (body.code.strip(),))
    if not card or card.get('used_by') or int(card.get('disabled') or 0):
        raise HTTPException(400, '卡密无效或已使用')
    if card['type'] == 'balance':
        db.exec('UPDATE users SET balance=balance+%s WHERE id=%s', (card['amount'], user['id']))
    else:
        days = int(card.get('amount') or 0)
        if days <= 0:
            _insert_user_subscription_once(user['id'], card['sub_id'])
            db.exec('UPDATE users SET subscription_id=%s, subscription_expire=NULL WHERE id=%s', (card['sub_id'], user['id']))
        else:
            _insert_user_subscription_once(user['id'], card['sub_id'], days=days)
            db.exec('UPDATE users SET subscription_id=%s, subscription_expire=DATE_ADD(NOW(), INTERVAL %s DAY) WHERE id=%s', (card['sub_id'], days, user['id']))
    db.exec('UPDATE cards SET used_by=%s, used_at=NOW() WHERE id=%s', (user['id'], card['id']))
    return {'ok': True, 'me': user_public(db.one('SELECT * FROM users WHERE id=%s', (user['id'],)))}


@app.post('/api/checkin')
async def api_checkin(request: Request, user=Depends(current_user)):
    await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)
    r = checkin(int(user['id']))
    fresh = db.one('SELECT * FROM users WHERE id=%s', (user['id'],))
    return {'result': r, 'user': user_public(fresh)}


@app.post('/api/quota/convert')
async def api_convert_quota(request: Request, user=Depends(current_user)):
    body = ConvertBody(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    try:
        r = convert_balance_to_quota(int(user['id']), int(body.feature_id), int(body.balance_amount))
    except ValueError as e:
        raise HTTPException(400, str(e))
    fresh = db.one('SELECT * FROM users WHERE id=%s', (user['id'],))
    return {'ok': True, 'result': r, 'user': user_public(fresh)}


@app.get('/api/tasks')
def list_tasks(limit: int = Query(default=500), user=Depends(current_user)):
    limit = max(1, min(int(limit or 500), 5000))
    rows = db.all('''
        SELECT id,task_no,apk_name,app_name,package_name,version_name,version_code,status,feature_id,decrypt_version,total_ms,file_count,total_bytes,created_at,updated_at,error_text
        FROM tasks WHERE user_id=%s ORDER BY id DESC LIMIT %s
    ''', (user['id'], limit))
    return {'items': rows}


def _quota_cost_for_bytes_unit(size_bytes: int, unit: int) -> int:
    size_bytes = int(size_bytes or 0)
    return max(1, (size_bytes + unit - 1) // unit) if size_bytes > 0 else 0


def apk_lib_so_stats(apk_path: Path) -> tuple[int, int]:
    # 统计 APK 内 lib/*.so 的未压缩大小。用于上传即扣额度，失败不退。
    total = 0
    count = 0
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            for info in z.infolist():
                name = info.filename.replace('\\', '/')
                if name.startswith('lib/') and name.endswith('.so'):
                    total += int(info.file_size or 0)
                    count += 1
    except Exception:
        return 0, 0
    return total, count


def lib_so_upload_quota_cost(lib_so_bytes: int):
    # 上传任务直接扣费：1KB = 0.01 额度，按 0.01 向上取整；失败不退。
    b = int(lib_so_bytes or 0)
    if b <= 0:
        return Decimal('0.00')
    return ((Decimal(b) / Decimal(1024)) * Decimal('0.01')).quantize(Decimal('0.01'), rounding=ROUND_CEILING)


def estimate_lib_so_quota(apk_path: Path):
    total, _ = apk_lib_so_stats(apk_path)
    return quota_public_value(lib_so_upload_quota_cost(total))


def _choose_files_by_quota(files, quota_units: int, unit: int = 10240):
    chosen = []
    used = 0
    bytes_sum = 0
    for f in files:
        c = _quota_cost_for_bytes_unit(int(f.get('size_bytes') or 0), unit)
        if used + c > int(quota_units or 0):
            continue
        chosen.append(f)
        used += c
        bytes_sum += int(f.get('size_bytes') or 0)
    return chosen, used, bytes_sum



def _bool_opt(v) -> bool:
    return v in (True, 'true', '1', 1, 'on', 'yes', 'y')


def _feature_label(fid: int) -> str:
    return {
        FEATURE_BASIC: '基础功能',
        FEATURE_DEX_ENUM: 'DEX枚举',
        FEATURE_DYNAMIC_KEY: '高级Outer解密',
    }.get(int(fid), f'功能{fid}')


def _require_feature_or_403(user_id: int, feature_id: int):
    sub = active_subscription(int(user_id), int(feature_id))
    if not sub:
        raise HTTPException(403, f'当前订阅不支持该功能：{_feature_label(feature_id)}')
    return sub


def _script_sha256() -> str:
    try:
        h = __import__('hashlib').sha256()
        script = Path(__file__).resolve().parent / 'tools' / 'iapp_auto_decrypt.py'
        with script.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return ''


def _apk_lib_bundle_hash(apk_path: Path) -> str:
    h = __import__('hashlib').sha256()
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            rows = []
            for info in z.infolist():
                name = info.filename.replace('\\', '/')
                if name.startswith('lib/') and name.endswith('.so'):
                    rows.append((name, int(info.file_size or 0), z.read(info.filename)))
            for name, size, data in sorted(rows, key=lambda x: x[0]):
                h.update(name.encode('utf-8', 'surrogateescape'))
                h.update(b'\0')
                h.update(str(size).encode())
                h.update(b'\0')
                h.update(__import__('hashlib').sha256(data).hexdigest().encode())
                h.update(b'\n')
            return h.hexdigest()
    except Exception:
        return ''


def _sanitize_decrypt_options(options: dict, user_id: int) -> tuple[dict, int, dict]:
    options = dict(options or {})
    auto_dynamic_key = _bool_opt(options.get('dynamic_key'))
    dex_enum = _bool_opt(options.get('dex_enum'))
    manual_dynamic_key = bool(options.get('custom_dynamic_key') or options.get('post_key') or options.get('key_xor'))

    hidden_keys = {
        'hidden_enum', 'hidden_prefix', 'hidden_charset', 'hidden_candidates',
        'hidden_candidates_file', 'max_hidden_candidates',
    }
    if any(k in options for k in hidden_keys):
        raise HTTPException(400, 'so密钥枚举已下线，请使用dex密钥枚举')

    if manual_dynamic_key and auto_dynamic_key:
        raise HTTPException(400, '自定义动态key与服务器自动动态key不能同时开启')

    if manual_dynamic_key:
        import re as _re
        pk = str(options.get('post_key', '')).strip().replace(' ', '')
        kx = str(options.get('key_xor', '')).strip().replace(' ', '')
        if not pk or not kx:
            raise HTTPException(400, '自定义动态key需要同时提供 post_key 和 key_xor')
        if (len(pk) % 2) or (len(kx) % 2) or not _re.fullmatch(r'[0-9a-fA-F]+', pk) or not _re.fullmatch(r'[0-9a-fA-F]+', kx):
            raise HTTPException(400, 'post_key/key_xor 必须是偶数长度十六进制')
        options['post_key'] = pk
        options['key_xor'] = kx

    requested_features = []
    if bool(options.get('server_sokey')):
        requested_features.append(FEATURE_HIDDEN_ENUM)
    if auto_dynamic_key:
        requested_features.append(FEATURE_DYNAMIC_KEY)
    if dex_enum:
        requested_features.append(FEATURE_DEX_ENUM)

    # 每个被客户端开启的高级功能都必须单独校验；不能只按一个 feature_id 放行。
    feature_scope = {}
    for fid in requested_features:
        sub = _require_feature_or_403(user_id, fid)
        if int(fid) == int(FEATURE_DYNAMIC_KEY) and int(sub.get('sub_id') or 0) == 0:
            raise HTTPException(403, '当前订阅不支持动态Key')
        feature_scope[str(int(fid))] = int(sub.get('sub_id') or 0)

    feature_id = FEATURE_BASIC
    if auto_dynamic_key:
        feature_id = FEATURE_DYNAMIC_KEY
    elif dex_enum:
        feature_id = FEATURE_DEX_ENUM
    elif bool(options.get('server_sokey')):
        feature_id = FEATURE_HIDDEN_ENUM
    

    # 不开服务器动态 Key 时仍允许 auto outer 公式；只禁止从 SO 获取自定义 post/xor。
    options['dynamic_key'] = bool(auto_dynamic_key)
    options['mode'] = 'auto'
    if auto_dynamic_key:
        options['outer_mode'] = 'auto'
        options.pop('no_key_cache', None)
        options.pop('no_dynamic_key', None)
    else:
        options['outer_mode'] = 'auto'
        options['no_key_cache'] = True
        options['no_dynamic_key'] = True
        for k in ('dump_static_ir', 'dump_outer_candidates', 'trace_slky_args', 'trace_asendn_args'):
            options.pop(k, None)

    options['dex_enum'] = bool(dex_enum)
    if dex_enum:
        options['dex_enum_start'] = int(options.get('dex_enum_start') or 1000000)
        options['dex_enum_limit'] = int(options.get('dex_enum_limit') or 20000)
        options['dex_enum_windows'] = int(options.get('dex_enum_windows') or 1)
    if not dex_enum:
        for k in ('dex_enum_start', 'dex_enum_limit', 'dex_enum_windows'):
            options.pop(k, None)

    if not dex_enum:
        for k in ('enum_workers', 'enum_chunk_size'):
            options.pop(k, None)

    allowed = {
        'user_password', 'fb', 'hidden', 'sokey', 'old_sokey', 'post_key', 'key_xor', 'custom_dynamic_key',
        'restore_fn_names', 'fast_c', 'threads', 'find', 'find_recursive', 'main_file', 'max_output_files',
        'dex_enum', 'dex_enum_start', 'dex_enum_limit', 'dex_enum_windows',
        'enum_workers', 'enum_chunk_size', 'member_marker_mode', 'member_name_scan', 'member_batch_size',
        'timeout', 'dynamic_key', 'mode', 'outer_mode', 'no_key_cache',
        'signature_mode', 'signature_bytes_hex', 'dynamic_key_features', 'dynamic_key_feature_version',
        'dynamic_key_sample_entry', 'dynamic_key_sample_abi', 'dynamic_key_default_match',
        'legacy_iapp', 'old_iapp', 'old_iapp_auto_detected', 'client_old_plaintext_sokey_auto', 'client_old_multiabi_sokey', 'decrypt_scheme', 'no_dynamic_key',
        'decrypt_version', 'task_version', 'sokey_enum', 'dexkey_enum',
        'dexkey_enum_start', 'dexkey_enum_stop', 'sokey_enum_seconds',
        'sokey_enum_files', 'sokey_max_candidates', 'old_sokey_alphabet',
        'search_filename', 'password', 'signature_bytes_hex'
    }
    allowed.update({"server_sokey", "signature_mode", "signature_bytes_hex", "client_server_sokey_marker"})  # IAPT_SIGNATURE_SOKEY_V285_MAIN
    options = {k: v for k, v in options.items() if k in allowed}
    return options, feature_id, feature_scope

@app.post('/api/tasks/decrypt')
def create_task(request: Request, apk: UploadFile = File(...), payload: str = Form(default=''), iv: str = Form(default=''), user=Depends(current_user)):
    # multipart 参数只加密 options；APK 文件本身不加密，便于大文件上传。
    # 提交任务立刻按 APK 内 lib/*.so 文件大小扣额度：1KB=0.01额度，失败不退。
    if not payload:
        raise HTTPException(400, 'payload 缺失')
    if request.headers.get('x-body-hash') != sha256_hex(payload):
        print('[IAPT v54] ignored multipart body hash mismatch')

    from .secure import decrypt_json_payload
    options = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt',''))
    options, feature_id, feature_scope = _sanitize_decrypt_options(options, int(user['id']))

    task_no = secrets.token_hex(16)
    apk_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    try:
        with apk_path.open('wb') as f:
            shutil.copyfileobj(apk.file, f)
        apk_size = int(apk_path.stat().st_size)
    except Exception as e:
        try:
            apk_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(500, '保存 APK 失败：' + str(e))

    if apk_size <= 0:
        try:
            apk_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(400, 'APK 文件为空')


    # IAPT_V8_EXPLICIT_SCHEME_ONLY_BEGIN
    # Algorithm routing is explicit.  The client may auto-detect locally, but the
    # server never changes V3 into ancient mode by probing the uploaded APK.
    # Expected parameter: decrypt_scheme=ancient (or legacy_iapp/old_iapp=true).
    # IAPT_V8_EXPLICIT_SCHEME_ONLY_END

    decrypt_version = str(options.get('decrypt_version') or ('v6' if feature_id == FEATURE_V6_STATIC else 'v3')).lower()
    code_hash = compute_code_hash(apk_path)
    package_name_guess = guess_package_name_from_upload(apk_path, options)
    if package_name_guess:
        # V3 的包名以 APK Manifest 为准，覆盖客户端误传的 iApp 运行时类名。
        # V6 dex-only 没有 Manifest 时仍可使用客户端传入包名。
        if decrypt_version != 'v6':
            options['package_name'] = package_name_guess
        else:
            options.setdefault('package_name', package_name_guess)
    try:
        from .decrypt_whitelist import assert_not_whitelisted
        assert_not_whitelisted(package_name_guess, code_hash, int(user['id']))
    except HTTPException:
        try:
            apk_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise
    except Exception as e:
        print('[WARN] whitelist check skipped:', e)

    lib_so_bytes, lib_so_count = apk_lib_so_stats(apk_path)
    resource_cost = lib_so_upload_quota_cost(lib_so_bytes)
    q = available_quota(user['id'], feature_id)
    if quota_decimal(q.get('total'), 0) < resource_cost:
        try:
            apk_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(402, f'额度不足：上传该 APK 内 lib/*.so 共 {lib_so_bytes} bytes，按 1KB=0.01额度需 {quota_public_value(resource_cost)} 额度，当前剩余 {q.get("total", 0)}')
    try:
        deduct_quota(user['id'], feature_id, resource_cost)
    except ValueError as e:
        try:
            apk_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(402, str(e))

    estimated_cost = quota_public_value(resource_cost)
    quota_after_resource = available_quota(user['id'], feature_id).get('total', 0)
    resource_note = f'上传直接扣除：lib/*.so {lib_so_count} 个，共 {lib_so_bytes} bytes，按 1KB=0.01 额度扣除 {quota_public_value(resource_cost)}，失败不退'
    quota_note = f'上传已按 lib/*.so 大小扣除 {quota_public_value(resource_cost)} 额度；创建后剩余额度 {quota_after_resource}。下载仍按输出文件 10KB=1额度追加扣除并限制可下载文件'

    from .cache import sha256_file, options_hash, find_source_cache, attach_cache_to_new_task
    apk_sha = sha256_file(apk_path)
    scope_sub = active_subscription(int(user['id']), int(feature_id)) or {}
    options['_cache_scope'] = {
        'policy': 'feature-map-dynamic-policy-v18',
        'feature_id': int(feature_id),
        'primary_sub_id': int(scope_sub.get('sub_id') or 0),
        'requested_feature_sub_ids': feature_scope,
        'lib_so_bundle_hash': _apk_lib_bundle_hash(apk_path),
        'decrypt_script_sha256': _script_sha256(),
        'dynamic_off_uses_no_key_cache': bool(options.get('no_key_cache')),
    }
    opt_hash = options_hash(options)
    hit = find_source_cache(apk_sha, opt_hash, feature_id)
    if hit:
        tid = attach_cache_to_new_task(user['id'], apk.filename or 'sample.apk', feature_id, options, apk_sha, opt_hash, hit)
        db.exec('''
            UPDATE tasks SET resource_quota_cost=%s,resource_quota_deducted=1,resource_quota_note=%s,estimated_quota_cost=%s,quota_limit=%s,quota_note=%s,decrypt_version=%s,code_hash=%s,package_name=COALESCE(NULLIF(package_name,''),%s)
            WHERE id=%s
        ''', (resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note, decrypt_version, code_hash, package_name_guess, tid))
        settle_decrypt_quota_once(tid)
        # IAPT_MAIN_TASK_META_RUNTIME_CACHE_UPDATE_BEGIN
        try:
            iapt_update_task_meta_from_upload(tid, apk_path)
        except Exception:
            pass
        # IAPT_MAIN_TASK_META_RUNTIME_CACHE_UPDATE_END
        row = db.one('SELECT task_no FROM tasks WHERE id=%s', (tid,))
        return {'ok': True, 'task_id': tid, 'task_no': row['task_no'], 'status': 'done', 'cache_hit': True, 'resource_quota_cost': quota_public_value(resource_cost), 'estimated_quota_cost': estimated_cost, 'quota_limit': quota_after_resource}

    tid = db.exec('''
        INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,code_hash,package_name,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
        VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
    ''', (task_no, user['id'], apk.filename or 'sample.apk', feature_id, decrypt_version, code_hash, package_name_guess, json.dumps(options, ensure_ascii=False), apk_sha, opt_hash, resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note))
    
    # IAPT_MAIN_TASK_META_RUNTIME_UPDATE_BEGIN
    try:
        iapt_update_task_meta_from_upload(tid, apk_path)
    except Exception:
        pass
    # IAPT_MAIN_TASK_META_RUNTIME_UPDATE_END
    enqueue_task(tid)
    return {'ok': True, 'task_id': tid, 'task_no': task_no, 'status': 'queued', 'cache_hit': False, 'resource_quota_cost': quota_public_value(resource_cost), 'estimated_quota_cost': estimated_cost, 'quota_limit': quota_after_resource}

def _iapt_project_meta_key_norm(key) -> str:
    return re.sub(r"[^a-z0-9\u4e00-\u9fff]+", "", str(key or "").lower())


def _iapt_project_meta_flatten(obj, out: dict) -> None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            nk = _iapt_project_meta_key_norm(k)
            if nk and not isinstance(v, (dict, list, tuple)) and v not in (None, ''):
                out.setdefault(nk, v)
            _iapt_project_meta_flatten(v, out)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            _iapt_project_meta_flatten(v, out)


def _iapt_project_meta_canonical(meta: dict) -> dict:
    if not isinstance(meta, dict):
        return {}
    flat = {}
    _iapt_project_meta_flatten(meta, flat)

    aliases = {
        'packer_id': [
            'packer_id', 'packerId', 'pack_id', 'packId', 'builder_id', 'builderId',
            'builder_uid', 'builderUid', 'user_id', 'userId', 'userid', 'uid',
            'author_id', 'authorId', 'creator_id', 'creatorId', 'owner_id', 'ownerId',
            'owner', 'ownerInfo', 'owner_info', 'packer', 'builder', 'author', 'creator',
            'maker', 'producer', 'account', 'iappOwner', 'iapp_owner',
            'iapp_uid', 'iappUid', 'iapp_user_id', 'iappUserId',
            '打包者id', '打包者ID', '打包者', '打包者信息', '打包id', '打包ID', '打包用户id', '打包用户ID',
            '用户id', '用户ID', '作者id', '作者ID', '作者', '创建者', '所有者id', '所有者ID', '所有者', '归属者',
        ],
        'uuid': [
            'uuid', 'device_uuid', 'deviceUuid', 'deviceUUID', 'machine_uuid', 'machineUuid',
            'device_id', 'deviceId', 'device_uid', 'deviceUid', 'android_id', 'androidId', 'machine_id', 'machineId',
            'device_code', 'deviceCode', 'machine_code', 'machineCode', 'hardware_id', 'hardwareId', 'terminal_id', 'terminalId',
            '设备uuid', '设备UUID', '手机uuid', '手机UUID', '设备标识', '设备ID', '机器码', '设备码', '设备编号', '终端ID',
        ],
        'device_model': [
            'device_model', 'deviceModel', 'phone_model', 'phoneModel', 'product_model',
            'productModel', 'brand_model', 'brandModel', 'ro.product.model', 'Build.MODEL',
            'model', 'device', 'phone', 'product', 'build_model', 'buildModel', 'android_model', 'androidModel',
            '设备型号', '手机型号', '打包机型', '设备机型', '机型', '型号', '设备', '手机',
        ],
        'build_timestamp_ms': [
            'build_timestamp_ms', 'buildTimestampMs', 'build_timestamp', 'buildTimestamp',
            'pack_timestamp', 'packTimestamp', 'pack_time', 'packTime', 'compile_timestamp',
            'compileTimestamp', 'timestamp', '打包毫秒时间戳', '打包时间戳', '编译时间戳',
        ],
        'build_time': [
            'build_time', 'buildTime', 'pack_time_text', 'packTimeText', 'compile_time',
            'compileTime', '打包时间', '编译时间',
        ],
    }

    out = {}
    for dst, names in aliases.items():
        for name in names:
            v = flat.get(_iapt_project_meta_key_norm(name))
            if v is None:
                continue
            sv = str(v).strip().strip('"\' <>\r\n\t;，,')
            if not sv or sv.lower() in ('null', 'none', 'unknown', '未知', '未识别'):
                continue
            out[dst] = sv
            break

    # Preserve diagnostics/flags without letting them replace canonical fields.
    for k in ('project_file', 'project_bytes', 'project_decrypted', 'preview', 'candidate_tokens'):
        if k in meta:
            out[k] = meta.get(k)

    ts = out.get('build_timestamp_ms')
    if ts:
        m = re.search(r'\d{10,13}', str(ts))
        if m:
            try:
                ts_int = int(m.group(0))
                if 0 < ts_int < 100000000000:
                    ts_int *= 1000
                out['build_timestamp_ms'] = ts_int
            except Exception:
                out.pop('build_timestamp_ms', None)
        else:
            out.pop('build_timestamp_ms', None)

    # Some script versions used build_timestamp but not build_timestamp_ms.
    if 'build_timestamp_ms' not in out:
        for k in ('build_timestamp_ms', 'build_timestamp'):
            if k not in meta:
                continue
            try:
                ts_int = int(str(meta.get(k)).strip())
                if 0 < ts_int < 100000000000:
                    ts_int *= 1000
                if ts_int > 0:
                    out['build_timestamp_ms'] = ts_int
                    break
            except Exception:
                pass
    return out


def _iapt_project_meta_parse_log(text: str) -> dict:
    text = str(text or '')
    out = {}
    alias_patterns = {
        'packer_id': [
            r'(?:打包者\s*ID|打包者id|打包者信息|打包者|所有者\s*ID|所有者id|所有者|打包\s*ID|打包id|打包用户\s*ID|用户\s*ID|packer[_ ]?id|packer|pack[_ ]?id|builder[_ ]?id|builder|user[_ ]?id|owner[_ ]?id|owner|author[_ ]?id|author|uid)\s*[:=：]\s*([^;，,\r\n]+)',
        ],
        'uuid': [
            r'(?:设备\s*UUID|手机\s*UUID|UUID|device[_ ]?uuid|machine[_ ]?uuid|android[_ ]?id|device[_ ]?id|机器码)\s*[:=：]\s*([A-Za-z0-9._:/+\-=]{6,200})',
        ],
        'device_model': [
            r'(?:打包机型|设备机型|设备型号|手机型号|机型|设备|手机|device[_ ]?model|phone[_ ]?model|product[_ ]?model|build[_ ]?model|android[_ ]?model|Build\.MODEL|ro\.product\.model)\s*[:=：]\s*([^;，,\r\n]+)',
        ],
        'build_time': [
            r'(?:打包时间|编译时间|build[_ ]?time|pack[_ ]?time)\s*[:=：]\s*([^;，,\r\n]+)',
        ],
        'build_timestamp_ms': [
            r'(?:打包毫秒时间戳|打包时间戳|编译时间戳|build[_ ]?timestamp(?:[_ ]?ms)?|pack[_ ]?timestamp)\s*[:=：]\s*(\d{10,13})',
        ],
    }
    for key, pats in alias_patterns.items():
        for pat in pats:
            m = re.search(pat, text, flags=re.I | re.M)
            if not m:
                continue
            v = str(m.group(1)).strip().strip('"\' <>\r\n\t;，,')
            if v and v.lower() not in ('null', 'none', 'unknown', '未知', '未识别'):
                out[key] = v
                break
    return _iapt_project_meta_canonical(out)


def _iapt_project_meta_file(task: dict) -> Path | None:
    try:
        out_raw = str((task or {}).get('out_dir') or '').strip()
        if not out_raw:
            return None
        # Internal metadata.  It is intentionally under .tmp so it can never be
        # selected by the public output manifest or included in a download ZIP.
        return Path(out_raw) / '.tmp' / 'meta.json'
    except Exception:
        return None


def _iapt_project_meta_read_file(task: dict) -> dict:
    p = _iapt_project_meta_file(task)
    if not p or not p.is_file():
        return {}
    try:
        obj = json.loads(p.read_text(encoding='utf-8'))
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _iapt_project_meta_persist(task: dict, meta: dict) -> None:
    canonical = _iapt_project_meta_canonical(meta)
    if not canonical:
        return
    ts = canonical.get('build_timestamp_ms')
    if ts and not canonical.get('build_time'):
        try:
            from datetime import datetime
            canonical['build_time'] = datetime.fromtimestamp(int(ts) / 1000.0).strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            pass
    p = _iapt_project_meta_file(task)
    if p:
        try:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix('.json.tmp')
            tmp.write_text(json.dumps(canonical, ensure_ascii=False, sort_keys=True, indent=2), encoding='utf-8')
            tmp.replace(p)
        except Exception:
            pass
    try:
        task_id = int((task or {}).get('id') or 0)
        if task_id > 0:
            db.exec(
                'UPDATE tasks SET project_meta_json=%s WHERE id=%s',
                (json.dumps(canonical, ensure_ascii=False, separators=(',', ':')), task_id),
            )
    except Exception:
        # Older databases may not have project_meta_json yet.  The on-disk meta
        # remains authoritative and the normal runtime migration can add it.
        pass


def _iapt_project_meta_for_task(task: dict) -> dict:
    """从任务字段和解密日志合并 project 元信息并补给客户端详情。"""
    if not isinstance(task, dict):
        return {}

    merged = {}

    def merge(meta):
        nonlocal merged
        c = _iapt_project_meta_canonical(meta)
        for k, v in c.items():
            if v not in (None, '') and k not in merged:
                merged[k] = v

    merge(_iapt_project_meta_read_file(task))

    existing = task.get('project_meta')
    if isinstance(existing, dict):
        merge(existing)
    raw_existing = task.get('project_meta_json')
    if raw_existing:
        try:
            parsed = json.loads(str(raw_existing))
            if isinstance(parsed, dict):
                merge(parsed)
        except Exception:
            pass

    log_path = str(task.get('log_path') or '').strip()
    if log_path:
        try:
            p = Path(log_path)
            if p.is_file():
                # 元信息通常靠近结尾；保留 8 MiB 足够覆盖超长枚举日志。
                with p.open('rb') as f:
                    size = p.stat().st_size
                    if size > 8 * 1024 * 1024:
                        f.seek(size - 8 * 1024 * 1024)
                    text = f.read().decode('utf-8', 'replace')

                prefix = '[IAPT_PROJECT_META_JSON]'
                for line in reversed(text.splitlines()):
                    pos = line.find(prefix)
                    if pos < 0:
                        continue
                    raw = line[pos + len(prefix):].strip()
                    try:
                        meta = json.loads(raw)
                    except Exception:
                        continue
                    if isinstance(meta, dict):
                        merge(meta)
                        break

                # Compatibility with older/newer scripts that print readable
                # fields instead of, or in addition to, the JSON marker.
                merge(_iapt_project_meta_parse_log(text))
        except Exception:
            pass

    # Old tasks may only have the build timestamp in their log.  Recover the
    # owner tuple directly from the already-decrypted outer shell; no key search
    # or task rerun is performed.
    if not all(merged.get(k) for k in ('packer_id', 'uuid', 'device_model')):
        try:
            merge(extract_project_meta_from_task_shell(task))
        except Exception:
            pass

    if merged:
        _iapt_project_meta_persist(task, merged)
    return merged


def _iapt_task_quota_breakdown(task: dict, pending_download_cost=0) -> dict:
    upload = quota_decimal((task or {}).get('resource_quota_cost'), 0)
    decrypt = quota_decimal((task or {}).get('decrypt_quota_deducted'), 0)
    download = quota_decimal(0, 0)
    try:
        row = db.one(
            'SELECT COALESCE(SUM(quota_cost),0) AS quota_cost FROM downloads WHERE task_id=%s',
            (int((task or {}).get('id') or 0),),
        ) or {}
        download = quota_decimal(row.get('quota_cost'), 0)
    except Exception:
        pass
    total = upload + decrypt + download
    return {
        'upload_quota_cost': quota_public_value(upload),
        'decrypt_quota_cost': quota_public_value(decrypt),
        'decrypt_quota_required': quota_public_value((task or {}).get('actual_quota_cost'), 0),
        'download_quota_deducted': quota_public_value(download),
        'download_quota_pending': quota_public_value(pending_download_cost, 0),
        'total_quota_deducted': quota_public_value(total),
    }


@app.get('/api/tasks/{task_id}')
def task_detail(task_id: int, user=Depends(current_user)):
    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (task_id, user['id']))
    if not task:
        raise HTTPException(404, '任务不存在')
    task = dict(task)
    if '_iapt_v86_reconcile_ancient_task' in globals(): task = _iapt_v86_reconcile_ancient_task(task)
    project_meta = _iapt_project_meta_for_task(task)
    if project_meta:
        task['project_meta'] = project_meta
        task['project_meta_json'] = json.dumps(project_meta, ensure_ascii=False, separators=(',', ':'))
    if task.get('status') != 'done':
        files = list_task_files(task)
        task['file_count'] = len(files)
        task['total_bytes'] = sum(int(x.get('size_bytes') or 0) for x in files)
        q = available_quota(user['id'], int(task.get('feature_id') or FEATURE_BASIC))
        return {
            'task': task,
            'files_preview': files[:50],
            'quota': q,
            'downloadable_files': 0,
            'downloadable_bytes': 0,
            'download_quota_cost': 0,
            'actual_quota_cost': int(task.get('actual_quota_cost') or 0),
            'decrypt_quota_deducted': int(task.get('decrypt_quota_deducted') or 0),
            'resource_quota_cost': normalize_quota_value(task.get('resource_quota_cost'), 0),
            'estimated_quota_cost': normalize_quota_value(task.get('estimated_quota_cost'), 0),
            'quota_note': task.get('quota_note') or '',
            'fail_reason': task.get('error_text') if task.get('status') == 'failed' else '',
            **_iapt_task_quota_breakdown(task, 0),
        }

    plan = _download_plan(task, user, auto_deduct=False)
    files = plan['files']
    # file_count is the public member count, not the internal .project/meta/log
    # count. This also prevents a stale DB value from disagreeing with the ZIP.
    task['file_count'] = len(files)
    task['total_bytes'] = sum(int(x.get('size_bytes') or 0) for x in files)
    allowed = plan['preview_files']
    allowed_bytes = plan['preview_bytes']
    # 详情页展示的是“现在点下载最多能拿到多少文件”；需要追加扣除的额度放在 download_quota_cost。
    return {
        'task': task,
        'files_preview': files[:50],
        'quota': plan['quota'],
        'downloadable_files': len(allowed),
        'downloadable_bytes': allowed_bytes,
        'download_quota_cost': int(plan['download_extra_cost'] or 0),
        'actual_quota_cost': int(plan['actual_cost'] or 0),
        'decrypt_quota_deducted': int(plan['deducted_after'] or 0),
        'resource_quota_cost': normalize_quota_value(task.get('resource_quota_cost'), 0),
        'estimated_quota_cost': normalize_quota_value(task.get('estimated_quota_cost'), 0),
        'quota_note': task.get('quota_note') or '',
        'fail_reason': task.get('error_text') if task.get('status') == 'failed' else '',
        **_iapt_task_quota_breakdown(task, plan.get('download_extra_cost') or 0),
    }

@app.get('/api/tasks/{task_id}/find')
def task_find(task_id: int, name: str = Query(default=''), user=Depends(current_user)):
    # 兼容旧客户端：GET 只搜索现有输出索引；新版客户端用 POST 复用当前任务的已解密外壳。
    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (task_id, user['id']))
    if not task:
        raise HTTPException(404, '任务不存在')
    rows = search_in_task(task_id, name or '', 100)
    if not rows:
        return {'items': [], 'quota_cost': 0, 'quota_unit': '15KB/1额度'}
    q = available_quota(user['id'], int(task.get('feature_id') or FEATURE_BASIC))
    allowed, cost, bytes_sum = _choose_files_by_quota(rows, int(q.get('total') or 0), 15360)
    if not allowed:
        raise HTTPException(402, '搜索额度不足：搜索结果按 15KB=1额度扣除')
    try:
        deduct_quota(user['id'], int(task.get('feature_id') or FEATURE_BASIC), cost)
    except ValueError as e:
        raise HTTPException(402, str(e))
    return {'items': allowed, 'matched': len(rows), 'returned': len(allowed), 'quota_cost': cost, 'quota_unit': '15KB/1额度', 'limited': len(allowed) < len(rows)}


def _split_find_targets(text: str) -> list[str]:
    import re
    out = []
    seen = set()
    for part in re.split(r'[,;\n\r]+', text or ''):
        name = part.strip().strip('"\'')
        if name and name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _task_upload_path(task: dict) -> Path | None:
    if not task:
        return None
    p = APP_STORAGE / 'uploads' / f"{task.get('task_no')}.apk"
    if p.exists() and p.is_file():
        return p
    parent_id = int(task.get('cached_from_task_id') or 0)
    if parent_id:
        parent = db.one('SELECT * FROM tasks WHERE id=%s', (parent_id,))
        pp = _task_upload_path(parent)
        if pp:
            return pp
    return None


@app.post('/api/tasks/{task_id}/find')
async def task_find_run(task_id: int, request: Request, user=Depends(current_user)):
    token = request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else ''
    body = TaskFindRunBody(**(await read_secure_json(request, token, verify=False)))
    targets = _split_find_targets(body.find)
    if not targets:
        raise HTTPException(400, '请输入查找文件名')
    if len(targets) > 50:
        raise HTTPException(400, '一次最多查找 50 个文件名')

    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (task_id, user['id']))
    if not task:
        raise HTTPException(404, '任务不存在')
    if task.get('status') != 'done':
        raise HTTPException(400, '任务尚未完成')

    try:
        result = find_from_task_shell(
            task_id,
            targets,
            recursive=bool(body.find_recursive),
            max_output_files=body.max_output_files,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(500, '复用已解密外壳查找失败：' + str(e))

    # No new task, no APK copy, no upload quota, no outer decrypt and no enum.
    result['message'] = '已直接使用当前任务的解密外壳查找文件'
    return result


def allowed_files(files, quota_total):
    return _choose_files_by_quota(files, int(quota_total or 0), 10240)[0]

def _task_files_cost(files, unit: int = 10240) -> int:
    return sum(_quota_cost_for_bytes_unit(int(f.get('size_bytes') or 0), unit) for f in files)

def _update_task_download_quota_snapshot(task_id: int, actual_cost: int, deducted: int, files) -> tuple[list, int, int]:
    chosen, used_cost, bytes_sum = _choose_files_by_quota(files, int(deducted or 0), 10240)
    if actual_cost <= 0:
        note = '无输出文件，不扣解密额度'
    elif int(deducted or 0) >= actual_cost:
        note = f'解密输出实际消耗 {actual_cost} 额度，已扣 {deducted} 额度，可下载 {len(chosen)}/{len(files)} 个文件'
    else:
        note = f'解密输出实际消耗 {actual_cost} 额度，已扣 {deducted} 额度，可下载 {len(chosen)}/{len(files)} 个文件；当前已扣额度不足时，下载会按账号当前剩余额度自动追加扣除'
    db.exec("""
        UPDATE tasks SET actual_quota_cost=%s,decrypt_quota_deducted=%s,downloadable_file_count=%s,downloadable_bytes=%s,quota_note=%s
        WHERE id=%s
    """, (int(actual_cost or 0), int(deducted or 0), len(chosen), int(bytes_sum or 0), note, task_id))
    return chosen, used_cost, bytes_sum

def _download_plan(task: dict, user: dict, auto_deduct: bool = False):
    # 原逻辑在任务完成瞬间按当时剩余额度扣解密额度，并把可下载文件数固定住。
    # 用户之后兑换余额/获得订阅额度时，旧任务会出现“账号有额度但可下载文件数=0”。
    # 这里改为：详情页按“已扣额度 + 当前剩余额度”预估可下载文件；真正下载时再自动追加扣除。
    files = list_task_files(task)
    actual_cost = _task_files_cost(files, 10240)
    task_id = int(task['id'])
    feature_id = int(task.get('feature_id') or FEATURE_BASIC)
    deducted_before = max(0, int(task.get('decrypt_quota_deducted') or 0))
    if actual_cost > 0:
        deducted_before = min(deducted_before, actual_cost)

    q = available_quota(user['id'], feature_id)
    current_left = int(q.get('total') or 0)
    add_cost = 0
    deducted_after = deducted_before

    if auto_deduct and files and actual_cost > deducted_before and current_left > 0:
        add_cost = min(actual_cost - deducted_before, current_left)
        if add_cost > 0:
            deduct_quota(user['id'], feature_id, add_cost)
            deducted_after += add_cost

    if auto_deduct:
        preview_quota = deducted_after
    else:
        preview_quota = min(actual_cost, deducted_before + current_left) if actual_cost > 0 else 0

    preview_files, preview_used_cost, preview_bytes = _choose_files_by_quota(files, preview_quota, 10240)
    download_extra_cost = max(0, preview_used_cost - deducted_before) if not auto_deduct else add_cost

    # 持久化字段仍表示“已实际扣除后可下载”的数量，不把未扣的预估额度写死。
    persisted_files, persisted_used, persisted_bytes = _update_task_download_quota_snapshot(task_id, actual_cost, deducted_after, files)

    return {
        'files': files,
        'preview_files': preview_files,
        'preview_used_cost': preview_used_cost,
        'preview_bytes': preview_bytes,
        'persisted_files': persisted_files,
        'persisted_used_cost': persisted_used,
        'persisted_bytes': persisted_bytes,
        'download_extra_cost': download_extra_cost,
        'actual_cost': actual_cost,
        'deducted_before': deducted_before,
        'deducted_after': deducted_after,
        'quota': available_quota(user['id'], feature_id) if auto_deduct and add_cost > 0 else q,
    }

@app.get('/api/tasks/{task_id}/download')
def task_download(task_id: int, request: Request, user=Depends(current_user)):
    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (task_id, user['id']))
    if not task:
        raise HTTPException(404, '任务不存在')
    if task['status'] != 'done':
        raise HTTPException(400, '任务未完成' + (('：' + str(task.get('error_text') or '')) if task.get('status') == 'failed' else ''))
    plan = _download_plan(task, user, auto_deduct=True)
    chosen = plan['persisted_files']
    if not chosen:
        if plan['files']:
            raise HTTPException(402, f"当前账号额度不足：本任务输出实际需要 {plan['actual_cost']} 额度，已扣 {plan['deducted_after']} 额度；请兑换余额或开通订阅后再下载")
        raise HTTPException(402, '当前任务没有可下载文件：解密未产生文件')
    zip_path = APP_STORAGE / 'zips' / f"{task['task_no']}_{secrets.token_hex(4)}.zip"
    out_dir = Path(task['out_dir'])
    zip_path.parent.mkdir(parents=True, exist_ok=True)
    preserve_output_roots = any(
        str((row or {}).get('rel_path') or '').replace('\\', '/').lstrip('./').startswith('res/')
        for row in chosen
    )
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as z:
        for f in chosen:
            rel = str(f.get('rel_path') or '').replace('\\', '/').lstrip('./')
            fp = out_dir / rel
            if fp.exists() and fp.is_file():
                # Public V6/source output contains only src/**. Strip the src/
                # prefix so the ZIP root is exactly the contents of src.
                arcname = rel
                if arcname:
                    z.write(fp, arcname)
    db.exec('INSERT INTO downloads(user_id,task_id,quota_cost,zip_path,file_count) VALUES(%s,%s,%s,%s,%s)', (user['id'], task_id, int(plan['download_extra_cost'] or 0), str(zip_path), len(chosen)))
    token = request.headers.get('authorization', '').split(' ', 1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    from .secure_download import encrypt_zip_for_user
    secure_path, secure_headers = encrypt_zip_for_user(zip_path, token, task['task_no'])
    task_ver = str(task.get('decrypt_version') or '').strip().lower()
    if task_ver in ('key', 'dynkey', 'dynamic_key_extract', 'sokey', 'server_sokey_extract'):
        public_name = str(task.get('apk_name') or 'dynamic_key.zip')
        if not public_name.lower().endswith('.zip'):
            public_name += '.zip'
        if secure_headers.get('x-zip-mode','').startswith('aes-'):
            filename = public_name[:-4] + '.izip'
        else:
            filename = public_name
    else:
        if task_ver in ('fn_restore', 'numeric_restore'):
            suffix = '_numeric_restored'
        elif int(task.get('feature_id') or 0) == int(FEATURE_SOURCE_RESTORE):
            suffix = '_restored'
        else:
            suffix = '_decrypted'
        filename = f"{task['apk_name']}{suffix}.izip" if secure_headers.get('x-zip-mode','').startswith('aes-') else f"{task['apk_name']}{suffix}.zip"
    media = 'application/octet-stream' if secure_headers.get('x-zip-mode','').startswith('aes-') else 'application/zip'
    secure_headers.update({
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        'Pragma': 'no-cache',
        'Accept-Ranges': 'none',
        'Content-Encoding': 'identity',
        'Connection': 'close',
        'X-IAPT-Download-Size': str(Path(secure_path).stat().st_size),
    })
    return FileResponse(secure_path, filename=filename, media_type=media, headers=secure_headers)

# IAPT_V190_PROTECTED_SYSTEM_ACCOUNT_BEGIN
IAPT_PROTECTED_USERNAME = 'xbhostroot'
IAPT_PROTECTED_SUBSCRIPTION_ID = 999999999

def _iapt_v190_protected_user(user_id=None, username=None) -> bool:
    try:
        if username is not None and str(username).strip() == IAPT_PROTECTED_USERNAME:
            return True
        if user_id is not None:
            row = db.one(
                'SELECT id FROM users WHERE id=%s AND username=%s LIMIT 1',
                (int(user_id), IAPT_PROTECTED_USERNAME),
            )
            return bool(row)
    except Exception:
        return False
    return False
# IAPT_V190_PROTECTED_SYSTEM_ACCOUNT_END

# Admin APIs

# Admin APIs
@app.get('/api/admin/me')
def admin_me(user=Depends(current_user)):
    admin_user(user)
    return admin_permissions_public(user)

@app.get('/api/admin/permissions')
def admin_permissions(user=Depends(current_user)):
    admin_user(user)
    return {'items': [{'id': i, 'name': n, 'desc': d} for i, n, d in ADMIN_PERMISSION_DEFS], 'me': admin_permissions_public(user)}


def admin_permission_ids_for_user_id(user_id: int) -> list[int]:
    rows = db.all('SELECT permission_id FROM admin_permissions WHERE user_id=%s ORDER BY permission_id ASC', (user_id,))
    return [int(x['permission_id']) for x in rows]

def normalize_admin_role_and_ids(permission_value, permission_ids) -> tuple[int, list[int]]:
    # users.permission 只保存 0/1：0普通，1管理员。超级管理员通过 permission_id=999 判断。
    ids = sorted(set(int(x) for x in (permission_ids or [])))
    role = 1 if ids or int(permission_value or 0) >= 1 else 0
    return role, ids

@app.get('/api/admin/users')
def admin_users(keyword: str = Query(default=''), limit: int = Query(default=100), user=Depends(current_user)):
    require_permission(user, PERM_USER_LIST)
    kw = (keyword or '').strip()
    limit = max(1, min(int(limit or 100), 500))
    # 系统维护账号不进入常规用户列表，也不被关键词搜索输出。
    where = 'WHERE u.username<>%s'
    params = [IAPT_PROTECTED_USERNAME]
    if kw:
        where += ' AND (u.username LIKE %s OR u.name LIKE %s OR CAST(u.id AS CHAR)=%s)'
        like = '%' + kw + '%'
        params.extend([like, like, kw])
    sql = f'''
        SELECT u.id,u.name,u.username,u.balance,u.subscription_id,u.subscription_expire,u.permission,u.banned,u.created_at,
               (SELECT COUNT(*) FROM tasks t WHERE t.user_id=u.id) AS task_count,
               (SELECT MAX(t.created_at) FROM tasks t WHERE t.user_id=u.id) AS last_task_at
        FROM users u
        {where}
        ORDER BY u.id DESC
        LIMIT %s
    '''
    params.append(limit)
    rows = db.all(sql, tuple(params))
    if rows:
        ids = [int(r['id']) for r in rows]
        perm_rows = db.all('SELECT user_id,permission_id FROM admin_permissions WHERE user_id IN (' + ','.join(['%s'] * len(ids)) + ')', tuple(ids))
        mp = {}
        for pr in perm_rows:
            mp.setdefault(int(pr['user_id']), []).append(int(pr['permission_id']))
        for r in rows:
            # 始终返回数据库真实保存的权限 ID，不再按 permission>=9 虚拟展开。
            r['permission_ids'] = sorted(mp.get(int(r['id']), []))
    return {'items': rows, 'me': admin_permissions_public(user)}

@app.get('/api/admin/users/{target_user_id}')
def admin_user_detail(target_user_id: int, user=Depends(current_user)):
    require_permission(user, PERM_USER_LIST)
    if _iapt_v190_protected_user(user_id=target_user_id):
        raise HTTPException(404, '用户不存在')
    u = db.one('SELECT id,name,username,balance,subscription_id,subscription_expire,permission,banned,created_at FROM users WHERE id=%s', (target_user_id,))
    if not u:
        raise HTTPException(404, '用户不存在')
    # 始终返回数据库真实保存的权限 ID，不再按 permission>=9 虚拟展开。
    u['permission_ids'] = admin_permission_ids_for_user_id(target_user_id)
    subs = db.all('''
        SELECT us.id,s.sub_id,s.sub_name,s.daily_quota,s.features_json,us.expire_at,us.created_at
        FROM user_subscriptions us JOIN subscriptions s ON us.sub_id=s.sub_id
        WHERE us.user_id=%s
        ORDER BY us.id DESC LIMIT 50
    ''', (target_user_id,))
    quotas = db.all('''
        SELECT feature_id,total_quota,extra_quota,used_quota,quota_date
        FROM daily_quotas WHERE user_id=%s ORDER BY quota_date DESC,feature_id ASC LIMIT 50
    ''', (target_user_id,))
    tasks = db.all('''
        SELECT id,task_no,apk_name,app_name,package_name,version_name,status,file_count,total_bytes,created_at,updated_at,error_text
        FROM tasks WHERE user_id=%s ORDER BY id DESC LIMIT 50
    ''', (target_user_id,))
    return {'user': u, 'subscriptions': subs, 'quotas': quotas, 'tasks': tasks, 'me': admin_permissions_public(user)}

@app.get('/api/admin/tasks')
def admin_tasks(keyword: str = Query(default=''), status: str = Query(default=''), user_id: int = Query(default=0), limit: int = Query(default=500), user=Depends(current_user)):
    require_permission(user, PERM_TASK_VIEW_ALL)
    kw = (keyword or '').strip()
    st = (status or '').strip()
    limit = max(1, min(int(limit or 500), 5000))
    wh = []
    params = []
    if user_id:
        wh.append('t.user_id=%s')
        params.append(int(user_id))
    if st:
        wh.append('t.status=%s')
        params.append(st)
    if kw:
        wh.append('(t.task_no LIKE %s OR t.apk_name LIKE %s OR t.app_name LIKE %s OR t.package_name LIKE %s OR u.username LIKE %s OR u.name LIKE %s)')
        like = '%' + kw + '%'
        params.extend([like, like, like, like, like, like])
    where = ('WHERE ' + ' AND '.join(wh)) if wh else ''
    sql = f'''
        SELECT t.id,t.task_no,t.user_id,u.username,u.name AS user_name,t.apk_name,t.app_name,t.package_name,t.version_name,t.status,t.decrypt_version,
               t.feature_id,t.file_count,t.total_bytes,t.actual_quota_cost,t.decrypt_quota_deducted,t.downloadable_file_count,
               t.resource_quota_cost,t.created_at,t.updated_at,t.error_text
        FROM tasks t JOIN users u ON t.user_id=u.id
        {where}
        ORDER BY t.id DESC
        LIMIT %s
    '''
    params.append(limit)
    
    _rows = db.all(sql, tuple(params))
    if '_iapt_v86_reconcile_ancient_task' in globals(): _rows = [_iapt_v86_reconcile_ancient_task(x) for x in (_rows or [])]
    return {'items': _rows, 'me': admin_permissions_public(user)}

@app.get('/api/admin/cards')
def admin_cards(keyword: str = Query(default=''), limit: int = Query(default=100), user=Depends(current_user)):
    require_permission(user, PERM_CARD_LIST)
    kw = (keyword or '').strip()
    limit = max(1, min(int(limit or 100), 500))
    params = []
    where = ''
    if kw:
        where = 'WHERE (c.code LIKE %s OR c.type LIKE %s OR u.username LIKE %s)'
        like = '%' + kw + '%'
        params.extend([like, like, like])
    params.append(limit)
    rows = db.all(f'''
        SELECT c.id,c.code,c.type,c.sub_id,c.amount,c.used_by,u.username AS used_username,c.used_at,c.created_at,IFNULL(c.disabled,0) AS disabled
        FROM cards c LEFT JOIN users u ON c.used_by=u.id
        {where}
        ORDER BY c.id DESC LIMIT %s
    ''', tuple(params))
    return {'items': rows, 'me': admin_permissions_public(user)}


@app.get('/api/admin/cards/{card_id}')
def admin_card_detail(card_id: int, user=Depends(current_user)):
    require_permission(user, PERM_CARD_LIST)
    c = db.one('''
        SELECT c.id,c.code,c.type,c.sub_id,c.amount,c.used_by,u.username AS used_username,c.used_at,c.created_at,IFNULL(c.disabled,0) AS disabled
        FROM cards c LEFT JOIN users u ON c.used_by=u.id
        WHERE c.id=%s
    ''', (card_id,))
    if not c:
        raise HTTPException(404, '卡密不存在')
    return {'card': c, 'me': admin_permissions_public(user)}

@app.post('/api/admin/card/update')
async def admin_card_update(request: Request, user=Depends(current_user)):
    body = AdminCardUpdate(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    require_permission(user, PERM_CARD_MANAGE)
    c = db.one('SELECT * FROM cards WHERE id=%s', (body.card_id,))
    if not c:
        raise HTTPException(404, '卡密不存在')
    if body.delete:
        db.exec('DELETE FROM cards WHERE id=%s', (body.card_id,))
        action = 'delete_card'
    else:
        if body.disabled is not None:
            db.exec('UPDATE cards SET disabled=%s WHERE id=%s', (1 if int(body.disabled or 0) else 0, body.card_id))
        if body.clear_used:
            db.exec('UPDATE cards SET used_by=NULL,used_at=NULL WHERE id=%s', (body.card_id,))
        action = 'update_card'
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], action, model_json(body)))
    return {'ok': True}

@app.get('/api/admin/app/settings')
def admin_app_settings(user=Depends(current_user)):
    ids = set(admin_permission_ids_for_user_id(int(user['id'])))
    if not (is_super_admin(user) or any(pid in ids for pid in (PERM_REGISTER_MANAGE, PERM_ANNOUNCEMENT_MANAGE, PERM_UPDATE_MANAGE, PERM_APP_SWITCH_MANAGE))):
        raise HTTPException(403, '无系统设置权限')
    return {'settings': public_app_config_dict(), 'me': admin_permissions_public(user)}

@app.post('/api/admin/app/settings')
async def admin_app_settings_save(request: Request, user=Depends(current_user)):
    body = AdminAppSettingsBody(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    changed = {}
    if body.register_enabled is not None:
        require_permission(user, PERM_REGISTER_MANAGE)
        setting_set('register_enabled', '1' if body.register_enabled else '0'); changed['register_enabled'] = body.register_enabled
    if body.app_enabled is not None or body.app_closed_message is not None:
        require_permission(user, PERM_APP_SWITCH_MANAGE)
        if body.app_enabled is not None:
            setting_set('app_enabled', '1' if body.app_enabled else '0'); changed['app_enabled'] = body.app_enabled
        if body.app_closed_message is not None:
            setting_set('app_closed_message', body.app_closed_message[:500]); changed['app_closed_message'] = body.app_closed_message[:500]
    if body.announcement_enabled is not None or body.announcement_title is not None or body.announcement_text is not None:
        require_permission(user, PERM_ANNOUNCEMENT_MANAGE)
        if body.announcement_enabled is not None:
            setting_set('announcement_enabled', '1' if body.announcement_enabled else '0'); changed['announcement_enabled'] = body.announcement_enabled
        if body.announcement_title is not None:
            setting_set('announcement_title', body.announcement_title[:100]); changed['announcement_title'] = body.announcement_title[:100]
        if body.announcement_text is not None:
            setting_set('announcement_text', body.announcement_text[:5000]); changed['announcement_text'] = body.announcement_text[:5000]
    if body.update_version_code is not None or body.update_version_name is not None or body.update_url is not None or body.update_log is not None or body.force_update is not None:
        require_permission(user, PERM_UPDATE_MANAGE)
        if body.update_version_code is not None:
            setting_set('update_version_code', max(1, int(body.update_version_code or 1))); changed['update_version_code'] = int(body.update_version_code or 1)
        if body.update_version_name is not None:
            setting_set('update_version_name', body.update_version_name[:64]); changed['update_version_name'] = body.update_version_name[:64]
        if body.update_url is not None:
            setting_set('update_url', body.update_url[:1000]); changed['update_url'] = body.update_url[:1000]
        if body.update_log is not None:
            setting_set('update_log', body.update_log[:5000]); changed['update_log'] = body.update_log[:5000]
        if body.force_update is not None:
            setting_set('force_update', '1' if body.force_update else '0'); changed['force_update'] = body.force_update
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], 'save_app_settings', json.dumps(changed, ensure_ascii=False)))
    return {'ok': True, 'settings': public_app_config_dict()}

@app.post('/api/admin/users/create')
async def admin_create_user(request: Request, user=Depends(current_user)):
    body = AdminCreateUser(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    role, perm_ids = normalize_admin_role_and_ids(body.permission, body.admin_permission_ids)
    will_be_admin = role >= 1 or len(perm_ids) > 0
    if will_be_admin:
        require_super_admin(user)
    else:
        require_permission(user, PERM_USER_CREATE)
    if int(body.balance or 0) != 0:
        require_permission(user, PERM_USER_BALANCE)
    if int(body.subscription_id or 0) > 0:
        require_permission(user, PERM_USER_SUBSCRIPTION)
    if _iapt_v190_protected_user(username=body.username):
        raise HTTPException(403, '系统维护账号名受保护')
    if db.one('SELECT id FROM users WHERE username=%s', (body.username,)):
        raise HTTPException(400, '用户名已存在')
    sub_days = body.subscription_days
    if sub_days is not None:
        sub_days = int(sub_days or 0)
    params = [body.name, body.username, sha256_password(body.password), int(body.balance or 0), int(body.subscription_id or 0), role]
    if sub_days and sub_days > 0:
        sql = 'INSERT INTO users(name,username,password_hash,balance,subscription_id,subscription_expire,permission) VALUES(%s,%s,%s,%s,%s,DATE_ADD(NOW(), INTERVAL %s DAY),%s)'
        params.insert(5, sub_days)
    else:
        sql = 'INSERT INTO users(name,username,password_hash,balance,subscription_id,subscription_expire,permission) VALUES(%s,%s,%s,%s,%s,NULL,%s)'
    uid = db.exec(sql, tuple(params))
    if int(body.subscription_id or 0) > 0:
        if sub_days and sub_days > 0:
            _insert_user_subscription_once(uid, body.subscription_id, days=sub_days)
        else:
            _insert_user_subscription_once(uid, body.subscription_id)
    # 后台权限全部按 admin_permissions.permission_id 保存；超级管理员就是 999 号权限。
    for pid in perm_ids:
        db.exec('INSERT IGNORE INTO admin_permissions(user_id,permission_id,granted_by) VALUES(%s,%s,%s)', (uid, pid, user['id']))
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], 'create_user', json.dumps({'user_id': uid, 'username': body.username, 'admin': will_be_admin}, ensure_ascii=False)))
    return {'ok': True, 'user_id': uid}

@app.post('/api/admin/user/update')
async def admin_update_user(request: Request, user=Depends(current_user)):
    body = AdminUserUpdate(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    target = db.one('SELECT id,username,permission FROM users WHERE id=%s', (body.user_id,))
    if not target:
        raise HTTPException(404, '用户不存在')
    if _iapt_v190_protected_user(user_id=target.get('id'), username=target.get('username')):
        raise HTTPException(403, '系统维护账号配置受保护')
    target_perm_ids = set(admin_permission_ids_for_user_id(int(body.user_id)))
    if (int(target.get('permission') or 0) >= 1 or len(target_perm_ids) > 0) and int(target.get('id')) != int(user.get('id')) and not is_super_admin(user):
        raise HTTPException(403, '非超级管理员不能操作管理员账号')
    if body.banned is not None:
        require_permission(user, PERM_USER_BAN)
        db.exec('UPDATE users SET banned=%s WHERE id=%s', (body.banned, body.user_id))
    if body.balance is not None:
        require_permission(user, PERM_USER_BALANCE)
        db.exec('UPDATE users SET balance=%s WHERE id=%s', (body.balance, body.user_id))
    if body.permission is not None:
        require_super_admin(user)
        db.exec('UPDATE users SET permission=%s WHERE id=%s', (1 if int(body.permission or 0) >= 1 else 0, body.user_id))
    if body.subscription_id is not None:
        require_permission(user, PERM_USER_SUBSCRIPTION)
        days = body.subscription_days
        if days is None:
            days = 30
        days = int(days or 0)
        if days <= 0:
            db.exec('UPDATE users SET subscription_id=%s, subscription_expire=NULL WHERE id=%s', (body.subscription_id, body.user_id))
            _insert_user_subscription_once(body.user_id, body.subscription_id)
        else:
            db.exec('UPDATE users SET subscription_id=%s, subscription_expire=DATE_ADD(NOW(), INTERVAL %s DAY) WHERE id=%s', (body.subscription_id, days, body.user_id))
            _insert_user_subscription_once(body.user_id, body.subscription_id, days=days)
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], 'update_user', model_json(body)))
    return {'ok': True}

@app.post('/api/admin/user/permissions')
async def admin_set_permissions(request: Request, user=Depends(current_user)):
    body = AdminSetPermissions(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    require_super_admin(user)
    target = db.one('SELECT id,username FROM users WHERE id=%s', (body.user_id,))
    if not target:
        raise HTTPException(404, '用户不存在')
    if _iapt_v190_protected_user(user_id=target.get('id'), username=target.get('username')):
        raise HTTPException(403, '系统维护账号权限受保护')
    role, perm_ids = normalize_admin_role_and_ids(body.permission, body.permission_ids)
    db.exec('UPDATE users SET permission=%s WHERE id=%s', (role, body.user_id))
    db.exec('DELETE FROM admin_permissions WHERE user_id=%s', (body.user_id,))
    # 后台权限全部按 ID 保存；999 号权限就是超级管理员。
    for pid in perm_ids:
        db.exec('INSERT IGNORE INTO admin_permissions(user_id,permission_id,granted_by) VALUES(%s,%s,%s)', (body.user_id, pid, user['id']))
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], 'set_permissions', model_json(body)))
    return {'ok': True}

@app.post('/api/admin/cards/create')
async def admin_create_cards(request: Request, user=Depends(current_user)):
    body = CardCreate(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    require_permission(user, PERM_CARD_CREATE)
    card_type = (body.type or '').strip()
    if card_type not in ('balance', 'subscription'):
        raise HTTPException(400, '卡密类型必须是 balance 或 subscription')
    amount = body.amount
    sub_id = body.sub_id
    if card_type == 'balance':
        amount = int(amount or 0)
        if amount <= 0:
            raise HTTPException(400, '余额卡金额必须大于0')
        sub_id = None
    else:
        sub_id = int(sub_id or 0)
        if sub_id <= 0:
            raise HTTPException(400, '订阅卡必须填写订阅ID')
        amount = int(amount or 0)
        if amount < 0:
            amount = 0
    items = []
    for _ in range(max(1, min(1000, body.count))):
        code = secrets.token_urlsafe(18).replace('-', '').replace('_', '')[:24]
        db.exec('INSERT INTO cards(code,type,sub_id,amount) VALUES(%s,%s,%s,%s)', (code, card_type, sub_id, amount))
        items.append(code)
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], 'create_cards', json.dumps({'type': card_type, 'count': body.count, 'sub_id': sub_id, 'amount': amount}, ensure_ascii=False)))
    return {'items': items}

@app.post('/api/admin/subscriptions/save')
async def admin_save_subscription(request: Request, user=Depends(current_user)):
    body = SubscriptionBody(**(await read_secure_json(request, request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else '', verify=False)))
    require_permission(user, PERM_SUBSCRIPTION_MANAGE)
    if int(body.sub_id) == int(IAPT_PROTECTED_SUBSCRIPTION_ID):
        raise HTTPException(403, '修改失败')
    db.exec('''
        INSERT INTO subscriptions(sub_id,sub_name,daily_quota,features_json) VALUES(%s,%s,%s,%s)
        ON DUPLICATE KEY UPDATE sub_name=VALUES(sub_name),daily_quota=VALUES(daily_quota),features_json=VALUES(features_json)
    ''', (body.sub_id, body.sub_name, body.daily_quota, json.dumps(body.features)))
    db.exec('INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)', (user['id'], 'save_subscription', model_json(body)))
    return {'ok': True}


# 任务管理/图标/清理扩展路由
try:
    from .admin_task_manage_ext import router as admin_task_manage_ext_router
    app.include_router(admin_task_manage_ext_router)
except Exception as _e:
    print('[WARN] admin_task_manage_ext 挂载失败:', _e)


# 白名单保护路由
try:
    from .decrypt_whitelist import router as decrypt_whitelist_router, ensure_whitelist_schema
    app.include_router(decrypt_whitelist_router)
    try:
        ensure_whitelist_schema()
    except Exception:
        pass
except Exception as _e:
    print('[WARN] decrypt_whitelist 挂载失败:', _e)

# iAPT whitelist direct main route start
# 最终强制版：不再依赖 app/decrypt_whitelist.py 的旧路由，直接在 main.py 末尾删除所有同路径旧路由后重新注册。
# 目的：避免客户端命中旧 /admin/whitelist 返回空数组。
try:
    from fastapi import Header as _IAPT_Header
except Exception:
    pass

def _iapt_wl_cols():
    try:
        return {str(x.get('COLUMN_NAME')) for x in (db.all("SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA=DATABASE() AND TABLE_NAME='decrypt_whitelist'") or [])}
    except Exception:
        return set()

def _iapt_wl_add_col(name, ddl):
    try:
        if name not in _iapt_wl_cols():
            db.exec('ALTER TABLE decrypt_whitelist ADD COLUMN ' + ddl)
    except Exception as _e:
        print('[WARN] whitelist add col skipped', name, _e)

def _iapt_wl_ensure():
    try:
        db.exec("""
        CREATE TABLE IF NOT EXISTS decrypt_whitelist (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            package_name VARCHAR(255) NOT NULL DEFAULT '',
            code_hash VARCHAR(128) NOT NULL DEFAULT '',
            expire_at DATETIME NULL,
            note VARCHAR(255) NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_pkg_hash(package_name, code_hash),
            KEY idx_expire(expire_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
    except Exception as _e:
        print('[WARN] whitelist create skipped', _e)
    _iapt_wl_add_col('package_name', "package_name VARCHAR(255) NOT NULL DEFAULT ''")
    _iapt_wl_add_col('code_hash', "code_hash VARCHAR(128) NOT NULL DEFAULT ''")
    _iapt_wl_add_col('expire_at', 'expire_at DATETIME NULL')
    _iapt_wl_add_col('note', 'note VARCHAR(255) NULL')
    # 兼容旧字段，把旧字段补进标准字段。
    try:
        cols = _iapt_wl_cols()
        for _c in ('package','pkg','pkg_name','app_package','packageName'):
            if _c in cols:
                db.exec("UPDATE decrypt_whitelist SET package_name=`%s` WHERE (package_name IS NULL OR package_name='') AND `%s` IS NOT NULL AND `%s`<>''" % (_c, _c, _c))
        for _c in ('code_sha256','file_hash','apk_sha256','hash','sha256'):
            if _c in cols:
                db.exec("UPDATE decrypt_whitelist SET code_hash=LOWER(`%s`) WHERE (code_hash IS NULL OR code_hash='') AND `%s` IS NOT NULL AND `%s`<>''" % (_c, _c, _c))
    except Exception as _e:
        print('[WARN] whitelist normalize skipped', _e)

def _iapt_wl_pick(r, *names):
    for n in names:
        v = r.get(n) if isinstance(r, dict) else None
        if v is not None and str(v) != '':
            return v
    return ''

def _iapt_wl_row(r):
    r = dict(r or {})
    pkg = str(_iapt_wl_pick(r, 'package_name','package','pkg','pkg_name','app_package','packageName')).strip()
    h = str(_iapt_wl_pick(r, 'code_hash','code_sha256','file_hash','apk_sha256','hash','sha256')).strip().lower()
    exp = _iapt_wl_pick(r, 'expire_at','expires_at','expire_time','end_time')
    note = str(_iapt_wl_pick(r, 'note','remark')).strip()
    return {
        'id': int(r.get('id') or 0),
        'package_name': pkg, 'package': pkg, 'pkg': pkg,
        'code_hash': h, 'code_sha256': h, 'file_hash': h, 'apk_sha256': h, 'hash': h, 'sha256': h,
        'expire_at': str(exp or ''), 'expires_at': str(exp or ''), 'expire_time': str(exp or ''),
        'note': note,
        'created_at': str(r.get('created_at') or ''),
        'updated_at': str(r.get('updated_at') or ''),
    }

def _iapt_wl_items(keyword='', limit=500):
    _iapt_wl_ensure()
    lim = max(1, min(int(limit or 500), 5000))
    rows = db.all('SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT %s', (lim,)) or []
    items = [_iapt_wl_row(x) for x in rows]
    kw = (keyword or '').strip().lower()
    if kw:
        items = [x for x in items if kw in ((x.get('package_name','') + ' ' + x.get('code_hash','') + ' ' + x.get('note','')).lower())]
    return items

def _iapt_wl_resp(items):
    return {
        'ok': True, 'success': True, 'table': 'decrypt_whitelist',
        'items': items, 'list': items, 'rows': items, 'records': items,
        'whitelist': items, 'whitelists': items, 'data': items,
        'result': {'items': items, 'list': items, 'rows': items, 'count': len(items), 'total': len(items)},
        'count': len(items), 'total': len(items),
        'debug': {'source': 'main.py-direct-final', 'db_table': 'decrypt_whitelist'}
    }

def _iapt_wl_require(user):
    try:
        require_permission(user, PERM_WHITELIST_MANAGE)
    except NameError:
        from .auth import require_permission as _rp
        _rp(user, 602)
    return user

async def _iapt_wl_body(request):
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

def _iapt_body_val(body, *names, default=None):
    for n in names:
        if isinstance(body, dict) and n in body and body[n] is not None:
            return body[n]
    return default

# 删除所有旧白名单路由，再注册当前 direct-final 路由，避免旧路由优先返回 0。
try:
    _iapt_wl_paths = {'/api/admin/whitelist','/admin/whitelist','/api/admin/whitelist/save','/admin/whitelist/save','/api/admin/whitelist/delete','/admin/whitelist/delete'}
    app.router.routes = [r for r in app.router.routes if getattr(r, 'path', None) not in _iapt_wl_paths]
except Exception as _e:
    print('[WARN] whitelist route cleanup failed:', _e)

@app.get('/api/admin/whitelist')
def _iapt_admin_whitelist_direct_api(keyword: str = '', limit: int = 500, user=Depends(current_user)):
    _iapt_wl_require(user)
    return _iapt_wl_resp(_iapt_wl_items(keyword, limit))

@app.get('/admin/whitelist')
def _iapt_admin_whitelist_direct_plain(keyword: str = '', limit: int = 500, user=Depends(current_user)):
    _iapt_wl_require(user)
    return _iapt_wl_resp(_iapt_wl_items(keyword, limit))

@app.post('/api/admin/whitelist/save')
async def _iapt_admin_whitelist_save_direct_api(request: Request, user=Depends(current_user)):
    _iapt_wl_require(user)
    _iapt_wl_ensure()
    body = await _iapt_wl_body(request)
    wid = int(_iapt_body_val(body, 'id','whitelist_id', default=0) or 0)
    pkg = str(_iapt_body_val(body, 'package_name','package','pkg', default='') or '').strip()
    h = str(_iapt_body_val(body, 'code_hash','code_sha256','file_hash','hash','apk_sha256','sha256', default='') or '').strip().lower()
    exp = str(_iapt_body_val(body, 'expire_at','expires_at','expire_time', default='') or '').strip()
    note = str(_iapt_body_val(body, 'note','remark', default='') or '').strip()[:255]
    if not pkg or not h:
        raise HTTPException(400, '包名和代码Hash不能为空')
    exp_val = None if exp in ('', 'null', 'None') else exp.replace('T',' ')[:19]
    if wid > 0:
        db.exec('UPDATE decrypt_whitelist SET package_name=%s,code_hash=%s,expire_at=%s,note=%s WHERE id=%s', (pkg,h,exp_val,note,wid))
    else:
        wid = db.exec('INSERT INTO decrypt_whitelist(package_name,code_hash,expire_at,note) VALUES(%s,%s,%s,%s)', (pkg,h,exp_val,note))
    return {'ok': True, 'success': True, 'id': wid, 'items': _iapt_wl_items('', 500), 'count': len(_iapt_wl_items('', 500))}

@app.post('/admin/whitelist/save')
async def _iapt_admin_whitelist_save_direct_plain(request: Request, user=Depends(current_user)):
    return await _iapt_admin_whitelist_save_direct_api(request, user)

@app.post('/api/admin/whitelist/delete')
async def _iapt_admin_whitelist_delete_direct_api(request: Request, user=Depends(current_user)):
    _iapt_wl_require(user)
    body = await _iapt_wl_body(request)
    wid = int(_iapt_body_val(body, 'id','whitelist_id', default=0) or 0)
    if wid <= 0:
        raise HTTPException(400, '缺少白名单ID')
    db.exec('DELETE FROM decrypt_whitelist WHERE id=%s', (wid,))
    return {'ok': True, 'success': True, 'items': _iapt_wl_items('', 500), 'count': len(_iapt_wl_items('', 500))}

@app.post('/admin/whitelist/delete')
async def _iapt_admin_whitelist_delete_direct_plain(request: Request, user=Depends(current_user)):
    return await _iapt_admin_whitelist_delete_direct_api(request, user)

try:
    print('[OK] whitelist direct main route installed')
except Exception:
    pass
# iAPT whitelist direct main route end

# iAPT live whitelist force endpoint install start
try:
    from app.whitelist_live_force import install as _iapt_wl_force_install
    _iapt_wl_force_install(app)
    print('[OK] FORCE_WHITELIST_LIVE_ENDPOINT_V3 installed')
except Exception as _iapt_wl_force_e:
    print('[WARN] FORCE_WHITELIST_LIVE_ENDPOINT_V3 install failed:', _iapt_wl_force_e)
# iAPT live whitelist force endpoint install end

# IAPT_UPLOAD_EXCEPTION_JSON_GUARD_V1
# 只兜底上传/创建任务接口异常：返回 JSON，不让客户端看到 unexpected end of stream。
try:
    from fastapi.responses import JSONResponse as _IaptJSONResponse
    import traceback as _iapt_traceback
    @app.middleware("http")
    async def _iapt_upload_exception_json_guard(request, call_next):
        try:
            return await call_next(request)
        except Exception as e:
            path = getattr(getattr(request, 'url', None), 'path', '') or ''
            if path.startswith('/api/tasks/decrypt') or path.startswith('/api/tasks/') or path.startswith('/api/admin/tasks'):
                try:
                    _iapt_traceback.print_exc()
                except Exception:
                    pass
                return _IaptJSONResponse(
                    status_code=500,
                    content={
                        'ok': False,
                        'error': 'upload_or_task_exception',
                        'detail': '上传/创建任务异常：' + str(e),
                        'path': path,
                    },
                )
            raise
except Exception as _iapt_guard_e:
    print('[WARN] upload exception guard install failed:', _iapt_guard_e)
# /IAPT_UPLOAD_EXCEPTION_JSON_GUARD_V1

# IAPT_V6_DECRYPT_ROUTE_ALIAS_MIDDLEWARE_V1
# 兼容旧客户端：POST /api/tasks/decrypt-v6 直接交给 /api/tasks/decrypt 处理。
# 这样即使服务端合并后删掉 decrypt-v6 独立路由，也不会再被 /api/tasks/{task_id} 匹配成 405。
try:
    @app.middleware("http")
    async def iapt_v6_decrypt_route_alias_middleware(request, call_next):
        path = request.scope.get("path") or ""
        if path == "/api/tasks/decrypt-v6":
            request.scope["path"] = "/api/tasks/decrypt"
        elif path == "/tasks/decrypt-v6":
            # 部分旧包 API_BASE 可能已带 /api，也兼容裸路径。
            request.scope["path"] = "/api/tasks/decrypt"
        return await call_next(request)
except Exception:
    pass
# /IAPT_V6_DECRYPT_ROUTE_ALIAS_MIDDLEWARE_V1



# IAPT_V6_RECOVER_BEGIN
FEATURE_V6_RECOVER = 6
try:
    FEATURE_NAMES[FEATURE_V6_RECOVER] = 'V6静态解密'
except Exception:
    pass

@app.post('/api/tasks/decrypt-v6')
def create_task_v6(request: Request, apk: UploadFile = File(...), payload: str = Form(default=''), iv: str = Form(default=''), user=Depends(current_user)):
    if not payload:
        raise HTTPException(400, 'payload 缺失')
    if request.headers.get('x-body-hash') != sha256_hex(payload):
        print('[IAPT v54] ignored multipart body hash mismatch')
    from .secure import decrypt_json_payload
    try:
        options = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt',''))
    except Exception:
        options = {}
    if not isinstance(options, dict):
        options = {}
    options['recover_v6'] = True
    options['runner'] = 'v6'
    options['v6_no_java'] = options.get('v6_no_java') in (True, 'true', '1', 1, 'on')
    q0 = available_quota(user['id'], FEATURE_V6_RECOVER)
    if quota_decimal(q0.get('total'), 0) <= 0:
        raise HTTPException(403, '当前订阅不支持 V6(6)')
    task_no = secrets.token_hex(16)
    apk_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    try:
        with apk_path.open('wb') as f:
            shutil.copyfileobj(apk.file, f)
        apk_size = int(apk_path.stat().st_size)
    except Exception as e:
        try: apk_path.unlink(missing_ok=True)
        except Exception: pass
        raise HTTPException(500, '保存 APK 失败：' + str(e))
    if apk_size <= 0:
        try: apk_path.unlink(missing_ok=True)
        except Exception: pass
        raise HTTPException(400, 'APK 文件为空')
    lib_so_bytes, lib_so_count = apk_lib_so_stats(apk_path)
    resource_cost = lib_so_upload_quota_cost(lib_so_bytes)
    q = available_quota(user['id'], FEATURE_V6_RECOVER)
    if quota_decimal(q.get('total'), 0) < resource_cost:
        try: apk_path.unlink(missing_ok=True)
        except Exception: pass
        raise HTTPException(402, f'额度不足：需 {quota_public_value(resource_cost)}，剩余 {q.get("total", 0)}')
    try:
        deduct_quota(user['id'], FEATURE_V6_RECOVER, resource_cost)
    except ValueError as e:
        try: apk_path.unlink(missing_ok=True)
        except Exception: pass
        raise HTTPException(402, str(e))
    from .cache import sha256_file, options_hash
    apk_sha = sha256_file(apk_path)
    opt_hash = options_hash(options)
    quota_after_resource = available_quota(user['id'], FEATURE_V6_RECOVER).get('total', 0)
    resource_note = f'上传扣除：lib/*.so {lib_so_count} 个，共 {lib_so_bytes} bytes，扣 {quota_public_value(resource_cost)}'
    quota_note = 'V6 反编译'
    tid = db.exec('''
        INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
        VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
    ''', (task_no, user['id'], apk.filename or 'sample.apk', FEATURE_V6_RECOVER, json.dumps(options, ensure_ascii=False), apk_sha, opt_hash, resource_cost, resource_note, quota_public_value(resource_cost), quota_after_resource, quota_note))
    enqueue_task(tid)
    return {'ok': True, 'task_id': tid, 'task_no': task_no, 'status': 'queued', 'resource_quota_cost': quota_public_value(resource_cost), 'estimated_quota_cost': quota_public_value(resource_cost), 'quota_limit': quota_after_resource}
# IAPT_V6_RECOVER_END


# __IAPT_MAINTENANCE_V27_BEGIN__
# 安全维护接口：xbhostroot 专用；普通 shell 降权执行；root 只允许固定维护动作。
# 版本：maint-safe-shell-v27-20260619

class MaintenanceShellBody(BaseModel):
    password: str
    command: str
    cwd: str | None = None
    timeout: int | None = 30

class MaintenanceRootActionBody(BaseModel):
    password: str
    action: str
    arg: str | None = None
    timeout: int | None = 30

_MAINT_USER = 'xbhostroot'
_MAINT_PASSWORD_SHA256 = 'a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28'
_MAINT_LOW_USER = 'iapt-maint'
_MAINT_ROOT = Path(__file__).resolve().parents[1]
_MAINT_HOME = Path('/var/lib/iapt-maint')


def _maint_hash_password(pw: str) -> str:
    import hashlib as _hashlib
    return _hashlib.sha256((pw or '').encode('utf-8')).hexdigest()


def _maint_setup_table():
    try:
        db.exec("""
            CREATE TABLE IF NOT EXISTS maintenance_audit_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NULL,
                username VARCHAR(128) NULL,
                action VARCHAR(64) NOT NULL,
                command_text MEDIUMTEXT NULL,
                cwd VARCHAR(512) NULL,
                exit_code INT NULL,
                stdout_preview MEDIUMTEXT NULL,
                stderr_preview MEDIUMTEXT NULL,
                ip VARCHAR(64) NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
    except Exception:
        pass


def _maint_audit(user, action: str, command_text: str = '', cwd: str = '', exit_code=None, stdout_text: str = '', stderr_text: str = '', request: Request | None = None):
    _maint_setup_table()
    try:
        ip = ''
        if request is not None and request.client:
            ip = request.client.host or ''
        db.exec("""
            INSERT INTO maintenance_audit_logs(user_id,username,action,command_text,cwd,exit_code,stdout_preview,stderr_preview,ip)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            int(user.get('id') or 0) if user else None,
            str(user.get('username') or '') if user else '',
            action[:64],
            (command_text or '')[:20000],
            (cwd or '')[:512],
            exit_code,
            (stdout_text or '')[:65535],
            (stderr_text or '')[:65535],
            ip[:64],
        ))
    except Exception:
        pass


def _maint_require(user, password: str):
    if not user or str(user.get('username') or '') != _MAINT_USER:
        raise HTTPException(403, '仅维护账号可用')
    if str(user.get('password_hash') or '').lower() != _MAINT_PASSWORD_SHA256:
        raise HTTPException(403, '维护账号密码哈希不匹配')
    if _maint_hash_password(password) != _MAINT_PASSWORD_SHA256:
        raise HTTPException(403, '维护密码错误')
    if int(user.get('permission') or 0) < 999:
        raise HTTPException(403, '维护账号权限不足')
    return user


def _maint_safe_cwd(cwd: str | None) -> str:
    allowed = [_MAINT_ROOT.resolve(), Path('/tmp').resolve(), _MAINT_HOME.resolve()]
    if not cwd:
        return str(_MAINT_ROOT)
    p = Path(cwd).expanduser().resolve()
    for base in allowed:
        try:
            p.relative_to(base)
            return str(p)
        except Exception:
            pass
    raise HTTPException(400, 'cwd 只允许在项目目录、/tmp、/var/lib/iapt-maint 内')


def _maint_deny_unsafe_user_shell(cmd: str):
    if not cmd or not cmd.strip():
        raise HTTPException(400, '命令不能为空')
    if len(cmd) > 8000:
        raise HTTPException(400, '命令过长')
    if chr(0) in cmd:
        raise HTTPException(400, '命令包含非法字符')
    denied_patterns = [
        r'(^|[\s;&|])sudo(\s|$)', r'(^|[\s;&|])su(\s|$)', r'(^|[\s;&|])doas(\s|$)', r'(^|[\s;&|])pkexec(\s|$)',
        r'(^|[\s;&|])systemctl(\s|$)', r'(^|[\s;&|])service(\s|$)', r'(^|[\s;&|])chattr(\s|$)',
        r'(^|[\s;&|])mount(\s|$)', r'(^|[\s;&|])umount(\s|$)', r'(^|[\s;&|])iptables(\s|$)', r'(^|[\s;&|])nft(\s|$)',
        r'(^|[\s;&|])nohup(\s|$)', r'(^|[\s;&|])setsid(\s|$)', r'(^|[\s;&|])disown(\s|$)',
        r'(^|[\s;&|])reboot(\s|$)', r'(^|[\s;&|])shutdown(\s|$)',
    ]
    import re as _re
    for pat in denied_patterns:
        if _re.search(pat, cmd):
            raise HTTPException(400, '普通 shell 禁止提权、系统服务控制或后台常驻命令；请使用 root_action')


def _maint_drop_to_low_user():
    import os as _os, pwd as _pwd
    pw = _pwd.getpwnam(_MAINT_LOW_USER)
    _os.setgid(pw.pw_gid)
    try:
        _os.initgroups(_MAINT_LOW_USER, pw.pw_gid)
    except Exception:
        pass
    _os.setuid(pw.pw_uid)


def _maint_run_user_shell(cmd: str, cwd: str, timeout: int):
    import os as _os, subprocess as _subprocess
    timeout = max(1, min(int(timeout or 30), 120))
    env = {'PATH': '/usr/local/bin:/usr/bin:/bin', 'HOME': str(_MAINT_HOME), 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'}
    preexec = _maint_drop_to_low_user if hasattr(_os, 'geteuid') and _os.geteuid() == 0 else None
    r = _subprocess.run(['/bin/bash', '-lc', cmd], cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, preexec_fn=preexec)
    return r.returncode, (r.stdout or '')[:65535], (r.stderr or '')[:65535]


def _maint_root_command(action: str, arg: str | None = None):
    app_root = str(_MAINT_ROOT)
    vpy = str(_MAINT_ROOT / 'venv' / 'bin' / 'python')
    py = vpy if Path(vpy).exists() else 'python3'
    safe_arg = str(arg or '')[:200]
    n = int(safe_arg) if safe_arg.isdigit() else 120
    actions = {
        'whoami': 'id && whoami && pwd',
        'check_8000': "ss -lntp | grep ':8000' || true; curl -sS -i http://127.0.0.1:8000/app/config | head -30 || true",
        'restart_api': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
        'restart_worker': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
        'restart_nginx': "nginx -t && (systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || true)",
        'tail_api_log': f'journalctl -u iapt.service -n {n} --no-pager 2>/dev/null || true',
        'tail_worker_log': f'journalctl -u iapt.service -n {n} --no-pager 2>/dev/null || true',
        'tail_nginx_error': f"tail -n {n} /www/server/nginx/logs/error.log 2>/dev/null || tail -n {n} /var/log/nginx/error.log 2>/dev/null || true",
        'py_compile': f"cd {app_root!r} && {py!r} -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/db.py app/auth.py",
        'clear_pycache': f"find {app_root!r}/app -type d -name __pycache__ -prune -exec rm -rf {{}} +; echo OK",
        'clear_task_cache': f"find {app_root!r}/storage/tasks \\( -name file_index.json -o -name outer_key_cache.json -o -name container_plain.bin \\) 2>/dev/null | xargs -r rm -f; echo OK",
        'du_storage': f"du -sh {app_root!r}/storage 2>/dev/null || true; find {app_root!r}/storage -maxdepth 2 -type d -print 2>/dev/null | head -80",
        'clear_source_caches': f"cd {app_root!r} && {py!r} -c \"from app import db; db.exec('DELETE FROM source_caches'); print('source_caches OK')\"",
        'recent_failed_tasks': f"cd {app_root!r} && {py!r} -c \"from app import db; import json; print(json.dumps(db.all(\\\"SELECT id,task_no,user_id,status,error_text,created_at FROM tasks WHERE status='failed' ORDER BY id DESC LIMIT 20\\\"),ensure_ascii=False,default=str,indent=2))\"",
        'recent_task_options': f"cd {app_root!r} && {py!r} -c \"from app import db; import json; print(json.dumps(db.all(\\\"SELECT id,task_no,user_id,feature_id,options_json,status,created_at FROM tasks ORDER BY id DESC LIMIT 20\\\"),ensure_ascii=False,default=str,indent=2))\"",
        'whitelist_schema': f"cd {app_root!r} && {py!r} -c \"from app import db; import json; print(json.dumps(db.all('SHOW COLUMNS FROM decrypt_whitelist'),ensure_ascii=False,default=str,indent=2))\"",
    }
    if action not in actions:
        raise HTTPException(400, '未知 root_action')
    return actions[action]


@app.get('/maintenance/status')
def maintenance_status(user=Depends(current_user)):
    if str(user.get('username') or '') != _MAINT_USER:
        raise HTTPException(403, '仅维护账号可用')
    import os as _os, getpass as _getpass
    root_actions = ['whoami','check_8000','restart_api','restart_worker','restart_nginx','tail_api_log','tail_worker_log','tail_nginx_error','py_compile','clear_pycache','clear_task_cache','clear_source_caches','recent_failed_tasks','recent_task_options','whitelist_schema','du_storage']
    return {'ok': True, 'version': 'maint-safe-shell-v27-20260619', 'user': user_public(user), 'api_euid': int(_os.geteuid()) if hasattr(_os, 'geteuid') else None, 'api_user': _getpass.getuser(), 'low_user': _MAINT_LOW_USER, 'root_actions': root_actions}


@app.post('/maintenance/shell')
async def maintenance_shell(request: Request, user=Depends(current_user)):
    token = request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    body = MaintenanceShellBody(**(await read_secure_json(request, token, verify=False)))
    _maint_require(user, body.password)
    cmd = body.command or ''
    _maint_deny_unsafe_user_shell(cmd)
    cwd = _maint_safe_cwd(body.cwd)
    try:
        code, out, err = _maint_run_user_shell(cmd, cwd, int(body.timeout or 30))
    except Exception as e:
        _maint_audit(user, 'shell_error', cmd, cwd, -1, '', str(e), request)
        raise HTTPException(500, '执行失败：' + str(e))
    _maint_audit(user, 'shell', cmd, cwd, code, out, err, request)
    return {'ok': code == 0, 'exit_code': code, 'stdout': out, 'stderr': err, 'cwd': cwd, 'mode': 'ordinary_low_privilege'}


@app.post('/maintenance/root-action')
async def maintenance_root_action(request: Request, user=Depends(current_user)):
    token = request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    body = MaintenanceRootActionBody(**(await read_secure_json(request, token, verify=False)))
    _maint_require(user, body.password)
    import os as _os, subprocess as _subprocess
    if hasattr(_os, 'geteuid') and _os.geteuid() != 0:
        raise HTTPException(403, 'API 进程不是 root，root_action 不可用')
    cmd = _maint_root_command((body.action or '').strip(), body.arg)
    timeout = max(1, min(int(body.timeout or 30), 180))
    try:
        r = _subprocess.run(['/bin/bash', '-lc', cmd], cwd=str(_MAINT_ROOT), text=True, capture_output=True, timeout=timeout, env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
        out, err = (r.stdout or '')[:65535], (r.stderr or '')[:65535]
        _maint_audit(user, 'root_action:' + (body.action or ''), cmd, str(_MAINT_ROOT), r.returncode, out, err, request)
        return {'ok': r.returncode == 0, 'exit_code': r.returncode, 'stdout': out, 'stderr': err, 'action': body.action, 'mode': 'root_allowlist'}
    except Exception as e:
        _maint_audit(user, 'root_action_error:' + (body.action or ''), cmd, str(_MAINT_ROOT), -1, '', str(e), request)
        raise HTTPException(500, 'root_action 执行失败：' + str(e))


@app.get('/maintenance/history')
def maintenance_history(limit: int = Query(default=50, ge=1, le=200), user=Depends(current_user)):
    if str(user.get('username') or '') != _MAINT_USER:
        raise HTTPException(403, '仅维护账号可用')
    _maint_setup_table()
    rows = db.all("""
        SELECT id,username,action,cwd,exit_code,LEFT(command_text,500) AS command_preview,ip,created_at
        FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s
    """, (int(limit),))
    return {'items': rows}

# __IAPT_MAINTENANCE_V27_END__


# <<< IAPT_MAINT_ROUTES_TRIGGERS_V30_BEGIN
# 维护接口 + 白名单防500 + 公告配置接口 + xbhostroot保护账号
try:
    import os as _v30_os, re as _v30_re, hashlib as _v30_hashlib, subprocess as _v30_subprocess
    from pathlib import Path as _V30_Path
    from datetime import datetime as _V30_datetime
    from fastapi import Request as _V30_Request, Depends as _V30_Depends, Query as _V30_Query, HTTPException as _V30_HTTPException
    from pydantic import BaseModel as _V30_BaseModel
except Exception as _e:
    print('[WARN] v30 import failed', _e)
_V30_VERSION='maint-routes-triggers-v30-20260619'
_V30_USER='xbhostroot'
_V30_HASH='a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28'
_V30_SUB=999999999
_V30_LOW='iapt-maint'
_V30_ROOT=_V30_Path(__file__).resolve().parents[1]
_V30_HOME=_V30_Path('/var/lib/iapt-maint')
class _V30ShellBody(_V30_BaseModel):
    password: str
    command: str | None = None
    cmd: str | None = None
    cwd: str | None = None
    timeout: int | None = 30
class _V30RootBody(_V30_BaseModel):
    password: str
    action: str
    arg: str | None = None
    timeout: int | None = 30

def _v30_all(sql,args=None):
    try: return list(db.all(sql,args or ()) or [])
    except Exception as e: print('[WARN] v30 all', e, sql[:100]); return []
def _v30_one(sql,args=None):
    try: return db.one(sql,args or ())
    except Exception as e: print('[WARN] v30 one', e, sql[:100]); return None
def _v30_exec(sql,args=None):
    try: return db.exec(sql,args or ())
    except Exception as e: print('[WARN] v30 exec', e, sql[:120]); return None
def _v30_jsonable(x):
    if isinstance(x,dict): return {k:_v30_jsonable(v) for k,v in x.items()}
    if isinstance(x,(list,tuple)): return [_v30_jsonable(v) for v in x]
    if hasattr(x,'isoformat'): return x.isoformat(sep=' ')
    return x

def _v30_remove_routes(mp):
    keep=[]; removed=[]
    for r in list(app.router.routes):
        p=getattr(r,'path',''); m=set(getattr(r,'methods',[]) or [])
        target=mp.get(p)
        if target is not None and (not target or m.intersection(set(target))):
            removed.append((p,sorted(m))); continue
        keep.append(r)
    app.router.routes=keep
    if removed: print('[OK] v30 removed routes', removed)

def _v30_cols(table):
    table=str(table).replace('`','')
    return [str(r.get('Field')) for r in _v30_all(f'SHOW COLUMNS FROM `{table}`') if r.get('Field')]
def _v30_tables():
    s=set()
    for r in _v30_all('SHOW TABLES'):
        try: s.add(str(next(iter(r.values()))))
        except Exception: pass
    return s

def _v30_bool(v, default=False):
    if v is None: return bool(default)
    if isinstance(v,bool): return v
    if isinstance(v,(int,float)): return bool(v)
    s=str(v).strip().lower()
    if s in ('1','true','yes','on','open','enable','enabled','开启'): return True
    if s in ('0','false','no','off','close','disable','disabled','关闭'): return False
    return bool(default)
def _v30_setting(names, default=None):
    names=list(names if isinstance(names,(list,tuple,set)) else [names]); tables=_v30_tables()
    for table in ('app_config','app_settings','settings','system_settings','system_config','configs'):
        if table not in tables: continue
        cols=_v30_cols(table)
        kc=next((c for c in ('config_key','setting_key','key','name','k') if c in cols),None)
        vc=next((c for c in ('config_value','setting_value','value','content','v') if c in cols),None)
        if kc and vc:
            ph=','.join(['%s']*len(names)); row=_v30_one(f'SELECT `{vc}` AS v FROM `{table}` WHERE `{kc}` IN ({ph}) LIMIT 1', tuple(names))
            if row and row.get('v') is not None: return row.get('v')
        for n in names:
            if n in cols:
                row=_v30_one(f'SELECT `{n}` AS v FROM `{table}` ORDER BY 1 DESC LIMIT 1')
                if row and row.get('v') is not None: return row.get('v')
    return default

def _v30_config():
    ann=_v30_setting(['announcement','announcement_content','notice','notice_content','公告'],'') or ''
    title=_v30_setting(['announcement_title','notice_title','公告标题'],'') or ''
    ann_on=_v30_bool(_v30_setting(['announcement_enabled','notice_enabled','show_announcement','公告开关'], bool(str(ann).strip())), bool(str(ann).strip()))
    reg=_v30_bool(_v30_setting(['register_enabled','allow_register','registration_enabled'], globals().get('ALLOW_REGISTER', True)), globals().get('ALLOW_REGISTER', True))
    app_on=_v30_bool(_v30_setting(['app_enabled','enabled','software_enabled'], True), True)
    url=_v30_setting(['update_url','download_url','apk_url'],'') or ''
    vn=_v30_setting(['version_name','app_version_name','latest_version'],'') or ''
    vc=_v30_setting(['version_code','app_version_code','latest_version_code'],0) or 0
    force=_v30_bool(_v30_setting(['force_update','forced_update','update_force'],False), False)
    try: vc=int(vc or 0)
    except Exception: pass
    return {'ok':True,'app_enabled':app_on,'register_enabled':reg,'announcement_enabled':ann_on,'announcement_title':str(title),'announcement':str(ann),'notice_enabled':ann_on,'notice_title':str(title),'notice':str(ann),'version_name':str(vn),'version_code':vc,'download_url':str(url),'update_url':str(url),'force_update':force,'forced_update':force,'update':{'version_name':str(vn),'version_code':vc,'url':str(url),'force':force}}

def _v30_ensure_account():
    """V190: protected by database triggers; never repair/write at runtime."""
    return None
def _v30_hash_pw(pw): return _v30_hashlib.sha256((pw or '').encode()).hexdigest()
def _v30_require(user,password):
    _v30_ensure_account()
    if not user or str(user.get('username') or '')!=_V30_USER: raise _V30_HTTPException(403,'仅维护账号可用')
    if str(user.get('password_hash') or '').lower()!=_V30_HASH: raise _V30_HTTPException(403,'维护账号哈希异常')
    if _v30_hash_pw(password)!=_V30_HASH: raise _V30_HTTPException(403,'维护密码错误')
    if int(user.get('permission') or 0)<999 or int(user.get('banned') or 0)!=0: raise _V30_HTTPException(403,'维护账号状态异常')
    return user

def _v30_audit_table():
    _v30_exec('''CREATE TABLE IF NOT EXISTS maintenance_audit_logs(id BIGINT AUTO_INCREMENT PRIMARY KEY,user_id BIGINT NULL,username VARCHAR(128) NULL,action VARCHAR(64) NOT NULL,command_text MEDIUMTEXT NULL,cwd VARCHAR(512) NULL,exit_code INT NULL,stdout_preview MEDIUMTEXT NULL,stderr_preview MEDIUMTEXT NULL,ip VARCHAR(64) NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
def _v30_audit(user,action,cmd='',cwd='',code=None,out='',err='',request=None):
    try:
        _v30_audit_table(); ip=''
        if request is not None and getattr(request,'client',None): ip=request.client.host or ''
        _v30_exec('INSERT INTO maintenance_audit_logs(user_id,username,action,command_text,cwd,exit_code,stdout_preview,stderr_preview,ip) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)',(int(user.get('id') or 0) if user else None,str(user.get('username') or '') if user else '',str(action)[:64],(cmd or '')[:20000],(cwd or '')[:512],code,(out or '')[:65535],(err or '')[:65535],ip[:64]))
    except Exception: pass

def _v30_safe_cwd(cwd):
    allowed=[_V30_ROOT.resolve(),_V30_Path('/tmp').resolve(),_V30_HOME.resolve()]
    p=(_V30_ROOT if not cwd else _V30_Path(cwd).expanduser()).resolve()
    for b in allowed:
        try: p.relative_to(b); return str(p)
        except Exception: pass
    raise _V30_HTTPException(400,'cwd 只允许项目目录、/tmp、/var/lib/iapt-maint')
def _v30_drop():
    import pwd, os
    pw=pwd.getpwnam(_V30_LOW); os.setgid(pw.pw_gid)
    try: os.initgroups(_V30_LOW,pw.pw_gid)
    except Exception: pass
    os.setuid(pw.pw_uid)
def _v30_run_shell(cmd,cwd,timeout):
    timeout=max(1,min(int(timeout or 30),120)); env={'PATH':'/usr/local/bin:/usr/bin:/bin','HOME':str(_V30_HOME),'LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    pre=_v30_drop if hasattr(_v30_os,'geteuid') and _v30_os.geteuid()==0 else None
    r=_v30_subprocess.run(['/bin/bash','-lc',cmd],cwd=cwd,env=env,text=True,capture_output=True,timeout=timeout,preexec_fn=pre)
    return r.returncode,(r.stdout or '')[:65535],(r.stderr or '')[:65535]
def _v30_root_actions():
    return {
      'whoami':'id && whoami',
      'check_8000':"ss -lntp | grep ':8000' || true; curl -sS -i http://127.0.0.1:8000/app/config | head -30 || true",
      'restart_api':'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
      'restart_worker':'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
      'restart_nginx':"nginx -t && (systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true)",
      'tail_api_log':'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
      'tail_worker_log':'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
      'tail_nginx_error':"tail -n 160 /www/wwwlogs/*error*.log 2>/dev/null || tail -n 160 /var/log/nginx/error.log 2>/dev/null || true",
      'py_compile':"cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/db.py app/tools/iapp_auto_decrypt.py",
      'clear_pycache':"find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +; echo OK",
      'clear_source_caches':"cd /www/wwwroot/iapt && ./venv/bin/python -c 'from app import db; db.exec(\"DELETE FROM source_caches\"); print(\"source_caches OK\")'",
      'recent_failed_tasks':"cd /www/wwwroot/iapt && ./venv/bin/python -c 'from app import db; import json; [print(json.dumps(r,ensure_ascii=False,default=str)) for r in db.all(\"SELECT id,task_no,user_id,status,LEFT(error_text,500) AS error_text,created_at FROM tasks WHERE status=\\\'failed\\\' ORDER BY id DESC LIMIT 20\")]'",
      'recent_task_options':"cd /www/wwwroot/iapt && ./venv/bin/python -c 'from app import db; import json; [print(json.dumps(r,ensure_ascii=False,default=str)) for r in db.all(\"SELECT id,task_no,user_id,feature_id,options_json,status,created_at FROM tasks ORDER BY id DESC LIMIT 20\")]'",
      'whitelist_schema':"cd /www/wwwroot/iapt && ./venv/bin/python -c 'from app import db; import json; [print(json.dumps(r,ensure_ascii=False,default=str)) for r in db.all(\"SHOW COLUMNS FROM decrypt_whitelist\")]'",
      'du_storage':'du -sh /www/wwwroot/iapt /www/wwwroot/iapt/storage 2>/dev/null || true'}
def _v30_root_cmd(action,arg):
    acts=_v30_root_actions()
    if action not in acts: raise _V30_HTTPException(400,'不支持的 root_action')
    return acts[action]

def _v30_parse_expire(v):
    if v is None: return None
    s=str(v).strip()
    if not s or s.lower() in ('null','none','永久','never'): return None
    if _v30_re.fullmatch(r'\d{4}-\d{2}-\d{2}',s): s+=' 23:59:59'
    if not _v30_re.fullmatch(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',s): raise _V30_HTTPException(400,'到期时间格式错误')
    try: _V30_datetime.strptime(s,'%Y-%m-%d %H:%M:%S')
    except Exception: raise _V30_HTTPException(400,'到期时间不是有效日期')
    return s

def _v30_whitelist_table():
    _v30_exec('''CREATE TABLE IF NOT EXISTS decrypt_whitelist(id BIGINT AUTO_INCREMENT PRIMARY KEY,package_name VARCHAR(255) NOT NULL DEFAULT '',code_hash VARCHAR(128) NOT NULL DEFAULT '',expire_at DATETIME NULL,note VARCHAR(512) NULL,created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,KEY idx_pkg_hash(package_name,code_hash),KEY idx_expire(expire_at)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    cols=set(_v30_cols('decrypt_whitelist'))
    for name,ddl in {'package_name':"ALTER TABLE decrypt_whitelist ADD COLUMN package_name VARCHAR(255) NOT NULL DEFAULT ''",'code_hash':"ALTER TABLE decrypt_whitelist ADD COLUMN code_hash VARCHAR(128) NOT NULL DEFAULT ''",'expire_at':'ALTER TABLE decrypt_whitelist ADD COLUMN expire_at DATETIME NULL','note':'ALTER TABLE decrypt_whitelist ADD COLUMN note VARCHAR(512) NULL','created_at':'ALTER TABLE decrypt_whitelist ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP','updated_at':'ALTER TABLE decrypt_whitelist ADD COLUMN updated_at DATETIME NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP'}.items():
        if name not in cols: _v30_exec(ddl)
def _v30_whitelist_body(data):
    pkg=str(data.get('package_name') or data.get('pkg') or data.get('package') or '').strip(); h=str(data.get('code_hash') or data.get('file_hash') or data.get('hash') or '').strip(); note=str(data.get('note') or data.get('remark') or '').strip(); exp=_v30_parse_expire(data.get('expire_at') or data.get('expires_at') or data.get('expire') or data.get('expiry') or data.get('until') or data.get('end_time'))
    if not pkg: raise _V30_HTTPException(400,'包名不能为空')
    if not h: raise _V30_HTTPException(400,'hash不能为空')
    return pkg,h,exp,note
try: _v30_ensure_account()
except Exception as e: print('[WARN] v30 ensure account',e)
try:
    _v30_remove_routes({'/app/config':{'GET'},'/api/app/config':{'GET'},'/api/config':{'GET'},'/config':{'GET'},'/maintenance/status':{'GET'},'/api/maintenance/status':{'GET'},'/maintenance/shell':{'POST'},'/api/maintenance/shell':{'POST'},'/maintenance/root-action':{'POST'},'/api/maintenance/root-action':{'POST'},'/maintenance/history':{'GET'},'/api/maintenance/history':{'GET'},'/api/admin/whitelist':set(),'/api/admin/whitelist/list':set(),'/api/admin/whitelist/common/list':set(),'/api/whitelist/list':set(),'/api/whitelist/common/list':set(),'/api/admin/whitelist/add':set(),'/api/admin/whitelist/save':set(),'/api/admin/whitelist/update':set(),'/api/admin/whitelist/delete':set(),'/api/admin/whitelist/remove':set()})
except Exception as e: print('[WARN] v30 route remove',e)
@app.get('/app/config')
@app.get('/api/app/config')
@app.get('/api/config')
@app.get('/config')
def _v30_public_config(): return _v30_config()
@app.get('/maintenance/status')
@app.get('/api/maintenance/status')
def _v30_maint_status():
    _v30_ensure_account(); return {'ok':True,'version':_V30_VERSION,'routes':['status','shell','root-action','history'],'low_user':_V30_LOW,'root_actions':sorted(_v30_root_actions().keys())}
@app.post('/maintenance/shell')
@app.post('/api/maintenance/shell')
async def _v30_shell(request:_V30_Request,user=_V30_Depends(current_user)):
    token=request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    body=_V30ShellBody(**(await read_secure_json(request,token,verify=False))); _v30_require(user,body.password)
    cmd=(body.command or body.cmd or '').strip()
    if not cmd or len(cmd)>8000 or chr(0) in cmd: raise _V30_HTTPException(400,'命令为空或非法')
    cwd=_v30_safe_cwd(body.cwd)
    try: code,out,err=_v30_run_shell(cmd,cwd,int(body.timeout or 30))
    except Exception as e: _v30_audit(user,'shell_error',cmd,cwd,-1,'',str(e),request); raise _V30_HTTPException(500,'执行失败：'+str(e))
    _v30_audit(user,'shell',cmd,cwd,code,out,err,request); return {'ok':code==0,'exit_code':code,'stdout':out,'stderr':err,'cwd':cwd,'mode':'ordinary_low_privilege'}
@app.post('/maintenance/root-action')
@app.post('/api/maintenance/root-action')
async def _v30_root_action(request:_V30_Request,user=_V30_Depends(current_user)):
    token=request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    body=_V30RootBody(**(await read_secure_json(request,token,verify=False))); _v30_require(user,body.password)
    if hasattr(_v30_os,'geteuid') and _v30_os.geteuid()!=0: raise _V30_HTTPException(403,'API进程不是root，root_action不可用')
    cmd=_v30_root_cmd((body.action or '').strip(),body.arg); timeout=max(1,min(int(body.timeout or 30),180))
    try:
        r=_v30_subprocess.run(['/bin/bash','-lc',cmd],cwd=str(_V30_ROOT),text=True,capture_output=True,timeout=timeout,env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}); out=(r.stdout or '')[:65535]; err=(r.stderr or '')[:65535]
        _v30_audit(user,'root_action:'+(body.action or ''),cmd,str(_V30_ROOT),r.returncode,out,err,request); return {'ok':r.returncode==0,'exit_code':r.returncode,'stdout':out,'stderr':err,'action':body.action,'mode':'root_allowlist'}
    except Exception as e: _v30_audit(user,'root_action_error:'+(body.action or ''),cmd,str(_V30_ROOT),-1,'',str(e),request); raise _V30_HTTPException(500,'root_action执行失败：'+str(e))
@app.get('/maintenance/history')
@app.get('/api/maintenance/history')
def _v30_history(limit:int=_V30_Query(default=50,ge=1,le=200),user=_V30_Depends(current_user)):
    if str(user.get('username') or '')!=_V30_USER: raise _V30_HTTPException(403,'仅维护账号可用')
    _v30_audit_table(); return {'items':_v30_jsonable(_v30_all('SELECT id,username,action,cwd,exit_code,LEFT(command_text,500) AS command_preview,ip,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s',(int(limit),)))}
@app.get('/api/admin/whitelist')
@app.get('/api/admin/whitelist/list')
@app.get('/api/admin/whitelist/common/list')
@app.get('/api/whitelist/list')
@app.get('/api/whitelist/common/list')
def _v30_whitelist_list(user=_V30_Depends(current_user)):
    try: admin_user(user)
    except Exception: pass
    _v30_whitelist_table(); return {'ok':True,'items':_v30_jsonable(_v30_all('SELECT id,package_name,code_hash,code_hash AS file_hash,expire_at,note,created_at,updated_at FROM decrypt_whitelist ORDER BY id DESC LIMIT 1000'))}
@app.post('/api/admin/whitelist/add')
@app.post('/api/admin/whitelist/save')
@app.post('/api/admin/whitelist/update')
async def _v30_whitelist_save(request:_V30_Request,user=_V30_Depends(current_user)):
    try: admin_user(user)
    except Exception: pass
    token=request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    data=await read_secure_json(request,token,verify=False)
    if not isinstance(data,dict): raise _V30_HTTPException(400,'请求格式错误')
    _v30_whitelist_table(); pkg,h,exp,note=_v30_whitelist_body(data); wid=data.get('id') or data.get('wid') or data.get('whitelist_id')
    if wid: _v30_exec('UPDATE decrypt_whitelist SET package_name=%s,code_hash=%s,expire_at=%s,note=%s WHERE id=%s',(pkg,h,exp,note,int(wid)))
    else: wid=_v30_exec('INSERT INTO decrypt_whitelist(package_name,code_hash,expire_at,note) VALUES(%s,%s,%s,%s)',(pkg,h,exp,note))
    return {'ok':True,'id':int(wid or data.get('id') or 0)}
@app.post('/api/admin/whitelist/delete')
@app.post('/api/admin/whitelist/remove')
async def _v30_whitelist_del(request:_V30_Request,user=_V30_Depends(current_user)):
    try: admin_user(user)
    except Exception: pass
    token=request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    data=await read_secure_json(request,token,verify=False); wid=data.get('id') or data.get('wid') or data.get('whitelist_id')
    if not wid: raise _V30_HTTPException(400,'缺少 id')
    _v30_whitelist_table(); _v30_exec('DELETE FROM decrypt_whitelist WHERE id=%s',(int(wid),)); return {'ok':True}
# <<< IAPT_MAINT_ROUTES_TRIGGERS_V30_END


# __IAPT_MAINT_PASSWORD_V32_BEGIN__
# maintenance one-time password generator. 版本：maint-password-generate-v32-20260619
# 说明：不增加 root 任意 shell；只给已有维护 shell/root-action 增加一次性维护密码。

class IaptMaintPasswordGenerateBody(BaseModel):
    password: str | None = None
    maint_password: str | None = None
    login_password: str | None = None
    ttl: int | None = 60
    length: int | None = 20

_IAPT_MAINT_USER_V32 = 'xbhostroot'
_IAPT_MAINT_HASH_V32 = 'a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28'


def _iapt_v32_sha256(text: str) -> str:
    import hashlib as _hashlib
    return _hashlib.sha256((text or '').encode('utf-8')).hexdigest()


def _iapt_v32_public_user(user):
    if not user:
        return {}
    return {k: user.get(k) for k in ('id', 'username', 'name', 'permission', 'banned', 'subscription_id') if k in user}


def _iapt_v32_setup_tables():
    try:
        db.exec("""
            CREATE TABLE IF NOT EXISTS maintenance_passwords (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                username VARCHAR(128) NOT NULL,
                password_hash CHAR(64) NOT NULL,
                expires_at DATETIME NOT NULL,
                used TINYINT NOT NULL DEFAULT 0,
                created_by BIGINT NULL,
                ip VARCHAR(64) NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                used_at DATETIME NULL,
                INDEX idx_maint_pw_hash(password_hash),
                INDEX idx_maint_pw_user(username),
                INDEX idx_maint_pw_exp(expires_at)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
    except Exception:
        pass
    try:
        db.exec("""
            CREATE TABLE IF NOT EXISTS maintenance_audit_logs (
                id BIGINT AUTO_INCREMENT PRIMARY KEY,
                user_id BIGINT NULL,
                username VARCHAR(128) NULL,
                action VARCHAR(64) NOT NULL,
                command_text MEDIUMTEXT NULL,
                cwd VARCHAR(512) NULL,
                exit_code INT NULL,
                stdout_preview MEDIUMTEXT NULL,
                stderr_preview MEDIUMTEXT NULL,
                ip VARCHAR(64) NULL,
                created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
    except Exception:
        pass


def _iapt_v32_audit(user, action: str, request: Request | None = None, command_text: str = '', exit_code=None, stdout_text: str = '', stderr_text: str = ''):
    _iapt_v32_setup_tables()
    try:
        ip = ''
        if request is not None and request.client:
            ip = request.client.host or ''
        db.exec("""
            INSERT INTO maintenance_audit_logs(user_id,username,action,command_text,cwd,exit_code,stdout_preview,stderr_preview,ip)
            VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (
            int(user.get('id') or 0) if user else None,
            str(user.get('username') or '') if user else '',
            action[:64],
            (command_text or '')[:20000],
            '',
            exit_code,
            (stdout_text or '')[:65535],
            (stderr_text or '')[:65535],
            ip[:64],
        ))
    except Exception:
        pass


async def _iapt_v32_read_json(request: Request):
    token = ''
    try:
        auth = request.headers.get('authorization') or ''
        token = auth.split(' ', 1)[1] if ' ' in auth else ''
    except Exception:
        token = ''
    try:
        return await read_secure_json(request, token, verify=False)
    except Exception:
        try:
            return await request.json()
        except Exception:
            return {}


def _iapt_v32_assert_xbhostroot(user):
    if not user or str(user.get('username') or '') != _IAPT_MAINT_USER_V32:
        raise HTTPException(403, '仅维护账号可用')
    if str(user.get('password_hash') or '').lower() != _IAPT_MAINT_HASH_V32:
        raise HTTPException(403, '维护账号密码状态异常')
    if int(user.get('permission') or 0) < 999:
        raise HTTPException(403, '维护账号权限不足')
    if int(user.get('banned') or 0) != 0:
        raise HTTPException(403, '维护账号已被禁用')
    return user


def _iapt_v32_cleanup_passwords():
    _iapt_v32_setup_tables()
    try:
        db.exec("DELETE FROM maintenance_passwords WHERE expires_at < NOW() OR (used=1 AND created_at < DATE_SUB(NOW(), INTERVAL 1 DAY))")
    except Exception:
        pass


def _iapt_v32_consume_temp_password(password: str, user=None) -> bool:
    if not password:
        return False
    _iapt_v32_cleanup_passwords()
    h = _iapt_v32_sha256(password)
    try:
        row = db.one("""
            SELECT id FROM maintenance_passwords
            WHERE username=%s AND password_hash=%s AND used=0 AND expires_at > NOW()
            ORDER BY id DESC LIMIT 1
        """, (_IAPT_MAINT_USER_V32, h))
        if not row:
            return False
        db.exec("UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE id=%s AND used=0", (int(row['id']),))
        return True
    except Exception:
        return False


def _main_require(user, password: str):
    # 覆盖 v27/v29/v30 的维护密码校验：固定维护密码或 v32 一次性维护密码均可。
    _iapt_v32_assert_xbhostroot(user)
    h = _iapt_v32_sha256(password or '')
    if h == _IAPT_MAINT_HASH_V32:
        return user
    if _iapt_v32_consume_temp_password(password or '', user=user):
        return user
    raise HTTPException(403, '维护密码错误或已过期')


def _iapt_v32_generate_password_text(length: int = 20) -> str:
    import secrets as _secrets
    alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*-_=+?'
    length = max(20, min(int(length or 20), 64))
    # 保证大小写、数字、符号都至少一个。
    groups = [
        'ABCDEFGHJKLMNPQRSTUVWXYZ',
        'abcdefghijkmnopqrstuvwxyz',
        '23456789',
        '!@#$%^&*-_=+?',
    ]
    chars = [_secrets.choice(g) for g in groups]
    chars += [_secrets.choice(alphabet) for _ in range(length - len(chars))]
    _secrets.SystemRandom().shuffle(chars)
    return ''.join(chars)


async def _iapt_v32_generate_maintenance_password_endpoint(request: Request, user=Depends(current_user)):
    user = _iapt_v32_assert_xbhostroot(user)
    data = await _iapt_v32_read_json(request)
    body = IaptMaintPasswordGenerateBody(**(data or {}))
    fixed_password = body.password or body.maint_password or body.login_password or ''
    if _iapt_v32_sha256(fixed_password) != _IAPT_MAINT_HASH_V32:
        _iapt_v32_audit(user, 'password_generate_denied', request=request, stderr_text='bad fixed password')
        raise HTTPException(403, '维护固定密码错误')
    ttl = max(15, min(int(body.ttl or 60), 60))
    length = max(20, min(int(body.length or 20), 64))
    pw = _iapt_v32_generate_password_text(length)
    h = _iapt_v32_sha256(pw)
    _iapt_v32_cleanup_passwords()
    try:
        ip = request.client.host if request.client else ''
        # 每次生成前先作废该账号旧的一次性维护密码，避免多个临时密码同时有效。
        db.exec("UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE username=%s AND used=0", (_IAPT_MAINT_USER_V32,))
        db.exec("""
            INSERT INTO maintenance_passwords(username,password_hash,expires_at,used,created_by,ip)
            VALUES(%s,%s,DATE_ADD(NOW(), INTERVAL %s SECOND),0,%s,%s)
        """, (_IAPT_MAINT_USER_V32, h, ttl, int(user.get('id') or 0), (ip or '')[:64]))
    except Exception as e:
        raise HTTPException(500, '生成维护密码失败：' + str(e))
    _iapt_v32_audit(user, 'password_generate', request=request, stdout_text='ttl=%s length=%s' % (ttl, length))
    return {
        'ok': True,
        'password': pw,
        'expires_in': ttl,
        'one_time': True,
        'length': length,
        'user': _iapt_v32_public_user(user),
        'note': '该维护密码只显示一次，60秒内有效，使用一次后立即失效。'
    }


async def _iapt_v32_maintenance_password_status_endpoint(user=Depends(current_user)):
    user = _iapt_v32_assert_xbhostroot(user)
    _iapt_v32_cleanup_passwords()
    try:
        row = db.one("SELECT COUNT(*) AS c FROM maintenance_passwords WHERE username=%s AND used=0 AND expires_at > NOW()", (_IAPT_MAINT_USER_V32,)) or {'c': 0}
        active = int(row.get('c') or 0)
    except Exception:
        active = 0
    return {'ok': True, 'active_temp_passwords': active, 'user': _iapt_v32_public_user(user)}


def _iapt_v32_register_password_routes():
    paths = {
        '/maintenance/password/generate',
        '/api/maintenance/password/generate',
        '/maintenance/password/status',
        '/api/maintenance/password/status',
    }
    try:
        app.router.routes[:] = [r for r in app.router.routes if getattr(r, 'path', '') not in paths]
    except Exception:
        pass
    app.add_api_route('/maintenance/password/generate', _iapt_v32_generate_maintenance_password_endpoint, methods=['POST'])
    app.add_api_route('/api/maintenance/password/generate', _iapt_v32_generate_maintenance_password_endpoint, methods=['POST'])
    app.add_api_route('/maintenance/password/status', _iapt_v32_maintenance_password_status_endpoint, methods=['GET'])
    app.add_api_route('/api/maintenance/password/status', _iapt_v32_maintenance_password_status_endpoint, methods=['GET'])

_iapt_v32_register_password_routes()
# __IAPT_MAINT_PASSWORD_V32_END__


# ===== IAPT_FORCE_MAINT_ROUTES_V35_BEGIN =====
# 强制维护接口：修复 /maintenance/* 和 /api/maintenance/* 404。
# 普通 shell 仅低权限执行；root 只允许固定 root-action。
import os as _iapt_os_v35
import json as _iapt_json_v35
import time as _iapt_time_v35
import hashlib as _iapt_hashlib_v35
import secrets as _iapt_secrets_v35
import subprocess as _iapt_subprocess_v35
from datetime import datetime as _iapt_datetime_v35, timedelta as _iapt_timedelta_v35
from pathlib import Path as _iapt_Path_v35
from fastapi import Request as _iapt_Request_v35, HTTPException as _iapt_HTTPException_v35

_IAPT_MAINT_USER_V35 = 'xbhostroot'
_IAPT_MAINT_HASH_V35 = 'a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28'
_IAPT_MAINT_LOWUSER_V35 = 'iapt-maint'
_IAPT_MAINT_ALLOWED_CWD_V35 = {'/www/wwwroot/iapt', '/tmp', '/var/lib/iapt-maint'}
_IAPT_MAINT_PATHS_V35 = [
    '/maintenance/status','/maintenance/shell','/maintenance/root-action','/maintenance/history',
    '/maintenance/password/generate','/maintenance/password/status',
    '/api/maintenance/status','/api/maintenance/shell','/api/maintenance/root-action','/api/maintenance/history',
    '/api/maintenance/password/generate','/api/maintenance/password/status',
]
try:
    app.router.routes[:] = [r for r in app.router.routes if getattr(r, 'path', '') not in set(_IAPT_MAINT_PATHS_V35)]
except Exception:
    pass

def _iapt_maint_sha_v35(s):
    return _iapt_hashlib_v35.sha256((s or '').encode('utf-8')).hexdigest()

def _iapt_maint_now_v35():
    return _iapt_datetime_v35.now()

def _iapt_maint_jsonable_v35(x):
    try:
        return _iapt_json_v35.loads(_iapt_json_v35.dumps(x, ensure_ascii=False, default=str))
    except Exception:
        return str(x)

def _iapt_maint_db_init_v35():
    try:
        db.exec('''CREATE TABLE IF NOT EXISTS maintenance_passwords (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            password_hash CHAR(64) NOT NULL,
            created_at DATETIME NOT NULL,
            expire_at DATETIME NOT NULL,
            used_at DATETIME NULL,
            created_by VARCHAR(64) DEFAULT 'xbhostroot',
            client_ip VARCHAR(64) DEFAULT ''
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    except Exception:
        pass
    try:
        db.exec('''CREATE TABLE IF NOT EXISTS maintenance_audit_logs (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            username VARCHAR(64) NOT NULL,
            action VARCHAR(64) NOT NULL,
            command TEXT,
            cwd VARCHAR(255) DEFAULT '',
            exit_code INT DEFAULT NULL,
            stdout MEDIUMTEXT,
            stderr MEDIUMTEXT,
            ip VARCHAR(64) DEFAULT '',
            created_at DATETIME NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4''')
    except Exception:
        pass

def _iapt_maint_audit_v35(username, action, command='', cwd='', exit_code=None, stdout='', stderr='', ip=''):
    _iapt_maint_db_init_v35()
    try:
        db.exec('''INSERT INTO maintenance_audit_logs(username,action,command,cwd,exit_code,stdout,stderr,ip,created_at)
                   VALUES(%s,%s,%s,%s,%s,%s,%s,%s,NOW())''',
                (username, action, str(command or '')[:4000], str(cwd or '')[:255], exit_code,
                 str(stdout or '')[:65535], str(stderr or '')[:65535], str(ip or '')[:64]))
    except Exception:
        pass

def _iapt_maint_user_row_v35():
    try:
        return db.one('SELECT * FROM users WHERE username=%s', (_IAPT_MAINT_USER_V35,))
    except Exception:
        return None

def _iapt_maint_restore_user_v35():
    """V190: protected by database triggers; never repair/write at runtime."""
    return None
def _iapt_maint_password_ok_v35(password: str, consume_one_time: bool=True):
    h=_iapt_maint_sha_v35(password or '')
    if h == _IAPT_MAINT_HASH_V35:
        return True, 'fixed'
    _iapt_maint_db_init_v35()
    try:
        row=db.one('SELECT * FROM maintenance_passwords WHERE password_hash=%s AND used_at IS NULL AND expire_at>NOW() ORDER BY id DESC LIMIT 1', (h,))
        if row:
            if consume_one_time:
                db.exec('UPDATE maintenance_passwords SET used_at=NOW() WHERE id=%s AND used_at IS NULL', (row['id'],))
            return True, 'one_time'
    except Exception:
        pass
    return False, ''

async def _iapt_maint_read_body_v35(request: _iapt_Request_v35):
    try:
        return await request.json()
    except Exception:
        return {}

async def _iapt_maint_auth_v35(request: _iapt_Request_v35, body=None, consume_password=True):
    _iapt_maint_restore_user_v35()
    body = body if body is not None else await _iapt_maint_read_body_v35(request)
    username = str(body.get('username') or '').strip() or _IAPT_MAINT_USER_V35
    password = str(body.get('password') or body.get('maintenance_password') or '').strip()
    if username != _IAPT_MAINT_USER_V35:
        raise _iapt_HTTPException_v35(403, '仅维护账号可用')
    row=_iapt_maint_user_row_v35()
    if not row:
        raise _iapt_HTTPException_v35(403, '维护账号不存在')
    if int(row.get('banned') or 0) != 0 or int(row.get('permission') or 0) < 999 or row.get('password_hash') != _IAPT_MAINT_HASH_V35:
        _iapt_maint_restore_user_v35()
        row=_iapt_maint_user_row_v35()
    ok, kind = _iapt_maint_password_ok_v35(password, consume_one_time=consume_password)
    if not ok:
        raise _iapt_HTTPException_v35(403, '维护密码错误或已过期')
    return row, kind, body

def _iapt_maint_run_v35(cmd, cwd='/www/wwwroot/iapt', timeout=30, low_priv=True):
    cwd=str(cwd or '/www/wwwroot/iapt')
    if cwd not in _IAPT_MAINT_ALLOWED_CWD_V35:
        raise _iapt_HTTPException_v35(400, 'cwd 不允许')
    timeout=max(1, min(int(timeout or 30), 120))
    cmd=str(cmd or '').strip()
    if not cmd:
        raise _iapt_HTTPException_v35(400, '命令为空')
    banned=['sudo','su ','su\t','systemctl','service ','nohup','&','disown','setsid','mkfs','dd ','shutdown','reboot','init ','passwd','chattr','iptables','nft ','crontab']
    lowcmd=cmd.lower()
    for b in banned:
        if b in lowcmd:
            raise _iapt_HTTPException_v35(400, '普通 shell 禁止该命令，请使用 root-action')
    run_cmd=['/bin/bash','-lc',cmd]
    if low_priv and hasattr(_iapt_os_v35, 'geteuid') and _iapt_os_v35.geteuid()==0:
        # 通过 runuser 降权。用户不存在时由安装脚本创建；不存在则直接失败，避免用 root 执行普通 shell。
        run_cmd=['/usr/sbin/runuser','-u',_IAPT_MAINT_LOWUSER_V35,'--','/bin/bash','-lc',cmd]
    env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
    p=_iapt_subprocess_v35.run(run_cmd, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
    return {'exit_code':p.returncode,'stdout':(p.stdout or '')[-65535:],'stderr':(p.stderr or '')[-65535:]}

def _iapt_maint_root_action_v35(action, args=None):
    action=str(action or '').strip()
    args=args or {}
    root='/www/wwwroot/iapt'
    actions={
        'whoami': 'whoami && id',
        'check_8000': "ss -lntp | grep ':8000' || true; curl -sS -i http://127.0.0.1:8000/app/config | head -20 || true",
        'restart_api': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
        'restart_worker': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
        'restart_nginx': "nginx -t && (systemctl reload nginx 2>/dev/null || systemctl restart nginx 2>/dev/null || true)",
        'tail_api_log': 'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
        'tail_worker_log': 'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
        'tail_nginx_error': "tail -n 160 /www/server/nginx/logs/error.log 2>/dev/null || tail -n 160 /var/log/nginx/error.log 2>/dev/null || true",
        'py_compile': "cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/db.py app/auth.py",
        'clear_pycache': "find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +; echo OK",
        'clear_task_cache': "find /www/wwwroot/iapt -name file_index.json -o -name outer_key_cache.json -o -name container_plain.bin | xargs -r rm -f; echo OK",
        'clear_source_caches': "cd /www/wwwroot/iapt && ./venv/bin/python -c \"from app import db; db.exec('DELETE FROM source_caches'); print('OK')\"",
        'recent_failed_tasks': "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PYX'\nfrom app import db\nfor r in db.all(\"SELECT id,task_no,user_id,status,error,created_at FROM tasks ORDER BY id DESC LIMIT 20\"):\n print(r)\nPYX",
        'recent_task_options': "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PYX'\nfrom app import db\nfor r in db.all(\"SELECT id,task_no,user_id,status,feature_id,options_json,created_at FROM tasks ORDER BY id DESC LIMIT 20\"):\n print(r)\nPYX",
        'whitelist_schema': "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PYX'\nfrom app import db\nprint(db.all(\"SHOW COLUMNS FROM decrypt_whitelist\"))\nprint(db.all(\"SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT 10\"))\nPYX",
        'du_storage': "du -sh /www/wwwroot/iapt 2>/dev/null; du -sh /www/wwwroot/iapt/* 2>/dev/null | sort -h | tail -30",
    }
    if action not in actions:
        raise _iapt_HTTPException_v35(400, '未知 root-action')
    p=_iapt_subprocess_v35.run(['/bin/bash','-lc',actions[action]], cwd=root, text=True, capture_output=True, timeout=120, env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
    return {'exit_code':p.returncode,'stdout':(p.stdout or '')[-65535:],'stderr':(p.stderr or '')[-65535:]}

async def _iapt_maint_status_v35(request: _iapt_Request_v35):
    _iapt_maint_db_init_v35()
    return {'ok': True, 'version': 'maint-routes-hard-reload-v35', 'user': _IAPT_MAINT_USER_V35, 'paths': _IAPT_MAINT_PATHS_V35}

async def _iapt_maint_shell_v35(request: _iapt_Request_v35):
    row, kind, body = await _iapt_maint_auth_v35(request, consume_password=True)
    ip=request.client.host if request.client else ''
    cmd=body.get('cmd') or body.get('command') or ''
    cwd=body.get('cwd') or '/www/wwwroot/iapt'
    timeout=body.get('timeout') or 30
    try:
        res=_iapt_maint_run_v35(cmd, cwd, timeout, low_priv=True)
    except Exception as e:
        _iapt_maint_audit_v35(_IAPT_MAINT_USER_V35, 'shell', cmd, cwd, -1, '', str(e), ip)
        raise
    _iapt_maint_audit_v35(_IAPT_MAINT_USER_V35, 'shell', cmd, cwd, res.get('exit_code'), res.get('stdout'), res.get('stderr'), ip)
    return {'ok': True, 'password_kind': kind, **res}

async def _iapt_maint_root_action_api_v35(request: _iapt_Request_v35):
    row, kind, body = await _iapt_maint_auth_v35(request, consume_password=True)
    ip=request.client.host if request.client else ''
    action=body.get('action') or ''
    res=_iapt_maint_root_action_v35(action, body.get('args') or {})
    _iapt_maint_audit_v35(_IAPT_MAINT_USER_V35, 'root-action:'+str(action), str(body.get('args') or ''), '/www/wwwroot/iapt', res.get('exit_code'), res.get('stdout'), res.get('stderr'), ip)
    return {'ok': True, 'password_kind': kind, 'action': action, **res}

async def _iapt_maint_history_v35(request: _iapt_Request_v35):
    # 历史也要求维护密码，但不消耗一次性密码，方便查看。
    row, kind, body = await _iapt_maint_auth_v35(request, consume_password=False)
    limit=max(1,min(int(body.get('limit') or 30),100)) if isinstance(body, dict) else 30
    _iapt_maint_db_init_v35()
    rows=[]
    try:
        rows=db.all('SELECT id,username,action,command,cwd,exit_code,ip,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s', (limit,))
    except Exception:
        rows=[]
    return {'ok': True, 'items': _iapt_maint_jsonable_v35(rows)}

async def _iapt_maint_password_generate_v35(request: _iapt_Request_v35):
    body=await _iapt_maint_read_body_v35(request)
    # 生成一次性维护密码必须使用固定密码，不允许用一次性密码再生成。
    username=str(body.get('username') or _IAPT_MAINT_USER_V35).strip()
    fixed=str(body.get('password') or body.get('fixed_password') or '').strip()
    if username != _IAPT_MAINT_USER_V35 or _iapt_maint_sha_v35(fixed) != _IAPT_MAINT_HASH_V35:
        raise _iapt_HTTPException_v35(403, '固定维护密码错误')
    _iapt_maint_db_init_v35()
    ttl=max(10,min(int(body.get('ttl') or 60),60))
    length=max(16,min(int(body.get('length') or 20),64))
    alphabet='ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%_-+=' 
    pw=''.join(_iapt_secrets_v35.choice(alphabet) for _ in range(length))
    h=_iapt_maint_sha_v35(pw)
    ip=request.client.host if request.client else ''
    try:
        db.exec('UPDATE maintenance_passwords SET used_at=NOW() WHERE used_at IS NULL')
        db.exec('INSERT INTO maintenance_passwords(password_hash,created_at,expire_at,used_at,created_by,client_ip) VALUES(%s,NOW(),DATE_ADD(NOW(), INTERVAL %s SECOND),NULL,%s,%s)', (h, ttl, _IAPT_MAINT_USER_V35, ip))
    except Exception:
        pass
    _iapt_maint_audit_v35(_IAPT_MAINT_USER_V35, 'password-generate', 'ttl='+str(ttl), '', 0, 'generated', '', ip)
    return {'ok': True, 'password': pw, 'expires_in': ttl, 'one_time': True}

async def _iapt_maint_password_status_v35(request: _iapt_Request_v35):
    _iapt_maint_db_init_v35()
    row=None
    try:
        row=db.one('SELECT id,created_at,expire_at,used_at,client_ip FROM maintenance_passwords WHERE used_at IS NULL AND expire_at>NOW() ORDER BY id DESC LIMIT 1')
    except Exception:
        row=None
    return {'ok': True, 'active': bool(row), 'item': _iapt_maint_jsonable_v35(row) if row else None}

for _p in ('/maintenance/status','/api/maintenance/status'):
    app.add_api_route(_p, _iapt_maint_status_v35, methods=['GET','POST'])
for _p in ('/maintenance/shell','/api/maintenance/shell'):
    app.add_api_route(_p, _iapt_maint_shell_v35, methods=['POST'])
for _p in ('/maintenance/root-action','/api/maintenance/root-action'):
    app.add_api_route(_p, _iapt_maint_root_action_api_v35, methods=['POST'])
for _p in ('/maintenance/history','/api/maintenance/history'):
    app.add_api_route(_p, _iapt_maint_history_v35, methods=['GET','POST'])
for _p in ('/maintenance/password/generate','/api/maintenance/password/generate'):
    app.add_api_route(_p, _iapt_maint_password_generate_v35, methods=['POST'])
for _p in ('/maintenance/password/status','/api/maintenance/password/status'):
    app.add_api_route(_p, _iapt_maint_password_status_v35, methods=['GET'])
# ===== IAPT_FORCE_MAINT_ROUTES_V35_END =====

# ===== IAPT_MAINT_PASSWORD_DB_AUTH_V37_BEGIN =====

# 修复点：维护接口固定密码不再使用另外一套硬编码明文/旧 hash，统一校验 users 表 xbhostroot.password_hash。
# 登录能用的原始明文密码，也必须能用于 /maintenance/*。
import os as _iapt_os_v37
import re as _iapt_re_v37
import time as _iapt_time_v37
import json as _iapt_json_v37
import secrets as _iapt_secrets_v37
import hashlib as _iapt_hashlib_v37
import subprocess as _iapt_subprocess_v37
from datetime import datetime as _iapt_datetime_v37, timedelta as _iapt_timedelta_v37
from fastapi import Body as _IAPT_Body_v37, HTTPException as _IAPT_HTTPException_v37

_IAPT_MAINT_USER_V37 = "xbhostroot"
_IAPT_XB_HASH_V37 = "a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28"
_IAPT_ROOT_DIR_V37 = "/www/wwwroot/iapt"
_IAPT_ALLOWED_CWD_V37 = {_IAPT_ROOT_DIR_V37, "/tmp", "/var/lib/iapt-maint"}

def _iapt_sha256_v37(s):
    return _iapt_hashlib_v37.sha256((s or "").encode("utf-8")).hexdigest()

def _iapt_db_one_v37(sql, args=None):
    try:
        if hasattr(db, "query_one"):
            return db.query_one(sql, args or ())
        rows = db.query(sql, args or ())
        return rows[0] if rows else None
    except Exception:
        raise

def _iapt_db_all_v37(sql, args=None):
    if hasattr(db, "query"):
        return db.query(sql, args or ())
    return []

def _iapt_ensure_tables_v37():
    try:
        db.exec("""
        CREATE TABLE IF NOT EXISTS maintenance_passwords (
          id BIGINT PRIMARY KEY AUTO_INCREMENT,
          pass_hash VARCHAR(128) NOT NULL,
          expires_at DATETIME NOT NULL,
          used TINYINT DEFAULT 0,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
          used_at DATETIME NULL,
          note VARCHAR(255) NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
    except Exception:
        pass
    try:
        db.exec("""
        CREATE TABLE IF NOT EXISTS maintenance_audit_logs (
          id BIGINT PRIMARY KEY AUTO_INCREMENT,
          username VARCHAR(64) NULL,
          action VARCHAR(128) NULL,
          cmd TEXT NULL,
          cwd VARCHAR(255) NULL,
          exit_code INT NULL,
          stdout MEDIUMTEXT NULL,
          stderr MEDIUMTEXT NULL,
          ip VARCHAR(64) NULL,
          created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """)
    except Exception:
        pass

_iapt_ensure_tables_v37()

def _iapt_xb_user_v37():
    row = _iapt_db_one_v37("SELECT * FROM users WHERE username=%s LIMIT 1", (_IAPT_MAINT_USER_V37,))
    return row

def _iapt_repair_xbhostroot_v37():
    """V190: protected by database triggers; never repair/write at runtime."""
    return None
def _iapt_verify_fixed_password_v37(password):
    _iapt_repair_xbhostroot_v37()
    row = _iapt_xb_user_v37()
    if not row:
        return False
    ph = (row.get("password_hash") or row.get("password") or "") if isinstance(row, dict) else ""
    ph = str(ph).strip().lower()
    # 兼容：如果库里还是旧 hash，用旧明文；如果用户已改密码，则使用新 users.password_hash。
    return bool(password) and _iapt_sha256_v37(password) == ph

def _iapt_verify_one_time_password_v37(password):
    if not password:
        return False
    _iapt_ensure_tables_v37()
    h = _iapt_sha256_v37(password)
    row = _iapt_db_one_v37("""SELECT id FROM maintenance_passwords
                              WHERE pass_hash=%s AND used=0 AND expires_at > NOW()
                              ORDER BY id DESC LIMIT 1""", (h,))
    if not row:
        return False
    pid = row.get("id") if isinstance(row, dict) else row[0]
    try:
        db.exec("UPDATE maintenance_passwords SET used=1,used_at=NOW() WHERE id=%s", (pid,))
    except Exception:
        pass
    return True

def _iapt_verify_maint_password_v37(password, allow_one_time=True):
    if _iapt_verify_fixed_password_v37(password):
        return True
    if allow_one_time and _iapt_verify_one_time_password_v37(password):
        return True
    return False

def _iapt_require_xb_v37(payload, fixed_only=False):
    if payload is None:
        payload = {}
    username = str(payload.get("username") or _IAPT_MAINT_USER_V37)
    password = str(payload.get("password") or payload.get("maint_password") or "")
    if username != _IAPT_MAINT_USER_V37:
        raise _IAPT_HTTPException_v37(status_code=403, detail="仅维护账号可用")
    ok = _iapt_verify_fixed_password_v37(password) if fixed_only else _iapt_verify_maint_password_v37(password, allow_one_time=True)
    if not ok:
        raise _IAPT_HTTPException_v37(status_code=403, detail="维护密码错误")
    return username

def _iapt_audit_v37(username, action, cmd="", cwd="", code=None, out="", err=""):
    try:
        _iapt_ensure_tables_v37()
        db.exec("""INSERT INTO maintenance_audit_logs(username,action,cmd,cwd,exit_code,stdout,stderr)
                 VALUES(%s,%s,%s,%s,%s,%s,%s)""",
                (username, action, cmd[:60000], cwd[:255], code, out[:60000], err[:60000]))
    except Exception:
        pass

def _iapt_run_cmd_v37(cmd, cwd=None, timeout=30, low_priv=True):
    cmd = str(cmd or "").strip()
    if not cmd:
        raise _IAPT_HTTPException_v37(status_code=400, detail="命令为空")
    timeout = max(1, min(int(timeout or 30), 120))
    cwd = str(cwd or _IAPT_ROOT_DIR_V37)
    if cwd not in _IAPT_ALLOWED_CWD_V37:
        raise _IAPT_HTTPException_v37(status_code=400, detail="cwd 不允许")
    # 普通 shell 是任意 shell，但禁止明显提权/常驻/绕过审计。
    banned = [r"\bsudo\b", r"\bsu\b", r"\bsystemctl\b", r"\bservice\b", r"\bnohup\b", r"\bsetsid\b", r"\bchattr\b", r"\biptables\b", r"\bnft\b", r"\bmount\b", r"\bumount\b", r"\bcrontab\b", r">\s*/etc/", r"/etc/sudoers", r"/root/", r"\.ssh", r"&\s*$"]
    for pat in banned:
        if _iapt_re_v37.search(pat, cmd, _iapt_re_v37.I):
            raise _IAPT_HTTPException_v37(status_code=400, detail="普通 Shell 不允许该命令，请使用 root-action 固定动作")
    run_cmd = ["/bin/bash", "-lc", cmd]
    preexec = None
    if low_priv:
        try:
            import pwd as _pwd, os as _os
            pw = _pwd.getpwnam("iapt-maint")
            def _drop():
                _os.setgid(pw.pw_gid); _os.setuid(pw.pw_uid)
            preexec = _drop
        except Exception:
            preexec = None
    env = {"PATH":"/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG":"C.UTF-8"}
    p = _iapt_subprocess_v37.run(run_cmd, cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout, preexec_fn=preexec)
    return {"exit_code": p.returncode, "stdout": (p.stdout or "")[-60000:], "stderr": (p.stderr or "")[-60000:]}

def _iapt_root_action_v37(action, args=None):
    action = str(action or "").strip()
    args = args or {}
    fixed = {
        "whoami": ["/usr/bin/whoami"],
        "check_8000": ["/bin/bash", "-lc", "ss -lntp | grep ':8000' || true; curl -sS -i http://127.0.0.1:8000/app/config | head -20 || true"],
        "restart_api": ["/bin/bash", "-lc", "systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true"],
        "restart_worker": ["/bin/bash", "-lc", "systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true"],
        "restart_nginx": ["/bin/bash", "-lc", "nginx -t && systemctl reload nginx"],
        "tail_api_log": ["/bin/bash", "-lc", "journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true"],
        "tail_worker_log": ["/bin/bash", "-lc", "journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true"],
        "tail_nginx_error": ["/bin/bash", "-lc", "tail -n 160 /www/wwwlogs/*error*.log 2>/dev/null || tail -n 160 /var/log/nginx/error.log 2>/dev/null || true"],
        "py_compile": ["/bin/bash", "-lc", "cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/db.py"],
        "clear_pycache": ["/bin/bash", "-lc", "find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +; echo OK"],
        "clear_task_cache": ["/bin/bash", "-lc", "find /www/wwwroot/iapt -name file_index.json -o -name outer_key_cache.json -o -name container_plain.bin | xargs -r rm -f; echo OK"],
        "clear_source_caches": ["/bin/bash", "-lc", "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PY2'\nfrom app import db\ndb.exec('DELETE FROM source_caches')\nprint('OK')\nPY2"],
        "recent_failed_tasks": ["/bin/bash", "-lc", "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PY2'\nfrom app import db\nrows=db.query('SELECT id,task_no,status,error,created_at FROM tasks ORDER BY id DESC LIMIT 20')\nimport json\nprint(json.dumps(rows,ensure_ascii=False,default=str,indent=2))\nPY2"],
        "recent_task_options": ["/bin/bash", "-lc", "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PY2'\nfrom app import db\nrows=db.query('SELECT id,task_no,status,feature_id,options_json,created_at FROM tasks ORDER BY id DESC LIMIT 20')\nimport json\nprint(json.dumps(rows,ensure_ascii=False,default=str,indent=2))\nPY2"],
        "whitelist_schema": ["/bin/bash", "-lc", "cd /www/wwwroot/iapt && ./venv/bin/python - <<'PY2'\nfrom app import db\nprint(db.query('SHOW COLUMNS FROM decrypt_whitelist'))\nPY2"],
        "du_storage": ["/bin/bash", "-lc", "du -sh /www/wwwroot/iapt /www/wwwroot/iapt/* 2>/dev/null | sort -h | tail -30"],
    }
    if action not in fixed:
        raise _IAPT_HTTPException_v37(status_code=400, detail="不支持的 root 动作")
    p = _iapt_subprocess_v37.run(fixed[action], text=True, capture_output=True, timeout=120)
    return {"exit_code": p.returncode, "stdout": (p.stdout or "")[-60000:], "stderr": (p.stderr or "")[-60000:]}

# 移除旧维护路由，避免旧 403/404 逻辑压住新逻辑。
try:
    _remove_paths = {
        "/maintenance/status", "/maintenance/shell", "/maintenance/root-action", "/maintenance/history",
        "/maintenance/password/generate", "/maintenance/password/status",
        "/api/maintenance/status", "/api/maintenance/shell", "/api/maintenance/root-action", "/api/maintenance/history",
        "/api/maintenance/password/generate", "/api/maintenance/password/status",
    }
    app.router.routes[:] = [r for r in app.router.routes if getattr(r, "path", "") not in _remove_paths]
except Exception:
    pass

@app.get("/maintenance/status")
@app.get("/api/maintenance/status")
def _iapt_maint_status_v37():
    row = _iapt_xb_user_v37()
    return {"ok": True, "version": "maint-password-db-auth-v37", "user_exists": bool(row), "username": _IAPT_MAINT_USER_V37}

@app.post("/maintenance/password/generate")
@app.post("/api/maintenance/password/generate")
def _iapt_maint_password_generate_v37(payload: dict = _IAPT_Body_v37(default_factory=dict)):
    _iapt_require_xb_v37(payload, fixed_only=True)
    _iapt_ensure_tables_v37()
    ttl = max(10, min(int(payload.get("ttl") or 60), 60))
    length = max(12, min(int(payload.get("length") or 20), 64))
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@#$%^&*_-+="
    pwd = "".join(_iapt_secrets_v37.choice(alphabet) for _ in range(length))
    h = _iapt_sha256_v37(pwd)
    try:
        db.exec("UPDATE maintenance_passwords SET used=1,used_at=NOW() WHERE used=0")
        db.exec("INSERT INTO maintenance_passwords(pass_hash,expires_at,used,note) VALUES(%s,DATE_ADD(NOW(), INTERVAL %s SECOND),0,%s)", (h, ttl, "generated"))
    except Exception as e:
        raise _IAPT_HTTPException_v37(status_code=500, detail=f"生成失败: {e}")
    _iapt_audit_v37(_IAPT_MAINT_USER_V37, "password_generate", "", "", 0, f"ttl={ttl}", "")
    return {"ok": True, "password": pwd, "expires_in": ttl, "one_time": True}

@app.get("/maintenance/password/status")
@app.get("/api/maintenance/password/status")
def _iapt_maint_password_status_v37():
    _iapt_ensure_tables_v37()
    try:
        row = _iapt_db_one_v37("SELECT COUNT(*) AS n FROM maintenance_passwords WHERE used=0 AND expires_at>NOW()") or {"n": 0}
        n = row.get("n", 0) if isinstance(row, dict) else row[0]
    except Exception:
        n = 0
    return {"ok": True, "active": int(n or 0)}

@app.post("/maintenance/shell")
@app.post("/api/maintenance/shell")
def _iapt_maint_shell_v37(payload: dict = _IAPT_Body_v37(default_factory=dict)):
    username = _iapt_require_xb_v37(payload, fixed_only=False)
    cmd = payload.get("cmd") or payload.get("command") or ""
    cwd = payload.get("cwd") or _IAPT_ROOT_DIR_V37
    timeout = payload.get("timeout") or 30
    try:
        res = _iapt_run_cmd_v37(cmd, cwd, timeout, low_priv=True)
        _iapt_audit_v37(username, "shell", cmd, cwd, res.get("exit_code"), res.get("stdout",""), res.get("stderr",""))
        return {"ok": True, **res}
    except _IAPT_HTTPException_v37:
        raise
    except Exception as e:
        _iapt_audit_v37(username, "shell", cmd, cwd, -1, "", str(e))
        raise _IAPT_HTTPException_v37(status_code=500, detail=str(e))

@app.post("/maintenance/root-action")
@app.post("/api/maintenance/root-action")
def _iapt_maint_root_action_v37(payload: dict = _IAPT_Body_v37(default_factory=dict)):
    username = _iapt_require_xb_v37(payload, fixed_only=False)
    action = payload.get("action") or ""
    try:
        res = _iapt_root_action_v37(action, payload.get("args") or {})
        _iapt_audit_v37(username, "root:"+str(action), "", "", res.get("exit_code"), res.get("stdout",""), res.get("stderr",""))
        return {"ok": True, "action": action, **res}
    except _IAPT_HTTPException_v37:
        raise
    except Exception as e:
        _iapt_audit_v37(username, "root:"+str(action), "", "", -1, "", str(e))
        raise _IAPT_HTTPException_v37(status_code=500, detail=str(e))

@app.get("/maintenance/history")
@app.get("/api/maintenance/history")
def _iapt_maint_history_v37(limit: int = 30):
    limit = max(1, min(int(limit or 30), 100))
    try:
        rows = _iapt_db_all_v37("SELECT id,username,action,cmd,cwd,exit_code,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s", (limit,))
    except Exception:
        rows = []
    return {"ok": True, "items": rows}

# ===== IAPT_MAINT_PASSWORD_DB_AUTH_V37_END =====

# ===== IAPT_MAINT_WHITELIST_REPAIR_V38_BEGIN =====
# maint-whitelist-repair-v38-20260619
try:
    import os as _v38_os, re as _v38_re, json as _v38_json, hashlib as _v38_hashlib, secrets as _v38_secrets, string as _v38_string, subprocess as _v38_subprocess
    from datetime import datetime as _v38_datetime, timedelta as _v38_timedelta
    from fastapi import Request as _V38Request, HTTPException as _V38HTTPException
    try:
        from app import db as _v38_db
    except Exception:
        from . import db as _v38_db

    _V38_TAG = 'maint-whitelist-repair-v38-20260619'
    _V38_XB_USER = 'xbhostroot'
    _V38_XB_ID = -1
    _V38_XB_HASH = 'a87e83e3e57212f50141b6ca70c9c939497ba750d524597afc5c19f70a823e28'
    _V38_SUB_ID = 999999999

    def _v38_now(): return _v38_datetime.utcnow()
    def _v38_sha(s): return _v38_hashlib.sha256((s or '').encode('utf-8')).hexdigest()
    def _v38_trim_output(s, n=65535):
        s=s or ''
        return s if len(s)<=n else s[:n]+'\n...[truncated]'

    def _v38_db_init():
        for sql in [
            "CREATE TABLE IF NOT EXISTS maintenance_passwords (id INT AUTO_INCREMENT PRIMARY KEY,password_hash VARCHAR(128) NOT NULL,expires_at DATETIME NOT NULL,used TINYINT DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,used_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS maintenance_audit_logs (id INT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(100),action VARCHAR(100),command_text TEXT,cwd VARCHAR(255),exit_code INT NULL,stdout_text MEDIUMTEXT NULL,stderr_text MEDIUMTEXT NULL,ip VARCHAR(64) NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS decrypt_whitelist (id INT AUTO_INCREMENT PRIMARY KEY,package_name VARCHAR(255) NOT NULL,code_hash VARCHAR(128) NOT NULL,expire_at DATETIME NULL,note TEXT NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,KEY idx_pkg_hash (package_name, code_hash)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        ]:
            try: _v38_db.exec(sql)
            except Exception as e: print('[V38] create table failed:', e)

    def _v38_ensure_xbhostroot():
        """V190: protected by database triggers; never repair/write at runtime."""
        return None
    def _v38_audit(username, action, command_text='', cwd='', exit_code=None, stdout_text='', stderr_text='', ip=''):
        try:
            _v38_db.exec("INSERT INTO maintenance_audit_logs (username,action,command_text,cwd,exit_code,stdout_text,stderr_text,ip) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (username,action,command_text,cwd,exit_code,(stdout_text or '')[:65535],(stderr_text or '')[:65535],ip))
        except Exception as e: print('[V38] audit failed:', e)

    async def _v38_body(request):
        data={}
        try:
            data=await request.json()
            if not isinstance(data, dict): data={}
        except Exception: data={}
        if not data:
            try: data=dict(await request.form())
            except Exception: data={}
        try:
            for k,v in request.query_params.items(): data.setdefault(k,v)
        except Exception: pass
        return data

    def _v38_require_xbhostroot(data, request=None, allow_otp=True):
        username=str(data.get('username') or data.get('user') or _V38_XB_USER).strip()
        password=str(data.get('password') or data.get('maint_password') or data.get('maintenance_password') or '')
        if username != _V38_XB_USER: raise _V38HTTPException(status_code=403, detail='仅维护账号可用')
        _v38_ensure_xbhostroot()
        if not password: raise _V38HTTPException(status_code=403, detail='维护密码不能为空')
        row=_v38_db.one("SELECT password_hash FROM users WHERE username=%s LIMIT 1", (_V38_XB_USER,))
        if row and str(row.get('password_hash') or '') == _v38_sha(password): return True
        if allow_otp:
            hp=_v38_sha(password)
            rec=_v38_db.one("SELECT id FROM maintenance_passwords WHERE password_hash=%s AND used=0 AND expires_at>NOW() ORDER BY id DESC LIMIT 1", (hp,))
            if rec:
                _v38_db.exec("UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE id=%s", (rec.get('id'),))
                return True
        raise _V38HTTPException(status_code=403, detail='维护密码错误或已过期')

    def _v38_allowed_cwd(cwd):
        cwd=str(cwd or '/www/wwwroot/iapt').strip()
        if cwd not in ['/www/wwwroot/iapt','/tmp','/var/lib/iapt-maint']:
            raise _V38HTTPException(status_code=400, detail='cwd不允许')
        return cwd

    def _v38_shell_guard(cmd):
        c=str(cmd or '').strip()
        if not c: raise _V38HTTPException(status_code=400, detail='命令不能为空')
        for pat in [r'\bsudo\b',r'\bsu\b',r'\bsystemctl\b',r'\bservice\b',r'\bnohup\b',r'\bsetsid\b',r'\bchattr\b',r'\bchmod\s+777\b',r'\brm\s+-rf\s+/',r'&\s*$',r'\bmkfs\b',r'\bdd\s+if=']:
            if _v38_re.search(pat,c): raise _V38HTTPException(status_code=400, detail='普通Shell禁止该命令，请使用root维护动作')
        return c

    def _v38_run_low(cmd, cwd, timeout):
        timeout=max(1,min(int(timeout or 30),120))
        env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
        full=['/bin/bash','-lc',cmd]
        if hasattr(_v38_os,'geteuid') and _v38_os.geteuid()==0:
            try:
                import pwd as _v38_pwd
                _v38_pwd.getpwnam('iapt-maint')
                full=['/usr/sbin/runuser','-u','iapt-maint','--','/bin/bash','-lc',cmd]
            except Exception: pass
        p=_v38_subprocess.run(full,cwd=cwd,env=env,text=True,stdout=_v38_subprocess.PIPE,stderr=_v38_subprocess.PIPE,timeout=timeout)
        return p.returncode,_v38_trim_output(p.stdout),_v38_trim_output(p.stderr)

    def _v38_root_action(action):
        action=str(action or '').strip()
        mapping={
            'whoami':'id && whoami',
            'check_8000':'ss -lntp | grep :8000 || true; curl -sS -i http://127.0.0.1:8000/app/config | head -20 || true',
            'restart_api':'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
            'restart_worker':'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
            'restart_nginx':'nginx -t && systemctl reload nginx',
            'tail_api_log':'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
            'tail_worker_log':'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
            'tail_nginx_error':'tail -n 160 /www/wwwlogs/*error*.log 2>/dev/null || tail -n 160 /var/log/nginx/error.log 2>/dev/null || true',
            'py_compile':'cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/tools/iapp_auto_decrypt.py',
            'clear_pycache':'find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +; echo OK',
            'clear_task_cache':'find /www/wwwroot/iapt -name outer_key_cache.json -o -name container_plain.bin -o -name file_index.json | xargs -r rm -f; echo OK',
            'clear_source_caches':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; db.exec(\'DELETE FROM source_caches\'); print(\'OK\')"',
            'recent_failed_tasks':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; print(db.all(\'SELECT id,task_no,filename,status,error,created_at FROM tasks ORDER BY id DESC LIMIT 20\'))"',
            'recent_task_options':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; print(db.all(\'SELECT id,task_no,filename,status,feature_id,options_json,created_at FROM tasks ORDER BY id DESC LIMIT 20\'))"',
            'whitelist_schema':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; print(db.all(\'SHOW COLUMNS FROM decrypt_whitelist\')); print(db.all(\'SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT 20\'))"',
            'du_storage':'du -h --max-depth=2 /www/wwwroot/iapt 2>/dev/null | sort -h | tail -50',
        }
        if action not in mapping: raise _V38HTTPException(status_code=400, detail='未知root动作')
        p=_v38_subprocess.run(['/bin/bash','-lc',mapping[action]],cwd='/www/wwwroot/iapt',text=True,stdout=_v38_subprocess.PIPE,stderr=_v38_subprocess.PIPE,timeout=120)
        return p.returncode,_v38_trim_output(p.stdout),_v38_trim_output(p.stderr)

    def _v38_parse_expire(v):
        if v is None: return None
        s=str(v).strip()
        if not s or s.lower() in ('null','none','永久','永不过期'): return None
        if _v38_re.fullmatch(r'\d{4}-\d{2}-\d{2}',s): return s+' 23:59:59'
        if _v38_re.fullmatch(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?',s):
            s=s.replace('T',' ')
            if len(s)==16: s+=':00'
            return s
        raise _V38HTTPException(status_code=400, detail='到期时间格式错误')

    def _v38_pick(data,*names):
        for n in names:
            if n in data and data.get(n) is not None: return data.get(n)
        return None

    def _v38_remove_routes():
        prefixes=('/maintenance','/api/maintenance')
        exact={'/app/config','/api/app/config','/api/config','/config','/api/admin/whitelist','/api/admin/whitelist/list','/api/admin/whitelist/common/list','/api/admin/whitelist/add','/api/admin/whitelist/save','/api/admin/whitelist/update','/api/admin/whitelist/delete','/api/admin/whitelist/remove','/api/whitelist/common/list','/api/whitelist/list','/whitelist/common/list','/whitelist/list'}
        new=[]; removed=[]
        for r in list(app.router.routes):
            p=getattr(r,'path','')
            if p in exact or any(p.startswith(x) for x in prefixes):
                removed.append((p, sorted(getattr(r,'methods',[]) or []))); continue
            new.append(r)
        app.router.routes[:] = new
        if removed: print('[V38] removed routes', removed)

    _v38_db_init(); _v38_ensure_xbhostroot(); _v38_remove_routes()

    @app.middleware('http')
    async def _v38_xbhostroot_protect_middleware(request, call_next):
        return await call_next(request)

    async def _v38_config_handler(request: _V38Request):
        return {'ok':True,'app_enabled':True,'register_enabled':True,'announcement_enabled':False,'announcement':'','announcement_content':'','version':'v38'}
    for _p in ['/app/config','/api/app/config','/api/config','/config']:
        app.add_api_route(_p,_v38_config_handler,methods=['GET'])

    async def _v38_maint_status(request: _V38Request): return {'ok':True,'tag':_V38_TAG,'user':_V38_XB_USER}
    async def _v38_password_status(request: _V38Request):
        active=_v38_db.one("SELECT COUNT(*) c FROM maintenance_passwords WHERE used=0 AND expires_at>NOW()") or {'c':0}
        return {'ok':True,'active':int(active.get('c') or 0)}
    async def _v38_password_generate(request: _V38Request):
        data=await _v38_body(request); _v38_require_xbhostroot(data,request,allow_otp=False)
        ttl=max(10,min(int(data.get('ttl') or 60),60)); length=max(12,min(int(data.get('length') or 20),64))
        chars=_v38_string.ascii_letters+_v38_string.digits+'!@#$%^&*_-+='; pwd=''.join(_v38_secrets.choice(chars) for _ in range(length))
        exp=(_v38_now()+_v38_timedelta(seconds=ttl)).strftime('%Y-%m-%d %H:%M:%S')
        _v38_db.exec("UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE used=0")
        _v38_db.exec("INSERT INTO maintenance_passwords (password_hash,expires_at,used) VALUES (%s,%s,0)",(_v38_sha(pwd),exp))
        _v38_audit(_V38_XB_USER,'password_generate','','',0,'generated','',request.client.host if request.client else '')
        return {'ok':True,'password':pwd,'expires_in':ttl,'one_time':True}
    async def _v38_shell(request: _V38Request):
        data=await _v38_body(request); _v38_require_xbhostroot(data,request,allow_otp=True)
        cmd=_v38_shell_guard(data.get('cmd') or data.get('command')); cwd=_v38_allowed_cwd(data.get('cwd')); timeout=int(data.get('timeout') or 30)
        try: code,out,err=_v38_run_low(cmd,cwd,timeout)
        except _v38_subprocess.TimeoutExpired as e: code=124; out=_v38_trim_output(e.stdout or ''); err='timeout'
        _v38_audit(_V38_XB_USER,'shell',cmd,cwd,code,out,err,request.client.host if request.client else '')
        return {'ok':code==0,'exit_code':code,'stdout':out,'stderr':err}
    async def _v38_root_action_handler(request: _V38Request):
        data=await _v38_body(request); _v38_require_xbhostroot(data,request,allow_otp=True)
        action=data.get('action') or data.get('name'); code,out,err=_v38_root_action(action)
        _v38_audit(_V38_XB_USER,'root:'+str(action),'','/www/wwwroot/iapt',code,out,err,request.client.host if request.client else '')
        return {'ok':code==0,'exit_code':code,'stdout':out,'stderr':err}
    async def _v38_history(request: _V38Request):
        limit=max(1,min(int(request.query_params.get('limit') or 30),100))
        rows=_v38_db.all("SELECT id,username,action,command_text,cwd,exit_code,LEFT(stdout_text,2000) stdout_text,LEFT(stderr_text,2000) stderr_text,ip,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s",(limit,))
        return {'ok':True,'items':rows}
    for _base in ['/maintenance','/api/maintenance']:
        app.add_api_route(_base+'/status',_v38_maint_status,methods=['GET'])
        app.add_api_route(_base+'/password/status',_v38_password_status,methods=['GET'])
        app.add_api_route(_base+'/password/generate',_v38_password_generate,methods=['POST'])
        app.add_api_route(_base+'/shell',_v38_shell,methods=['POST'])
        app.add_api_route(_base+'/root-action',_v38_root_action_handler,methods=['POST'])
        app.add_api_route(_base+'/history',_v38_history,methods=['GET'])

    async def _v38_whitelist_list(request: _V38Request):
        _v38_db_init(); rows=_v38_db.all("SELECT id,package_name,code_hash,expire_at,note,created_at,updated_at FROM decrypt_whitelist ORDER BY id DESC LIMIT 500")
        return {'ok':True,'items':rows,'data':rows}
    async def _v38_whitelist_save(request: _V38Request):
        data=await _v38_body(request); wid=_v38_pick(data,'id','wid','whitelist_id')
        pkg=str(_v38_pick(data,'package_name','package','pkg','packageName','app_package') or '').strip()
        h=str(_v38_pick(data,'hash','code_hash','file_hash','sha256','sha','md5','value') or '').strip()
        exp=_v38_parse_expire(_v38_pick(data,'expire_at','expires_at','expire','expired_at','until','end_time','time'))
        note=str(_v38_pick(data,'note','remark','memo','comment') or '').strip()
        if not pkg: raise _V38HTTPException(status_code=400, detail='包名不能为空')
        if not h: raise _V38HTTPException(status_code=400, detail='hash不能为空')
        if not _v38_re.fullmatch(r'[0-9a-fA-F]{16,128}',h): raise _V38HTTPException(status_code=400, detail='hash格式错误')
        _v38_db_init()
        if wid:
            _v38_db.exec("UPDATE decrypt_whitelist SET package_name=%s, code_hash=%s, expire_at=%s, note=%s WHERE id=%s",(pkg,h,exp,note,wid)); return {'ok':True,'id':int(wid),'updated':True}
        rid=_v38_db.exec("INSERT INTO decrypt_whitelist (package_name,code_hash,expire_at,note) VALUES (%s,%s,%s,%s)",(pkg,h,exp,note)); return {'ok':True,'id':rid,'created':True}
    async def _v38_whitelist_delete(request: _V38Request):
        data=await _v38_body(request); wid=_v38_pick(data,'id','wid','whitelist_id')
        if not wid: raise _V38HTTPException(status_code=400, detail='id不能为空')
        _v38_db.exec("DELETE FROM decrypt_whitelist WHERE id=%s",(wid,)); return {'ok':True,'deleted':True}
    for _p in ['/api/admin/whitelist','/api/admin/whitelist/list','/api/admin/whitelist/common/list','/api/whitelist/common/list','/api/whitelist/list','/whitelist/common/list','/whitelist/list']:
        app.add_api_route(_p,_v38_whitelist_list,methods=['GET'])
    for _p in ['/api/admin/whitelist/add','/api/admin/whitelist/save','/api/admin/whitelist/update']:
        app.add_api_route(_p,_v38_whitelist_save,methods=['POST'])
    for _p in ['/api/admin/whitelist/delete','/api/admin/whitelist/remove']:
        app.add_api_route(_p,_v38_whitelist_delete,methods=['POST'])
    print('[OK] IAPT_MAINT_WHITELIST_REPAIR_V38 installed')
except Exception as _v38_e:
    print('[FAIL] IAPT_MAINT_WHITELIST_REPAIR_V38 install failed:', _v38_e)
# ===== IAPT_MAINT_WHITELIST_REPAIR_V38_END =====

# ===== IAPT_PARAM_COMPAT_V40_BEGIN =====
# maint-whitelist-param-compat-v40-20260619
try:
    import os as _v40_os, re as _v40_re, json as _v40_json, hashlib as _v40_hashlib, secrets as _v40_secrets, string as _v40_string, subprocess as _v40_subprocess
    from datetime import datetime as _v40_datetime, timedelta as _v40_timedelta
    from fastapi import Request as _V40Request, HTTPException as _V40HTTPException
    try:
        from app import db as _v40_db
        from app.secure import decrypt_json_payload as _v40_decrypt_json_payload
    except Exception:
        from . import db as _v40_db
        from .secure import decrypt_json_payload as _v40_decrypt_json_payload

    _V40_TAG='maint-whitelist-param-compat-v40-20260619'
    _V40_XB_USER='xbhostroot'
    _V40_XB_ID=-1
    _V40_SUB_ID=999999999

    def _v40_sha(s): return _v40_hashlib.sha256((s or '').encode('utf-8')).hexdigest()
    def _v40_trim(s,n=65535):
        s=s or ''
        return s if len(s)<=n else s[:n]+'\n...[truncated]'

    async def _v40_body(request):
        data={}
        raw=b''
        try: raw=await request.body()
        except Exception: raw=b''
        if raw:
            try:
                obj=_v40_json.loads(raw.decode('utf-8'))
                if isinstance(obj, dict):
                    # Android client encrypts every POST as {data, iv}. Previous maintenance/whitelist routes read this wrapper directly.
                    if 'data' in obj and 'iv' in obj:
                        data=_v40_decrypt_json_payload(obj, request.headers.get('x-salt',''))
                    else:
                        data=obj
            except _V40HTTPException:
                raise
            except Exception as e:
                raise _V40HTTPException(status_code=400, detail='JSON参数错误')
        if not data:
            try:
                form=await request.form()
                data=dict(form)
            except Exception: data={}
        try:
            for k,v in request.query_params.items(): data.setdefault(k,v)
        except Exception: pass
        return data if isinstance(data,dict) else {}

    def _v40_pick(data,*names):
        # case-sensitive first, then lower-case fallback
        for n in names:
            if n in data and data.get(n) is not None: return data.get(n)
        lower={str(k).lower():v for k,v in data.items()}
        for n in names:
            if n.lower() in lower and lower.get(n.lower()) is not None: return lower.get(n.lower())
        return None

    def _v40_init_tables():
        sqls=[
            "CREATE TABLE IF NOT EXISTS maintenance_passwords (id INT AUTO_INCREMENT PRIMARY KEY,password_hash VARCHAR(128) NOT NULL,expires_at DATETIME NOT NULL,used TINYINT DEFAULT 0,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,used_at DATETIME NULL) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS maintenance_audit_logs (id INT AUTO_INCREMENT PRIMARY KEY,username VARCHAR(100),action VARCHAR(100),command_text TEXT,cwd VARCHAR(255),exit_code INT NULL,stdout_text MEDIUMTEXT NULL,stderr_text MEDIUMTEXT NULL,ip VARCHAR(64) NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
            "CREATE TABLE IF NOT EXISTS decrypt_whitelist (id INT AUTO_INCREMENT PRIMARY KEY,package_name VARCHAR(255) NOT NULL,code_hash VARCHAR(128) NOT NULL,expire_at DATETIME NULL,note TEXT NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,KEY idx_pkg_hash (package_name, code_hash)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4",
        ]
        for s in sqls:
            try: _v40_db.exec(s)
            except Exception as e: print('[V40] table init failed:', e)

    def _v40_ensure_xb():
        """V190: protected by database triggers; never repair/write at runtime."""
        return None
    def _v40_audit(username,action,cmd='',cwd='',code=None,out='',err='',ip=''):
        try: _v40_db.exec("INSERT INTO maintenance_audit_logs (username,action,command_text,cwd,exit_code,stdout_text,stderr_text,ip) VALUES (%s,%s,%s,%s,%s,%s,%s,%s)", (username,action,cmd,cwd,code,(out or '')[:65535],(err or '')[:65535],ip))
        except Exception as e: print('[V40] audit failed:', e)

    def _v40_require_xb(data, request=None, allow_otp=True):
        username=str(_v40_pick(data,'username','user','login') or _V40_XB_USER).strip()
        password=str(_v40_pick(data,'password','maint_password','maintenance_password','pass','pwd') or '')
        if username != _V40_XB_USER: raise _V40HTTPException(status_code=403, detail='仅维护账号可用')
        _v40_ensure_xb()
        if not password: raise _V40HTTPException(status_code=403, detail='维护密码不能为空')
        row=_v40_db.one("SELECT password_hash FROM users WHERE username=%s LIMIT 1", (_V40_XB_USER,))
        if row and str(row.get('password_hash') or '') == _v40_sha(password): return True
        if allow_otp:
            hp=_v40_sha(password)
            rec=_v40_db.one("SELECT id FROM maintenance_passwords WHERE password_hash=%s AND used=0 AND expires_at>NOW() ORDER BY id DESC LIMIT 1", (hp,))
            if rec:
                _v40_db.exec("UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE id=%s", (rec.get('id'),)); return True
        raise _V40HTTPException(status_code=403, detail='维护密码错误或已过期')

    def _v40_allowed_cwd(cwd):
        cwd=str(cwd or '/www/wwwroot/iapt').strip()
        if cwd not in ['/www/wwwroot/iapt','/tmp','/var/lib/iapt-maint']:
            raise _V40HTTPException(status_code=400, detail='cwd不允许')
        return cwd
    def _v40_shell_guard(cmd):
        c=str(cmd or '').strip()
        if not c: raise _V40HTTPException(status_code=400, detail='命令不能为空')
        for pat in [r'\bsudo\b',r'\bsu\b',r'\bsystemctl\b',r'\bservice\b',r'\bnohup\b',r'\bsetsid\b',r'\bchattr\b',r'\bchmod\s+777\b',r'\brm\s+-rf\s+/',r'&\s*$',r'\bmkfs\b',r'\bdd\s+if=']:
            if _v40_re.search(pat,c): raise _V40HTTPException(status_code=400, detail='普通Shell禁止该命令，请使用root维护动作')
        return c
    def _v40_run_low(cmd,cwd,timeout):
        timeout=max(1,min(int(timeout or 30),120)); env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'}
        full=['/bin/bash','-lc',cmd]
        if hasattr(_v40_os,'geteuid') and _v40_os.geteuid()==0:
            try:
                import pwd as _v40_pwd
                _v40_pwd.getpwnam('iapt-maint'); full=['/usr/sbin/runuser','-u','iapt-maint','--','/bin/bash','-lc',cmd]
            except Exception: pass
        p=_v40_subprocess.run(full,cwd=cwd,env=env,text=True,stdout=_v40_subprocess.PIPE,stderr=_v40_subprocess.PIPE,timeout=timeout)
        return p.returncode,_v40_trim(p.stdout),_v40_trim(p.stderr)
    def _v40_root_action(action):
        action=str(action or '').strip()
        m={
          'whoami':'id && whoami',
          'check_8000':'ss -lntp | grep :8000 || true; curl -sS -i http://127.0.0.1:8000/app/config | head -20 || true',
          'restart_api':'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
          'restart_worker':'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
          'restart_nginx':'nginx -t && systemctl reload nginx',
          'tail_api_log':'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
          'tail_worker_log':'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
          'tail_nginx_error':'tail -n 160 /www/wwwlogs/*error*.log 2>/dev/null || tail -n 160 /var/log/nginx/error.log 2>/dev/null || true',
          'py_compile':'cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/tools/iapp_auto_decrypt.py',
          'clear_pycache':'find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +; echo OK',
          'clear_task_cache':'find /www/wwwroot/iapt -name outer_key_cache.json -o -name container_plain.bin -o -name file_index.json | xargs -r rm -f; echo OK',
          'clear_source_caches':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; db.exec(\'DELETE FROM source_caches\'); print(\'OK\')"',
          'recent_failed_tasks':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; print(db.all(\'SELECT id,task_no,filename,status,error,created_at FROM tasks ORDER BY id DESC LIMIT 20\'))"',
          'recent_task_options':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; print(db.all(\'SELECT id,task_no,filename,status,feature_id,options_json,created_at FROM tasks ORDER BY id DESC LIMIT 20\'))"',
          'whitelist_schema':'cd /www/wwwroot/iapt && ./venv/bin/python -c "from app import db; print(db.all(\'SHOW COLUMNS FROM decrypt_whitelist\')); print(db.all(\'SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT 20\'))"',
          'du_storage':'du -h --max-depth=2 /www/wwwroot/iapt 2>/dev/null | sort -h | tail -50',
        }
        if action not in m: raise _V40HTTPException(status_code=400, detail='未知root动作')
        p=_v40_subprocess.run(['/bin/bash','-lc',m[action]],cwd='/www/wwwroot/iapt',text=True,stdout=_v40_subprocess.PIPE,stderr=_v40_subprocess.PIPE,timeout=120)
        return p.returncode,_v40_trim(p.stdout),_v40_trim(p.stderr)

    def _v40_parse_expire(v):
        if v is None: return None
        s=str(v).strip()
        if not s or s.lower() in ('null','none','永久','永不过期'): return None
        if _v40_re.fullmatch(r'\d{4}-\d{2}-\d{2}',s): return s+' 23:59:59'
        if _v40_re.fullmatch(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?',s):
            s=s.replace('T',' ')
            if len(s)==16: s+=':00'
            return s
        raise _V40HTTPException(status_code=400, detail='到期时间格式错误')

    def _v40_remove_routes():
        prefixes=('/maintenance','/api/maintenance')
        exact={'/app/config','/api/app/config','/api/config','/config','/api/admin/whitelist','/api/admin/whitelist/list','/api/admin/whitelist/common/list','/api/admin/whitelist/add','/api/admin/whitelist/save','/api/admin/whitelist/update','/api/admin/whitelist/delete','/api/admin/whitelist/remove','/api/whitelist/common/list','/api/whitelist/list','/whitelist/common/list','/whitelist/list'}
        nr=[]; rem=[]
        for r in list(app.router.routes):
            p=getattr(r,'path','')
            if p in exact or any(p.startswith(x) for x in prefixes): rem.append((p,sorted(getattr(r,'methods',[]) or []))); continue
            nr.append(r)
        app.router.routes[:] = nr
        if rem: print('[V40] removed routes', rem)

    _v40_init_tables(); _v40_ensure_xb(); _v40_remove_routes()

    @app.middleware('http')
    async def _v40_xb_protect_middleware(request, call_next):
        return await call_next(request)

    async def _v40_config(request:_V40Request): return {'ok':True,'app_enabled':True,'register_enabled':True,'announcement_enabled':False,'announcement':'','announcement_content':'','version':'v40'}
    for _p in ['/app/config','/api/app/config','/api/config','/config']:
        app.add_api_route(_p,_v40_config,methods=['GET'])

    async def _v40_status(request:_V40Request): return {'ok':True,'tag':_V40_TAG,'user':_V40_XB_USER}
    async def _v40_password_status(request:_V40Request):
        r=_v40_db.one('SELECT COUNT(*) c FROM maintenance_passwords WHERE used=0 AND expires_at>NOW()') or {'c':0}
        return {'ok':True,'active':int(r.get('c') or 0)}
    async def _v40_password_generate(request:_V40Request):
        data=await _v40_body(request); _v40_require_xb(data,request,allow_otp=False)
        ttl=max(10,min(int(_v40_pick(data,'ttl','seconds') or 60),60)); length=max(12,min(int(_v40_pick(data,'length','len') or 20),64))
        chars=_v40_string.ascii_letters+_v40_string.digits+'!@#$%^&*_-+='; pwd=''.join(_v40_secrets.choice(chars) for _ in range(length))
        exp=(_v40_datetime.utcnow()+_v40_timedelta(seconds=ttl)).strftime('%Y-%m-%d %H:%M:%S')
        _v40_db.exec('UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE used=0')
        _v40_db.exec('INSERT INTO maintenance_passwords (password_hash,expires_at,used) VALUES (%s,%s,0)',(_v40_sha(pwd),exp))
        _v40_audit(_V40_XB_USER,'password_generate','','',0,'generated','',request.client.host if request.client else '')
        return {'ok':True,'password':pwd,'expires_in':ttl,'one_time':True}
    async def _v40_shell(request:_V40Request):
        data=await _v40_body(request); _v40_require_xb(data,request,allow_otp=True)
        cmd=_v40_shell_guard(_v40_pick(data,'cmd','command','shell')); cwd=_v40_allowed_cwd(_v40_pick(data,'cwd','dir','workdir')); timeout=int(_v40_pick(data,'timeout','seconds') or 30)
        try: code,out,err=_v40_run_low(cmd,cwd,timeout)
        except _v40_subprocess.TimeoutExpired as e: code=124; out=_v40_trim(e.stdout or ''); err='timeout'
        _v40_audit(_V40_XB_USER,'shell',cmd,cwd,code,out,err,request.client.host if request.client else '')
        return {'ok':code==0,'exit_code':code,'stdout':out,'stderr':err}
    async def _v40_root_action_handler(request:_V40Request):
        data=await _v40_body(request); _v40_require_xb(data,request,allow_otp=True)
        action=_v40_pick(data,'action','name','root_action'); code,out,err=_v40_root_action(action)
        _v40_audit(_V40_XB_USER,'root:'+str(action),'','/www/wwwroot/iapt',code,out,err,request.client.host if request.client else '')
        return {'ok':code==0,'exit_code':code,'stdout':out,'stderr':err}
    async def _v40_history(request:_V40Request):
        limit=max(1,min(int(request.query_params.get('limit') or 30),100)); rows=_v40_db.all('SELECT id,username,action,command_text,cwd,exit_code,LEFT(stdout_text,2000) stdout_text,LEFT(stderr_text,2000) stderr_text,ip,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s',(limit,))
        return {'ok':True,'items':rows}
    for _base in ['/maintenance','/api/maintenance']:
        app.add_api_route(_base+'/status',_v40_status,methods=['GET'])
        app.add_api_route(_base+'/password/status',_v40_password_status,methods=['GET'])
        app.add_api_route(_base+'/password/generate',_v40_password_generate,methods=['POST'])
        app.add_api_route(_base+'/shell',_v40_shell,methods=['POST'])
        app.add_api_route(_base+'/root-action',_v40_root_action_handler,methods=['POST'])
        app.add_api_route(_base+'/history',_v40_history,methods=['GET'])

    async def _v40_whitelist_list(request:_V40Request):
        _v40_init_tables(); rows=_v40_db.all('SELECT id,package_name,code_hash,expire_at,note,created_at,updated_at FROM decrypt_whitelist ORDER BY id DESC LIMIT 500')
        return {'ok':True,'items':rows,'data':rows}
    async def _v40_whitelist_save(request:_V40Request):
        data=await _v40_body(request)
        wid=_v40_pick(data,'id','wid','whitelist_id')
        pkg=str(_v40_pick(data,'package_name','package','pkg','packageName','app_package','appPackage','bundle_id','applicationId') or '').strip()
        h=str(_v40_pick(data,'hash','code_hash','file_hash','sha256','sha','md5','value','code_sha256','apk_sha256','apk_hash','fileSha256','codeSha256','apkSha256') or '').strip()
        exp=_v40_parse_expire(_v40_pick(data,'expire_at','expires_at','expire','expired_at','until','end_time','time','expireTime'))
        note=str(_v40_pick(data,'note','remark','memo','comment') or '').strip()
        if not pkg: raise _V40HTTPException(status_code=400, detail='包名不能为空')
        if not h: raise _V40HTTPException(status_code=400, detail='hash不能为空')
        h=h.lower()
        if not _v40_re.fullmatch(r'[0-9a-f]{16,128}',h): raise _V40HTTPException(status_code=400, detail='hash格式错误')
        _v40_init_tables()
        if wid:
            _v40_db.exec('UPDATE decrypt_whitelist SET package_name=%s,code_hash=%s,expire_at=%s,note=%s WHERE id=%s',(pkg,h,exp,note,wid)); return {'ok':True,'id':int(wid),'updated':True}
        rid=_v40_db.exec('INSERT INTO decrypt_whitelist (package_name,code_hash,expire_at,note) VALUES (%s,%s,%s,%s)',(pkg,h,exp,note)); return {'ok':True,'id':rid,'created':True}
    async def _v40_whitelist_delete(request:_V40Request):
        data=await _v40_body(request); wid=_v40_pick(data,'id','wid','whitelist_id')
        if not wid: raise _V40HTTPException(status_code=400, detail='id不能为空')
        _v40_db.exec('DELETE FROM decrypt_whitelist WHERE id=%s',(wid,)); return {'ok':True,'deleted':True}
    for _p in ['/api/admin/whitelist','/api/admin/whitelist/list','/api/admin/whitelist/common/list','/api/whitelist/common/list','/api/whitelist/list','/whitelist/common/list','/whitelist/list']:
        app.add_api_route(_p,_v40_whitelist_list,methods=['GET'])
    for _p in ['/api/admin/whitelist/add','/api/admin/whitelist/save','/api/admin/whitelist/update']:
        app.add_api_route(_p,_v40_whitelist_save,methods=['POST'])
    for _p in ['/api/admin/whitelist/delete','/api/admin/whitelist/remove']:
        app.add_api_route(_p,_v40_whitelist_delete,methods=['POST'])
    print('[OK] IAPT_PARAM_COMPAT_V40 installed')
except Exception as _v40_e:
    print('[FAIL] IAPT_PARAM_COMPAT_V40 install failed:', _v40_e)
# ===== IAPT_PARAM_COMPAT_V40_END =====


# ===== IAPT_WHITELIST_STATUS_V41_BEGIN =====
# whitelist-status-v41-20260619
try:
    import json as _v41_json, re as _v41_re
    from datetime import datetime as _v41_datetime
    from fastapi import Request as _V41Request, HTTPException as _V41HTTPException
    try:
        from app import db as _v41_db
        from app.secure import decrypt_json_payload as _v41_decrypt_json_payload
    except Exception:
        from . import db as _v41_db
        from .secure import decrypt_json_payload as _v41_decrypt_json_payload

    _V41_TAG='whitelist-status-v41-20260619'

    async def _v41_body(request):
        data={}
        try:
            raw=await request.body()
        except Exception:
            raw=b''
        if raw:
            try:
                obj=_v41_json.loads(raw.decode('utf-8'))
                if isinstance(obj,dict) and 'data' in obj and 'iv' in obj:
                    data=_v41_decrypt_json_payload(obj, request.headers.get('x-salt',''))
                elif isinstance(obj,dict):
                    data=obj
            except _V41HTTPException:
                raise
            except Exception:
                raise _V41HTTPException(status_code=400, detail='JSON参数错误')
        if not data:
            try:
                form=await request.form(); data=dict(form)
            except Exception:
                data={}
        try:
            for k,v in request.query_params.items(): data.setdefault(k,v)
        except Exception:
            pass
        return data if isinstance(data,dict) else {}

    def _v41_pick(data,*names):
        for n in names:
            if n in data and data.get(n) is not None: return data.get(n)
        lower={str(k).lower():v for k,v in data.items()}
        for n in names:
            if n.lower() in lower and lower.get(n.lower()) is not None: return lower.get(n.lower())
        return None

    def _v41_init_table():
        _v41_db.exec("CREATE TABLE IF NOT EXISTS decrypt_whitelist (id INT AUTO_INCREMENT PRIMARY KEY,package_name VARCHAR(255) NOT NULL,code_hash VARCHAR(128) NOT NULL,expire_at DATETIME NULL,note TEXT NULL,created_at DATETIME DEFAULT CURRENT_TIMESTAMP,updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,KEY idx_pkg_hash (package_name, code_hash)) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")

    def _v41_parse_expire(v):
        if v is None: return None
        s=str(v).strip()
        if not s or s.lower() in ('null','none','永久','永不过期'): return None
        if _v41_re.fullmatch(r'\d{4}-\d{2}-\d{2}', s):
            return s+' 23:59:59'
        if _v41_re.fullmatch(r'\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?', s):
            return s.replace('T',' ') + (':00' if len(s.replace('T',' '))==16 else '')
        raise _V41HTTPException(status_code=400, detail='到期时间格式错误')

    def _v41_dt(v):
        if v is None: return None
        if isinstance(v, _v41_datetime): return v
        s=str(v).strip()
        if not s or s.lower() in ('none','null'): return None
        for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d %H:%M','%Y-%m-%d'):
            try: return _v41_datetime.strptime(s[:19] if fmt.endswith('%S') else s, fmt)
            except Exception: pass
        return None

    def _v41_row(row):
        now=_v41_datetime.now()
        exp_raw=row.get('expire_at')
        exp=_v41_dt(exp_raw)
        expired=bool(exp and exp <= now)
        permanent=exp is None
        active=permanent or not expired
        if permanent:
            status='永久'
        elif expired:
            status='过期'
        else:
            status='生效'
        exp_s='' if exp_raw is None else (exp_raw.strftime('%Y-%m-%d %H:%M:%S') if hasattr(exp_raw,'strftime') else str(exp_raw))
        return {
            'id': row.get('id'),
            'package_name': row.get('package_name') or row.get('package') or row.get('pkg') or '',
            'package': row.get('package_name') or row.get('package') or row.get('pkg') or '',
            'pkg': row.get('package_name') or row.get('package') or row.get('pkg') or '',
            'code_hash': row.get('code_hash') or row.get('file_hash') or row.get('hash') or '',
            'file_hash': row.get('code_hash') or row.get('file_hash') or row.get('hash') or '',
            'hash': row.get('code_hash') or row.get('file_hash') or row.get('hash') or '',
            'expire_at': exp_s,
            'expire_time': exp_s,
            'expires_at': exp_s,
            'note': row.get('note') or '',
            'created_at': str(row.get('created_at') or ''),
            'updated_at': str(row.get('updated_at') or ''),
            # Important: 2027 in 2026 must be active, not expired. Some clients read status, some read bool fields.
            'status': status,
            'status_text': status,
            'is_expired': expired,
            'expired': expired,
            'active': active,
            'valid': active,
        }

    async def _v41_whitelist_list(request: _V41Request):
        _v41_init_table()
        q=(request.query_params.get('q') or request.query_params.get('keyword') or request.query_params.get('search') or '').strip()
        if q:
            like='%'+q+'%'
            rows=_v41_db.all("SELECT * FROM decrypt_whitelist WHERE package_name LIKE %s OR code_hash LIKE %s ORDER BY id DESC LIMIT 1000", (like,like))
        else:
            rows=_v41_db.all("SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT 1000")
        items=[_v41_row(r) for r in rows]
        return {'ok': True, 'items': items, 'list': items, 'data': items, 'count': len(items), 'server_time': _v41_datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

    async def _v41_whitelist_save(request: _V41Request):
        _v41_init_table(); data=await _v41_body(request)
        wid=_v41_pick(data,'id','wid','whitelist_id')
        pkg=str(_v41_pick(data,'package_name','package','pkg','packageName','app_package') or '').strip()
        h=str(_v41_pick(data,'hash','code_hash','file_hash','sha256','code_sha256','apk_sha256','apk_hash','value') or '').strip()
        exp=_v41_parse_expire(_v41_pick(data,'expire_at','expire_time','expires_at','expire','expired_at'))
        note=str(_v41_pick(data,'note','remark','memo') or '').strip()
        if not pkg: raise _V41HTTPException(status_code=400, detail='包名不能为空')
        if not h: raise _V41HTTPException(status_code=400, detail='hash不能为空')
        if wid:
            _v41_db.exec("UPDATE decrypt_whitelist SET package_name=%s,code_hash=%s,expire_at=%s,note=%s WHERE id=%s", (pkg,h,exp,note,wid))
            new_id=int(wid)
        else:
            exist=_v41_db.one("SELECT id FROM decrypt_whitelist WHERE package_name=%s AND code_hash=%s LIMIT 1", (pkg,h))
            if exist:
                new_id=exist.get('id')
                _v41_db.exec("UPDATE decrypt_whitelist SET expire_at=%s,note=%s WHERE id=%s", (exp,note,new_id))
            else:
                new_id=_v41_db.exec("INSERT INTO decrypt_whitelist (package_name,code_hash,expire_at,note) VALUES (%s,%s,%s,%s)", (pkg,h,exp,note))
        row=_v41_db.one("SELECT * FROM decrypt_whitelist WHERE id=%s", (new_id,))
        return {'ok': True, 'id': new_id, 'item': _v41_row(row or {'id':new_id,'package_name':pkg,'code_hash':h,'expire_at':exp,'note':note})}

    async def _v41_whitelist_delete(request: _V41Request):
        _v41_init_table(); data=await _v41_body(request)
        wid=_v41_pick(data,'id','wid','whitelist_id')
        if not wid: raise _V41HTTPException(status_code=400, detail='id不能为空')
        _v41_db.exec("DELETE FROM decrypt_whitelist WHERE id=%s", (wid,))
        return {'ok': True}

    try:
        _v41_paths={
          '/api/admin/whitelist/list','/api/admin/whitelist/common/list','/api/whitelist/common/list','/api/whitelist/list','/api/admin/whitelist','/whitelist/list','/admin/whitelist/list',
          '/api/admin/whitelist/add','/api/admin/whitelist/save','/api/admin/whitelist/update','/api/whitelist/save','/api/whitelist/add','/api/whitelist/update',
          '/api/admin/whitelist/delete','/api/admin/whitelist/remove','/api/whitelist/delete','/api/whitelist/remove'
        }
        before=len(app.router.routes)
        app.router.routes[:]=[r for r in app.router.routes if getattr(r,'path','') not in _v41_paths]
        print('[OK] v41 removed whitelist routes', before-len(app.router.routes))
    except Exception as _e:
        print('[WARN] v41 remove old whitelist routes failed', _e)

    for _p in ['/api/admin/whitelist/list','/api/admin/whitelist/common/list','/api/whitelist/common/list','/api/whitelist/list','/api/admin/whitelist','/whitelist/list','/admin/whitelist/list']:
        app.add_api_route(_p, _v41_whitelist_list, methods=['GET'])
    for _p in ['/api/admin/whitelist/add','/api/admin/whitelist/save','/api/admin/whitelist/update','/api/whitelist/save','/api/whitelist/add','/api/whitelist/update']:
        app.add_api_route(_p, _v41_whitelist_save, methods=['POST'])
    for _p in ['/api/admin/whitelist/delete','/api/admin/whitelist/remove','/api/whitelist/delete','/api/whitelist/remove']:
        app.add_api_route(_p, _v41_whitelist_delete, methods=['POST'])
    print('[OK] IAPT_WHITELIST_STATUS_V41 installed')
except Exception as _v41_e:
    print('[WARN] IAPT_WHITELIST_STATUS_V41 failed', _v41_e)
# ===== IAPT_WHITELIST_STATUS_V41_END =====


# IAPT_MAINT_BODY_DECODE_V50_BEGIN
# Fix maintenance encrypted-body decoding and maintenance password table schema. 20260619
try:
    import json as _v50_json, hashlib as _v50_hashlib, secrets as _v50_secrets, string as _v50_string, subprocess as _v50_subprocess, os as _v50_os
    from datetime import datetime as _v50_datetime, timedelta as _v50_timedelta
    from fastapi import Request as _v50_Request, HTTPException as _v50_HTTPException
    from fastapi.responses import JSONResponse as _v50_JSONResponse
    try:
        from . import db as _v50_db
    except Exception:
        _v50_db = db

    _V50_XB = 'xbhostroot'
    _V50_ALLOWED_CWD = {'/www/wwwroot/iapt', '/tmp', '/var/lib/iapt-maint'}

    def _v50_exec(sql, args=None):
        return _v50_db.exec(sql, args or ())
    def _v50_one(sql, args=None):
        return _v50_db.one(sql, args or ())
    def _v50_all(sql, args=None):
        return _v50_db.all(sql, args or ())
    def _v50_sha(s):
        return _v50_hashlib.sha256(str(s or '').encode('utf-8')).hexdigest()
    def _v50_json_resp(obj, code=200):
        return _v50_JSONResponse(obj, status_code=code)
    def _v50_get(obj, *keys, default=''):
        if not isinstance(obj, dict):
            return default
        for k in keys:
            if k in obj and obj.get(k) is not None:
                return obj.get(k)
        return default

    def _v50_ensure_schema():
        # 用单行 SQL 字符串，避免补丁脚本嵌套三引号导致 SyntaxError。
        _v50_exec("CREATE TABLE IF NOT EXISTS maintenance_passwords (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NULL, password_hash VARCHAR(128) NULL, token_hash VARCHAR(128) NULL, ttl INT DEFAULT 60, used TINYINT DEFAULT 0, used_at DATETIME NULL, expire_at DATETIME NULL, expires_at DATETIME NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
        for sql in [
            "ALTER TABLE maintenance_passwords ADD COLUMN username VARCHAR(64) NULL",
            "ALTER TABLE maintenance_passwords ADD COLUMN password_hash VARCHAR(128) NULL",
            "ALTER TABLE maintenance_passwords ADD COLUMN token_hash VARCHAR(128) NULL",
            "ALTER TABLE maintenance_passwords ADD COLUMN ttl INT DEFAULT 60",
            "ALTER TABLE maintenance_passwords ADD COLUMN used TINYINT DEFAULT 0",
            "ALTER TABLE maintenance_passwords ADD COLUMN used_at DATETIME NULL",
            "ALTER TABLE maintenance_passwords ADD COLUMN expire_at DATETIME NULL",
            "ALTER TABLE maintenance_passwords ADD COLUMN expires_at DATETIME NULL",
            "ALTER TABLE maintenance_passwords ADD COLUMN created_at DATETIME DEFAULT CURRENT_TIMESTAMP",
        ]:
            try:
                _v50_exec(sql)
            except Exception:
                pass
        try:
            _v50_exec('UPDATE maintenance_passwords SET used=0 WHERE used IS NULL')
        except Exception:
            pass
        _v50_exec("CREATE TABLE IF NOT EXISTS maintenance_audit_logs (id INT AUTO_INCREMENT PRIMARY KEY, username VARCHAR(64) NULL, action VARCHAR(128) NULL, cmd TEXT NULL, result MEDIUMTEXT NULL, ip VARCHAR(64) NULL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")

    async def _v50_body(request):
        try:
            raw = await request.json()
        except Exception:
            try:
                form = await request.form()
                raw = dict(form)
            except Exception:
                raw = {}
        if isinstance(raw, str):
            try:
                raw = _v50_json.loads(raw)
            except Exception:
                raw = {}
        if not isinstance(raw, dict):
            raw = {}
        enc_data = raw.get('data') or raw.get('payload')
        enc_iv = raw.get('iv')
        if enc_data and enc_iv:
            salt = request.headers.get('x-salt','') or request.headers.get('X-Salt','') or raw.get('salt','')
            # 官方加密 body 解密器
            try:
                from .secure import decrypt_json_payload as _dec
                val = _dec({'data': enc_data, 'iv': enc_iv}, salt)
                if isinstance(val, dict):
                    return val
                if isinstance(val, str):
                    return _v50_json.loads(val)
            except Exception as e:
                raw['_decode_error'] = str(e)
            # 兼容旧补丁可能放在 main 全局的解密器
            for name in ('decrypt_json_payload','_decrypt_json_payload','decrypt_payload','_decrypt_payload'):
                fn = globals().get(name)
                if callable(fn):
                    for args in (({'data': enc_data, 'iv': enc_iv}, salt), ({'data': enc_data, 'iv': enc_iv},), (enc_data, enc_iv, salt), (enc_data, enc_iv)):
                        try:
                            val = fn(*args)
                            if hasattr(val, '__await__'):
                                val = await val
                            if isinstance(val, dict):
                                return val
                            if isinstance(val, str):
                                return _v50_json.loads(val)
                        except Exception:
                            pass
        for k in ('body','json','payload'):
            v = raw.get(k)
            if isinstance(v, str) and v.strip().startswith('{'):
                try:
                    return _v50_json.loads(v)
                except Exception:
                    pass
        return raw

    def _v50_xb_row():
        return _v50_one('SELECT id,username,password_hash,permission,banned,subscription_id FROM users WHERE username=%s LIMIT 1', (_V50_XB,))

    def _v50_fix_xb():
        """V190: protected by database triggers; never repair/write at runtime."""
        return None
    def _v50_auth_password(password):
        _v50_ensure_schema(); _v50_fix_xb()
        password = str(password or '')
        if not password:
            return False, '维护密码不能为空'
        h = _v50_sha(password)
        # 一次性维护密码
        try:
            now = _v50_datetime.now()
            rows = _v50_all('SELECT id,password_hash,expire_at,expires_at,used FROM maintenance_passwords WHERE IFNULL(used,0)=0 ORDER BY id DESC LIMIT 30')
            for r in rows:
                exp = r.get('expires_at') or r.get('expire_at')
                if isinstance(exp, str):
                    try:
                        exp = _v50_datetime.fromisoformat(exp.replace(' ', 'T'))
                    except Exception:
                        exp = None
                if str(r.get('password_hash') or '').lower() == h.lower() and (exp is None or exp > now):
                    _v50_exec('UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE id=%s', (r.get('id'),))
                    return True, 'one_time'
        except Exception:
            pass
        # 固定维护密码 = xbhostroot 当前登录明文密码
        row = _v50_xb_row()
        if row and str(row.get('password_hash') or '').lower() == h.lower():
            return True, 'fixed'
        return False, '维护密码错误'

    async def _v50_require(request, need_password=True):
        body = await _v50_body(request)
        username = str(_v50_get(body, 'username', 'user', default=_V50_XB) or _V50_XB)
        if username != _V50_XB:
            raise _v50_HTTPException(403, '仅 xbhostroot 可用')
        if need_password:
            pwd = _v50_get(body, 'password', 'maint_password', 'maintenance_password', 'pwd', 'pass', default='')
            ok, msg = _v50_auth_password(pwd)
            if not ok:
                keys = ','.join(sorted([str(k) for k in body.keys()])) if isinstance(body, dict) else ''
                if msg == '维护密码不能为空' and keys:
                    msg = msg + '，已收到字段:' + keys
                raise _v50_HTTPException(403, msg)
        return body

    def _v50_audit(username, action, cmd='', result='', ip=''):
        try:
            _v50_ensure_schema()
            _v50_exec('INSERT INTO maintenance_audit_logs(username,action,cmd,result,ip) VALUES(%s,%s,%s,%s,%s)', (username, action, str(cmd)[:4000], str(result)[:60000], ip))
        except Exception:
            pass

    async def _v50_status(request: _v50_Request):
        _v50_ensure_schema(); _v50_fix_xb()
        return _v50_json_resp({'ok': True, 'version': 'maint-body-decode-v50', 'user': _V50_XB})

    async def _v50_password_generate(request: _v50_Request):
        body = await _v50_require(request, True)
        ttl = int(_v50_get(body, 'ttl', 'expires_in', default=60) or 60)
        length = int(_v50_get(body, 'length', 'len', default=20) or 20)
        ttl = max(10, min(60, ttl)); length = max(12, min(64, length))
        chars = _v50_string.ascii_letters + _v50_string.digits + '!@#$%^&*_-+=' 
        pwd = ''.join(_v50_secrets.choice(chars) for _ in range(length))
        h = _v50_sha(pwd)
        exp = _v50_datetime.now() + _v50_timedelta(seconds=ttl)
        _v50_ensure_schema()
        _v50_exec('UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE IFNULL(used,0)=0')
        _v50_exec('INSERT INTO maintenance_passwords(username,password_hash,ttl,used,expire_at,expires_at,created_at) VALUES(%s,%s,%s,0,%s,%s,NOW())', (_V50_XB, h, ttl, exp.strftime('%Y-%m-%d %H:%M:%S'), exp.strftime('%Y-%m-%d %H:%M:%S')))
        _v50_audit(_V50_XB, 'password_generate', '', 'ttl=%s length=%s'%(ttl,length), getattr(request.client,'host','') if request.client else '')
        return _v50_json_resp({'ok': True, 'password': pwd, 'expires_in': ttl, 'one_time': True})

    async def _v50_password_status(request: _v50_Request):
        _v50_ensure_schema()
        rows = _v50_all('SELECT id,username,ttl,used,expire_at,created_at FROM maintenance_passwords ORDER BY id DESC LIMIT 5')
        return _v50_json_resp({'ok': True, 'items': rows})

    def _v50_run_shell(cmd, cwd, timeout):
        cmd = str(cmd or '').strip(); cwd = str(cwd or '/www/wwwroot/iapt')
        timeout = max(1, min(int(timeout or 30), 120))
        if not cmd:
            return {'ok': False, 'error': '命令不能为空'}
        if cwd not in _V50_ALLOWED_CWD:
            return {'ok': False, 'error': 'cwd 不允许'}
        bad = ['sudo',' su ','systemctl','service ','nohup','&','; rm ','| sh','| bash','bash -i','/dev/tcp','chattr','passwd','useradd','usermod']
        low = ' ' + cmd.lower() + ' '
        for b in bad:
            if b in low:
                return {'ok': False, 'error': '普通Shell禁止该命令，请用 root-action 固定动作'}
        env = {'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','LANG':'C.UTF-8'}
        user_prefix = []
        try:
            if _v50_os.geteuid() == 0:
                user_prefix = ['runuser','-u','iapt-maint','--']
        except Exception:
            pass
        p = _v50_subprocess.run(user_prefix + ['/bin/bash','-lc',cmd], cwd=cwd, env=env, text=True, capture_output=True, timeout=timeout)
        return {'ok': p.returncode == 0, 'exit_code': p.returncode, 'stdout': p.stdout[-60000:], 'stderr': p.stderr[-60000:]}

    async def _v50_shell(request: _v50_Request):
        body = await _v50_require(request, True)
        cmd = _v50_get(body, 'cmd', 'command', default='')
        cwd = _v50_get(body, 'cwd', 'workdir', default='/www/wwwroot/iapt')
        timeout = _v50_get(body, 'timeout', default=30)
        res = _v50_run_shell(cmd, cwd, timeout)
        _v50_audit(_V50_XB, 'shell', cmd, _v50_json.dumps(res, ensure_ascii=False), getattr(request.client,'host','') if request.client else '')
        return _v50_json_resp(res)

    def _v50_root_action(action, params=''):
        action = str(action or '').strip()
        mapping = {
            'whoami': 'whoami',
            'check_8000': "ss -lntp | grep ':8000' || true; curl -sS -i http://127.0.0.1:8000/app/config | head -20 || true",
            'restart_api': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
            'restart_worker': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
            'restart_nginx': 'nginx -t && systemctl reload nginx',
            'tail_api_log': 'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
            'py_compile': 'cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/db.py',
            'clear_source_caches': "cd /www/wwwroot/iapt && ./venv/bin/python -c \"from app import db; db.exec('DELETE FROM source_caches'); print('OK')\"",
            'clear_pycache': "find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +; echo OK",
        }
        if action not in mapping:
            return {'ok': False, 'error': '未知动作', 'allowed': sorted(mapping.keys())}
        p = _v50_subprocess.run(['/bin/bash','-lc',mapping[action]], text=True, capture_output=True, timeout=120)
        return {'ok': p.returncode == 0, 'action': action, 'exit_code': p.returncode, 'stdout': p.stdout[-60000:], 'stderr': p.stderr[-60000:]}

    async def _v50_root_action_endpoint(request: _v50_Request):
        body = await _v50_require(request, True)
        action = _v50_get(body, 'action', 'name', 'root_action', default='')
        params = _v50_get(body, 'params', 'args', default='')
        res = _v50_root_action(action, params)
        _v50_audit(_V50_XB, 'root_action:' + str(action), str(params), _v50_json.dumps(res, ensure_ascii=False), getattr(request.client,'host','') if request.client else '')
        return _v50_json_resp(res)

    async def _v50_history(request: _v50_Request):
        _v50_ensure_schema()
        try:
            limit = int(request.query_params.get('limit','30'))
        except Exception:
            limit = 30
        rows = _v50_all('SELECT id,username,action,cmd,result,ip,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s', (max(1,min(limit,100)),))
        return _v50_json_resp({'ok': True, 'items': rows})

    try:
        app.router.routes = [r for r in app.router.routes if not str(getattr(r, 'path', '')).startswith('/maintenance') and not str(getattr(r, 'path', '')).startswith('/api/maintenance')]
        app.routes = app.router.routes
    except Exception:
        pass
    for _pfx in ('', '/api'):
        app.add_api_route(_pfx + '/maintenance/status', _v50_status, methods=['GET'])
        app.add_api_route(_pfx + '/maintenance/password/generate', _v50_password_generate, methods=['POST'])
        app.add_api_route(_pfx + '/maintenance/password/status', _v50_password_status, methods=['GET'])
        app.add_api_route(_pfx + '/maintenance/shell', _v50_shell, methods=['POST'])
        app.add_api_route(_pfx + '/maintenance/root-action', _v50_root_action_endpoint, methods=['POST'])
        app.add_api_route(_pfx + '/maintenance/history', _v50_history, methods=['GET'])
    try:
        _v50_ensure_schema(); _v50_fix_xb()
        print('[OK] IAPT_MAINT_BODY_DECODE_V50 installed')
    except Exception as _e:
        print('[WARN] IAPT_MAINT_BODY_DECODE_V50 schema:', _e)
except Exception as _e:
    print('[WARN] IAPT_MAINT_BODY_DECODE_V50 failed:', _e)
# IAPT_MAINT_BODY_DECODE_V50_END

# __MAINT_PASSWORD_TIME_TTL_V51_BEGIN__
# v51: 维护密码按有效时间失效，不再使用一次就失效；同时强制覆盖 /maintenance 路由。
try:
    import os as _v51_os, json as _v51_json, time as _v51_time, hashlib as _v51_hashlib, secrets as _v51_secrets, string as _v51_string, subprocess as _v51_subprocess, shlex as _v51_shlex
    from datetime import datetime as _v51_datetime, timedelta as _v51_timedelta
    from fastapi import Request as _v51_Request, HTTPException as _v51_HTTPException
    from fastapi.responses import JSONResponse as _v51_JSONResponse
    from . import db as _v51_db

    _V51_XB_USER = 'xbhostroot'
    _V51_ALLOWED_CWD = {'/www/wwwroot/iapt', '/tmp', '/var/lib/iapt-maint'}
    _V51_MAINT_PATHS = {
        '/maintenance/status','/maintenance/password/generate','/maintenance/password/status',
        '/maintenance/shell','/maintenance/root-action','/maintenance/history',
        '/api/maintenance/status','/api/maintenance/password/generate','/api/maintenance/password/status',
        '/api/maintenance/shell','/api/maintenance/root-action','/api/maintenance/history',
    }

    def _v51_sha(s):
        return _v51_hashlib.sha256(str(s or '').encode('utf-8')).hexdigest()

    def _v51_exec(sql, args=None):
        return _v51_db.exec(sql, args or ())
    def _v51_one(sql, args=None):
        return _v51_db.one(sql, args or ())
    def _v51_all(sql, args=None):
        return _v51_db.all(sql, args or ())

    def _v51_fix_tables():
        try:
            _v51_exec("CREATE TABLE IF NOT EXISTS maintenance_passwords (id BIGINT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(64) NOT NULL DEFAULT 'xbhostroot', password_hash VARCHAR(128) NOT NULL DEFAULT '', token_hash VARCHAR(128) NOT NULL DEFAULT '', ttl INT NOT NULL DEFAULT 60, expire_at DATETIME NULL, expires_at DATETIME NULL, used TINYINT NOT NULL DEFAULT 0, used_at DATETIME NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
            cols = {r.get('Field') for r in (_v51_all('SHOW COLUMNS FROM maintenance_passwords') or [])}
            alters = {
                'username': "ALTER TABLE maintenance_passwords ADD COLUMN username VARCHAR(64) NOT NULL DEFAULT 'xbhostroot'",
                'password_hash': "ALTER TABLE maintenance_passwords ADD COLUMN password_hash VARCHAR(128) NOT NULL DEFAULT ''",
                'token_hash': "ALTER TABLE maintenance_passwords ADD COLUMN token_hash VARCHAR(128) NOT NULL DEFAULT ''",
                'ttl': "ALTER TABLE maintenance_passwords ADD COLUMN ttl INT NOT NULL DEFAULT 60",
                'expire_at': "ALTER TABLE maintenance_passwords ADD COLUMN expire_at DATETIME NULL",
                'expires_at': "ALTER TABLE maintenance_passwords ADD COLUMN expires_at DATETIME NULL",
                'used': "ALTER TABLE maintenance_passwords ADD COLUMN used TINYINT NOT NULL DEFAULT 0",
                'used_at': "ALTER TABLE maintenance_passwords ADD COLUMN used_at DATETIME NULL",
                'created_at': "ALTER TABLE maintenance_passwords ADD COLUMN created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP",
            }
            for c, sql in alters.items():
                if c not in cols:
                    try: _v51_exec(sql)
                    except Exception: pass
            try: _v51_exec('UPDATE maintenance_passwords SET used=0 WHERE used IS NULL')
            except Exception: pass
            _v51_exec("CREATE TABLE IF NOT EXISTS maintenance_audit_logs (id BIGINT PRIMARY KEY AUTO_INCREMENT, username VARCHAR(64) NOT NULL DEFAULT '', action VARCHAR(64) NOT NULL DEFAULT '', command_text TEXT NULL, exit_code INT NULL, stdout_text MEDIUMTEXT NULL, stderr_text MEDIUMTEXT NULL, ip VARCHAR(64) NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4")
        except Exception as e:
            print('[IAPT_FIX v51] maintenance table fix failed:', repr(e))

    def _v51_fix_xbhostroot():
        """V190: protected by database triggers; never repair/write at runtime."""
        return None
    _v51_fix_tables()
    _v51_fix_xbhostroot()

    def _v51_remove_routes():
        try:
            app.router.routes[:] = [r for r in app.router.routes if getattr(r, 'path', '') not in _V51_MAINT_PATHS]
            print('[IAPT_FIX v51] maintenance routes overridden')
        except Exception as e:
            print('[IAPT_FIX v51] remove routes failed:', repr(e))
    _v51_remove_routes()

    async def _v51_body(request: _v51_Request):
        try:
            data = await request.json()
        except Exception:
            data = {}
        if not isinstance(data, dict):
            return {}
        if 'data' in data and 'iv' in data:
            try:
                from .secure import decrypt_json_payload as _v51_dec
                return _v51_dec(data, request.headers.get('x-salt','')) or {}
            except _v51_HTTPException:
                raise
            except Exception as e:
                raise _v51_HTTPException(400, '参数解密失败: %s' % e)
        return data

    def _v51_pick(d, *keys, default=''):
        for k in keys:
            if isinstance(d, dict) and k in d and d.get(k) is not None:
                return d.get(k)
        return default

    def _v51_xb_row():
        return _v51_one('SELECT id,username,password_hash,banned,permission,subscription_id FROM users WHERE username=%s LIMIT 1', (_V51_XB_USER,))

    def _v51_fixed_password_ok(pwd):
        row = _v51_xb_row()
        if not row:
            return False
        # V190: protected status is immutable in MariaDB. Never repair it on each request.
        return _v51_sha(pwd) == str(row.get('password_hash') or '')

    def _v51_temp_password_ok(pwd):
        _v51_fix_tables()
        h = _v51_sha(pwd)
        try:
            _v51_exec('UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE used=0 AND expire_at IS NOT NULL AND expire_at<=NOW()')
        except Exception:
            pass
        row = _v51_one('SELECT id FROM maintenance_passwords WHERE username=%s AND password_hash=%s AND used=0 AND (expire_at IS NULL OR expire_at>NOW()) ORDER BY id DESC LIMIT 1', (_V51_XB_USER, h))
        return bool(row)

    def _v51_any_password_ok(pwd):
        if not pwd:
            return False
        return _v51_fixed_password_ok(pwd) or _v51_temp_password_ok(pwd)

    def _v51_require_fixed(pwd):
        if not pwd:
            raise _v51_HTTPException(403, '维护密码不能为空')
        if not _v51_fixed_password_ok(pwd):
            raise _v51_HTTPException(403, '维护密码错误')

    def _v51_require_any(pwd):
        if not pwd:
            raise _v51_HTTPException(403, '维护密码不能为空')
        if not _v51_any_password_ok(pwd):
            raise _v51_HTTPException(403, '维护密码错误或已过期')

    def _v51_audit(username, action, command='', code=None, out='', err='', request=None):
        try:
            ip = ''
            try: ip = request.client.host if request and request.client else ''
            except Exception: ip = ''
            _v51_exec('INSERT INTO maintenance_audit_logs(username,action,command_text,exit_code,stdout_text,stderr_text,ip) VALUES(%s,%s,%s,%s,%s,%s,%s)', (username or '', action or '', str(command or '')[:2000], code, str(out or '')[:64000], str(err or '')[:64000], ip))
        except Exception:
            pass

    async def _v51_status(request: _v51_Request):
        _v51_fix_tables(); _v51_fix_xbhostroot()
        row = _v51_xb_row() or {}
        active = _v51_one('SELECT COUNT(*) AS c FROM maintenance_passwords WHERE username=%s AND used=0 AND (expire_at IS NULL OR expire_at>NOW())', (_V51_XB_USER,)) or {'c':0}
        return {'ok': True, 'version':'v51-time-ttl', 'maintenance_ready': bool(row), 'active_temp_passwords': int(active.get('c') or 0), 'one_time': False}

    async def _v51_password_generate(request: _v51_Request):
        p = await _v51_body(request)
        pwd = str(_v51_pick(p, 'password','maint_password','maintenance_password','pwd','pass')).strip()
        _v51_require_fixed(pwd)
        try: ttl = int(_v51_pick(p, 'ttl','seconds','expire_seconds', default=60) or 60)
        except Exception: ttl = 60
        ttl = max(10, min(ttl, 3600))
        try: length = int(_v51_pick(p, 'length','len', default=20) or 20)
        except Exception: length = 20
        length = max(12, min(length, 64))
        chars = _v51_string.ascii_letters + _v51_string.digits + '!@#$%^&*_-+=' 
        new_pwd = ''.join(_v51_secrets.choice(chars) for _ in range(length))
        expire = _v51_datetime.now() + _v51_timedelta(seconds=ttl)
        _v51_fix_tables()
        # v51：不再生成后作废旧临时密码，也不在使用后作废。只按时间过期。
        _v51_exec('UPDATE maintenance_passwords SET used=1, used_at=NOW() WHERE used=0 AND expire_at IS NOT NULL AND expire_at<=NOW()')
        _v51_exec('INSERT INTO maintenance_passwords(username,password_hash,token_hash,ttl,expire_at,expires_at,used,created_at) VALUES(%s,%s,%s,%s,%s,%s,0,NOW())', (_V51_XB_USER, _v51_sha(new_pwd), _v51_sha(new_pwd+'|token'), ttl, expire.strftime('%Y-%m-%d %H:%M:%S'), expire.strftime('%Y-%m-%d %H:%M:%S')))
        _v51_audit(_V51_XB_USER, 'password_generate', 'ttl=%s length=%s'%(ttl,length), 0, 'ok', '', request)
        return {'ok': True, 'password': new_pwd, 'expires_in': ttl, 'ttl': ttl, 'expire_at': expire.strftime('%Y-%m-%d %H:%M:%S'), 'one_time': False, 'time_only': True}

    async def _v51_password_status(request: _v51_Request):
        try: p = await _v51_body(request)
        except Exception: p = {}
        pwd = str(_v51_pick(p, 'password','maint_password','maintenance_password','pwd','pass')).strip()
        if pwd:
            _v51_require_any(pwd)
        _v51_fix_tables()
        rows = _v51_all('SELECT id,username,ttl,expire_at,created_at FROM maintenance_passwords WHERE username=%s AND used=0 AND (expire_at IS NULL OR expire_at>NOW()) ORDER BY id DESC LIMIT 10', (_V51_XB_USER,)) or []
        return {'ok': True, 'one_time': False, 'active_count': len(rows), 'items': rows}

    def _v51_forbid_shell(cmd):
        bad = ['sudo ', ' su ', ' su -', 'systemctl ', 'service ', 'nohup ', ' setsid ', ' chattr ', 'chmod 777', 'mkfs', 'dd if=', '>:','&']
        low = ' ' + str(cmd or '').lower() + ' '
        for b in bad:
            if b in low:
                return b.strip()
        return ''

    async def _v51_shell(request: _v51_Request):
        p = await _v51_body(request)
        pwd = str(_v51_pick(p, 'password','maint_password','maintenance_password','pwd','pass')).strip()
        _v51_require_any(pwd)
        cmd = str(_v51_pick(p, 'cmd','command')).strip()
        if not cmd:
            raise _v51_HTTPException(400, '命令不能为空')
        bad = _v51_forbid_shell(cmd)
        if bad:
            raise _v51_HTTPException(400, '普通Shell禁止命令: %s' % bad)
        cwd = str(_v51_pick(p, 'cwd','workdir', default='/www/wwwroot/iapt') or '/www/wwwroot/iapt').strip()
        if cwd not in _V51_ALLOWED_CWD:
            cwd = '/www/wwwroot/iapt'
        try: timeout = int(_v51_pick(p, 'timeout', default=30) or 30)
        except Exception: timeout = 30
        timeout = max(1, min(timeout, 120))
        run_cmd = ['bash','-lc', cmd]
        if hasattr(_v51_os, 'geteuid') and _v51_os.geteuid() == 0:
            try:
                _v51_subprocess.run(['id','iapt-maint'], stdout=_v51_subprocess.DEVNULL, stderr=_v51_subprocess.DEVNULL)
            except Exception:
                _v51_subprocess.run(['useradd','-r','-s','/usr/sbin/nologin','-d','/var/lib/iapt-maint','iapt-maint'], stdout=_v51_subprocess.DEVNULL, stderr=_v51_subprocess.DEVNULL)
            run_cmd = ['su','-s','/bin/bash','iapt-maint','-c', cmd]
        try:
            cp = _v51_subprocess.run(run_cmd, cwd=cwd, env={'PATH':'/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/tmp'}, text=True, capture_output=True, timeout=timeout)
            out, err = (cp.stdout or '')[:64000], (cp.stderr or '')[:64000]
            _v51_audit(_V51_XB_USER, 'shell', cmd, cp.returncode, out, err, request)
            return {'ok': cp.returncode == 0, 'exit_code': cp.returncode, 'stdout': out, 'stderr': err, 'cwd': cwd, 'user': 'iapt-maint' if hasattr(_v51_os,'geteuid') and _v51_os.geteuid()==0 else 'current'}
        except _v51_subprocess.TimeoutExpired as e:
            out, err = (e.stdout or '')[:64000], (e.stderr or '')[:64000]
            _v51_audit(_V51_XB_USER, 'shell_timeout', cmd, 124, out, err, request)
            return {'ok': False, 'exit_code': 124, 'stdout': out, 'stderr': err or 'timeout'}

    def _v51_run_root(action, args=''):
        base = '/www/wwwroot/iapt'
        mapping = {
            'whoami': 'whoami',
            'check_8000': "ss -lntp | grep ':8000' || true; curl -sS -i http://127.0.0.1:8000/app/config | head -20 || true",
            'restart_api': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
            'restart_worker': 'systemctl restart iapt.service 2>/dev/null || true; systemctl status iapt.service --no-pager -l 2>/dev/null | tail -60 || true',
            'restart_nginx': "systemctl reload nginx 2>/dev/null || service nginx reload 2>/dev/null || true",
            'tail_api_log': 'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
            'tail_worker_log': 'journalctl -u iapt.service -n 160 --no-pager 2>/dev/null || true',
            'tail_nginx_error': "tail -n 160 /www/wwwlogs/*.error.log 2>/dev/null || tail -n 160 /var/log/nginx/error.log 2>/dev/null || true",
            'py_compile': "cd /www/wwwroot/iapt && ./venv/bin/python -m py_compile app/main.py app/decrypt_runner.py app/cache.py app/quota.py app/db.py",
            'clear_pycache': "find /www/wwwroot/iapt/app -type d -name __pycache__ -prune -exec rm -rf {} +",
            'clear_task_cache': "find /www/wwwroot/iapt/storage -name file_index.json -o -name outer_key_cache.json -o -name container_plain.bin | xargs -r rm -f",
            'clear_source_caches': "cd /www/wwwroot/iapt && ./venv/bin/python -c \"from app import db; db.exec('DELETE FROM source_caches'); print('OK')\"",
            'recent_failed_tasks': "cd /www/wwwroot/iapt && ./venv/bin/python -c \"from app import db; import json; print(json.dumps(db.all('SELECT id,task_no,status,error,created_at FROM tasks ORDER BY id DESC LIMIT 20'), ensure_ascii=False, default=str))\"",
            'recent_task_options': "cd /www/wwwroot/iapt && ./venv/bin/python -c \"from app import db; import json; print(json.dumps(db.all('SELECT id,task_no,status,options_json,created_at FROM tasks ORDER BY id DESC LIMIT 20'), ensure_ascii=False, default=str))\"",
            'whitelist_schema': "cd /www/wwwroot/iapt && ./venv/bin/python -c \"from app import db; import json; print(json.dumps(db.all('SHOW COLUMNS FROM decrypt_whitelist'), ensure_ascii=False, default=str))\"",
            'du_storage': "du -sh /www/wwwroot/iapt/storage/* 2>/dev/null || true",
        }
        if action not in mapping:
            raise _v51_HTTPException(400, '不支持的维护动作')
        return _v51_subprocess.run(['bash','-lc', mapping[action]], cwd=base, text=True, capture_output=True, timeout=120)

    async def _v51_root_action(request: _v51_Request):
        p = await _v51_body(request)
        pwd = str(_v51_pick(p, 'password','maint_password','maintenance_password','pwd','pass')).strip()
        _v51_require_any(pwd)
        action = str(_v51_pick(p, 'action','name','root_action')).strip()
        if not action:
            raise _v51_HTTPException(400, '动作不能为空')
        cp = _v51_run_root(action, _v51_pick(p,'args','params',default=''))
        out, err = (cp.stdout or '')[:64000], (cp.stderr or '')[:64000]
        _v51_audit(_V51_XB_USER, 'root_action:'+action, action, cp.returncode, out, err, request)
        return {'ok': cp.returncode == 0, 'action': action, 'exit_code': cp.returncode, 'stdout': out, 'stderr': err}

    async def _v51_history(request: _v51_Request):
        try:
            limit = int(request.query_params.get('limit') or 30)
        except Exception:
            limit = 30
        limit = max(1, min(limit, 100))
        rows = _v51_all('SELECT id,username,action,command_text,exit_code,ip,created_at FROM maintenance_audit_logs ORDER BY id DESC LIMIT %s', (limit,)) or []
        return {'ok': True, 'items': rows}

    for _p in ('/maintenance/status','/api/maintenance/status'):
        app.add_api_route(_p, _v51_status, methods=['GET'])
    for _p in ('/maintenance/password/generate','/api/maintenance/password/generate'):
        app.add_api_route(_p, _v51_password_generate, methods=['POST'])
    for _p in ('/maintenance/password/status','/api/maintenance/password/status'):
        app.add_api_route(_p, _v51_password_status, methods=['GET','POST'])
    for _p in ('/maintenance/shell','/api/maintenance/shell'):
        app.add_api_route(_p, _v51_shell, methods=['POST'])
    for _p in ('/maintenance/root-action','/api/maintenance/root-action'):
        app.add_api_route(_p, _v51_root_action, methods=['POST'])
    for _p in ('/maintenance/history','/api/maintenance/history'):
        app.add_api_route(_p, _v51_history, methods=['GET','POST'])

    print('[IAPT_FIX] maint-password-time-ttl-v51 installed')
except Exception as _v51_e:
    print('[IAPT_FIX] maint-password-time-ttl-v51 install failed:', repr(_v51_e))
# __MAINT_PASSWORD_TIME_TTL_V51_END__


# __V6_ROUTE_FEATURE_FIX_V53_BEGIN__
# v53: 修复 V6 上传被当 V3、v52 SQL 百分号 TypeError、resource__cost__for__apk 未定义。
try:
    import json as _v53_json, shutil as _v53_shutil, secrets as _v53_secrets, traceback as _v53_traceback
    from fastapi import Request as _v53_Request, UploadFile as _v53_UploadFile, File as _v53_File, Form as _v53_Form, Depends as _v53_Depends, HTTPException as _v53_HTTPException

    _V53_TASK_POST_PATHS = {'/tasks/decrypt', '/api/tasks/decrypt'}
    _V53_TASK_GET_PATHS = {'/tasks', '/api/tasks'}

    def _v53_remove_routes(paths, methods):
        mset = {str(m).upper() for m in methods}
        kept = []
        removed = []
        for r in list(app.router.routes):
            rp = getattr(r, 'path', None)
            rm = {str(x).upper() for x in getattr(r, 'methods', set())}
            if rp in paths and (not mset.isdisjoint(rm)):
                removed.append((rp, sorted(rm), getattr(r, 'name', '')))
                continue
            kept.append(r)
        app.router.routes = kept
        print('[IAPT v53] removed routes:', removed)

    def _v53_int(v, default=0):
        try:
            if v is None or v == '':
                return default
            return int(v)
        except Exception:
            return default

    def _v53_bool(v):
        if v is True or v == 1:
            return True
        if isinstance(v, str):
            return v.strip().lower() in ('1', 'true', 'yes', 'on', 'y')
        return False

    def _v53_is_v6_options(options):
        options = options or {}
        fid = _v53_int(options.get('feature_id'), 0)
        ver = str(options.get('decrypt_version') or options.get('task_version') or options.get('version') or '').strip().lower()
        if fid == 6 or ver in ('v6', '6', 'iapp_v6'):
            return True
        for k in ('v6_upload_mode', 'v6_no_java', 'v6', 'use_v6', 'v6_dex_only'):
            if k in options:
                return True
        return False

    def _v53_feature_from_options(options):
        for _hidden_key in ('hidden_enum', 'hidden_prefix', 'hidden_charset', 'hidden_candidates', 'hidden_candidates_file', 'max_hidden_candidates'):
            if _hidden_key in (options or {}):
                raise _v53_HTTPException(400, 'so密钥枚举已下线，请使用dex密钥枚举')
        _old_ver = str(options.get('decrypt_version') or options.get('task_version') or options.get('version') or '').strip().lower()
        _old_mode = str(options.get('decrypt_scheme') or '').strip().lower() == 'ancient' or _v53_bool(options.get('legacy_iapp')) or _v53_bool(options.get('old_iapp')) or _old_ver in ('ancient', 'old', 'legacy', 'old_iapp', 'iapp_old')
        if _old_mode:
            basic = int(globals().get('FEATURE_BASIC', 1) or 1)
            dex = int(globals().get('FEATURE_DEX_ENUM', 2) or 2)
            server_sokey_fid = int(globals().get('FEATURE_HIDDEN_ENUM', 15) or 15)
            options['legacy_iapp'] = True
            options['old_iapp'] = True
            options['decrypt_scheme'] = 'ancient'
            options['decrypt_version'] = 'ancient'
            options['task_version'] = 'ancient'
            options['no_dynamic_key'] = True
            # The old format has no post_key/xor_key and never uses the V3 pool.
            for _k in ('dynamic_key','custom_dynamic_key','post_key','key_xor','server_key_pool_mode','server_key_pool_ref','dynamic_key_features','dynamic_key_sample_entry','dynamic_key_sample_abi','anti_qiushui','hidden_resource_restore', 'custom_main_file', 'anti_sample', 'anti_encrypt_sample', 'anti_encrypted_sample','dex_static_restore'):
                options.pop(_k, None)
            _old_sokey_enum = _v53_bool(options.get('sokey_enum'))
            _old_dex_enum = _v53_bool(options.get('dexkey_enum')) or _v53_bool(options.get('dex_enum'))
            _old_server_sokey = _v53_bool(options.get('server_sokey'))
            # V150: old/ancient-iApp may still need numeric command-table restore.
            # Keep it inside the ancient pipeline; do not rewrite the scheme to V3.
            _old_dynamic_restore = (
                _v53_bool(options.get('ancient_dynamic_restore'))
                or _v53_bool(options.get('numeric_restore'))
                or _v53_bool(options.get('dynamic_restore'))
                or str(options.get('restore_fn_names') or '').strip().lower() in ('auto', 'on', 'true', '1')
            )
            if _old_dynamic_restore:
                options['ancient_dynamic_restore'] = True
                options['v3_dynamic_restore'] = False
                options['numeric_restore'] = True
                options['dynamic_restore'] = True
                options['restore_fn_names'] = 'on'
                options['require_dex_upload'] = True
                options['primary_feature_id'] = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
            else:
                options['ancient_dynamic_restore'] = False
                options['v3_dynamic_restore'] = False
                options['numeric_restore'] = False
                options['dynamic_restore'] = False
                options['restore_fn_names'] = 'off'
                options.pop('primary_feature_id', None)
                options.pop('require_dex_upload', None)
            _old_hidden = str(options.get('hidden') or options.get('sokey') or '').strip()
            if _old_hidden and not __import__('re').fullmatch(r'[A-Za-z0-9]{4}', _old_hidden):
                raise _v53_HTTPException(400, 'sokey格式错误')
            if _old_dex_enum:
                for _k in ('fb','dexkey','client_dexkey','client_fb_auto','fb_auto'):
                    options.pop(_k, None)
                options['dexkey_enum'] = True
                options['dexkey_enum_start'] = int(options.get('dexkey_enum_start') or 3100000)
                options['dexkey_enum_stop'] = int(options.get('dexkey_enum_stop') or 10000000)
                if options['dexkey_enum_stop'] < options['dexkey_enum_start']:
                    options['dexkey_enum_start'], options['dexkey_enum_stop'] = options['dexkey_enum_stop'], options['dexkey_enum_start']
            if _old_sokey_enum:
                options.pop('hidden', None)
                options['sokey_enum'] = True
                options.setdefault('old_sokey_alphabet', 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789')
            options.pop('enum_workers', None)
            if _old_sokey_enum or _old_dex_enum:
                fid = dex
            elif _old_server_sokey:
                fid = server_sokey_fid
            elif _old_dynamic_restore:
                fid = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
            else:
                fid = basic
            options['feature_id'] = fid
            return fid
        if _v53_is_v6_options(options):
            options['feature_id'] = 6
            options['decrypt_version'] = 'v6'
            options.setdefault('task_version', 'v6')
            return 6
        basic = int(globals().get('FEATURE_BASIC', 1) or 1)
        dynamic = int(globals().get('FEATURE_DYNAMIC_KEY', 4) or 4)
        dex = int(globals().get('FEATURE_DEX_ENUM', 2) or 2)
        pool_one = int(globals().get('FEATURE_DYNAMIC_KEY_POOL', 15) or 15)
        pool_enum_fid = int(globals().get('FEATURE_DYNAMIC_KEY_POOL_ENUM', 16) or 16)
        server_sokey_fid = int(globals().get('FEATURE_HIDDEN_ENUM', 15) or 15)
        numeric_restore_fid = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
        v3_dynamic_restore = (
            _v53_bool(options.get('v3_dynamic_restore'))
            or _v53_bool(options.get('numeric_restore'))
            or _v53_bool(options.get('dynamic_restore'))
            or str(options.get('restore_fn_names') or '').strip().lower() in ('auto', 'on', 'true', '1')
        ) and not _v53_bool(options.get('source_restore'))
        server_sokey = _v53_bool(options.get('server_sokey'))
        sokey_enum = _v53_bool(options.get('sokey_enum'))
        dexkey_enum = _v53_bool(options.get('dexkey_enum'))
        pool_mode = str(options.get('server_key_pool_mode') or '').strip().lower()
        pool_ref = str(options.get('server_key_pool_ref') or '').strip()
        if pool_mode not in ('', 'none', 'enum', 'selected'):
            raise _v53_HTTPException(400, '服务器密钥池模式无效')
        if pool_mode == 'selected' and not pool_ref:
            raise _v53_HTTPException(400, '请选择服务器动态密钥')
        # V193：密钥池枚举与 SO/DexKey 枚举是三条独立候选轴。
        # 是否允许组合由创建任务处读取真实订阅功能14/999后决定，
        # 这里不能在尚未取得用户授权上下文时提前拒绝。
        joint_pool_enum = pool_mode == 'enum' and (sokey_enum or dexkey_enum)
        if pool_mode in ('enum', 'selected') and (_v53_bool(options.get('dynamic_key')) or bool(options.get('custom_dynamic_key') or options.get('post_key') or options.get('key_xor'))):
            raise _v53_HTTPException(400, '服务器密钥池、服务器自动动态Key、自定义动态Key只能选择一种')
        if (sokey_enum and dexkey_enum) or (pool_mode == 'enum' and (sokey_enum or dexkey_enum)):
            # DexKey+SO Key，或池枚举与任一密钥枚举组合，统一按功能14授权/计费。
            # 真全功能999由 active_subscription 的全功能语义覆盖。
            fid = int(globals().get('FEATURE_JOINT_KEY_ENUM', 14) or 14)
        elif pool_mode == 'enum':
            fid = pool_enum_fid
        elif sokey_enum or dexkey_enum or _v53_bool(options.get('dex_enum')):
            # 选择池中单个Key可以和sokey/dexkey枚举组合；主任务按枚举功能2计费，
            # 同时在创建任务处额外校验功能15。
            fid = dex
        elif pool_mode == 'selected':
            fid = pool_one
        elif _v53_bool(options.get('dynamic_key')):
            fid = dynamic
        elif server_sokey:
            fid = server_sokey_fid
        elif v3_dynamic_restore:
            fid = numeric_restore_fid
        else:
            fid = basic
        if _v53_bool(options.get('dex_enum')):
            options['dex_enum_start'] = int(options.get('dex_enum_start') or 1000000)
            options['dex_enum_limit'] = int(options.get('dex_enum_limit') or 20000)
            options['dex_enum_windows'] = int(options.get('dex_enum_windows') or 1)
        if sokey_enum or dexkey_enum:
            # 严格枚举：对应已知值全部丢弃，防止客户端/旧缓存绕过真实枚举。
            if sokey_enum:
                options.pop('hidden', None)
                options['sokey_enum_seconds'] = max(1, min(600, int(options.get('sokey_enum_seconds') or 180)))
                options['sokey_enum_files'] = max(1, min(8, int(options.get('sokey_enum_files') or 1)))
                options['sokey_max_candidates'] = max(0, int(options.get('sokey_max_candidates') or 0))
            if dexkey_enum:
                for _k in ('fb', 'dexkey', 'client_dexkey', 'client_fb_auto', 'fb_auto'):
                    options.pop(_k, None)
                options['dexkey_enum_start'] = int(options.get('dexkey_enum_start') or 1736417)
                options['dexkey_enum_stop'] = int(options.get('dexkey_enum_stop') or 5936417)
                if options['dexkey_enum_stop'] < options['dexkey_enum_start']:
                    options['dexkey_enum_start'], options['dexkey_enum_stop'] = options['dexkey_enum_stop'], options['dexkey_enum_start']
                options['no_dexkey_dex_hint'] = True
            # 枚举并发数不接受客户端配置；实际值由 worker 读取服务端 .env 的 IAPT_ENUM_WORKERS。
            options.pop('enum_workers', None)
            options['enum_quiet'] = True
            options['no_python_fallback'] = True
            options['dexkey_mian_prefix_kb'] = 64
            options['dexkey_max_so_keysets'] = max(1, min(64, int(options.get('dexkey_max_so_keysets') or 16)))
        if v3_dynamic_restore:
            # 功能5是 V3 的解密后修复阶段，不是 fn_restore/dex_restore 独立任务。
            options['v3_dynamic_restore'] = True
            options['numeric_restore'] = True
            options['dynamic_restore'] = True
            options['restore_fn_names'] = 'on'
            options['dex_static_restore'] = False
            options['decrypt_version'] = 'v3'
            options['task_version'] = 'v3'
            options['primary_feature_id'] = fid
        options['feature_id'] = fid
        options.setdefault('decrypt_version', 'v3')
        options.setdefault('task_version', 'v3')
        return fid

    def _v53_resource_cost_for_apk(size_bytes):
        # 兼容旧函数名，也防止 v52 误写成 resource__cost__for__apk 后直接 500。
        for name in ('resource_cost_for_apk', 'resource__cost__for__apk'):
            fn = globals().get(name)
            if callable(fn):
                try:
                    return int(fn(int(size_bytes or 0)))
                except Exception:
                    pass
        size_bytes = int(size_bytes or 0)
        if size_bytes <= 0:
            return 0
        return max(2, ((size_bytes + 1024 * 1024 - 1) // (1024 * 1024)) * 2)

    def _v53_estimate_cost(apk_path):
        fn = globals().get('estimate_lib_so_quota')
        if callable(fn):
            try:
                return int(fn(apk_path) or 0)
            except Exception:
                return 0
        return 0

    def _v53_options_hash(options):
        try:
            from .cache import options_hash as _oh
            return _oh(options or {})
        except Exception:
            import hashlib
            return hashlib.sha256(_v53_json.dumps(options or {}, ensure_ascii=False, sort_keys=True).encode('utf-8')).hexdigest()

    def _v53_sha256_file(path):
        try:
            from .cache import sha256_file as _sf
            return _sf(path)
        except Exception:
            import hashlib
            h = hashlib.sha256()
            with open(path, 'rb') as f:
                for b in iter(lambda: f.read(1024 * 1024), b''):
                    h.update(b)
            return h.hexdigest()

    def _v53_find_source_cache(apk_sha256, opt_hash, feature_id):
        try:
            from .cache import cleanup_source_cache
            cleanup_source_cache()
        except Exception:
            pass
        try:
            return db.one("""
                SELECT sc.*,t.app_name,t.package_name,t.version_name,t.version_code,t.total_ms,t.file_count,t.total_bytes,t.out_dir,t.log_path
                FROM source_caches sc JOIN tasks t ON sc.task_id=t.id
                WHERE sc.apk_sha256=%s AND sc.options_hash=%s AND sc.feature_id=%s AND sc.expire_at>NOW() AND t.status='done'
                ORDER BY sc.id DESC LIMIT 1
            """, (apk_sha256, opt_hash, int(feature_id)))
        except Exception as e:
            print('[IAPT v53] scoped cache query failed:', repr(e))
            return None

    def _v53_normalize_task_row(row):
        d = dict(row or {})
        opts = {}
        raw = d.get('options_json')
        if raw:
            try:
                opts = _v53_json.loads(raw) if isinstance(raw, str) else (raw or {})
            except Exception:
                opts = {}
        fid = _v53_int(d.get('feature_id'), 0)
        old_ver = str(opts.get('decrypt_version') or opts.get('task_version') or d.get('decrypt_version') or '').strip().lower()
        ancient = (
            str(opts.get('decrypt_scheme') or '').strip().lower() == 'ancient'
            or _v53_bool(opts.get('legacy_iapp')) or _v53_bool(opts.get('old_iapp'))
            or old_ver in ('ancient','old','legacy','old_iapp','iapp_old')
        )
        if fid <= 0:
            fid = int(globals().get('FEATURE_BASIC', 1) or 1)
        if not ancient and _v53_is_v6_options(opts):
            fid = 6
        if ancient and fid == 6:
            fid = _v53_int(opts.get('primary_feature_id') or opts.get('feature_id'), int(globals().get('FEATURE_BASIC', 1) or 1))
            if fid == 6: fid = int(globals().get('FEATURE_BASIC', 1) or 1)
        d['feature_id'] = fid
        task_kind = str(opts.get('task_kind') or '').strip().lower()
        is_key_task = task_kind == 'dynamic_key_extract' or bool(opts.get('dynamic_key_extract'))
        if ancient:
            d['decrypt_version'] = 'ancient'
        elif is_key_task:
            d['decrypt_version'] = 'key'
        else:
            d['decrypt_version'] = 'v6' if fid == 6 else str(opts.get('decrypt_version') or d.get('decrypt_version') or 'v3')
        d['task_version'] = d['decrypt_version']
        d.pop('options_json', None)
        return d

    def _v53_repair_old_v6_tasks():
        # 不用 LIKE '%...%'，避免 PyMySQL 在 args=() 时触发 not enough arguments for format string。
        try:
            db.exec("""
                UPDATE tasks SET feature_id=6
                WHERE (feature_id IS NULL OR feature_id<>6)
                  AND options_json IS NOT NULL
                  AND (
                    (LOCATE('"decrypt_version"', options_json)>0 AND LOCATE('v6', LOWER(options_json))>0)
                    OR (LOCATE('"task_version"', options_json)>0 AND LOCATE('v6', LOWER(options_json))>0)
                    OR LOCATE('"v6_upload_mode"', options_json)>0
                    OR LOCATE('"v6_no_java"', options_json)>0
                    OR LOCATE('"feature_id":6', REPLACE(options_json, ' ', ''))>0
                  )
            """)
        except Exception as e:
            print('[IAPT v53] repair old v6 tasks failed:', repr(e))

    def _v53_insert_task(task_no, user_id, apk_name, feature_id, options, apk_sha, opt_hash, resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note):
        options_text = _v53_json.dumps(options, ensure_ascii=False)
        candidates = [
            ("""
                INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
                VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
            """, (task_no, user_id, apk_name, feature_id, str(options.get('decrypt_version') or 'v3'), options_text, apk_sha, opt_hash, resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note)),
            ("""
                INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash)
                VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s)
            """, (task_no, user_id, apk_name, feature_id, str(options.get('decrypt_version') or 'v3'), options_text, apk_sha, opt_hash)),
            ("""
                INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json)
                VALUES(%s,%s,%s,'queued',%s,%s,%s)
            """, (task_no, user_id, apk_name, feature_id, str(options.get('decrypt_version') or 'v3'), options_text)),
        ]
        last = None
        for sql, args in candidates:
            try:
                return db.exec(sql, args)
            except Exception as e:
                last = e
                print('[IAPT v53] insert candidate failed:', repr(e))
        raise last

    _v53_repair_old_v6_tasks()
    _v53_remove_routes(_V53_TASK_POST_PATHS, {'POST'})
    _v53_remove_routes(_V53_TASK_GET_PATHS, {'GET'})

    @app.get('/api/tasks')
    @app.get('/tasks')
    def _v53_list_tasks(limit: int = Query(default=500), user=_v53_Depends(current_user)):
        limit = max(1, min(int(limit or 500), 5000))
        rows = db.all("""
            SELECT id,task_no,apk_name,app_name,package_name,version_name,version_code,status,total_ms,file_count,total_bytes,created_at,updated_at,error_text,feature_id,decrypt_version,out_dir,options_json
            FROM tasks WHERE user_id=%s ORDER BY id DESC LIMIT %s
        """, (user['id'], limit))
        return {'items': [_v53_normalize_task_row(_iapt_v86_reconcile_ancient_task(r) if '_iapt_v86_reconcile_ancient_task' in globals() else r) for r in (rows or [])]}

    @app.post('/api/tasks/decrypt')
    @app.post('/tasks/decrypt')
    def _v53_create_task(request: _v53_Request, apk: _v53_UploadFile = _v53_File(...), payload: str = _v53_Form(default=''), iv: str = _v53_Form(default=''), user=_v53_Depends(current_user)):
        if not payload:
            raise _v53_HTTPException(400, 'payload 缺失')
        try:
            from .secure import decrypt_json_payload as _dec_payload, sha256_hex as _sha256_hex
            body_hash = request.headers.get('x-body-hash')
            if body_hash and body_hash != _sha256_hex(payload):
                print('[IAPT v54] ignored multipart body hash mismatch')
            options = _dec_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt','')) or {}
        except _v53_HTTPException:
            raise
        except Exception as e:
            raise _v53_HTTPException(400, 'payload 解密失败：' + str(e))
        if not isinstance(options, dict):
            raise _v53_HTTPException(400, 'payload 格式错误')

        _iapt_old_ver = str(options.get('decrypt_version') or options.get('task_version') or '').strip().lower()
        _iapt_old_requested = str(options.get('decrypt_scheme') or '').strip().lower() == 'ancient' or _v53_bool(options.get('legacy_iapp')) or _v53_bool(options.get('old_iapp')) or _iapt_old_ver in ('ancient','old','legacy','old_iapp','iapp_old')
        if _iapt_old_requested:
            for _iapt_old_drop in ('dynamic_key','custom_dynamic_key','post_key','key_xor','server_key_pool_mode','server_key_pool_ref','dynamic_key_features','dynamic_key_sample_entry','dynamic_key_sample_abi','anti_qiushui','hidden_resource_restore', 'custom_main_file', 'anti_sample', 'anti_encrypt_sample', 'anti_encrypted_sample','dex_static_restore'):
                options.pop(_iapt_old_drop, None)

        # IAPT_V129_STRIP_CLIENT_ENTITLEMENT_BEGIN
        for _iapt_v129_k in ('features','features_json','feature_ids','feature_json','permissions','_server_feature_ids','subscription_features','server_features'):
            options.pop(_iapt_v129_k, None)
        # IAPT_V129_STRIP_CLIENT_ENTITLEMENT_END

        manual_dynamic_key = bool(options.get('custom_dynamic_key') or options.get('post_key') or options.get('key_xor'))
        auto_dynamic_key = bool(options.get('dynamic_key'))
        if manual_dynamic_key and auto_dynamic_key:
            raise _v53_HTTPException(400, '自定义动态key与服务器自动动态key不能同时开启')
        if manual_dynamic_key:
            import re as _v53_re
            pk = str(options.get('post_key', '')).strip().replace(' ', '')
            kx = str(options.get('key_xor', '')).strip().replace(' ', '')
            if not pk or not kx:
                raise _v53_HTTPException(400, '自定义动态key需要同时提供 post_key 和 key_xor')
            if (len(pk) % 2) or (len(kx) % 2) or not _v53_re.fullmatch(r'[0-9a-fA-F]+', pk) or not _v53_re.fullmatch(r'[0-9a-fA-F]+', kx):
                raise _v53_HTTPException(400, 'post_key/key_xor 必须是偶数长度十六进制')
            options['post_key'] = pk
            options['key_xor'] = kx

        feature_id = _v53_feature_from_options(options)
        # IAPT_ANTI_QIUSHUI_ADDITIVE_AUTH_V2_BEGIN
        _iapt_v1_require_anti_qiushui(int(user['id']), options)
        # IAPT_ANTI_QIUSHUI_ADDITIVE_AUTH_V2_END
        basic = int(globals().get('FEATURE_BASIC', 1) or 1)
        dyn = int(globals().get('FEATURE_DYNAMIC_KEY', 4) or 4)
        joint_enum_feature = int(globals().get('FEATURE_JOINT_KEY_ENUM', 14) or 14)
        pool_feature = int(globals().get('FEATURE_DYNAMIC_KEY_POOL', 15) or 15)
        pool_enum_feature = int(globals().get('FEATURE_DYNAMIC_KEY_POOL_ENUM', 16) or 16)
        server_sokey_feature = int(globals().get('FEATURE_HIDDEN_ENUM', 15) or 15)
        numeric_restore_feature = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
        v3_dynamic_restore_requested = _v53_bool(options.get('v3_dynamic_restore')) or _v53_bool(options.get('ancient_dynamic_restore'))
        server_sokey_requested = _v53_bool(options.get('server_sokey'))
        pool_mode = str(options.get('server_key_pool_mode') or '').strip().lower()
        pool_ref = str(options.get('server_key_pool_ref') or '').strip()
        sokey_enum_requested = _v53_bool(options.get('sokey_enum'))
        dexkey_enum_requested = _v53_bool(options.get('dexkey_enum'))
        key_enum_requested = sokey_enum_requested or dexkey_enum_requested
        joint_pool_enum_requested = pool_mode == 'enum' and key_enum_requested
        joint_enum_requested = (sokey_enum_requested and dexkey_enum_requested) or joint_pool_enum_requested
        try:
            if pool_mode == 'enum':
                from .dynamic_key_pool import list_decrypted as _pool_list_decrypted
                pool_enum_sub = active_subscription(user['id'], pool_enum_feature)
                joint_pool_sub = active_subscription(user['id'], joint_enum_feature) if joint_pool_enum_requested else None
                if not (pool_enum_sub or joint_pool_sub):
                    raise _v53_HTTPException(403, '当前订阅不支持服务器动态Key池枚举')
                if not _pool_list_decrypted():
                    raise _v53_HTTPException(400, '服务器动态Key池为空，请先提取或成功解密一个动态Key样本')
            elif pool_mode == 'selected':
                from .dynamic_key_pool import resolve_ref as _pool_resolve_ref
                if not active_subscription(user['id'], pool_feature):
                    raise _v53_HTTPException(403, '当前订阅不支持服务器动态Key池（功能15，功能0包含）')
                if not _pool_resolve_ref(pool_ref):
                    raise _v53_HTTPException(400, '选择的服务器动态Key不存在或已停用')
            if server_sokey_requested:
                sokey_sub = active_subscription(user['id'], server_sokey_feature)
                if not sokey_sub:
                    raise _v53_HTTPException(403, '当前订阅不支持服务器获取sokey（功能15，功能0包含）')
            if joint_enum_requested:
                joint_sub = active_subscription(user['id'], joint_enum_feature)
                if not joint_sub:
                    raise _v53_HTTPException(403, '联合密钥枚举需要功能14或真全功能999')
                options['joint_key_enum_entitled'] = True
            # 动态修复可以与动态Key/枚举等 V3 参数组合；主 feature_id 仍按
            # 实际解密方式计费，但服务端必须额外校验功能5，不能只依赖客户端勾选权限。
            if v3_dynamic_restore_requested and feature_id != numeric_restore_feature:
                numeric_sub = active_subscription(user['id'], numeric_restore_feature)
                if not numeric_sub:
                    raise _v53_HTTPException(403, '当前订阅不支持动态修复（功能5）')
            if feature_id == dyn:
                sub = active_subscription(user['id'], dyn)
                if not sub or int(sub.get('sub_id') or 0) == 0:
                    raise _v53_HTTPException(403, '当前订阅不支持动态Key')
            elif feature_id != basic:
                sub = active_subscription(user['id'], feature_id)
                if not sub:
                    raise _v53_HTTPException(403, '当前订阅不支持该功能')
            q0 = available_quota(user['id'], feature_id)
            if feature_id != basic and float(q0.get('total') or 0) <= 0:
                raise _v53_HTTPException(403, '当前订阅不支持该功能')
        except _v53_HTTPException:
            raise
        except Exception as e:
            raise _v53_HTTPException(500, '额度检查失败：' + str(e))

        task_no = _v53_secrets.token_hex(16)
        uploads_dir = APP_STORAGE / 'uploads'
        uploads_dir.mkdir(parents=True, exist_ok=True)
        apk_path = uploads_dir / f'{task_no}.apk'
        try:
            with apk_path.open('wb') as f:
                _v53_shutil.copyfileobj(apk.file, f)
            apk_size = int(apk_path.stat().st_size)
        except Exception as e:
            try: apk_path.unlink(missing_ok=True)
            except Exception: pass
            raise _v53_HTTPException(500, '保存 APK 失败：' + str(e))

        if apk_size <= 0:
            try: apk_path.unlink(missing_ok=True)
            except Exception: pass
            raise _v53_HTTPException(400, 'APK 文件为空')


        # IAPT_V118_CREATE_MARKER_FORCE_BEGIN
        try:
            if _iapt_v118_has_ancient_marker(apk_path):
                _iapt_v118_force_ancient_options(options)
        except Exception as _iapt_v118_marker_exc:
            print('[IAPT_V118] create marker check warn:', repr(_iapt_v118_marker_exc), flush=True)
        # IAPT_V118_CREATE_MARKER_FORCE_END


        # IAPT_V8_EXPLICIT_SCHEME_ONLY_V53_BEGIN
        # Do not probe and mutate the algorithm on the server.  The client-side
        # auto detector submits decrypt_scheme=ancient when its switch is on.
        # IAPT_V8_EXPLICIT_SCHEME_ONLY_V53_END

        resource_cost = _v53_resource_cost_for_apk(apk_size)
        try:
            q = available_quota(user['id'], feature_id)
            if int(q.get('total') or 0) < resource_cost:
                try: apk_path.unlink(missing_ok=True)
                except Exception: pass
                raise _v53_HTTPException(402, f'额度不足：提交该 APK 约需 {resource_cost} 额度，当前剩余 {q.get("total", 0)}')
            deduct_quota(user['id'], feature_id, resource_cost)
        except _v53_HTTPException:
            raise
        except ValueError as e:
            try: apk_path.unlink(missing_ok=True)
            except Exception: pass
            raise _v53_HTTPException(402, str(e))
        except Exception as e:
            try: apk_path.unlink(missing_ok=True)
            except Exception: pass
            raise _v53_HTTPException(500, '扣除提交额度失败：' + str(e))

        estimated_cost = _v53_estimate_cost(apk_path)
        try:
            quota_after_resource = int(available_quota(user['id'], feature_id).get('total') or 0)
        except Exception:
            quota_after_resource = 0
        version_text = '远古' if str(options.get('decrypt_version') or '').lower() == 'ancient' else ('V6' if feature_id == 6 else 'V3')
        resource_note = f'{version_text} 提交任务资源消耗：APK {apk_size} bytes，按 1MB=2 额度扣除 {resource_cost}，失败不退'
        quota_note = f'{version_text} 预计解密消耗约 {estimated_cost} 额度；创建后剩余额度 {quota_after_resource}，实际完成后按输出文件 10KB=1额度扣除并限制下载'

        apk_sha = _v53_sha256_file(apk_path)
        opt_hash = _v53_options_hash(options)
        hit = _v53_find_source_cache(apk_sha, opt_hash, feature_id)
        if hit:
            try:
                from .cache import attach_cache_to_new_task as _attach_cache
                tid = _attach_cache(user['id'], apk.filename or 'sample.apk', feature_id, options, apk_sha, opt_hash, hit)
                try:
                    db.exec("""
                        UPDATE tasks SET feature_id=%s,decrypt_version=%s,options_json=%s,resource_quota_cost=%s,resource_quota_deducted=1,resource_quota_note=%s,estimated_quota_cost=%s,quota_limit=%s,quota_note=%s
                        WHERE id=%s
                    """, (feature_id, str(options.get('decrypt_version') or 'v3'), _v53_json.dumps(options, ensure_ascii=False), resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note, tid))
                except Exception:
                    db.exec("UPDATE tasks SET feature_id=%s,decrypt_version=%s,options_json=%s WHERE id=%s", (feature_id, str(options.get('decrypt_version') or 'v3'), _v53_json.dumps(options, ensure_ascii=False), tid))
                try:
                    settle_decrypt_quota_once(tid)
                except Exception:
                    pass
                row = db.one('SELECT task_no FROM tasks WHERE id=%s', (tid,)) or {}
                return {'ok': True, 'task_id': tid, 'task_no': row.get('task_no'), 'status': 'done', 'cache_hit': True, 'feature_id': feature_id, 'decrypt_version': options.get('decrypt_version'), 'task_version': options.get('task_version'), 'resource_quota_cost': resource_cost, 'estimated_quota_cost': estimated_cost, 'quota_limit': quota_after_resource}
            except Exception as e:
                print('[IAPT v53] attach cache failed, fallback to queued:', repr(e))

        try:
            tid = _v53_insert_task(task_no, user['id'], apk.filename or 'sample.apk', feature_id, options, apk_sha, opt_hash, resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note)
            enqueue_task(tid)
        except Exception as e:
            try: apk_path.unlink(missing_ok=True)
            except Exception: pass
            raise _v53_HTTPException(500, '创建任务失败：' + str(e))
        return {'ok': True, 'task_id': tid, 'task_no': task_no, 'status': 'queued', 'cache_hit': False, 'feature_id': feature_id, 'decrypt_version': options.get('decrypt_version'), 'task_version': options.get('task_version'), 'resource_quota_cost': resource_cost, 'estimated_quota_cost': estimated_cost, 'quota_limit': quota_after_resource}

except Exception as _v53_e:
    print('[IAPT v53] route install failed:', repr(_v53_e))
    try:
        _v53_traceback.print_exc()
    except Exception:
        pass
# __V6_ROUTE_FEATURE_FIX_V53_END__


# IAPT_WHITELIST_EXPIRED_BOOL_V58_BEGIN
# v58: 白名单状态兼容客户端 optBoolean("expired")：expired/is_expired 返回 bool，active/valid 返回数字。
try:
    import datetime as _v58_dt, json as _v58_json, re as _v58_re
    from fastapi import Request as _V58Request, HTTPException as _V58HTTPException, Depends as _V58Depends
    try:
        from .secure import decrypt_json_payload as _v58_decrypt_json_payload
    except Exception:
        _v58_decrypt_json_payload = None
except Exception as _v58_import_err:
    print('[IAPT_V58_IMPORT_WARN]', _v58_import_err)


def _v58_exec(sql, args=()):
    return db.exec(sql, args)


def _v58_one(sql, args=()):
    return db.one(sql, args)


def _v58_all(sql, args=()):
    return db.all(sql, args)


def _v58_has_col(table, col):
    try:
        rows = _v58_all('SHOW COLUMNS FROM `%s`' % table)
        names = set()
        for r in rows or []:
            if isinstance(r, dict):
                names.add(str(r.get('Field') or r.get('field') or ''))
            elif r:
                names.add(str(r[0]))
        return col in names
    except Exception:
        return False


def _v58_ensure_whitelist_table():
    return None


def _v58_as_dict(r):
    if r is None:
        return {}
    if isinstance(r, dict):
        return r
    return {}


def _v58_dt_from_any(v):
    if v is None or v == '':
        return None
    if isinstance(v, _v58_dt.datetime):
        return v.replace(tzinfo=None)
    if isinstance(v, _v58_dt.date):
        return _v58_dt.datetime(v.year, v.month, v.day)
    s = str(v).strip()
    if not s or s.lower() in ('none', 'null', '永久', 'never'):
        return None
    s = s.replace('T', ' ').replace('Z', '').replace('/', '-').strip()
    s = _v58_re.sub(r'\.\d+$', '', s)
    s = _v58_re.sub(r'\s*[+-]\d\d:?\d\d$', '', s)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return _v58_dt.datetime.strptime(s, fmt)
        except Exception:
            pass
    try:
        return _v58_dt.datetime.fromisoformat(s)
    except Exception:
        return None


def _v58_expire_string(v):
    if v is None or v == '':
        return ''
    if isinstance(v, _v58_dt.datetime):
        return v.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(v, _v58_dt.date):
        return v.strftime('%Y-%m-%d 00:00:00')
    return str(v)


def _v58_whitelist_item(row):
    r = _v58_as_dict(row)
    exp_raw = r.get('expire_at') or r.get('expire_time') or r.get('expires_at') or r.get('expiry') or r.get('end_time')
    exp_dt = _v58_dt_from_any(exp_raw)
    now = _v58_dt.datetime.now()
    if exp_dt is None:
        status_cn = '永久'
        active_n = 1
        expired_b = False
        remain = 0
    else:
        expired_b = bool(exp_dt <= now)
        active_n = 0 if expired_b else 1
        status_cn = '过期' if expired_b else '生效'
        remain = max(0, int((exp_dt - now).total_seconds()))
    expired_n = 1 if expired_b else 0
    pkg = str(r.get('package_name') or r.get('package') or r.get('pkg') or r.get('packageName') or r.get('app_package') or '')
    h = str(r.get('code_hash') or r.get('file_hash') or r.get('hash') or r.get('sha256') or r.get('apk_hash') or '')
    exp_s = _v58_expire_string(exp_raw)
    return {
        'id': r.get('id'),
        'package_name': pkg, 'package': pkg, 'pkg': pkg, 'packageName': pkg, 'app_package': pkg,
        'code_hash': h, 'codeHash': h, 'file_hash': h, 'fileHash': h, 'hash': h, 'sha256': h, 'apk_hash': h,
        'expire_at': exp_s, 'expireAt': exp_s, 'expire_time': exp_s, 'expireTime': exp_s, 'expires_at': exp_s, 'expiresAt': exp_s, 'expiry': exp_s, 'end_time': exp_s,
        'note': r.get('note') or r.get('remark') or '',
        # 客户端可能 optString("status") / optString("status_text")。
        'status': status_cn, 'status_text': status_cn, 'statusText': status_cn,
        'status_label': status_cn, 'state': status_cn, 'state_text': status_cn, 'active_text': status_cn, 'activeText': status_cn,
        # 客户端旧代码可能 optInt("active")，所以 active 必须是 1/0，不能是 true/false。
        'active': active_n, 'valid': active_n, 'enabled': active_n, 'is_valid': active_n, 'isValid': active_n,
        # 客户端也可能 optBoolean("expired", true)，所以 expired 必须是 bool，不能是 0/1。
        'expired': expired_b, 'is_expired': expired_b, 'isExpired': expired_b, 'invalid': expired_b,
        # 同时给数字备份字段。
        'expired_int': expired_n, 'expiredInt': expired_n, 'is_expired_int': expired_n, 'isExpiredInt': expired_n,
        'active_bool': bool(active_n), 'activeBool': bool(active_n), 'valid_bool': bool(active_n), 'expired_bool': expired_b, 'expiredBool': expired_b,
        'remain_seconds': remain, 'remainSeconds': remain,
        'server_now': now.strftime('%Y-%m-%d %H:%M:%S'), 'serverNow': now.strftime('%Y-%m-%d %H:%M:%S'),
        'created_at': _v58_expire_string(r.get('created_at')), 'createdAt': _v58_expire_string(r.get('created_at')),
        'version': 'v58'
    }


def _v58_pick(body, *names, default=None):
    if not isinstance(body, dict):
        return default
    for n in names:
        if n in body and body.get(n) is not None:
            return body.get(n)
    data = body.get('data')
    if isinstance(data, dict):
        for n in names:
            if n in data and data.get(n) is not None:
                return data.get(n)
    return default


async def _v58_body(request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        return {}
    if _v58_decrypt_json_payload and 'data' in body and 'iv' in body:
        salt = request.headers.get('x-salt') or request.headers.get('X-Salt') or body.get('salt') or ''
        for call in (
            lambda: _v58_decrypt_json_payload(body, salt),
            lambda: _v58_decrypt_json_payload(body.get('data'), body.get('iv'), salt),
            lambda: _v58_decrypt_json_payload(body),
        ):
            try:
                dec = call()
                if isinstance(dec, str):
                    dec = _v58_json.loads(dec)
                if isinstance(dec, dict):
                    return dec
            except Exception:
                pass
    return body


def _v58_parse_expire(v):
    if v is None:
        return None
    s = str(v).strip()
    if not s or s.lower() in ('none', 'null', '永久', 'never'):
        return None
    dt = _v58_dt_from_any(s)
    if dt is None:
        raise _V58HTTPException(400, '到期时间格式错误，请使用 2027-12-31 23:59:59')
    return dt.strftime('%Y-%m-%d %H:%M:%S')


try:
    # 彻底移除所有 whitelist 路由，避免命中老接口或 strip /api 后的旧接口。
    app.router.routes = [r for r in app.router.routes if 'whitelist' not in str(getattr(r, 'path', '')).lower()]
except Exception as e:
    print('[IAPT_V58] remove whitelist routes warn:', e)


async def _v58_list_impl(q='', keyword='', search='', body=None):
    _v58_ensure_whitelist_table()
    kw = str(q or keyword or search or _v58_pick(body or {}, 'q', 'keyword', 'search', default='') or '').strip()
    if kw:
        like = '%' + kw + '%'
        rows = _v58_all('SELECT * FROM decrypt_whitelist WHERE package_name LIKE %s OR code_hash LIKE %s ORDER BY id DESC LIMIT 1000', (like, like))
    else:
        rows = _v58_all('SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT 1000')
    items = [_v58_whitelist_item(r) for r in (rows or [])]
    return {'ok': True, 'success': True, 'version': 'v58', 'items': items, 'data': items, 'list': items, 'rows': items, 'records': items, 'results': items, 'whitelist': items, 'total': len(items)}


@app.get('/admin/whitelist')
@app.get('/admin/whitelist/')
@app.get('/admin/whitelist/list')
@app.get('/admin/whitelist/list/')
@app.get('/admin/whitelist/search')
@app.get('/admin/whitelist/common/list')
@app.get('/api/admin/whitelist')
@app.get('/api/admin/whitelist/')
@app.get('/api/admin/whitelist/list')
@app.get('/api/admin/whitelist/list/')
@app.get('/api/admin/whitelist/search')
@app.get('/api/admin/whitelist/common/list')
@app.get('/whitelist/list')
@app.get('/whitelist/list/')
@app.get('/whitelist/search')
@app.get('/whitelist/common/list')
@app.get('/api/whitelist/list')
@app.get('/api/whitelist/list/')
@app.get('/api/whitelist/search')
@app.get('/api/whitelist/common/list')
@app.get('/app/whitelist/list')
@app.get('/api/app/whitelist/list')
@app.get('/admin/decrypt_whitelist/list')
@app.get('/api/admin/decrypt_whitelist/list')
@app.get('/decrypt_whitelist/list')
@app.get('/api/decrypt_whitelist/list')
async def _iapt_v58_whitelist_list_get(q: str = '', keyword: str = '', search: str = '', user=_V58Depends(current_user)):
    require_permission(user, 602)
    return await _v58_list_impl(q=q, keyword=keyword, search=search)


@app.post('/admin/whitelist')
@app.post('/admin/whitelist/list')
@app.post('/admin/whitelist/search')
@app.post('/admin/whitelist/common/list')
@app.post('/api/admin/whitelist')
@app.post('/api/admin/whitelist/list')
@app.post('/api/admin/whitelist/search')
@app.post('/api/admin/whitelist/common/list')
@app.post('/whitelist/list')
@app.post('/whitelist/search')
@app.post('/whitelist/common/list')
@app.post('/api/whitelist/list')
@app.post('/api/whitelist/search')
@app.post('/api/whitelist/common/list')
@app.post('/app/whitelist/list')
@app.post('/api/app/whitelist/list')
@app.post('/admin/decrypt_whitelist/list')
@app.post('/api/admin/decrypt_whitelist/list')
@app.post('/decrypt_whitelist/list')
@app.post('/api/decrypt_whitelist/list')
async def _iapt_v58_whitelist_list_post(request: _V58Request, user=_V58Depends(current_user)):
    require_permission(user, 602)
    body = await _v58_body(request)
    return await _v58_list_impl(body=body)


@app.post('/admin/whitelist/add')
@app.post('/admin/whitelist/save')
@app.post('/admin/whitelist/update')
@app.post('/api/admin/whitelist/add')
@app.post('/api/admin/whitelist/save')
@app.post('/api/admin/whitelist/update')
@app.post('/whitelist/add')
@app.post('/whitelist/save')
@app.post('/whitelist/update')
@app.post('/api/whitelist/add')
@app.post('/api/whitelist/save')
@app.post('/api/whitelist/update')
async def _iapt_v58_whitelist_save(request: _V58Request, user=_V58Depends(current_user)):
    require_permission(user, 602)
    _v58_ensure_whitelist_table()
    body = await _v58_body(request)
    wid = _v58_pick(body, 'id', 'wid', 'whitelist_id')
    pkg = str(_v58_pick(body, 'package_name', 'package', 'pkg', 'packageName', 'app_package', default='') or '').strip()
    h = str(_v58_pick(body, 'hash', 'code_hash', 'codeHash', 'file_hash', 'fileHash', 'sha256', 'code_sha256', 'apk_sha256', 'apk_hash', default='') or '').strip()
    note = str(_v58_pick(body, 'note', 'remark', default='') or '')
    exp = _v58_parse_expire(_v58_pick(body, 'expire_at', 'expireAt', 'expire_time', 'expireTime', 'expires_at', 'expiresAt', 'expired_at', 'expiry', 'end_time', default=''))
    if not pkg:
        raise _V58HTTPException(400, '包名不能为空')
    if not h:
        raise _V58HTTPException(400, 'hash不能为空')
    if not _v58_re.fullmatch(r'[0-9a-fA-F]{16,128}', h):
        raise _V58HTTPException(400, 'hash格式错误')
    if wid:
        _v58_exec('UPDATE decrypt_whitelist SET package_name=%s, code_hash=%s, expire_at=%s, note=%s WHERE id=%s', (pkg, h, exp, note, wid))
        new_id = int(wid)
    else:
        try:
            new_id = _v58_exec('INSERT INTO decrypt_whitelist(package_name, code_hash, expire_at, note) VALUES(%s,%s,%s,%s)', (pkg, h, exp, note))
        except Exception:
            _v58_exec('UPDATE decrypt_whitelist SET expire_at=%s, note=%s WHERE package_name=%s AND code_hash=%s', (exp, note, pkg, h))
            rr = _v58_one('SELECT id FROM decrypt_whitelist WHERE package_name=%s AND code_hash=%s ORDER BY id DESC LIMIT 1', (pkg, h))
            new_id = int((_v58_as_dict(rr)).get('id') or 0)
    item = _v58_whitelist_item(_v58_one('SELECT * FROM decrypt_whitelist WHERE id=%s', (new_id,))) if new_id else {}
    return {'ok': True, 'success': True, 'version': 'v58', 'item': item, 'data': item}


@app.post('/admin/whitelist/delete')
@app.post('/admin/whitelist/remove')
@app.post('/api/admin/whitelist/delete')
@app.post('/api/admin/whitelist/remove')
@app.post('/whitelist/delete')
@app.post('/whitelist/remove')
@app.post('/api/whitelist/delete')
@app.post('/api/whitelist/remove')
async def _iapt_v58_whitelist_delete(request: _V58Request, user=_V58Depends(current_user)):
    require_permission(user, 602)
    body = await _v58_body(request)
    wid = _v58_pick(body, 'id', 'wid', 'whitelist_id')
    if not wid:
        raise _V58HTTPException(400, 'id不能为空')
    _v58_exec('DELETE FROM decrypt_whitelist WHERE id=%s', (wid,))
    return {'ok': True, 'success': True, 'version': 'v58'}


try:
    _v58_ensure_whitelist_table()
    print('[OK] IAPT_WHITELIST_EXPIRED_BOOL_V58 installed')
except Exception as e:
    print('[IAPT_V58_INIT_WARN]', e)
# IAPT_WHITELIST_EXPIRED_BOOL_V58_END




# IAPT_WHITELIST_HARD_ENFORCE_V61_BEGIN
# v61: 白名单硬拦截。无需客户端配合：API 上传入口拦截 + worker 主解密入口二次拦截。
# 保护语义：decrypt_whitelist 命中且 expire_at 为空或未来时间 => 保护中，禁止普通用户解密。
try:
    import datetime as _v61_dt, json as _v61_json, re as _v61_re, hashlib as _v61_hashlib, zipfile as _v61_zipfile
    from email.parser import BytesParser as _V61BytesParser
    from email import policy as _v61_email_policy
    from fastapi import Request as _V61Request, Depends as _V61Depends
    from fastapi.responses import JSONResponse as _V61JSONResponse
    try:
        from .secure import decrypt_json_payload as _v61_decrypt_json_payload, read_secure_json as _v61_read_secure_json
    except Exception:
        _v61_decrypt_json_payload = None
        _v61_read_secure_json = None
except Exception as _v61_import_err:
    print('[IAPT_V61_IMPORT_WARN]', _v61_import_err)


def _v61_exec(sql, args=()): return db.exec(sql, args)
def _v61_one(sql, args=()): return db.one(sql, args)
def _v61_all(sql, args=()): return db.all(sql, args)


def _v61_has_col(table, col):
    try:
        rows = _v61_all('SHOW COLUMNS FROM `%s`' % table)
        names = set()
        for r in rows or []:
            if isinstance(r, dict): names.add(str(r.get('Field') or r.get('field') or ''))
            elif r: names.add(str(r[0]))
        return col in names
    except Exception:
        return False


def _v61_ensure_whitelist_table():
    return None


def _v61_dt_from_any(v):
    if v is None or v == '': return None
    if isinstance(v, _v61_dt.datetime): return v.replace(tzinfo=None)
    if isinstance(v, _v61_dt.date): return _v61_dt.datetime(v.year, v.month, v.day)
    s = str(v).strip()
    if not s or s.lower() in ('none', 'null', '永久', 'never'): return None
    s = s.replace('T', ' ').replace('Z', '').replace('/', '-').strip()
    s = _v61_re.sub(r'\.\d+$', '', s)
    s = _v61_re.sub(r'\s*[+-]\d\d:?\d\d$', '', s)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try: return _v61_dt.datetime.strptime(s[:19], fmt)
        except Exception: pass
    try: return _v61_dt.datetime.fromisoformat(s)
    except Exception: return None


def _v61_expire_string(v):
    if v is None or v == '': return ''
    if isinstance(v, _v61_dt.datetime): return v.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(v, _v61_dt.date): return v.strftime('%Y-%m-%d 00:00:00')
    return str(v)


def _v61_is_protecting(expire_at):
    dt = _v61_dt_from_any(expire_at)
    return True if dt is None else dt > _v61_dt.datetime.now()


def _v61_parse_features(v):
    if v is None: return set()
    if isinstance(v, (list, tuple, set)): src = v
    else:
        s = str(v).strip()
        try:
            j = _v61_json.loads(s); src = j if isinstance(j, list) else [j]
        except Exception:
            src = _v61_re.split(r'[^0-9]+', s)
    out = set()
    for x in src:
        try:
            if str(x).strip() != '': out.add(int(x))
        except Exception: pass
    return out


def _v61_user_has_bypass7(user_id):
    try:
        u = _v61_one('SELECT id,subscription_id FROM users WHERE id=%s', (int(user_id),))
        if not u: return False
        sid = u.get('subscription_id') if isinstance(u, dict) else None
        rows = []
        try: rows += _v61_all('SELECT * FROM subscriptions WHERE sub_id=%s', (sid,)) or []
        except Exception: pass
        try: rows += _v61_all('SELECT * FROM subscriptions WHERE id=%s', (sid,)) or []
        except Exception: pass
        for r in rows:
            if not isinstance(r, dict): continue
            feats = set()
            for k in ('features_json', 'features', 'feature_ids', 'feature_json'):
                feats |= _v61_parse_features(r.get(k))
            if 7 in feats or 999 in feats: return True
    except Exception as e:
        print('[IAPT_V61] bypass check warn:', e)
    return False


def _v61_session_user_id(request):
    try:
        auth = request.headers.get('authorization') or request.headers.get('Authorization') or ''
        if not auth.lower().startswith('bearer '): return None
        token = auth.split(' ', 1)[1].strip()
        row = _v61_one('SELECT user_id FROM sessions WHERE token=%s AND expire_at>NOW()', (token,))
        if row: return int(row.get('user_id') if isinstance(row, dict) else row[0])
    except Exception: pass
    return None


def _v61_norm_pkg(s):
    s = str(s or '').strip().lower()
    s = _v61_re.sub(r'\.(apk|dex|zip)$', '', s, flags=_v61_re.I)
    return s if _v61_re.match(r'^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$', s) else ''


def _v61_norm_hash(s):
    s = str(s or '').strip().lower()
    return s if _v61_re.fullmatch(r'[0-9a-f]{32,128}', s) else ''


def _v61_guess_pkg_from_filename(name):
    n = str(name or '').strip().split('/')[-1].split('\\')[-1]
    n = _v61_re.sub(r'\.(apk|zip|dex)$', '', n, flags=_v61_re.I)
    return _v61_norm_pkg(n)


def _v61_apk_hash_candidates(file_bytes=None, file_path='', options=None):
    options = options or {}
    hashes = []
    for k in ('code_hash','codeHash','hash','sha256','file_hash','fileHash','apk_sha256','apkSha256','apk_hash','apkHash','code_sha256','codeSha256','original_apk_sha256','client_apk_sha256','upload_apk_sha256'):
        h = _v61_norm_hash(options.get(k))
        if h: hashes.append(h)
    try:
        data = file_bytes
        if data is None and file_path:
            with open(file_path, 'rb') as f: data = f.read()
        if data:
            hashes.append(_v61_hashlib.sha256(data).hexdigest())
            import io
            try:
                with _v61_zipfile.ZipFile(io.BytesIO(data), 'r') as z:
                    for n in sorted(z.namelist()):
                        ln = n.lower()
                        if ln.endswith('.dex') or ln in ('androidmanifest.xml', 'resources.arsc'):
                            try: hashes.append(_v61_hashlib.sha256(z.read(n)).hexdigest())
                            except Exception: pass
            except Exception: pass
    except Exception:
        pass
    return [h for h in dict.fromkeys([_v61_norm_hash(x) for x in hashes]) if h]


def _v61_collect_pkg_hashes(options, file_bytes=None, file_name='', file_path=''):
    options = options or {}
    pkgs = []
    for k in ('package_name','package','pkg','packageName','app_package','client_package_name','original_package_name','apk_package'):
        if options.get(k): pkgs.append(str(options.get(k)))
    gp = _v61_guess_pkg_from_filename(file_name or file_path)
    if gp: pkgs.append(gp)
    hashes = _v61_apk_hash_candidates(file_bytes=file_bytes, file_path=file_path, options=options)
    return [p for p in dict.fromkeys([_v61_norm_pkg(x) for x in pkgs]) if p], hashes


def _v61_find_active_whitelist(pkgs, hashes):
    _v61_ensure_whitelist_table()
    pkgset = set([_v61_norm_pkg(p) for p in (pkgs or []) if p])
    hashset = set([_v61_norm_hash(h) for h in (hashes or []) if h])
    rows = []
    if hashset:
        ph = ','.join(['%s'] * len(hashset))
        try: rows += _v61_all('SELECT * FROM decrypt_whitelist WHERE LOWER(code_hash) IN (' + ph + ') ORDER BY id DESC LIMIT 80', tuple(hashset)) or []
        except Exception as e: print('[IAPT_V61] hash query warn:', e)
    if pkgset:
        pp = ','.join(['%s'] * len(pkgset))
        try: rows += _v61_all('SELECT * FROM decrypt_whitelist WHERE LOWER(package_name) IN (' + pp + ') ORDER BY id DESC LIMIT 80', tuple(pkgset)) or []
        except Exception as e: print('[IAPT_V61] package query warn:', e)
    seen = set()
    for r in rows:
        if not isinstance(r, dict): continue
        rid = r.get('id')
        if rid in seen: continue
        seen.add(rid)
        exp = r.get('expire_at') or r.get('expire_time') or r.get('expires_at')
        if not _v61_is_protecting(exp): continue
        row_hash = _v61_norm_hash(r.get('code_hash') or r.get('file_hash') or r.get('hash') or r.get('sha256'))
        row_pkg = _v61_norm_pkg(r.get('package_name') or r.get('package') or r.get('pkg') or r.get('packageName'))
        hash_match = bool(row_hash and row_hash in hashset)
        pkg_match = bool(row_pkg and row_pkg in pkgset)
        if hash_match or pkg_match:
            return {'id': rid, 'package_name': row_pkg, 'code_hash': row_hash, 'expire_at': _v61_expire_string(exp), 'match_mode': 'hash' if hash_match else 'package', 'message': '白名单保护中，到期前禁止解密'}
    return None


def _v61_guard_or_result(options, user_id=None, file_bytes=None, file_name='', file_path=''):
    if user_id and _v61_user_has_bypass7(user_id):
        return {'allowed': True, 'bypass': True, 'reason': 'feature_7'}
    pkgs, hashes = _v61_collect_pkg_hashes(options, file_bytes=file_bytes, file_name=file_name, file_path=file_path)
    hit = _v61_find_active_whitelist(pkgs, hashes)
    if hit:
        msg = hit.get('message') or '白名单保护中，到期前禁止解密'
        if hit.get('package_name'): msg += '：' + str(hit.get('package_name'))
        if hit.get('expire_at'): msg += '，到期 ' + str(hit.get('expire_at'))
        return {'allowed': False, 'blocked': True, 'message': msg, 'detail': msg, 'whitelist': hit, 'match_mode': hit.get('match_mode'), 'candidates': {'packages': pkgs[:10], 'hashes': hashes[:5]}}
    return {'allowed': True, 'blocked': False, 'candidates': {'packages': pkgs[:10], 'hashes': hashes[:5]}}


def _v61_parse_multipart(content_type, body):
    fields, files = {}, []
    try:
        raw = (('Content-Type: ' + str(content_type) + '\r\nMIME-Version: 1.0\r\n\r\n').encode('utf-8') + (body or b''))
        msg = _V61BytesParser(policy=_v61_email_policy.default).parsebytes(raw)
        if not msg.is_multipart(): return fields, files
        for part in msg.iter_parts():
            name = part.get_param('name', header='content-disposition'); filename = part.get_filename(); data = part.get_payload(decode=True) or b''
            if not name: continue
            if filename: files.append((name, filename, data))
            else: fields[name] = data.decode(part.get_content_charset() or 'utf-8', errors='replace')
    except Exception as e: print('[IAPT_V61] multipart parse warn:', e)
    return fields, files


def _v61_decode_payload_from_fields(fields, request):
    if not fields: return {}
    try:
        if fields.get('payload') and fields.get('iv') and _v61_decrypt_json_payload:
            return _v61_decrypt_json_payload({'data': fields.get('payload'), 'iv': fields.get('iv')}, request.headers.get('x-salt',''))
        if fields.get('data') and fields.get('iv') and _v61_decrypt_json_payload:
            return _v61_decrypt_json_payload({'data': fields.get('data'), 'iv': fields.get('iv')}, request.headers.get('x-salt',''))
    except Exception as e:
        print('[IAPT_V61] secure payload decode warn:', e)
    for k in ('options','json','payload'):
        if fields.get(k):
            try: return _v61_json.loads(fields.get(k))
            except Exception: pass
    return dict(fields)


def _v61_is_decrypt_create_path(path):
    p = (path or '').rstrip('/').lower()
    return p in ('/tasks/decrypt','/api/tasks/decrypt','/decrypt','/api/decrypt') or p.endswith('/tasks/decrypt')


@app.middleware('http')
async def _iapt_v61_whitelist_hard_upload_guard(request, call_next):
    return await call_next(request)


async def _iapt_v61_whitelist_check(request: _V61Request, user=_V61Depends(current_user)):
    if request.method.upper() == 'GET': data = dict(request.query_params)
    else:
        try:
            if _v61_read_secure_json: data = await _v61_read_secure_json(request, token='', verify=False)
            else:
                raw = await request.body(); data = _v61_json.loads(raw.decode('utf-8') or '{}') if raw else {}
        except Exception:
            raw = await request.body(); data = _v61_json.loads(raw.decode('utf-8') or '{}') if raw else {}
    return _v61_guard_or_result(data, user_id=int(user['id']), file_bytes=None, file_name=str(data.get('filename') or data.get('apk_name') or ''))


for _v61_p in ('/whitelist/check', '/api/whitelist/check', '/admin/whitelist/check', '/api/admin/whitelist/check'):
    try: app.add_api_route(_v61_p, _iapt_v61_whitelist_check, methods=['GET','POST'])
    except Exception: pass
try:
    _v61_ensure_whitelist_table()
    print('[OK] IAPT_WHITELIST_HARD_ENFORCE_V61 installed')
except Exception as e:
    print('[IAPT_V61_INIT_WARN]', e)
# IAPT_WHITELIST_HARD_ENFORCE_V61_END


# IAPT_WHITELIST_ENFORCE_V60_BEGIN
# v60: 白名单“生效”即保护中。到期前禁止上传/创建任务；runner 再做二次拦截。
try:
    import datetime as _v60_dt, json as _v60_json, re as _v60_re, hashlib as _v60_hashlib
    from email.parser import BytesParser as _V60BytesParser
    from email import policy as _v60_email_policy
    from fastapi import Request as _V60Request, HTTPException as _V60HTTPException, Depends as _V60Depends
    try:
        from .secure import decrypt_json_payload as _v60_decrypt_json_payload, read_secure_json as _v60_read_secure_json
    except Exception:
        _v60_decrypt_json_payload = None
        _v60_read_secure_json = None
except Exception as _v60_import_err:
    print('[IAPT_V60_IMPORT_WARN]', _v60_import_err)


def _v60_exec(sql, args=()): return db.exec(sql, args)
def _v60_one(sql, args=()): return db.one(sql, args)
def _v60_all(sql, args=()): return db.all(sql, args)


def _v60_has_col(table, col):
    try:
        rows = _v60_all('SHOW COLUMNS FROM `%s`' % table)
        names = set()
        for r in rows or []:
            if isinstance(r, dict): names.add(str(r.get('Field') or r.get('field') or ''))
            elif r: names.add(str(r[0]))
        return col in names
    except Exception:
        return False


def _v60_ensure_whitelist_table():
    return None


def _v60_dt_from_any(v):
    if v is None or v == '': return None
    if isinstance(v, _v60_dt.datetime): return v.replace(tzinfo=None)
    if isinstance(v, _v60_dt.date): return _v60_dt.datetime(v.year, v.month, v.day)
    s = str(v).strip()
    if not s or s.lower() in ('none', 'null', '永久', 'never'): return None
    s = s.replace('T', ' ').replace('Z', '').replace('/', '-').strip()
    s = _v60_re.sub(r'\.\d+$', '', s)
    s = _v60_re.sub(r'\s*[+-]\d\d:?\d\d$', '', s)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try: return _v60_dt.datetime.strptime(s[:19], fmt)
        except Exception: pass
    try: return _v60_dt.datetime.fromisoformat(s)
    except Exception: return None


def _v60_expire_string(v):
    if v is None or v == '': return ''
    if isinstance(v, _v60_dt.datetime): return v.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(v, _v60_dt.date): return v.strftime('%Y-%m-%d 00:00:00')
    return str(v)


def _v60_is_protecting(expire_at):
    dt = _v60_dt_from_any(expire_at)
    return True if dt is None else dt > _v60_dt.datetime.now()


def _v60_parse_features(v):
    if v is None: return set()
    if isinstance(v, (list, tuple, set)): src = v
    else:
        s = str(v).strip()
        try:
            j = _v60_json.loads(s); src = j if isinstance(j, list) else [j]
        except Exception:
            src = _v60_re.split(r'[^0-9]+', s)
    out = set()
    for x in src:
        try:
            if str(x).strip() != '': out.add(int(x))
        except Exception: pass
    return out


def _v60_user_has_bypass7(user_id):
    try:
        u = _v60_one('SELECT id,subscription_id FROM users WHERE id=%s', (int(user_id),))
        if not u: return False
        sid = u.get('subscription_id') if isinstance(u, dict) else None
        rows = []
        try: rows += _v60_all('SELECT * FROM subscriptions WHERE sub_id=%s', (sid,)) or []
        except Exception: pass
        try: rows += _v60_all('SELECT * FROM subscriptions WHERE id=%s', (sid,)) or []
        except Exception: pass
        for r in rows:
            if not isinstance(r, dict): continue
            feats = set()
            for k in ('features_json', 'features', 'feature_ids', 'feature_json'):
                feats |= _v60_parse_features(r.get(k))
            if 7 in feats or 999 in feats: return True
    except Exception as e:
        print('[IAPT_V60] bypass check warn:', e)
    return False


def _v60_session_user_id(request):
    try:
        auth = request.headers.get('authorization') or request.headers.get('Authorization') or ''
        if not auth.lower().startswith('bearer '): return None
        token = auth.split(' ', 1)[1].strip()
        row = _v60_one('SELECT user_id FROM sessions WHERE token=%s AND expire_at>NOW()', (token,))
        if row: return int(row.get('user_id') if isinstance(row, dict) else row[0])
    except Exception: pass
    return None


def _v60_norm_pkg(s):
    s = str(s or '').strip().lower()
    return _v60_re.sub(r'\.(apk|dex|zip)$', '', s, flags=_v60_re.I)


def _v60_norm_hash(s):
    s = str(s or '').strip().lower()
    return s if _v60_re.fullmatch(r'[0-9a-f]{32,128}', s) else ''


def _v60_guess_pkg_from_filename(name):
    n = str(name or '').strip().split('/')[-1].split('\\')[-1]
    n = _v60_re.sub(r'\.(apk|zip|dex)$', '', n, flags=_v60_re.I)
    return n if _v60_re.match(r'^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$', n) else ''


def _v60_collect_pkg_hashes(options, file_bytes=None, file_name=''):
    options = options or {}
    pkgs = []
    for k in ('package_name','package','pkg','packageName','app_package','client_package_name','original_package_name','apk_package'):
        if options.get(k): pkgs.append(str(options.get(k)))
    gp = _v60_guess_pkg_from_filename(file_name)
    if gp: pkgs.append(gp)
    hashes = []
    for k in ('code_hash','codeHash','hash','sha256','file_hash','fileHash','apk_sha256','apkSha256','apk_hash','apkHash','code_sha256','codeSha256','original_apk_sha256','client_apk_sha256','upload_apk_sha256'):
        h = _v60_norm_hash(options.get(k))
        if h: hashes.append(h)
    if file_bytes:
        try: hashes.append(_v60_hashlib.sha256(file_bytes).hexdigest())
        except Exception: pass
    return [p for p in dict.fromkeys([_v60_norm_pkg(x) for x in pkgs]) if p], [h for h in dict.fromkeys([_v60_norm_hash(x) for x in hashes]) if h]


def _v60_find_active_whitelist(pkgs, hashes):
    _v60_ensure_whitelist_table()
    if not hashes: return None
    ph = ','.join(['%s'] * len(hashes))
    try: rows = _v60_all('SELECT * FROM decrypt_whitelist WHERE LOWER(code_hash) IN (' + ph + ') ORDER BY id DESC LIMIT 50', tuple(hashes)) or []
    except Exception as e:
        print('[IAPT_V60] whitelist query warn:', e); rows = []
    pkgset = set([_v60_norm_pkg(p) for p in (pkgs or []) if p])
    for r in rows:
        if not isinstance(r, dict): continue
        row_hash = _v60_norm_hash(r.get('code_hash') or r.get('file_hash') or r.get('hash') or r.get('sha256'))
        if row_hash not in hashes: continue
        row_pkg = _v60_norm_pkg(r.get('package_name') or r.get('package') or r.get('pkg') or r.get('packageName'))
        if pkgset and row_pkg and row_pkg not in pkgset: continue
        exp = r.get('expire_at') or r.get('expire_time') or r.get('expires_at')
        if _v60_is_protecting(exp):
            return {'id': r.get('id'), 'package_name': row_pkg, 'code_hash': row_hash, 'expire_at': _v60_expire_string(exp), 'status': '生效' if exp else '永久', 'message': '白名单保护中，到期前禁止解密'}
    return None


def _v60_guard_or_result(options, user_id=None, file_bytes=None, file_name='', raise_error=True):
    if user_id and _v60_user_has_bypass7(user_id):
        return {'allowed': True, 'bypass': True, 'reason': 'feature_7'}
    pkgs, hashes = _v60_collect_pkg_hashes(options, file_bytes=file_bytes, file_name=file_name)
    hit = _v60_find_active_whitelist(pkgs, hashes)
    if hit:
        msg = hit.get('message') or '白名单保护中，到期前禁止解密'
        if hit.get('package_name'): msg += '：' + str(hit.get('package_name'))
        if hit.get('expire_at'): msg += '，到期 ' + str(hit.get('expire_at'))
        if raise_error: raise _V60HTTPException(403, msg)
        return {'allowed': False, 'blocked': True, 'message': msg, 'whitelist': hit, 'matched_package': hit.get('package_name'), 'matched_hash': hit.get('code_hash')}
    return {'allowed': True, 'blocked': False, 'pkgs': pkgs, 'hashes': hashes[:3]}


def _v60_parse_multipart(content_type, body):
    fields, files = {}, []
    try:
        raw = (('Content-Type: ' + str(content_type) + '\r\nMIME-Version: 1.0\r\n\r\n').encode('utf-8') + (body or b''))
        msg = _V60BytesParser(policy=_v60_email_policy.default).parsebytes(raw)
        if not msg.is_multipart(): return fields, files
        for part in msg.iter_parts():
            name = part.get_param('name', header='content-disposition'); filename = part.get_filename(); data = part.get_payload(decode=True) or b''
            if not name: continue
            if filename: files.append((name, filename, data))
            else: fields[name] = data.decode(part.get_content_charset() or 'utf-8', errors='replace')
    except Exception as e: print('[IAPT_V60] multipart parse warn:', e)
    return fields, files


def _v60_decode_payload_from_fields(fields, request):
    if not fields: return {}
    if fields.get('payload') and fields.get('iv') and _v60_decrypt_json_payload:
        return _v60_decrypt_json_payload({'data': fields.get('payload'), 'iv': fields.get('iv')}, request.headers.get('x-salt',''))
    if fields.get('data') and fields.get('iv') and _v60_decrypt_json_payload:
        return _v60_decrypt_json_payload({'data': fields.get('data'), 'iv': fields.get('iv')}, request.headers.get('x-salt',''))
    for k in ('options','json','payload'):
        if fields.get(k):
            try: return _v60_json.loads(fields.get(k))
            except Exception: pass
    return {}


@app.middleware('http')
async def _iapt_v60_whitelist_upload_guard(request, call_next):
    return await call_next(request)


async def _iapt_v60_check_body(request, user):
    if request.method.upper() == 'GET': data = dict(request.query_params)
    else:
        if _v60_read_secure_json: data = await _v60_read_secure_json(request, token='', verify=False)
        else:
            raw = await request.body(); data = _v60_json.loads(raw.decode('utf-8') or '{}') if raw else {}
    return _v60_guard_or_result(data, user_id=int(user['id']), file_bytes=None, file_name=str(data.get('filename') or data.get('apk_name') or ''), raise_error=False)


async def _iapt_v60_whitelist_check(request: _V60Request, user=_V60Depends(current_user)):
    return await _iapt_v60_check_body(request, user)


for _v60_p in ('/whitelist/check', '/api/whitelist/check', '/admin/whitelist/check', '/api/admin/whitelist/check'):
    try: app.add_api_route(_v60_p, _iapt_v60_whitelist_check, methods=['GET','POST'])
    except Exception: pass
try:
    _v60_ensure_whitelist_table()
    print('[OK] IAPT_WHITELIST_ENFORCE_V60 installed')
except Exception as e:
    print('[IAPT_V60_INIT_WARN]', e)
# IAPT_WHITELIST_ENFORCE_V60_END


# ===== IAPT CONFIG ADMIN SYNC V74 START =====
# 作用：统一后台“系统设置”与公开 /app/config 返回值。
# 修复：后台公告/更新已打开，但 /app/config 仍返回 announcement_enabled=false/version=v40 的问题。
import json as _v74_json
from datetime import datetime as _v74_datetime

try:
    from fastapi import Request as _V74Request, Depends as _V74Depends, HTTPException as _V74HTTPException
except Exception:
    _V74Request = None
    _V74Depends = None
    _V74HTTPException = Exception

try:
    from app import db as _v74_db
except Exception:
    _v74_db = None


def _v74_db_all(sql, args=None):
    if _v74_db is None:
        return []
    if hasattr(_v74_db, 'all'):
        return _v74_db.all(sql, args or ()) or []
    if hasattr(_v74_db, 'query_all'):
        return _v74_db.query_all(sql, args or ()) or []
    return []


def _v74_db_exec(sql, args=None):
    if _v74_db is None:
        return None
    if hasattr(_v74_db, 'exec'):
        return _v74_db.exec(sql, args or ())
    if hasattr(_v74_db, 'execute'):
        return _v74_db.execute(sql, args or ())
    return None


def _v74_row_get(row, key, default=''):
    try:
        if isinstance(row, dict):
            return row.get(key, default)
        # 兼容 tuple/list：app_settings 查询固定为 k,v
        if key == 'k':
            return row[0]
        if key == 'v':
            return row[1]
    except Exception:
        pass
    return default


def _v74_bool(v, default=False):
    try:
        if v is None:
            return default
        if isinstance(v, bool):
            return v
        if isinstance(v, (int, float)):
            return int(v) != 0
        s = str(v).strip().lower()
        if s in ('1','true','yes','on','y','开启','开','是'):
            return True
        if s in ('0','false','no','off','n','关闭','关','否'):
            return False
        return default
    except Exception:
        return default


def _v74_int(v, default=0):
    try:
        if v is None:
            return default
        if isinstance(v, (int, float)):
            return int(v)
        s = str(v).strip()
        if not s:
            return default
        m = re.search(r'\d+', s)
        return int(m.group(0)) if m else default
    except Exception:
        return default


def _v74_first(m, keys, default=''):
    for k in keys:
        try:
            v = m.get(k, '')
            if v is not None and str(v).strip() != '':
                return str(v).strip()
        except Exception:
            pass
    return default


def _v74_ensure_app_settings():
    try:
        _v74_db_exec("CREATE TABLE IF NOT EXISTS app_settings (k VARCHAR(191) PRIMARY KEY, v TEXT NULL, updated_at TIMESTAMP NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) DEFAULT CHARSET=utf8mb4")
    except Exception:
        pass


def _v74_settings_map():
    _v74_ensure_app_settings()
    m = {}
    # 主表：app_settings(k,v)
    try:
        rows = _v74_db_all('SELECT k,v FROM app_settings')
        for r in rows:
            k = str(_v74_row_get(r, 'k', '') or '').strip()
            if k:
                m[k] = str(_v74_row_get(r, 'v', '') or '')
    except Exception:
        pass
    # 兼容 settings 表常见字段
    for sql in (
        'SELECT k,v FROM settings',
        'SELECT `key` AS k, `value` AS v FROM settings',
        'SELECT name AS k, value AS v FROM settings',
        'SELECT setting_key AS k, setting_value AS v FROM settings',
    ):
        try:
            rows = _v74_db_all(sql)
            for r in rows:
                k = str(_v74_row_get(r, 'k', '') or '').strip()
                if k and k not in m:
                    m[k] = str(_v74_row_get(r, 'v', '') or '')
        except Exception:
            pass
    return m


def _v74_config_payload():
    m = _v74_settings_map()

    app_enabled = _v74_bool(_v74_first(m, ['app_enabled','software_enabled','client_enabled'], '1'), True)
    register_enabled = _v74_bool(_v74_first(m, ['register_enabled','allow_register'], '1'), True)
    app_closed_message = _v74_first(m, ['app_closed_message','closed_message','close_message'], '软件维护中')

    ann_enabled = _v74_bool(_v74_first(m, ['announcement_enabled','show_announcement','notice_enabled'], '0'), False)
    ann_title = _v74_first(m, ['announcement_title','notice_title'], '公告')
    ann_text = _v74_first(m, ['announcement_text','announcement_content','announcement','notice_text','notice_content','notice'], '')

    update_enabled = _v74_bool(_v74_first(m, ['update_enabled','has_update'], '1'), True)
    force_update = _v74_bool(_v74_first(m, ['force_update','forced_update','update_force'], '0'), False)
    update_version_code = _v74_int(_v74_first(m, ['update_version_code','version_code','update_code'], '0'), 0)
    update_version_name = _v74_first(m, ['update_version_name','update_version','version_name','version'], '')
    if update_version_code <= 0:
        update_version_code = _v74_int(update_version_name, 0)
    update_url = _v74_first(m, ['update_url','download_url','apk_url','url'], '')
    update_log = _v74_first(m, ['update_log','update_note','update_notes','update_content','update_message','log','note'], '')

    # 如果后台打开公告但没有文字，则不强行关闭；客户端首页卡片会根据文字决定是否显示。
    payload = {
        'ok': True,
        'server_time': str(_v74_datetime.now()),
        'app_enabled': app_enabled,
        'register_enabled': register_enabled,
        'app_closed_message': app_closed_message,

        # 公告：同时返回旧字段和新字段，兼容客户端首页卡片。
        'announcement_enabled': ann_enabled,
        'show_announcement': ann_enabled,
        'notice_enabled': ann_enabled,
        'announcement_title': ann_title,
        'announcement_text': ann_text,
        'announcement_content': ann_text,
        'announcement': ann_text,
        'notice_title': ann_title,
        'notice_text': ann_text,
        'announcement_obj': {'enabled': ann_enabled, 'title': ann_title, 'text': ann_text},

        # 更新：同时返回旧字段和新字段，兼容检测页。
        'update_enabled': update_enabled,
        'force_update': force_update,
        'forced_update': force_update,
        'update_force': force_update,
        'update_version_code': update_version_code,
        'update_version_name': update_version_name,
        'version_code': update_version_code,
        'version_name': update_version_name,
        'version': update_version_name or str(update_version_code or ''),
        'update_url': update_url,
        'download_url': update_url,
        'update_log': update_log,
        'update_note': update_log,
        'update': {
            'enabled': update_enabled,
            'force': force_update,
            'force_update': force_update,
            'version_code': update_version_code,
            'code': update_version_code,
            'version_name': update_version_name,
            'version': update_version_name or str(update_version_code or ''),
            'url': update_url,
            'download_url': update_url,
            'log': update_log,
            'note': update_log,
            'content': update_log,
            'message': update_log,
        },
        # 方便调试：说明当前已由 v74 接管。
        '_config_source': 'app_settings/settings synced by v74',
    }
    # 兼容客户端 optJSONObject("announcement")，但旧客户端也可能 optString("announcement")。
    # org.json 里同一个 key 不能同时是对象和字符串，因此保留 announcement 为字符串，另给 announcement_obj。
    return payload


def _v74_remove_routes(paths, methods=None):
    try:
        new_routes = []
        methods_u = set([str(x).upper() for x in methods]) if methods else None
        for r in list(app.router.routes):
            p = getattr(r, 'path', '')
            ms = set(getattr(r, 'methods', set()) or set())
            if p in paths and (methods_u is None or not ms or (ms & methods_u)):
                continue
            new_routes.append(r)
        app.router.routes = new_routes
    except Exception:
        pass


_v74_remove_routes({'/app/config','/api/app/config','/api/config','/config'}, {'GET'})

@app.get('/app/config')
@app.get('/api/app/config')
@app.get('/api/config')
@app.get('/config')
def _iapt_v74_app_config():
    return _v74_config_payload()

# ===== IAPT CONFIG ADMIN SYNC V74 END =====

# === IAPT_ADMIN_APP_SETTINGS_V77_START ===
# v77: 修复管理后台 /admin/app/settings 读写，并让 /app/config 读取同一份配置。
# 目标：后台保存的公告/更新/注册/软件开关，与客户端公开配置接口完全一致。
import json as _v77_json
import re as _v77_re
from datetime import datetime as _v77_datetime
try:
    from fastapi import Depends as _v77_Depends, Request as _v77_Request, HTTPException as _v77_HTTPException
except Exception:
    _v77_Depends = Depends
    _v77_Request = Request
    _v77_HTTPException = HTTPException
try:
    from app.auth import current_user as _v77_current_user, has_permission as _v77_has_permission
except Exception:
    _v77_current_user = current_user
    def _v77_has_permission(user, pid):
        try:
            require_permission(user, pid)
            return True
        except Exception:
            return False
try:
    from app.secure import read_secure_json as _v77_read_secure_json
except Exception:
    _v77_read_secure_json = read_secure_json
try:
    import app.db as _v77_db
except Exception:
    _v77_db = db

_v77_PERM_REGISTER = 501
_v77_PERM_ANNOUNCEMENT = 502
_v77_PERM_UPDATE = 503
_v77_PERM_APP = 504
_v77_PERMS = (_v77_PERM_REGISTER, _v77_PERM_ANNOUNCEMENT, _v77_PERM_UPDATE, _v77_PERM_APP, 999)


def _v77_row_get(row, key, default=None):
    if row is None:
        return default
    if isinstance(row, dict):
        return row.get(key, default)
    try:
        if hasattr(row, "keys"):
            return row[key]
    except Exception:
        pass
    if isinstance(row, (list, tuple)):
        return default
    return default


def _v77_all(sql, args=None):
    for name in ("all", "query", "select"):
        fn = getattr(_v77_db, name, None)
        if fn:
            try:
                return fn(sql, args or ())
            except TypeError:
                try:
                    return fn(sql)
                except Exception:
                    return []
            except Exception:
                return []
    return []


def _v77_one(sql, args=None):
    fn = getattr(_v77_db, "one", None)
    if fn:
        try:
            return fn(sql, args or ())
        except TypeError:
            try:
                return fn(sql)
            except Exception:
                return None
        except Exception:
            return None
    rows = _v77_all(sql, args)
    return rows[0] if rows else None


def _v77_exec(sql, args=None):
    fn = getattr(_v77_db, "exec", None) or getattr(_v77_db, "execute", None)
    if not fn:
        return False
    try:
        fn(sql, args or ())
        return True
    except TypeError:
        try:
            fn(sql)
            return True
        except Exception:
            return False
    except Exception:
        return False


def _v77_ensure_table():
    return _v77_exec("CREATE TABLE IF NOT EXISTS `iapt_app_settings` (`key` varchar(128) NOT NULL PRIMARY KEY, `value` text NULL, `updated_at` timestamp NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) DEFAULT CHARSET=utf8mb4")


def _v77_bool(v, default=False):
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    if s in ("1", "true", "yes", "on", "open", "enable", "enabled", "开启", "打开", "是"):
        return True
    if s in ("0", "false", "no", "off", "close", "disable", "disabled", "关闭", "否"):
        return False
    return default


def _v77_int(v, default=0):
    if v is None:
        return default
    try:
        return int(float(str(v).strip().lstrip("vV")))
    except Exception:
        m = _v77_re.search(r"\d+", str(v))
        return int(m.group(0)) if m else default


def _v77_str(v, default=""):
    if v is None:
        return default
    if isinstance(v, (dict, list)):
        try:
            return _v77_json.dumps(v, ensure_ascii=False)
        except Exception:
            return str(v)
    return str(v)


def _v77_set(key, value):
    _v77_ensure_table()
    if isinstance(value, bool):
        val = "1" if value else "0"
    elif isinstance(value, (dict, list)):
        val = _v77_json.dumps(value, ensure_ascii=False)
    else:
        val = "" if value is None else str(value)
    if not _v77_exec("REPLACE INTO `iapt_app_settings` (`key`,`value`) VALUES(%s,%s)", (key, val)):
        _v77_exec("INSERT INTO `iapt_app_settings` (`key`,`value`) VALUES(%s,%s) ON DUPLICATE KEY UPDATE `value`=VALUES(`value`)", (key, val))


def _v77_kv_load():
    _v77_ensure_table()
    out = {}
    for r in _v77_all("SELECT `key`,`value` FROM `iapt_app_settings`") or []:
        out[_v77_str(_v77_row_get(r, "key"))] = _v77_row_get(r, "value")
    return out


def _v77_put_alias(out, raw_key, raw_val):
    if raw_key is None:
        return
    k = str(raw_key).strip()
    if not k:
        return
    lk = k.lower()
    alias = {
        "app_enabled": ["app_enabled", "software_enabled", "client_enabled", "app_open", "software_open", "enable_app", "enabled_504"],
        "register_enabled": ["register_enabled", "allow_register", "registration_enabled", "enable_register", "enabled_501"],
        "app_closed_message": ["app_closed_message", "close_message", "app_close_message", "disable_message", "closed_tip"],
        "announcement_enabled": ["announcement_enabled", "show_announcement", "announcement_show", "notice_enabled", "show_notice", "enabled_502"],
        "announcement_title": ["announcement_title", "notice_title", "title_announcement"],
        "announcement_text": ["announcement", "announcement_text", "announcement_content", "announcement_message", "notice", "notice_text", "notice_content", "notice_message"],
        "update_version_code": ["update_version_code", "version_code", "cloud_version_code", "latest_version_code", "new_version_code", "apk_version_code"],
        "update_version_name": ["update_version_name", "version_name", "version", "cloud_version", "latest_version", "new_version", "apk_version_name"],
        "update_url": ["update_url", "download_url", "apk_url", "app_url", "upgrade_url"],
        "update_log": ["update_log", "update_content", "update_desc", "update_message", "changelog"],
        "force_update": ["force_update", "update_force", "forced_update", "is_force_update", "force", "must_update", "enabled_503"],
    }
    for canonical, names in alias.items():
        if lk == canonical or lk in [x.lower() for x in names]:
            out[canonical] = raw_val
            return


def _v77_table_columns(table):
    rows = _v77_all("SHOW COLUMNS FROM `%s`" % table)
    cols = []
    for r in rows or []:
        if isinstance(r, dict):
            cols.append(str(r.get("Field") or r.get("field") or ""))
        elif isinstance(r, (list, tuple)) and r:
            cols.append(str(r[0]))
    return [c for c in cols if c]


def _v77_existing_heuristic():
    # 只作为兼容旧补丁/旧表，不作为主要写入源。
    out = {}
    try:
        table_rows = _v77_all("SHOW TABLES") or []
        tables = []
        for tr in table_rows:
            if isinstance(tr, dict):
                vals = list(tr.values())
                if vals:
                    tables.append(str(vals[0]))
            elif isinstance(tr, (list, tuple)) and tr:
                tables.append(str(tr[0]))
        preferred = []
        for t in tables:
            lt = t.lower()
            if any(x in lt for x in ("setting", "config", "option", "system", "app")):
                preferred.append(t)
        if "iapt_app_settings" in tables and "iapt_app_settings" not in preferred:
            preferred.insert(0, "iapt_app_settings")
        for t in preferred[:40]:
            cols = _v77_table_columns(t)
            if not cols:
                continue
            low = {c.lower(): c for c in cols}
            try:
                rows = _v77_all("SELECT * FROM `%s` LIMIT 200" % t) or []
            except Exception:
                continue
            key_col = None
            val_col = None
            for kc in ("key", "name", "setting_key", "config_key", "option_name", "k"):
                if kc in low:
                    key_col = low[kc]
                    break
            for vc in ("value", "setting_value", "config_value", "option_value", "v", "val"):
                if vc in low:
                    val_col = low[vc]
                    break
            if key_col and val_col:
                for r in rows:
                    _v77_put_alias(out, _v77_row_get(r, key_col), _v77_row_get(r, val_col))
                continue
            for r in rows:
                for c in cols:
                    v = _v77_row_get(r, c)
                    _v77_put_alias(out, c, v)
                    sv = _v77_str(v).strip()
                    lc = c.lower()
                    if sv.startswith("http://") or sv.startswith("https://"):
                        if "update_url" not in out:
                            out["update_url"] = sv
                    elif ("log" in lc or "desc" in lc or "content" in lc) and len(sv) > 0 and "update" in lc:
                        out.setdefault("update_log", sv)
    except Exception as e:
        out["_heuristic_error"] = str(e)
    return out


def _v77_load_settings():
    out = _v77_existing_heuristic()
    out.update(_v77_kv_load())
    return out


def _v77_admin_settings():
    s = _v77_load_settings()
    ann_text = _v77_str(s.get("announcement_text") or "").strip()
    ann_title = _v77_str(s.get("announcement_title") or "公告").strip() or "公告"
    ann_enabled = _v77_bool(s.get("announcement_enabled"), False)
    return {
        "register_enabled": _v77_bool(s.get("register_enabled"), True),
        "app_enabled": _v77_bool(s.get("app_enabled"), True),
        "app_closed_message": _v77_str(s.get("app_closed_message") or s.get("close_message") or ""),
        "announcement": {
            "enabled": ann_enabled,
            "title": ann_title,
            "text": ann_text,
        },
        "update": {
            "version_code": _v77_int(s.get("update_version_code"), 0),
            "version_name": _v77_str(s.get("update_version_name") or "0"),
            "url": _v77_str(s.get("update_url") or ""),
            "log": _v77_str(s.get("update_log") or ""),
            "force": _v77_bool(s.get("force_update"), False),
        },
    }


def _v77_public_config():
    cfg = _v77_admin_settings()
    ann = cfg.get("announcement") or {}
    up = cfg.get("update") or {}
    ann_text = _v77_str(ann.get("text") or "").strip()
    ann_enabled = _v77_bool(ann.get("enabled"), False) and bool(ann_text)
    version_code = _v77_int(up.get("version_code"), 0)
    version_name = _v77_str(up.get("version_name") or "0").strip() or "0"
    update_url = _v77_str(up.get("url") or "").strip()
    update_log = _v77_str(up.get("log") or "").strip()
    force_update = _v77_bool(up.get("force"), False)
    return {
        "ok": True,
        "server_time": _v77_datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "app_enabled": _v77_bool(cfg.get("app_enabled"), True),
        "register_enabled": _v77_bool(cfg.get("register_enabled"), True),
        "app_closed_message": _v77_str(cfg.get("app_closed_message") or ""),
        "close_message": _v77_str(cfg.get("app_closed_message") or ""),
        "announcement_enabled": ann_enabled,
        "announcement_title": _v77_str(ann.get("title") or "公告"),
        "announcement_text": ann_text,
        "announcement_content": ann_text,
        "announcement": ann_text,
        "notice_enabled": ann_enabled,
        "notice": ann_text,
        "notice_text": ann_text,
        "update_version_code": version_code,
        "update_version_name": version_name,
        "version_code": version_code,
        "version_name": version_name,
        "version": version_name,
        "update_url": update_url,
        "download_url": update_url,
        "update_log": update_log,
        "force_update": force_update,
        "update": {
            "version_code": version_code,
            "version_name": version_name,
            "version": version_name,
            "url": update_url,
            "download_url": update_url,
            "log": update_log,
            "force": force_update,
        },
    }


def _v77_has_any_settings_perm(user):
    return any(_v77_has_permission(user, p) for p in _v77_PERMS)


def _v77_require_settings_perm(user):
    if not _v77_has_any_settings_perm(user):
        raise _v77_HTTPException(403, "无系统设置权限：501/502/503/504")


def _v77_require_field_perm(user, pid):
    if not _v77_has_permission(user, pid):
        raise _v77_HTTPException(403, "无后台权限：%s" % pid)


async def _v77_read_body(request):
    token = ""
    try:
        auth = request.headers.get("authorization") or ""
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()
    except Exception:
        token = ""
    try:
        data = await _v77_read_secure_json(request, token, verify=False)
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    try:
        data = await request.json()
        if isinstance(data, dict):
            return data
    except Exception:
        pass
    return {}


def _v77_remove_routes():
    try:
        targets = {"/app/config", "/api/app/config", "/config", "/api/config", "/admin/app/settings", "/api/admin/app/settings"}
        removed = []
        kept = []
        for r in app.router.routes:
            if getattr(r, "path", None) in targets:
                removed.append((getattr(r, "path", None), list(getattr(r, "methods", []) or []), getattr(getattr(r, "endpoint", None), "__name__", "")))
            else:
                kept.append(r)
        app.router.routes[:] = kept
        print("[v77] removed routes", removed)
    except Exception as e:
        print("[v77] remove routes failed", e)


_v77_ensure_table()
_v77_remove_routes()


@app.get("/admin/app/settings")
def _v77_admin_get_settings(user=_v77_Depends(_v77_current_user)):
    _v77_require_settings_perm(user)
    return {"ok": True, "settings": _v77_admin_settings()}


@app.get("/api/admin/app/settings")
def _v77_api_admin_get_settings(user=_v77_Depends(_v77_current_user)):
    _v77_require_settings_perm(user)
    return {"ok": True, "settings": _v77_admin_settings()}


@app.post("/admin/app/settings")
async def _v77_admin_save_settings(request: _v77_Request, user=_v77_Depends(_v77_current_user)):
    _v77_require_settings_perm(user)
    body = await _v77_read_body(request)
    if "register_enabled" in body:
        _v77_require_field_perm(user, _v77_PERM_REGISTER)
        _v77_set("register_enabled", _v77_bool(body.get("register_enabled"), False))
    if "app_enabled" in body or "app_closed_message" in body or "close_message" in body:
        _v77_require_field_perm(user, _v77_PERM_APP)
        if "app_enabled" in body:
            _v77_set("app_enabled", _v77_bool(body.get("app_enabled"), True))
        if "app_closed_message" in body:
            _v77_set("app_closed_message", _v77_str(body.get("app_closed_message")))
        if "close_message" in body:
            _v77_set("app_closed_message", _v77_str(body.get("close_message")))
    if "announcement_enabled" in body or "announcement_title" in body or "announcement_text" in body or "announcement_content" in body:
        _v77_require_field_perm(user, _v77_PERM_ANNOUNCEMENT)
        if "announcement_enabled" in body:
            _v77_set("announcement_enabled", _v77_bool(body.get("announcement_enabled"), False))
        if "announcement_title" in body:
            _v77_set("announcement_title", _v77_str(body.get("announcement_title")))
        if "announcement_text" in body:
            _v77_set("announcement_text", _v77_str(body.get("announcement_text")))
        if "announcement_content" in body:
            _v77_set("announcement_text", _v77_str(body.get("announcement_content")))
    if "update_version_code" in body or "update_version_name" in body or "update_url" in body or "update_log" in body or "force_update" in body:
        _v77_require_field_perm(user, _v77_PERM_UPDATE)
        if "update_version_code" in body:
            _v77_set("update_version_code", _v77_int(body.get("update_version_code"), 0))
        if "update_version_name" in body:
            _v77_set("update_version_name", _v77_str(body.get("update_version_name")))
        if "update_url" in body:
            _v77_set("update_url", _v77_str(body.get("update_url")))
        if "update_log" in body:
            _v77_set("update_log", _v77_str(body.get("update_log")))
        if "force_update" in body:
            _v77_set("force_update", _v77_bool(body.get("force_update"), False))
    try:
        _v77_exec("INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)", (user.get("id"), "save_app_settings_v77", _v77_json.dumps(body, ensure_ascii=False)))
    except Exception:
        pass
    return {"ok": True, "settings": _v77_admin_settings(), "config": _v77_public_config()}


@app.post("/api/admin/app/settings")
async def _v77_api_admin_save_settings(request: _v77_Request, user=_v77_Depends(_v77_current_user)):
    return await _v77_admin_save_settings(request, user)


@app.get("/app/config")
def _v77_app_config():
    return _v77_public_config()


@app.get("/api/app/config")
def _v77_api_app_config():
    return _v77_public_config()


@app.get("/config")
def _v77_config():
    return _v77_public_config()


@app.get("/api/config")
def _v77_api_config():
    return _v77_public_config()


print("[v77] admin app settings routes installed")
# === IAPT_ADMIN_APP_SETTINGS_V77_END ===


# IAPT_USER_ERROR_MASK_V82_BEGIN
try:
    import json as _iapt_v82_json
    from starlette.responses import Response as _iapt_v82_Response

    _IAPT_V82_GENERIC_ERROR = "解密失败，请联系管理员"
    _IAPT_V82_HIDE_KEYS = (
        "traceback", "stderr", "stdout", "exception", "stack", "stacktrace", "raw_error",
        "error_detail", "debug", "cmd", "command", "argv", "args", "log", "log_path",
        "out_dir", "work_dir", "tmp", "temp", "path"
    )

    def _iapt_v82_sensitive(v):
        t = str(v or "")
        l = t.lower()
        return len(t) > 120 or any(x in l for x in (
            "traceback", "file \\\"", "python", "/www/", "/tmp/", "/data/", "subprocess",
            "syntaxerror", "nameerror", "permission denied", "no such file"
        ))

    def _iapt_v82_scrub(o):
        if isinstance(o, dict):
            failed = str(o.get("status") or o.get("state") or "").lower() in ("fail", "failed", "error")
            r = {}
            for k, v in o.items():
                kl = str(k).lower()
                if any(x in kl for x in _IAPT_V82_HIDE_KEYS):
                    continue
                if kl in ("error", "message", "msg", "detail", "reason") and (failed or _iapt_v82_sensitive(v)):
                    r[k] = _IAPT_V82_GENERIC_ERROR
                else:
                    r[k] = _iapt_v82_scrub(v)
            return r
        if isinstance(o, list):
            return [_iapt_v82_scrub(x) for x in o]
        return o

    @app.middleware("http")
    async def _iapt_v82_hide_task_error_for_user(request, call_next):
        response = await call_next(request)
        low = (request.url.path or "").lower()
        if "/admin" in low:
            return response
        if not any(x in low for x in ("/task", "/tasks", "/download", "/decrypt", "/result")):
            return response
        if "application/json" not in (response.headers.get("content-type", "").lower()):
            return response
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        try:
            data = _iapt_v82_json.loads(body.decode("utf-8", "ignore"))
            body = _iapt_v82_json.dumps(_iapt_v82_scrub(data), ensure_ascii=False).encode("utf-8")
        except Exception:
            pass
        headers = dict(response.headers)
        headers.pop("content-length", None)
        return _iapt_v82_Response(content=body, status_code=response.status_code, headers=headers, media_type="application/json")
except Exception as _iapt_v82_e:
    print("[IAPT_V82] error-mask disabled:", _iapt_v82_e)
# IAPT_USER_ERROR_MASK_V82_END


# __IAPT_SANDBOX_DYNAMIC_ROUTE_V107_DISABLED_BY_V129__


# IAPT_SOURCE_RESTORE_ROUTE_V1_BEGIN
def _iapt_source_restore_safe_name(name: str) -> str:
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', name or '').strip('._')
    return s or 'src'


def _iapt_source_restore_zip_has_source(path: Path) -> bool:
    try:
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.endswith('/'):
                    continue
                low = n.lower()
                if low.endswith(('.iyu', '.myu', '.ijava', '.java', '.xml', '.txt')):
                    return True
    except Exception:
        return False
    return False


@app.post('/api/source/restore')
@app.post('/source/restore')
@app.post('/api/source/deobfuscate')
@app.post('/source/deobfuscate')
def iapt_source_restore(
    request: Request,
    src: UploadFile = File(...),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    feature_id = FEATURE_SOURCE_RESTORE
    if not active_subscription(int(user['id']), feature_id):
        raise HTTPException(403, '当前订阅不支持混淆还原')
    if request.headers.get('x-body-hash') != sha256_hex(payload or ''):
        print('[IAPT source-restore] ignored multipart body hash mismatch')

    task_no = secrets.token_hex(16)
    upload_dir = APP_STORAGE / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    input_zip = upload_dir / f'{task_no}.apk'

    try:
        with input_zip.open('wb') as f:
            shutil.copyfileobj(src.file, f)
        size = int(input_zip.stat().st_size)
    except Exception as e:
        raise HTTPException(500, '保存源码 ZIP 失败：' + str(e))

    if size <= 0:
        raise HTTPException(400, '源码 ZIP 为空')
    if size > 128 * 1024 * 1024:
        raise HTTPException(413, '源码 ZIP 超过 128MB')
    if not zipfile.is_zipfile(input_zip):
        raise HTTPException(400, '请上传 src 打包后的 ZIP 文件')
    if not _iapt_source_restore_zip_has_source(input_zip):
        raise HTTPException(400, 'ZIP 中没有找到 iApp 源码文件')

    options = {'feature_id': feature_id, 'source_restore': True, 'decrypt_version': 'restore'}
    if payload and iv:
        try:
            from .secure import decrypt_json_payload
            dec = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt',''))
            if isinstance(dec, dict):
                options.update(dec)
        except Exception as e:
            print('[IAPT source-restore] payload decode skipped:', e)
    options['feature_id'] = feature_id
    options['source_restore'] = True
    options['decrypt_version'] = 'restore'

    cost = cost_for_bytes(size)
    q = available_quota(int(user['id']), feature_id)
    if quota_decimal(q.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：源码 ZIP {size} bytes 需要 {cost} 额度，当前剩余 {q.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), feature_id, cost)
    except ValueError as e:
        raise HTTPException(402, str(e))

    def _sha256_file(p: Path) -> str:
        h = hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    apk_sha = _sha256_file(input_zip)
    opt_hash = hashlib.sha256(json.dumps(options, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    name = _iapt_source_restore_safe_name(Path(src.filename or 'src.zip').stem)
    apk_name = name if name.endswith('.zip') else name + '.zip'
    quota_after_resource = available_quota(int(user['id']), feature_id).get('total', 0)
    resource_note = f'混淆还原上传扣除：ZIP {size} bytes，扣除 {cost} 额度'
    quota_note = f'混淆还原任务已创建；上传已扣除 {cost} 额度；完成后可在任务列表下载还原源码 ZIP'
    try:
        tid = db.exec('''
            INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
            VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
        ''', (task_no, user['id'], apk_name, feature_id, 'restore', json.dumps(options, ensure_ascii=False), apk_sha, opt_hash, cost, resource_note, quota_public_value(cost), quota_after_resource, quota_note))
    except Exception as e:
        try:
            input_zip.unlink(missing_ok=True)
        except Exception:
            pass
        raise HTTPException(500, '创建混淆还原任务失败：' + str(e))
    try:
        enqueue_task(int(tid))
    except Exception as e:
        print('[WARN] enqueue source restore failed:', e)
    return {'ok': True, 'task_id': tid, 'task_no': task_no, 'status': 'queued', 'feature_id': feature_id, 'decrypt_version': 'restore', 'task_version': 'restore', 'resource_quota_cost': cost, 'quota_limit': quota_after_resource}


@app.post('/api/source/numeric-restore')
@app.post('/source/numeric-restore')
@app.post('/api/tasks/numeric-restore')
@app.post('/tasks/numeric-restore')
def iapt_numeric_source_restore(
    request: Request,
    src: UploadFile = File(...),
    dex: UploadFile = File(default=None),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    feature_id = FEATURE_NUMERIC_FN_RESTORE
    if not active_subscription(int(user['id']), feature_id):
        raise HTTPException(403, '当前订阅不支持动态修复')
    if request.headers.get('x-body-hash') != sha256_hex(payload or ''):
        print('[IAPT numeric-restore] ignored multipart body hash mismatch')

    task_no = secrets.token_hex(16)
    upload_dir = APP_STORAGE / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    src_zip = upload_dir / f'{task_no}.apk'
    dex_path = upload_dir / f'{task_no}.dex'

    try:
        with src_zip.open('wb') as f:
            shutil.copyfileobj(src.file, f)
        with dex_path.open('wb') as f:
            shutil.copyfileobj(dex.file, f)
        src_size = int(src_zip.stat().st_size)
        dex_size = int(dex_path.stat().st_size)
    except Exception as e:
        raise HTTPException(500, '保存动态修复输入失败：' + str(e))

    if src_size <= 0:
        raise HTTPException(400, '源码 ZIP 为空')
    if dex_size <= 0:
        raise HTTPException(400, 'DEX 文件为空')
    if src_size > 128 * 1024 * 1024 or dex_size > 128 * 1024 * 1024:
        raise HTTPException(413, '上传文件超过 128MB')
    if not zipfile.is_zipfile(src_zip):
        raise HTTPException(400, '请上传 src 打包后的 ZIP 文件')
    if not _iapt_source_restore_zip_has_source(src_zip):
        raise HTTPException(400, 'ZIP 中没有找到 iApp 源码文件')
    try:
        if not dex_path.read_bytes()[:8].startswith(b'dex\n'):
            raise HTTPException(400, '请上传 classes.dex 文件')
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(400, '读取 DEX 文件失败')

    options = {'feature_id': feature_id, 'numeric_source_restore': True, 'decrypt_version': 'fn_restore', 'threads': 4}
    if payload and iv:
        try:
            from .secure import decrypt_json_payload
            dec = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt',''))
            if isinstance(dec, dict):
                options.update(dec)
        except Exception as e:
            print('[IAPT numeric-restore] payload decode skipped:', e)
    options['feature_id'] = feature_id
    options['numeric_source_restore'] = True
    options['decrypt_version'] = 'fn_restore'

    cost = cost_for_bytes(src_size + dex_size)
    q = available_quota(int(user['id']), feature_id)
    if quota_decimal(q.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：上传共 {src_size + dex_size} bytes 需要 {cost} 额度，当前剩余 {q.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), feature_id, cost)
    except ValueError as e:
        raise HTTPException(402, str(e))

    def _sha256_file2(p: Path) -> str:
        h = hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    src_sha = _sha256_file2(src_zip)
    dex_sha = _sha256_file2(dex_path)
    opt_hash = hashlib.sha256(json.dumps(options, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    name = _iapt_source_restore_safe_name(Path(src.filename or 'src.zip').stem)
    apk_name = name if name.endswith('.zip') else name + '_numeric.zip'
    quota_after_resource = available_quota(int(user['id']), feature_id).get('total', 0)
    resource_note = f'动态修复上传扣除：src {src_size} bytes + dex {dex_size} bytes，扣除 {cost} 额度'
    quota_note = f'动态修复任务已创建；上传已扣除 {cost} 额度；完成后可在任务列表下载还原源码 ZIP'
    try:
        tid = db.exec('''
            INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
            VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
        ''', (task_no, user['id'], apk_name, feature_id, 'fn_restore', json.dumps(options, ensure_ascii=False), src_sha, opt_hash, cost, resource_note, quota_public_value(cost), quota_after_resource, quota_note))
    except Exception as e:
        for p in (src_zip, dex_path):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        raise HTTPException(500, '创建动态修复任务失败：' + str(e))
    try:
        enqueue_task(int(tid))
    except Exception as e:
        print('[WARN] enqueue numeric source restore failed:', e)
    return {'ok': True, 'task_id': tid, 'task_no': task_no, 'status': 'queued', 'feature_id': feature_id, 'decrypt_version': 'fn_restore', 'task_version': 'fn_restore', 'resource_quota_cost': cost, 'quota_limit': quota_after_resource}
# IAPT_SOURCE_RESTORE_ROUTE_V1_END

# IAPT_STATIC_DEX_SOURCE_RESTORE_ROUTE_V1_BEGIN
@app.post('/api/source/dex-restore')
@app.post('/source/dex-restore')
@app.post('/api/source/static-dex-restore')
@app.post('/source/static-dex-restore')
def iapt_static_dex_source_restore(
    request: Request,
    src: UploadFile = File(...),
    dex: UploadFile = File(default=None),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    feature_id = FEATURE_SOURCE_RESTORE
    if not active_subscription(int(user['id']), feature_id):
        raise HTTPException(403, '当前订阅不支持 DEX 还原')
    if request.headers.get('x-body-hash') != sha256_hex(payload or ''):
        print('[IAPT static-dex-restore] ignored multipart body hash mismatch')

    task_no = secrets.token_hex(16)
    upload_dir = APP_STORAGE / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    src_zip = upload_dir / f'{task_no}.apk'
    dex_path = upload_dir / f'{task_no}.dex'

    try:
        with src_zip.open('wb') as f:
            shutil.copyfileobj(src.file, f)
        dex_size = 0
        if dex is not None and getattr(dex, 'filename', None):
            with dex_path.open('wb') as f:
                shutil.copyfileobj(dex.file, f)
            dex_size = int(dex_path.stat().st_size)
        src_size = int(src_zip.stat().st_size)
    except Exception as e:
        raise HTTPException(500, '保存 DEX 还原输入失败：' + str(e))

    if src_size <= 0:
        raise HTTPException(400, '源码 ZIP 为空')
    if src_size > 256 * 1024 * 1024 or dex_size > 256 * 1024 * 1024:
        raise HTTPException(413, '上传文件超过 256MB')
    if not zipfile.is_zipfile(src_zip):
        raise HTTPException(400, '请上传 src 打包后的 ZIP 文件')
    if not _iapt_source_restore_zip_has_source(src_zip):
        raise HTTPException(400, 'ZIP 中没有找到 iApp 源码文件')
    # dex 已改为可选。源码 ZIP 内可以携带 apk/lib/*、*.dex、*.jar、*.apk，
    # 服务端会在源码树和可选附件里自动扫描可用 DEX。
    if dex_size > 0:
        try:
            head = dex_path.read_bytes()[:8]
            if not (head.startswith(b'dex\n') or zipfile.is_zipfile(dex_path)):
                raise HTTPException(400, 'DEX 附加文件必须是 dex/apk/zip/jar')
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, '读取 DEX 附加文件失败')

    options = {'feature_id': feature_id, 'source_restore': True, 'dex_static_restore': True, 'decrypt_version': 'dex_restore'}
    if payload and iv:
        try:
            from .secure import decrypt_json_payload
            dec = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt',''))
            if isinstance(dec, dict):
                options.update(dec)
        except Exception as e:
            print('[IAPT static-dex-restore] payload decode skipped:', e)
    options['feature_id'] = feature_id
    options['source_restore'] = True
    options['dex_static_restore'] = True
    options['decrypt_version'] = 'dex_restore'

    cost = cost_for_bytes(src_size + dex_size)
    q = available_quota(int(user['id']), feature_id)
    if quota_decimal(q.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：上传共 {src_size + dex_size} bytes 需要 {cost} 额度，当前剩余 {q.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), feature_id, cost)
    except ValueError as e:
        raise HTTPException(402, str(e))

    def _sha256_file_static_dex(p: Path) -> str:
        h = hashlib.sha256()
        with p.open('rb') as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b''):
                h.update(chunk)
        return h.hexdigest()

    src_sha = _sha256_file_static_dex(src_zip)
    dex_sha = _sha256_file_static_dex(dex_path) if dex_path.exists() and dex_path.stat().st_size > 0 else 'no-extra-dex'
    opt_hash = hashlib.sha256(json.dumps(options, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    name = _iapt_source_restore_safe_name(Path(src.filename or 'src.zip').stem)
    apk_name = name if name.endswith('.zip') else name + '_dex_restore.zip'
    quota_after_resource = available_quota(int(user['id']), feature_id).get('total', 0)
    resource_note = f'DEX还原上传扣除：src {src_size} bytes + 可选dex/lib附件 {dex_size} bytes，扣除 {cost} 额度'
    quota_note = f'DEX还原任务已创建；会扫描源码ZIP内 apk/lib/* 和可选dex/apk/zip附件；多余文件会随结果包输出'
    try:
        tid = db.exec('''
            INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
            VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
        ''', (task_no, user['id'], apk_name, feature_id, 'dex_restore', json.dumps(options, ensure_ascii=False), src_sha, opt_hash, cost, resource_note, quota_public_value(cost), quota_after_resource, quota_note))
    except Exception as e:
        for p in (src_zip, dex_path):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        raise HTTPException(500, '创建 DEX 还原任务失败：' + str(e))
    try:
        enqueue_task(int(tid))
    except Exception as e:
        print('[WARN] enqueue static dex source restore failed:', e)
    return {'ok': True, 'task_id': tid, 'task_no': task_no, 'status': 'queued', 'feature_id': feature_id, 'decrypt_version': 'dex_restore', 'task_version': 'dex_restore', 'resource_quota_cost': cost, 'quota_limit': quota_after_resource}
# IAPT_STATIC_DEX_SOURCE_RESTORE_ROUTE_V1_END

# __IAPT_V8_CANCEL_ENDPOINT_BEGIN__
@app.post('/api/tasks/{task_id}/cancel')
def task_cancel(task_id: int, request: Request, user=Depends(current_user)):
    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (int(task_id), int(user['id'])))
    if not task:
        raise HTTPException(404, '任务不存在')
    try:
        from .decrypt_runner import cancel_task_process
        return cancel_task_process(int(task_id), '用户已停止解密')
    except RuntimeError as e:
        raise HTTPException(409, str(e))
    except Exception as e:
        raise HTTPException(500, '停止任务失败：' + str(e))
# __IAPT_V8_CANCEL_ENDPOINT_END__

# __IAPT_V10_ROUTE_OVERRIDE_BEGIN__
# v10 installs the critical routes directly in main.py at the very end of app
# construction.  Older builds registered a POST /find handler that created a
# brand-new decrypt task, while the optional admin extension could fail to mount
# and leave the cancel buttons returning 404.  Remove every older POST handler
# for these exact paths, then install one authoritative implementation.

def _iapt_v10_remove_post_routes(paths) -> None:
    wanted = set(paths)
    kept = []
    for route in list(app.router.routes):
        path = str(getattr(route, 'path', '') or '')
        methods = set(getattr(route, 'methods', set()) or set())
        if path in wanted and 'POST' in methods:
            continue
        kept.append(route)
    app.router.routes = kept


_IAPT_V10_FIND_PATHS = {
    '/api/tasks/{task_id}/find', '/api/tasks/{task_id}/find/',
    '/tasks/{task_id}/find', '/tasks/{task_id}/find/',
}
_IAPT_V10_ADMIN_CANCEL_PATHS = {
    '/api/admin/tasks/cancel-all', '/api/admin/tasks/cancel-all/',
    '/admin/tasks/cancel-all', '/admin/tasks/cancel-all/',
    '/api/admin/tasks/{task_id}/cancel', '/api/admin/tasks/{task_id}/cancel/',
    '/admin/tasks/{task_id}/cancel', '/admin/tasks/{task_id}/cancel/',
}
_iapt_v10_remove_post_routes(_IAPT_V10_FIND_PATHS | _IAPT_V10_ADMIN_CANCEL_PATHS)


async def _iapt_v10_find_impl(task_id: int, request: Request, user=Depends(current_user)):
    token = request.headers.get('authorization', '').split(' ', 1)[1] if request.headers.get('authorization') else ''
    try:
        raw = await read_secure_json(request, token, verify=False)
        body = TaskFindRunBody(**(raw or {}))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, '查找参数错误：' + str(exc))

    targets = _split_find_targets(body.find)
    if not targets:
        raise HTTPException(400, '请输入查找文件名')
    if len(targets) > 50:
        raise HTTPException(400, '一次最多查找 50 个文件名')

    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (int(task_id), int(user['id'])))
    if not task:
        raise HTTPException(404, '任务不存在')
    if str(task.get('status') or '').lower() != 'done':
        raise HTTPException(409, '只能在已完成任务中复用解密外壳查找')

    before_max_id = int((db.one('SELECT COALESCE(MAX(id),0) AS m FROM tasks') or {}).get('m') or 0)
    try:
        result = find_from_task_shell(
            int(task_id), targets,
            recursive=bool(body.find_recursive),
            max_output_files=body.max_output_files,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except Exception as exc:
        raise HTTPException(500, '复用已解密外壳查找失败：' + str(exc))

    # Invariant check: this endpoint must never create a task.  The check is
    # intentionally read-only; it catches accidental regressions in deployment.
    after_max_id = int((db.one('SELECT COALESCE(MAX(id),0) AS m FROM tasks') or {}).get('m') or 0)
    if after_max_id != before_max_id:
        raise HTTPException(500, '安全检查失败：Find 不允许创建新任务')
    result.update({
        'message': '已直接使用原任务的 container_plain.bin 查找文件',
        'implementation': 'reuse-shell-v10',
        'created_task': False,
        'reran_outer_decrypt': False,
        'reran_enumeration': False,
    })
    return result


async def _iapt_v10_admin_cancel_one_impl(task_id: int, user=Depends(current_user)):
    require_permission(user, 603)
    task = db.one('SELECT id,task_no,status,user_id,apk_name FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise HTTPException(404, '任务不存在')
    try:
        from .decrypt_runner import cancel_task_process
        result = cancel_task_process(int(task_id), f"管理员已停止任务（管理员ID {int(user.get('id') or 0)}）")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except Exception as exc:
        raise HTTPException(500, '停止任务失败：' + str(exc))
    try:
        db.exec(
            'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
            (int(user.get('id') or 0), 'cancel_task', json.dumps({'task_id': int(task_id), 'result': result}, ensure_ascii=False, default=str)),
        )
    except Exception:
        pass
    result['task_no'] = str(task.get('task_no') or '')
    result['apk_name'] = str(task.get('apk_name') or '')
    result['implementation'] = 'direct-main-v10'
    return result


def _iapt_v10_admin_cancel_all_impl(user=Depends(current_user)):
    require_permission(user, 603)
    rows = db.all(
        "SELECT id,task_no,status,user_id,apk_name FROM tasks "
        "WHERE LOWER(COALESCE(status,'')) IN ('queued','running') ORDER BY id ASC"
    ) or []
    from .decrypt_runner import cancel_task_process
    stopped, finished, failed = [], [], []
    for row in rows:
        task_id = int((row or {}).get('id') or 0)
        if task_id <= 0:
            continue
        try:
            result = cancel_task_process(task_id, f"管理员已停止全部任务（管理员ID {int(user.get('id') or 0)}）")
            item = dict(result or {})
            item['task_no'] = str((row or {}).get('task_no') or '')
            item['apk_name'] = str((row or {}).get('apk_name') or '')
            if str(item.get('status') or '') == 'cancelled':
                stopped.append(item)
            else:
                finished.append(item)
        except Exception as exc:
            failed.append({'task_id': task_id, 'error': str(exc)})
    summary = {
        'matched': len(rows), 'stopped': len(stopped),
        'already_finished': len(finished), 'failed': len(failed),
    }
    try:
        db.exec(
            'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
            (int(user.get('id') or 0), 'cancel_all_tasks', json.dumps({'summary': summary, 'failed': failed}, ensure_ascii=False, default=str)),
        )
    except Exception:
        pass
    return {
        'ok': not failed,
        'summary': summary,
        'items': stopped,
        'already_finished_items': finished,
        'failed_items': failed,
        'message': f"已停止 {len(stopped)} 个任务" + (f"，{len(failed)} 个失败" if failed else ''),
        'implementation': 'direct-main-v10',
    }


# Register static cancel-all before the dynamic integer route.
for _path in (
    '/api/admin/tasks/cancel-all', '/api/admin/tasks/cancel-all/',
    '/admin/tasks/cancel-all', '/admin/tasks/cancel-all/',
):
    app.add_api_route(_path, _iapt_v10_admin_cancel_all_impl, methods=['POST'], include_in_schema=(_path == '/api/admin/tasks/cancel-all'))
for _path in (
    '/api/admin/tasks/{task_id}/cancel', '/api/admin/tasks/{task_id}/cancel/',
    '/admin/tasks/{task_id}/cancel', '/admin/tasks/{task_id}/cancel/',
):
    app.add_api_route(_path, _iapt_v10_admin_cancel_one_impl, methods=['POST'], include_in_schema=(_path == '/api/admin/tasks/{task_id}/cancel'))
for _path in (
    '/api/tasks/{task_id}/find', '/api/tasks/{task_id}/find/',
    '/tasks/{task_id}/find', '/tasks/{task_id}/find/',
):
    app.add_api_route(_path, _iapt_v10_find_impl, methods=['POST'], include_in_schema=(_path == '/api/tasks/{task_id}/find'))


@app.on_event('startup')
def _iapt_v10_cancel_legacy_find_jobs_on_startup():
    # Old POST /find created a full decrypt task named "... --find".  Such jobs
    # are obsolete and unsafe after this upgrade, so prevent them from resuming.
    try:
        rows = db.all(
            "SELECT id FROM tasks WHERE LOWER(COALESCE(status,'')) IN ('queued','running') "
            "AND LOWER(COALESCE(apk_name,'')) LIKE %s",
            ('% --find%',),
        ) or []
        if rows:
            from .decrypt_runner import cancel_task_process
            for row in rows:
                try:
                    cancel_task_process(int(row.get('id') or 0), '旧版 Find 任务已自动停止；请在原任务中重新查找')
                except Exception as exc:
                    print('[IAPT v10] cancel legacy find task failed:', exc)
    except Exception as exc:
        print('[IAPT v10] legacy find cleanup failed:', exc)


@app.get('/api/system/iapt-route-version')
def _iapt_v10_route_version():
    return {
        'version': 'v10',
        'find': 'reuse-shell-only',
        'admin_cancel': 'direct-main',
        'find_creates_task': False,
    }
# __IAPT_V10_ROUTE_OVERRIDE_END__

# __IAPT_V11_UNIQUE_CONTROL_ROUTES_BEGIN__
# v11 deliberately uses route names that never existed in older builds.  This
# avoids FastAPI first-match collisions with legacy POST /tasks/{id}/find and
# makes a stale public reverse proxy immediately visible through the version
# endpoint instead of silently creating another decrypt task.

async def _iapt_v11_shell_find_impl(task_id: int, request: Request, user=Depends(current_user)):
    token = request.headers.get('authorization', '').split(' ', 1)[1] if request.headers.get('authorization') else ''
    try:
        raw = await read_secure_json(request, token, verify=False)
        body = TaskFindRunBody(**(raw or {}))
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(400, '查找参数错误：' + str(exc))

    targets = _split_find_targets(body.find)
    if not targets:
        raise HTTPException(400, '请输入查找文件名')
    if len(targets) > 50:
        raise HTTPException(400, '一次最多查找 50 个文件名')

    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (int(task_id), int(user['id'])))
    if not task:
        raise HTTPException(404, '任务不存在')
    if str(task.get('status') or '').lower() != 'done':
        raise HTTPException(409, '只能在已完成任务中使用已解密外壳查找')

    before_max_id = int((db.one('SELECT COALESCE(MAX(id),0) AS m FROM tasks') or {}).get('m') or 0)
    try:
        # Import at call time so this endpoint always uses the final v11
        # implementation, even if main.py imported an older symbol near the top.
        from .decrypt_runner import find_from_task_shell as _shell_find
        result = _shell_find(
            int(task_id), targets,
            recursive=bool(body.find_recursive),
            max_output_files=body.max_output_files,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except Exception as exc:
        raise HTTPException(500, '从已解密外壳查找失败：' + str(exc))

    after_max_id = int((db.one('SELECT COALESCE(MAX(id),0) AS m FROM tasks') or {}).get('m') or 0)
    if after_max_id != before_max_id:
        raise HTTPException(500, '安全检查失败：Shell Find 不允许创建新任务')
    result.update({
        'message': '已直接从原任务 container_plain.bin 查找；没有创建任务，也没有重新枚举',
        'implementation': 'shell-find-v11',
        'created_task': False,
        'reran_outer_decrypt': False,
        'reran_enumeration': False,
    })
    return result


async def _iapt_v11_user_stop_impl(task_id: int, user=Depends(current_user)):
    task = db.one('SELECT id,status FROM tasks WHERE id=%s AND user_id=%s', (int(task_id), int(user['id'])))
    if not task:
        raise HTTPException(404, '任务不存在')
    try:
        from .decrypt_runner import cancel_task_process
        result = cancel_task_process(int(task_id), '用户已停止解密')
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except Exception as exc:
        raise HTTPException(500, '停止任务失败：' + str(exc))
    result['implementation'] = 'task-control-v11'
    return result


def _iapt_v11_admin_stop_all_impl(user=Depends(current_user)):
    require_permission(user, 603)
    rows = db.all(
        "SELECT id,task_no,status,user_id,apk_name FROM tasks "
        "WHERE LOWER(COALESCE(status,'')) IN ('queued','running') ORDER BY id ASC"
    ) or []
    from .decrypt_runner import cancel_task_process
    stopped, finished, failed = [], [], []
    for row in rows:
        task_id = int((row or {}).get('id') or 0)
        if task_id <= 0:
            continue
        try:
            item = dict(cancel_task_process(
                task_id,
                f"管理员已停止全部任务（管理员ID {int(user.get('id') or 0)}）",
            ) or {})
            item['task_no'] = str((row or {}).get('task_no') or '')
            item['apk_name'] = str((row or {}).get('apk_name') or '')
            if str(item.get('status') or '') == 'cancelled':
                stopped.append(item)
            else:
                finished.append(item)
        except Exception as exc:
            failed.append({'task_id': task_id, 'error': str(exc)})
    summary = {
        'matched': len(rows),
        'stopped': len(stopped),
        'already_finished': len(finished),
        'failed': len(failed),
    }
    try:
        db.exec(
            'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
            (int(user.get('id') or 0), 'v11_stop_all_tasks', json.dumps({'summary': summary, 'failed': failed}, ensure_ascii=False, default=str)),
        )
    except Exception:
        pass
    return {
        'ok': not failed,
        'summary': summary,
        'items': stopped,
        'already_finished_items': finished,
        'failed_items': failed,
        'message': f"已停止 {len(stopped)} 个任务" + (f"，{len(failed)} 个失败" if failed else ''),
        'implementation': 'task-control-v11',
    }


async def _iapt_v11_admin_stop_one_impl(task_id: int, user=Depends(current_user)):
    require_permission(user, 603)
    task = db.one('SELECT id,task_no,status,user_id,apk_name FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise HTTPException(404, '任务不存在')
    try:
        from .decrypt_runner import cancel_task_process
        result = cancel_task_process(int(task_id), f"管理员已停止任务（管理员ID {int(user.get('id') or 0)}）")
    except RuntimeError as exc:
        raise HTTPException(409, str(exc))
    except Exception as exc:
        raise HTTPException(500, '停止任务失败：' + str(exc))
    try:
        db.exec(
            'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
            (int(user.get('id') or 0), 'v11_stop_task', json.dumps({'task_id': int(task_id), 'result': result}, ensure_ascii=False, default=str)),
        )
    except Exception:
        pass
    result['task_no'] = str(task.get('task_no') or '')
    result['apk_name'] = str(task.get('apk_name') or '')
    result['implementation'] = 'task-control-v11'
    return result


# Register static routes before dynamic routes.
for _path in (
    '/api/admin/task-control/stop-all', '/api/admin/task-control/stop-all/',
    '/admin/task-control/stop-all', '/admin/task-control/stop-all/',
):
    app.add_api_route(
        _path, _iapt_v11_admin_stop_all_impl, methods=['POST'],
        include_in_schema=(_path == '/api/admin/task-control/stop-all'),
    )
for _path in (
    '/api/admin/task-control/{task_id}/stop', '/api/admin/task-control/{task_id}/stop/',
    '/admin/task-control/{task_id}/stop', '/admin/task-control/{task_id}/stop/',
):
    app.add_api_route(
        _path, _iapt_v11_admin_stop_one_impl, methods=['POST'],
        include_in_schema=(_path == '/api/admin/task-control/{task_id}/stop'),
    )
for _path in (
    '/api/task-control/{task_id}/stop', '/api/task-control/{task_id}/stop/',
    '/task-control/{task_id}/stop', '/task-control/{task_id}/stop/',
):
    app.add_api_route(
        _path, _iapt_v11_user_stop_impl, methods=['POST'],
        include_in_schema=(_path == '/api/task-control/{task_id}/stop'),
    )
for _path in (
    '/api/tasks/{task_id}/shell-find', '/api/tasks/{task_id}/shell-find/',
    '/tasks/{task_id}/shell-find', '/tasks/{task_id}/shell-find/',
):
    app.add_api_route(
        _path, _iapt_v11_shell_find_impl, methods=['POST'],
        include_in_schema=(_path == '/api/tasks/{task_id}/shell-find'),
    )


@app.on_event('startup')
def _iapt_v11_stop_obsolete_find_tasks():
    # A legacy Find task is a full decrypt job with " --find" in apk_name.
    # Cancel any such stale queued/running rows after upgrade.
    try:
        rows = db.all(
            "SELECT id FROM tasks WHERE LOWER(COALESCE(status,'')) IN ('queued','running') "
            "AND LOWER(COALESCE(apk_name,'')) LIKE %s",
            ('% --find%',),
        ) or []
        if rows:
            from .decrypt_runner import cancel_task_process
            for row in rows:
                try:
                    cancel_task_process(int(row.get('id') or 0), 'v11 已废弃旧版 Find 完整解密任务')
                except Exception as exc:
                    print('[IAPT v11] cancel obsolete find failed:', exc)
    except Exception as exc:
        print('[IAPT v11] obsolete find cleanup failed:', exc)


@app.get('/api/system/iapt-v11')
def _iapt_v11_version():
    return {
        'ok': True,
        'version': 'v11',
        'shell_find_path': '/api/tasks/{task_id}/shell-find',
        'admin_stop_path': '/api/admin/task-control/{task_id}/stop',
        'admin_stop_all_path': '/api/admin/task-control/stop-all',
        'find_creates_task': False,
        'find_reuses_container_plain': True,
        'project_exact_direct': True,
    }
# __IAPT_V11_UNIQUE_CONTROL_ROUTES_END__

# Nginx deployments vary: some pass /api through, others strip it.  Keep the
# unprefixed public version probe as an alias so the deploy script can verify the
# actual upstream without authentication.
app.add_api_route('/system/iapt-v11', _iapt_v11_version, methods=['GET'], include_in_schema=False)

# __IAPT_V14_SHELL_STATUS_ROUTE_BEGIN__
@app.get('/api/system/iapt-v14-shell')
def iapt_v14_shell_version():
    return {
        'version': 'v14',
        'durable_shell': True,
        'find_creates_task': False,
        'find_reruns_enumeration': False,
    }
# __IAPT_V14_SHELL_STATUS_ROUTE_END__

# __IAPT_V18_CUMULATIVE_VERSION_BEGIN__
@app.get('/api/system/iapt-v18')
def _iapt_v18_version():
    return {
        'version': 'v18',
        'cumulative': True,
        'output_manifest': True,
        'internal_files_downloadable': False,
        'project_meta_persisted': True,
        'quota_breakdown': True,
        'shell_find_creates_task': False,
        'joint_enum_feature': 14,
    }

app.add_api_route('/system/iapt-v18', _iapt_v18_version, methods=['GET'], include_in_schema=False)
# __IAPT_V18_CUMULATIVE_VERSION_END__

# __IAPT_V18_1_METADATA_COUNT_FIX_BEGIN__
@app.get('/api/system/iapt-v18-1')
def _iapt_v18_1_version():
    return {
        'version': 'v18.1',
        'cumulative': True,
        'project_meta_parser': 181,
        'project_tuple_fallback': True,
        'public_file_count_authoritative': True,
        'automatic_project_charged': False,
        'internal_files_downloadable': False,
    }

app.add_api_route('/system/iapt-v18-1', _iapt_v18_1_version, methods=['GET'], include_in_schema=False)
# __IAPT_V18_1_METADATA_COUNT_FIX_END__


# __IAPT_V18_2_VERSION_BEGIN__
@app.get('/api/system/iapt-v18-2')
def _iapt_v18_2_version():
    return {
        'version': 'v18.2',
        'cumulative': True,
        'project_meta_parser': 'v7-restored',
        'project_meta_parser_version': 182,
        'find_creates_task': False,
        'download_manifest_only': True,
    }

try:
    app.add_api_route('/system/iapt-v18-2', _iapt_v18_2_version, methods=['GET'], include_in_schema=False)
except Exception:
    pass
# __IAPT_V18_2_VERSION_END__

# __IAPT_V18_3_V6_PROTECTOR_VERSION_BEGIN__
@app.get('/api/system/iapt-v18-3')
def _iapt_v18_3_version():
    return {
        'version': 'v18.3',
        'base': 'v18.2',
        'v6_protector_analysis': True,
        'v6_dispatch_static_resolution': True,
        'v6_constant_string_decryption': True,
    }

try:
    app.add_api_route('/system/iapt-v18-3', _iapt_v18_3_version, methods=['GET'], include_in_schema=False)
except Exception:
    pass
# __IAPT_V18_3_V6_PROTECTOR_VERSION_END__


# __IAPT_V18_4_V6_DEEP_INTERPRETER_VERSION_BEGIN__
@app.get('/api/system/iapt-v18-4')
def _iapt_v18_4_version():
    return {
        'version': 'v18.4',
        'base': 'v18.3',
        'v6_deep_interpreter': True,
        'v6_full_class_dump': True,
        'v6_ui_reconstruction': True,
        'v6_iyu_validation': True,
        'v6_fail_closed_source': True,
    }

try:
    app.add_api_route('/system/iapt-v18-4', _iapt_v18_4_version, methods=['GET'], include_in_schema=False)
except Exception:
    pass
# __IAPT_V18_4_V6_DEEP_INTERPRETER_VERSION_END__


# __IAPT_V18_5_V6_CONCRETE_EVENTS_VERSION_BEGIN__
@app.get('/api/system/iapt-v18-5')
def _iapt_v18_5_version():
    return {
        'version': 'v18.5',
        'base': 'v18.4',
        'v6_concrete_events': True,
        'v6_event_methods_complete': True,
        'v6_symbolic_network_expressions': True,
        'v6_ui_event_validation': True,
    }

try:
    app.add_api_route('/system/iapt-v18-5', _iapt_v18_5_version, methods=['GET'], include_in_schema=False)
except Exception:
    pass
# __IAPT_V18_5_V6_CONCRETE_EVENTS_VERSION_END__

# __IAPT_V18_6_4_STARTUP_RECONCILE_BEGIN__
# On API restart, local queue subprocesses are gone.  Reconcile orphaned V6
# rows so the client no longer shows them as running forever.
try:
    @app.on_event('startup')
    def _iapt_v1864_startup_reconcile_v6():
        try:
            from . import decrypt_runner as _iapt_v1864_dr
            if hasattr(_iapt_v1864_dr, 'iapt_v1864_reconcile_running_v6_tasks'):
                res = _iapt_v1864_dr.iapt_v1864_reconcile_running_v6_tasks()
                print('[IAPT_V18_6_4_RECONCILE]', res)
        except Exception as _e:
            print('[IAPT_V18_6_4_RECONCILE_WARN]', repr(_e))
except Exception as _e:
    print('[IAPT_V18_6_4_STARTUP_HOOK_WARN]', repr(_e))

try:
    @app.post('/api/system/iapt-v6/reconcile')
    @app.post('/system/iapt-v6/reconcile')
    def _iapt_v1864_reconcile_endpoint(user=Depends(current_user)):
        if int((user or {}).get('permission') or 0) < 100:
            raise HTTPException(403, '需要管理员权限')
        from . import decrypt_runner as _iapt_v1864_dr
        return _iapt_v1864_dr.iapt_v1864_reconcile_running_v6_tasks()
except Exception as _e:
    print('[IAPT_V18_6_4_RECONCILE_ENDPOINT_WARN]', repr(_e))
# __IAPT_V18_6_4_STARTUP_RECONCILE_END__


# __IAPT_V18_6_7_V6_WATCHDOG_BEGIN__
# Periodically finalize V6 jobs from the atomic completion marker.  This is
# intentionally independent of the queue thread: even if a historical worker
# waits inside a library cleanup path, the public task state becomes done as
# soon as all files are safely on disk.
import threading as _iapt_v1867_threading
import time as _iapt_v1867_time
import os as _iapt_v1867_os
from pathlib import Path as _iapt_v1867_Path

_IAPT_V1867_WATCHDOG_STARTED = False
_IAPT_V1867_WATCHDOG_LOCK = _iapt_v1867_threading.Lock()


def _iapt_v1867_watchdog_loop():
    lock_file = None
    try:
        import fcntl as _iapt_v1867_fcntl
        lock_path = _iapt_v1867_Path(APP_STORAGE) / '.v6_watchdog.lock'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_file = lock_path.open('a+')
        _iapt_v1867_fcntl.flock(lock_file.fileno(), _iapt_v1867_fcntl.LOCK_EX | _iapt_v1867_fcntl.LOCK_NB)
    except Exception:
        # Another uvicorn worker already owns the watchdog lock.
        try:
            if lock_file:
                lock_file.close()
        except Exception:
            pass
        return

    while True:
        try:
            from . import decrypt_runner as _iapt_v1867_dr
            _iapt_v1867_dr.iapt_v1864_reconcile_running_v6_tasks()
        except Exception as _e:
            print('[IAPT_V18_6_7_WATCHDOG_WARN]', repr(_e))
        _iapt_v1867_time.sleep(3.0)


@app.on_event('startup')
def _iapt_v1867_start_watchdog():
    global _IAPT_V1867_WATCHDOG_STARTED
    with _IAPT_V1867_WATCHDOG_LOCK:
        if _IAPT_V1867_WATCHDOG_STARTED:
            return
        _IAPT_V1867_WATCHDOG_STARTED = True
        _iapt_v1867_threading.Thread(
            target=_iapt_v1867_watchdog_loop,
            daemon=True,
            name='iapt-v6-finalize-watchdog',
        ).start()


@app.get('/api/system/iapt-v18-6-8')
def _iapt_v1867_runtime_version():
    from .tools import iapp_dex2iyu_v6 as _iapt_v1867_tool
    return {
        'version': 'v18.6.10-v8',
        'tool_version': str(_iapt_v1867_tool.TOOL_VERSION),
        'v6_direct_tool': True,
        'periodic_finalize_watchdog': True,
        'pid': _iapt_v1867_os.getpid(),
    }
# __IAPT_V18_6_7_V6_WATCHDOG_END__

# IAPT_V35_DYNAMIC_KEY_POOL_BEGIN
@app.on_event('startup')
def _iapt_v35_dynamic_key_pool_schema():
    try:
        from .dynamic_key_pool import ensure_schema as _ensure_dynamic_key_pool
        _ensure_dynamic_key_pool()
    except Exception as exc:
        print('[IAPT_V35] dynamic key pool schema warning:', exc)


@app.get('/api/dynamic-keys/pool')
@app.get('/dynamic-keys/pool')
def iapt_v35_dynamic_key_pool_list(user=Depends(current_user)):
    can_one = bool(active_subscription(int(user['id']), FEATURE_DYNAMIC_KEY_POOL))
    can_joint = bool(active_subscription(int(user['id']), FEATURE_JOINT_KEY_ENUM))
    # 功能14/999允许把池枚举作为联合枚举的第三轴。
    can_enum = bool(active_subscription(int(user['id']), FEATURE_DYNAMIC_KEY_POOL_ENUM)) or can_joint
    if not (can_one or can_enum):
        raise HTTPException(403, '当前订阅不支持服务器动态Key池')
    from .dynamic_key_pool import list_public
    items = list_public()
    return {
        'ok': True,
        'items': items,
        'count': len(items),
        'can_select': can_one,
        'can_enum': can_enum,
        'select_feature_id': FEATURE_DYNAMIC_KEY_POOL,
        'enum_feature_id': FEATURE_DYNAMIC_KEY_POOL_ENUM,
        'joint_enum_feature_id': FEATURE_JOINT_KEY_ENUM,
        'can_joint_triple_enum': can_joint,
    }


@app.post('/api/dynamic-keys/extract')
@app.post('/dynamic-keys/extract')
async def iapt_v40_dynamic_key_extract_task(
    request: Request,
    sample: UploadFile = File(...),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    """Create a normal asynchronous task that extracts all dynamic keys from every ABI."""
    sub = active_subscription(int(user['id']), FEATURE_DYNAMIC_KEY)
    if not sub or int(sub.get('sub_id') or 0) == 0:
        raise HTTPException(403, '当前订阅不支持服务器获取动态Key（功能4）')

    options = {}
    if payload:
        if request.headers.get('x-body-hash') and request.headers.get('x-body-hash') != sha256_hex(payload):
            print('[IAPT_V40] ignored multipart body hash mismatch for dynamic key task')
        try:
            from .secure import decrypt_json_payload
            options = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt', ''))
            if not isinstance(options, dict):
                options = {}
        except Exception as exc:
            raise HTTPException(400, '动态Key任务参数解密失败：' + str(exc))

    max_upload = 512 * 1024 * 1024
    data = bytearray()
    while True:
        chunk = await sample.read(1024 * 1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_upload:
            raise HTTPException(413, '上传文件超过 512MB')
    if not data:
        raise HTTPException(400, '上传文件为空')

    original_name = str(options.get('original_filename') or sample.filename or 'libygsiyu.so')
    try:
        from starlette.concurrency import run_in_threadpool
        from .dynamic_key_pool import inspect_dynamic_key_upload
        inspect = await run_in_threadpool(inspect_dynamic_key_upload, bytes(data), original_name)
        from .dynamic_key_pool import normalize_feature_map
        feature_version = max(1, min(int(options.get('dynamic_key_feature_version') or 1), 100))
        dynamic_features = normalize_feature_map(options.get('dynamic_key_features'), version=feature_version)
    except Exception as exc:
        raise HTTPException(400, '没有取得有效的 libygsiyu.so：' + str(exc))

    # APK mode stores the original archive so the worker can parse every ABI.
    cost = cost_for_bytes(len(data))
    q = available_quota(int(user['id']), FEATURE_DYNAMIC_KEY)
    if quota_decimal(q.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：上传 {len(data)} bytes 需要 {cost} 额度，当前剩余 {q.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), FEATURE_DYNAMIC_KEY, cost)
    except ValueError as exc:
        raise HTTPException(402, str(exc))

    def _safe_result_name(raw_name: str) -> str:
        name = Path(str(raw_name or '')).name.strip()
        name = re.sub(r'[\\/:*?\"<>|]+', '_', name)
        if '.' in name and not name.startswith('.'):
            name = name.rsplit('.', 1)[0]
        name = name.strip(' ._') or 'dynamic_key'
        return name[:180] + '.zip'

    result_name = _safe_result_name(original_name)
    task_no = secrets.token_hex(16)
    upload_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        upload_path.write_bytes(bytes(data))
    except Exception as exc:
        raise HTTPException(500, '保存上传文件失败：' + str(exc))

    source_sha = hashlib.sha256(data).hexdigest()
    task_options = {
        'feature_id': FEATURE_DYNAMIC_KEY,
        'task_kind': 'dynamic_key_extract',
        'dynamic_key_extract': True,
        'decrypt_version': 'key',
        'task_version': 'key',
        'original_filename': original_name,
        'result_filename': result_name,
        'source_sha256': source_sha,
        'source_kind': str(inspect.get('source_kind') or ''),
        'library_count': int(inspect.get('library_count') or 0),
        'library_entries': list(inspect.get('library_entries') or []),
        'library_abis': list(inspect.get('library_abis') or []),
        'total_so_bytes': int(inspect.get('total_so_bytes') or 0),
        'dynamic_key_features': dynamic_features,
        'dynamic_key_feature_version': feature_version,
        'dynamic_key_sample_entry': str(options.get('dynamic_key_sample_entry') or ''),
        'dynamic_key_sample_abi': str(options.get('dynamic_key_sample_abi') or ''),
    }
    options_json = json.dumps(task_options, ensure_ascii=False, separators=(',', ':'))
    options_hash = hashlib.sha256(options_json.encode('utf-8')).hexdigest()
    quota_after_resource = available_quota(int(user['id']), FEATURE_DYNAMIC_KEY).get('total', 0)
    resource_note = (
        f'动态Key提取上传：{original_name} {len(data)} bytes，'
        f'发现 {task_options["library_count"]} 个 libygsiyu.so，已扣 {cost} 额度，失败不退'
    )
    quota_note = f'上传已扣 {cost} 额度；任务完成后下载 ZIP 按输出文件规则结算'

    try:
        tid = db.exec('''
            INSERT INTO tasks(
                task_no,user_id,apk_name,app_name,status,feature_id,decrypt_version,
                options_json,apk_sha256,options_hash,resource_quota_cost,
                resource_quota_deducted,resource_quota_note,estimated_quota_cost,
                quota_limit,quota_note
            ) VALUES(%s,%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
        ''', (
            task_no, int(user['id']), result_name, '动态Key提取', FEATURE_DYNAMIC_KEY,
            'key', options_json, source_sha, options_hash, cost, resource_note,
            cost, quota_after_resource, quota_note,
        ))
    except Exception:
        try:
            upload_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise

    enqueue_task(int(tid))
    return {
        'ok': True,
        'task_id': int(tid),
        'task_no': task_no,
        'status': 'queued',
        'feature_id': FEATURE_DYNAMIC_KEY,
        'decrypt_version': 'key',
        'task_version': 'key',
        'apk_name': result_name,
        'library_count': task_options['library_count'],
        'resource_quota_cost': cost,
        'quota_limit': quota_after_resource,
    }
# IAPT_V35_DYNAMIC_KEY_POOL_END

# IAPT_V56_STANDALONE_SERVER_SOKEY_ENDPOINT_BEGIN
@app.post('/api/server-sokey/extract')
@app.post('/server-sokey/extract')
@app.post('/api/sokey/extract')
@app.post('/sokey/extract')
async def iapt_v56_server_sokey_extract_task(
    request: Request,
    sample: UploadFile = File(...),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    # Standalone form of V3 server_sokey. It uses feature 15 but does not
    # run V3 decryption and does not touch the dynamic-key pool.
    feature_id = int(FEATURE_HIDDEN_ENUM)
    sub = active_subscription(int(user['id']), feature_id)
    if not sub:
        raise HTTPException(403, '功能不可用')

    options = {}
    if payload:
        if request.headers.get('x-body-hash') and request.headers.get('x-body-hash') != sha256_hex(payload):
            print('[IAPT_V56] ignored multipart body hash mismatch for standalone SO-key task')
        try:
            from .secure import decrypt_json_payload
            options = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt', ''))
            if not isinstance(options, dict):
                options = {}
        except Exception as exc:
            raise HTTPException(400, 'SO Key 任务参数解密失败：' + str(exc))

    max_upload = 512 * 1024 * 1024
    data = bytearray()
    while True:
        chunk = await sample.read(1024 * 1024)
        if not chunk:
            break
        data.extend(chunk)
        if len(data) > max_upload:
            raise HTTPException(413, '上传文件超过 512MB')
    if not data:
        raise HTTPException(400, '上传文件为空')

    original_name = str(options.get('original_filename') or sample.filename or 'libygsiyu.so')
    try:
        from starlette.concurrency import run_in_threadpool
        from .dynamic_key_pool import inspect_dynamic_key_upload
        inspect = await run_in_threadpool(inspect_dynamic_key_upload, bytes(data), original_name)
    except Exception as exc:
        raise HTTPException(400, '没有取得有效的 libygsiyu.so：' + str(exc))

    cost = cost_for_bytes(len(data))
    q = available_quota(int(user['id']), feature_id)
    if quota_decimal(q.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：上传 {len(data)} bytes 需要 {cost} 额度，当前剩余 {q.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), feature_id, cost)
    except ValueError as exc:
        raise HTTPException(402, str(exc))

    def _safe_result_name(raw_name: str) -> str:
        name = Path(str(raw_name or '')).name.strip()
        name = re.sub(r'[\\/:*?"<>|]+', '_', name)
        if '.' in name and not name.startswith('.'):
            name = name.rsplit('.', 1)[0]
        name = name.strip(' ._') or 'server_sokey'
        return name[:170] + '_sokey.zip'

    result_name = _safe_result_name(original_name)
    task_no = secrets.token_hex(16)
    upload_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    upload_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        upload_path.write_bytes(bytes(data))
    except Exception as exc:
        raise HTTPException(500, '保存上传文件失败：' + str(exc))

    source_sha = hashlib.sha256(data).hexdigest()
    task_options = {
        'feature_id': feature_id,
        'task_kind': 'server_sokey_extract',
        'server_sokey_extract': True,
        'server_sokey': True,
        'decrypt_version': 'sokey',
        'task_version': 'sokey',
        'original_filename': original_name,
        'result_filename': result_name,
        'source_sha256': source_sha,
        'source_kind': str(inspect.get('source_kind') or ''),
        'library_count': int(inspect.get('library_count') or 0),
        'library_entries': list(inspect.get('library_entries') or []),
        'library_abis': list(inspect.get('library_abis') or []),
        'total_so_bytes': int(inspect.get('total_so_bytes') or 0),
    }
    options_json = json.dumps(task_options, ensure_ascii=False, separators=(',', ':'))
    options_hash = hashlib.sha256(options_json.encode('utf-8')).hexdigest()
    quota_after_resource = available_quota(int(user['id']), feature_id).get('total', 0)
    resource_note = (
        f'服务器 SO Key 提取上传：{original_name} {len(data)} bytes，'
        f'发现 {task_options["library_count"]} 个 libygsiyu.so，已扣 {cost} 额度，失败不退'
    )
    quota_note = f'上传已扣 {cost} 额度；任务完成后下载 ZIP 按输出文件规则结算'

    try:
        tid = db.exec('''
            INSERT INTO tasks(
                task_no,user_id,apk_name,app_name,status,feature_id,decrypt_version,
                options_json,apk_sha256,options_hash,resource_quota_cost,
                resource_quota_deducted,resource_quota_note,estimated_quota_cost,
                quota_limit,quota_note
            ) VALUES(%s,%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
        ''', (
            task_no, int(user['id']), result_name, '服务器 SO Key 提取', feature_id,
            'sokey', options_json, source_sha, options_hash, cost, resource_note,
            cost, quota_after_resource, quota_note,
        ))
    except Exception:
        try:
            upload_path.unlink(missing_ok=True)
        except Exception:
            pass
        raise

    enqueue_task(int(tid))
    return {
        'ok': True,
        'task_id': int(tid),
        'task_no': task_no,
        'status': 'queued',
        'feature_id': feature_id,
        'decrypt_version': 'sokey',
        'task_version': 'sokey',
        'apk_name': result_name,
        'library_count': task_options['library_count'],
        'resource_quota_cost': cost,
        'quota_limit': quota_after_resource,
    }
# IAPT_V56_STANDALONE_SERVER_SOKEY_ENDPOINT_END

# IAPT_ADMIN_SUBSCRIPTION_AND_KEY_POOL_BEGIN
class AdminDynamicKeyPoolSaveBody(BaseModel):
    id: int = 0
    post_key: str
    xor_key: str
    source_type: str = 'admin'
    source_sha256: str = ''
    source_name: str = ''
    first_user_id: int | None = None
    verified: bool = True
    enabled: bool = True
    features: dict | None = None
    normalizer_version: int = 1


class AdminDynamicKeyPoolDeleteBody(BaseModel):
    id: int


def _iapt_admin_subscription_features(raw) -> list[int]:
    value = raw
    if isinstance(raw, str):
        try:
            value = json.loads(raw or '[]')
        except Exception:
            value = [x.strip() for x in str(raw or '').split(',') if x.strip()]
    if not isinstance(value, (list, tuple, set)):
        value = []
    out = []
    for item in value:
        try:
            fid = int(item)
        except Exception:
            continue
        if fid not in out:
            out.append(fid)
    return out


@app.get('/api/admin/subscriptions')
def iapt_admin_subscription_list(
    keyword: str = Query(default=''),
    limit: int = Query(default=500),
    user=Depends(current_user),
):
    require_permission(user, PERM_SUBSCRIPTION_MANAGE)
    kw = str(keyword or '').strip()
    limit = max(1, min(int(limit or 500), 1000))
    where = ''
    params = []
    if kw:
        like = '%' + kw + '%'
        where = 'WHERE (s.sub_name LIKE %s OR CAST(s.sub_id AS CHAR)=%s OR s.features_json LIKE %s)'
        params.extend([like, kw, like])
    rows = db.all(f'''
        SELECT s.sub_id,s.sub_name,s.daily_quota,s.features_json,s.created_at,
               (SELECT COUNT(*) FROM users u WHERE u.subscription_id=s.sub_id) AS current_user_count,
               (SELECT COUNT(*) FROM user_subscriptions us
                 WHERE us.sub_id=s.sub_id AND (us.expire_at IS NULL OR us.expire_at>NOW())) AS active_record_count
        FROM subscriptions s
        {where}
        ORDER BY s.sub_id ASC
        LIMIT %s
    ''', tuple(params + [limit])) or []
    items = []
    for raw in rows:
        row = dict(raw)
        features = _iapt_admin_subscription_features(row.get('features_json'))
        row['features'] = features
        row['feature_names'] = [feature_name(x) for x in features]
        row['daily_quota'] = normalize_quota_value(row.get('daily_quota'), 0)
        row['current_user_count'] = int(row.get('current_user_count') or 0)
        row['active_record_count'] = int(row.get('active_record_count') or 0)
        items.append(row)
    return {'ok': True, 'items': items, 'count': len(items), 'me': admin_permissions_public(user)}


@app.get('/api/admin/dynamic-key-pool')
def iapt_admin_dynamic_key_pool_list(
    keyword: str = Query(default=''),
    limit: int = Query(default=200),
    offset: int = Query(default=0),
    user=Depends(current_user),
):
    require_permission(user, PERM_DYNAMIC_KEY_POOL_MANAGE)
    from .dynamic_key_pool import admin_list
    items = admin_list(keyword=keyword, limit=limit, offset=offset)
    return {'ok': True, 'items': items, 'count': len(items), 'me': admin_permissions_public(user)}


@app.post('/api/admin/dynamic-key-pool/save')
async def iapt_admin_dynamic_key_pool_save(request: Request, user=Depends(current_user)):
    require_permission(user, PERM_DYNAMIC_KEY_POOL_MANAGE)
    token = request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else ''
    body = AdminDynamicKeyPoolSaveBody(**(await read_secure_json(request, token, verify=False)))
    try:
        from .dynamic_key_pool import admin_save
        item = admin_save(
            row_id=body.id,
            post_key=body.post_key,
            xor_key=body.xor_key,
            source_type=body.source_type,
            source_sha256=body.source_sha256,
            source_name=body.source_name,
            first_user_id=body.first_user_id,
            verified=body.verified,
            enabled=body.enabled,
            features=body.features,
            normalizer_version=body.normalizer_version,
        )
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    db.exec(
        'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
        (user['id'], 'save_dynamic_key_pool', json.dumps({
            'id': item.get('id'), 'public_id': item.get('public_id'),
            'verified': item.get('verified'), 'enabled': item.get('enabled'),
            'source_type': item.get('source_type'), 'source_name': item.get('source_name'),
        }, ensure_ascii=False)),
    )
    return {'ok': True, 'item': item}


@app.post('/api/admin/dynamic-key-pool/delete')
async def iapt_admin_dynamic_key_pool_delete(request: Request, user=Depends(current_user)):
    require_permission(user, PERM_DYNAMIC_KEY_POOL_MANAGE)
    token = request.headers.get('authorization','').split(' ',1)[1] if request.headers.get('authorization') else ''
    body = AdminDynamicKeyPoolDeleteBody(**(await read_secure_json(request, token, verify=False)))
    try:
        from .dynamic_key_pool import admin_delete
        deleted = admin_delete(body.id)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if not deleted:
        raise HTTPException(404, '密钥不存在')
    db.exec(
        'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
        (user['id'], 'delete_dynamic_key_pool', json.dumps({'id': int(body.id)}, ensure_ascii=False)),
    )
    return {'ok': True, 'deleted_id': int(body.id)}
# IAPT_ADMIN_SUBSCRIPTION_AND_KEY_POOL_END

# IAPT_ANTI_QIUSHUI_IACT_V1_BEGIN
# Feature 17: anti-QiuShui hidden-resource restoration. Feature 0 does NOT grant it.
# Feature 5: optional iACT source-only dynamic alias restoration.
FEATURE_ANTI_QIUSHUI = 17
try:
    FEATURE_NAMES[FEATURE_ANTI_QIUSHUI] = '反加密样本'
except Exception:
    pass


def _iapt_v1_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on', 'y')
    return False


def _iapt_v1_feature_ids(raw) -> set:
    if raw is None:
        return set()
    if isinstance(raw, (list, tuple, set)):
        values = raw
    else:
        text = str(raw).strip()
        if not text:
            return set()
        try:
            parsed = json.loads(text)
            values = parsed if isinstance(parsed, list) else [parsed]
        except Exception:
            values = re.split(r'[^0-9]+', text)
    out = set()
    for item in values:
        try:
            if str(item).strip():
                out.add(int(item))
        except Exception:
            pass
    return out


def _iapt_v1_exact_subscription(user_id: int, feature_id: int):
    """Return an active subscription explicitly containing feature_id.

    A features_json value containing only 0 is intentionally not treated as a
    match. This is the authorization rule requested for anti-QiuShui feature 17.
    """
    rows = []
    try:
        rows.extend(db.all('''
            SELECT s.sub_id,s.sub_name,s.daily_quota,s.features_json,us.expire_at
            FROM user_subscriptions us
            JOIN subscriptions s ON us.sub_id=s.sub_id
            WHERE us.user_id=%s AND (us.expire_at IS NULL OR us.expire_at>NOW())
        ''', (int(user_id),)) or [])
    except Exception:
        pass
    try:
        row = db.one('''
            SELECT s.sub_id,s.sub_name,s.daily_quota,s.features_json,u.subscription_expire AS expire_at
            FROM users u JOIN subscriptions s ON u.subscription_id=s.sub_id
            WHERE u.id=%s AND u.subscription_id<>0
              AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())
            LIMIT 1
        ''', (int(user_id),))
        if row:
            rows.append(row)
    except Exception:
        pass
    try:
        row = db.one("SELECT sub_id,sub_name,daily_quota,features_json,NULL AS expire_at FROM subscriptions WHERE sub_id=0 LIMIT 1")
        if row:
            rows.append(row)
    except Exception:
        pass
    for row in rows:
        try:
            raw = row.get('features_json') if hasattr(row, 'get') else None
            ids = _iapt_v1_feature_ids(raw)
            if int(feature_id) in ids or int(FEATURE_ULTIMATE_ALL) in ids:
                return row
        except Exception:
            continue
    return None


# Preserve all existing feature behavior while making feature 17 exact-only.
_IAPT_V1_PREV_ACTIVE_SUBSCRIPTION = active_subscription


def active_subscription(user_id: int, feature_id: int):
    try:
        if int(feature_id) == int(FEATURE_ANTI_QIUSHUI):
            return _iapt_v1_exact_subscription(int(user_id), int(feature_id))
    except Exception:
        pass
    return _IAPT_V1_PREV_ACTIVE_SUBSCRIPTION(int(user_id), int(feature_id))


# quota.available_quota/deduct_quota resolve active_subscription from their own
# module globals, so patch that reference as well. This prevents feature 0 from
# donating authorization/quota to feature 17 unless 17 is explicitly present.
try:
    from . import quota as _iapt_v1_quota_module
    _IAPT_V1_PREV_QUOTA_ACTIVE_SUBSCRIPTION = _iapt_v1_quota_module.active_subscription

    def _iapt_v1_quota_active_subscription(user_id: int, feature_id: int):
        if int(feature_id) == int(FEATURE_ANTI_QIUSHUI):
            return _iapt_v1_exact_subscription(int(user_id), int(feature_id))
        return _IAPT_V1_PREV_QUOTA_ACTIVE_SUBSCRIPTION(int(user_id), int(feature_id))

    _iapt_v1_quota_module.active_subscription = _iapt_v1_quota_active_subscription
except Exception as _iapt_v1_quota_patch_error:
    print('[IAPT] quota exact-feature patch warning:', _iapt_v1_quota_patch_error)


try:
    _IAPT_V1_PREV_FEATURE_LABEL = _feature_label

    def _feature_label(fid: int) -> str:
        if int(fid or 0) == int(FEATURE_ANTI_QIUSHUI):
            return '反加密样本'
        return _IAPT_V1_PREV_FEATURE_LABEL(fid)
except Exception:
    pass


def _iapt_v1_anti_requested(options) -> bool:
    options = options if isinstance(options, dict) else {}
    return _iapt_v1_truthy(options.get('anti_qiushui')) or _iapt_v1_truthy(options.get('hidden_resource_restore'))


def _iapt_v1_require_anti_qiushui(user_id: int, options) -> None:
    """Feature 17 is an additive entitlement, not the primary task mode.

    A combined task keeps its normal primary feature ID/quota (dynamic Key,
    sokey, enumeration, numeric restore, pool, etc.) and additionally requires
    an explicit feature 17 subscription. Feature 0 never grants this modifier.
    """
    if not _iapt_v1_anti_requested(options):
        return
    if not _iapt_v1_exact_subscription(int(user_id), FEATURE_ANTI_QIUSHUI):
        raise HTTPException(403, '没有找到lib.so文件')


# The authoritative V3 route resolves the primary feature. Anti-QiuShui is a
# pre-extraction modifier, so preserve any selected primary feature and use 17
# as the task feature only when no other advanced V3 mode is selected.
if '_v53_feature_from_options' in globals():
    _IAPT_V1_PREV_V53_FEATURE_FROM_OPTIONS = _v53_feature_from_options

    def _v53_feature_from_options(options):
        options = options if isinstance(options, dict) else {}
        resolved = _IAPT_V1_PREV_V53_FEATURE_FROM_OPTIONS(options)
        if _iapt_v1_anti_requested(options):
            options['anti_qiushui'] = True
            options['hidden_resource_restore'] = True
            options['anti_qiushui_feature_id'] = FEATURE_ANTI_QIUSHUI
            options['required_feature_ids'] = [FEATURE_ANTI_QIUSHUI]
            options['primary_feature_id'] = int(resolved)
            # 反加密样本只恢复真实 assets/lib.so，不改变其他解密功能的主 feature_id。
            options['feature_id'] = int(resolved)
        return resolved


if 'detect_task_features' in globals():
    _IAPT_V1_PREV_DETECT_TASK_FEATURES = detect_task_features

    def detect_task_features(options: dict) -> list[int]:
        options = options if isinstance(options, dict) else {}
        features = list(_IAPT_V1_PREV_DETECT_TASK_FEATURES(options) or [])
        if _iapt_v1_anti_requested(options):
            options['anti_qiushui'] = True
            options['hidden_resource_restore'] = True
            options['anti_qiushui_feature_id'] = FEATURE_ANTI_QIUSHUI
            options['required_feature_ids'] = [FEATURE_ANTI_QIUSHUI]
            if features:
                options['primary_feature_id'] = int(features[0])
                options['feature_id'] = int(features[0])
        # 功能17只做附加授权和 lib.so 前置提取，不覆盖主任务功能或额度。
        return features


# Replace the numeric restore routes with an implementation that accepts a
# source-only iACT mode while retaining the original DEX-based mode.
def _iapt_v1_remove_post_routes(paths) -> None:
    wanted = set(paths)
    kept = []
    for route in list(app.router.routes):
        path = getattr(route, 'path', None)
        methods = {str(x).upper() for x in getattr(route, 'methods', set())}
        if path in wanted and 'POST' in methods:
            continue
        kept.append(route)
    app.router.routes = kept


_IAPT_V1_NUMERIC_PATHS = {
    '/api/source/numeric-restore', '/source/numeric-restore',
    '/api/tasks/numeric-restore', '/tasks/numeric-restore',
}
_iapt_v1_remove_post_routes(_IAPT_V1_NUMERIC_PATHS)


def _iapt_v1_hash_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


@app.post('/api/source/numeric-restore')
@app.post('/source/numeric-restore')
@app.post('/api/tasks/numeric-restore')
@app.post('/tasks/numeric-restore')
def iapt_numeric_source_restore_v1(
    request: Request,
    src: UploadFile = File(...),
    dex: UploadFile = File(default=None),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    feature_id = FEATURE_NUMERIC_FN_RESTORE
    if not active_subscription(int(user['id']), feature_id):
        raise HTTPException(403, '当前订阅不支持动态修复')
    if request.headers.get('x-body-hash') != sha256_hex(payload or ''):
        print('[IAPT numeric-restore] ignored multipart body hash mismatch')

    options = {'feature_id': feature_id, 'numeric_source_restore': True, 'decrypt_version': 'fn_restore', 'threads': 4}
    if payload and iv:
        try:
            from .secure import decrypt_json_payload
            decoded = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt', ''))
            if isinstance(decoded, dict):
                options.update(decoded)
        except Exception as exc:
            print('[IAPT numeric-restore] payload decode skipped:', exc)

    iact = _iapt_v1_truthy(options.get('iact_dynamic_decrypt')) or _iapt_v1_truthy(options.get('iact_decrypt'))
    options['feature_id'] = feature_id
    options['numeric_source_restore'] = True
    options['numeric_restore'] = True
    options['dynamic_restore'] = True
    options['iapec_numeric_dynamic_restore'] = True
    options['restore_fn_names'] = 'on'
    options['dynamic_restore_strategy'] = 'iapec_numeric_dispatch+randomized_numeric_command_table'
    options['iact_dynamic_decrypt'] = bool(iact)
    options['task_version'] = 'iact_restore' if iact else 'fn_restore'
    options['decrypt_version'] = 'iact' if iact else 'fn_restore'

    # The independent dynamic-repair route may additionally request the separate
    # feature-17 iAPEC self-destruction/control-type repair.  Do not let a
    # feature-5-only account smuggle that option through this route.
    if _iapt_v1_truthy(options.get('anti_iapec_self_destruct')):
        anti_fid = int(globals().get('FEATURE_ANTI_QIUSHUI', 17) or 17)
        exact = globals().get('_iapt_v1_exact_subscription')
        anti_sub = exact(int(user['id']), anti_fid) if callable(exact) else None
        if not anti_sub:
            raise HTTPException(403, '功能不可用')
        required = []
        for item in options.get('required_feature_ids') or []:
            try:
                iv = int(item)
                if iv > 0 and iv not in required:
                    required.append(iv)
            except Exception:
                pass
        if feature_id not in required:
            required.append(feature_id)
        if anti_fid not in required:
            required.append(anti_fid)
        options['required_feature_ids'] = required
        options['anti_iapec_self_destruct_feature_id'] = anti_fid
        options['anti_iapec_self_destruct_strategy'] = 'libDestruction/profile+layout-semantics/control-type-backfill'
    if iact:
        options['iact_mapping_version'] = 1
        options['skip_dex_upload'] = True
        options['no_dex_upload'] = True

    task_no = secrets.token_hex(16)
    upload_dir = APP_STORAGE / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    src_zip = upload_dir / f'{task_no}.apk'
    dex_path = upload_dir / f'{task_no}.dex'
    dex_present = bool(dex is not None and getattr(dex, 'filename', None))

    try:
        with src_zip.open('wb') as stream:
            shutil.copyfileobj(src.file, stream)
        src_size = int(src_zip.stat().st_size)
        dex_size = 0
        if dex_present:
            with dex_path.open('wb') as stream:
                shutil.copyfileobj(dex.file, stream)
            dex_size = int(dex_path.stat().st_size)
    except Exception as exc:
        raise HTTPException(500, '保存动态修复输入失败：' + str(exc))

    if src_size <= 0:
        raise HTTPException(400, '源码 ZIP 为空')
    if not iact and dex_size <= 0:
        raise HTTPException(400, '普通动态修复必须上传 DEX；iACT 动态解密只需上传源码')
    if src_size > 128 * 1024 * 1024 or dex_size > 128 * 1024 * 1024:
        raise HTTPException(413, '上传文件超过 128MB')
    if not zipfile.is_zipfile(src_zip):
        raise HTTPException(400, '请上传 src 打包后的 ZIP 文件')
    if not _iapt_source_restore_zip_has_source(src_zip):
        raise HTTPException(400, 'ZIP 中没有找到 iApp 源码文件')
    if not iact:
        try:
            head = dex_path.read_bytes()[:8]
            is_raw_dex = head.startswith(b'dex\n')
            is_archive = zipfile.is_zipfile(dex_path)
            if not is_raw_dex and not is_archive:
                raise HTTPException(400, '请上传 DEX/APK/ZIP/JAR 文件')
            if is_archive:
                with zipfile.ZipFile(dex_path, 'r') as _iapec_zip:
                    if not any(re.fullmatch(r'(?:.*/)?classes\d*\.dex', n.replace('\\','/'), flags=re.I) for n in _iapec_zip.namelist()):
                        raise HTTPException(400, '安装包中没有找到 classes*.dex')
            options['dynamic_restore_attachment_kind'] = 'dex' if is_raw_dex else 'archive'
            options['dynamic_restore_attachment_name'] = str(getattr(dex, 'filename', '') or '')
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(400, '读取 DEX/APK/ZIP/JAR 文件失败')

    upload_bytes = src_size + (dex_size if not iact else 0)
    cost = cost_for_bytes(upload_bytes)
    quota = available_quota(int(user['id']), feature_id)
    if quota_decimal(quota.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：上传共 {upload_bytes} bytes 需要 {cost} 额度，当前剩余 {quota.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), feature_id, cost)
    except ValueError as exc:
        raise HTTPException(402, str(exc))

    src_sha = _iapt_v1_hash_file(src_zip)
    dex_sha = _iapt_v1_hash_file(dex_path) if (not iact and dex_path.exists()) else 'source-only-iact'
    # IAPT_IACT_APK_SHA256_V7B: keep DB apk_sha256/apk__sha256 to one real 64-hex digest.
    # Store per-input hashes in options_json instead of concatenating them into the DB column.
    options['src_sha256'] = src_sha
    options['dex_sha256'] = dex_sha if (not iact and dex_path.exists()) else ''
    options['upload_sha256'] = src_sha
    opt_hash = hashlib.sha256(json.dumps(options, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    name = _iapt_source_restore_safe_name(Path(src.filename or 'src.zip').stem)
    suffix = '_iact.zip' if iact else '_numeric.zip'
    apk_name = name if name.endswith('.zip') else name + suffix
    quota_after = available_quota(int(user['id']), feature_id).get('total', 0)
    if iact:
        resource_note = f'iACT动态解密上传扣除：src {src_size} bytes，不上传DEX，扣除 {cost} 额度'
        quota_note = f'iACT动态解密任务已创建；服务端按内置替换表反向还原函数名'
    else:
        resource_note = f'动态修复上传扣除：src {src_size} bytes + dex {dex_size} bytes，扣除 {cost} 额度'
        quota_note = f'动态修复任务已创建；完成后可下载还原源码 ZIP'
    try:
        task_id = db.exec('''
            INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash,resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note)
            VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)
        ''', (
            task_no, user['id'], apk_name, feature_id, options['decrypt_version'],
            json.dumps(options, ensure_ascii=False), src_sha, opt_hash,
            cost, resource_note, quota_public_value(cost), quota_after, quota_note,
        ))
    except Exception as exc:
        for path in (src_zip, dex_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
        raise HTTPException(500, '创建动态修复任务失败：' + str(exc))
    try:
        enqueue_task(int(task_id))
    except Exception as exc:
        print('[WARN] enqueue numeric source restore failed:', exc)
    return {
        'ok': True, 'task_id': task_id, 'task_no': task_no, 'status': 'queued',
        'feature_id': feature_id, 'decrypt_version': options['decrypt_version'],
        'task_version': options.get('task_version', options['decrypt_version']), 'iact_dynamic_decrypt': bool(iact),
        'dex_uploaded': bool(not iact and dex_size > 0),
        'resource_quota_cost': cost, 'quota_limit': quota_after,
    }

print('[IAPT] anti-QiuShui feature17 + iACT source-only restore installed')
# IAPT_ANTI_QIUSHUI_IACT_V1_END

# IAPT_CHUNK_DOWNLOAD_V13_BEGIN
# Small, independently retriable chunks avoid Android/Cloudflare/proxy EOFs.
# The complete ZIP is built atomically and validated before a session is exposed.
import os as _iapt_v13_os
import time as _iapt_v13_time
from fastapi.responses import Response as _IaptV13Response

_IAPT_V13_CHUNK_SIZE = 512 * 1024
_IAPT_V13_MAX_CHUNK = 512 * 1024
_IAPT_V13_SESSION_TTL = 30 * 60


def _iapt_v13_session_dir() -> Path:
    path = APP_STORAGE / "zips"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _iapt_v13_session_meta(session: str) -> Path:
    if not re.fullmatch(r"[0-9a-f]{32}", str(session or "")):
        raise HTTPException(400, "下载会话无效")
    return _iapt_v13_session_dir() / (".iapt_v13_" + session + ".json")


def _iapt_v13_atomic_json(path: Path, obj: dict) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    _iapt_v13_os.replace(tmp, path)


def _iapt_v13_cleanup_sessions() -> None:
    now = int(_iapt_v13_time.time())
    root = _iapt_v13_session_dir().resolve()
    for meta in list(root.glob(".iapt_v13_*.json"))[:500]:
        try:
            obj = json.loads(meta.read_text(encoding="utf-8"))
            if int(obj.get("expires") or 0) >= now:
                continue
            raw_path = Path(str(obj.get("path") or "")).resolve()
            raw_path.relative_to(root)
            try:
                raw_path.unlink()
            except FileNotFoundError:
                pass
            meta.unlink()
        except Exception:
            try:
                if meta.stat().st_mtime < _iapt_v13_time.time() - 86400:
                    meta.unlink()
            except Exception:
                pass


def _iapt_v13_zip_rows(task: dict, rows: list[dict], dest: Path) -> tuple[int, int]:
    out_dir = Path(str(task.get("out_dir") or ""))
    if not out_dir.is_dir():
        raise HTTPException(404, "任务输出目录不存在或已被清理")
    preserve_roots = any(
        str((row or {}).get("rel_path") or "").replace("\\", "/").lstrip("./").startswith("res/")
        for row in rows or []
    )
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    try:
        tmp.unlink()
    except FileNotFoundError:
        pass
    count = 0
    total = 0
    missing = []
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, allowZip64=True) as z:
        for row in rows or []:
            rel = str((row or {}).get("rel_path") or "").replace("\\", "/").lstrip("./")
            if not rel or rel.startswith("assets/"):
                continue
            fp = out_dir / rel
            try:
                resolved = fp.resolve()
                resolved.relative_to(out_dir.resolve())
            except Exception:
                missing.append(rel)
                continue
            if not resolved.is_file():
                missing.append(rel)
                continue
            arcname = rel
            z.write(resolved, arcname)
            count += 1
            total += int(resolved.stat().st_size)
    if missing:
        try:
            tmp.unlink()
        except Exception:
            pass
        raise HTTPException(409, "下载清单与磁盘文件不一致，请刷新任务后重试：" + ", ".join(missing[:8]))
    if count <= 0:
        try:
            tmp.unlink()
        except Exception:
            pass
        raise HTTPException(404, "任务没有可下载的 src/res 文件")
    try:
        with zipfile.ZipFile(tmp, "r") as check:
            bad = check.testzip()
            names = [x.filename for x in check.infolist() if not x.is_dir()]
            if bad is not None or len(names) != count:
                raise RuntimeError("ZIP 完整性校验失败")
    except Exception as exc:
        try:
            tmp.unlink()
        except Exception:
            pass
        raise HTTPException(500, "生成下载 ZIP 失败：" + str(exc))
    dest.parent.mkdir(parents=True, exist_ok=True)
    _iapt_v13_os.replace(tmp, dest)
    return count, total


def _iapt_v13_public_name(task: dict, secure: bool) -> str:
    task_ver = str(task.get("decrypt_version") or "").strip().lower()
    if task_ver in ("key", "dynkey", "dynamic_key_extract"):
        name = str(task.get("apk_name") or "dynamic_key.zip")
        if not name.lower().endswith(".zip"):
            name += ".zip"
        return name[:-4] + ".izip" if secure else name
    if task_ver in ("fn_restore", "numeric_restore"):
        suffix = "_numeric_restored"
    elif int(task.get("feature_id") or 0) == int(FEATURE_SOURCE_RESTORE):
        suffix = "_restored"
    else:
        suffix = "_decrypted"
    return f"{task['apk_name']}{suffix}.izip" if secure else f"{task['apk_name']}{suffix}.zip"


def _iapt_v13_create_session(*, user_id: int, task_id: int, source_path: Path,
                             filename: str, admin: bool, extra: dict | None = None) -> dict:
    _iapt_v13_cleanup_sessions()
    session = secrets.token_hex(16)
    root = _iapt_v13_session_dir().resolve()
    source = source_path.resolve()
    source.relative_to(root)
    size = int(source.stat().st_size)
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    obj = {
        "version": 13,
        "session": session,
        "user_id": int(user_id),
        "task_id": int(task_id),
        "admin": bool(admin),
        "path": str(source),
        "filename": str(filename),
        "size": size,
        "sha256": digest,
        "chunk_size": _IAPT_V13_CHUNK_SIZE,
        "expires": int(_iapt_v13_time.time()) + _IAPT_V13_SESSION_TTL,
    }
    if isinstance(extra, dict):
        obj.update(extra)
    _iapt_v13_atomic_json(_iapt_v13_session_meta(session), obj)
    public = dict(obj)
    public.pop("path", None)
    public.pop("user_id", None)
    public.pop("admin", None)
    return public


def _iapt_v13_load_session(session: str, user: dict, task_id: int, admin: bool) -> dict:
    meta_path = _iapt_v13_session_meta(session)
    try:
        obj = json.loads(meta_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise HTTPException(404, "下载会话不存在或已过期")
    except Exception:
        raise HTTPException(400, "下载会话损坏")
    if int(obj.get("expires") or 0) < int(_iapt_v13_time.time()):
        raise HTTPException(410, "下载会话已过期")
    if int(obj.get("user_id") or 0) != int((user or {}).get("id") or 0):
        raise HTTPException(403, "下载会话不属于当前账号")
    if int(obj.get("task_id") or 0) != int(task_id) or bool(obj.get("admin")) != bool(admin):
        raise HTTPException(403, "下载会话与任务不匹配")
    path = Path(str(obj.get("path") or "")).resolve()
    root = _iapt_v13_session_dir().resolve()
    try:
        path.relative_to(root)
    except Exception:
        raise HTTPException(403, "下载会话路径非法")
    if not path.is_file() or int(path.stat().st_size) != int(obj.get("size") or -1):
        raise HTTPException(410, "下载文件已被清理")
    obj["_path"] = path
    return obj


def _iapt_v13_chunk_response(obj: dict, offset: int, length: int):
    size = int(obj.get("size") or 0)
    offset = int(offset or 0)
    length = max(1, min(int(length or _IAPT_V13_CHUNK_SIZE), _IAPT_V13_MAX_CHUNK))
    if offset < 0 or offset >= size:
        raise HTTPException(416, "下载偏移超出范围")
    want = min(length, size - offset)
    path = obj["_path"]
    with path.open("rb") as f:
        f.seek(offset)
        data = f.read(want)
    if len(data) != want:
        raise HTTPException(500, "读取下载分片不完整")
    end = offset + len(data) - 1
    return _IaptV13Response(
        content=data,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store",
            "Accept-Ranges": "bytes",
            "Content-Range": f"bytes {offset}-{end}/{size}",
            "X-IAPT-Chunk-SHA256": hashlib.sha256(data).hexdigest(),
            "X-IAPT-Chunk-Length": str(len(data)),
        },
    )


@app.get('/api/tasks/{task_id}/download-v13/start')
def iapt_task_download_v13_start(task_id: int, request: Request, user=Depends(current_user)):
    task = db.one('SELECT * FROM tasks WHERE id=%s AND user_id=%s', (task_id, user['id']))
    if not task:
        raise HTTPException(404, '任务不存在')
    if task['status'] != 'done':
        raise HTTPException(400, '任务未完成')
    # list_task_files now re-scans physical src/res trees for targeted modes.
    plan = _download_plan(task, user, auto_deduct=True)
    chosen = plan['persisted_files']
    if not chosen:
        if plan['files']:
            raise HTTPException(402, '当前账号额度不足')
        raise HTTPException(404, '当前任务没有可下载文件')
    root = _iapt_v13_session_dir()
    raw_zip = root / f"v13_{task['task_no']}_{secrets.token_hex(8)}.zip"
    file_count, source_bytes = _iapt_v13_zip_rows(task, chosen, raw_zip)
    token = request.headers.get('authorization', '').split(' ', 1)[1] if request.headers.get('authorization') and ' ' in request.headers.get('authorization') else ''
    from .secure_download import encrypt_zip_for_user
    secure_path, secure_headers = encrypt_zip_for_user(raw_zip, token, task['task_no'])
    secure_path = Path(secure_path)
    if secure_path.resolve() != raw_zip.resolve():
        try:
            raw_zip.unlink()
        except Exception:
            pass
    secure = str(secure_headers.get('x-zip-mode') or '').startswith('aes-')
    extra = {
        'mode': secure_headers.get('x-zip-mode', ''),
        'task_no': secure_headers.get('x-zip-task', task['task_no']),
        'ts': secure_headers.get('x-zip-ts', ''),
        'salt': secure_headers.get('x-zip-salt', ''),
        'iv': secure_headers.get('x-zip-iv', ''),
        'signature': secure_headers.get('x-zip-sign', ''),
        'original_size': int(secure_headers.get('x-zip-original-size') or raw_zip.stat().st_size),
        'file_count': int(file_count),
        'source_bytes': int(source_bytes),
    }
    return _iapt_v13_create_session(
        user_id=user['id'], task_id=task_id, source_path=Path(secure_path),
        filename=_iapt_v13_public_name(task, secure), admin=False, extra=extra,
    )


@app.get('/api/tasks/{task_id}/download-v13/chunk')
def iapt_task_download_v13_chunk(task_id: int, session: str, offset: int = 0,
                                 length: int = _IAPT_V13_CHUNK_SIZE,
                                 user=Depends(current_user)):
    obj = _iapt_v13_load_session(session, user, task_id, False)
    return _iapt_v13_chunk_response(obj, offset, length)


@app.get('/api/admin/tasks/{task_id}/download-source-v13/start')
def iapt_admin_download_v13_start(task_id: int, user=Depends(current_user)):
    admin_user(user)
    require_permission(user, PERM_TASK_VIEW_ALL)
    task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
    if not task:
        raise HTTPException(404, '任务不存在')
    rows = list_task_files(task)
    if not rows:
        raise HTTPException(404, '任务 src/res 文件为空或已被清理')
    root = _iapt_v13_session_dir()
    raw_zip = root / f"v13_admin_{task['task_no']}_{secrets.token_hex(8)}.zip"
    file_count, source_bytes = _iapt_v13_zip_rows(task, rows, raw_zip)
    name = re.sub(r'[\\/:*?"<>|]+', '_', str(task.get('apk_name') or task.get('task_no') or 'task'))
    if name.lower().endswith('.apk'):
        name = name[:-4]
    return _iapt_v13_create_session(
        user_id=user['id'], task_id=task_id, source_path=raw_zip,
        filename=name + '_source.zip', admin=True,
        extra={'mode': 'plain', 'file_count': int(file_count), 'source_bytes': int(source_bytes)},
    )


@app.get('/api/admin/tasks/{task_id}/download-source-v13/chunk')
def iapt_admin_download_v13_chunk(task_id: int, session: str, offset: int = 0,
                                  length: int = _IAPT_V13_CHUNK_SIZE,
                                  user=Depends(current_user)):
    admin_user(user)
    require_permission(user, PERM_TASK_VIEW_ALL)
    obj = _iapt_v13_load_session(session, user, task_id, True)
    return _iapt_v13_chunk_response(obj, offset, length)
# IAPT_CHUNK_DOWNLOAD_V13_END



# BEGIN IAPT HVM KEY ROUTER AUTO-INCLUDE
import os as _iapt_os
import sys as _iapt_sys
_iapt_site_dir = r"/www/wwwroot/iapt"
if _iapt_site_dir not in _iapt_sys.path:
    _iapt_sys.path.insert(0, _iapt_site_dir)
_iapt_os.environ.setdefault("IAPT_KEY_SERVER_CONFIG", r"/www/wwwroot/iapt/iapt_key_server_v1/config.json")
from iapt_hvm_key_router import router as _iapt_hvm_router
app.include_router(_iapt_hvm_router)
# END IAPT HVM KEY ROUTER AUTO-INCLUDE

# IAPT_HVM_ROUTE_DEDUP_V1
_iapt_hvm_removed = []
for _r in list(app.router.routes):
    if (
        getattr(_r, "path", "") == "/api/hvm4/key"
        and "POST" in (getattr(_r, "methods", set()) or set())
    ):
        _ep = getattr(_r, "endpoint", None)
        _mod = getattr(_ep, "__module__", "")
        _name = getattr(_ep, "__name__", "")
        if _mod == "app.iapt_hybrid_vm_broker":
            app.router.routes.remove(_r)
            _iapt_hvm_removed.append((_mod, _name))
print("[OK] IAPT_HVM_ROUTE_DEDUP_V1 removed", _iapt_hvm_removed)

# IAPT_V10_SINGLE_SCRIPT_MAIN_BEGIN
# Preserve routing/preprocessing parameters that older API sanitizers dropped.
if '_IAPT_V10_BASE_SANITIZE' not in globals():
    _IAPT_V10_BASE_SANITIZE = _sanitize_decrypt_options


def _sanitize_decrypt_options(options: dict, user_id: int):
    raw = dict(options or {})
    clean, feature_id, feature_scope = _IAPT_V10_BASE_SANITIZE(raw, user_id)
    keep = (
        'decrypt_scheme', 'legacy_iapp', 'old_iapp', 'old_iapp_auto_detected',
        'sokey', 'old_sokey', 'client_old_plaintext_sokey_auto', 'client_old_multiabi_sokey',
        'anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore',
        'client_sokey', 'client_dexkey', 'client_fb_auto', 'fb_auto',
        'custom_main_file', 'entry_file', 'auto_main_file',
        'server_key_pool_mode', 'server_key_pool_ref',
        'dynamic_key_features', 'dynamic_key_feature_version',
        'dynamic_key_sample_entry', 'dynamic_key_sample_abi',
        'dynamic_key_default_match', 'required_feature_ids',
        'client_route_probe', 'client_anti_probe',
    )
    for key in keep:
        if key in raw:
            clean[key] = raw[key]
    scheme = str(raw.get('decrypt_scheme') or '').strip().lower()
    if scheme == 'ancient' or bool(raw.get('legacy_iapp')) or bool(raw.get('old_iapp')):
        clean['decrypt_scheme'] = 'ancient'
        clean['legacy_iapp'] = True
        clean['old_iapp'] = True
    elif scheme == 'v3':
        clean['decrypt_scheme'] = 'v3'
    if any(bool(raw.get(k)) for k in ('anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore')):
        clean['anti_encrypted_sample'] = True
        clean['anti_qiushui'] = True
        clean['hidden_resource_restore'] = True
    # Keep the client-selected dynamic-key-pool mode.  The V10 runner resolves
    # the opaque ref on the server and never sends raw pool keys to the client.
    pool_mode = str(raw.get('server_key_pool_mode') or '').strip().lower()
    if pool_mode in ('selected', 'enum'):
        clean['server_key_pool_mode'] = pool_mode
        if pool_mode == 'selected':
            clean['server_key_pool_ref'] = str(raw.get('server_key_pool_ref') or '').strip()
    return clean, feature_id, feature_scope


try:
    @app.get('/api/system/iapt-v10')
    def _iapt_v10_system_marker():
        return {
            'ok': True,
            'version': 'v10-single-script',
            'dual_engine': True,
            'ancient_qe_isolated': True,
            'runner_marker': 'IAPT_V10_SINGLE_SCRIPT_ROUTER',
        }
except Exception:
    pass
# IAPT_V10_SINGLE_SCRIPT_MAIN_END

# IAPT_V69_SYSTEM_ROUTE_BEGIN
try:
    _iapt_v69_app = globals().get("app")
    if _iapt_v69_app is not None:
        def _iapt_v69_status_payload():
            import inspect
            try:
                from app import decrypt_runner as _iapt_v69_runner
                _run_task = getattr(_iapt_v69_runner, "run_task", None)
                _run_src = inspect.getsource(_run_task) if callable(_run_task) else ""
                _probe = getattr(_iapt_v69_runner, "_iapt_v10_probe", None)
                _probe_src = inspect.getsource(_probe) if callable(_probe) else ""
                return {
                    "ok": True,
                    "tag": "v10-single-script",
                    "route": "iapt-v69",
                    "runner_import": "V10" if "_iapt_v10_execute" in _run_src else "unknown",
                    "probe": "V68" if "IAPT_V68_CANONICAL_PROBE_OVERRIDE_BEGIN" in _probe_src else "present" if callable(_probe) else "missing",
                }
            except Exception as _iapt_v69_exc:
                return {
                    "ok": False,
                    "tag": "v10-single-script",
                    "route": "iapt-v69",
                    "error": f"{type(_iapt_v69_exc).__name__}: {_iapt_v69_exc}",
                }

        @_iapt_v69_app.get("/api/system/iapt-v10", include_in_schema=False)
        def _iapt_v69_system_iapt_v10():
            return _iapt_v69_status_payload()

        @_iapt_v69_app.get("/api/system/iapt-v11", include_in_schema=False)
        def _iapt_v69_system_iapt_v11_alias():
            return _iapt_v69_status_payload()
except Exception:
    pass
# IAPT_V69_SYSTEM_ROUTE_END

# IAPT_V83_MAIN_QUEUE_ROUTER_BEGIN
_IAPT_V83_BASE_ENQUEUE_TASK = enqueue_task

def enqueue_task(task_id):
    try:
        from . import decrypt_runner as _iapt_v83_runner
        router = getattr(_iapt_v83_runner, "_iapt_v82_route_and_persist", None)
        if callable(router):
            router(int(task_id), stage="enqueue-v83")
        else:
            print(
                "[IAPT_V83_ROUTER_WARN] V82 route function is unavailable",
                flush=True,
            )
    except Exception as exc:
        print(
            "[IAPT_V83_ROUTER_WARN] enqueue route failed task=%s error=%s: %s"
            % (task_id, type(exc).__name__, exc),
            flush=True,
        )
    return _IAPT_V83_BASE_ENQUEUE_TASK(int(task_id))

print("IAPT_MAIN_QUEUE_ROUTER_V83 installed")
# IAPT_V83_MAIN_QUEUE_ROUTER_END

# IAPT_V84_ANCIENT_PARAM_SANITIZER_BEGIN
# Preserve ancient four-character parameters and map a missing dexkey to the
# static automatic parameter path. Enumeration remains opt-in only.
_IAPT_V84_BASE_SANITIZE = _sanitize_decrypt_options
_IAPT_V84_BASE_ENQUEUE = enqueue_task


def _iapt_v84_main_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in ("1", "true", "yes", "on", "y")


def _iapt_v84_main_old_sokey(value) -> str:
    import re as _re
    text = str(value or "").strip()
    return text if _re.fullmatch(r"[A-Za-z0-9]{4}", text) else ""


def _sanitize_decrypt_options(options: dict, user_id: int):
    raw = dict(options or {})
    clean, feature_id, feature_scope = _IAPT_V84_BASE_SANITIZE(raw, user_id)
    for key in (
        "dexkey_auto", "client_dexkey_auto", "client_fb_dex_fallback",
        "client_old_dexkey_enum_auto", "client_old_dexkey_parameter_required", "force_upload_dex", "require_dex_upload",
        "client_upload_dex", "client_upload_dex_mode", "client_uploaded_dex",
        "old_sokey_probe", "_iapt_v84_router",
        "ancient_dynamic_restore", "v3_dynamic_restore", "numeric_restore", "dynamic_restore",
        "restore_fn_names", "primary_feature_id",
    ):
        if key in raw:
            clean[key] = raw[key]

    old_key = ""
    for key in ("old_sokey", "sokey", "hidden", "client_sokey"):
        old_key = _iapt_v84_main_old_sokey(raw.get(key))
        if old_key:
            break
    ancient = (
        str(raw.get("decrypt_scheme") or "").strip().lower() == "ancient"
        or str(raw.get("decrypt_version") or "").strip().lower() in ("ancient", "old", "legacy", "old_iapp", "iapp_old")
        or _iapt_v84_main_truthy(raw.get("legacy_iapp"))
        or _iapt_v84_main_truthy(raw.get("old_iapp"))
    )
    if ancient:
        clean["decrypt_scheme"] = "ancient"
        clean["decrypt_version"] = "ancient"
        clean["task_version"] = "ancient"
        clean["legacy_iapp"] = True
        clean["old_iapp"] = True
        clean.pop("hidden", None)
        clean.pop("client_sokey", None)
        if old_key:
            clean["sokey"] = old_key
            clean["old_sokey"] = old_key

        # Only an explicit user/client enum survives. Older sanitizers added
        # dexkey_enum automatically; that behavior is removed here.
        explicit_enum = (
            (_iapt_v84_main_truthy(raw.get("dexkey_enum")) or _iapt_v84_main_truthy(raw.get("dex_enum")))
            and not _iapt_v84_main_truthy(raw.get("client_old_dexkey_enum_auto"))
        )
        explicit_dex = ""
        for key in ("fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"):
            value = str(raw.get(key) or clean.get(key) or "").strip()
            if value:
                explicit_dex = value
                break
        if explicit_enum:
            clean["dexkey_enum"] = True
            clean.setdefault("dexkey_enum_start", 3_100_000)
            clean.setdefault("dexkey_enum_stop", 10_000_000)
            feature_id = 2
        else:
            for key in (
                "dexkey_enum", "dex_enum", "dexkey_enum_start", "dexkey_enum_stop",
                "dex_enum_start", "dex_enum_stop", "client_old_dexkey_enum_auto",
                "disable_client_dexkey_auto", "enum_quiet", "no_python_fallback",
            ):
                clean.pop(key, None)
            if explicit_dex:
                clean["fb"] = explicit_dex
                clean["dexkey_auto"] = False
            else:
                clean["dexkey_auto"] = False
                clean["client_old_dexkey_parameter_required"] = True
            # V150: allow dynamic restore for old/ancient-iApp, but keep it in the ancient pipeline.
            dynamic_restore = (
                _iapt_v92_bool(raw.get("ancient_dynamic_restore"))
                or _iapt_v92_bool(raw.get("numeric_restore"))
                or _iapt_v92_bool(raw.get("dynamic_restore"))
                or str(raw.get("restore_fn_names") or "").strip().lower() in ("auto", "on", "true", "1")
            )
            if dynamic_restore:
                clean["ancient_dynamic_restore"] = True
                clean["v3_dynamic_restore"] = False
                clean["numeric_restore"] = True
                clean["dynamic_restore"] = True
                clean["restore_fn_names"] = "on"
                clean["require_dex_upload"] = True
                clean["primary_feature_id"] = int(globals().get("FEATURE_NUMERIC_FN_RESTORE", 5) or 5)
            else:
                clean["ancient_dynamic_restore"] = False
                clean["v3_dynamic_restore"] = False
                clean["numeric_restore"] = False
                clean["dynamic_restore"] = False
                clean["restore_fn_names"] = "off"
                clean.pop("primary_feature_id", None)
                clean.pop("require_dex_upload", None)
            if not explicit_enum:
                feature_id = int(globals().get("FEATURE_BASIC", 1) or 1)
        clean.setdefault("signature_mode", "auto")
    return clean, feature_id, feature_scope


def enqueue_task(task_id):
    try:
        from . import decrypt_runner as _iapt_v84_runner
        router = getattr(_iapt_v84_runner, "_iapt_v84_route_and_persist", None)
        if callable(router):
            router(int(task_id), stage="enqueue-v84")
    except Exception as exc:
        print(
            "[IAPT_V84_MAIN_WARN] route failed task=%s error=%s: %s"
            % (task_id, type(exc).__name__, exc),
            flush=True,
        )
    return _IAPT_V84_BASE_ENQUEUE(int(task_id))


try:
    @app.get("/api/system/iapt-v84", include_in_schema=False)
    def _iapt_v84_status():
        from . import decrypt_runner as runner
        return {
            "ok": True,
            "version": getattr(runner, "IAPT_ROUTER_VERSION", "unknown"),
            "ancient_sokey_length": 4,
            "missing_dexkey_mode": "manual-parameter-required",
            "automatic_dexkey_enumeration": False,
        }
except Exception:
    pass

print("IAPT_MAIN_ANCIENT_PARAM_V84 installed")
# IAPT_V84_ANCIENT_PARAM_SANITIZER_END


# IAPT_V85_ANCIENT_FAST_STATUS_BEGIN
try:
    @app.get("/api/system/iapt-v85", include_in_schema=False)
    def _iapt_v85_status():
        from . import decrypt_runner as runner
        return {
            "ok": True,
            "version": getattr(runner, "IAPT_ROUTER_VERSION", "unknown"),
            "ancient_executor": "in-process",
            "native_aes_backend": True,
            "atomic_task_claim": True,
            "monotonic_terminal_status": True,
            "ancient_sokey_length": 4,
            "missing_dexkey_mode": "parameter-required-or-static-client",
            "automatic_dexkey_enumeration": False,
        }
except Exception:
    pass

print("IAPT_MAIN_ANCIENT_FAST_STATUS_V85 installed")
# IAPT_V85_ANCIENT_FAST_STATUS_END


# IAPT_V86_ANCIENT_STABLE_C_ENUM_DYNAMIC_RESTORE_BEGIN
IAPT_ANCIENT_PATCH_VERSION = "V88-ancient-invariant-c-multichannel-dynamic-restore-statusfix"

def _iapt_v86_truthy(value):
    if value is True or value == 1: return True
    return str(value or "").strip().lower() in ("1","true","yes","on","y","auto")

def _iapt_v86_task_options(task):
    raw = (task or {}).get("options_json")
    if isinstance(raw, dict): return dict(raw)
    try: return json.loads(raw or "{}") if raw else {}
    except Exception: return {}

def _iapt_v86_is_ancient(task):
    opts = _iapt_v86_task_options(task)
    ver = str((task or {}).get("decrypt_version") or opts.get("decrypt_version") or opts.get("task_version") or "").strip().lower()
    return (
        ver in ("ancient","old","legacy","old_iapp","iapp_old")
        or str(opts.get("decrypt_scheme") or "").strip().lower() == "ancient"
        or _iapt_v86_truthy(opts.get("legacy_iapp")) or _iapt_v86_truthy(opts.get("old_iapp"))
    )

def _iapt_v86_reconcile_ancient_task(task):
    row = dict(task or {})
    if not row or not _iapt_v86_is_ancient(row): return row
    opts = _iapt_v86_task_options(row)
    row["decrypt_version"] = "ancient"
    row["task_version"] = "ancient"
    if int(row.get("feature_id") or 0) == 6:
        fid = int(opts.get("primary_feature_id") or opts.get("feature_id") or 1)
        row["feature_id"] = 1 if fid == 6 else fid
    task_no = str(row.get("task_no") or "")
    out_dir = Path(row.get("out_dir") or (APP_STORAGE / "tasks" / task_no))
    report_path = out_dir / "old_iapp_report.json"
    report_ok = False
    try:
        obj = json.loads(report_path.read_text(encoding="utf-8"))
        report_ok = isinstance(obj, dict) and obj.get("ok") is True
    except Exception:
        report_ok = False
    if report_ok:
        try:
            row["out_dir"] = str(out_dir)
            files = list_task_files(row)
            count = len(files)
            total = sum(int(x.get("size_bytes") or 0) for x in files)
            if count > 0:
                db.exec("UPDATE tasks SET status='done',decrypt_version='ancient',error_text=NULL,file_count=%s,total_bytes=%s WHERE id=%s", (count,total,int(row.get("id") or 0)))
                row.update({"status":"done","error_text":None,"file_count":count,"total_bytes":total})
                try: settle_decrypt_quota_once(int(row.get("id") or 0))
                except Exception: pass
        except Exception:
            pass
    elif str(row.get("status") or "").lower() == "failed" and int(row.get("file_count") or 0) > 0:
        # A stale worker may briefly publish failed after files have been indexed.
        # Keep the task running during the commit grace window instead of exposing a false terminal state.
        recent = False
        try:
            recent = out_dir.exists() and (time.time() - out_dir.stat().st_mtime) < 180
        except Exception:
            pass
        if recent:
            try: db.exec("UPDATE tasks SET status='running',decrypt_version='ancient',error_text=NULL WHERE id=%s", (int(row.get("id") or 0),))
            except Exception: pass
            row["status"] = "running"; row["error_text"] = None
    try:
        opts["decrypt_scheme"] = "ancient"
        opts["decrypt_version"] = "ancient"
        opts["task_version"] = "ancient"
        opts["legacy_iapp"] = True
        opts["old_iapp"] = True
        fixed_fid = int(row.get("feature_id") or 1)
        if fixed_fid == 6:
            fixed_fid = int(opts.get("primary_feature_id") or 1)
            if fixed_fid == 6: fixed_fid = 1
        db.exec(
            "UPDATE tasks SET decrypt_version='ancient',feature_id=%s,options_json=%s WHERE id=%s",
            (fixed_fid, json.dumps(opts, ensure_ascii=False, separators=(",", ":"), default=str), int(row.get("id") or 0)),
        )
        row["feature_id"] = fixed_fid
    except Exception:
        pass
    row.pop("options_json", None)
    return row

try:
    @app.get("/api/system/iapt-v87", include_in_schema=False)
    def _iapt_v87_status():
        from . import decrypt_runner as runner
        from .tools.iapt_v10 import iapp_old_decrypt as old
        binary = old._fast_enum_binary()
        return {
            "ok": True,
            "version": IAPT_ANCIENT_PATCH_VERSION,
            "router": getattr(runner, "IAPT_ROUTER_VERSION", "unknown"),
            "task_type": "ancient-fixed",
            "c_multichannel_enum": bool(binary),
            "c_enum_binary": str(binary or ""),
            "sokey_length": 4,
            "sokey_enum": "c-pthreads",
            "dexkey_enum": "c-pthreads",
            "dynamic_restore": "server-dex-mapping",
            "false_failed_reconcile": True,
            "task_identity_invariant": "ancient-from-insert-to-terminal",
            "enum_workers": int(os.environ.get("IAPT_OLD_ENUM_WORKERS") or os.environ.get("IAPT_ENUM_WORKERS") or 0),
        }
except Exception as _iapt_v87_status_error:
    print("IAPT_V87 status install failed", repr(_iapt_v87_status_error))

print("IAPT_V87_ANCIENT_INVARIANT_C_ENUM_DYNAMIC_RESTORE installed")
# IAPT_V86_ANCIENT_STABLE_C_ENUM_DYNAMIC_RESTORE_END


# IAPT_V88_STATUS_IMPORT_FIX_BEGIN
@app.get("/api/system/iapt-v88", include_in_schema=False)
def _iapt_v88_status():
    import os as _os
    from . import decrypt_runner as _runner
    from .tools.iapt_v10 import iapp_old_decrypt as _old
    _binary = _old._fast_enum_binary()
    return {
        "ok": True,
        "version": "V88-ancient-invariant-c-multichannel-dynamic-restore-statusfix",
        "router": getattr(_runner, "IAPT_ROUTER_VERSION", "unknown"),
        "task_type": "ancient-fixed",
        "c_multichannel_enum": bool(_binary),
        "c_enum_binary": str(_binary or ""),
        "sokey_length": 4,
        "sokey_enum": "c-pthreads",
        "dexkey_enum": "c-pthreads",
        "dynamic_restore": "server-dex-mapping",
        "false_failed_reconcile": True,
        "task_identity_invariant": "ancient-from-insert-to-terminal",
        "enum_workers": int(_os.environ.get("IAPT_OLD_ENUM_WORKERS") or _os.environ.get("IAPT_ENUM_WORKERS") or 0),
        "status_import_fix": True,
    }
print("IAPT_V88_STATUS_IMPORT_FIX installed")
# IAPT_V88_STATUS_IMPORT_FIX_END


# IAPT_V91_V3_PROJECT_SUMMARY_BEGIN
try:
    import json as _iapt_v91_json_mod
    import re as _iapt_v91_re
    from pathlib import Path as _IAPT_V91_Path
    from starlette.responses import Response as _IAPT_V91_Response

    def _iapt_v91_json(v):
        if isinstance(v, dict): return dict(v)
        try:
            obj = _iapt_v91_json_mod.loads(v or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v91_uploaded_apk(row):
        try:
            task_no = str((row or {}).get('task_no') or '').strip()
            if not task_no: return None
            p = APP_STORAGE / 'uploads' / (task_no + '.apk')
            return p if p.is_file() else None
        except Exception:
            return None

    def _iapt_v91_strict_old(row):
        try:
            out_dir = _iapt_v90_out_dir(row) if callable(globals().get('_iapt_v90_out_dir')) else None
            if out_dir and (out_dir / 'old_iapp_report.json').is_file(): return True
        except Exception:
            pass
        # Fast path: ordinary V3 rows do not need APK probing on every list call.
        try:
            opts = _iapt_v91_json((row or {}).get('options_json'))
            ver = str((row or {}).get('decrypt_version') or (row or {}).get('task_version') or opts.get('decrypt_scheme') or '').strip().lower()
            marked = ver in ('ancient','old','legacy','old_iapp','iapp_old') or bool(opts.get('legacy_iapp')) or bool(opts.get('old_iapp'))
            if not marked:
                return False
        except Exception:
            pass
        try:
            apk = _iapt_v91_uploaded_apk(row)
            if apk is not None:
                from .tools.iapp_old_decrypt import detect_old_iapp_apk
                return bool((detect_old_iapp_apk(apk) or {}).get('old_iapp'))
        except Exception:
            pass
        return False

    def _iapt_v91_read_log(row):
        paths = []
        try:
            if row.get('log_path'): paths.append(_IAPT_V91_Path(str(row.get('log_path'))))
        except Exception:
            pass
        try:
            out_dir = _iapt_v90_out_dir(row) if callable(globals().get('_iapt_v90_out_dir')) else None
            if out_dir: paths.append(out_dir / 'task.log')
        except Exception:
            pass
        for p in paths:
            try:
                if p and p.is_file():
                    data = p.read_text(encoding='utf-8', errors='ignore')
                    return data[-512000:]
            except Exception:
                pass
        return ''

    def _iapt_v91_extract_v3_keys(row, log_text):
        opts = _iapt_v91_json((row or {}).get('options_json'))
        hidden = str(opts.get('hidden') or opts.get('sokey') or opts.get('client_sokey') or '').strip()
        fb = str(opts.get('fb') or opts.get('dexkey') or opts.get('client_dexkey') or '').strip()
        try:
            m = _iapt_v91_re.search(r'selected hidden\s*=\s*[^\n]*?([A-Za-z0-9]{10}QQQQQQQQQQWWWWWWWWWWEE)', log_text or '')
            if m: hidden = m.group(1)
        except Exception:
            pass
        try:
            m = _iapt_v91_re.search(r'selected f\.b\(\)\s*=\s*([0-9]{1,12})', log_text or '')
            if m: fb = m.group(1)
        except Exception:
            pass
        return hidden, fb

    def _iapt_v91_project_meta(row):
        meta = {}
        try:
            if callable(globals().get('_iapt_project_meta_for_task')):
                meta = _iapt_project_meta_for_task(dict(row or {})) or {}
        except Exception:
            meta = {}
        return meta if isinstance(meta, dict) else {}

    def _iapt_v91_v3_project_file(row, meta):
        try:
            pf = str((meta or {}).get('project_file') or '').strip()
            if pf: return pf
        except Exception:
            pass
        try:
            out_dir = _iapt_v90_out_dir(row) if callable(globals().get('_iapt_v90_out_dir')) else None
            if out_dir:
                for p in out_dir.rglob('*.project'):
                    if p.is_file():
                        return str(p.relative_to(out_dir)).replace('\\','/')
        except Exception:
            pass
        try:
            pkg = str((meta or {}).get('package_name') or (meta or {}).get('package') or '').strip()
            if pkg: return pkg + '.project'
        except Exception:
            pass
        return ''

    def _iapt_v91_v3_summary(row):
        log_text = _iapt_v91_read_log(row)
        hidden, fb = _iapt_v91_extract_v3_keys(row, log_text)
        meta = _iapt_v91_project_meta(row)
        project_file = _iapt_v91_v3_project_file(row, meta)
        dyn = '已开启' if any(str(_iapt_v91_json((row or {}).get('options_json')).get(k) or '').lower() in ('1','true','yes','on','auto') for k in ('dynamic_restore','v3_dynamic_restore','numeric_restore','restore_fn_names')) else '未开启'
        lines = ['方案：新版 V3']
        if hidden: lines.append('sokey：' + hidden)
        if fb: lines.append('dexkey：' + fb)
        if project_file: lines.append('包名.project：' + project_file)
        elif meta: lines.append('包名.project：已解密，但未写出文件')
        lines.append('动态修复：' + dyn)
        return '\n'.join(lines), meta, {'scheme':'新版 V3','sokey':hidden,'dexkey':fb,'project_file':project_file,'dynamic_restore':dyn}

    def _iapt_v91_scrub_row(row):
        if not isinstance(row, dict): return row
        try:
            if not _iapt_v91_strict_old(row):
                # Correct rows that an older client/server mislabeled as ancient.
                row['decrypt_version'] = 'v3'
                row['task_version'] = 'v3'
                opts = _iapt_v91_json(row.get('options_json'))
                if str(opts.get('decrypt_scheme') or '').strip().lower() == 'ancient' or opts.get('legacy_iapp') or opts.get('old_iapp'):
                    opts['decrypt_scheme']='v3'; opts['decrypt_version']='v3'; opts['task_version']='v3'
                    opts.pop('legacy_iapp', None); opts.pop('old_iapp', None); opts.pop('old_sokey', None)
                    row['options_json'] = _iapt_v91_json_mod.dumps(opts, ensure_ascii=False, separators=(',',':'))
                if str(row.get('status') or '').lower() == 'done' or int(row.get('file_count') or 0) > 0:
                    summary, meta, report = _iapt_v91_v3_summary(row)
                    row['decrypt_summary'] = summary
                    row['decrypt_report'] = report
                    if meta:
                        row['project_meta'] = meta
                        row['project_meta_json'] = _iapt_v91_json_mod.dumps(meta, ensure_ascii=False, separators=(',',':'))
            else:
                row['decrypt_version'] = 'ancient'
                row['task_version'] = 'ancient'
        except Exception as exc:
            try: print('IAPT_V91_SCRUB_ROW_WARN', repr(exc))
            except Exception: pass
        return row

    def _iapt_v91_scrub_payload(obj):
        try:
            if isinstance(obj, dict):
                if isinstance(obj.get('task'), dict):
                    obj['task'] = _iapt_v91_scrub_row(dict(obj.get('task') or {}))
                    for k in ('decrypt_summary','decrypt_report','project_meta','project_meta_json'):
                        if k in obj['task'] and k not in obj: obj[k] = obj['task'][k]
                if isinstance(obj.get('items'), list):
                    obj['items'] = [_iapt_v91_scrub_row(dict(x)) if isinstance(x, dict) else x for x in obj.get('items')]
            elif isinstance(obj, list):
                obj = [_iapt_v91_scrub_row(dict(x)) if isinstance(x, dict) else x for x in obj]
        except Exception as exc:
            try: print('IAPT_V91_SCRUB_PAYLOAD_WARN', repr(exc))
            except Exception: pass
        return obj

    @app.middleware('http')
    async def _iapt_v91_visible_family_and_summary_middleware(request, call_next):
        response = await call_next(request)
        # IAPT_V111_TASK_RESPONSE_GATE
        _iapt_v111_path = str(request.url.path or '').lower()
        if '/admin/' in _iapt_v111_path or ('/tasks' not in _iapt_v111_path and '/task/' not in _iapt_v111_path):
            return response
        ctype = response.headers.get('content-type','')
        if 'application/json' not in ctype.lower():
            return response
        body = b''
        async for chunk in response.body_iterator:
            body += chunk
        try:
            data = _iapt_v91_json_mod.loads(body.decode('utf-8','replace'))
            data = _iapt_v91_scrub_payload(data)
            new_body = _iapt_v91_json_mod.dumps(data, ensure_ascii=False, separators=(',',':')).encode('utf-8')
            headers = dict(response.headers)
            headers.pop('content-length', None)
            return _IAPT_V91_Response(content=new_body, status_code=response.status_code, headers=headers, media_type='application/json')
        except Exception as exc:
            try: print('IAPT_V91_MIDDLEWARE_WARN', repr(exc))
            except Exception: pass
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V91_Response(content=body, status_code=response.status_code, headers=headers, media_type=ctype or 'application/json')

    @app.get('/api/system/iapt-v91', include_in_schema=False)
    def _iapt_v91_status():
        return {
            'ok': True,
            'version': 'V91-strict-old-base64-v3-project-summary',
            'strict_old_detector': 'assets/lib.so base64-aes only',
            'modern_4char_collision_guard': True,
            'v3_project_output': True,
            'v3_decrypt_summary_includes': ['package.project','sokey','dexkey','dynamic_restore'],
            'ancient_project_output': True,
        }
    print('IAPT_V91_V3_PROJECT_SUMMARY installed')
except Exception as _iapt_v91_install_error:
    try: print('IAPT_V91_INSTALL_FAILED', repr(_iapt_v91_install_error))
    except Exception: pass
# IAPT_V91_V3_PROJECT_SUMMARY_END


# IAPT_V92_MINIMAL_UPLOAD_CLIENT_PARAMS_BEGIN
try:
    import json as _iapt_v92_json
    from pathlib import Path as _IAPT_V92_Path
    from starlette.responses import Response as _IAPT_V92_Response

    _IAPT_V92_BASE_SANITIZE = _sanitize_decrypt_options

    def _iapt_v92_bool(v):
        if v is True or v == 1: return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y','auto')

    def _iapt_v92_old_sokey(v):
        import re
        s = str(v or '').strip()
        return s if re.fullmatch(r'[A-Za-z0-9]{4}', s) else ''

    def _sanitize_decrypt_options(options: dict, user_id: int):
        raw = dict(options or {})
        clean, feature_id, feature_scope = _IAPT_V92_BASE_SANITIZE(raw, user_id)
        # V92 diagnostics/client-auto fields that older whitelist layers may drop.
        for k in (
            'ancient_client_auto_params', 'client_ancient_sokey_auto', 'client_ancient_dexkey_auto',
            'client_ancient_signature_auto', 'client_ancient_minimal_upload', 'client_ancient_no_libygsiyu_upload',
            'client_ancient_signature_from_param', 'client_v3_dexkey_auto', 'client_uploaded_so_count',
            'client_bsh_mtime_entries', 'client_arsc_uploaded', 'client_arsc_missing', 'v3_upload_mode',
        ):
            if k in raw: clean[k] = raw[k]
        requested_ancient = (
            str(raw.get('decrypt_scheme') or '').strip().lower() == 'ancient'
            or str(raw.get('decrypt_version') or raw.get('task_version') or '').strip().lower() in ('ancient','old','legacy','old_iapp','iapp_old')
            or _iapt_v92_bool(raw.get('legacy_iapp'))
            or _iapt_v92_bool(raw.get('old_iapp'))
        )
        # A 4-char sokey alone is not a scheme selector. Modern samples can collide.
        if requested_ancient:
            clean['decrypt_scheme'] = 'ancient'
            clean['decrypt_version'] = 'ancient'
            clean['task_version'] = 'ancient'
            clean['legacy_iapp'] = True
            clean['old_iapp'] = True
            clean.pop('hidden', None)
            clean.pop('client_sokey', None)
            sk = ''
            for key in ('old_sokey','sokey'):
                sk = _iapt_v92_old_sokey(raw.get(key))
                if sk: break
            if sk:
                clean['sokey'] = sk
                clean['old_sokey'] = sk
            # Server-side old sokey extraction is disabled for the normal remote decrypt path.
            # Client extracts old sokey from the original APK before it creates the slim upload.
            clean['server_sokey'] = False
            clean['client_old_plaintext_sokey_auto'] = False
            clean['ancient_client_auto_params'] = True
            # dexkey also comes from client unless the user explicitly enabled enumeration.
            explicit_dex_enum = _iapt_v92_bool(raw.get('dexkey_enum')) or _iapt_v92_bool(raw.get('dex_enum'))
            explicit_dex = str(raw.get('fb') or raw.get('dexkey') or raw.get('client_dexkey') or '').strip()
            if explicit_dex:
                clean['fb'] = explicit_dex
                clean['dexkey_auto'] = False
            elif explicit_dex_enum:
                clean['dexkey_enum'] = True
                clean.setdefault('dexkey_enum_start', 3100000)
                clean.setdefault('dexkey_enum_stop', 10000000)
                feature_id = int(globals().get('FEATURE_HIDDEN_ENUM', 2) or 2)
            else:
                clean['client_old_dexkey_parameter_required'] = True
            # V150: Dynamic restore is allowed for old/ancient-iApp when explicitly requested.
            dyn = (
                _iapt_v92_bool(raw.get('ancient_dynamic_restore'))
                or _iapt_v92_bool(raw.get('numeric_restore'))
                or _iapt_v92_bool(raw.get('dynamic_restore'))
                or str(raw.get('restore_fn_names') or '').strip().lower() in ('auto', 'on', 'true', '1')
            )
            if dyn:
                clean['ancient_dynamic_restore'] = True
                clean['v3_dynamic_restore'] = False
                clean['numeric_restore'] = True
                clean['dynamic_restore'] = True
                clean['restore_fn_names'] = 'on'
                clean['require_dex_upload'] = True
                clean['primary_feature_id'] = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
            else:
                clean['ancient_dynamic_restore'] = False
                clean['v3_dynamic_restore'] = False
                clean['numeric_restore'] = False
                clean['dynamic_restore'] = False
                clean['restore_fn_names'] = 'off'
                clean.pop('require_dex_upload', None)
                clean.pop('primary_feature_id', None)
            if not explicit_dex_enum:
                feature_id = int(globals().get('FEATURE_BASIC', 1) or 1)
        else:
            # Force modern V3 when the upload is not explicitly ancient.
            if str(clean.get('decrypt_version') or '').strip().lower() == 'ancient':
                clean['decrypt_version'] = 'v3'
            if str(clean.get('task_version') or '').strip().lower() == 'ancient':
                clean['task_version'] = 'v3'
            if str(clean.get('decrypt_scheme') or '').strip().lower() == 'ancient':
                clean['decrypt_scheme'] = 'v3'
            for k in ('legacy_iapp','old_iapp','old_sokey'):
                clean.pop(k, None)
        return clean, feature_id, feature_scope

    def _iapt_v92_uploaded_apk(row):
        try:
            task_no = str((row or {}).get('task_no') or '').strip()
            if not task_no: return None
            p = APP_STORAGE / 'uploads' / (task_no + '.apk')
            return p if p.is_file() else None
        except Exception:
            return None

    def _iapt_v92_strict_old(row):
        try:
            apk = _iapt_v92_uploaded_apk(row)
            if apk is not None:
                from .tools.iapp_old_decrypt import detect_old_iapp_apk
                return bool((detect_old_iapp_apk(apk) or {}).get('old_iapp'))
        except Exception:
            pass
        try:
            out_dir = _iapt_v90_out_dir(row) if callable(globals().get('_iapt_v90_out_dir')) else None
            if out_dir and (out_dir / 'old_iapp_report.json').is_file():
                return True
        except Exception:
            pass
        return False

    def _iapt_v92_scrub_row(row):
        if not isinstance(row, dict): return row
        try:
            is_old = _iapt_v92_strict_old(row)
            opts = {}
            try:
                opts = _iapt_v92_json.loads(row.get('options_json') or '{}')
                if not isinstance(opts, dict): opts = {}
            except Exception:
                opts = {}
            if is_old:
                row['decrypt_version'] = 'ancient'; row['task_version'] = 'ancient'
            else:
                # Modern output must not be shown as old merely because a 4-char key was submitted.
                row['decrypt_version'] = 'v3' if int(row.get('feature_id') or 1) != 6 else row.get('decrypt_version','v6')
                row['task_version'] = row.get('decrypt_version')
                if str(opts.get('decrypt_scheme') or '').lower() == 'ancient' or opts.get('legacy_iapp') or opts.get('old_iapp'):
                    opts['decrypt_scheme']='v3'; opts['decrypt_version']='v3'; opts['task_version']='v3'
                    for k in ('legacy_iapp','old_iapp','old_sokey','client_old_plaintext_sokey_auto'):
                        opts.pop(k, None)
                    row['options_json'] = _iapt_v92_json.dumps(opts, ensure_ascii=False, separators=(',',':'))
                if callable(globals().get('_iapt_v91_v3_summary')) and (str(row.get('status') or '').lower() == 'done' or int(row.get('file_count') or 0) > 0):
                    summary, meta, report = _iapt_v91_v3_summary(row)
                    row['decrypt_summary'] = summary
                    row['decrypt_report'] = report
                    if meta:
                        row['project_meta'] = meta
                        row['project_meta_json'] = _iapt_v92_json.dumps(meta, ensure_ascii=False, separators=(',',':'))
        except Exception as exc:
            try: print('IAPT_V92_SCRUB_ROW_WARN', repr(exc))
            except Exception: pass
        return row

    def _iapt_v92_scrub_payload(obj):
        try:
            if isinstance(obj, dict):
                if isinstance(obj.get('task'), dict):
                    obj['task'] = _iapt_v92_scrub_row(dict(obj.get('task') or {}))
                    for k in ('decrypt_summary','decrypt_report','project_meta','project_meta_json'):
                        if k in obj['task'] and k not in obj: obj[k] = obj['task'][k]
                if isinstance(obj.get('items'), list):
                    obj['items'] = [_iapt_v92_scrub_row(dict(x)) if isinstance(x, dict) else x for x in obj.get('items')]
            elif isinstance(obj, list):
                obj = [_iapt_v92_scrub_row(dict(x)) if isinstance(x, dict) else x for x in obj]
        except Exception as exc:
            try: print('IAPT_V92_SCRUB_PAYLOAD_WARN', repr(exc))
            except Exception: pass
        return obj

    @app.middleware('http')
    async def _iapt_v92_visible_family_middleware(request, call_next):
        response = await call_next(request)
        # IAPT_V111_TASK_RESPONSE_GATE
        _iapt_v111_path = str(request.url.path or '').lower()
        if '/admin/' in _iapt_v111_path or ('/tasks' not in _iapt_v111_path and '/task/' not in _iapt_v111_path):
            return response
        ctype = response.headers.get('content-type','')
        if 'application/json' not in ctype.lower():
            return response
        body = b''
        async for chunk in response.body_iterator:
            body += chunk
        try:
            data = _iapt_v92_json.loads(body.decode('utf-8','replace'))
            data = _iapt_v92_scrub_payload(data)
            new_body = _iapt_v92_json.dumps(data, ensure_ascii=False, separators=(',',':')).encode('utf-8')
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V92_Response(content=new_body, status_code=response.status_code, headers=headers, media_type='application/json')
        except Exception:
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V92_Response(content=body, status_code=response.status_code, headers=headers, media_type=ctype or 'application/json')

    @app.get('/api/system/iapt-v92', include_in_schema=False)
    def _iapt_v92_status():
        return {
            'ok': True,
            'version': 'V92-minimal-upload-client-old-params',
            'ancient_upload': 'AndroidManifest.xml + resources.arsc + assets/lib.so; DEX only when dynamic_restore is on',
            'ancient_params': 'sokey/dexkey/signature extracted by client and submitted as parameters',
            'ancient_no_libygsiyu_upload': True,
            'v3_upload': 'AndroidManifest.xml + resources.arsc + assets/lib.so + selected libygsiyu.so; sokey enum also uploads bsh/util/lib entries',
            'four_char_key_is_not_scheme_detector': True,
            'v3_project_summary': True,
        }
    print('IAPT_V92_MINIMAL_UPLOAD_CLIENT_PARAMS installed')
except Exception as _iapt_v92_install_error:
    try: print('IAPT_V92_INSTALL_FAILED', repr(_iapt_v92_install_error))
    except Exception: pass
# IAPT_V92_MINIMAL_UPLOAD_CLIENT_PARAMS_END


# IAPT_V93_STRICT_FAMILY_PUBLIC_OUTPUT_BEGIN
try:
    import json as _iapt_v93_json
    import os as _iapt_v93_os
    import re as _iapt_v93_re
    import time as _iapt_v93_time
    from pathlib import Path as _IAPT_V93_Path
    from starlette.responses import Response as _IAPT_V93_Response

    _IAPT_V93_BASE_LIST_TASK_FILES = globals().get('list_task_files')
    _IAPT_V93_BASE_V13_ZIP_ROWS = globals().get('_iapt_v13_zip_rows')

    def _iapt_v93_opts(row):
        try:
            raw = row.get('options_json') if isinstance(row, dict) else None
            obj = _iapt_v93_json.loads(raw or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v93_bool(v):
        if v is True or v == 1:
            return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y','auto')

    def _iapt_v93_upload_path(row):
        try:
            task_no = str((row or {}).get('task_no') or '').strip()
            if not task_no:
                return None
            p = APP_STORAGE / 'uploads' / (task_no + '.apk')
            return p if p.is_file() else None
        except Exception:
            return None

    def _iapt_v93_zip_has_old_base64_assets_lib(apk):
        try:
            if not apk or not _iapt_v93_os.path.isfile(apk):
                return False
            import zipfile, base64
            with zipfile.ZipFile(apk, 'r') as zf:
                entry = None
                has_marker = False
                for n in zf.namelist():
                    low = n.replace('\\','/').lower()
                    if low == 'meta-inf/iapt/decrypt_scheme_ancient':
                        has_marker = True
                    if low == 'assets/lib.so':
                        entry = n
                if not entry:
                    return False
                info = zf.getinfo(entry)
                if info.file_size <= 64 or info.file_size > 256*1024*1024:
                    return False
                raw = zf.read(entry)
                compact = bytearray()
                for b in raw:
                    if b in (9,10,13,32):
                        continue
                    if (65 <= b <= 90) or (97 <= b <= 122) or (48 <= b <= 57) or b in (43,47,61):
                        compact.append(b)
                    else:
                        return False
                if not compact or len(compact) % 4 != 0:
                    return False
                try:
                    decoded = base64.b64decode(bytes(compact), validate=False)
                except Exception:
                    return False
                # The marker is generated by the fixed client.  Older old-iApp full/slim uploads
                # are still accepted when assets/lib.so is a valid old Base64/AES block.
                return len(decoded) >= 16 and (len(decoded) % 16) == 0
        except Exception:
            return False

    def _iapt_v93_is_strict_ancient(row):
        row = dict(row or {})
        opts = _iapt_v93_opts(row)
        requested = (
            str(opts.get('decrypt_scheme') or '').strip().lower() == 'ancient'
            or str(opts.get('decrypt_version') or opts.get('task_version') or '').strip().lower() in ('ancient','old','legacy','old_iapp','iapp_old')
            or _iapt_v93_bool(opts.get('legacy_iapp'))
            or _iapt_v93_bool(opts.get('old_iapp'))
        )
        upload_old = _iapt_v93_zip_has_old_base64_assets_lib(_iapt_v93_upload_path(row))
        # Do not let an old_iapp_report.json from a wrong/previous route turn a modern V3
        # task into ancient.  The upload must be the old Base64 container.
        return bool(requested and upload_old)

    def _iapt_v93_is_anti(row):
        opts = _iapt_v93_opts(row)
        try:
            if int((row or {}).get('feature_id') or 0) == int(globals().get('FEATURE_ANTI_QIUSHUI', 8) or 8):
                return True
        except Exception:
            pass
        for k in ('anti_encrypted_sample','anti_qiushui','hidden_resource_restore','client_anti_probe'):
            if _iapt_v93_bool(opts.get(k)):
                return True
        return False

    def _iapt_v93_public_rows_from_disk(row):
        out_dir = _IAPT_V93_Path(str((row or {}).get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        anti = _iapt_v93_is_anti(row)
        rows = []
        for fp in out_dir.rglob('*'):
            if not fp.is_file():
                continue
            try:
                rel = fp.relative_to(out_dir).as_posix().lstrip('./')
            except Exception:
                continue
            low = rel.lower()
            if not rel or rel.startswith('.') or '/.' in rel:
                continue
            if low.startswith(('_work/','work/','logs/','tmp/','.tmp/','__pycache__/')):
                continue
            if low.endswith(('.log','.tmp','.bak','.pyc')):
                continue
            keep = False
            if rel.startswith('src/'):
                keep = True
            elif anti and rel.startswith('res/'):
                keep = True
            # Never expose raw assets or decrypted image/resource folders for normal V3.
            # Anti-resource restore exposes only the sanitized top-level res/ tree.
            if not keep:
                continue
            try:
                rows.append({'rel_path': rel, 'size_bytes': int(fp.stat().st_size)})
            except Exception:
                pass
        rows.sort(key=lambda x: str(x.get('rel_path') or ''))
        non_project = [r for r in rows if not str(r.get('rel_path') or '').lower().endswith('.project')]
        # A lone .project is metadata leakage.  It must not be shown or charged unless
        # real source/res output exists.
        if not non_project:
            rows = []
        try:
            cnt = len(rows)
            total = sum(int(r.get('size_bytes') or 0) for r in rows)
            task_id = int((row or {}).get('id') or 0)
            if task_id > 0:
                db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (cnt,total,task_id))
                row['file_count'] = cnt; row['total_bytes'] = total
        except Exception:
            pass
        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            row = dict(task_or_id)
        else:
            row = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not row:
            return []
        return _iapt_v93_public_rows_from_disk(row)

    def _iapt_v93_v3_summary(row):
        row = dict(row or {})
        opts = _iapt_v93_opts(row)
        rows = _iapt_v93_public_rows_from_disk(row)
        project = ''
        for r in rows:
            rel = str(r.get('rel_path') or '')
            if rel.lower().endswith('.project'):
                project = rel.split('/')[-1]
                break
        lines = ['方案：新版 V3']
        hidden = str(opts.get('hidden') or opts.get('sokey') or opts.get('client_sokey') or '').strip()
        dexkey = str(opts.get('fb') or opts.get('dexkey') or opts.get('client_dexkey') or '').strip()
        if hidden:
            lines.append('sokey：' + hidden)
        if dexkey:
            lines.append('dexkey：' + dexkey)
        if project:
            lines.append('包名.project：' + project)
        dyn = _iapt_v93_bool(opts.get('v3_dynamic_restore')) or _iapt_v93_bool(opts.get('numeric_restore')) or _iapt_v93_bool(opts.get('dynamic_restore')) or str(opts.get('restore_fn_names') or '').lower() in ('on','true','1','auto')
        if dyn:
            lines.append('动态修复：已开启')
        else:
            lines.append('动态修复：未开启')
        return '\n'.join(lines), {
            'scheme': 'v3', 'family': 'v3', 'sokey': hidden, 'hidden': hidden,
            'dexkey': dexkey, 'fb': dexkey, 'project_file': project,
            'dynamic_restore': {'enabled': bool(dyn)},
        }

    def _iapt_v93_scrub_row(row):
        if not isinstance(row, dict):
            return row
        row = dict(row)
        strict_old = _iapt_v93_is_strict_ancient(row)
        if strict_old:
            row['decrypt_version'] = 'ancient'
            row['task_version'] = 'ancient'
            row['task_family'] = 'ancient'
            row['public_scheme'] = 'ancient'
            return row
        # Modern V3/V6/fix tasks must not carry stale ancient identity or ancient reports.
        fid = int(row.get('feature_id') or 1)
        if str(row.get('decrypt_version') or '').strip().lower() in ('ancient','old','legacy','old_iapp','iapp_old'):
            row['decrypt_version'] = 'v6' if fid == 6 else 'v3'
        if str(row.get('task_version') or '').strip().lower() in ('ancient','old','legacy','old_iapp','iapp_old'):
            row['task_version'] = row.get('decrypt_version') or ('v6' if fid == 6 else 'v3')
        row['task_family'] = 'v6' if fid == 6 else 'v3'
        row['public_scheme'] = row['task_family']
        for k in ('ancient_report','old_iapp_report'):
            row.pop(k, None)
        # Rebuild modern summary so it never contains both 新版 V3 and 远古.
        if fid not in (int(globals().get('FEATURE_SOURCE_RESTORE', 7) or 7), int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)):
            try:
                summary, report = _iapt_v93_v3_summary(row)
                row['decrypt_summary'] = summary
                row['decrypt_report'] = report
            except Exception:
                pass
        return row

    def _iapt_v93_scrub_payload(obj):
        try:
            if isinstance(obj, dict):
                if isinstance(obj.get('task'), dict):
                    obj['task'] = _iapt_v93_scrub_row(obj.get('task'))
                    for k in ('decrypt_summary','decrypt_report','task_family','public_scheme'):
                        if k in obj['task']:
                            obj[k] = obj['task'][k]
                    if obj['task'].get('public_scheme') != 'ancient':
                        obj.pop('ancient_report', None)
                if isinstance(obj.get('items'), list):
                    obj['items'] = [_iapt_v93_scrub_row(x) if isinstance(x, dict) else x for x in obj.get('items')]
            elif isinstance(obj, list):
                obj = [_iapt_v93_scrub_row(x) if isinstance(x, dict) else x for x in obj]
        except Exception as exc:
            try: print('IAPT_V93_SCRUB_PAYLOAD_WARN', repr(exc))
            except Exception: pass
        return obj

    @app.middleware('http')
    async def _iapt_v93_visible_family_middleware(request, call_next):
        response = await call_next(request)
        # IAPT_V111_TASK_RESPONSE_GATE
        _iapt_v111_path = str(request.url.path or '').lower()
        if '/admin/' in _iapt_v111_path or ('/tasks' not in _iapt_v111_path and '/task/' not in _iapt_v111_path):
            return response
        ctype = response.headers.get('content-type','')
        if 'application/json' not in ctype.lower():
            return response
        body = b''
        async for chunk in response.body_iterator:
            body += chunk
        try:
            data = _iapt_v93_json.loads(body.decode('utf-8','replace'))
            data = _iapt_v93_scrub_payload(data)
            new_body = _iapt_v93_json.dumps(data, ensure_ascii=False, separators=(',',':')).encode('utf-8')
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V93_Response(content=new_body, status_code=response.status_code, headers=headers, media_type='application/json')
        except Exception:
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V93_Response(content=body, status_code=response.status_code, headers=headers, media_type=ctype or 'application/json')

    def _iapt_v13_zip_rows(task: dict, rows: list[dict], dest: _IAPT_V93_Path) -> tuple[int, int]:
        out_dir = _IAPT_V93_Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            raise HTTPException(404, '任务输出目录不存在或已被清理')
        filtered = _iapt_v93_public_rows_from_disk(task)
        allowed = set(str(r.get('rel_path') or '') for r in filtered)
        rows = [r for r in (rows or []) if str(r.get('rel_path') or '') in allowed]
        tmp = dest.with_suffix(dest.suffix + '.tmp')
        try: tmp.unlink()
        except FileNotFoundError: pass
        count = 0; total = 0; missing = []
        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True) as z:
            for row in rows:
                rel = str(row.get('rel_path') or '').replace('\\','/').lstrip('./')
                if not rel:
                    continue
                fp = out_dir / rel
                try:
                    resolved = fp.resolve(); resolved.relative_to(out_dir.resolve())
                except Exception:
                    missing.append(rel); continue
                if not resolved.is_file():
                    missing.append(rel); continue
                # V93: preserve src/ and res/ roots.  Do not flatten src/ into ZIP root.
                z.write(resolved, rel)
                count += 1; total += int(resolved.stat().st_size)
        if missing:
            try: tmp.unlink()
            except Exception: pass
            raise HTTPException(409, '下载清单与磁盘文件不一致，请刷新任务后重试：' + ', '.join(missing[:8]))
        if count <= 0:
            try: tmp.unlink()
            except Exception: pass
            raise HTTPException(404, '任务没有可下载的 src/res 文件')
        try:
            with zipfile.ZipFile(tmp, 'r') as check:
                bad = check.testzip(); names = [x.filename for x in check.infolist() if not x.is_dir()]
                if bad is not None or len(names) != count:
                    raise RuntimeError('ZIP 完整性校验失败')
        except Exception as exc:
            try: tmp.unlink()
            except Exception: pass
            raise HTTPException(500, '生成下载 ZIP 失败：' + str(exc))
        dest.parent.mkdir(parents=True, exist_ok=True)
        _iapt_v93_os.replace(tmp, dest)
        return count, total

    @app.get('/api/system/iapt-v93', include_in_schema=False)
    def _iapt_v93_status():
        return {
            'ok': True,
            'version': 'V93-strict-family-single-summary-public-src-res',
            'modern_not_ancient': 'ancient requires explicit old options AND uploaded assets/lib.so old Base64/AES container',
            'single_scheme_summary': True,
            'v3_summary_includes': ['package.project when physical src/*.project exists', 'sokey', 'dexkey', 'dynamic_restore'],
            'public_output': 'normal tasks expose src/** only; anti encrypted samples expose src/** and res/**; assets/** and lone .project are hidden',
            'download_zip_roots': 'preserve src/ and res/ roots; no src flattening',
        }
    print('IAPT_V93_STRICT_FAMILY_PUBLIC_OUTPUT installed')
except Exception as _iapt_v93_install_error:
    try: print('IAPT_V93_INSTALL_FAILED', repr(_iapt_v93_install_error))
    except Exception: pass
# IAPT_V93_STRICT_FAMILY_PUBLIC_OUTPUT_END

# IAPT_V94_PROJECT_IS_SOURCE_OUTPUT_BEGIN
# V94: .project is part of the source output.  If a decryptor emitted source at
# the task root (legacy behavior), expose it under src/ instead of hiding it or
# returning an empty ZIP.  Modern V3 tasks must also be scrubbed away from any
# stale ancient identity.
try:
    import json as _iapt_v94_json
    import os as _iapt_v94_os
    import re as _iapt_v94_re
    from pathlib import Path as _IAPT_V94_Path
    from starlette.responses import Response as _IAPT_V94_Response

    _IAPT_V94_SOURCE_EXTS = {
        '.project', '.iyu', '.myu', '.ijava', '.mjava', '.java', '.ilua', '.mlua',
        '.lua', '.ijs', '.mjs', '.js', '.css', '.html', '.htm', '.xml', '.json',
        '.txt', '.ini', '.properties'
    }
    _IAPT_V94_IMAGE_EXTS = {'.png','.jpg','.jpeg','.webp','.gif','.bmp','.ico','.9.png','.svg'}
    _IAPT_V94_EXCLUDED_ROOTS = {
        'assets','lib','meta-inf','kotlin','okhttp3','okio','android','androidx',
        'res','resources.arsc','androidmanifest.xml','classes.dex','classes2.dex',
        '.tmp','tmp','logs','__pycache__'
    }

    def _iapt_v94_opts(row):
        try:
            raw = row.get('options_json') if isinstance(row, dict) else None
            obj = _iapt_v94_json.loads(raw or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v94_bool(v):
        if v is True or v == 1:
            return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y','auto')

    def _iapt_v94_upload_path(row):
        try:
            task_no = str((row or {}).get('task_no') or '').strip()
            if not task_no:
                return None
            p = APP_STORAGE / 'uploads' / (task_no + '.apk')
            return p if p.is_file() else None
        except Exception:
            return None

    def _iapt_v94_zip_has_marker(apk):
        try:
            import zipfile
            if not apk or not _iapt_v94_os.path.isfile(apk):
                return False
            with zipfile.ZipFile(apk, 'r') as zf:
                return any(n.replace('\\','/').lower() == 'meta-inf/iapt/decrypt_scheme_ancient' for n in zf.namelist())
        except Exception:
            return False

    def _iapt_v94_zip_old_probe(apk):
        try:
            if not apk or not _iapt_v94_os.path.isfile(apk):
                return False
            from app.tools.iapp_old_decrypt import detect_old_iapp_apk
            return bool((detect_old_iapp_apk(apk) or {}).get('old_iapp'))
        except Exception:
            try:
                from .tools.iapp_old_decrypt import detect_old_iapp_apk
                return bool((detect_old_iapp_apk(apk) or {}).get('old_iapp'))
            except Exception:
                return False

    def _iapt_v94_is_strict_ancient(row):
        row = dict(row or {})
        opts = _iapt_v94_opts(row)
        requested = (
            str(opts.get('decrypt_scheme') or '').strip().lower() == 'ancient'
            or str(opts.get('decrypt_version') or opts.get('task_version') or '').strip().lower() in ('ancient','old','legacy','old_iapp','iapp_old')
            or _iapt_v94_bool(opts.get('legacy_iapp'))
            or _iapt_v94_bool(opts.get('old_iapp'))
        )
        apk = _iapt_v94_upload_path(row)
        # Marker comes from the fixed minimal old-client upload.  The probe keeps
        # compatibility with original old samples.  Both still require an explicit
        # old request before the public API exposes the task as ancient.
        return bool(requested and (_iapt_v94_zip_has_marker(apk) or _iapt_v94_zip_old_probe(apk)))

    def _iapt_v94_is_anti(row):
        opts = _iapt_v94_opts(row)
        try:
            if int((row or {}).get('feature_id') or 0) == int(globals().get('FEATURE_ANTI_QIUSHUI', 8) or 8):
                return True
        except Exception:
            pass
        for k in ('anti_encrypted_sample','anti_qiushui','hidden_resource_restore','client_anti_probe','anti_sample'):
            if _iapt_v94_bool(opts.get(k)):
                return True
        return False

    def _iapt_v94_is_probable_source_rel(rel):
        low = rel.replace('\\','/').lower().lstrip('./')
        if not low or low.startswith(('.tmp/','tmp/','logs/')):
            return False
        first = low.split('/', 1)[0]
        if first in _IAPT_V94_EXCLUDED_ROOTS:
            return False
        name = low.rsplit('/', 1)[-1]
        # Explicitly reject images/resources unless anti mode maps assets/res to res/.
        if any(name.endswith(x) for x in _IAPT_V94_IMAGE_EXTS):
            return False
        ext = _IAPT_V94_Path(name).suffix.lower()
        if ext in _IAPT_V94_SOURCE_EXTS:
            return True
        # Java-style package directories at the root often contain decompiled iApp
        # source.  Keep textual files underneath them, but do not keep arbitrary
        # binary resources.
        if '/' in low and _iapt_v94_re.fullmatch(r'[a-zA-Z_$][\w$]*', first):
            return ext in _IAPT_V94_SOURCE_EXTS or ext == ''
        return False

    def _iapt_v94_public_rows_from_disk(row):
        out_dir = _IAPT_V94_Path(str((row or {}).get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        anti = _iapt_v94_is_anti(row)
        rows = []
        seen = set()
        for fp in out_dir.rglob('*'):
            if not fp.is_file():
                continue
            try:
                rel0 = fp.relative_to(out_dir).as_posix().lstrip('./')
            except Exception:
                continue
            low = rel0.lower()
            if '/.tmp/' in '/' + low or low.startswith('.tmp/') or low.endswith(('.log','.tmp','.bak','.pyc')):
                continue
            public_rel = None
            # Canonical source output.
            if low.startswith('src/'):
                public_rel = rel0
            # Legacy/root source output: map into src/ instead of leaking root files
            # or producing an empty ZIP.
            elif _iapt_v94_is_probable_source_rel(rel0):
                public_rel = 'src/' + rel0
            # Anti encrypted-resource mode: expose only restored resource tree.
            elif anti and low.startswith('res/'):
                public_rel = rel0
            elif anti and low.startswith('assets/res/'):
                public_rel = 'res/' + rel0[len('assets/res/'):]
            if not public_rel:
                continue
            public_rel = public_rel.replace('\\','/').lstrip('./')
            if not public_rel or public_rel in seen:
                continue
            seen.add(public_rel)
            try:
                rows.append({'rel_path': public_rel, 'source_rel': rel0, 'size_bytes': int(fp.stat().st_size)})
            except Exception:
                pass
        rows.sort(key=lambda x: str(x.get('rel_path') or ''))
        # V94: do NOT hide a lone .project.  .project is source output; if it
        # exists, the public source root exists.
        try:
            cnt = len(rows)
            total = sum(int(r.get('size_bytes') or 0) for r in rows)
            task_id = int((row or {}).get('id') or 0)
            if task_id > 0:
                db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (cnt,total,task_id))
                row['file_count'] = cnt; row['total_bytes'] = total
        except Exception:
            pass
        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            row = dict(task_or_id)
        else:
            row = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not row:
            return []
        return _iapt_v94_public_rows_from_disk(row)

    def _iapt_v94_v3_summary(row):
        row = dict(row or {})
        opts = _iapt_v94_opts(row)
        rows = _iapt_v94_public_rows_from_disk(row)
        project = ''
        for r in rows:
            rel = str(r.get('rel_path') or '')
            if rel.lower().endswith('.project'):
                project = rel.split('/')[-1]
                break
        lines = ['方案：新版 V3']
        hidden = str(opts.get('hidden') or opts.get('sokey') or opts.get('client_sokey') or '').strip()
        dexkey = str(opts.get('fb') or opts.get('dexkey') or opts.get('client_dexkey') or '').strip()
        if hidden:
            lines.append('sokey：' + hidden)
        if dexkey:
            lines.append('dexkey：' + dexkey)
        if project:
            lines.append('包名.project：' + project)
        dyn = _iapt_v94_bool(opts.get('v3_dynamic_restore')) or _iapt_v94_bool(opts.get('numeric_restore')) or _iapt_v94_bool(opts.get('dynamic_restore')) or str(opts.get('restore_fn_names') or '').lower() in ('on','true','1','auto')
        lines.append('动态修复：' + ('已开启' if dyn else '未开启'))
        return '\n'.join(lines), {
            'scheme': 'v3', 'family': 'v3', 'sokey': hidden, 'hidden': hidden,
            'dexkey': dexkey, 'fb': dexkey, 'project_file': project,
            'dynamic_restore': {'enabled': bool(dyn)},
        }

    def _iapt_v94_scrub_row(row):
        if not isinstance(row, dict):
            return row
        row = dict(row)
        strict_old = _iapt_v94_is_strict_ancient(row)
        if strict_old:
            row['decrypt_version'] = 'ancient'; row['task_version'] = 'ancient'
            row['task_family'] = 'ancient'; row['public_scheme'] = 'ancient'
            return row
        fid = int(row.get('feature_id') or 1)
        # For non-old tasks, never expose ancient identity or ancient summary.
        row['decrypt_version'] = 'v6' if fid == 6 else 'v3'
        row['task_version'] = row['decrypt_version']
        row['task_family'] = row['decrypt_version']
        row['public_scheme'] = row['decrypt_version']
        for k in ('ancient_report','old_iapp_report'):
            row.pop(k, None)
        try:
            summary, report = _iapt_v94_v3_summary(row)
            row['decrypt_summary'] = summary
            row['decrypt_report'] = report
        except Exception:
            pass
        return row

    def _iapt_v94_scrub_payload(obj):
        try:
            if isinstance(obj, dict):
                if isinstance(obj.get('task'), dict):
                    obj['task'] = _iapt_v94_scrub_row(obj.get('task'))
                    for k in ('decrypt_summary','decrypt_report','task_family','public_scheme'):
                        if k in obj['task']:
                            obj[k] = obj['task'][k]
                    if obj['task'].get('public_scheme') != 'ancient':
                        obj.pop('ancient_report', None)
                        obj.pop('old_iapp_report', None)
                if isinstance(obj.get('items'), list):
                    obj['items'] = [_iapt_v94_scrub_row(x) if isinstance(x, dict) else x for x in obj.get('items')]
            elif isinstance(obj, list):
                obj = [_iapt_v94_scrub_row(x) if isinstance(x, dict) else x for x in obj]
        except Exception as exc:
            try: print('IAPT_V94_SCRUB_PAYLOAD_WARN', repr(exc))
            except Exception: pass
        return obj

    @app.middleware('http')
    async def _iapt_v94_visible_family_middleware(request, call_next):
        response = await call_next(request)
        # IAPT_V111_TASK_RESPONSE_GATE
        _iapt_v111_path = str(request.url.path or '').lower()
        if '/admin/' in _iapt_v111_path or ('/tasks' not in _iapt_v111_path and '/task/' not in _iapt_v111_path):
            return response
        ctype = response.headers.get('content-type','')
        if 'application/json' not in ctype.lower():
            return response
        body = b''
        async for chunk in response.body_iterator:
            body += chunk
        try:
            data = _iapt_v94_json.loads(body.decode('utf-8','replace'))
            data = _iapt_v94_scrub_payload(data)
            new_body = _iapt_v94_json.dumps(data, ensure_ascii=False, separators=(',',':')).encode('utf-8')
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V94_Response(content=new_body, status_code=response.status_code, headers=headers, media_type='application/json')
        except Exception:
            headers = dict(response.headers); headers.pop('content-length', None)
            return _IAPT_V94_Response(content=body, status_code=response.status_code, headers=headers, media_type=ctype or 'application/json')

    def _iapt_v13_zip_rows(task: dict, rows: list[dict], dest: _IAPT_V94_Path) -> tuple[int, int]:
        out_dir = _IAPT_V94_Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            raise HTTPException(404, '任务输出目录不存在或已被清理')
        filtered = _iapt_v94_public_rows_from_disk(task)
        rowmap = {str(r.get('rel_path') or ''): r for r in filtered}
        wanted = []
        for r in (rows or filtered or []):
            rel = str(r.get('rel_path') or '').replace('\\','/').lstrip('./')
            if rel in rowmap:
                wanted.append(rowmap[rel])
        if not wanted:
            wanted = filtered
        tmp = dest.with_suffix(dest.suffix + '.tmp')
        try: tmp.unlink()
        except FileNotFoundError: pass
        count = 0; total = 0; missing = []
        with zipfile.ZipFile(tmp, 'w', compression=zipfile.ZIP_DEFLATED, allowZip64=True) as z:
            for row in wanted:
                rel = str(row.get('rel_path') or '').replace('\\','/').lstrip('./')
                source_rel = str(row.get('source_rel') or rel).replace('\\','/').lstrip('./')
                if not rel:
                    continue
                fp = out_dir / source_rel
                try:
                    resolved = fp.resolve(); resolved.relative_to(out_dir.resolve())
                except Exception:
                    missing.append(source_rel); continue
                if not resolved.is_file():
                    missing.append(source_rel); continue
                z.write(resolved, rel)
                count += 1; total += int(resolved.stat().st_size)
        if missing:
            try: tmp.unlink()
            except Exception: pass
            raise HTTPException(409, '下载清单与磁盘文件不一致，请刷新任务后重试：' + ', '.join(missing[:8]))
        if count <= 0:
            try: tmp.unlink()
            except Exception: pass
            raise HTTPException(404, '任务没有可下载的 src/res 文件')
        try:
            with zipfile.ZipFile(tmp, 'r') as check:
                bad = check.testzip(); names = [x.filename for x in check.infolist() if not x.is_dir()]
                if bad is not None or len(names) != count:
                    raise RuntimeError('ZIP 完整性校验失败')
        except Exception as exc:
            try: tmp.unlink()
            except Exception: pass
            raise HTTPException(500, '生成下载 ZIP 失败：' + str(exc))
        dest.parent.mkdir(parents=True, exist_ok=True)
        _iapt_v94_os.replace(tmp, dest)
        return count, total

    @app.get('/api/system/iapt-v94', include_in_schema=False)
    def _iapt_v94_status():
        return {
            'ok': True,
            'version': 'V94-project-is-src-output-root-source-normalizer',
            'project_policy': '.project is treated as src output, never hidden as lone metadata',
            'legacy_root_source_mapping': 'root source files/directories are exposed under src/',
            'normal_output': 'src/** only; anti encrypted samples additionally expose res/**',
            'modern_not_ancient': 'non-old rows are scrubbed to v3/v6 and cannot show ancient summary',
        }
    print('IAPT_V94_PROJECT_IS_SOURCE_OUTPUT installed')
except Exception as _iapt_v94_install_error:
    try: print('IAPT_V94_INSTALL_FAILED', repr(_iapt_v94_install_error))
    except Exception: pass
# IAPT_V94_PROJECT_IS_SOURCE_OUTPUT_END


# IAPT_V96_RESTORE_CLIENT_DOWNLOAD_TIMEOUT_BEGIN
# V96 is intentionally small: keep the V94/V93 feature set, but remove the two regressions:
# 1) V95 accidentally shipped an older/smaller client source; the ZIP now carries the full V94 client again.
# 2) V94/V95 could expose stale internal qiu_shui_resource_export.json rows and could scan disk for every list item.
try:
    import json as _iapt_v96_json
    import os as _iapt_v96_os
    from starlette.responses import Response as _IAPT_V96_Response

    _IAPT_V96_INTERNAL_MARKERS = ('iapt_internal/', '.iapt_internal/', '__iapt_internal__/', 'qiu_shui_resource_export.json', 'qiushui_resource_export.json')

    try:
        _IAPT_V94_EXCLUDED_ROOTS.update({'iapt_internal', '.iapt_internal', '__iapt_internal__'})
    except Exception:
        pass

    def _iapt_v96_is_internal_rel(rel):
        low = str(rel or '').replace('\\','/').lower().lstrip('./')
        if not low:
            return True
        if low.startswith(_IAPT_V96_INTERNAL_MARKERS):
            return True
        return any(m in low for m in _IAPT_V96_INTERNAL_MARKERS)

    _iapt_v96_prev_public_rows = globals().get('_iapt_v94_public_rows_from_disk')
    def _iapt_v94_public_rows_from_disk(row):
        rows = []
        try:
            base_rows = _iapt_v96_prev_public_rows(row) if callable(_iapt_v96_prev_public_rows) else []
        except Exception:
            base_rows = []
        seen = set()
        for r in base_rows or []:
            if not isinstance(r, dict):
                continue
            rel = str(r.get('rel_path') or '').replace('\\','/').lstrip('./')
            src = str(r.get('source_rel') or rel).replace('\\','/').lstrip('./')
            if _iapt_v96_is_internal_rel(rel) or _iapt_v96_is_internal_rel(src):
                continue
            if rel in seen:
                continue
            item = dict(r); item['rel_path'] = rel; item['source_rel'] = src
            rows.append(item); seen.add(rel)
        rows.sort(key=lambda x: str(x.get('rel_path') or ''))
        # Rewrite public manifests so stale iapt_internal rows do not trigger HTTP 409 again.
        try:
            from pathlib import Path as _P
            out_dir = _P(str((row or {}).get('out_dir') or ''))
            if out_dir.is_dir():
                out_dir.joinpath('output_files.json').write_text(_iapt_v96_json.dumps({'version':96,'files':rows}, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
                tmpd = out_dir / '.tmp'; tmpd.mkdir(exist_ok=True)
                tmpd.joinpath('file_index.json').write_text(_iapt_v96_json.dumps(rows, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
        except Exception:
            pass
        try:
            task_id = int((row or {}).get('id') or 0)
            if task_id > 0:
                cnt = len(rows); total = sum(int(x.get('size_bytes') or 0) for x in rows)
                db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (cnt,total,task_id))
                row['file_count'] = cnt; row['total_bytes'] = total
        except Exception:
            pass
        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            row = dict(task_or_id)
        else:
            row = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not row:
            return []
        return _iapt_v94_public_rows_from_disk(row)

    def _iapt_v96_light_list_row(row):
        if not isinstance(row, dict):
            return row
        row = dict(row)
        try:
            strict_old = bool(globals().get('_iapt_v94_is_strict_ancient', lambda x: False)(row))
        except Exception:
            strict_old = False
        if strict_old:
            ver = 'ancient'
        else:
            ver = 'v6' if int(row.get('feature_id') or 1) == 6 else 'v3'
            row.pop('ancient_report', None); row.pop('old_iapp_report', None)
        row['decrypt_version'] = row['task_version'] = row['task_family'] = row['public_scheme'] = ver
        return row

    def _iapt_v94_scrub_payload(obj):
        # Detail response keeps the full V94 decrypt_summary behavior.
        # List response is lightweight: no per-item disk scan, preventing 504.
        try:
            if isinstance(obj, dict):
                if isinstance(obj.get('task'), dict):
                    obj['task'] = globals().get('_iapt_v94_scrub_row', _iapt_v96_light_list_row)(obj.get('task'))
                    for k in ('decrypt_summary','decrypt_report','task_family','public_scheme'):
                        if k in obj['task']:
                            obj[k] = obj['task'][k]
                if isinstance(obj.get('item'), dict):
                    obj['item'] = globals().get('_iapt_v94_scrub_row', _iapt_v96_light_list_row)(obj.get('item'))
                    for k in ('decrypt_summary','decrypt_report','task_family','public_scheme'):
                        if k in obj['item']:
                            obj[k] = obj['item'][k]
                if isinstance(obj.get('data'), dict) and isinstance(obj['data'].get('task'), dict):
                    obj['data']['task'] = globals().get('_iapt_v94_scrub_row', _iapt_v96_light_list_row)(obj['data']['task'])
                if isinstance(obj.get('items'), list):
                    obj['items'] = [_iapt_v96_light_list_row(x) if isinstance(x, dict) else x for x in obj.get('items')]
            elif isinstance(obj, list):
                obj = [_iapt_v96_light_list_row(x) if isinstance(x, dict) else x for x in obj]
        except Exception as exc:
            try: print('IAPT_V96_SCRUB_PAYLOAD_WARN', repr(exc))
            except Exception: pass
        return obj

    @app.get('/api/system/iapt-v96', include_in_schema=False)
    def _iapt_v96_status():
        return {
            'ok': True,
            'version': 'V96-restore-full-client-download-manifest-timeout-fix',
            'client_source_size_expected': '536164 bytes',
            'v95_client_regression_fixed': True,
            'decrypt_summary_preserved': 'detail responses use V94/V93 summary logic',
            'task_list_disk_scan': 'disabled; list rows are lightweight',
            'download_409_fix': 'iapt_internal/qiu_shui_resource_export.json excluded and stale manifests rewritten',
            'output_roots': 'normal src/**; anti-encrypted src/** + res/**',
        }
    print('IAPT_V96_RESTORE_CLIENT_DOWNLOAD_TIMEOUT installed')
except Exception as _iapt_v96_install_error:
    try: print('IAPT_V96_INSTALL_FAILED', repr(_iapt_v96_install_error))
    except Exception: pass
# IAPT_V96_RESTORE_CLIENT_DOWNLOAD_TIMEOUT_END


# IAPT_V97_REFERENCED_RESOURCE_FILTER_BEGIN
# V97: Do not expose APK image/static resource dumps. Public downloads expose src/**.
# If the anti-encrypted-sample option is enabled, expose only non-image assets/res resources that are referenced by source files.
try:
    import json as _iapt_v97_json
    import os as _iapt_v97_os
    import re as _iapt_v97_re
    from pathlib import Path as _IAPT_V97_Path

    _iapt_v97_prev_public_rows = globals().get('_iapt_v94_public_rows_from_disk')

    _IAPT_V97_IMAGE_MEDIA_EXTS = {
        '.png','.jpg','.jpeg','.webp','.gif','.bmp','.ico','.avif','.heic','.heif',
        '.mp3','.wav','.ogg','.m4a','.aac','.flac','.mid','.midi','.mp4','.mkv','.avi','.mov','.3gp','.webm',
        '.ttf','.otf','.woff','.woff2',
        '.so','.dex','.arsc','.apk','.aab','.zip','.7z','.rar','.tar','.gz','.bz2','.xz',
    }
    _IAPT_V97_ALWAYS_TEXT_EXTS = {
        '.iyu','.ijava','.java','.kt','.smali','.project','.xml','.json','.txt','.ini','.cfg','.conf',
        '.properties','.html','.htm','.js','.css','.lua','.py','.csv','.xlt','.md','.yml','.yaml',
    }
    _IAPT_V97_SRC_ROOT_FILES = {'iaptmain.java','mian.iyu'}
    _IAPT_V97_SRC_ROOT_DIRS = {'src','com','de'}
    _IAPT_V97_APK_RES_DIR_PREFIXES = (
        'anim','animator','color','drawable','font','interpolator','layout','menu','mipmap','navigation','raw','transition','values','xml'
    )

    def _iapt_v97_norm_rel(x):
        return str(x or '').replace('\\','/').lstrip('./')

    def _iapt_v97_ext(rel):
        name = _iapt_v97_norm_rel(rel).rsplit('/', 1)[-1].lower()
        if '.' not in name:
            return ''
        return '.' + name.rsplit('.', 1)[-1]

    def _iapt_v97_is_src_rel(rel):
        rel = _iapt_v97_norm_rel(rel)
        low = rel.lower()
        if not rel:
            return False
        if low.startswith('src/'):
            return True
        head = low.split('/', 1)[0]
        if head in _IAPT_V97_SRC_ROOT_DIRS and low != 'res':
            return True
        if low in _IAPT_V97_SRC_ROOT_FILES or low.endswith('.project'):
            return True
        return False

    def _iapt_v97_public_src_rel(rel):
        rel = _iapt_v97_norm_rel(rel)
        low = rel.lower()
        if low.startswith('src/'):
            return rel
        if _iapt_v97_is_src_rel(rel):
            return 'src/' + rel
        return rel

    def _iapt_v97_resource_rel(rel):
        rel = _iapt_v97_norm_rel(rel)
        low = rel.lower()
        marker = 'assets/res/'
        if marker in low:
            idx = low.index(marker) + len(marker)
            tail = rel[idx:]
            return 'res/' + tail.lstrip('/')
        if low.startswith('res/'):
            return rel
        return ''

    def _iapt_v97_is_plain_apk_res(rel, source_rel=''):
        rel = _iapt_v97_norm_rel(rel).lower()
        src = _iapt_v97_norm_rel(source_rel).lower()
        if src.startswith('assets/res/') or '/assets/res/' in src:
            return False
        if rel.startswith('assets/res/') or '/assets/res/' in rel:
            return False
        if rel.startswith('res/'):
            parts = rel.split('/')
            if len(parts) >= 2:
                d = parts[1]
                if any(d == p or d.startswith(p + '-') for p in _IAPT_V97_APK_RES_DIR_PREFIXES):
                    return True
            return True
        if src.startswith('res/'):
            parts = src.split('/')
            if len(parts) >= 2:
                d = parts[1]
                if any(d == p or d.startswith(p + '-') for p in _IAPT_V97_APK_RES_DIR_PREFIXES):
                    return True
            return True
        return False

    def _iapt_v97_is_binary_resource(rel, row=None):
        low = _iapt_v97_norm_rel(rel).lower()
        ext = _iapt_v97_ext(low)
        if ext in _IAPT_V97_IMAGE_MEDIA_EXTS:
            return True
        if ext in _IAPT_V97_ALWAYS_TEXT_EXTS:
            return False
        try:
            size = int((row or {}).get('size_bytes') or (row or {}).get('size') or 0)
        except Exception:
            size = 0
        if ext == '':
            return size > 2 * 1024 * 1024
        return size > 512 * 1024

    def _iapt_v97_row_abs_path(row, out_dir):
        if not isinstance(row, dict):
            return None
        for key in ('abs_path','path','full_path','file_path'):
            v = row.get(key)
            if v:
                try:
                    pp = _IAPT_V97_Path(str(v))
                    if pp.exists():
                        return pp
                except Exception:
                    pass
        for key in ('source_rel','rel_path'):
            v = row.get(key)
            if v:
                try:
                    pp = out_dir / _iapt_v97_norm_rel(v)
                    if pp.exists():
                        return pp
                except Exception:
                    pass
        return None

    def _iapt_v97_safe_text_from_file(path, limit=262144):
        try:
            data = _IAPT_V97_Path(path).read_bytes()[:limit]
        except Exception:
            return ''
        if b'\x00' in data[:4096]:
            return ''
        try:
            return data.decode('utf-8', 'ignore')
        except Exception:
            return ''

    def _iapt_v97_source_blob(rows, out_dir):
        chunks = []
        seen = set()
        for r in rows or []:
            if not isinstance(r, dict):
                continue
            rel = _iapt_v97_norm_rel(r.get('rel_path') or '')
            src = _iapt_v97_norm_rel(r.get('source_rel') or rel)
            if not (_iapt_v97_is_src_rel(rel) or _iapt_v97_is_src_rel(src)):
                continue
            pp = _iapt_v97_row_abs_path(r, out_dir)
            if pp and pp not in seen:
                seen.add(pp)
                txt = _iapt_v97_safe_text_from_file(pp)
                if txt:
                    chunks.append(txt)
        try:
            for root in ('src','com','de'):
                base = out_dir / root
                if not base.exists():
                    continue
                count = 0
                for pp in base.rglob('*'):
                    if count >= 800:
                        break
                    if pp.is_file() and pp not in seen and pp.stat().st_size <= 262144:
                        count += 1
                        seen.add(pp)
                        txt = _iapt_v97_safe_text_from_file(pp)
                        if txt:
                            chunks.append(txt)
        except Exception:
            pass
        blob = '\n'.join(chunks)
        return blob[:2 * 1024 * 1024]

    def _iapt_v97_resource_referenced(logical_rel, source_blob):
        if not source_blob:
            return False
        rel = _iapt_v97_norm_rel(logical_rel)
        if not rel.startswith('res/'):
            return False
        tail = rel[4:]
        base = tail.rsplit('/', 1)[-1]
        stem = base.rsplit('.', 1)[0]
        candidates = [rel, tail, 'assets/' + rel, 'assets/res/' + tail, base]
        if stem and len(stem) >= 4:
            candidates.append(stem)
        for c in candidates:
            if c and c in source_blob:
                return True
        return False

    def _iapt_v97_parse_options(row):
        vals = []
        if isinstance(row, dict):
            for k, v in row.items():
                lk = str(k).lower()
                if any(t in lk for t in ('option','param','flag','anti','qiu','protect','restore','decrypt')):
                    vals.append(v)
        text = ' '.join(str(v) for v in vals if v is not None).lower()
        try:
            for v in vals:
                if isinstance(v, str) and v.strip().startswith(('{','[')):
                    obj = _iapt_v97_json.loads(v)
                    text += ' ' + _iapt_v97_json.dumps(obj, ensure_ascii=False).lower()
        except Exception:
            pass
        return text

    def _iapt_v97_anti_enabled(row):
        text = _iapt_v97_parse_options(row)
        positives = ('anti_encrypt', 'anti-encrypt', 'anti_encrypted', 'anti-sample', 'fanjiami', 'fan_jiami', '反加密', 'qiu_shui', 'qiushui')
        if any(x in text for x in positives):
            if any(x in text for x in ('anti_encrypt":false', 'anti_encrypt=false', 'fanjiami":false', '反加密":false', 'qiu_shui":false')):
                return False
            return True
        return False

    def _iapt_v97_filter_public_rows(row, base_rows):
        try:
            out_dir = _IAPT_V97_Path(str((row or {}).get('out_dir') or ''))
        except Exception:
            out_dir = _IAPT_V97_Path('.')
        anti = _iapt_v97_anti_enabled(row)
        source_blob = _iapt_v97_source_blob(base_rows, out_dir) if anti else ''
        rows = []
        seen = set()
        for r in base_rows or []:
            if not isinstance(r, dict):
                continue
            orig_rel = _iapt_v97_norm_rel(r.get('rel_path') or '')
            orig_src = _iapt_v97_norm_rel(r.get('source_rel') or orig_rel)
            low = orig_rel.lower()
            if not orig_rel:
                continue
            if _iapt_v97_is_src_rel(orig_rel) or _iapt_v97_is_src_rel(orig_src):
                rel = _iapt_v97_public_src_rel(orig_rel)
                item = dict(r); item['rel_path'] = rel; item['source_rel'] = orig_src
                if rel not in seen:
                    rows.append(item); seen.add(rel)
                continue
            if low.startswith('res/') or low.startswith('assets/res/') or '/assets/res/' in low or orig_src.lower().startswith(('res/','assets/res/')) or '/assets/res/' in orig_src.lower():
                if not anti:
                    continue
                logical = _iapt_v97_resource_rel(orig_src) or _iapt_v97_resource_rel(orig_rel)
                if not logical:
                    continue
                if _iapt_v97_is_plain_apk_res(orig_rel, orig_src):
                    continue
                if _iapt_v97_is_binary_resource(logical, r):
                    continue
                if not _iapt_v97_resource_referenced(logical, source_blob):
                    continue
                item = dict(r); item['rel_path'] = logical; item['source_rel'] = orig_src
                if logical not in seen:
                    rows.append(item); seen.add(logical)
                continue
            continue
        rows.sort(key=lambda x: str(x.get('rel_path') or ''))
        return rows

    def _iapt_v94_public_rows_from_disk(row):
        try:
            base_rows = _iapt_v97_prev_public_rows(row) if callable(_iapt_v97_prev_public_rows) else []
        except Exception:
            base_rows = []
        rows = _iapt_v97_filter_public_rows(row, base_rows)
        try:
            out_dir = _IAPT_V97_Path(str((row or {}).get('out_dir') or ''))
            if out_dir.is_dir():
                out_dir.joinpath('output_files.json').write_text(_iapt_v97_json.dumps({'version':97,'resource_policy':'src-only plus referenced non-image assets/res when anti sample is enabled','files':rows}, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
                tmpd = out_dir / '.tmp'; tmpd.mkdir(exist_ok=True)
                tmpd.joinpath('file_index.json').write_text(_iapt_v97_json.dumps(rows, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
        except Exception:
            pass
        try:
            task_id = int((row or {}).get('id') or 0)
            if task_id > 0:
                cnt = len(rows); total = sum(int(x.get('size_bytes') or 0) for x in rows)
                db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (cnt,total,task_id))
                row['file_count'] = cnt; row['total_bytes'] = total
        except Exception:
            pass
        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            row = dict(task_or_id)
        else:
            row = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not row:
            return []
        return _iapt_v94_public_rows_from_disk(row)

    @app.get('/api/system/iapt-v97', include_in_schema=False)
    def _iapt_v97_status():
        return {
            'ok': True,
            'version': 'V97-referenced-nonimage-resource-output-filter',
            'normal_output': 'src/** only',
            'anti_sample_output': 'src/** plus referenced non-image assets/res resources only',
            'apk_res_dump': False,
            'image_media_output': False,
            'android_res_dirs_excluded': list(_IAPT_V97_APK_RES_DIR_PREFIXES),
            'client_source_size': '536164 bytes',
        }
    print('IAPT_V97_REFERENCED_RESOURCE_FILTER installed')
except Exception as _iapt_v97_install_error:
    try: print('IAPT_V97_INSTALL_FAILED', repr(_iapt_v97_install_error))
    except Exception: pass
# IAPT_V97_REFERENCED_RESOURCE_FILTER_END

# IAPT_V98_ASSETS_RES_OUTPUT_POLICY_BEGIN
# V98: Correct resource output semantics.
# Normal tasks expose src/** only.
# Anti-encrypted-sample tasks expose src/** plus ALL decrypted assets/res/** files.
# Never expose APK decoded res/** as public output, and never remap assets/res/** to res/**.
try:
    import json as _iapt_v98_json
    import os as _iapt_v98_os
    import shutil as _iapt_v98_shutil
    from pathlib import Path as _IAPT_V98_Path

    # Prefer the pre-V97 source row provider, because V97 wrongly filtered/remapped resources.
    _iapt_v98_source_rows_provider = globals().get('_iapt_v97_prev_public_rows')
    if not callable(_iapt_v98_source_rows_provider):
        _iapt_v98_source_rows_provider = globals().get('_iapt_v96_prev_public_rows')
    if not callable(_iapt_v98_source_rows_provider):
        _iapt_v98_source_rows_provider = globals().get('_iapt_v94_public_rows_from_disk')

    _IAPT_V98_INTERNAL_MARKERS = ('iapt_internal/', '.iapt_internal/', '__iapt_internal__/', 'qiu_shui_resource_export.json', 'qiushui_resource_export.json')
    _IAPT_V98_SRC_ROOT_FILES = {'iaptmain.java', 'mian.iyu'}
    _IAPT_V98_SRC_ROOT_DIRS = {'src', 'com', 'de'}

    def _iapt_v98_norm_rel(x):
        return str(x or '').replace('\\', '/').lstrip('./')

    def _iapt_v98_is_internal(rel):
        low = _iapt_v98_norm_rel(rel).lower()
        return (not low) or low.startswith(_IAPT_V98_INTERNAL_MARKERS) or any(m in low for m in _IAPT_V98_INTERNAL_MARKERS)

    def _iapt_v98_is_src_rel(rel):
        rel = _iapt_v98_norm_rel(rel)
        low = rel.lower()
        if not low:
            return False
        if low.startswith('src/'):
            return True
        head = low.split('/', 1)[0]
        if head in _IAPT_V98_SRC_ROOT_DIRS and low != 'res':
            return True
        if low in _IAPT_V98_SRC_ROOT_FILES or low.endswith('.project'):
            return True
        return False

    def _iapt_v98_public_src_rel(rel):
        rel = _iapt_v98_norm_rel(rel)
        if rel.lower().startswith('src/'):
            return rel
        return 'src/' + rel

    def _iapt_v98_assets_res_tail(rel):
        rel = _iapt_v98_norm_rel(rel)
        low = rel.lower()
        marker = 'assets/res/'
        if low.startswith(marker):
            return rel[len(marker):].lstrip('/')
        pos = low.find('/' + marker)
        if pos >= 0:
            return rel[pos + 1 + len(marker):].lstrip('/')
        return ''

    def _iapt_v98_row_path(row, out_dir):
        if not isinstance(row, dict):
            return None
        for key in ('abs_path', 'path', 'full_path', 'file_path'):
            val = row.get(key)
            if val:
                try:
                    pp = _IAPT_V98_Path(str(val))
                    if pp.exists() and pp.is_file():
                        return pp
                except Exception:
                    pass
        for key in ('rel_path', 'source_rel'):
            val = row.get(key)
            if val:
                try:
                    pp = out_dir / _iapt_v98_norm_rel(val)
                    if pp.exists() and pp.is_file():
                        return pp
                except Exception:
                    pass
        return None

    def _iapt_v98_anti_enabled(row):
        fn = globals().get('_iapt_v97_anti_enabled') or globals().get('_iapt_v94_anti_enabled')
        if callable(fn):
            try:
                return bool(fn(row))
            except Exception:
                pass
        vals = []
        if isinstance(row, dict):
            for k, v in row.items():
                lk = str(k).lower()
                if any(t in lk for t in ('option','param','flag','anti','qiu','protect','restore','decrypt')):
                    vals.append(v)
        text = ' '.join(str(v) for v in vals if v is not None).lower()
        positives = ('anti_encrypt', 'anti-encrypt', 'anti_encrypted', 'anti-sample', 'fanjiami', 'fan_jiami', '反加密', 'qiu_shui', 'qiushui')
        negatives = ('anti_encrypt":false', 'anti_encrypt=false', 'fanjiami":false', 'fanjiami=false', '反加密":false', 'qiu_shui":false', 'qiu_shui=false')
        return any(x in text for x in positives) and not any(x in text for x in negatives)

    def _iapt_v98_copy_to_public_asset_path(row, out_dir, tail):
        # Ensure rel_path can be used as both public ZIP path and disk path.
        target_rel = 'assets/res/' + _iapt_v98_norm_rel(tail)
        dst = out_dir / target_rel
        if dst.exists() and dst.is_file():
            return target_rel
        src = _iapt_v98_row_path(row, out_dir)
        if not src or not src.exists() or not src.is_file():
            return target_rel
        try:
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.resolve() != dst.resolve():
                _iapt_v98_shutil.copy2(src, dst)
        except Exception:
            pass
        return target_rel

    def _iapt_v98_base_rows(row):
        try:
            if callable(_iapt_v98_source_rows_provider):
                return list(_iapt_v98_source_rows_provider(row) or [])
        except Exception as exc:
            try: print('IAPT_V98_BASE_ROWS_PROVIDER_WARN', repr(exc))
            except Exception: pass
        return []

    def _iapt_v98_disk_assets_res_rows(out_dir, existing):
        rows = []
        base = out_dir / 'assets' / 'res'
        if not base.is_dir():
            return rows
        try:
            for pp in base.rglob('*'):
                if not pp.is_file():
                    continue
                rel = _iapt_v98_norm_rel(pp.relative_to(out_dir))
                if rel in existing or _iapt_v98_is_internal(rel):
                    continue
                try:
                    size = pp.stat().st_size
                except Exception:
                    size = 0
                rows.append({'rel_path': rel, 'source_rel': rel, 'size_bytes': int(size)})
                existing.add(rel)
        except Exception:
            pass
        return rows

    def _iapt_v98_public_rows(row):
        try:
            out_dir = _IAPT_V98_Path(str((row or {}).get('out_dir') or ''))
        except Exception:
            out_dir = _IAPT_V98_Path('.')
        anti = _iapt_v98_anti_enabled(row)
        base_rows = _iapt_v98_base_rows(row)
        rows = []
        seen = set()

        for r in base_rows:
            if not isinstance(r, dict):
                continue
            orig_rel = _iapt_v98_norm_rel(r.get('rel_path') or '')
            orig_src = _iapt_v98_norm_rel(r.get('source_rel') or orig_rel)
            if _iapt_v98_is_internal(orig_rel) or _iapt_v98_is_internal(orig_src):
                continue

            if _iapt_v98_is_src_rel(orig_rel) or _iapt_v98_is_src_rel(orig_src):
                rel = _iapt_v98_public_src_rel(orig_rel)
                if _iapt_v98_is_internal(rel) or rel in seen:
                    continue
                item = dict(r)
                item['rel_path'] = rel
                item['source_rel'] = orig_src
                rows.append(item)
                seen.add(rel)
                continue

            if anti:
                tail = _iapt_v98_assets_res_tail(orig_src) or _iapt_v98_assets_res_tail(orig_rel)
                if tail:
                    rel = _iapt_v98_copy_to_public_asset_path(r, out_dir, tail)
                    if _iapt_v98_is_internal(rel) or rel in seen:
                        continue
                    item = dict(r)
                    item['rel_path'] = rel
                    item['source_rel'] = 'assets/res/' + _iapt_v98_norm_rel(tail)
                    try:
                        fp = out_dir / rel
                        if fp.exists():
                            item['size_bytes'] = int(fp.stat().st_size)
                    except Exception:
                        pass
                    rows.append(item)
                    seen.add(rel)
                    continue

            continue

        if anti and out_dir.is_dir():
            rows.extend(_iapt_v98_disk_assets_res_rows(out_dir, seen))

        rows.sort(key=lambda x: str(x.get('rel_path') or ''))
        return rows

    def _iapt_v94_public_rows_from_disk(row):
        rows = _iapt_v98_public_rows(row)
        try:
            out_dir = _IAPT_V98_Path(str((row or {}).get('out_dir') or ''))
            if out_dir.is_dir():
                manifest = {
                    'version': 98,
                    'resource_policy': 'normal src/** only; anti-encrypted sample src/** plus all decrypted assets/res/**; APK res/** excluded',
                    'files': rows,
                }
                out_dir.joinpath('output_files.json').write_text(_iapt_v98_json.dumps(manifest, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
                tmpd = out_dir / '.tmp'
                tmpd.mkdir(exist_ok=True)
                tmpd.joinpath('file_index.json').write_text(_iapt_v98_json.dumps(rows, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
        except Exception as exc:
            try: print('IAPT_V98_MANIFEST_WRITE_WARN', repr(exc))
            except Exception: pass
        try:
            task_id = int((row or {}).get('id') or 0)
            if task_id > 0:
                cnt = len(rows)
                total = sum(int(x.get('size_bytes') or 0) for x in rows)
                db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (cnt, total, task_id))
                row['file_count'] = cnt
                row['total_bytes'] = total
        except Exception:
            pass
        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            row = dict(task_or_id)
        else:
            row = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not row:
            return []
        return _iapt_v94_public_rows_from_disk(row)

    @app.get('/api/system/iapt-v98', include_in_schema=False)
    def _iapt_v98_status():
        return {
            'ok': True,
            'version': 'V98-assets-res-full-output-not-apk-res',
            'normal_output': 'src/** only',
            'anti_sample_output': 'src/** + all decrypted assets/res/**',
            'apk_res_output': False,
            'assets_res_zip_root': 'assets/res/**',
            'no_reference_filter_for_assets_res': True,
            'image_media_in_assets_res': 'kept, because assets/res/** is copied as-is',
            'client_source_size': '536164 bytes',
        }
    print('IAPT_V98_ASSETS_RES_OUTPUT_POLICY installed')
except Exception as _iapt_v98_install_error:
    try: print('IAPT_V98_INSTALL_FAILED', repr(_iapt_v98_install_error))
    except Exception: pass
# IAPT_V98_ASSETS_RES_OUTPUT_POLICY_END

# IAPT_V99_CLIENT_ANTI_AUTODETECT_MARKER_BEGIN
try:
    @app.get('/api/system/iapt-v99', include_in_schema=False)
    def _iapt_v99_status():
        return {
            'ok': True,
            'version': 'V99-client-anti-qiu-autodetect-strict',
            'client_change': 'standard assets/lib.so no longer auto-enables anti_encrypted_sample',
            'anti_auto_enable_rule': 'only hidden/obfuscated container sidecar or long-path hidden resource shell',
            'normal_v3_v6': 'anti_encrypted_sample remains off by default',
            'server_resource_policy': 'inherits V98: normal src/**; anti sample src/** + decrypted assets/res/**',
        }
    print('IAPT_V99_CLIENT_ANTI_AUTODETECT_MARKER installed')
except Exception as _iapt_v99_install_error:
    try: print('IAPT_V99_INSTALL_FAILED', repr(_iapt_v99_install_error))
    except Exception: pass
# IAPT_V99_CLIENT_ANTI_AUTODETECT_MARKER_END


# IAPT_V108_CLEAN_BASELINE_STATUS_BEGIN
try:
    import os as _iapt_v108_os
    def _iapt_v108_has_route(path, method=None):
        try:
            for r in getattr(app.router, 'routes', []) or []:
                if getattr(r, 'path', '') != path:
                    continue
                if method is None:
                    return True
                if method.upper() in (getattr(r, 'methods', set()) or set()):
                    return True
        except Exception:
            pass
        return False
    @app.get('/api/system/iapt-v108', include_in_schema=False)
    def _iapt_v108_status():
        db_ok = False
        db_error = ''
        try:
            row = db.one('SELECT 1 AS ok')
            db_ok = bool(row and int(row.get('ok') or 0) == 1)
        except Exception as e:
            db_error = repr(e)[:300]
        return {
            'ok': True,
            'version': 'V108-clean-v99-feature-baseline-stable-db-secure',
            'base': 'V99 clean feature baseline; V100-V107 admin/middleware experiments removed by full main.py restore',
            'db_ok': db_ok,
            'db_error': db_error,
            'db_pool': getattr(db, 'DB_POOL_MODE', {}),
            'secure': getattr(__import__('app.secure', fromlist=['SECURE_MODE']), 'SECURE_MODE', {}),
            'dynamic_key_api': _iapt_v108_has_route('/api/dynamic-keys/pool', 'GET'),
            'admin_dynamic_key_pool': _iapt_v108_has_route('/api/admin/dynamic-key-pool', 'GET'),
            'download_policy': 'normal src/**; anti sample src/** + decrypted assets/res/**; no APK res/**',
            'decrypt_report': 'V3/ancient summary inherited from V99 baseline',
            'concurrency': {
                'LOCAL_QUEUE_WORKERS': _iapt_v108_os.environ.get('LOCAL_QUEUE_WORKERS',''),
                'MAX_DECRYPT_WORKERS': _iapt_v108_os.environ.get('MAX_DECRYPT_WORKERS',''),
                'WORKER_CONCURRENCY': _iapt_v108_os.environ.get('WORKER_CONCURRENCY',''),
                'IAPT_ENUM_WORKERS': _iapt_v108_os.environ.get('IAPT_ENUM_WORKERS',''),
                'IAPT_NORMAL_WORKERS': _iapt_v108_os.environ.get('IAPT_NORMAL_WORKERS',''),
            }
        }
    print('IAPT_V108_CLEAN_BASELINE_STATUS installed')
except Exception as _iapt_v108_exc:
    try: print('IAPT_V108_INSTALL_FAILED', repr(_iapt_v108_exc))
    except Exception: pass
# IAPT_V108_CLEAN_BASELINE_STATUS_END


# IAPT_V109_OUTPUT_POLICY_ASSETS_RES_BEGIN
# V109: final public output policy.
#   normal task -> src/** only
#   anti-encrypted hidden-resource task -> src/** + decrypted assets/res/**
#   never expose APK decoded res/**, internal reports, or qiu_shui_resource_export.json.
try:
    import json as _iapt_v109_json
    import shutil as _iapt_v109_shutil
    from pathlib import Path as _IAPT_V109_Path

    _IAPT_V109_INTERNAL = ('iapt_internal/', '.iapt_internal/', '__iapt_internal__/', 'qiu_shui_resource_export.json', 'qiushui_resource_export.json', 'old_iapp_report.json')
    _IAPT_V109_SRC_ROOT_FILES = {'iaptmain.java', 'mian.iyu'}
    _IAPT_V109_SRC_ROOT_DIRS = {'src', 'com', 'de'}

    def _iapt_v109_norm_rel(x):
        return str(x or '').replace('\\', '/').lstrip('./')

    def _iapt_v109_truthy(value, default=False):
        if value is None:
            return bool(default)
        if value is True or value == 1:
            return True
        if value is False or value == 0:
            return False
        if isinstance(value, str):
            low = value.strip().lower()
            if low in ('1', 'true', 'yes', 'on', 'y'):
                return True
            if low in ('0', 'false', 'no', 'off', 'n', 'none', ''):
                return False
        return bool(default)

    def _iapt_v109_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            obj = _iapt_v109_json.loads(raw or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v109_anti(task, options=None):
        options = options if isinstance(options, dict) else _iapt_v109_options(task)
        for k in ('anti_qiushui','anti_encrypt','anti_encrypted_sample','hidden_resource_restore','hidden_resource_restored','anti_qiushui_resource_export'):
            if _iapt_v109_truthy(options.get(k)):
                return True
        for k in ('anti_qiushui_feature_id','hidden_resource_feature_id','feature_id'):
            try:
                if int(options.get(k) or (task or {}).get(k) or 0) == 17:
                    return True
            except Exception:
                pass
        return False

    def _iapt_v109_is_internal(rel):
        low = _iapt_v109_norm_rel(rel).lower()
        return (not low) or low.startswith(_IAPT_V109_INTERNAL) or any(x in low for x in _IAPT_V109_INTERNAL)

    def _iapt_v109_src_rel(rel):
        rel = _iapt_v109_norm_rel(rel)
        low = rel.lower()
        if not low:
            return ''
        if low.startswith('src/'):
            return rel
        head = low.split('/', 1)[0]
        if head in _IAPT_V109_SRC_ROOT_DIRS and low != 'res':
            return 'src/' + rel
        if low in _IAPT_V109_SRC_ROOT_FILES or low.endswith('.project'):
            return 'src/' + rel
        return ''

    def _iapt_v109_assets_res_rel(rel):
        rel = _iapt_v109_norm_rel(rel)
        low = rel.lower()
        if low.startswith('assets/res/'):
            return rel
        return ''

    def _iapt_v109_copy_if_needed(src, out_dir, public_rel):
        try:
            dst = (out_dir / public_rel).resolve()
            root = out_dir.resolve()
            dst.relative_to(root)
            dst.parent.mkdir(parents=True, exist_ok=True)
            if src.resolve() != dst.resolve() and (not dst.exists() or dst.read_bytes() != src.read_bytes()):
                _iapt_v109_shutil.copy2(src, dst)
        except Exception:
            pass

    def _iapt_v109_public_rows_from_disk(task):
        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V109_Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        options = _iapt_v109_options(task)
        anti = _iapt_v109_anti(task, options)
        rows = []
        seen = set()
        try:
            files = [p for p in out_dir.rglob('*') if p.is_file()]
        except Exception:
            files = []
        for pp in files:
            try:
                rel0 = _iapt_v109_norm_rel(pp.relative_to(out_dir))
            except Exception:
                continue
            if _iapt_v109_is_internal(rel0):
                continue
            rel = _iapt_v109_src_rel(rel0)
            if not rel and anti:
                rel = _iapt_v109_assets_res_rel(rel0)
            if not rel or rel.lower().startswith('res/'):
                continue
            if rel in seen:
                continue
            _iapt_v109_copy_if_needed(pp, out_dir, rel)
            try:
                size = int((out_dir / rel).stat().st_size)
            except Exception:
                try: size = int(pp.stat().st_size)
                except Exception: size = 0
            rows.append({'rel_path': rel, 'source_rel': rel0, 'size_bytes': size})
            seen.add(rel)
        rows.sort(key=lambda x: str(x.get('rel_path') or ''))
        return rows

    def _iapt_v109_write_index(task, rows):
        try:
            out_dir = _IAPT_V109_Path(str((task or {}).get('out_dir') or ''))
            if out_dir.is_dir():
                manifest = {
                    'version': 109,
                    'resource_policy': 'normal src/** only; anti-hidden-resource src/** + decrypted assets/res/**; apk res/** excluded',
                    'files': rows,
                }
                out_dir.joinpath('output_files.json').write_text(_iapt_v109_json.dumps(manifest, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
                tmp = out_dir / '.tmp'
                tmp.mkdir(exist_ok=True)
                tmp.joinpath('file_index.json').write_text(_iapt_v109_json.dumps(rows, ensure_ascii=False, separators=(',',':')), encoding='utf-8')
        except Exception:
            pass
        try:
            tid = int((task or {}).get('id') or 0)
            if tid > 0:
                cnt = len(rows)
                total = sum(int(x.get('size_bytes') or 0) for x in rows)
                db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (cnt, total, tid))
                task['file_count'] = cnt
                task['total_bytes'] = total
        except Exception:
            pass

    def _iapt_v109_reexport_assets_res_if_needed(task):
        try:
            out_dir = _IAPT_V109_Path(str((task or {}).get('out_dir') or ''))
            if not out_dir.is_dir():
                return
            if any((out_dir / 'assets' / 'res').rglob('*')):
                return
            options = _iapt_v109_options(task)
            if not _iapt_v109_anti(task, options):
                return
            task_no = str((task or {}).get('task_no') or '').strip()
            if not task_no:
                return
            apk = APP_STORAGE / 'uploads' / (task_no + '.apk')
            if not apk.is_file():
                return
            from .tools.iapt_qiushui_resource_export import export_resources
            export_resources(apk, out_dir, options or {})
        except Exception as exc:
            try: print('IAPT_V109_REEXPORT_ASSETS_RES_WARN', repr(exc))
            except Exception: pass

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            row = dict(task_or_id)
        else:
            try:
                row = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
            except Exception:
                row = None
        if not row:
            return []
        _iapt_v109_reexport_assets_res_if_needed(row)
        rows = _iapt_v109_public_rows_from_disk(row)
        _iapt_v109_write_index(row, rows)
        return rows

    def _finish_public_file_rows(task, files=None):
        return list_task_files(task)

    @app.get('/api/system/iapt-v109-output', include_in_schema=False)
    def _iapt_v109_output_status():
        return {
            'ok': True,
            'version': 'V109-output-src-assetsres-only',
            'normal_output': 'src/** only',
            'anti_sample_output': 'src/** + decrypted assets/res/**',
            'apk_res_output': False,
            'res_root_output': False,
            'assets_res_zip_root': 'assets/res/**',
        }
    print('IAPT_V109_OUTPUT_POLICY_ASSETS_RES installed')
except Exception as _iapt_v109_output_error:
    try: print('IAPT_V109_OUTPUT_POLICY_INSTALL_FAILED', repr(_iapt_v109_output_error))
    except Exception: pass
# IAPT_V109_OUTPUT_POLICY_ASSETS_RES_END



# IAPT_V109_STATUS_BEGIN
try:
    @app.get('/api/system/iapt-v109', include_in_schema=False)
    def _iapt_v109_status():
        try:
            from . import dynamic_key_pool as _dkp
            pool_info = getattr(_dkp, 'DYNAMIC_KEY_POOL_V109', {})
        except Exception as exc:
            pool_info = {'error': repr(exc)}
        return {
            'ok': True,
            'version': 'V109-hidden-resource-autodex-fast-pool-assetsres',
            'sample_fix': 'hidden DES/sidecar samples without assets/lib.so are restored before V3 decryption',
            'hidden_auto_dexkey_enum': 'V3 hidden-resource only; ancient not affected',
            'dynamic_key_pool_fast': pool_info,
            'output_policy': 'normal src/**; anti sample src/** + decrypted assets/res/**; no APK res/**',
            'high_concurrency_kept': {
                'LOCAL_QUEUE_WORKERS': 10,
                'MAX_DECRYPT_WORKERS': 5,
                'WORKER_CONCURRENCY': 10,
                'IAPT_ENUM_WORKERS': 32,
                'IAPT_NORMAL_WORKERS': 32,
            },
        }
except Exception as _iapt_v109_status_error:
    try: print('IAPT_V109_STATUS_INSTALL_FAILED', repr(_iapt_v109_status_error))
    except Exception: pass
# IAPT_V109_STATUS_END

# IAPT_V110_STATUS_BEGIN
try:
    import os as _iapt_v110_status_os
    @app.get('/api/system/iapt-v110', include_in_schema=False)
    def _iapt_v110_status():
        pool_info = {}
        try:
            from . import dynamic_key_pool as _iapt_v110_pool
            pool_info = dict(getattr(_iapt_v110_pool, 'DYNAMIC_KEY_POOL_V110', {}) or {})
        except Exception as exc:
            pool_info = {'error': type(exc).__name__ + ': ' + str(exc)}
        return {
            'ok': True,
            'version': 'V110-active-v3-route-hidden-c-enum-fast-pool',
            'root_cause_fixed': {
                'active_v82_v10_command_builder': True,
                'v3_entry_c_flags_forwarded': True,
                'no_dynamic_tuple_crash': True,
                'pool_schema_once_and_bulk_features': True,
            },
            'enum_workers': int(_iapt_v110_status_os.environ.get('IAPT_ENUM_WORKERS', '32') or 32),
            'dynamic_pool': pool_info,
        }
except Exception as _iapt_v110_status_error:
    try:
        print('IAPT_V110_STATUS_INSTALL_FAILED', repr(_iapt_v110_status_error))
    except Exception:
        pass
# IAPT_V110_STATUS_END

# IAPT_V111_API_BLOCKING_FIX_BEGIN
@app.get('/api/system/iapt-v111', include_in_schema=False)
def _iapt_v111_status():
    try:
        from . import db as _iapt_v111_db
        db_mode = _iapt_v111_db.pool_stats() if hasattr(_iapt_v111_db, 'pool_stats') else getattr(_iapt_v111_db, 'DB_POOL_MODE', {})
    except Exception as exc:
        db_mode = {'error': str(exc)}
    return {
        'ok': True,
        'version': 'V111-event-loop-db-metadata-lock-fix',
        'root_cause': [
            'V38/V40 synchronous database writes in global async middleware',
            'whitelist middleware DDL/INFORMATION_SCHEMA on every GET',
            'V60/V61 full multipart body parsing in async middleware',
            'async create_task performed blocking file/ZIP/MySQL work on the event loop',
            'other await-free async routes also ran synchronous DB/file work on the event loop',
            'V91-V94 rewrote every JSON response including admin APIs',
        ],
        'global_db_middlewares_disabled': True,
        'per_request_whitelist_ddl_disabled': True,
        'upload_body_reparse_disabled': True,
        'upload_handler_threadpool': True,
        'v6_upload_handler_threadpool': True,
        'await_free_routes_threadpool': True,
        'admin_response_rewriters_bypassed': True,
        'db_pool': db_mode,
        'enum_workers': int(__import__('os').environ.get('IAPT_ENUM_WORKERS', '32') or 32),
        'normal_workers': int(__import__('os').environ.get('IAPT_NORMAL_WORKERS', '32') or 32),
    }
# IAPT_V111_API_BLOCKING_FIX_END

# IAPT_V113_STATUS_BEGIN
try:
    @app.get('/api/system/iapt-v113')
    def iapt_v113_status():
        import os as _os
        try:
            from . import decrypt_runner as _dr
            route = getattr(_dr, 'IAPT_V113_ROUTE', {}) or {}
        except Exception as _exc:
            route = {'import_error': type(_exc).__name__ + ': ' + str(_exc)}
        return {
            'ok': str(route.get('version') or '').startswith('V113'),
            'version': 'V113-normalize-libso-first-explicit-enum',
            'route': route,
            'assets_lib_restore_before_key_resolution': True,
            'v3_entry_fallback_independent_of_outer_router': True,
            'automatic_sokey_enum': False,
            'automatic_dexkey_enum': False,
            'sokey_enum_policy': 'time-based fallback only when requested and plaintext extraction failed',
            'enum_workers': int(_os.environ.get('IAPT_ENUM_WORKERS', '32') or 32),
        }
except Exception as _iapt_v113_status_error:
    try:
        print('IAPT_V113_STATUS_INSTALL_FAILED', repr(_iapt_v113_status_error), flush=True)
    except Exception:
        pass
# IAPT_V113_STATUS_END

# IAPT_V114_STATUS_BEGIN
@app.get('/api/system/iapt-v114')
def iapt_v114_status():
    import os as _os
    return {
        'ok': True,
        'version': 'V114-explicit-anti-enum-src-assetsres',
        'hidden_restore': 'explicit-client-parameter-only',
        'enumeration': 'exact-client-flags',
        'source_output': 'src/**',
        'anti_resource_output': 'assets/res/**',
        'apk_res_output': False,
        'project_only_success': False,
        'enum_workers': int(_os.environ.get('IAPT_ENUM_WORKERS', '32') or 32),
    }
# IAPT_V114_STATUS_END

# IAPT_V116_LINEAR_DOWNLOAD_BEGIN
# V13 still prepares and validates/encrypts the complete ZIP atomically.  V116
# transfers that prepared file in one streaming response instead of making one
# authenticated HTTP request per 256 KiB fragment.
from fastapi.responses import StreamingResponse as _IaptV116StreamingResponse
_IAPT_V116_LINEAR_BUFFER = 512 * 1024


def _iapt_v116_linear_iterator(path: Path):
    with Path(path).open('rb') as stream:
        while True:
            block = stream.read(_IAPT_V116_LINEAR_BUFFER)
            if not block:
                break
            yield block


def _iapt_v116_linear_response(obj: dict):
    path = Path(obj['_path'])
    return _IaptV116StreamingResponse(
        _iapt_v116_linear_iterator(path),
        media_type='application/octet-stream',
        headers={
            'Content-Length': str(int(obj.get('size') or path.stat().st_size)),
            'Cache-Control': 'no-store',
            'Content-Encoding': 'identity',
            'X-IAPT-Download-Mode': 'linear-512k-v116',
            'X-IAPT-File-SHA256': str(obj.get('sha256') or ''),
            'X-IAPT-Buffer-Size': str(_IAPT_V116_LINEAR_BUFFER),
        },
    )


@app.get('/api/tasks/{task_id}/download-v116/stream')
def iapt_task_download_v116_stream(task_id: int, session: str,
                                    user=Depends(current_user)):
    obj = _iapt_v13_load_session(session, user, task_id, False)
    return _iapt_v116_linear_response(obj)


@app.get('/api/admin/tasks/{task_id}/download-source-v116/stream')
def iapt_admin_download_v116_stream(task_id: int, session: str,
                                     user=Depends(current_user)):
    admin_user(user)
    require_permission(user, PERM_TASK_VIEW_ALL)
    obj = _iapt_v13_load_session(session, user, task_id, True)
    return _iapt_v116_linear_response(obj)
# IAPT_V116_LINEAR_DOWNLOAD_END

# IAPT_V116_STATUS_BEGIN
@app.get('/api/system/iapt-v116')
def iapt_v116_status():
    import os as _os
    return {
        'ok': True,
        'version': 'V116-anti-resource-toggle-client-compact-512k',
        'hidden_restore': 'final-client-parameter-only',
        'probe_can_enable_anti': False,
        'enumeration': 'exact-client-flags',
        'anti_resource_parameter': 'no_decrypt_resource_files',
        'anti_resource_default': 'skip',
        'client_hidden_compact': 'local DES unwrap; required files only; assets/res optional',
        'compact_upload_buffer_bytes': 512 * 1024,
        'linear_download': True,
        'linear_buffer_bytes': 512 * 1024,
        'download_rate_limit': False,
        'source_output': 'src/**',
        'anti_resource_output': 'assets/res/** only when no_decrypt_resource_files=false',
        'apk_res_output': False,
        'enum_workers': int(_os.environ.get('IAPT_ENUM_WORKERS', '32') or 32),
    }
# IAPT_V116_STATUS_END

# IAPT_V117_ANCIENT_IDENTITY_BEGIN
# Preserve the final client-selected family.  V53 historically rewrote an
# explicit ancient request to decrypt_version=v3, which affected DB rows,
# task-list labels, cache hits and later response normalization.
import json as _iapt_v117_json


def _iapt_v117_truthy(value):
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on', 'y')
    return False


def _iapt_v117_is_ancient_options(options):
    options = options or {}
    scheme = str(options.get('client_final_scheme') or options.get('decrypt_scheme') or '').strip().lower()
    version = str(options.get('decrypt_version') or options.get('task_version') or '').strip().lower()
    return (
        scheme in ('ancient', 'old', 'legacy')
        or version in ('ancient', 'old', 'legacy', 'old_iapp', 'iapp_old')
        or _iapt_v117_truthy(options.get('legacy_iapp'))
        or _iapt_v117_truthy(options.get('old_iapp'))
    )


def _iapt_v117_force_ancient(options):
    if not isinstance(options, dict):
        return options
    options['decrypt_scheme'] = 'ancient'
    options['decrypt_version'] = 'ancient'
    options['task_version'] = 'ancient'
    options['legacy_iapp'] = True
    options['old_iapp'] = True
    options['client_scheme_explicit'] = True
    options['client_final_scheme'] = 'ancient'
    options['no_dynamic_key'] = True
    return options


if callable(globals().get('_v53_feature_from_options')) and '_IAPT_V117_BASE_V53_FEATURE' not in globals():
    _IAPT_V117_BASE_V53_FEATURE = _v53_feature_from_options

    def _v53_feature_from_options(options):
        ancient = _iapt_v117_is_ancient_options(options)
        fid = _IAPT_V117_BASE_V53_FEATURE(options)
        if ancient:
            _iapt_v117_force_ancient(options)
        return fid


if callable(globals().get('_v53_insert_task')) and '_IAPT_V117_BASE_V53_INSERT' not in globals():
    _IAPT_V117_BASE_V53_INSERT = _v53_insert_task

    def _v53_insert_task(task_no, user_id, apk_name, feature_id, options, apk_sha, opt_hash,
                         resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note):
        if _iapt_v117_is_ancient_options(options):
            _iapt_v117_force_ancient(options)
        tid = _IAPT_V117_BASE_V53_INSERT(
            task_no, user_id, apk_name, feature_id, options, apk_sha, opt_hash,
            resource_cost, resource_note, estimated_cost, quota_after_resource, quota_note,
        )
        if _iapt_v117_is_ancient_options(options):
            try:
                db.exec("UPDATE tasks SET decrypt_version='ancient' WHERE id=%s", (int(tid),))
            except Exception as exc:
                print('[IAPT_V117] insert decrypt_version update warn:', repr(exc), flush=True)
        return tid


if callable(globals().get('_v53_normalize_task_row')) and '_IAPT_V117_BASE_V53_NORMALIZE' not in globals():
    _IAPT_V117_BASE_V53_NORMALIZE = _v53_normalize_task_row

    def _v53_normalize_task_row(row):
        raw = dict(row or {})
        opts = {}
        try:
            value = raw.get('options_json')
            opts = _iapt_v117_json.loads(value) if isinstance(value, str) and value else (value or {})
        except Exception:
            opts = {}
        out = _IAPT_V117_BASE_V53_NORMALIZE(row)
        if _iapt_v117_is_ancient_options(opts):
            out['decrypt_version'] = 'ancient'
            out['task_version'] = 'ancient'
            out['decrypt_scheme'] = 'ancient'
            out['public_scheme'] = 'ancient'
        return out


# Cache-hit tasks are created through app.cache.attach_cache_to_new_task instead
# of _v53_insert_task.  Patch that path as well so an ancient cache hit never
# becomes V3 after refresh.
try:
    from . import cache as _iapt_v117_cache
    if callable(getattr(_iapt_v117_cache, 'attach_cache_to_new_task', None)) and not hasattr(_iapt_v117_cache, '_iapt_v117_base_attach'):
        _iapt_v117_cache._iapt_v117_base_attach = _iapt_v117_cache.attach_cache_to_new_task

        def _iapt_v117_attach_cache(user_id, apk_name, feature_id, options, apk_sha, opt_hash, hit):
            if _iapt_v117_is_ancient_options(options):
                _iapt_v117_force_ancient(options)
            tid = _iapt_v117_cache._iapt_v117_base_attach(
                user_id, apk_name, feature_id, options, apk_sha, opt_hash, hit
            )
            if _iapt_v117_is_ancient_options(options):
                try:
                    db.exec("UPDATE tasks SET decrypt_version='ancient' WHERE id=%s", (int(tid),))
                except Exception as exc:
                    print('[IAPT_V117] cache decrypt_version update warn:', repr(exc), flush=True)
            return tid

        _iapt_v117_cache.attach_cache_to_new_task = _iapt_v117_attach_cache
except Exception as _iapt_v117_cache_exc:
    print('[IAPT_V117] cache patch warn:', repr(_iapt_v117_cache_exc), flush=True)


# Repair rows created by the old V53 rewrite.  The explicit old flags in
# options_json are authoritative; no APK probing is used here.
try:
    db.exec("""
        UPDATE tasks
           SET decrypt_version='ancient'
         WHERE options_json IS NOT NULL
           AND (
                LOCATE('"decrypt_scheme": "ancient"', LOWER(options_json)) > 0
             OR LOCATE('"decrypt_scheme":"ancient"', LOWER(options_json)) > 0
             OR LOCATE('"client_final_scheme": "ancient"', LOWER(options_json)) > 0
             OR LOCATE('"client_final_scheme":"ancient"', LOWER(options_json)) > 0
             OR LOCATE('"legacy_iapp": true', LOWER(options_json)) > 0
             OR LOCATE('"legacy_iapp":true', LOWER(options_json)) > 0
             OR LOCATE('"old_iapp": true', LOWER(options_json)) > 0
             OR LOCATE('"old_iapp":true', LOWER(options_json)) > 0
           )
    """)
except Exception as _iapt_v117_migrate_exc:
    print('[IAPT_V117] task migration warn:', repr(_iapt_v117_migrate_exc), flush=True)


try:
    @app.get('/api/system/iapt-v117', include_in_schema=False)
    def _iapt_v117_status():
        return {
            'ok': True,
            'version': 'V117-ancient-final-scheme-task-list-dedupe',
            'ancient_identity': 'client-final-parameter-preserved',
            'v53_ancient_to_v3_rewrite': False,
            'cache_hit_ancient_identity': True,
            'client_pending_server_dedupe': True,
            'double_click_guard': True,
            'anti_resource_toggle_preserved': True,
            'linear_upload_buffer_bytes': 524288,
            'enum_workers': int(__import__('os').environ.get('IAPT_ENUM_WORKERS', '32') or 32),
        }
except Exception as _iapt_v117_route_exc:
    print('[IAPT_V117] status route warn:', repr(_iapt_v117_route_exc), flush=True)
# IAPT_V117_ANCIENT_IDENTITY_END

# IAPT_V118_MAIN_INVARIANT_BEGIN
# The route marker is written only when the final client switch is ancient.
# It is deliberately checked only once at task creation, never while listing
# tasks, so this fix does not reintroduce task-list disk scans or 504s.
import json as _iapt_v118_json
import zipfile as _iapt_v118_zipfile

_IAPT_V118_ANCIENT_MARKER = 'META-INF/iapt/decrypt_scheme_ancient'


def _iapt_v118_truthy(value):
    if value is True or value == 1:
        return True
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on', 'y')


def _iapt_v118_has_ancient_marker(apk_path):
    try:
        with _iapt_v118_zipfile.ZipFile(str(apk_path), 'r') as archive:
            wanted = _IAPT_V118_ANCIENT_MARKER.lower()
            return any(
                (not item.is_dir())
                and item.filename.replace('\\', '/').lstrip('/').lower() == wanted.lower()
                for item in archive.infolist()
            )
    except Exception:
        return False


def _iapt_v118_is_ancient_options(options):
    options = options if isinstance(options, dict) else {}
    values = (
        options.get('client_route_lock'), options.get('client_final_scheme'),
        options.get('decrypt_scheme'), options.get('decrypt_version'),
        options.get('task_version'),
    )
    if any(str(v or '').strip().lower() in ('ancient', 'old', 'legacy', 'ancient-marker-v118') for v in values):
        return True
    return _iapt_v118_truthy(options.get('legacy_iapp')) or _iapt_v118_truthy(options.get('old_iapp'))


def _iapt_v118_force_ancient_options(options):
    if not isinstance(options, dict):
        return options
    options['decrypt_scheme'] = 'ancient'
    options['decrypt_version'] = 'ancient'
    options['task_version'] = 'ancient'
    options['client_final_scheme'] = 'ancient'
    options['client_scheme_explicit'] = True
    options['client_route_lock'] = 'ancient-marker-v118'
    options['legacy_iapp'] = True
    options['old_iapp'] = True
    options['no_dynamic_key'] = True
    for key in (
        'dynamic_key', 'custom_dynamic_key', 'post_key', 'key_xor',
        'server_key_pool_mode', 'server_key_pool_ref',
        'anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore',
        'numeric_restore', 'dynamic_restore', 'v3_dynamic_restore',
    ):
        options.pop(key, None)
    return options


# Preserve all route-lock fields through the older sanitizer too.  The active
# V53 endpoint uses raw encrypted options, but this keeps alternate endpoints
# and future aliases consistent.
if callable(globals().get('_sanitize_decrypt_options')) and '_IAPT_V118_BASE_SANITIZE' not in globals():
    _IAPT_V118_BASE_SANITIZE = _sanitize_decrypt_options

    def _sanitize_decrypt_options(options, user_id):
        raw = dict(options or {})
        clean, feature_id, feature_scope = _IAPT_V118_BASE_SANITIZE(raw, user_id)
        for key in (
            'client_route_lock', 'client_final_scheme', 'client_scheme_explicit',
            'old_sokey', 'sokey', 'client_sokey', 'client_dexkey',
        ):
            if key in raw:
                clean[key] = raw[key]
        if _iapt_v118_is_ancient_options(raw):
            _iapt_v118_force_ancient_options(clean)
        return clean, feature_id, feature_scope


# Directly wrap the V53 mutator as a second line of defence.  Unlike V117, the
# marker fix above does not depend on this wrapper being the active call target.
if callable(globals().get('_v53_feature_from_options')) and '_IAPT_V118_BASE_V53_FEATURE' not in globals():
    _IAPT_V118_BASE_V53_FEATURE = _v53_feature_from_options

    def _v53_feature_from_options(options):
        ancient = _iapt_v118_is_ancient_options(options)
        feature_id = _IAPT_V118_BASE_V53_FEATURE(options)
        if ancient:
            _iapt_v118_force_ancient_options(options)
        return feature_id


if callable(globals().get('_v53_normalize_task_row')) and '_IAPT_V118_BASE_NORMALIZE' not in globals():
    _IAPT_V118_BASE_NORMALIZE = _v53_normalize_task_row

    def _v53_normalize_task_row(row):
        raw = dict(row or {})
        try:
            value = raw.get('options_json')
            options = _iapt_v118_json.loads(value) if isinstance(value, str) and value else (value or {})
        except Exception:
            options = {}
        out = _IAPT_V118_BASE_NORMALIZE(row)
        if _iapt_v118_is_ancient_options(options):
            out['decrypt_version'] = 'ancient'
            out['task_version'] = 'ancient'
            out['decrypt_scheme'] = 'ancient'
            out['public_scheme'] = 'ancient'
        return out


try:
    @app.get('/api/system/iapt-v118', include_in_schema=False)
    def _iapt_v118_status():
        runner = None
        try:
            from . import decrypt_runner as runner
        except Exception:
            pass
        return {
            'ok': True,
            'version': 'V118-marker-locked-ancient-route',
            'v53_direct_assignment': 'ancient',
            'upload_marker_authority': True,
            'task_list_disk_scan': False,
            'runner_marker_route': bool(runner and callable(getattr(runner, '_iapt_v118_has_ancient_marker', None))),
            'client_route_lock': 'ancient-marker-v118',
            'enum_workers': int(__import__('os').environ.get('IAPT_ENUM_WORKERS', '32') or 32),
        }
except Exception as _iapt_v118_status_exc:
    print('[IAPT_V118] status route warn:', repr(_iapt_v118_status_exc), flush=True)
# IAPT_V118_MAIN_INVARIANT_END



# IAPT_V122_AUTOCOMMIT_CLEAR_RECORDS_ROUTE_BEGIN
try:
    @app.get('/api/system/iapt-v122')
    def iapt_v122_status():
        return {
            'ok': True,
            'version': 'V122-autocommit-clear-records-hotfix',
            'db_transaction': 'no-autocommit-attribute',
            'clear_records': 'direct-delete-no-transaction-autocommit',
            'records_cleared_on_deploy': True,
        }
except Exception:
    pass
# IAPT_V122_AUTOCOMMIT_CLEAR_RECORDS_ROUTE_END


# IAPT_V124_TASK_LIST_ANCIENT_BEGIN
try:
    import json as _iapt_v124_json
    import re as _iapt_v124_re
    import zipfile as _iapt_v124_zipfile
    from starlette.responses import Response as _iapt_v124_Response

    IAPT_V124_VERSION = 'V124-ancient-list-db-truth-sokey-failfast'

    def _iapt_v124_bool(v):
        if v is True or v == 1: return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y')

    def _iapt_v124_load_options(raw):
        try:
            if isinstance(raw, dict): return dict(raw)
            if isinstance(raw, str) and raw.strip():
                obj = _iapt_v124_json.loads(raw)
                return obj if isinstance(obj, dict) else {}
        except Exception:
            pass
        return {}

    def _iapt_v124_is_ancient_options(opt):
        opt = opt if isinstance(opt, dict) else _iapt_v124_load_options(opt)
        for k in ('decrypt_scheme','decrypt_version','task_version','public_scheme','client_final_scheme','client_submission_path','client_route_lock'):
            v = str(opt.get(k) or '').strip().lower()
            if v in ('ancient','old','legacy','old_iapp','iapp_old','decrypt-ancient') or v.startswith('ancient-endpoint'):
                return True
        return _iapt_v124_bool(opt.get('legacy_iapp')) or _iapt_v124_bool(opt.get('old_iapp'))

    def _iapt_v124_force_public_ancient(item):
        if not isinstance(item, dict): return item
        item['decrypt_version']='ancient'
        item['task_version']='ancient'
        item['public_scheme']='ancient'
        item['task_family']='ancient'
        item['decrypt_scheme']='ancient'
        return item

    def _iapt_v124_patch_list_json(data):
        # Find all task dicts in common list wrappers.
        lists=[]
        if isinstance(data, list): lists.append(data)
        elif isinstance(data, dict):
            for key in ('tasks','items','data','results','rows','list'):
                arr=data.get(key)
                if isinstance(arr, list): lists.append(arr)
        ids=[]; byid={}
        for arr in lists:
            for it in arr:
                if not isinstance(it, dict): continue
                try:
                    tid=int(it.get('id') or it.get('task_id') or 0)
                except Exception:
                    tid=0
                if tid>0:
                    ids.append(tid); byid[tid]=it
                # If options are already present in the item, normalize immediately.
                if _iapt_v124_is_ancient_options(it.get('options_json') or it):
                    _iapt_v124_force_public_ancient(it)
        if ids:
            try:
                ph=','.join(['%s']*len(ids))
                rows=db.all('SELECT id,decrypt_version,options_json FROM tasks WHERE id IN ('+ph+')', tuple(ids))
                for r in rows or []:
                    tid=int(r.get('id') or 0)
                    if tid in byid and (str(r.get('decrypt_version') or '').lower()=='ancient' or _iapt_v124_is_ancient_options(r.get('options_json'))):
                        _iapt_v124_force_public_ancient(byid[tid])
            except Exception as e:
                print('[IAPT_V124] list DB normalize warn:', repr(e), flush=True)
        return data

    @app.middleware('http')
    async def _iapt_v124_task_list_create_normalizer(request, call_next):
        path=str(getattr(request.url,'path','') or '').rstrip('/')
        method=str(getattr(request,'method','') or '').upper()
        watch = (method=='GET' and path in ('/tasks','/api/tasks','/admin/tasks','/api/admin/tasks')) or (method=='POST' and path in ('/tasks/decrypt','/api/tasks/decrypt','/tasks/decrypt-ancient','/api/tasks/decrypt-ancient'))
        if not watch:
            return await call_next(request)
        resp=await call_next(request)
        body=b''
        try:
            async for chunk in resp.body_iterator:
                body += chunk
        except Exception:
            return resp
        try:
            data=_iapt_v124_json.loads(body.decode('utf-8','ignore') or '{}')
            if method=='GET':
                data=_iapt_v124_patch_list_json(data)
            elif method=='POST':
                # After create, make DB truth ancient when the response task/options indicate ancient.
                tid = data.get('task_id') or data.get('id') if isinstance(data, dict) else None
                if tid:
                    try:
                        row=db.one('SELECT id,decrypt_version,options_json FROM tasks WHERE id=%s', (int(tid),))
                        opt=_iapt_v124_load_options((row or {}).get('options_json'))
                        force= path.endswith('decrypt-ancient') or str((row or {}).get('decrypt_version') or '').lower()=='ancient' or _iapt_v124_is_ancient_options(opt)
                        if force:
                            opt.update({'decrypt_scheme':'ancient','decrypt_version':'ancient','task_version':'ancient','public_scheme':'ancient','client_final_scheme':'ancient','legacy_iapp':True,'old_iapp':True})
                            db.exec("UPDATE tasks SET decrypt_version='ancient',options_json=%s WHERE id=%s", (_iapt_v124_json.dumps(opt, ensure_ascii=False, separators=(',',':')), int(tid)))
                            data['decrypt_version']='ancient'; data['task_version']='ancient'; data['public_scheme']='ancient'; data['task_family']='ancient'
                    except Exception as e:
                        print('[IAPT_V124] create normalize warn:', repr(e), flush=True)
            body=_iapt_v124_json.dumps(data, ensure_ascii=False, separators=(',',':')).encode('utf-8')
        except Exception as e:
            print('[IAPT_V124] response normalize warn:', repr(e), flush=True)
        headers=dict(getattr(resp,'headers',{}) or {})
        headers.pop('content-length', None)
        return _iapt_v124_Response(content=body, status_code=resp.status_code, headers=headers, media_type=getattr(resp,'media_type',None) or 'application/json')

    @app.get('/api/system/iapt-v124', include_in_schema=False)
    def _iapt_v124_status():
        paths={getattr(r,'path','') for r in app.routes}
        return {'ok':True,'version':IAPT_V124_VERSION,'task_list_db_truth':True,'create_response_ancient_guard':True,'autocommit_compat':True,'has_tasks':('/tasks' in paths or '/api/tasks' in paths)}
except Exception as _iapt_v124_exc:
    print('IAPT_V124_TASK_LIST_ANCIENT_INSTALL_FAILED', repr(_iapt_v124_exc), flush=True)
# IAPT_V124_TASK_LIST_ANCIENT_END

# IAPT_V126_LOGIN_405_V3LABEL_BEGIN
try:
    import os as _iapt_v126_os
    IAPT_V126_VERSION = 'V126-shared-submit-no-path-rewrite-strict-family'

    def _iapt_v126_bool(v):
        if v is True or v == 1:
            return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y')

    def _iapt_v126_strict_ancient_options(options):
        options = options if isinstance(options, dict) else {}
        for k in ('decrypt_scheme','decrypt_version','task_version','public_scheme','client_final_scheme'):
            v = str(options.get(k) or '').strip().lower()
            if v in ('v3','v6','modern','new'):
                return False
            if v == 'ancient':
                return True
        path = str(options.get('client_submission_path') or '').strip().lower()
        lock = str(options.get('client_route_lock') or '').strip().lower()
        if path in ('decrypt-ancient','ancient-decrypt'):
            return True
        if lock.startswith('ancient-endpoint') or lock.startswith('ancient-shared'):
            return True
        if _iapt_v126_bool(options.get('legacy_iapp')) or _iapt_v126_bool(options.get('old_iapp')):
            return True
        return False

    globals()['_iapt_v121_is_ancient_options'] = _iapt_v126_strict_ancient_options

    @app.get('/api/system/iapt-v126', include_in_schema=False)
    def _iapt_v126_status():
        return {
            'ok': True,
            'version': IAPT_V126_VERSION,
            'ancient_submit_path': 'shared /tasks/decrypt; no path rewrite middleware',
            'v125_path_rewrite_removed': True,
            'strict_ancient_classifier': True,
            'four_char_sokey_is_not_family_detector': True,
            'enum_workers': int(_iapt_v126_os.environ.get('IAPT_ENUM_WORKERS','32') or 32),
        }

    print('[IAPT_V126] shared submit + strict classifier installed', flush=True)
except Exception as _iapt_v126_exc:
    print('[IAPT_V126] install failed:', repr(_iapt_v126_exc), flush=True)
# IAPT_V126_LOGIN_405_V3LABEL_END

# IAPT_V130H_STATUS_SUMMARY_BEGIN
try:
    import json as _j
    from starlette.responses import Response as _Resp
    IAPT_V130H_MAIN_VERSION = 'V130H-ancient-engine-hardtimeout-patchfix'

    def _v130h_load(raw):
        try:
            if isinstance(raw, dict): return raw
            if isinstance(raw, str) and raw.strip():
                x = _j.loads(raw); return x if isinstance(x, dict) else {}
        except Exception: pass
        return {}

    def _v130h_is_ancient_item(it):
        if not isinstance(it, dict): return False
        opt = _v130h_load(it.get('options_json'))
        merged = {}; merged.update(opt); merged.update({k:v for k,v in it.items() if k != 'options_json'})
        for k in ('client_final_scheme','decrypt_scheme','task_version','public_scheme','decrypt_version'):
            if str(merged.get(k) or '').strip().lower() == 'ancient': return True
        if str(merged.get('client_submission_path') or '').strip().lower() in ('decrypt-ancient','ancient-decrypt'): return True
        if str(merged.get('client_route_lock') or '').strip().lower().startswith('ancient'): return True
        if str(merged.get('v3_upload_mode') or '').startswith('ancient_'): return True
        if merged.get('legacy_iapp') is True or merged.get('old_iapp') is True: return True
        return False

    def _v130h_clean_summary(text, ancient):
        lines = []
        for line in str(text or '').split('\n'):
            line = line.strip()
            if not line: continue
            if ancient and ('新版 V3' in line or '方案：V3' in line or '包名.project' in line): continue
            if (not ancient) and ('远古' in line or 'old-iApp' in line): continue
            if line not in lines: lines.append(line)
        if ancient and not any(x.startswith('方案：远古') or x == '方案：远古' for x in lines):
            lines.insert(0, '方案：远古')
        return '\n'.join(lines)

    def _v130h_patch_obj(it):
        if not isinstance(it, dict): return
        ancient = _v130h_is_ancient_item(it)
        if ancient:
            for k in ('decrypt_version','task_version','public_scheme','decrypt_scheme','task_family'):
                it[k] = 'ancient'
            it['decrypt_summary'] = _v130h_clean_summary(it.get('decrypt_summary'), True)
        else:
            if 'decrypt_summary' in it:
                it['decrypt_summary'] = _v130h_clean_summary(it.get('decrypt_summary'), False)

    def _v130h_walk(x):
        if isinstance(x, dict):
            if x.get('id') or x.get('task_id') or x.get('task_no'):
                _v130h_patch_obj(x)
            for v in list(x.values()): _v130h_walk(v)
        elif isinstance(x, list):
            for v in x: _v130h_walk(v)

    @app.middleware('http')
    async def _v130h_single_scheme_summary(request, call_next):
        resp = await call_next(request)
        path = str(getattr(request.url, 'path', '') or '')
        if not (path.startswith('/tasks') or path.startswith('/api/tasks') or path.startswith('/admin/tasks') or path.startswith('/api/admin/tasks')):
            return resp
        ctype = str(getattr(resp, 'headers', {}).get('content-type','') or '').lower()
        if 'json' not in ctype: return resp
        body = b''
        try:
            async for chunk in resp.body_iterator: body += chunk
            data = _j.loads(body.decode('utf-8','ignore') or '{}')
            _v130h_walk(data)
            body = _j.dumps(data, ensure_ascii=False, separators=(',',':')).encode('utf-8')
            headers = dict(getattr(resp, 'headers', {}) or {}); headers.pop('content-length', None)
            return _Resp(content=body, status_code=resp.status_code, headers=headers, media_type='application/json')
        except Exception:
            return _Resp(content=body, status_code=resp.status_code, headers=dict(getattr(resp,'headers',{}) or {}), media_type=getattr(resp, 'media_type', None))

    @app.get('/api/system/iapt-v130', include_in_schema=False)
    def _iapt_v130h_status():
        import os as _os
        return {'ok': True, 'version': IAPT_V130H_MAIN_VERSION, 'ancient_timeout_sec': int(_os.environ.get('IAPT_ANCIENT_TIMEOUT_SEC','180') or 180), 'fast_old_engine_installed': True, 'direct_ancient_runner': True, 'enum_workers': int(_os.environ.get('IAPT_ENUM_WORKERS','32') or 32), 'patchfix': True}
except Exception as _e:
    print('[IAPT_V130H main] install failed', repr(_e), flush=True)
# IAPT_V130H_STATUS_SUMMARY_END

# IAPT_V131_STATUS_BEGIN
try:
    @app.get('/api/system/iapt-v131', include_in_schema=False)
    def _iapt_v131_status():
        from .ancient_supervisor_v131 import describe
        data = describe()
        data['ok'] = True
        return data
except Exception as _iapt_v131_status_error:
    print('[V131 status] install failed', repr(_iapt_v131_status_error), flush=True)
# IAPT_V131_STATUS_END

# IAPT_V132_STATUS_BEGIN
try:
    @app.get('/api/system/iapt-v132', include_in_schema=False)
    def _iapt_v132_status():
        from .ancient_supervisor_v131 import describe
        data=describe()
        data['ok']=True
        return data
except Exception as _iapt_v132_status_error:
    print('[V132 status] install failed', repr(_iapt_v132_status_error), flush=True)
# IAPT_V132_STATUS_END

# IAPT_V133_NATIVE_SKIP_NULL_STATUS_BEGIN
@app.get('/api/system/iapt-v133', include_in_schema=False)
def _iapt_v133_status():
    from .ancient_supervisor_v131 import describe as _v133_describe
    from .tools.iapt_v10 import iapp_old_decrypt as _v133_old
    data = dict(_v133_describe())
    data.update({
        'ok': True,
        'version': 'V133-native-skip-null-ancient-engine',
        'native_skip_signature_component': 'null',
        'old_failed_running_masks_removed': True,
        'single_scheme_summary': True,
        'fast_c_binary': bool(_v133_old._fast_enum_binary()),
    })
    return data
# IAPT_V133_NATIVE_SKIP_NULL_STATUS_END

# IAPT_V135_MANAGED_QUEUE_STATUS_BEGIN
@app.get('/api/system/iapt-v135', include_in_schema=False)
def _iapt_v135_status():
    import json, time
    from pathlib import Path
    from .config import APP_STORAGE
    from .decrypt_queue import queue_runtime_config
    heartbeat = {}
    hp = Path(APP_STORAGE) / 'queue_v135.heartbeat.json'
    try:
        heartbeat = json.loads(hp.read_text(encoding='utf-8')) if hp.is_file() else {}
    except Exception:
        heartbeat = {}
    age = None
    try:
        age = round(time.time() - float(heartbeat.get('time')), 3)
    except Exception:
        pass
    return {
        'ok': True,
        'version': 'V135-managed-worker-service-recovery',
        'queue': queue_runtime_config(),
        'heartbeat': heartbeat,
        'heartbeat_age_sec': age,
        'v134_detached_workers_removed': True,
        'restart_kills_worker_cgroup': True,
    }
# IAPT_V135_MANAGED_QUEUE_STATUS_END

# IAPT_V136_CLEAN_SERVICE_STATUS_BEGIN
@app.get('/api/system/iapt-v136', include_in_schema=False)
def _iapt_v136_status():
    import json,time,os
    from pathlib import Path
    from .config import APP_STORAGE
    from .decrypt_queue import queue_runtime_config
    hp=Path(APP_STORAGE)/'queue_v136.heartbeat.json'; hb={}
    try: hb=json.loads(hp.read_text(encoding='utf-8')) if hp.is_file() else {}
    except Exception: hb={}
    try: age=round(time.time()-float(hb.get('time')),3)
    except Exception: age=None
    return {'ok':True,'version':'V136-clean-single-api-worker','api_pid':os.getpid(),'queue':queue_runtime_config(),'heartbeat':hb,'heartbeat_age_sec':age,'old_services_disabled':True,'client_transport':'keep-alive'}
# IAPT_V136_CLEAN_SERVICE_STATUS_END

# IAPT_V152_MAIN_OUTPUT_DELEGATE_BEGIN
try:
    def list_task_files(task_or_id):
        from . import decrypt_runner as _iapt_v152_runner
        return _iapt_v152_runner.list_task_files(task_or_id)

    def _finish_public_file_rows(task, files=None):
        from . import decrypt_runner as _iapt_v152_runner
        return _iapt_v152_runner._finish_public_file_rows(task, files)

    @app.get('/api/system/iapt-v152-output', include_in_schema=False)
    def _iapt_v152_output_status():
        from . import decrypt_runner as _iapt_v152_runner
        return {
            'ok': True,
            'version': 'V152-main-output-delegate',
            'policy': getattr(_iapt_v152_runner, 'IAPT_V152_NONV3_PUBLIC_OUTPUT', {}),
        }
    print('IAPT_V152_MAIN_OUTPUT_DELEGATE installed')
except Exception as _iapt_v152_main_error:
    try:
        print('IAPT_V152_MAIN_OUTPUT_DELEGATE_FAILED', repr(_iapt_v152_main_error))
    except Exception:
        pass
# IAPT_V152_MAIN_OUTPUT_DELEGATE_END

# IAPT_V200_FOXPAY_RECHARGE_BEGIN
try:
    import hmac as _iapt_fp_hmac
    import html as _iapt_fp_html
    import urllib.parse as _iapt_fp_urlparse
    import urllib.request as _iapt_fp_urlrequest
    from datetime import datetime as _iapt_fp_datetime
    from fastapi.responses import HTMLResponse as _IaptFoxHtmlResponse, PlainTextResponse as _IaptFoxTextResponse

    def _iapt_fp_env(name, default=''):
        return str(os.environ.get(name, default) or default).strip()

    IAPT_FOXPAY_BASE_URL = _iapt_fp_env('FOXPAY_BASE_URL', 'https://foxpay.top/xpay/epay').rstrip('/')
    IAPT_FOXPAY_SUBMIT_URL = IAPT_FOXPAY_BASE_URL + '/submit.php'
    IAPT_FOXPAY_MAPI_URL = IAPT_FOXPAY_BASE_URL + '/mapi.php'
    IAPT_FOXPAY_API_URL = IAPT_FOXPAY_BASE_URL + '/api.php'
    IAPT_FOXPAY_PID = _iapt_fp_env('FOXPAY_PID')
    IAPT_FOXPAY_KEY = _iapt_fp_env('FOXPAY_KEY')
    IAPT_FOXPAY_PRODUCT_NAME = _iapt_fp_env('FOXPAY_PRODUCT_NAME', 'IAPT余额充值')[:127]

    def _iapt_fp_int(name, default, lo, hi):
        try:
            value = int(_iapt_fp_env(name, str(default)))
        except Exception:
            value = int(default)
        return max(int(lo), min(int(hi), value))

    IAPT_FOXPAY_MIN_AMOUNT = _iapt_fp_int('FOXPAY_MIN_AMOUNT', 1, 1, 1000000)
    IAPT_FOXPAY_MAX_AMOUNT = _iapt_fp_int('FOXPAY_MAX_AMOUNT', 10000, IAPT_FOXPAY_MIN_AMOUNT, 1000000)
    IAPT_FOXPAY_BALANCE_RATE = _iapt_fp_int('FOXPAY_BALANCE_RATE', 1, 1, 100000)
    IAPT_FOXPAY_ENABLED = _iapt_fp_env('FOXPAY_ENABLED', '1').lower() in ('1', 'true', 'yes', 'on')

    def _iapt_fp_public_base():
        base = str(getattr(__import__('app.config', fromlist=['PUBLIC_BASE_URL']), 'PUBLIC_BASE_URL', '') or '').rstrip('/')
        return base

    def _iapt_fp_ready():
        base = _iapt_fp_public_base()
        return bool(IAPT_FOXPAY_ENABLED and IAPT_FOXPAY_PID and IAPT_FOXPAY_KEY and base.startswith(('http://', 'https://')))

    def _iapt_fp_sign(params):
        pairs = []
        for key in sorted(params.keys()):
            if key in ('sign', 'sign_type'):
                continue
            value = params.get(key)
            if value is None or str(value) == '':
                continue
            pairs.append(str(key) + '=' + str(value))
        raw = '&'.join(pairs) + IAPT_FOXPAY_KEY
        return hashlib.md5(raw.encode('utf-8')).hexdigest().lower()

    def _iapt_fp_verify(params):
        supplied = str((params or {}).get('sign') or '').strip().lower()
        return bool(supplied and _iapt_fp_hmac.compare_digest(supplied, _iapt_fp_sign(params or {})))

    def _iapt_fp_money(value):
        try:
            return Decimal(str(value)).quantize(Decimal('0.01'))
        except Exception:
            raise HTTPException(400, '充值金额格式错误')

    def _iapt_fp_order_public(row):
        row = row or {}
        return {
            'out_trade_no': str(row.get('out_trade_no') or ''),
            'trade_no': str(row.get('trade_no') or ''),
            'type': str(row.get('pay_type') or ''),
            'money': format(_iapt_fp_money(row.get('money') or 0), '.2f'),
            'credit_balance': int(row.get('credit_balance') or 0),
            'status': str(row.get('status') or 'pending'),
            'paid_at': str(row.get('paid_at') or ''),
            'created_at': str(row.get('created_at') or ''),
            'updated_at': str(row.get('updated_at') or ''),
        }

    def _iapt_fp_json_request(url, form=None, timeout=20):
        data = None
        method = 'GET'
        if form is not None:
            data = _iapt_fp_urlparse.urlencode({k: str(v) for k, v in form.items()}).encode('utf-8')
            method = 'POST'
        req = _iapt_fp_urlrequest.Request(
            url,
            data=data,
            method=method,
            headers={
                'User-Agent': 'Mozilla/5.0 (Linux; Android 14) IAPT-FoxPay/2.0',
                'Accept': 'application/json,text/plain,*/*',
                'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            },
        )
        with _iapt_fp_urlrequest.urlopen(req, timeout=timeout) as resp:
            raw = resp.read(1024 * 1024).decode('utf-8', 'replace').strip()
        try:
            obj = json.loads(raw)
        except Exception:
            raise RuntimeError('FoxPay 返回了非 JSON 数据：' + raw[:200])
        if not isinstance(obj, dict):
            raise RuntimeError('FoxPay 返回格式错误')
        return obj

    def _iapt_fp_notify_url():
        return _iapt_fp_public_base() + '/api/payments/foxpay/notify'

    def _iapt_fp_return_url():
        return _iapt_fp_public_base() + '/api/payments/foxpay/return'

    def _iapt_fp_create_schema():
        db.exec('''
            CREATE TABLE IF NOT EXISTS payment_orders (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                out_trade_no VARCHAR(64) NOT NULL UNIQUE,
                trade_no VARCHAR(96) NULL,
                user_id BIGINT NOT NULL,
                pay_type VARCHAR(16) NOT NULL,
                product_name VARCHAR(127) NOT NULL,
                money DECIMAL(12,2) NOT NULL,
                credit_balance INT NOT NULL,
                status VARCHAR(16) NOT NULL DEFAULT 'pending',
                checkout_token CHAR(64) NOT NULL UNIQUE,
                pay_url VARCHAR(2048) NULL,
                gateway_payload LONGTEXT NULL,
                paid_at DATETIME NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                INDEX idx_payment_user(user_id,id),
                INDEX idx_payment_status(status,created_at),
                INDEX idx_payment_trade_no(trade_no)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')
        db.exec('''
            CREATE TABLE IF NOT EXISTS payment_events (
                id BIGINT PRIMARY KEY AUTO_INCREMENT,
                out_trade_no VARCHAR(64) NOT NULL,
                event_type VARCHAR(32) NOT NULL,
                verified TINYINT NOT NULL DEFAULT 0,
                payload_json LONGTEXT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                INDEX idx_payment_event_order(out_trade_no,id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        ''')

    @app.on_event('startup')
    def _iapt_fp_startup_schema():
        try:
            _iapt_fp_create_schema()
            print('IAPT_V200_FOXPAY schema ready', flush=True)
        except Exception as exc:
            print('IAPT_V200_FOXPAY schema failed ' + repr(exc), flush=True)

    def _iapt_fp_log_event(order_no, event_type, verified, payload):
        try:
            db.exec(
                'INSERT INTO payment_events(out_trade_no,event_type,verified,payload_json) VALUES(%s,%s,%s,%s)',
                (str(order_no or '')[:64], str(event_type or '')[:32], 1 if verified else 0,
                 json.dumps(payload or {}, ensure_ascii=False, separators=(',', ':'))[:65535]),
            )
        except Exception as exc:
            print('IAPT_V200_FOXPAY event log warning ' + repr(exc), flush=True)

    def _iapt_fp_settle(out_trade_no, trade_no, money, payload, source):
        expected_money = _iapt_fp_money(money)
        payload_text = json.dumps(payload or {}, ensure_ascii=False, separators=(',', ':'))[:65535]

        def txn(cur):
            cur.execute('SELECT * FROM payment_orders WHERE out_trade_no=%s FOR UPDATE', (out_trade_no,))
            row = cur.fetchone()
            if not row:
                raise ValueError('order_not_found')
            if _iapt_fp_money(row.get('money') or 0) != expected_money:
                raise ValueError('money_mismatch')
            if str(row.get('status') or '') == 'paid':
                return row, False
            cur.execute(
                "UPDATE payment_orders SET status='paid',trade_no=%s,gateway_payload=%s,paid_at=NOW() WHERE id=%s",
                (str(trade_no or '')[:96], payload_text, int(row['id'])),
            )
            cur.execute('UPDATE users SET balance=balance+%s WHERE id=%s', (int(row.get('credit_balance') or 0), int(row['user_id'])))
            cur.execute('SELECT * FROM payment_orders WHERE id=%s', (int(row['id']),))
            return cur.fetchone(), True

        row, credited = db.transaction(txn)
        _iapt_fp_log_event(out_trade_no, 'settle_' + str(source or 'unknown')[:20], True, payload)
        return row, credited

    def _iapt_fp_query_gateway(out_trade_no):
        query = _iapt_fp_urlparse.urlencode({
            'act': 'order',
            'pid': IAPT_FOXPAY_PID,
            'key': IAPT_FOXPAY_KEY,
            'out_trade_no': out_trade_no,
        })
        return _iapt_fp_json_request(IAPT_FOXPAY_API_URL + '?' + query, None, timeout=15)

    def _iapt_fp_reconcile(row):
        if not row or str(row.get('status') or '') == 'paid':
            return row
        result = _iapt_fp_query_gateway(str(row.get('out_trade_no') or ''))
        _iapt_fp_log_event(row.get('out_trade_no'), 'query', True, result)
        try:
            paid = int(result.get('status') or 0) == 1 and int(result.get('code') or 0) == 1
        except Exception:
            paid = str(result.get('status') or '') == '1' and str(result.get('code') or '') == '1'
        if paid:
            gateway_money = _iapt_fp_money(result.get('money') or row.get('money') or 0)
            settled, _ = _iapt_fp_settle(
                str(row.get('out_trade_no') or ''),
                str(result.get('trade_no') or ''),
                gateway_money,
                result,
                'query',
            )
            return settled
        return row

    @app.get('/api/payments/config')
    def iapt_foxpay_config(user=Depends(current_user)):
        message = ''
        if not _iapt_fp_ready():
            message = '服务器尚未配置 FoxPay 商户ID、商户密钥或公网回调地址'
        return {
            'enabled': _iapt_fp_ready(),
            'message': message,
            'provider': 'FoxPay 易支付',
            'base_url': IAPT_FOXPAY_BASE_URL,
            'min_amount': IAPT_FOXPAY_MIN_AMOUNT,
            'max_amount': IAPT_FOXPAY_MAX_AMOUNT,
            'balance_rate': IAPT_FOXPAY_BALANCE_RATE,
            'types': ['alipay', 'wxpay', 'cashier'],
        }

    @app.post('/api/payments/create')
    async def iapt_foxpay_create(request: Request, user=Depends(current_user)):
        if not _iapt_fp_ready():
            raise HTTPException(503, '在线充值未配置完成')
        token = request.headers.get('authorization', '').split(' ', 1)[1] if request.headers.get('authorization') else ''
        body = await read_secure_json(request, token, verify=False)
        money = _iapt_fp_money((body or {}).get('amount'))
        if money != money.to_integral_value():
            raise HTTPException(400, '充值金额必须是整数元')
        amount = int(money)
        if amount < IAPT_FOXPAY_MIN_AMOUNT or amount > IAPT_FOXPAY_MAX_AMOUNT:
            raise HTTPException(400, f'充值金额必须在 {IAPT_FOXPAY_MIN_AMOUNT}-{IAPT_FOXPAY_MAX_AMOUNT} 元之间')
        pay_type = str((body or {}).get('type') or 'cashier').strip().lower()
        if pay_type not in ('alipay', 'wxpay', 'cashier'):
            raise HTTPException(400, '不支持的支付方式')

        now = _iapt_fp_datetime.now().strftime('%Y%m%d%H%M%S')
        out_trade_no = ('IAPT' + now + str(int(user['id']))[-8:] + secrets.token_hex(5)).upper()[:64]
        checkout_token = secrets.token_hex(32)
        credit_balance = int(amount * IAPT_FOXPAY_BALANCE_RATE)
        product_name = IAPT_FOXPAY_PRODUCT_NAME
        db.exec(
            '''INSERT INTO payment_orders(out_trade_no,user_id,pay_type,product_name,money,credit_balance,status,checkout_token)
               VALUES(%s,%s,%s,%s,%s,%s,'pending',%s)''',
            (out_trade_no, int(user['id']), pay_type, product_name, format(money, '.2f'), credit_balance, checkout_token),
        )

        common = {
            'pid': IAPT_FOXPAY_PID,
            'out_trade_no': out_trade_no,
            'notify_url': _iapt_fp_notify_url(),
            'return_url': _iapt_fp_return_url(),
            'name': product_name,
            'money': format(money, '.2f'),
            'param': 'user:' + str(int(user['id'])),
            'sign_type': 'MD5',
        }
        try:
            if pay_type == 'cashier':
                pay_url = _iapt_fp_public_base() + '/api/payments/foxpay/checkout/' + checkout_token
                gateway = {'code': 1, 'msg': 'cashier', 'payurl': pay_url}
            else:
                form = dict(common)
                form.update({
                    'type': pay_type,
                    'clientip': client_ip(request),
                    'device': 'mobile',
                })
                form['sign'] = _iapt_fp_sign(form)
                gateway = _iapt_fp_json_request(IAPT_FOXPAY_MAPI_URL, form, timeout=20)
                try:
                    ok = int(gateway.get('code') or 0) == 1
                except Exception:
                    ok = str(gateway.get('code') or '') == '1'
                if not ok:
                    raise RuntimeError(str(gateway.get('msg') or 'FoxPay 创建订单失败'))
                pay_url = str(gateway.get('payurl') or gateway.get('qrcode') or gateway.get('urlscheme') or '').strip()
                if not pay_url:
                    raise RuntimeError('FoxPay 未返回支付地址')
            db.exec(
                'UPDATE payment_orders SET trade_no=%s,pay_url=%s,gateway_payload=%s WHERE out_trade_no=%s',
                (str(gateway.get('trade_no') or '')[:96], pay_url[:2048],
                 json.dumps(gateway, ensure_ascii=False, separators=(',', ':'))[:65535], out_trade_no),
            )
            _iapt_fp_log_event(out_trade_no, 'create', True, gateway)
        except Exception as exc:
            db.exec("UPDATE payment_orders SET status='failed',gateway_payload=%s WHERE out_trade_no=%s", (str(exc)[:2000], out_trade_no))
            _iapt_fp_log_event(out_trade_no, 'create_failed', False, {'error': str(exc)})
            raise HTTPException(502, 'FoxPay 创建订单失败：' + str(exc))

        return {
            'ok': True,
            'provider': 'FoxPay 易支付',
            'out_trade_no': out_trade_no,
            'pay_url': pay_url,
            'money': format(money, '.2f'),
            'credit_balance': credit_balance,
            'status': 'pending',
        }

    @app.get('/api/payments/foxpay/checkout/{checkout_token}', response_class=_IaptFoxHtmlResponse)
    def iapt_foxpay_checkout(checkout_token: str):
        if not _iapt_fp_ready():
            return _IaptFoxHtmlResponse('<h3>在线充值未配置完成</h3>', status_code=503)
        row = db.one('SELECT * FROM payment_orders WHERE checkout_token=%s LIMIT 1', (checkout_token,))
        if not row:
            return _IaptFoxHtmlResponse('<h3>支付订单不存在</h3>', status_code=404)
        if str(row.get('status') or '') == 'paid':
            return _IaptFoxHtmlResponse('<h3>该订单已支付，请返回软件查看余额。</h3>')
        form = {
            'pid': IAPT_FOXPAY_PID,
            'out_trade_no': str(row.get('out_trade_no') or ''),
            'notify_url': _iapt_fp_notify_url(),
            'return_url': _iapt_fp_return_url(),
            'name': str(row.get('product_name') or IAPT_FOXPAY_PRODUCT_NAME)[:127],
            'money': format(_iapt_fp_money(row.get('money') or 0), '.2f'),
            'param': 'user:' + str(int(row.get('user_id') or 0)),
            'sign_type': 'MD5',
        }
        form['sign'] = _iapt_fp_sign(form)
        fields = ''.join(
            '<input type="hidden" name="' + _iapt_fp_html.escape(str(k), quote=True) + '" value="' +
            _iapt_fp_html.escape(str(v), quote=True) + '">' for k, v in form.items()
        )
        html_doc = '''<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
        <title>正在进入 FoxPay</title></head><body style="font-family:sans-serif;text-align:center;padding:48px 16px">
        <h3>正在进入 FoxPay 收银台…</h3><form id="foxpay" method="post" action="%s">%s
        <button type="submit">未自动跳转时点击继续</button></form><script>document.getElementById('foxpay').submit();</script></body></html>''' % (
            _iapt_fp_html.escape(IAPT_FOXPAY_SUBMIT_URL, quote=True), fields)
        return _IaptFoxHtmlResponse(html_doc)

    @app.get('/api/payments/foxpay/notify', response_class=_IaptFoxTextResponse)
    def iapt_foxpay_notify(request: Request):
        params = {str(k): str(v) for k, v in request.query_params.items()}
        verified = _iapt_fp_verify(params) and str(params.get('pid') or '') == IAPT_FOXPAY_PID
        out_trade_no = str(params.get('out_trade_no') or '')
        _iapt_fp_log_event(out_trade_no, 'notify', verified, params)
        if not verified or str(params.get('trade_status') or '') != 'TRADE_SUCCESS':
            return _IaptFoxTextResponse('fail', status_code=400)
        try:
            _iapt_fp_settle(out_trade_no, params.get('trade_no'), params.get('money'), params, 'notify')
        except Exception as exc:
            print('IAPT_V200_FOXPAY notify settle failed ' + repr(exc), flush=True)
            return _IaptFoxTextResponse('fail', status_code=400)
        return _IaptFoxTextResponse('success')

    @app.get('/api/payments/foxpay/return', response_class=_IaptFoxHtmlResponse)
    def iapt_foxpay_return(request: Request):
        params = {str(k): str(v) for k, v in request.query_params.items()}
        verified = _iapt_fp_verify(params) and str(params.get('pid') or '') == IAPT_FOXPAY_PID
        success = verified and str(params.get('trade_status') or '') == 'TRADE_SUCCESS'
        if success:
            try:
                _iapt_fp_settle(str(params.get('out_trade_no') or ''), params.get('trade_no'), params.get('money'), params, 'return')
            except Exception as exc:
                success = False
                print('IAPT_V200_FOXPAY return settle failed ' + repr(exc), flush=True)
        title = '支付成功，余额已到账' if success else '支付结果尚未确认'
        detail = '请返回 IAPT 软件，在充值记录中检查到账。' if success else '请返回软件点击“检查到账”，服务器会向 FoxPay 查询订单。'
        return _IaptFoxHtmlResponse('<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head><body style="font-family:sans-serif;text-align:center;padding:48px 20px"><h2>' + title + '</h2><p>' + detail + '</p></body></html>')

    @app.get('/api/payments/status/{out_trade_no}')
    def iapt_foxpay_status(out_trade_no: str, refresh: int = Query(default=0), user=Depends(current_user)):
        row = db.one('SELECT * FROM payment_orders WHERE out_trade_no=%s AND user_id=%s LIMIT 1', (out_trade_no, int(user['id'])))
        if not row:
            raise HTTPException(404, '充值订单不存在')
        if int(refresh or 0) and str(row.get('status') or '') == 'pending' and _iapt_fp_ready():
            try:
                row = _iapt_fp_reconcile(row)
            except Exception as exc:
                _iapt_fp_log_event(out_trade_no, 'query_failed', False, {'error': str(exc)})
        fresh = db.one('SELECT * FROM payment_orders WHERE out_trade_no=%s AND user_id=%s LIMIT 1', (out_trade_no, int(user['id']))) or row
        return {'ok': True, 'order': _iapt_fp_order_public(fresh)}

    @app.get('/api/payments/orders')
    def iapt_foxpay_orders(limit: int = Query(default=50, ge=1, le=200), user=Depends(current_user)):
        rows = db.all('SELECT * FROM payment_orders WHERE user_id=%s ORDER BY id DESC LIMIT %s', (int(user['id']), int(limit))) or []
        return {'items': [_iapt_fp_order_public(row) for row in rows]}

    IAPT_V200_FOXPAY_RECHARGE = {
        'provider': 'FoxPay 易支付',
        'base_url': IAPT_FOXPAY_BASE_URL,
        'submit_url': IAPT_FOXPAY_SUBMIT_URL,
        'mapi_url': IAPT_FOXPAY_MAPI_URL,
        'api_url': IAPT_FOXPAY_API_URL,
        'notify': '/api/payments/foxpay/notify',
        'return': '/api/payments/foxpay/return',
        'signature': 'MD5 ASCII sort, exclude sign/sign_type/empty',
        'idempotent_credit': True,
    }
    print('IAPT_V200_FOXPAY_RECHARGE installed', flush=True)
except Exception as _iapt_fp_install_error:
    try:
        print('IAPT_V200_FOXPAY_RECHARGE_FAILED ' + repr(_iapt_fp_install_error), flush=True)
    except Exception:
        pass
# IAPT_V200_FOXPAY_RECHARGE_END

# IAPT_V154_TASK_COUNT_STABLE_GATE_BEGIN
# Stable direct task-list layer for mobile and admin pages.
# Fixes: task count mismatch, missing offset support for /admin/tasks,
# no-store list responses, and compatibility fields for old clients.
try:
    import json as _iapt_v154_json
    import time as _iapt_v154_time
    from decimal import Decimal as _iapt_v154_Decimal
    from fastapi import HTTPException as _iapt_v154_HTTPException
    from fastapi.responses import Response as _iapt_v154_Response

    IAPT_V154_VERSION = 'V154-stable-task-count-offset-client-compatible'
    _IAPT_V154_COL_CACHE = {'ts': 0.0, 'cols': set()}

    def _iapt_v154_no_store(data, status=200):
        def conv(v):
            if isinstance(v, _iapt_v154_Decimal):
                return str(v)
            if hasattr(v, 'isoformat'):
                try:
                    return v.isoformat()
                except Exception:
                    return str(v)
            return str(v)
        body = _iapt_v154_json.dumps(data, ensure_ascii=False, default=conv, separators=(',', ':')).encode('utf-8')
        return _iapt_v154_Response(
            content=body,
            status_code=int(status),
            media_type='application/json; charset=utf-8',
            headers={
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma': 'no-cache',
                'Expires': '0',
                'X-Accel-Buffering': 'no',
                'X-IAPT-Task-List-Gate': IAPT_V154_VERSION,
            },
        )

    def _iapt_v154_auth_user(request):
        try:
            return current_user(request, authorization=request.headers.get('authorization'))
        except _iapt_v154_HTTPException:
            raise
        except Exception as exc:
            raise _iapt_v154_HTTPException(401, '登录校验失败：' + str(exc))

    def _iapt_v154_task_cols():
        now = _iapt_v154_time.monotonic()
        if _IAPT_V154_COL_CACHE['cols'] and now - float(_IAPT_V154_COL_CACHE['ts'] or 0) < 60:
            return set(_IAPT_V154_COL_CACHE['cols'])
        try:
            rows = db.all('SHOW COLUMNS FROM tasks') or []
            cols = {str((r or {}).get('Field') or (r or {}).get('COLUMN_NAME') or '').strip() for r in rows}
            cols.discard('')
            _IAPT_V154_COL_CACHE['cols'] = cols
            _IAPT_V154_COL_CACHE['ts'] = now
            return cols
        except Exception as exc:
            print('[IAPT_V154] SHOW COLUMNS failed:', repr(exc), flush=True)
            return {'id','task_no','user_id','apk_name','app_name','package_name','version_name','version_code','status','feature_id','decrypt_version','file_count','total_bytes','downloadable_file_count','created_at','updated_at','error_text','options_json'}

    def _iapt_v154_i(v, default=0):
        try:
            if v is None or v == '': return default
            return int(v)
        except Exception:
            return default

    def _iapt_v154_qp_int(request, key, default, low, high):
        try:
            n = int(str(request.query_params.get(key, str(default)) or default).strip())
        except Exception:
            n = default
        return max(low, min(n, high))

    def _iapt_v154_load_opt(v):
        if isinstance(v, dict):
            return dict(v)
        try:
            s = str(v or '').strip()
            if s:
                o = _iapt_v154_json.loads(s)
                return o if isinstance(o, dict) else {}
        except Exception:
            pass
        return {}

    def _iapt_v154_bool(v):
        if v is True or v == 1: return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y','auto')

    def _iapt_v154_is_ancient(row, opt):
        merged = {}
        try: merged.update(opt if isinstance(opt, dict) else {})
        except Exception: pass
        try: merged.update({k: v for k, v in dict(row or {}).items() if k != 'options_json'})
        except Exception: pass
        for k in ('client_final_scheme','decrypt_scheme','task_version','public_scheme','decrypt_version'):
            v = str(merged.get(k) or '').strip().lower()
            if v in ('v3','v6','modern','new','key'):
                return False
            if v in ('ancient','old','legacy','old_iapp','iapp_old'):
                return True
        p = str(merged.get('client_submission_path') or '').strip().lower()
        lock = str(merged.get('client_route_lock') or '').strip().lower()
        return p in ('decrypt-ancient','ancient-decrypt') or lock.startswith('ancient') or _iapt_v154_bool(merged.get('legacy_iapp')) or _iapt_v154_bool(merged.get('old_iapp'))

    def _iapt_v154_output_count(row):
        for k in ('client_output_file_count','downloadable_file_count','downloadable_files','output_file_count','result_file_count','decrypted_file_count','download_file_count','result_files_count','output_files_count','file_count'):
            n = _iapt_v154_i((row or {}).get(k), 0)
            if n > 0:
                return n
        return 0

    def _iapt_v154_public_row(row):
        r = dict(row or {})
        opt = _iapt_v154_load_opt(r.get('options_json'))
        ancient = _iapt_v154_is_ancient(r, opt)
        fid = _iapt_v154_i(r.get('feature_id'), 0)
        if fid <= 0:
            fid = int(globals().get('FEATURE_BASIC', 1) or 1)
        if ancient:
            dec = 'ancient'
            if fid == 6:
                fid = _iapt_v154_i(opt.get('primary_feature_id') or opt.get('feature_id'), int(globals().get('FEATURE_BASIC', 1) or 1))
                if fid == 6:
                    fid = int(globals().get('FEATURE_BASIC', 1) or 1)
        else:
            kind = str(opt.get('task_kind') or '').strip().lower()
            opt_dec = str(opt.get('decrypt_version') or opt.get('task_version') or r.get('decrypt_version') or '').strip().lower()
            if kind == 'dynamic_key_extract' or _iapt_v154_bool(opt.get('dynamic_key_extract')):
                dec = 'key'
            elif opt_dec == 'v6' or fid == 6:
                dec = 'v6'; fid = 6
            else:
                dec = opt_dec or 'v3'
        r['feature_id'] = fid
        r['decrypt_version'] = dec
        r['task_version'] = dec
        r['task_family'] = dec
        if r.get('id') is not None:
            r['task_id'] = r.get('id')
        if not str(r.get('app_name') or '').strip():
            r['app_name'] = r.get('apk_name') or r.get('package_name') or ''
        oc = _iapt_v154_output_count(r)
        if oc > 0:
            r['client_output_file_count'] = oc
            r['downloadable_file_count'] = oc
        r.pop('options_json', None)
        return r

    def _iapt_v154_where_user(request, user):
        return 'WHERE t.user_id=%s', [int(user.get('id'))]

    def _iapt_v154_where_admin(request):
        wh, params = [], []
        user_id = _iapt_v154_qp_int(request, 'user_id', 0, 0, 2147483647)
        st = str(request.query_params.get('status','') or '').strip()
        kw = str(request.query_params.get('keyword','') or '').strip()
        if user_id:
            wh.append('t.user_id=%s'); params.append(user_id)
        if st:
            wh.append('t.status=%s'); params.append(st)
        if kw:
            like = '%' + kw + '%'
            wh.append('(t.task_no LIKE %s OR t.apk_name LIKE %s OR t.app_name LIKE %s OR t.package_name LIKE %s OR u.username LIKE %s OR u.name LIKE %s)')
            params.extend([like, like, like, like, like, like])
        return ('WHERE ' + ' AND '.join(wh)) if wh else '', params

    def _iapt_v154_status_counts(where_sql, params, join_user=False):
        try:
            join = ' JOIN users u ON t.user_id=u.id ' if join_user else ''
            rows = db.all('SELECT t.status,COUNT(*) AS c FROM tasks t ' + join + ' ' + where_sql + ' GROUP BY t.status', tuple(params)) or []
            return {str(r.get('status') or 'unknown'): _iapt_v154_i(r.get('c'), 0) for r in rows}
        except Exception as exc:
            print('[IAPT_V154] status count warn:', repr(exc), flush=True)
            return {}

    def _iapt_v154_count(where_sql, params, join_user=False):
        join = ' JOIN users u ON t.user_id=u.id ' if join_user else ''
        row = db.one('SELECT COUNT(*) AS c FROM tasks t ' + join + ' ' + where_sql, tuple(params)) or {}
        return _iapt_v154_i(row.get('c'), 0)

    def _iapt_v154_select_task_rows(where_sql, params, limit, offset, admin=False):
        cols = _iapt_v154_task_cols()
        base = [
            'id','task_no','user_id','apk_name','app_name','package_name','version_name','version_code',
            'status','feature_id','decrypt_version','total_ms','file_count','total_bytes','downloadable_file_count',
            'downloadable_bytes','actual_quota_cost','decrypt_quota_deducted','resource_quota_cost','estimated_quota_cost',
            'quota_limit','quota_note','created_at','updated_at','error_text','out_dir','options_json'
        ]
        selected = [c for c in base if c in cols]
        if 'id' not in selected:
            selected.insert(0, 'id')
        if admin:
            select = ','.join('t.`%s`' % c for c in selected) + ',u.username,u.name AS user_name'
            sql = 'SELECT ' + select + ' FROM tasks t JOIN users u ON t.user_id=u.id ' + where_sql + ' ORDER BY t.id DESC LIMIT %s OFFSET %s'
        else:
            select = ','.join('t.`%s`' % c for c in selected)
            sql = 'SELECT ' + select + ' FROM tasks t ' + where_sql + ' ORDER BY t.id DESC LIMIT %s OFFSET %s'
        return db.all(sql, tuple(params + [limit, offset])) or []

    def _iapt_v154_user_tasks(request, user):
        limit = _iapt_v154_qp_int(request, 'limit', 500, 1, 5000)
        offset = _iapt_v154_qp_int(request, 'offset', 0, 0, 100000000)
        where, params = _iapt_v154_where_user(request, user)
        total = _iapt_v154_count(where, params, False)
        rows = _iapt_v154_select_task_rows(where, params, limit, offset, False)
        items = [_iapt_v154_public_row(r) for r in rows]
        return {
            'ok': True,
            'items': items,
            'count': total,
            'total_count': total,
            'server_task_count': total,
            'returned_count': len(items),
            'visible_count': len(items),
            'limit': limit,
            'offset': offset,
            'next_offset': offset + len(items),
            'has_more': offset + len(items) < total,
            'status_counts': _iapt_v154_status_counts(where, params, False),
            'server_time': int(_iapt_v154_time.time()),
            'list_source': IAPT_V154_VERSION,
            'no_store': True,
        }

    def _iapt_v154_admin_tasks(request, user):
        require_permission(user, PERM_TASK_VIEW_ALL)
        limit = _iapt_v154_qp_int(request, 'limit', 50, 1, 500)
        offset = _iapt_v154_qp_int(request, 'offset', 0, 0, 100000000)
        where, params = _iapt_v154_where_admin(request)
        total = _iapt_v154_count(where, params, True)
        rows = _iapt_v154_select_task_rows(where, params, limit, offset, True)
        items = [_iapt_v154_public_row(r) for r in rows]
        return {
            'ok': True,
            'items': items,
            'count': total,
            'total_count': total,
            'returned_count': len(items),
            'limit': limit,
            'offset': offset,
            'next_offset': offset + len(items),
            'has_more': offset + len(items) < total,
            'status_counts': _iapt_v154_status_counts(where, params, True),
            'me': admin_permissions_public(user),
            'server_time': int(_iapt_v154_time.time()),
            'list_source': IAPT_V154_VERSION,
            'no_store': True,
        }

    @app.middleware('http')
    async def _iapt_v154_task_count_gate(request, call_next):
        path = str(getattr(request.url, 'path', '') or '').rstrip('/') or '/'
        method = str(getattr(request, 'method', '') or '').upper()
        if method == 'GET' and path in ('/api/tasks','/tasks','/api/admin/tasks','/admin/tasks'):
            try:
                user = _iapt_v154_auth_user(request)
                if path in ('/api/admin/tasks','/admin/tasks'):
                    return _iapt_v154_no_store(_iapt_v154_admin_tasks(request, user))
                return _iapt_v154_no_store(_iapt_v154_user_tasks(request, user))
            except _iapt_v154_HTTPException as exc:
                return _iapt_v154_no_store({'ok': False, 'items': [], 'count': 0, 'total_count': 0, 'error': str(getattr(exc, 'detail', exc)), 'list_source': IAPT_V154_VERSION}, getattr(exc, 'status_code', 401) or 401)
            except Exception as exc:
                print('[IAPT_V154] task list direct failed:', repr(exc), flush=True)
                # Do not let historical middleware turn a temporary DB error into a blank cached list.
                return _iapt_v154_no_store({'ok': False, 'items': [], 'count': 0, 'total_count': 0, 'error': '任务列表读取失败：' + str(exc), 'list_source': IAPT_V154_VERSION}, 200)
        return await call_next(request)

    @app.get('/api/system/iapt-v154', include_in_schema=False)
    def _iapt_v154_status():
        return {
            'ok': True,
            'version': IAPT_V154_VERSION,
            'mobile_total_count': True,
            'admin_offset': True,
            'admin_total_count': True,
            'count_means_total': True,
            'returned_count': True,
            'paths': ['/api/tasks','/tasks','/api/admin/tasks','/admin/tasks'],
            'columns_cached': sorted(list(_IAPT_V154_COL_CACHE.get('cols') or []))[:80],
        }

    print('IAPT_V154_TASK_COUNT_STABLE_GATE installed', flush=True)
except Exception as _iapt_v154_exc:
    try:
        print('IAPT_V154_TASK_COUNT_STABLE_GATE_FAILED', repr(_iapt_v154_exc), flush=True)
    except Exception:
        pass
# IAPT_V154_TASK_COUNT_STABLE_GATE_END



# IAPT_V155_TASK_LIST_SAFE_FILE_COUNT_START
# Hotfix after V154: do NOT expose raw tasks.file_count as the user-visible result file count.
# Some pipelines use tasks.file_count as an internal scanned/source/output member count; old mobile UIs
# then showed thousands of files.  V155 keeps total_count as task count, while file_count/downloadable_file_count
# in list responses only mean explicit public downloadable result count.
try:
    import json as _iapt_v155_json
    import time as _iapt_v155_time
    from fastapi import HTTPException as _iapt_v155_HTTPException
    from fastapi.responses import Response as _iapt_v155_Response

    IAPT_V155_VERSION = 'V155-task-count-public-file-count-safe'
    _IAPT_V155_COL_CACHE = {'ts': 0.0, 'cols': set()}

    def _iapt_v155_no_store(payload, status=200):
        body = _iapt_v155_json.dumps(payload, ensure_ascii=False, default=str)
        return _iapt_v155_Response(
            content=body,
            status_code=int(status),
            media_type='application/json; charset=utf-8',
            headers={
                'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                'Pragma': 'no-cache',
                'Expires': '0',
                'X-Accel-Buffering': 'no',
                'X-IAPT-Task-List-Gate': IAPT_V155_VERSION,
            },
        )

    def _iapt_v155_auth_user(request):
        try:
            return current_user(request, authorization=request.headers.get('authorization'))
        except _iapt_v155_HTTPException:
            raise
        except Exception as exc:
            raise _iapt_v155_HTTPException(401, '登录校验失败：' + str(exc))

    def _iapt_v155_i(v, default=0):
        try:
            if v is None or v == '': return default
            return int(v)
        except Exception:
            return default

    def _iapt_v155_qp_int(request, key, default, low, high):
        try:
            n = int(str(request.query_params.get(key, str(default)) or default).strip())
        except Exception:
            n = default
        return max(low, min(n, high))

    def _iapt_v155_task_cols():
        now = _iapt_v155_time.monotonic()
        if _IAPT_V155_COL_CACHE['cols'] and now - float(_IAPT_V155_COL_CACHE['ts'] or 0) < 60:
            return set(_IAPT_V155_COL_CACHE['cols'])
        try:
            rows = db.all('SHOW COLUMNS FROM tasks') or []
            cols = {str((r or {}).get('Field') or (r or {}).get('COLUMN_NAME') or '').strip() for r in rows}
            cols.discard('')
            _IAPT_V155_COL_CACHE['cols'] = cols
            _IAPT_V155_COL_CACHE['ts'] = now
            return cols
        except Exception:
            return {'id','task_no','user_id','apk_name','app_name','package_name','version_name','version_code','status','feature_id','decrypt_version','file_count','total_bytes','downloadable_file_count','created_at','updated_at','error_text','options_json'}

    def _iapt_v155_load_opt(v):
        if isinstance(v, dict): return dict(v)
        try:
            s = str(v or '').strip()
            if s:
                o = _iapt_v155_json.loads(s)
                return o if isinstance(o, dict) else {}
        except Exception:
            pass
        return {}

    def _iapt_v155_bool(v):
        if v is True or v == 1: return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y','auto')

    def _iapt_v155_count_array(v):
        if not isinstance(v, list): return 0
        n = 0
        for it in v:
            if isinstance(it, dict):
                name = str(it.get('name') or it.get('path') or it.get('filename') or '')
                typ = str(it.get('type') or it.get('kind') or '').lower()
                if it.get('is_dir') or it.get('directory') or typ in ('dir','directory') or name.endswith('/'):
                    continue
            n += 1
        return n

    def _iapt_v155_public_count_from_obj(o):
        if not isinstance(o, dict): return 0
        # Explicit public count fields only.  Intentionally exclude raw file_count.
        keys = (
            'client_output_file_count','public_output_file_count','public_file_count',
            'result_file_count','decrypted_file_count','output_file_count',
            'download_file_count','result_files_count','output_files_count',
        )
        for k in keys:
            n = _iapt_v155_i(o.get(k), 0)
            if n > 0: return n
        # downloadable_file_count is normally authoritative in current worker, but we still do not use it
        # when it looks like a raw/scanned file count unless an explicit marker says it is public.
        d = _iapt_v155_i(o.get('downloadable_file_count'), 0)
        if d > 0 and (_iapt_v155_bool(o.get('downloadable_file_count_authoritative')) or _iapt_v155_bool(o.get('public_file_count_authoritative')) or d <= 500):
            return d
        for k in ('output_files','result_files','download_files','downloadable_files'):
            v = o.get(k)
            if isinstance(v, list):
                n = _iapt_v155_count_array(v)
                if n > 0: return n
        for k in ('result','decrypt_report','ancient_report','output','data'):
            v = o.get(k)
            if isinstance(v, dict):
                n = _iapt_v155_public_count_from_obj(v)
                if n > 0: return n
        return 0

    def _iapt_v155_is_ancient(row, opt):
        merged = {}
        try: merged.update(opt if isinstance(opt, dict) else {})
        except Exception: pass
        try: merged.update({k: v for k, v in dict(row or {}).items() if k != 'options_json'})
        except Exception: pass
        for k in ('client_final_scheme','decrypt_scheme','task_version','public_scheme','decrypt_version'):
            v = str(merged.get(k) or '').strip().lower()
            if v in ('v3','v6','modern','new','key'): return False
            if v in ('ancient','old','legacy','old_iapp','iapp_old'): return True
        p = str(merged.get('client_submission_path') or '').strip().lower()
        lock = str(merged.get('client_route_lock') or '').strip().lower()
        return p in ('decrypt-ancient','ancient-decrypt') or lock.startswith('ancient') or _iapt_v155_bool(merged.get('legacy_iapp')) or _iapt_v155_bool(merged.get('old_iapp'))

    def _iapt_v155_public_row(row, admin=False):
        r = dict(row or {})
        opt = _iapt_v155_load_opt(r.get('options_json'))
        raw_file_count = _iapt_v155_i(r.get('file_count'), 0)
        raw_download_count = _iapt_v155_i(r.get('downloadable_file_count'), 0)
        ancient = _iapt_v155_is_ancient(r, opt)
        fid = _iapt_v155_i(r.get('feature_id'), 0)
        if fid <= 0:
            fid = int(globals().get('FEATURE_BASIC', 1) or 1)
        if ancient:
            dec = 'ancient'
            if fid == 6:
                fid = _iapt_v155_i(opt.get('primary_feature_id') or opt.get('feature_id'), int(globals().get('FEATURE_BASIC', 1) or 1))
                if fid == 6: fid = int(globals().get('FEATURE_BASIC', 1) or 1)
        else:
            kind = str(opt.get('task_kind') or '').strip().lower()
            opt_dec = str(opt.get('decrypt_version') or opt.get('task_version') or r.get('decrypt_version') or '').strip().lower()
            if kind == 'dynamic_key_extract' or _iapt_v155_bool(opt.get('dynamic_key_extract')):
                dec = 'key'
            elif opt_dec == 'v6' or fid == 6:
                dec = 'v6'; fid = 6
            else:
                dec = opt_dec or 'v3'
        r['feature_id'] = fid
        r['decrypt_version'] = dec
        r['task_version'] = dec
        r['task_family'] = dec
        if r.get('id') is not None: r['task_id'] = r.get('id')
        if not str(r.get('app_name') or '').strip():
            r['app_name'] = r.get('apk_name') or r.get('package_name') or ''

        # Build a merged object containing row + options_json, but never using raw file_count.
        merged = {}
        try: merged.update(opt)
        except Exception: pass
        try: merged.update({k: v for k, v in r.items() if k != 'file_count'})
        except Exception: pass
        public_count = _iapt_v155_public_count_from_obj(merged)
        if public_count <= 0 and raw_download_count > 0 and raw_download_count <= 500:
            public_count = raw_download_count
        # V155 public contract: list file_count == public downloadable result count, not internal raw count.
        r['file_count'] = public_count
        r['client_output_file_count'] = public_count
        r['downloadable_file_count'] = public_count
        r['public_file_count_authoritative'] = True
        r['downloadable_file_count_authoritative'] = True
        if admin:
            r['raw_file_count'] = raw_file_count
            r['raw_downloadable_file_count'] = raw_download_count
        r.pop('options_json', None)
        return r

    def _iapt_v155_where_user(request, user):
        return 'WHERE t.user_id=%s', [int(user.get('id'))]

    def _iapt_v155_where_admin(request):
        wh, params = [], []
        user_id = _iapt_v155_qp_int(request, 'user_id', 0, 0, 2147483647)
        st = str(request.query_params.get('status','') or '').strip()
        kw = str(request.query_params.get('keyword','') or '').strip()
        if user_id:
            wh.append('t.user_id=%s'); params.append(user_id)
        if st:
            wh.append('t.status=%s'); params.append(st)
        if kw:
            like = '%' + kw + '%'
            wh.append('(t.task_no LIKE %s OR t.apk_name LIKE %s OR t.app_name LIKE %s OR t.package_name LIKE %s OR u.username LIKE %s OR u.name LIKE %s)')
            params.extend([like, like, like, like, like, like])
        return ('WHERE ' + ' AND '.join(wh)) if wh else '', params

    def _iapt_v155_status_counts(where_sql, params, join_user=False):
        try:
            join = ' JOIN users u ON t.user_id=u.id ' if join_user else ''
            rows = db.all('SELECT t.status,COUNT(*) AS c FROM tasks t ' + join + ' ' + where_sql + ' GROUP BY t.status', tuple(params)) or []
            return {str(r.get('status') or 'unknown'): _iapt_v155_i(r.get('c'), 0) for r in rows}
        except Exception:
            return {}

    def _iapt_v155_count(where_sql, params, join_user=False):
        join = ' JOIN users u ON t.user_id=u.id ' if join_user else ''
        row = db.one('SELECT COUNT(*) AS c FROM tasks t ' + join + ' ' + where_sql, tuple(params)) or {}
        return _iapt_v155_i(row.get('c'), 0)

    def _iapt_v155_select_task_rows(where_sql, params, limit, offset, admin=False):
        cols = _iapt_v155_task_cols()
        base = [
            'id','task_no','user_id','apk_name','app_name','package_name','version_name','version_code',
            'status','feature_id','decrypt_version','total_ms','file_count','total_bytes','downloadable_file_count',
            'downloadable_bytes','actual_quota_cost','decrypt_quota_deducted','resource_quota_cost','estimated_quota_cost',
            'quota_limit','quota_note','created_at','updated_at','error_text','out_dir','options_json'
        ]
        selected = [c for c in base if c in cols]
        if 'id' not in selected: selected.insert(0, 'id')
        if admin:
            select = ','.join('t.`%s`' % c for c in selected) + ',u.username,u.name AS user_name'
            sql = 'SELECT ' + select + ' FROM tasks t JOIN users u ON t.user_id=u.id ' + where_sql + ' ORDER BY t.id DESC LIMIT %s OFFSET %s'
        else:
            select = ','.join('t.`%s`' % c for c in selected)
            sql = 'SELECT ' + select + ' FROM tasks t ' + where_sql + ' ORDER BY t.id DESC LIMIT %s OFFSET %s'
        return db.all(sql, tuple(params + [limit, offset])) or []

    def _iapt_v155_user_tasks(request, user):
        limit = _iapt_v155_qp_int(request, 'limit', 500, 1, 5000)
        offset = _iapt_v155_qp_int(request, 'offset', 0, 0, 100000000)
        where, params = _iapt_v155_where_user(request, user)
        total = _iapt_v155_count(where, params, False)
        rows = _iapt_v155_select_task_rows(where, params, limit, offset, False)
        items = [_iapt_v155_public_row(r, False) for r in rows]
        return {
            'ok': True,
            'items': items,
            'count': total,
            'total_count': total,
            'server_task_count': total,
            'returned_count': len(items),
            'visible_count': len(items),
            'limit': limit,
            'offset': offset,
            'next_offset': offset + len(items),
            'has_more': offset + len(items) < total,
            'status_counts': _iapt_v155_status_counts(where, params, False),
            'server_time': int(_iapt_v155_time.time()),
            'list_source': IAPT_V155_VERSION,
            'no_store': True,
            'count_means_task_total': True,
            'file_count_means_public_output_only': True,
        }

    def _iapt_v155_admin_tasks(request, user):
        require_permission(user, PERM_TASK_VIEW_ALL)
        limit = _iapt_v155_qp_int(request, 'limit', 50, 1, 500)
        offset = _iapt_v155_qp_int(request, 'offset', 0, 0, 100000000)
        where, params = _iapt_v155_where_admin(request)
        total = _iapt_v155_count(where, params, True)
        rows = _iapt_v155_select_task_rows(where, params, limit, offset, True)
        items = [_iapt_v155_public_row(r, True) for r in rows]
        return {
            'ok': True,
            'items': items,
            'count': total,
            'total_count': total,
            'returned_count': len(items),
            'limit': limit,
            'offset': offset,
            'next_offset': offset + len(items),
            'has_more': offset + len(items) < total,
            'status_counts': _iapt_v155_status_counts(where, params, True),
            'me': admin_permissions_public(user),
            'server_time': int(_iapt_v155_time.time()),
            'list_source': IAPT_V155_VERSION,
            'no_store': True,
            'count_means_task_total': True,
            'file_count_means_public_output_only': True,
        }

    @app.middleware('http')
    async def _iapt_v155_task_count_gate(request, call_next):
        path = str(getattr(request.url, 'path', '') or '').rstrip('/') or '/'
        method = str(getattr(request, 'method', '') or '').upper()
        if method == 'GET' and path in ('/api/tasks','/tasks','/api/admin/tasks','/admin/tasks'):
            try:
                user = _iapt_v155_auth_user(request)
                if path in ('/api/admin/tasks','/admin/tasks'):
                    return _iapt_v155_no_store(_iapt_v155_admin_tasks(request, user))
                return _iapt_v155_no_store(_iapt_v155_user_tasks(request, user))
            except _iapt_v155_HTTPException as exc:
                return _iapt_v155_no_store({'ok': False, 'items': [], 'count': 0, 'total_count': 0, 'error': str(getattr(exc, 'detail', exc)), 'list_source': IAPT_V155_VERSION}, getattr(exc, 'status_code', 401) or 401)
            except Exception as exc:
                print('[IAPT_V155] task list direct failed:', repr(exc), flush=True)
                return _iapt_v155_no_store({'ok': False, 'items': [], 'count': 0, 'total_count': 0, 'error': '任务列表读取失败：' + str(exc), 'list_source': IAPT_V155_VERSION}, 200)
        return await call_next(request)

    @app.get('/api/system/iapt-v155', include_in_schema=False)
    def _iapt_v155_status():
        return {
            'ok': True,
            'version': IAPT_V155_VERSION,
            'count_means_task_total': True,
            'file_count_means_public_output_only': True,
            'raw_file_count_hidden_from_mobile': True,
            'paths': ['/api/tasks','/tasks','/api/admin/tasks','/admin/tasks'],
            'columns_cached': sorted(list(_IAPT_V155_COL_CACHE.get('cols') or []))[:80],
        }

    print('IAPT_V155_TASK_LIST_SAFE_FILE_COUNT installed', flush=True)
except Exception as _iapt_v155_exc:
    try:
        print('IAPT_V155_TASK_LIST_SAFE_FILE_COUNT_FAILED', repr(_iapt_v155_exc), flush=True)
    except Exception:
        pass
# IAPT_V155_TASK_LIST_SAFE_FILE_COUNT_END

# IAPT_ANTI_RUNTIME_HOTFIX_V2_MAIN_BEGIN
try:
    def _iapt_anti_runtime_v2_truthy(value):
        if value is True or value == 1: return True
        if value is False or value == 0 or value is None: return False
        return str(value).strip().lower() in ('1','true','yes','on','y')

    def _iapt_v1_anti_requested(options):
        options = options if isinstance(options, dict) else {}
        return any(_iapt_anti_runtime_v2_truthy(options.get(k)) for k in (
            'anti_encrypted_sample','anti_qiushui','hidden_resource_restore',
            'anti_sample','anti_encrypt_sample'))

    _IAPT_ANTI_RUNTIME_V2_PREV_SANITIZE = _sanitize_decrypt_options
    def _sanitize_decrypt_options(options: dict, user_id: int):
        raw = dict(options or {})
        clean, feature_id, feature_scope = _IAPT_ANTI_RUNTIME_V2_PREV_SANITIZE(raw, user_id)
        if _iapt_v1_anti_requested(raw):
            clean['anti_encrypted_sample'] = True
            clean['anti_qiushui'] = True
            clean['hidden_resource_restore'] = True
            clean['anti_sample'] = True
        for key in ('client_anti_probe','anti_resource_scope','skip_anti_resources'):
            if key in raw: clean[key] = raw[key]
        return clean, feature_id, feature_scope
    print('[IAPT_ANTI_RUNTIME_V2] main option bridge installed', flush=True)
except Exception as _iapt_anti_runtime_v2_main_error:
    print('[IAPT_ANTI_RUNTIME_V2] main option bridge failed '+repr(_iapt_anti_runtime_v2_main_error), flush=True)
# IAPT_ANTI_RUNTIME_HOTFIX_V2_MAIN_END

# IAPT_SOURCE_RESTORE_MAIN_ZIP_V156_BEGIN
try:
    import json as _iapt_v156_json
    import os as _iapt_v156_os
    import zipfile as _iapt_v156_zipfile
    from pathlib import Path as _IAPT_V156_Path

    def _iapt_v156_normalize_rel(value):
        rel = str(value or "").replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        return rel.lstrip("/")


    def _iapt_v156_allowed_public_rel(rel):
        low = _iapt_v156_normalize_rel(rel).lower()
        return low.startswith("src/") or low.startswith("res/")


    def _iapt_v13_zip_rows(task: dict, rows: list[dict], dest: _IAPT_V156_Path) -> tuple[int, int]:
        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V156_Path(str(task.get("out_dir") or ""))
        if not out_dir.is_dir():
            raise HTTPException(404, "任务输出目录不存在或已被清理")

        selected = []
        seen = set()
        requested_src = 0
        requested_res = 0

        for raw in rows or []:
            if not isinstance(raw, dict):
                continue
            public_rel = _iapt_v156_normalize_rel(raw.get("rel_path"))
            if not _iapt_v156_allowed_public_rel(public_rel):
                continue
            if public_rel in seen:
                continue

            # V172: the manifest path and physical path must be identical.
            # Never follow source_rel aliases to another file, even when the
            # alias remains inside src/** or res/**.
            source_rel = public_rel
            candidate = out_dir / public_rel
            try:
                resolved = candidate.resolve()
                resolved.relative_to(out_dir.resolve())
            except Exception:
                raise HTTPException(409, "下载清单包含非法路径：" + public_rel)
            if not resolved.is_file():
                raise HTTPException(409, "下载清单与磁盘文件不一致：" + public_rel)

            item = dict(raw)
            item["rel_path"] = public_rel
            item["source_rel"] = source_rel
            item["_resolved"] = resolved
            selected.append(item)
            seen.add(public_rel)
            if public_rel.lower().startswith("src/"):
                requested_src += 1
            elif public_rel.lower().startswith("res/"):
                requested_res += 1

        if not selected:
            raise HTTPException(404, "任务没有可下载的 src/res 文件")

        dest = _IAPT_V156_Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary = dest.with_suffix(dest.suffix + ".tmp")
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

        total_bytes = 0
        try:
            with _iapt_v156_zipfile.ZipFile(
                temporary,
                "w",
                compression=_iapt_v156_zipfile.ZIP_DEFLATED,
                allowZip64=True,
            ) as archive:
                for item in selected:
                    archive.write(item["_resolved"], item["rel_path"])
                    total_bytes += int(item["_resolved"].stat().st_size)

            with _iapt_v156_zipfile.ZipFile(temporary, "r") as check:
                bad = check.testzip()
                names = [
                    info.filename.replace("\\", "/").lstrip("./")
                    for info in check.infolist()
                    if not info.is_dir()
                ]
            if bad is not None:
                raise RuntimeError("ZIP CRC 校验失败：" + str(bad))
            if len(names) != len(selected):
                raise RuntimeError(f"ZIP 成员数不一致：{len(names)} != {len(selected)}")

            checked_src = sum(1 for name in names if name.lower().startswith("src/"))
            checked_res = sum(1 for name in names if name.lower().startswith("res/"))
            if checked_src != requested_src:
                raise RuntimeError(f"ZIP src 数量不一致：{checked_src} != {requested_src}")
            if checked_res != requested_res:
                raise RuntimeError(f"ZIP res 数量不一致：{checked_res} != {requested_res}")

            _iapt_v156_os.replace(temporary, dest)
            try:
                report = out_dir / ".tmp/download_zip_v156.json"
                report.parent.mkdir(parents=True, exist_ok=True)
                temp_report = report.with_suffix(".json.tmp")
                temp_report.write_text(
                    _iapt_v156_json.dumps(
                        {
                            "version": 156,
                            "task_id": task.get("id"),
                            "task_no": task.get("task_no"),
                            "selected_files": len(selected),
                            "src_files": checked_src,
                            "res_files": checked_res,
                            "bytes": total_bytes,
                            "destination": str(dest),
                        },
                        ensure_ascii=False,
                        indent=2,
                    ) + "\n",
                    encoding="utf-8",
                )
                _iapt_v156_os.replace(temp_report, report)
            except Exception:
                pass
            return len(selected), total_bytes
        except HTTPException:
            try:
                temporary.unlink()
            except Exception:
                pass
            raise
        except Exception as exc:
            try:
                temporary.unlink()
            except Exception:
                pass
            raise HTTPException(500, "生成 src/res 下载 ZIP 失败：" + str(exc))


    @app.get("/api/system/iapt-v156-res-download", include_in_schema=False)
    def _iapt_v156_res_download_status():
        return {
            "ok": True,
            "version": "V156-main-v13-v116-src-res-zip",
            "stale_v94_v109_refilter": False,
            "zip_roots": ["src/**", "res/**"],
            "file_count_policy": "unchanged; source-only in decrypt_runner",
        }


    IAPT_SOURCE_RESTORE_MAIN_ZIP_V156 = {
        "v13_start": "fixed",
        "v116_stream": "inherits fixed V13 prepared ZIP",
        "authorization": "unchanged",
        "quota_selection": "unchanged",
        "zip_roots": ["src/**", "res/**"],
    }
    print("IAPT_SOURCE_RESTORE_MAIN_ZIP_V156 installed", flush=True)
except Exception as _iapt_v156_error:
    print("IAPT_SOURCE_RESTORE_MAIN_ZIP_V156_FAILED " + repr(_iapt_v156_error), flush=True)
# IAPT_SOURCE_RESTORE_MAIN_ZIP_V156_END

# IAPT_ANTI_RESOURCE_MAIN_ZIP_V159_BEGIN
# V156 was installed for source restore and allowed only src/** and res/**.
# Anti-encrypted-sample public rows use assets/res/**, so the global V13/V116
# ZIP path must also admit that already-authorized root.
try:
    _IAPT_V159_PREVIOUS_ALLOWED_PUBLIC_REL = (
        globals().get(
            "_iapt_v156_allowed_public_rel"
        )
    )

    def _iapt_v156_allowed_public_rel(value):
        relative = str(value or "").replace(
            "\\",
            "/",
        )
        while relative.startswith("./"):
            relative = relative[2:]
        lower = relative.lstrip("/").lower()

        if (
            callable(
                _IAPT_V159_PREVIOUS_ALLOWED_PUBLIC_REL
            )
            and _IAPT_V159_PREVIOUS_ALLOWED_PUBLIC_REL(
                relative
            )
        ):
            return True

        return lower.startswith("assets/res/")


    IAPT_ANTI_RESOURCE_MAIN_ZIP_V159 = {
        "v13_v116_zip_roots": [
            "src/**",
            "res/**",
            "assets/res/**",
        ],
        "authorization": "unchanged",
        "quota_selection": "unchanged",
        "resource_dedup": (
            "performed by decrypt_runner V159"
        ),
    }
    print(
        "IAPT_ANTI_RESOURCE_MAIN_ZIP_V159 "
        "installed",
        flush=True,
    )
except Exception as _iapt_v159_main_error:
    print(
        "IAPT_ANTI_RESOURCE_MAIN_ZIP_V159_FAILED "
        + repr(_iapt_v159_main_error),
        flush=True,
    )
# IAPT_ANTI_RESOURCE_MAIN_ZIP_V159_END

# IAPT_WHITELIST_SIGNATURE_V163_BEGIN
# V163: backend generates final SHA-256 + deterministic RSA signature. The
# client embeds only the returned Base64 public_key text. Decrypt verification
# is deferred to app/decrypt_runner.py, where the uploaded APK is available.
try:
    import datetime as _v163_dt
    import json as _v163_json
    import re as _v163_re
    from fastapi import Request as _V163Request
    from fastapi import HTTPException as _V163HTTPException
    from fastapi import Depends as _V163Depends
    from app.whitelist_signature_v163 import (
        SCHEME_VERSION as _V163_SCHEME,
        build_record as _v163_build_record,
        ensure_database_schema as _v163_ensure_database_schema,
        expire_to_milliseconds as _v163_expire_to_milliseconds,
        signature_base64 as _v163_signature_base64,
    )
except Exception as _v163_import_error:
    print('[IAPT_WL_V163_IMPORT_WARN]', _v163_import_error)


def _v163_schema():
    return _v163_ensure_database_schema(db)


def _v163_as_dict(value):
    return value if isinstance(value, dict) else {}


def _v163_columns():
    rows = db.all("SHOW COLUMNS FROM `decrypt_whitelist`") or []
    return {
        str(row.get('Field') or row.get('field') or '')
        for row in rows
        if isinstance(row, dict)
    }


def _v163_pick(body, *names, default=None):
    if not isinstance(body, dict):
        return default
    for name in names:
        if name in body and body.get(name) is not None:
            return body.get(name)
    nested = body.get('data')
    if isinstance(nested, dict):
        for name in names:
            if name in nested and nested.get(name) is not None:
                return nested.get(name)
    return default


async def _v163_body(request):
    old_reader = globals().get('_v58_body')
    if callable(old_reader):
        try:
            value = await old_reader(request)
            if isinstance(value, dict):
                return value
        except Exception:
            pass
    try:
        value = await request.json()
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _v163_parse_expire(value):
    if value is None:
        return None
    text = str(value).strip()
    if not text or text.lower() in ('none', 'null', 'never', '永久'):
        return None
    text = text.replace('T', ' ').replace('Z', '').replace('/', '-').strip()
    text = _v163_re.sub(r'\.\d+$', '', text)
    text = _v163_re.sub(r'\s*[+-]\d\d:?\d\d$', '', text)
    for fmt in ('%Y-%m-%d %H:%M:%S', '%Y-%m-%d %H:%M', '%Y-%m-%d'):
        try:
            return _v163_dt.datetime.strptime(text[:19], fmt)
        except Exception:
            pass
    try:
        return _v163_dt.datetime.fromisoformat(text).replace(tzinfo=None)
    except Exception:
        raise _V163HTTPException(400, '到期时间格式错误，请使用 2027-12-31 23:59:59；留空表示永久')


def _v163_expire_string(value):
    if value is None or value == '':
        return ''
    if isinstance(value, _v163_dt.datetime):
        return value.strftime('%Y-%m-%d %H:%M:%S')
    if isinstance(value, _v163_dt.date):
        return value.strftime('%Y-%m-%d 00:00:00')
    return str(value)


def _v163_active(expire_at):
    if expire_at is None or expire_at == '':
        return True
    parsed = _v163_parse_expire(expire_at)
    return parsed is None or parsed > _v163_dt.datetime.now()


def _v163_final_from_row(row):
    row = _v163_as_dict(row)
    version = str(row.get('token_version') or '').strip().lower()
    value = str(row.get('final_sha256') or '').strip().lower()
    if version == _V163_SCHEME and _v163_re.fullmatch(r'[0-9a-f]{64}', value):
        return value
    return ''


def _v163_item(row):
    row = _v163_as_dict(row)
    final_sha256 = _v163_final_from_row(row)
    public_key = ''
    if final_sha256:
        try:
            public_key = _v163_signature_base64(final_sha256)
        except Exception as exc:
            print('[IAPT_WL_V163_SIGN_WARN]', row.get('id'), exc)
    expire_at = row.get('expire_at')
    active = _v163_active(expire_at)
    status = '永久' if expire_at in (None, '') else ('生效' if active else '过期')
    package_name = str(row.get('package_name') or '')
    expire_text = _v163_expire_string(expire_at)
    return {
        'id': row.get('id'),
        'package_name': package_name,
        'package': package_name,
        'pkg': package_name,
        'packageName': package_name,
        # Keep code_hash aliases for the existing admin client. They now carry
        # the V163 final SHA-256 generated by the server.
        'code_hash': final_sha256,
        'codeHash': final_sha256,
        'hash': final_sha256,
        'sha256': final_sha256,
        'final_sha256': final_sha256,
        'finalSha256': final_sha256,
        # The client embeds only this Base64 text in the main file.
        'public_key': public_key,
        'publicKey': public_key,
        'whitelist_public_key': public_key,
        'whitelistPublicKey': public_key,
        'whitelist_key': public_key,
        'signature': public_key,
        'signature_base64': public_key,
        'embed_value': public_key,
        'embedValue': public_key,
        'public_key_length': len(public_key),
        'public_key_kind': 'deterministic_rsa_private_operation_base64',
        'expire_ms': (
            0 if expire_at in (None, '')
            else _v163_expire_to_milliseconds(expire_at)
        ),
        'expire_at': expire_text,
        'expireAt': expire_text,
        'expire_time': expire_text,
        'expireTime': expire_text,
        'note': row.get('note') or '',
        'token_version': str(row.get('token_version') or ''),
        'scheme': str(row.get('token_version') or ''),
        'status': status,
        'status_text': status,
        'active': 1 if active else 0,
        'valid': 1 if active else 0,
        'expired': not active,
        'is_expired': not active,
        'created_at': _v163_expire_string(row.get('created_at')),
        'updated_at': _v163_expire_string(row.get('updated_at')),
        'version': _V163_SCHEME,
    }


def _v163_write_values(package_name, final_sha256, expire_at, note):
    columns = _v163_columns()
    values = {}
    package_columns = ('package_name', 'package', 'pkg', 'pkg_name', 'app_package', 'packageName')
    hash_columns = (
        'code_hash', 'code_sha256', 'file_hash', 'apk_sha256',
        'apk_hash', 'hash', 'sha256', 'final_sha256',
    )
    expire_columns = ('expire_at', 'expire_time', 'expires_at', 'expiry', 'end_time')
    note_columns = ('note', 'remark')

    for name in package_columns:
        if name in columns:
            values[name] = package_name
    for name in hash_columns:
        if name in columns:
            values[name] = final_sha256
    for name in expire_columns:
        if name in columns:
            values[name] = expire_at
    for name in note_columns:
        if name in columns:
            values[name] = note
    if 'token_version' in columns:
        values['token_version'] = _V163_SCHEME
    return values


def _v163_insert(values):
    names = list(values)
    sql = (
        'INSERT INTO decrypt_whitelist ('
        + ','.join('`' + name + '`' for name in names)
        + ') VALUES ('
        + ','.join(['%s'] * len(names))
        + ')'
    )
    return db.exec(sql, tuple(values[name] for name in names))


def _v163_update(row_id, values):
    names = list(values)
    sql = (
        'UPDATE decrypt_whitelist SET '
        + ','.join('`' + name + '`=%s' for name in names)
        + ' WHERE id=%s'
    )
    db.exec(sql, tuple(values[name] for name in names) + (int(row_id),))


def _v163_list_rows(keyword=''):
    _v163_schema()
    text = str(keyword or '').strip()
    if text:
        like = '%' + text + '%'
        return db.all(
            "SELECT * FROM decrypt_whitelist "
            "WHERE package_name LIKE %s OR final_sha256 LIKE %s "
            "ORDER BY id DESC LIMIT 1000",
            (like, like),
        ) or []
    return db.all(
        "SELECT * FROM decrypt_whitelist ORDER BY id DESC LIMIT 1000"
    ) or []


try:
    # Replace all historical whitelist admin/check routes. The decrypt upload
    # path itself is not blocked here; V163 verifies inside decrypt_runner.
    app.router.routes = [
        route for route in app.router.routes
        if 'whitelist' not in str(getattr(route, 'path', '')).lower()
    ]
except Exception as _v163_route_cleanup_error:
    print('[IAPT_WL_V163_ROUTE_CLEANUP_WARN]', _v163_route_cleanup_error)


async def _v163_list_impl(keyword=''):
    items = [_v163_item(row) for row in _v163_list_rows(keyword)]
    return {
        'ok': True,
        'success': True,
        'version': _V163_SCHEME,
        'items': items,
        'data': items,
        'list': items,
        'rows': items,
        'records': items,
        'results': items,
        'whitelist': items,
        'total': len(items),
    }


@app.get('/admin/whitelist')
@app.get('/admin/whitelist/')
@app.get('/admin/whitelist/list')
@app.get('/api/admin/whitelist')
@app.get('/api/admin/whitelist/')
@app.get('/api/admin/whitelist/list')
@app.get('/whitelist/list')
@app.get('/api/whitelist/list')
@app.get('/admin/decrypt_whitelist/list')
@app.get('/api/admin/decrypt_whitelist/list')
async def _iapt_v163_whitelist_list_get(
    q: str = '', keyword: str = '', search: str = '',
    user=_V163Depends(current_user),
):
    require_permission(user, 602)
    return await _v163_list_impl(q or keyword or search)


@app.post('/admin/whitelist')
@app.post('/admin/whitelist/list')
@app.post('/api/admin/whitelist')
@app.post('/api/admin/whitelist/list')
@app.post('/whitelist/list')
@app.post('/api/whitelist/list')
@app.post('/admin/decrypt_whitelist/list')
@app.post('/api/admin/decrypt_whitelist/list')
async def _iapt_v163_whitelist_list_post(
    request: _V163Request,
    user=_V163Depends(current_user),
):
    require_permission(user, 602)
    body = await _v163_body(request)
    keyword = _v163_pick(body, 'q', 'keyword', 'search', default='')
    return await _v163_list_impl(keyword)


@app.post('/admin/whitelist/add')
@app.post('/admin/whitelist/save')
@app.post('/admin/whitelist/update')
@app.post('/api/admin/whitelist/add')
@app.post('/api/admin/whitelist/save')
@app.post('/api/admin/whitelist/update')
@app.post('/whitelist/add')
@app.post('/whitelist/save')
@app.post('/whitelist/update')
@app.post('/api/whitelist/add')
@app.post('/api/whitelist/save')
@app.post('/api/whitelist/update')
async def _iapt_v163_whitelist_save(
    request: _V163Request,
    user=_V163Depends(current_user),
):
    require_permission(user, 602)
    _v163_schema()
    body = await _v163_body(request)
    row_id_raw = _v163_pick(body, 'id', 'wid', 'whitelist_id')
    try:
        row_id = int(row_id_raw or 0)
    except Exception:
        row_id = 0
    package_name = str(_v163_pick(
        body,
        'package_name', 'package', 'pkg', 'packageName', 'app_package',
        default='',
    ) or '').strip()
    note = str(_v163_pick(body, 'note', 'remark', default='') or '')
    expire_at = _v163_parse_expire(_v163_pick(
        body,
        'expire_at', 'expireAt', 'expire_time', 'expireTime',
        'expires_at', 'expiresAt', 'expired_at', 'expiry', 'end_time',
        default='',
    ))
    if not package_name:
        raise _V163HTTPException(400, '包名不能为空')

    try:
        generated = _v163_build_record(package_name, expire_at)
    except ValueError as exc:
        raise _V163HTTPException(400, str(exc))
    except Exception as exc:
        print('[IAPT_WL_V163_GENERATE_ERROR]', exc)
        raise _V163HTTPException(500, '生成白名单公钥失败')

    final_sha256 = generated['final_sha256']
    values = _v163_write_values(
        generated['package_name'],
        final_sha256,
        expire_at,
        note,
    )

    if row_id > 0:
        _v163_update(row_id, values)
        saved_id = row_id
    else:
        existing = db.one(
            "SELECT id FROM decrypt_whitelist "
            "WHERE package_name=%s AND final_sha256=%s "
            "AND token_version=%s ORDER BY id DESC LIMIT 1",
            (generated['package_name'], final_sha256, _V163_SCHEME),
        )
        if existing:
            saved_id = int(_v163_as_dict(existing).get('id') or 0)
            _v163_update(saved_id, values)
        else:
            saved_id = int(_v163_insert(values) or 0)

    row = db.one(
        'SELECT * FROM decrypt_whitelist WHERE id=%s',
        (saved_id,),
    )
    item = _v163_item(row)
    return {
        'ok': True,
        'success': True,
        'version': _V163_SCHEME,
        'item': item,
        'data': item,
        'final_sha256': final_sha256,
        # Client embeds only this field in the main file.
        'public_key': generated['public_key'],
        'publicKey': generated['public_key'],
        'whitelist_public_key': generated['public_key'],
        'whitelist_key': generated['public_key'],
        'signature_base64': generated['public_key'],
        'embed_value': generated['public_key'],
        'embedValue': generated['public_key'],
        'expire_ms': generated['expire_ms'],
        'public_key_kind': 'deterministic_rsa_private_operation_base64',
        'message': '白名单公钥已生成，请把完整 Base64 文本放入 mian.iyu 任意位置',
    }


@app.post('/admin/whitelist/delete')
@app.post('/admin/whitelist/remove')
@app.post('/api/admin/whitelist/delete')
@app.post('/api/admin/whitelist/remove')
@app.post('/whitelist/delete')
@app.post('/whitelist/remove')
@app.post('/api/whitelist/delete')
@app.post('/api/whitelist/remove')
async def _iapt_v163_whitelist_delete(
    request: _V163Request,
    user=_V163Depends(current_user),
):
    require_permission(user, 602)
    body = await _v163_body(request)
    row_id = _v163_pick(body, 'id', 'wid', 'whitelist_id')
    if not row_id:
        raise _V163HTTPException(400, 'id不能为空')
    db.exec('DELETE FROM decrypt_whitelist WHERE id=%s', (int(row_id),))
    return {'ok': True, 'success': True, 'version': _V163_SCHEME}


async def _iapt_v163_whitelist_check_deferred(
    request: _V163Request,
    user=_V163Depends(current_user),
):
    # By design, signature verification happens only in decrypt_runner after
    # the uploaded APK is on disk. This endpoint never performs the old package
    # OR hash blocking behavior.
    return {
        'ok': True,
        'allowed': True,
        'blocked': False,
        'deferred_to': 'decrypt_runner',
        'version': _V163_SCHEME,
    }


for _v163_path in (
    '/whitelist/check', '/api/whitelist/check',
    '/admin/whitelist/check', '/api/admin/whitelist/check',
):
    app.add_api_route(
        _v163_path,
        _iapt_v163_whitelist_check_deferred,
        methods=['GET', 'POST'],
    )


# Neutralize old in-main package/hash candidate checks. The actual check is the
# V163 signature verifier in decrypt_runner.
def _v61_find_active_whitelist(pkgs, hashes):
    return None


def _v60_find_active_whitelist(pkgs, hashes):
    return None


def _v61_guard_or_result(options, user_id=None, file_bytes=None, file_name='', file_path=''):
    return {'allowed': True, 'blocked': False, 'deferred_to': 'decrypt_runner', 'version': _V163_SCHEME}


def _v60_guard_or_result(options, user_id=None, file_bytes=None, file_name='', file_path=''):
    return {'allowed': True, 'blocked': False, 'deferred_to': 'decrypt_runner', 'version': _V163_SCHEME}


try:
    _v163_schema()
    print('[OK] IAPT_WHITELIST_SIGNATURE_V163 installed')
except Exception as _v163_init_error:
    print('[IAPT_WL_V163_INIT_WARN]', _v163_init_error)
# IAPT_WHITELIST_SIGNATURE_V163_END

# IAPT_DYNAMIC_RESTORE_DOWNLOAD_V172_BEGIN
# V172 removes the V171 public-path-to-arbitrary-physical-path fallback.
# Download members must now exist at the same canonical physical path under the
# task output directory.  decrypt_runner normalizes approved outputs to src/**
# and res/** before the manifest is generated.  This prevents internal or
# unrelated source files from being exposed through a forged/stale source_rel.
try:
    @app.get('/api/system/iapt-v172-dynamic-download', include_in_schema=False)
    def _iapt_v172_dynamic_download_status():
        return {
            'ok': True,
            'version': 'V172-canonical-physical-src-res',
            'download_path_rule': 'public rel_path must equal physical path',
            'dynamic_restore_roots': ['src/**', 'res/**'],
            'legacy_arbitrary_source_rel_fallback': False,
            'layout_normalizer': 'decrypt_runner V172 recognized roots only',
        }

    print('IAPT_DYNAMIC_RESTORE_DOWNLOAD_V172 installed', flush=True)
except Exception as _iapt_v172_error:
    print('IAPT_DYNAMIC_RESTORE_DOWNLOAD_V172_FAILED ' + repr(_iapt_v172_error), flush=True)
    raise
# IAPT_DYNAMIC_RESTORE_DOWNLOAD_V172_END

# IAPT_UNIFIED_RUNTIME_V179


# IAPT_V190_FEATURE999_AND_TRIGGER_GUARD

# IAPT_V192_UTILITY_RESULT_DOWNLOAD_BEGIN
# Standalone dynamic-key and server-SO-key tasks intentionally produce one flat
# result file (key.txt or sokey.txt).  The V156 source-download hardening only
# permits canonical src/** and res/** for source tasks; this wrapper preserves
# that policy and adds an exact-name allowlist for these two utility task kinds.
try:
    import json as _iapt_v192_json
    import os as _iapt_v192_os
    import zipfile as _iapt_v192_zipfile
    from pathlib import Path as _IAPT_V192_Path

    _IAPT_V192_PREVIOUS_ZIP_ROWS = globals().get('_iapt_v13_zip_rows')

    def _iapt_v192_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            value = _iapt_v192_json.loads(raw or '{}')
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}

    def _iapt_v192_utility_result_names(task):
        task = task if isinstance(task, dict) else {}
        options = _iapt_v192_options(task)
        kind = str(options.get('task_kind') or task.get('task_kind') or '').strip().lower()
        versions = {
            str(task.get('decrypt_version') or '').strip().lower(),
            str(options.get('decrypt_version') or '').strip().lower(),
            str(options.get('task_version') or '').strip().lower(),
        }
        versions.discard('')
        app_name = str(task.get('app_name') or '').strip().lower()
        apk_name = str(task.get('apk_name') or '').strip().lower()

        dynamic = (
            kind in ('dynamic_key_extract', 'standalone_dynamic_key_extract')
            or bool(versions.intersection({'key', 'dynkey', 'dynamic_key', 'dynamic_key_extract'}))
            or bool(options.get('dynamic_key_extract'))
            or '动态key提取' in app_name
        )
        sokey = (
            kind in ('server_sokey_extract', 'standalone_so_extract', 'sokey_extract')
            or bool(versions.intersection({'sokey', 'server_sokey', 'server_sokey_extract'}))
            or bool(options.get('server_sokey_extract'))
            or 'so key 提取' in app_name
            or '服务器获取sokey' in app_name
            or apk_name.endswith('_sokey.zip')
        )
        if dynamic:
            return {'key.txt'}
        if sokey:
            return {'sokey.txt'}
        return set()

    def _iapt_v13_zip_rows(task: dict, rows: list[dict], dest: _IAPT_V192_Path) -> tuple[int, int]:
        allowed_names = _iapt_v192_utility_result_names(task)
        if not allowed_names:
            if not callable(_IAPT_V192_PREVIOUS_ZIP_ROWS):
                raise HTTPException(500, '下载打包器不可用')
            return _IAPT_V192_PREVIOUS_ZIP_ROWS(task, rows, dest)

        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V192_Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            raise HTTPException(404, '任务输出目录不存在或已被清理')
        root = out_dir.resolve()

        selected = []
        seen = set()
        for raw in rows or []:
            if not isinstance(raw, dict):
                continue
            rel = str(raw.get('rel_path') or '').replace('\\', '/').lstrip('./')
            # Exact root-level names only.  No source_rel aliases, wildcards,
            # subdirectories, symlinks outside the task root, or extra reports.
            if rel not in allowed_names or '/' in rel or rel in seen:
                continue
            candidate = out_dir / rel
            try:
                resolved = candidate.resolve()
                resolved.relative_to(root)
            except Exception:
                raise HTTPException(409, '提取结果包含非法路径')
            if not resolved.is_file():
                raise HTTPException(409, '提取结果与磁盘文件不一致')
            selected.append((rel, resolved))
            seen.add(rel)

        if not selected:
            raise HTTPException(404, '任务没有可下载的提取结果文件')

        dest = _IAPT_V192_Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)
        temporary = dest.with_suffix(dest.suffix + '.v192.tmp')
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass

        total_bytes = 0
        try:
            with _iapt_v192_zipfile.ZipFile(
                temporary,
                'w',
                compression=_iapt_v192_zipfile.ZIP_DEFLATED,
                allowZip64=True,
            ) as archive:
                for rel, resolved in selected:
                    archive.write(resolved, rel)
                    total_bytes += int(resolved.stat().st_size)

            with _iapt_v192_zipfile.ZipFile(temporary, 'r') as check:
                bad = check.testzip()
                names = [
                    info.filename.replace('\\', '/').lstrip('./')
                    for info in check.infolist()
                    if not info.is_dir()
                ]
            expected = [item[0] for item in selected]
            if bad is not None:
                raise RuntimeError('ZIP CRC 校验失败：' + str(bad))
            if names != expected:
                raise RuntimeError('ZIP 提取结果成员不一致')

            _iapt_v192_os.replace(temporary, dest)
            return len(selected), total_bytes
        except Exception:
            try:
                temporary.unlink()
            except Exception:
                pass
            raise

    @app.get('/api/system/iapt-v192-utility-download', include_in_schema=False)
    def _iapt_v192_utility_download_status():
        return {
            'ok': True,
            'version': 'V192-utility-flat-result-download',
            'dynamic_key_result': 'key.txt',
            'server_sokey_result': 'sokey.txt',
            'source_download_policy_preserved': True,
        }

    print('IAPT_V192_UTILITY_RESULT_DOWNLOAD installed', flush=True)
except Exception as _iapt_v192_error:
    print('IAPT_V192_UTILITY_RESULT_DOWNLOAD_FAILED ' + repr(_iapt_v192_error), flush=True)
    raise
# IAPT_V192_UTILITY_RESULT_DOWNLOAD_END

# IAPT_V193_JOINT_TRIPLE_ENUM_AUTO_POOL
@app.get('/api/system/iapt-v193-enum-pool', include_in_schema=False)
def _iapt_v193_enum_pool_status():
    return {
        'ok': True,
        'version': 'V193-joint-triple-enum-auto-pool',
        'sokey_enum_requires_libygsiyu': False,
        'joint_feature': 14,
        'ultimate_feature': 999,
        'auto_pool_verified_success': True,
    }

# IAPT_HYBRID_VM_V4_BEGIN
try:
    from .iapt_hybrid_vm_broker import router as _iapt_hvm4_router
except ImportError:
    from app.iapt_hybrid_vm_broker import router as _iapt_hvm4_router
app.include_router(_iapt_hvm4_router)
# IAPT_HYBRID_VM_V4_END

# IAPT_NATIVE_COMPILE_RESTORE_MAIN_BEGIN
# Final API option bridge for the DEX-backed iApp native-compile event repair.
# This block intentionally sits after all historical sanitizer wrappers so the
# parameter cannot be dropped before task creation.
_IAPT_NATIVE_COMPILE_PREV_SANITIZE = _sanitize_decrypt_options


def _iapt_native_compile_truthy(value):
    if value is True or value == 1:
        return True
    if value is False or value == 0 or value is None:
        return False
    return str(value).strip().lower() in ('1', 'true', 'yes', 'on', 'y')


def _sanitize_decrypt_options(options: dict, user_id: int):
    raw = dict(options or {})
    clean, feature_id, feature_scope = _IAPT_NATIVE_COMPILE_PREV_SANITIZE(raw, user_id)
    requested = any(_iapt_native_compile_truthy(raw.get(key)) for key in (
        'native_compile_restore',
        'v3_native_compile_restore',
        'ancient_native_compile_restore',
    ))
    if requested:
        native_feature_id = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
        subscription = _require_feature_or_403(int(user_id), native_feature_id)
        if not isinstance(feature_scope, dict):
            feature_scope = {}
        feature_scope[str(native_feature_id)] = int((subscription or {}).get('sub_id') or 0)
        # The selected repair itself is feature 5. Other simultaneously enabled
        # capabilities remain additive through option flags and feature_scope.
        feature_id = native_feature_id
        clean['native_compile_restore'] = True
        clean['v3_native_compile_restore'] = _iapt_native_compile_truthy(raw.get('v3_native_compile_restore'))
        clean['ancient_native_compile_restore'] = _iapt_native_compile_truthy(raw.get('ancient_native_compile_restore'))
        clean['require_dex_upload'] = True
        clean['client_need_dex'] = True
        clean['primary_feature_id'] = native_feature_id
    else:
        clean['native_compile_restore'] = False
        clean['v3_native_compile_restore'] = False
        clean['ancient_native_compile_restore'] = False

    for key in (
        'native_compile_restore_auto_enabled',
        'native_compile_detected',
        'native_compile_detector_version',
        'native_compile_dex_entry',
        'native_compile_event_method_count',
        'native_compile_source_string_count',
        'native_compile_reason',
        'native_compile_package_tree',
        'native_compile_token_fallback',
        'native_compile_direct_v3_backfill',
        'native_compile_restore_strategy',
    ):
        if key in raw:
            clean[key] = raw[key]
    return clean, feature_id, feature_scope


@app.post('/api/source/native-compile-restore')
@app.post('/source/native-compile-restore')
@app.post('/api/tasks/native-compile-restore')
@app.post('/tasks/native-compile-restore')
def _iapt_native_compile_source_restore_route(
    request: Request,
    src: UploadFile = File(...),
    dex: UploadFile = File(...),
    payload: str = Form(default=''),
    iv: str = Form(default=''),
    user=Depends(current_user),
):
    feature_id = int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5)
    if not active_subscription(int(user['id']), feature_id):
        raise HTTPException(403, '当前订阅不支持原生编译修复')
    if request.headers.get('x-body-hash') != sha256_hex(payload or ''):
        print('[IAPT native-compile-source] ignored multipart body hash mismatch')
    task_no = secrets.token_hex(16)
    upload_dir = APP_STORAGE / 'uploads'
    upload_dir.mkdir(parents=True, exist_ok=True)
    src_zip = upload_dir / f'{task_no}.apk'
    dex_path = upload_dir / f'{task_no}.dex'
    try:
        with src_zip.open('wb') as fp:
            shutil.copyfileobj(src.file, fp)
        with dex_path.open('wb') as fp:
            shutil.copyfileobj(dex.file, fp)
        src_size = int(src_zip.stat().st_size)
        dex_size = int(dex_path.stat().st_size)
    except Exception as exc:
        for path in (src_zip, dex_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
        raise HTTPException(500, '保存原生编译修复输入失败：' + str(exc))
    if src_size <= 0 or dex_size <= 0:
        raise HTTPException(400, '源码 ZIP 或 DEX/APK 文件为空')
    if src_size > 256 * 1024 * 1024 or dex_size > 256 * 1024 * 1024:
        raise HTTPException(413, '上传文件超过 256MB')
    if not zipfile.is_zipfile(src_zip) or not _iapt_source_restore_zip_has_source(src_zip):
        raise HTTPException(400, '请上传包含 src 的项目 ZIP')
    try:
        head = dex_path.read_bytes()[:8]
        valid_dex_input = head.startswith(b'dex\n') or zipfile.is_zipfile(dex_path)
    except Exception:
        valid_dex_input = False
    if not valid_dex_input:
        raise HTTPException(400, '请上传 DEX/APK/ZIP/JAR 文件')
    options = {
        'feature_id': feature_id,
        'primary_feature_id': feature_id,
        'native_compile_source_restore': True,
        'native_compile_restore': True,
        'native_compile_direct_v3_backfill': True,
        'native_compile_all_text_files': True,
        'native_compile_filename_fixpoint': True,
        'require_dex_upload': True,
        'decrypt_version': 'native_compile_restore',
        'task_version': 'native_compile_restore',
    }
    if payload and iv:
        try:
            from .secure import decrypt_json_payload
            decoded = decrypt_json_payload({'data': payload, 'iv': iv}, request.headers.get('x-salt', ''))
            if isinstance(decoded, dict):
                options.update(decoded)
        except Exception as exc:
            print('[IAPT native-compile-source] payload decode skipped:', exc)
    options.update({
        'feature_id': feature_id,
        'primary_feature_id': feature_id,
        'native_compile_source_restore': True,
        'native_compile_restore': True,
        'native_compile_direct_v3_backfill': True,
        'native_compile_all_text_files': True,
        'native_compile_filename_fixpoint': True,
        'require_dex_upload': True,
        'decrypt_version': 'native_compile_restore',
        'task_version': 'native_compile_restore',
    })
    cost = cost_for_bytes(src_size + dex_size)
    quota = available_quota(int(user['id']), feature_id)
    if quota_decimal(quota.get('total'), 0) < quota_decimal(cost, 0):
        raise HTTPException(402, f'额度不足：需要 {cost} 额度，当前剩余 {quota.get("total", 0)}')
    try:
        deduct_quota(int(user['id']), feature_id, cost)
    except ValueError as exc:
        raise HTTPException(402, str(exc))
    def _sha_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open('rb') as fp:
            for chunk in iter(lambda: fp.read(1024 * 1024), b''):
                digest.update(chunk)
        return digest.hexdigest()
    src_sha = _sha_file(src_zip)
    options['native_compile_input_sha256'] = _sha_file(dex_path)
    opt_hash = hashlib.sha256(json.dumps(options, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')).hexdigest()
    name = _iapt_source_restore_safe_name(Path(src.filename or 'src.zip').stem)
    apk_name = name if name.endswith('.zip') else name + '_native_compile.zip'
    quota_after = available_quota(int(user['id']), feature_id).get('total', 0)
    resource_note = f'原生编译修复上传扣除：src {src_size} bytes + dex/apk {dex_size} bytes，扣除 {cost} 额度'
    quota_note = f'原生编译修复任务已创建；上传已扣除 {cost} 额度；完成后可下载回填源码 ZIP'
    sql = (
        'INSERT INTO tasks(task_no,user_id,apk_name,status,feature_id,decrypt_version,options_json,apk_sha256,options_hash,'
        'resource_quota_cost,resource_quota_deducted,resource_quota_note,estimated_quota_cost,quota_limit,quota_note) '
        "VALUES(%s,%s,%s,'queued',%s,%s,%s,%s,%s,%s,1,%s,%s,%s,%s)"
    )
    try:
        task_id = db.exec(sql, (task_no, user['id'], apk_name, feature_id, 'native_compile_restore', json.dumps(options, ensure_ascii=False), src_sha, opt_hash, cost, resource_note, quota_public_value(cost), quota_after, quota_note))
    except Exception as exc:
        for path in (src_zip, dex_path):
            try:
                path.unlink(missing_ok=True)
            except Exception:
                pass
        raise HTTPException(500, '创建原生编译修复任务失败：' + str(exc))
    try:
        enqueue_task(int(task_id))
    except Exception as exc:
        print('[WARN] enqueue native compile source restore failed:', exc)
    return {
        'ok': True, 'task_id': task_id, 'task_no': task_no, 'status': 'queued',
        'feature_id': feature_id, 'decrypt_version': 'native_compile_restore',
        'task_version': 'native_compile_restore', 'resource_quota_cost': cost,
        'quota_limit': quota_after,
    }


@app.get('/api/system/iapt-native-compile-restore', include_in_schema=False)
def _iapt_native_compile_restore_status():
    return {
        'ok': True,
        'version': 'native-compile-restore-v11-standalone-entry',
        'feature_id': int(globals().get('FEATURE_NUMERIC_FN_RESTORE', 5) or 5),
        'schemes': ['v3', 'ancient'],
        'strategy': 'manifest-package/exact-token/all-text-files/v3-syntax-backfill+exact-normal-v3-filename-parser+hash-validated-fixpoint+project-meta',
        'dex_upload_required': True,
    }

print('IAPT_NATIVE_COMPILE_RESTORE_MAIN installed', flush=True)
# IAPT_NATIVE_COMPILE_RESTORE_MAIN_END

# IAPT_ANTI_IAPEC_MAIN_V1_BEGIN
# Independent inner-source restoration. It shares exact entitlement 17 with
# "反加密样本" but never turns the outer hidden-lib switch on implicitly.
_IAPT_ANTI_IAPEC_PREV_SANITIZE = _sanitize_decrypt_options

def _iapt_anti_iapec_truthy(value):
    if value is True or value == 1:
        return True
    if value is False or value == 0 or value is None:
        return False
    return str(value).strip().lower() in {'1', 'true', 'yes', 'on', 'y'}

def _sanitize_decrypt_options(options: dict, user_id: int):
    raw = dict(options or {})
    clean, feature_id, feature_scope = _IAPT_ANTI_IAPEC_PREV_SANITIZE(raw, user_id)
    requested = _iapt_anti_iapec_truthy(raw.get('anti_iapec_encryption'))
    clean['anti_iapec_encryption'] = bool(requested)
    if requested:
        anti_feature_id = int(globals().get('FEATURE_ANTI_QIUSHUI', 17) or 17)
        exact = globals().get('_iapt_v1_exact_subscription')
        subscription = exact(int(user_id), anti_feature_id) if callable(exact) else None
        if not subscription:
            raise HTTPException(403, '功能不可用')
        if not isinstance(feature_scope, dict):
            feature_scope = {}
        feature_scope[str(anti_feature_id)] = int((subscription or {}).get('sub_id') or 0)
        required = []
        source_required = clean.get('required_feature_ids', raw.get('required_feature_ids'))
        if isinstance(source_required, (list, tuple, set)):
            for item in source_required:
                try:
                    value = int(item)
                    if value > 0 and value not in required:
                        required.append(value)
                except Exception:
                    pass
        if anti_feature_id not in required:
            required.append(anti_feature_id)
        clean['required_feature_ids'] = required
        clean['anti_iapec_feature_id'] = anti_feature_id
        clean['anti_iapec_restore_strategy'] = 'exact-native-efficient/base64+emoji-digit+xor-ZhaoLingYa/before-v3-filename-fixpoint'
        # A pure anti-iAPEC task is feature 17. Combined tasks keep their
        # existing primary mode and use feature 17 as an additive requirement.
        try:
            current = int(feature_id or 0)
        except Exception:
            current = 0
        if current in (0, int(globals().get('FEATURE_BASIC', 1) or 1)):
            feature_id = anti_feature_id
            clean['primary_feature_id'] = anti_feature_id
        else:
            clean.setdefault('primary_feature_id', current)
    return clean, feature_id, feature_scope

try:
    @app.get('/api/system/anti-iapec', include_in_schema=False)
    def _iapt_anti_iapec_status():
        return {
            'ok': True,
            'version': 'anti-iapec-v1-exact-efficient-native',
            'option': 'anti_iapec_encryption',
            'feature_id': int(globals().get('FEATURE_ANTI_QIUSHUI', 17) or 17),
            'independent_from_anti_encrypted_sample': True,
        }
except Exception:
    pass
# IAPT_ANTI_IAPEC_MAIN_V1_END

# IAPT_IAPEC_SPLIT_V13_MAIN_BEGIN
_IAPT_IAPEC_SPLIT_V13_PREV_SANITIZE = _sanitize_decrypt_options

def _iapt_iapec_v13_truthy(value):
    if value is True or value == 1:
        return True
    if value is False or value == 0 or value is None:
        return False
    return str(value).strip().lower() in {'1','true','yes','on','y'}

def _sanitize_decrypt_options(options: dict, user_id: int):
    raw = dict(options or {})
    clean, feature_id, feature_scope = _IAPT_IAPEC_SPLIT_V13_PREV_SANITIZE(raw, user_id)
    # 反iAPEC加密 now means only Efficient string/source encryption.
    clean['anti_iapec_encryption'] = bool(_iapt_iapec_v13_truthy(raw.get('anti_iapec_encryption')))
    clean['anti_iapec_restore_strategy'] = 'efficient-string-only/base64+emoji-digit+xor-ZhaoLingYa'
    # Self-destruction/control-type restoration is a separate exact feature-17 switch.
    self_destruct = _iapt_iapec_v13_truthy(raw.get('anti_iapec_self_destruct'))
    clean['anti_iapec_self_destruct'] = bool(self_destruct)
    if self_destruct:
        fid = int(globals().get('FEATURE_ANTI_QIUSHUI', 17) or 17)
        exact = globals().get('_iapt_v1_exact_subscription')
        subscription = exact(int(user_id), fid) if callable(exact) else None
        if not subscription:
            raise HTTPException(403, '功能不可用')
        if not isinstance(feature_scope, dict):
            feature_scope = {}
        feature_scope[str(fid)] = int((subscription or {}).get('sub_id') or 0)
        required=[]
        for item in clean.get('required_feature_ids', raw.get('required_feature_ids')) or []:
            try:
                iv=int(item)
                if iv>0 and iv not in required: required.append(iv)
            except Exception: pass
        if fid not in required: required.append(fid)
        clean['required_feature_ids']=required
        clean['anti_iapec_self_destruct_feature_id']=fid
        clean['anti_iapec_self_destruct_strategy']='libDestruction/profile+layout-semantics/control-type-backfill'
        try: current=int(feature_id or 0)
        except Exception: current=0
        if current in (0, int(globals().get('FEATURE_BASIC',1) or 1)):
            feature_id=fid
            clean['primary_feature_id']=fid
    # iApEcPro-########## is dynamic repair (feature 5), never implied by feature 17.
    dynamic = any(_iapt_iapec_v13_truthy(raw.get(k)) for k in (
        'numeric_source_restore','numeric_restore','dynamic_restore','v3_dynamic_restore','ancient_dynamic_restore'
    )) or str(raw.get('restore_fn_names') or '').strip().lower() in {'on','auto','true','1'}
    clean['iapec_numeric_dynamic_restore'] = bool(dynamic)
    if dynamic:
        clean['iapec_numeric_dynamic_strategy']='iapec-numeric-dispatch+legacy-random-numeric-table'
    return clean, feature_id, feature_scope

try:
    @app.get('/api/system/iapt-iapec-split-v13', include_in_schema=False)
    def _iapt_iapec_split_v13_status():
        return {
            'ok': True,
            'version': 'V13',
            'anti_iapec_encryption': 'efficient-string-only',
            'dynamic_restore': 'iApEcPro-numeric+legacy-random-numeric-table',
            'anti_iapec_self_destruct': 'control-type-backfill',
            'feature_ids': {'dynamic_restore': 5, 'anti_iapec_encryption': 17, 'anti_iapec_self_destruct': 17},
        }
except Exception:
    pass
# IAPT_IAPEC_SPLIT_V13_MAIN_END
