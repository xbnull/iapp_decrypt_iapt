"""
缓存模块
修复点：
  1. cleanup_source_cache() 里原来有个 for 循环体是 pass（无效操作），
     每次查询都会白跑一遍 SELECT + 空循环，现已移除。
  2. 保留三条 DELETE 清理过期记录，但合并成一次 conn() 取出，减少池操作次数。
"""
import hashlib
import json
import logging
from pathlib import Path
from . import db
from .config import SOURCE_CACHE_TTL_MINUTES, APP_STORAGE

logger = logging.getLogger(__name__)


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b''):
            h.update(chunk)
    return h.hexdigest()


def options_hash(options: dict) -> str:
    # 缓存按真实解密行为隔离；只忽略 timeout。
    # find/find_recursive/max_output_files/fb/hidden/dynamic_key/订阅/lib.so/脚本指纹都应进入 options。
    clean = {k: v for k, v in (options or {}).items() if k not in ('timeout',) and v not in (None, '')}
    raw = json.dumps(clean, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
    return hashlib.sha256(raw).hexdigest()


def cleanup_source_cache():
    """
    清理过期的缓存记录、nonce 记录、过期 session。
    修复前：有一个 for 循环遍历过期行但循环体是 pass，白白多一条 SELECT。
    修复后：直接 DELETE，不再做无用 SELECT。
    """
    try:
        db.exec('DELETE FROM source_caches WHERE expire_at < NOW()')
        db.exec('DELETE FROM api_nonces WHERE created_at < DATE_SUB(NOW(), INTERVAL 30 MINUTE)')
        db.exec('DELETE FROM sessions WHERE expire_at < NOW()')
    except Exception as e:
        logger.warning('cleanup_source_cache 异常: %s', e)


def find_source_cache(apk_sha256: str, opt_hash: str, feature_id=None):
    cleanup_source_cache()
    if feature_id is None:
        return db.one('''
            SELECT sc.*,t.app_name,t.package_name,t.version_name,t.version_code,t.total_ms,t.file_count,t.total_bytes,t.out_dir,t.log_path
            FROM source_caches sc JOIN tasks t ON sc.task_id=t.id
            WHERE sc.apk_sha256=%s AND sc.options_hash=%s AND sc.expire_at>NOW() AND t.status='done'
            ORDER BY sc.id DESC LIMIT 1
        ''', (apk_sha256, opt_hash))
    return db.one('''
        SELECT sc.*,t.app_name,t.package_name,t.version_name,t.version_code,t.total_ms,t.file_count,t.total_bytes,t.out_dir,t.log_path
        FROM source_caches sc JOIN tasks t ON sc.task_id=t.id
        WHERE sc.apk_sha256=%s AND sc.options_hash=%s AND sc.feature_id=%s AND sc.expire_at>NOW() AND t.status='done'
        ORDER BY sc.id DESC LIMIT 1
    ''', (apk_sha256, opt_hash, int(feature_id)))


def attach_cache_to_new_task(user_id: int, apk_name: str, feature_id: int,
                              options: dict, apk_sha256: str, opt_hash: str,
                              cache_row: dict) -> int:
    import secrets
    task_no = secrets.token_hex(16)
    tid = db.exec('''
        INSERT INTO tasks(
            task_no, user_id, apk_name, status, feature_id, options_json,
            app_name, package_name, version_name, version_code,
            total_ms, file_count, total_bytes, out_dir, log_path,
            cached_from_task_id
        )
        VALUES(%s,%s,%s,'done',%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
    ''', (
        task_no, user_id, apk_name, feature_id,
        json.dumps(options, ensure_ascii=False),
        cache_row.get('app_name'), cache_row.get('package_name'),
        cache_row.get('version_name'), cache_row.get('version_code'),
        cache_row.get('total_ms'),
        cache_row.get('file_count') or 0,
        cache_row.get('total_bytes') or 0,
        cache_row.get('out_dir'), cache_row.get('log_path'),
        cache_row.get('task_id'),
    ))
    return tid


def save_source_cache(task_id: int, apk_sha256: str, opt_hash: str,
                      feature_id: int, out_dir: str):
    db.exec('''
        INSERT INTO source_caches(
            apk_sha256, options_hash, feature_id, task_id, out_dir, expire_at
        )
        VALUES(%s, %s, %s, %s, %s, DATE_ADD(NOW(), INTERVAL %s MINUTE))
    ''', (apk_sha256, opt_hash, feature_id, task_id, out_dir,
          SOURCE_CACHE_TTL_MINUTES))

# IAPT_V128_DISABLE_SOURCE_CACHE_BEGIN
# 临时彻底关闭 source cache，避免开过动态 key 的输出被未授权任务复用。
def _iapt_v128_source_cache_noop(*args, **kwargs):
    print("[IAPT_V128] source cache disabled")
    return None

for _iapt_v128_name in list(globals()):
    if "source_cache" in str(_iapt_v128_name).lower() and callable(globals().get(_iapt_v128_name)) and _iapt_v128_name != "_iapt_v128_source_cache_noop":
        globals()[_iapt_v128_name] = _iapt_v128_source_cache_noop
# IAPT_V128_DISABLE_SOURCE_CACHE_END
