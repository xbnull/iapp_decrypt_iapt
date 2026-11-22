# -*- coding: utf-8 -*-
from __future__ import annotations
import os, re, shutil, secrets, zipfile
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import FileResponse
from . import db
from .auth import current_user, require_permission
from .config import APP_STORAGE

PERM_TASK_MANAGE = 603
PERM_CLEAR_UPLOADS = 604
PERM_CLEAR_TASK_FILES = 605
PERM_CLEAR_TASK_RECORDS = 606

router = APIRouter()


def _storage_root() -> Path:
    return APP_STORAGE.resolve()


def _inside_storage(p: Path) -> bool:
    try:
        p = p.resolve()
        root = _storage_root()
        return p == root or root in p.parents
    except Exception:
        return False



def _safe_filename(s: str) -> str:
    s = str(s or 'task').strip() or 'task'
    return re.sub(r'[\\/:*?"<>|]+', '_', s)


def _remove_path(p: Path) -> tuple[int, int]:
    try:
        if not _inside_storage(p) or p.resolve() == _storage_root():
            raise HTTPException(400, '拒绝删除 storage 外路径或 storage 根目录')
        if not p.exists():
            return 0, 0
        total = 0
        if p.is_file() or p.is_symlink():
            try:
                total = int(p.stat().st_size or 0)
            except Exception:
                total = 0
            p.unlink(missing_ok=True)
            return 1, total
        cnt = 0
        for fp in p.rglob('*'):
            if fp.is_file():
                cnt += 1
                try:
                    total += int(fp.stat().st_size or 0)
                except Exception:
                    pass
        shutil.rmtree(p, ignore_errors=True)
        return max(1, cnt), total
    except Exception:
        return 0, 0


def _task_upload_path(task: dict) -> Path:
    return APP_STORAGE / 'uploads' / f"{task.get('task_no')}.apk"


def _task_out_dir(task: dict) -> Path:
    od = task.get('out_dir')
    if od:
        return Path(str(od))
    return APP_STORAGE / 'tasks' / str(task.get('task_no'))


def _zip_dir(src: Path, dest: Path) -> int:
    """Build the admin source ZIP using the same public roots as user downloads.

    When res/** exists, preserve src/** and res/** directory names.  This fixes
    the old admin ZIP path that always switched base to src/ and silently lost
    every restored resource.  assets/** and internal files are excluded.
    """
    src_root = src / 'src'
    res_root = src / 'res'
    has_src = src_root.is_dir()
    has_res = res_root.is_dir()
    rows = []

    if has_res:
        roots = []
        if has_src:
            roots.append(src_root)
        roots.append(res_root)
        for root in roots:
            for fp in root.rglob('*'):
                if not fp.is_file() or fp.name.startswith('.'):
                    continue
                rel = fp.relative_to(src).as_posix()
                if '/.tmp/' in '/' + rel or rel.startswith(('.tmp/', '.iapt_internal/', 'logs/')):
                    continue
                rows.append((fp, rel))
    elif has_src:
        # Keep legacy root layout for src-only tasks.
        for fp in src_root.rglob('*'):
            if not fp.is_file() or fp.name.startswith('.'):
                continue
            rel = fp.relative_to(src_root).as_posix()
            if '/.tmp/' in '/' + rel:
                continue
            rows.append((fp, rel))
    else:
        raise HTTPException(404, '任务 src/res 文件为空或已被清理')

    rows.sort(key=lambda x: x[1])
    if not rows:
        raise HTTPException(404, '任务 src/res 文件为空或已被清理')
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as z:
        for fp, rel in rows:
            z.write(fp, rel)
    return len(rows)


def _candidate_icon_from_apk(apk_path: Path) -> tuple[bytes, str] | None:
    if not apk_path.exists() or apk_path.stat().st_size <= 0:
        return None
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            best = None
            for info in z.infolist():
                name = info.filename.replace('\\', '/')
                low = name.lower()
                if info.is_dir():
                    continue
                if not (low.endswith('.png') or low.endswith('.webp') or low.endswith('.jpg') or low.endswith('.jpeg')):
                    continue
                if not (low.startswith('res/mipmap') or low.startswith('res/drawable') or low.startswith('assets/')):
                    continue
                score = 0
                if 'ic_launcher' in low: score += 120
                if 'launcher' in low: score += 80
                if 'icon' in low: score += 60
                if 'logo' in low: score += 40
                if 'xxxhdpi' in low: score += 12
                elif 'xxhdpi' in low: score += 10
                elif 'xhdpi' in low: score += 8
                elif 'hdpi' in low: score += 6
                elif 'mdpi' in low: score += 4
                if 'foreground' in low: score -= 35
                if 'background' in low: score -= 35
                if 'round' in low: score -= 10
                if score <= 0:
                    continue
                size = int(info.file_size or 0)
                if size <= 0 or size > 2 * 1024 * 1024:
                    continue
                key = (score, min(size, 512 * 1024))
                if best is None or key > best[0]:
                    media = 'image/png'
                    if low.endswith('.webp'): media = 'image/webp'
                    elif low.endswith('.jpg') or low.endswith('.jpeg'): media = 'image/jpeg'
                    best = (key, info.filename, media)
            if best is None:
                return None
            data = z.read(best[1])
            return data, best[2]
    except Exception:
        return None


@router.get('/api/tasks/{task_id}/icon')
def task_icon(task_id: int, user=Depends(current_user)):
    task = db.one('SELECT id,task_no,user_id FROM tasks WHERE id=%s AND user_id=%s', (task_id, user['id']))
    if not task:
        raise HTTPException(404, '任务不存在')
    got = _candidate_icon_from_apk(_task_upload_path(task))
    if not got:
        raise HTTPException(404, '未找到图标')
    data, media = got
    return Response(data, media_type=media, headers={'Cache-Control': 'public, max-age=86400'})




def _admin_audit(user: dict, action: str, payload: dict) -> None:
    try:
        db.exec(
            'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
            (
                int((user or {}).get('id') or 0),
                str(action or ''),
                __import__('json').dumps(payload or {}, ensure_ascii=False, default=str),
            ),
        )
    except Exception:
        pass


def _cancel_admin_task(task_id: int, user: dict, reason: str) -> dict:
    from .decrypt_runner import cancel_task_process
    result = cancel_task_process(int(task_id), reason)
    _admin_audit(user, 'cancel_task', {
        'task_id': int(task_id),
        'reason': str(reason or ''),
        'result': result,
    })
    return result


@router.post('/api/admin/tasks/cancel-all')
def admin_cancel_all_tasks(user=Depends(current_user)):
    """Stop every queued/running decrypt task without restarting the API."""
    require_permission(user, PERM_TASK_MANAGE)
    rows = db.all(
        "SELECT id,task_no,status,user_id,apk_name FROM tasks "
        "WHERE LOWER(COALESCE(status,'')) IN ('queued','running') ORDER BY id ASC"
    ) or []
    admin_id = int((user or {}).get('id') or 0)
    reason = f'管理员已停止全部任务（管理员ID {admin_id}）'
    stopped = []
    already_finished = []
    failed = []
    for row in rows:
        task_id = int((row or {}).get('id') or 0)
        if task_id <= 0:
            continue
        try:
            result = _cancel_admin_task(task_id, user, reason)
            item = {
                'task_id': task_id,
                'task_no': str((row or {}).get('task_no') or ''),
                'previous_status': str((row or {}).get('status') or ''),
                'status': str((result or {}).get('status') or ''),
                'signal_sent': bool((result or {}).get('signal_sent')),
                'pid': int((result or {}).get('pid') or 0),
                'message': str((result or {}).get('message') or ''),
            }
            if item['status'] == 'cancelled':
                stopped.append(item)
            else:
                already_finished.append(item)
        except Exception as exc:
            failed.append({'task_id': task_id, 'error': str(exc)})
    summary = {
        'matched': len(rows),
        'stopped': len(stopped),
        'already_finished': len(already_finished),
        'failed': len(failed),
    }
    _admin_audit(user, 'cancel_all_tasks', {
        'summary': summary,
        'task_ids': [int(x.get('task_id') or 0) for x in stopped],
        'failed': failed,
    })
    return {
        'ok': len(failed) == 0,
        'summary': summary,
        'items': stopped,
        'already_finished_items': already_finished,
        'failed_items': failed,
        'message': f"已停止 {len(stopped)} 个任务" + (f"，{len(failed)} 个失败" if failed else ''),
    }


@router.post('/api/admin/tasks/{task_id}/cancel')
def admin_cancel_task(task_id: int, user=Depends(current_user)):
    """Stop one queued/running decrypt task owned by any user."""
    require_permission(user, PERM_TASK_MANAGE)
    task = db.one('SELECT id,task_no,status,user_id,apk_name FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise HTTPException(404, '任务不存在')
    admin_id = int((user or {}).get('id') or 0)
    try:
        result = _cancel_admin_task(int(task_id), user, f'管理员已停止任务（管理员ID {admin_id}）')
    except RuntimeError as exc:
        raise HTTPException(400, str(exc))
    except Exception as exc:
        raise HTTPException(500, '停止任务失败：' + str(exc))
    result['task_no'] = str(task.get('task_no') or '')
    result['apk_name'] = str(task.get('apk_name') or '')
    return result


@router.get('/api/admin/tasks/{task_id}/download-source')
def admin_download_task_source(task_id: int, request: Request, user=Depends(current_user)):
    require_permission(user, PERM_TASK_MANAGE)
    task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
    if not task:
        raise HTTPException(404, '任务不存在')
    out_dir = _task_out_dir(task)
    if not out_dir.exists() or not out_dir.is_dir():
        raise HTTPException(404, '任务源码文件不存在或已被清理')
    zip_dir = APP_STORAGE / 'zips'
    zip_dir.mkdir(parents=True, exist_ok=True)
    zip_path = zip_dir / f"admin_src_{task.get('task_no')}_{secrets.token_hex(4)}.zip"
    count = _zip_dir(out_dir, zip_path)
    name = _safe_filename(task.get('apk_name') or task.get('task_no'))
    if name.lower().endswith('.apk'):
        name = name[:-4]
    return FileResponse(zip_path, filename=f'{name}_source.zip', media_type='application/zip', headers={'X-File-Count': str(count)})


@router.post('/api/admin/tasks/{task_id}/delete')
def admin_delete_task(task_id: int, user=Depends(current_user)):
    require_permission(user, PERM_TASK_MANAGE)
    task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
    if not task:
        raise HTTPException(404, '任务不存在')
    deleted = 0
    bytes_sum = 0
    # 删除任务只删除上传包和该任务相关压缩包；不删除源码目录，避免误删大量文件。
    for p in (_task_upload_path(task),):
        c, b = _remove_path(p); deleted += c; bytes_sum += b
    # 清掉该任务可能产生的临时 zip/加密 zip。
    for sub in ('zips', 'secure_zips'):
        d = APP_STORAGE / sub
        if d.exists():
            for fp in d.glob(f"*{task.get('task_no')}*"):
                c, b = _remove_path(fp); deleted += c; bytes_sum += b
    for sql, params in (
        ('DELETE FROM task_files WHERE task_id=%s', (task_id,)),
        ('DELETE FROM downloads WHERE task_id=%s', (task_id,)),
        ('DELETE FROM source_caches WHERE task_id=%s', (task_id,)),
        ('DELETE FROM tasks WHERE id=%s', (task_id,)),
    ):
        try:
            db.exec(sql, params)
        except Exception:
            pass
    return {'ok': True, 'deleted': deleted, 'bytes': bytes_sum}


@router.post('/api/admin/storage/clear-uploads')
def admin_clear_uploads(user=Depends(current_user)):
    require_permission(user, PERM_CLEAR_UPLOADS)
    d = APP_STORAGE / 'uploads'
    d.mkdir(parents=True, exist_ok=True)
    deleted = 0; bytes_sum = 0
    for p in list(d.iterdir()):
        c, b = _remove_path(p); deleted += c; bytes_sum += b
    return {'ok': True, 'deleted': deleted, 'bytes': bytes_sum, 'kind': 'uploads'}


@router.post('/api/admin/storage/clear-tasks')
def admin_clear_task_files(user=Depends(current_user)):
    require_permission(user, PERM_CLEAR_TASK_FILES)
    deleted = 0; bytes_sum = 0
    for name in ('tasks', 'zips', 'secure_zips'):
        d = APP_STORAGE / name
        d.mkdir(parents=True, exist_ok=True)
        for p in list(d.iterdir()):
            c, b = _remove_path(p); deleted += c; bytes_sum += b
    try:
        db.exec("""
            UPDATE tasks SET out_dir=NULL,file_count=0,total_bytes=0,downloadable_file_count=0,downloadable_bytes=0,
            quota_note=CONCAT(COALESCE(quota_note,''), '\n管理员已清空任务文件')
        """)
    except Exception:
        pass
    return {'ok': True, 'deleted': deleted, 'bytes': bytes_sum, 'kind': 'tasks'}


@router.post('/api/admin/tasks/clear-records')
def admin_clear_task_records(user=Depends(current_user)):
    require_permission(user, PERM_CLEAR_TASK_RECORDS)

    tables = ('task_files', 'downloads', 'source_caches', 'tasks')
    counts = {}
    for table in tables:
        try:
            row = db.one(f'SELECT COUNT(*) AS c FROM `{table}`')
            counts[table] = int((row or {}).get('c') or 0)
        except Exception:
            counts[table] = 0

    # V122：不使用 db.transaction，不读取 c.autocommit；每个表单独执行，避免 DBUtils 兼容性 500。
    for table in tables:
        try:
            db.exec(f'DELETE FROM `{table}`')
        except Exception:
            pass
    for table in ('tasks', 'task_files', 'downloads', 'source_caches'):
        try:
            db.exec(f'ALTER TABLE `{table}` AUTO_INCREMENT=1')
        except Exception:
            pass

    try:
        db.exec(
            'INSERT INTO admin_logs(admin_id,action,payload_json) VALUES(%s,%s,%s)',
            (user['id'], 'clear_task_records', __import__('json').dumps({'counts': counts, 'fix':'v122'}, ensure_ascii=False)),
        )
    except Exception:
        pass
    return {'ok': True, 'kind': 'task_records', 'deleted': counts, 'reset_auto_increment': True, 'fix': 'v122-no-autocommit'}