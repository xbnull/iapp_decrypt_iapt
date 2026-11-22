"""
解密执行器
修复点：
  原版没有限制同时运行的解密子进程数量。每个解密任务会 fork 一个
  python3 子进程（iapp_auto_decrypt.py 本身就很重），多个任务并发时
  内存容易耗尽，触发 Linux OOM Killer 把整个 uvicorn 进程杀掉。
  这是"服务突然掉、过很久才好"的主要原因之一。

  修复：用进程级 Semaphore 限制同时运行的解密子进程数（默认 1，
  可通过 .env 里的 MAX_DECRYPT_WORKERS 调整）。
  获取不到 Semaphore 的任务会在队列里等待，不会被丢弃。
"""
import json
import hashlib
import logging
import math
import os
import re
import shutil
import subprocess
import threading
import time
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

from . import db
from .config import APP_STORAGE, MAX_DECRYPT_WORKERS, IAPT_ENUM_WORKERS, IAPT_NORMAL_WORKERS, IAPT_JOINT_DEX_HINT_FIRST, IAPT_JOINT_FAST_HIDDEN_LIMIT, IAPT_JOINT_FAST_HIDDEN_BATCH_SIZE, IAPT_JOINT_NO_HINT_HIDDEN_MAJOR, IAPT_JOINT_NO_HINT_MIN_HIDDEN
from .apk_meta import extract_v3_apk_meta, merge_meta_nonempty, update_task_meta_if_empty

logger = logging.getLogger(__name__)

SCRIPT = Path(__file__).resolve().parent / "tools" / "iapp_auto_decrypt.py"
V6_SCRIPT = Path(__file__).resolve().parent / "tools" / "iapp_dex2iyu_v6.py"

TEXT_EXTS = {".iyu", ".myu", ".mjava", ".ijava", ".mlua", ".ilua",
             ".mjs", ".ijs", ".txt", ".xml", ".json"}

# -----------------------------------------------------------------------
# 并发限制：同时最多运行 MAX_DECRYPT_WORKERS 个解密子进程。
# 解密工具内存占用大（APK 解析 + DEX 处理），并发过多会触发 OOM。
# 默认值 1 适合 2C/1G 低配服务器；内存 >=8G 可调到 4。
# -----------------------------------------------------------------------
_MAX_WORKERS = max(1, int(MAX_DECRYPT_WORKERS or 1))
_decrypt_semaphore = threading.Semaphore(_MAX_WORKERS)


class _IaptProcResult:
    def __init__(self, returncode: int, stdout: str):
        self.returncode = int(returncode)
        self.stdout = stdout or ""


def _iapt_truthy(v) -> bool:
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _read_kv_file(path: Path) -> dict:
    out = {}
    try:
        if not path.exists():
            return out
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip().strip('"').strip("'")
    except Exception as e:
        logger.warning("读取远程 DEX worker 配置失败: %s", e)
    return out


def _dex_remote_config() -> dict | None:
    cfg_path = Path(os.environ.get("DEX_ENUM_REMOTE_CONFIG") or (APP_STORAGE.parent / ".dex_worker_8c.txt"))
    cfg = _read_kv_file(cfg_path)
    host = cfg.get("SSH_HOST") or cfg.get("HOST")
    if not host:
        return None
    cfg.setdefault("SSH_HOST", host)
    cfg.setdefault("SSH_USER", cfg.get("USER") or "root")
    cfg.setdefault("SSH_PORT", cfg.get("PORT") or "22")
    cfg.setdefault("REMOTE_DIR", "/www/wwwroot/iapt")
    cfg.setdefault("REMOTE_WORK_DIR", cfg["REMOTE_DIR"].rstrip("/") + "/storage/remote_dex_jobs")
    return cfg


def _ssh_target(cfg: dict) -> str:
    return "%s@%s" % (cfg.get("SSH_USER") or "root", cfg.get("SSH_HOST"))


def _ssh_cmd(cfg: dict, scp: bool = False) -> tuple[list, dict]:
    env = os.environ.copy()
    base = ["scp" if scp else "ssh"]
    passwd = cfg.get("SSH_PASS") or cfg.get("SSH_PASSWORD") or cfg.get("PASSWORD") or cfg.get("PASS")
    key = cfg.get("SSH_KEY") or cfg.get("KEY")
    if passwd and not key:
        base = ["sshpass", "-e"] + base
        env["SSHPASS"] = passwd
    if scp:
        base += ["-P", str(cfg.get("SSH_PORT") or "22")]
    else:
        base += ["-p", str(cfg.get("SSH_PORT") or "22")]
    base += ["-o", "StrictHostKeyChecking=accept-new", "-o", "ServerAliveInterval=20"]
    if key:
        base += ["-i", str(key)]
    return base, env


def _run_ssh(cfg: dict, remote_script: str, check: bool = True) -> subprocess.CompletedProcess:
    import shlex
    base, env = _ssh_cmd(cfg, scp=False)
    cmd = base + [_ssh_target(cfg), "bash", "-lc", remote_script]
    cp = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if check and cp.returncode != 0:
        raise RuntimeError("remote ssh failed: " + (cp.stdout or "")[-2000:])
    return cp


def _run_scp_to(cfg: dict, local_path: Path, remote_path: str):
    base, env = _ssh_cmd(cfg, scp=True)
    cmd = base + [str(local_path), _ssh_target(cfg) + ":" + remote_path]
    cp = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if cp.returncode != 0:
        raise RuntimeError("remote upload failed: " + (cp.stdout or "")[-2000:])


def _run_scp_from(cfg: dict, remote_path: str, local_path: Path):
    base, env = _ssh_cmd(cfg, scp=True)
    cmd = base + [_ssh_target(cfg) + ":" + remote_path, str(local_path)]
    cp = subprocess.run(cmd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    if cp.returncode != 0:
        raise RuntimeError("remote download failed: " + (cp.stdout or "")[-2000:])


def _rewrite_remote_args(cmd: list, remote_apk: str, remote_out: str) -> list:
    args = [str(x) for x in (cmd or [])]
    if len(args) >= 2:
        args = args[2:]
    out = []
    i = 0
    while i < len(args):
        if args[i] == "--apk" and i + 1 < len(args):
            out += ["--apk", remote_apk]
            i += 2
        elif args[i] == "--outdir" and i + 1 < len(args):
            out += ["--outdir", remote_out]
            i += 2
        else:
            out.append(args[i])
            i += 1
    return out


def _extract_tar_safe(tar_path: Path, dest: Path):
    dest.mkdir(parents=True, exist_ok=True)
    root = dest.resolve()
    with tarfile.open(tar_path, "r:gz") as tf:
        for m in tf.getmembers():
            target = (dest / m.name).resolve()
            if not (target == root or root in target.parents):
                raise RuntimeError("unsafe tar path: " + m.name)
        tf.extractall(dest)


def _run_remote_dex_process(cmd: list, apk_path: Path, out_dir: Path, options: dict, task: dict) -> _IaptProcResult:
    import shlex
    cfg = _dex_remote_config()
    if not cfg:
        return None
    task_no = str((task or {}).get("task_no") or int(time.time()))
    remote_dir = cfg["REMOTE_DIR"].rstrip("/")
    remote_base = cfg["REMOTE_WORK_DIR"].rstrip("/")
    remote_job = remote_base + "/" + task_no + "_" + str(int(time.time()))
    remote_apk = remote_job + "/input.apk"
    remote_out = remote_job + "/out"
    remote_tgz = remote_job + "/out.tgz"
    out_dir.mkdir(parents=True, exist_ok=True)

    log_parts = ["[IAPT_REMOTE_DEX_ENUM] enabled host=%s work=%s" % (cfg.get("SSH_HOST"), remote_job)]
    _run_ssh(cfg, "mkdir -p %s %s" % (shlex.quote(remote_job), shlex.quote(remote_out)))
    _run_scp_to(cfg, apk_path, remote_apk)

    remote_args = _rewrite_remote_args(cmd, remote_apk, remote_out)
    remote_cmd = (
        "cd {rd}; "
        "PY={py}; "
        "if [ ! -x \"$PY\" ]; then PY={py2}; fi; "
        "PYTHONPATH={rd} \"$PY\" app/tools/iapp_auto_decrypt.py {args}"
    ).format(
        rd=shlex.quote(remote_dir),
        py=shlex.quote(cfg.get("PYTHON") or (remote_dir + "/venv/bin/python")),
        py2=shlex.quote("python3"),
        args=" ".join(shlex.quote(x) for x in remote_args),
    )
    cp = _run_ssh(cfg, remote_cmd, check=False)
    log_parts.append(cp.stdout or "")
    tar_cp = _run_ssh(cfg, "tar -czf %s -C %s . 2>/dev/null || true; ls -l %s 2>/dev/null || true" % (
        shlex.quote(remote_tgz), shlex.quote(remote_out), shlex.quote(remote_tgz)
    ), check=False)
    log_parts.append("[IAPT_REMOTE_TAR]\n" + (tar_cp.stdout or ""))
    with tempfile.TemporaryDirectory(prefix="iapt_remote_dex_") as td:
        local_tgz = Path(td) / "out.tgz"
        try:
            _run_scp_from(cfg, remote_tgz, local_tgz)
            if local_tgz.exists() and local_tgz.stat().st_size > 0:
                _extract_tar_safe(local_tgz, out_dir)
        except Exception as e:
            log_parts.append("[IAPT_REMOTE_FETCH_WARN] " + str(e))
    if not _iapt_truthy(cfg.get("KEEP_REMOTE")):
        _run_ssh(cfg, "rm -rf %s" % shlex.quote(remote_job), check=False)
    return _IaptProcResult(cp.returncode, "\n".join(log_parts))


def run_decrypt_process(cmd: list, apk_path: Path, out_dir: Path, options: dict, task: dict, env: dict | None = None) -> _IaptProcResult:
    from .task_feature_guard_v191 import enforce_task_or_mark_failed
    _iapt_guard_task_id = int((task or {}).get('id') or (task or {}).get('task_id') or 0)
    if _iapt_guard_task_id <= 0 or not enforce_task_or_mark_failed(_iapt_guard_task_id, stage='run_decrypt_process'):
        raise PermissionError('task feature denied before decrypt process')
    if _iapt_truthy((options or {}).get("dex_enum")):
        try:
            remote = _run_remote_dex_process(cmd, apk_path, out_dir, options, task)
            if remote is not None:
                return remote
        except Exception as e:
            logger.warning("远程 DEX 枚举失败，回退本机执行: %s", e)
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=None, env=env)
    return _IaptProcResult(proc.returncode, proc.stdout or "")


def parse_meta(log_text: str) -> dict:
    meta = {}
    text = log_text or ""
    patterns = {
        "total_ms": [r"\[T\]\s+script total\s+([0-9.]+)\s+ms"],
        "package_name": [
            r"(?:^|[\s\[\]+])package(?:Name)?\s*[:=]\s*([^\s,\r\n]+)",
            r"packageName\s+([^\s,\r\n]+)",
        ],
        "version_name": [
            r"versionName\s*[:=]\s*([^\r\n]+)",
            r"version_name\s*[:=]\s*([^\r\n]+)",
        ],
        "version_code": [
            r"versionCode\s*[:=]\s*([^\r\n]+)",
            r"version_code\s*[:=]\s*([^\r\n]+)",
        ],
        "app_name": [
            r"appLabel\s*[:=]\s*([^\r\n]+)",
            r"app_name\s*[:=]\s*([^\r\n]+)",
            r"appName\s*[:=]\s*([^\r\n]+)",
        ],
    }
    for key, pats in patterns.items():
        for pat in pats:
            m = re.search(pat, text, flags=re.I | re.M)
            if not m:
                continue
            val = str(m.group(1)).strip().strip('"\'')
            if val and val.lower() not in ('none', 'null', 'unknown', '未找到'):
                meta[key] = val
                break
    return meta


# IAPT_TASK_META_FALLBACK_BEGIN
def meta_from_apk_path(apk_path: Path) -> dict:
    """Read AndroidManifest.xml directly so task metadata will not become null when log parsing changes."""
    meta = {}
    try:
        import zipfile as _zipfile
        with _zipfile.ZipFile(apk_path) as z:
            manifest = z.read('AndroidManifest.xml')
    except Exception:
        return meta
    try:
        from .tools.iapp_auto_decrypt import parse_axml_manifest, parse_int_auto
        params = parse_axml_manifest(manifest) or {}
        if params.get('package'):
            meta['package_name'] = str(params.get('package') or '').strip()
        if params.get('versionName'):
            meta['version_name'] = str(params.get('versionName') or '').strip()
        if params.get('versionCode') not in (None, ''):
            try:
                meta['version_code'] = str(parse_int_auto(params.get('versionCode')))
            except Exception:
                meta['version_code'] = str(params.get('versionCode') or '').strip()
        if params.get('appLabel'):
            meta['app_name'] = str(params.get('appLabel') or '').strip()
    except Exception:
        pass
    return {k: v for k, v in meta.items() if v and str(v).lower() not in ('none', 'null')}
# IAPT_TASK_META_FALLBACK_END



# IAPT_TASK_META_RUNTIME_HELPER_BEGIN
def iapt_task_clean_meta_value(v):
    if v is None:
        return None
    v = str(v).strip().strip('"\'')
    if not v:
        return None
    if v.lower() in ('none', 'null', 'unknown', '未找到', '未知'):
        return None
    return v


def iapt_meta_from_apk_path(apk_path):
    """从 APK 的 AndroidManifest.xml/resources.arsc 直接读取任务元信息，避免日志解析为空导致新任务字段 null。"""
    meta = {}
    try:
        import zipfile as _zipfile
        apk_path = Path(apk_path)
        with _zipfile.ZipFile(apk_path, 'r') as z:
            if 'AndroidManifest.xml' not in z.namelist():
                return meta
            manifest = z.read('AndroidManifest.xml')
            resources = z.read('resources.arsc') if 'resources.arsc' in z.namelist() else None
    except Exception:
        return meta
    try:
        from .tools.iapp_auto_decrypt import parse_axml_manifest
        try:
            from .tools.iapp_auto_decrypt import resolve_arsc_string_ref
        except Exception:
            resolve_arsc_string_ref = None
        params = parse_axml_manifest(manifest) or {}
        pkg = iapt_task_clean_meta_value(params.get('package'))
        ver_name = iapt_task_clean_meta_value(params.get('versionName'))
        ver_code = iapt_task_clean_meta_value(params.get('versionCode'))
        app_label = iapt_task_clean_meta_value(params.get('appLabel'))
        if app_label and app_label.startswith('@') and resources and resolve_arsc_string_ref:
            try:
                resolved = iapt_task_clean_meta_value(resolve_arsc_string_ref(resources, app_label))
                if resolved:
                    app_label = resolved
            except Exception:
                pass
        if pkg:
            meta['package_name'] = pkg
        if ver_name:
            meta['version_name'] = ver_name
        if ver_code:
            meta['version_code'] = ver_code
        if app_label:
            meta['app_name'] = app_label
    except Exception:
        pass
    return {k: v for k, v in meta.items() if iapt_task_clean_meta_value(v)}


def iapt_merge_task_meta(meta, task_row, apk_path):
    """优先使用日志有效值；日志为空/错时用 APK Manifest；再保留数据库旧值，禁止覆盖成 null。"""
    try:
        old = task_row or {}
        apk_meta = iapt_meta_from_apk_path(apk_path)
        if not isinstance(meta, dict):
            meta = {}
        out = dict(meta)
        for k in ('app_name', 'package_name', 'version_name', 'version_code'):
            v = iapt_task_clean_meta_value(out.get(k))
            if not v:
                v = iapt_task_clean_meta_value(apk_meta.get(k))
            if not v:
                v = iapt_task_clean_meta_value(old.get(k))
            if v:
                out[k] = v
            elif k in out:
                out.pop(k, None)
        return out
    except Exception:
        return meta if isinstance(meta, dict) else {}
# IAPT_TASK_META_RUNTIME_HELPER_END






# IAPT_V3_RUNNER_META_FIX_HELPERS_V5

def _iapt_truthy(v):
    return v in (True, 1, "1", "true", "TRUE", "True", "on", "ON", "yes", "YES")


def _iapt_runner_python():
    p = os.environ.get("IAPT_PYTHON")
    if p and Path(p).exists():
        return p
    venv = Path(__file__).resolve().parents[1] / "venv" / "bin" / "python"
    if venv.exists():
        return str(venv)
    venv2 = Path(__file__).resolve().parents[1] / ".venv" / "bin" / "python"
    if venv2.exists():
        return str(venv2)
    return sys.executable or "python3"


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    # IAPT v122 stable build_cmd.
    # 免费/无功能 0/4：不启用 outer-mode auto，不传 max_output_files<=1，不自动递归 find。
    options = dict(options or {})
    cmd = ["python3", str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def _truthy(v):
        return v in (True, 1, "1", "true", "TRUE", "True", "yes", "YES", "on", "ON")

    def _add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def _add_bool(api_name, flag):
        if _truthy(options.get(api_name)):
            cmd.append(flag)

    def _collect_ids(v, out=None):
        import json as _json, re as _re
        if out is None:
            out = set()
        if v is None or isinstance(v, bool):
            return out
        if isinstance(v, int):
            out.add(v)
            return out
        if isinstance(v, (list, tuple, set)):
            for x in v:
                _collect_ids(x, out)
            return out
        if isinstance(v, dict):
            for k, x in v.items():
                lk = str(k).lower()
                if lk in ("features", "feature_ids", "features_json", "feature_list", "subscription_features", "permissions"):
                    _collect_ids(x, out)
            return out
        if isinstance(v, str):
            s = v.strip()
            if not s:
                return out
            try:
                _collect_ids(_json.loads(s), out)
                return out
            except Exception:
                pass
            for n in _re.findall(r"-?\d+", s):
                try:
                    out.add(int(n))
                except Exception:
                    pass
        return out

    feature_ids = _collect_ids(options)
    dynamic_allowed = (999 in feature_ids) or (0 in feature_ids) or (4 in feature_ids)

    _add_value("user_password", "--user-password")
    _add_value("fb", "--fb")
    _add_value("hidden", "--hidden")
    # Forward the client's raw archive metadata.  In anti mode v3_entry treats
    # these as source values, applies only statically proven idbfj transforms,
    # and then forwards the effective values to iapp_auto_decrypt.py.
    if str(options.get("package_name") or options.get("package") or "").strip():
        cmd.extend(["--package", str(options.get("package_name") or options.get("package")).strip()])
    if str(options.get("version_name") or "").strip():
        cmd.extend(["--version-name", str(options.get("version_name")).strip()])
    if str(options.get("version_code") or "").strip():
        cmd.extend(["--version-code", str(options.get("version_code")).strip()])
    if str(options.get("app_name") or options.get("client_app_name") or options.get("label") or "").strip():
        cmd.extend(["--app-label", str(options.get("app_name") or options.get("client_app_name") or options.get("label")).strip()])
    _add_value("post_key", "--post-key")
    _add_value("key_xor", "--key-xor")
    _add_value("restore_fn_names", "--restore-fn-names")
    _add_value("fast_c", "--fast-c")
    _add_value("threads", "--threads")
    _add_value("main_file", "--main-file")

    # 文件名查找：仅兼容旧客户端；新版客户端从任务列表调用文件搜索接口。
    has_find = bool(str(options.get("find") or "").strip())
    if has_find:
        _add_value("find", "--find")
    else:
        _add_bool("find_recursive", "--find-recursive")

    # max_output_files <= 1 不传，避免所有样本只出一个文件。
    mv = options.get("max_output_files")
    try:
        mi = int(str(mv).strip()) if mv is not None and str(mv).strip() != "" else 0
    except Exception:
        mi = 0
    if mi > 1:
        cmd.extend(["--max-output-files", str(mi)])

    _add_bool("dex_enum", "--dex-enum")
    _add_value("dex_enum_start", "--dex-enum-start")
    _add_value("dex_enum_limit", "--dex-enum-limit")
    _add_value("dex_enum_windows", "--dex-enum-windows")
    _add_bool("hidden_enum", "--hidden-enum")
    _add_value("hidden_prefix", "--hidden-prefix")
    _add_value("hidden_charset", "--hidden-charset")
    _add_value("hidden_candidates", "--hidden-candidates")
    _add_value("hidden_candidates_file", "--hidden-candidates-file")
    _add_value("max_hidden_candidates", "--max-hidden-candidates")
    _add_value("enum_workers", "--enum-workers")
    _add_value("enum_chunk_size", "--enum-chunk-size")
    _add_value("member_marker_mode", "--member-marker-mode")
    _add_value("member_name_scan", "--member-name-scan")
    _add_value("member_batch_size", "--member-batch-size")

    cmd.extend(["--mode", "auto"])

    if dynamic_allowed:
        cmd.extend(["--outer-mode", "auto"])
    else:
        # 关键：免费/未开动态 key 时不再开启 outer-mode auto。
        # 只传禁缓存/禁动态标记，避免 dynamic-pack/numeric-bridge 被免费跑出来。
        if "--no-key-cache" not in cmd:
            cmd.append("--no-key-cache")
        if "--no-dynamic-key" not in cmd:
            cmd.append("--no-dynamic-key")

    print("[IAPT_V122] feature_ids=%s dynamic_allowed=%s max_output_files=%s has_find=%s" % (sorted(feature_ids), dynamic_allowed, mi, has_find))
    print("[IAPT_V122] cmd=" + " ".join(map(str, cmd)))

    # IAPT_V123_RUNNER_GATE_BEGIN
    def _iapt_v123_collect_ids(v, out=None):
        import json as _json, re as _re
        if out is None:
            out=set()
        if v is None or isinstance(v, bool):
            return out
        if isinstance(v, int):
            out.add(v); return out
        if isinstance(v, (list, tuple, set)):
            for _x in v:
                _iapt_v123_collect_ids(_x, out)
            return out
        if isinstance(v, dict):
            for _k,_x in v.items():
                if str(_k).lower() in ("features","feature_ids","features_json","feature_list","subscription_features","permissions"):
                    _iapt_v123_collect_ids(_x, out)
            return out
        if isinstance(v, str):
            _s=v.strip()
            if not _s:
                return out
            try:
                _iapt_v123_collect_ids(_json.loads(_s), out); return out
            except Exception:
                pass
            for _n in _re.findall(r"-?\d+", _s):
                try:
                    out.add(int(_n))
                except Exception:
                    pass
        return out
    def _iapt_v123_strip_flag(cmd_list, flag, has_value=True):
        out=[]
        i=0
        while i < len(cmd_list):
            if str(cmd_list[i]) == flag:
                i += 2 if has_value else 1
                continue
            out.append(cmd_list[i])
            i += 1
        return out
    def _iapt_v123_set_flag(cmd_list, flag, value):
        cmd_list = _iapt_v123_strip_flag(cmd_list, flag, True)
        cmd_list.extend([flag, str(value)])
        return cmd_list
    _iapt_v123_ids=_iapt_v123_collect_ids(options if isinstance(options, dict) else {})
    _iapt_v123_allowed=(999 in _iapt_v123_ids) or (0 in _iapt_v123_ids) or (4 in _iapt_v123_ids)
    # 修复只出一个文件：max_output_files <= 1 不传。
    _iapt_v123_cmd=[]
    _iapt_v123_i=0
    while _iapt_v123_i < len(cmd):
        _x=str(cmd[_iapt_v123_i])
        if _x == "--max-output-files" and _iapt_v123_i + 1 < len(cmd):
            try:
                _mv=int(str(cmd[_iapt_v123_i+1]).strip())
            except Exception:
                _mv=0
            if _mv <= 1:
                _iapt_v123_i += 2
                continue
        _iapt_v123_cmd.append(cmd[_iapt_v123_i])
        _iapt_v123_i += 1
    cmd=_iapt_v123_cmd
    # 修复 find：有 --find 时不自动递归。
    if "--find" in [str(_c) for _c in cmd]:
        cmd=_iapt_v123_strip_flag(cmd, "--find-recursive", False)
    if _iapt_v123_allowed:
        cmd=_iapt_v123_strip_flag(cmd, "--no-dynamic-key", False)
        cmd=_iapt_v123_set_flag(cmd, "--mode", "auto")
        cmd=_iapt_v123_set_flag(cmd, "--outer-mode", "auto")
    else:
        cmd=_iapt_v123_set_flag(cmd, "--mode", "fast")
        cmd=_iapt_v123_set_flag(cmd, "--outer-mode", "fixed")
        if "--no-key-cache" not in [str(_c) for _c in cmd]:
            cmd.append("--no-key-cache")
        if "--no-dynamic-key" not in [str(_c) for _c in cmd]:
            cmd.append("--no-dynamic-key")
    print("[IAPT_V123] runner feature_ids=%s dynamic_allowed=%s" % (sorted(_iapt_v123_ids), _iapt_v123_allowed))
    print("[IAPT_V123] runner cmd=" + " ".join(map(str, cmd)))
    # IAPT_V123_RUNNER_GATE_END
    return cmd

def _file_index_path(out_dir: Path) -> Path:
    return out_dir / ".tmp" / "file_index.json"


def _output_manifest_path(out_dir: Path) -> Path:
    # v18: the manifest lives in the task directory but is never itself an
    # output member.  Downloads only use the member rows recorded here.
    return out_dir / "output_files.json"


def _is_internal_output_path(rel_path: str) -> bool:
    rel = str(rel_path or "").replace("\\", "/").lstrip("./")
    low = rel.lower()
    if not rel:
        return True
    if low.startswith((".tmp/", "logs/", ".iapt_internal/")):
        return True
    if low in {
        "container_plain.bin", "meta.json", "output_files.json", "task.json",
        "result.zip", "download.zip", "secure.zip", "deobfuscation_map.txt",
        "outer_key_cache.json", "reuse_session_v7.json", "reuse_session_v14.json",
        "project_meta_v7.json", "project_meta_v6.json", "project_meta.json",
        "decrypt.pid", "cancel.request",
    }:
        return True
    return False


def _sanitize_public_file_rows(out_dir: Path, rows) -> list[dict]:
    out = []
    seen = set()
    base = out_dir.resolve()
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        rel = str(row.get("rel_path") or "").replace("\\", "/").lstrip("./")
        if _is_internal_output_path(rel) or rel in seen:
            continue
        fp = out_dir / rel
        try:
            resolved = fp.resolve()
            resolved.relative_to(base)
            if not resolved.is_file():
                continue
            size = int(resolved.stat().st_size)
        except Exception:
            continue
        seen.add(rel)
        item = dict(row)
        item["rel_path"] = rel
        item["size_bytes"] = size
        out.append(item)
    out.sort(key=lambda x: str(x.get("rel_path") or ""))
    return out


def _scan_out_files(out_dir: Path):
    files = []
    for fp in out_dir.rglob("*"):
        if not fp.is_file():
            continue
        try:
            rel = fp.relative_to(out_dir).as_posix()
        except Exception:
            continue
        if _is_internal_output_path(rel):
            continue
        try:
            sz = int(fp.stat().st_size)
        except OSError:
            continue
        files.append({"rel_path": rel, "size_bytes": sz})
    files.sort(key=lambda x: x["rel_path"])
    return files


def _write_output_manifest(out_dir: Path, files) -> None:
    manifest = _output_manifest_path(out_dir)
    payload = {
        "version": 18,
        "updated_at": int(time.time()),
        "files": _sanitize_public_file_rows(out_dir, files),
    }
    tmp = manifest.with_suffix(manifest.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    os.replace(tmp, manifest)


def _write_file_index(out_dir: Path, files) -> None:
    files = _sanitize_public_file_rows(out_dir, files)
    idx = _file_index_path(out_dir)
    idx.parent.mkdir(parents=True, exist_ok=True)
    idx.write_text(
        json.dumps(files, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )
    _write_output_manifest(out_dir, files)


def _sync_public_file_counts(task: dict, files: list[dict]) -> None:
    try:
        task_id = int((task or {}).get('id') or 0)
        if task_id <= 0:
            return
        count = len(files or [])
        total = sum(int(x.get('size_bytes') or 0) for x in (files or []))
        if int((task or {}).get('file_count') or -1) != count or int((task or {}).get('total_bytes') or -1) != total:
            db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (count, total, task_id))
            task['file_count'] = count
            task['total_bytes'] = total
    except Exception:
        pass


def _src_only_public_rows(out_dir: Path, files: list[dict]) -> list[dict]:
    """Expose only files physically located under out_dir/src when that tree exists.

    Decompiler diagnostics (deep_code/, analysis/, reports, replacement logs, etc.)
    may remain on the server for maintenance, but they are not part of the public
    task file list, quota calculation, preview, or download package.
    """
    src_dir = out_dir / "src"
    if not src_dir.is_dir():
        return list(files or [])
    out = []
    for row in files or []:
        rel = str((row or {}).get("rel_path") or "").replace("\\", "/").lstrip("./")
        if rel.startswith("src/"):
            item = dict(row)
            item["rel_path"] = rel
            out.append(item)
    out.sort(key=lambda x: str(x.get("rel_path") or ""))
    return out


def _finish_public_file_rows(task: dict, files: list[dict]) -> list[dict]:
    if not task or not task.get('out_dir'):
        return []
    out_dir = Path(task['out_dir'])
    clean = _sanitize_public_file_rows(out_dir, files)
    clean = _src_only_public_rows(out_dir, clean)
    # Persist the filtered public manifest so every API consumer sees the same
    # src-only result set. Internal diagnostics remain on disk but undisclosed.
    _write_file_index(out_dir, clean)
    _sync_public_file_counts(task, clean)
    return clean


def list_task_files(task_or_id):
    if isinstance(task_or_id, dict):
        task = task_or_id
    else:
        task = db.one("SELECT * FROM tasks WHERE id=%s",
                      (task_or_id,))
    if not task or not task.get("out_dir"):
        return []
    out_dir = Path(task["out_dir"])

    # Prefer the v18 public-output manifest.  Validate every row against the
    # task directory so a stale or edited manifest cannot expose internal files.
    manifest = _output_manifest_path(out_dir)
    if manifest.exists():
        try:
            obj = json.loads(manifest.read_text(encoding="utf-8"))
            rows = obj.get("files") if isinstance(obj, dict) else obj
            clean = _sanitize_public_file_rows(out_dir, rows)
            if isinstance(rows, list):
                _write_file_index(out_dir, clean)
                return _finish_public_file_rows(task, clean)
        except Exception:
            pass

    idx = _file_index_path(out_dir)
    if idx.exists():
        try:
            data = json.loads(idx.read_text(encoding="utf-8"))
            if isinstance(data, list):
                clean = _sanitize_public_file_rows(out_dir, data)
                _write_file_index(out_dir, clean)
                return _finish_public_file_rows(task, clean)
        except Exception:
            pass
    files = _scan_out_files(out_dir)
    _write_file_index(out_dir, files)
    return _finish_public_file_rows(task, files)


def _quota_cost_for_bytes(size_bytes: int, unit: int) -> int:
    size_bytes = int(size_bytes or 0)
    return max(1, math.ceil(size_bytes / unit)) if size_bytes > 0 else 0


def _choose_files_by_quota(files, quota_units: int, unit: int = 10240):
    chosen = []
    used = 0
    bytes_sum = 0
    for f in files:
        c = _quota_cost_for_bytes(int(f.get("size_bytes") or 0), unit)
        if used + c > int(quota_units or 0):
            continue
        chosen.append(f)
        used += c
        bytes_sum += int(f.get("size_bytes") or 0)
    return chosen, used, bytes_sum


def settle_decrypt_quota_once(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (task_id,))
    if not task \
            or int(task.get("actual_quota_cost") or 0) > 0 \
            or int(task.get("decrypt_quota_deducted") or 0) > 0:
        return
    # The automatic <package>.project is internal metadata unless it was
    # explicitly requested or referenced by decrypted source. Remove it before
    # counting files and charging decrypt quota.
    try:
        prune = globals().get('_iapt_v8_prune_automatic_project_files')
        if callable(prune):
            prune(int(task_id), task)
            task = db.one("SELECT * FROM tasks WHERE id=%s", (task_id,)) or task
    except Exception as exc:
        logger.warning('IAPT v18.1 pre-quota project visibility failed: %s', exc)
    files = list_task_files(task)
    actual_cost = sum(
        _quota_cost_for_bytes(int(f.get("size_bytes") or 0), 10240)
        for f in files
    )
    if actual_cost <= 0:
        db.exec(
            "UPDATE tasks SET actual_quota_cost=0, decrypt_quota_deducted=0,"
            " downloadable_file_count=0, downloadable_bytes=0, quota_note=%s"
            " WHERE id=%s",
            ("无输出文件，不扣解密额度", task_id),
        )
        return

    from .quota import available_quota, deduct_quota
    feature_id = int(task.get("feature_id") or 1)
    user_id    = int(task["user_id"])
    left       = int(available_quota(user_id, feature_id).get("total") or 0)
    charge     = min(actual_cost, left)
    if charge > 0:
        deduct_quota(user_id, feature_id, charge)
    chosen, used, bytes_sum = _choose_files_by_quota(files, charge, 10240)
    note = (f"解密输出实际消耗 {actual_cost} 额度，已扣 {charge} 额度，"
            f"可下载 {len(chosen)}/{len(files)} 个文件")
    db.exec(
        "UPDATE tasks SET actual_quota_cost=%s, decrypt_quota_deducted=%s,"
        " downloadable_file_count=%s, downloadable_bytes=%s, quota_note=%s"
        " WHERE id=%s",
        (actual_cost, charge, len(chosen), bytes_sum, note, task_id),
    )


def summarize_fail_reason(log_text: str, returncode=None) -> str:
    log_text = log_text or ""
    keywords = (
        "traceback", "exception", "error", "failed", "fail", "invalid",
        "missing", "not found", "no such file", "permission", "timeout",
        "错误", "失败", "异常", "无法", "不存在",
    )
    hits = []
    for line in log_text.splitlines():
        t = line.strip()
        if not t:
            continue
        if any(k in t.lower() for k in keywords):
            hits.append(t)
    if hits:
        reason = "\n".join(hits[-40:])
    else:
        tail = [x.rstrip() for x in log_text.splitlines()[-60:] if x.strip()]
        reason = "\n".join(tail)
    if not reason:
        reason = f"解密进程失败，退出码 {returncode}"
    elif returncode not in (None, 0):
        reason = f"解密进程退出码 {returncode}\n" + reason
    return reason[-4000:]


def scan_files(task_id: int, out_dir: Path):
    files = _scan_out_files(out_dir)
    _write_file_index(out_dir, files)
    count = len(files)
    total = sum(int(f.get("size_bytes") or 0) for f in files)
    db.exec(
        "UPDATE tasks SET file_count=%s, total_bytes=%s WHERE id=%s",
        (count, total, task_id),
    )
    return count, total


def run_task(task_id: int):
    """
    执行单个解密任务。
    在进入子进程前先获取 Semaphore，保证同时运行的解密进程数不超过
    MAX_DECRYPT_WORKERS（默认 1），防止内存溢出触发 OOM Killer。
    """
    task = db.one("SELECT * FROM tasks WHERE id=%s", (task_id,))
    if not task:
        return

    options  = json.loads(task.get("options_json") or "{}")
    if not isinstance(options, dict):
        options = {}
    try:
        options.setdefault("feature_id", int(task.get("feature_id") or 0))
    except Exception:
        pass
    if task.get("decrypt_version"):
        options.setdefault("decrypt_version", str(task.get("decrypt_version") or "").lower())
    apk_path = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
    out_dir  = APP_STORAGE / "tasks"   / task["task_no"]
    log_path = APP_STORAGE / "tasks"   / f"{task['task_no']}.log"
    out_dir.mkdir(parents=True, exist_ok=True)

    db.exec(
        "UPDATE tasks SET status='running', out_dir=%s, log_path=%s WHERE id=%s",
        (str(out_dir), str(log_path), task_id),
    )

    cmd = build_cmd(apk_path, out_dir, options)
    runner_header = "[IAPT_FIX] feature-map-dynamic-policy-v18\n" + "[IAPT_FIX] options=" + json.dumps(options, ensure_ascii=False, sort_keys=True, default=str) + "\n" + "[IAPT_FIX] cmd=" + " ".join(cmd) + "\n"
    runner_header = "[IAPT_FIX] explicit-feature-off-hardguard-v16\n" + "[IAPT_FIX] options=" + json.dumps(options, ensure_ascii=False, sort_keys=True, default=str) + "\n" + "[IAPT_FIX] cmd=" + " ".join(cmd) + "\n"
    timeout = None
    # IAPT_RUNNER_UTF8_ENV_V4
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("LANG", "C.UTF-8")
    env.setdefault("LC_ALL", "C.UTF-8")
    env.setdefault("IAPT_PYTHON", cmd[0] if cmd else "python3")
    try:
        logger.warning("IAPT run task %s cmd: %s", task_id, " ".join(map(str, cmd)))
    except Exception:
        pass

    logger.info("任务 %d 等待解密 Semaphore（当前最大并发 %d）",
                task_id, _MAX_WORKERS)
    # 阻塞等待，直到可以运行（不会丢任务）
    _decrypt_semaphore.acquire()
    logger.info("任务 %d 开始解密", task_id)
    t0 = time.perf_counter()
    try:
        proc = run_decrypt_process(cmd, apk_path, out_dir, options, task, env=env)
        log = runner_header + (proc.stdout or "")
        log_path.write_text(log, encoding="utf-8", errors="replace")
        log_meta = parse_meta(log)
        apk_meta = {}
        try:
            if int(task.get("feature_id") or 1) != 6:
                apk_meta = extract_v3_apk_meta(apk_path)
                update_task_meta_if_empty(task_id, apk_meta, overwrite=True)
        except Exception:
            apk_meta = {}
        meta = merge_meta_nonempty(apk_meta, log_meta)
        # IAPT_TASK_META_RUNTIME_MERGE_BEGIN
        try:
            meta = iapt_merge_task_meta(meta, task, apk_path)
        except Exception:
            pass
        # IAPT_TASK_META_RUNTIME_MERGE_END

        try:
            _manifest_meta = meta_from_apk_path(apk_path)
            for _k, _v in _manifest_meta.items():
                if _v and not meta.get(_k):
                    meta[_k] = _v
        except Exception:
            pass
        count, total = scan_files(task_id, out_dir)
        total_ms = float(
            meta.get("total_ms")
            or ((time.perf_counter() - t0) * 1000.0)
        )

        if proc.returncode == 0 and count > 0:
            db.exec(
                "UPDATE tasks SET status='done', total_ms=%s, app_name=%s,"
                " package_name=%s, version_name=%s, version_code=%s"
                " WHERE id=%s",
                (total_ms, meta.get("app_name"), meta.get("package_name"),
                 meta.get("version_name"), meta.get("version_code"), task_id),
            )
            settle_decrypt_quota_once(task_id)
            try:
                if task.get('apk_sha256') and task.get('options_hash'):
                    from .cache import save_source_cache, cleanup_source_cache
                    cleanup_source_cache()
                    save_source_cache(
                        task_id,
                        task.get('apk_sha256'),
                        task.get('options_hash'),
                        int(task.get('feature_id') or 1),
                        str(out_dir),
                    )
            except Exception as e:
                logger.warning("保存缓存失败: %s", e)
        else:
            db.exec(
                "UPDATE tasks SET status='failed', total_ms=%s, error_text=%s"
                " WHERE id=%s",
                (total_ms,
                 summarize_fail_reason(log, proc.returncode),
                 task_id),
            )

    except subprocess.TimeoutExpired:
        reason = "解密超时"
        log_path.write_text(reason, encoding="utf-8")
        db.exec(
            "UPDATE tasks SET status='failed', error_text=%s WHERE id=%s",
            (reason, task_id),
        )
    except Exception as e:
        reason = '运行异常：' + str(e)
        log_path.write_text(reason, encoding="utf-8")
        db.exec(
            "UPDATE tasks SET status='failed', error_text=%s WHERE id=%s",
            (reason, task_id),
        )
    finally:
        # 无论成功/失败/异常，都必须释放 Semaphore，否则后续任务永远等待
        _decrypt_semaphore.release()
        logger.info("任务 %d 完成，已释放 Semaphore", task_id)


def search_in_task(task_id: int, keyword: str, limit: int = 100):
    keyword = (keyword or "").lower()
    rows = list_task_files(task_id)
    if keyword:
        rows = [f for f in rows
                if keyword in str(f.get("rel_path", "")).lower()]
    return rows[:limit]


# __V6_WORKER_RUNNER_V55_BEGIN__
# v55: Worker 按 feature_id/decrypt_version 分流。V6 不允许再落回 iapp_auto_decrypt.py(V3)。
try:
    _IAPT_V55_BUILD_CMD_V3 = build_cmd
except Exception:
    _IAPT_V55_BUILD_CMD_V3 = None


def _iapt_v55_int(v, default=0):
    try:
        if v is None or v == '':
            return default
        return int(v)
    except Exception:
        return default


def _iapt_v55_is_v6(options):
    options = options or {}
    fid = _iapt_v55_int(options.get('feature_id'), 0)
    ver = str(options.get('decrypt_version') or options.get('task_version') or options.get('version') or '').strip().lower()
    if fid == 6 or ver in ('v6', '6', 'iapp_v6'):
        return True
    for k in ('v6_upload_mode', 'v6_no_java', 'v6_dex_only', 'use_v6', 'v6'):
        if k in options:
            return True
    return False


def _iapt_v55_build_cmd_v6(apk_path: Path, out_dir: Path, options: dict):
    # v18.6.8: call the real V6 tool directly.  The historical dispatcher
    # introduced a second stdout pipe/process group and was the remaining
    # source of tasks that had already produced files but never returned.
    tool = Path(__file__).resolve().parent / 'tools' / 'iapp_dex2iyu_v6.py'
    cmd = [sys.executable, str(tool), '--apk', str(apk_path), '--outdir', str(out_dir)]
    def add_value(api_name, flag):
        v = (options or {}).get(api_name)
        if v is not None and str(v).strip() != '':
            cmd.extend([flag, str(v).strip()])
    add_value('package_name', '--package')
    add_value('package', '--package')
    if _iapt_truthy((options or {}).get('v6_no_java')) or _iapt_truthy((options or {}).get('no_java')):
        cmd.append('--no-java')
    # v18.5: V6 protector/static analysis, concrete event VM and deep interpreter are the server default.  It resolves
    # LianYi/NB dispatch tables and constant strings without running the APK.
    # Public API V26: generate source only. Do not create deep_code/, analysis
    # reports, or 恢复说明.txt; after recovery, strip the top-level src/ folder
    # so only its contents remain in the task output root.
    cmd.extend(['--advanced-analysis', '--protector-analysis', '--no-deep-code', '--flat-src-root'])
    return cmd


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = options or {}
    if _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)
    if _IAPT_V55_BUILD_CMD_V3 is not None:
        return _IAPT_V55_BUILD_CMD_V3(apk_path, out_dir, options)
    raise RuntimeError('V3 build_cmd 不存在')


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
    if not task:
        return
    try:
        options = json.loads(task.get('options_json') or '{}')
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    feature_id = _iapt_v55_int(task.get('feature_id') or options.get('feature_id') or 1, 1)
    options['feature_id'] = feature_id
    if feature_id == 6 or _iapt_v55_is_v6(options):
        options['feature_id'] = 6
        options['decrypt_version'] = 'v6'
        options['task_version'] = 'v6'
    apk_path = APP_STORAGE / 'uploads' / f"{task['task_no']}.apk"
    out_dir = APP_STORAGE / 'tasks' / task['task_no']
    log_path = APP_STORAGE / 'tasks' / f"{task['task_no']}.log"
    out_dir.mkdir(parents=True, exist_ok=True)
    db.exec("UPDATE tasks SET status='running', out_dir=%s, log_path=%s WHERE id=%s", (str(out_dir), str(log_path), task_id))
    cmd = build_cmd(apk_path, out_dir, options)
    t0 = time.perf_counter()
    try:
        proc = run_decrypt_process(cmd, apk_path, out_dir, options, task)
        log = '### IAPT worker v55 command: ' + ' '.join(str(x) for x in cmd) + '\n' + (proc.stdout or '')
        log_path.write_text(log, encoding='utf-8', errors='replace')
        meta = parse_meta(log)
        count, total = scan_files(task_id, out_dir)
        total_ms = float(meta.get('total_ms') or ((time.perf_counter() - t0) * 1000.0))
        if proc.returncode == 0 and count > 0:
            db.exec("""
                UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
                version_name=%s, version_code=%s, feature_id=%s WHERE id=%s
            """, (total_ms, meta.get('app_name'), meta.get('package_name'), meta.get('version_name'), meta.get('version_code'), int(options.get('feature_id') or feature_id), task_id))
            settle_decrypt_quota_once(task_id)
            try:
                if task.get('apk_sha256') and task.get('options_hash'):
                    from .cache import save_source_cache, cleanup_source_cache
                    cleanup_source_cache()
                    save_source_cache(task_id, task.get('apk_sha256'), task.get('options_hash'), int(options.get('feature_id') or feature_id), str(out_dir))
            except Exception:
                pass
        else:
            db.exec("UPDATE tasks SET status='failed', total_ms=%s, error_text=%s, feature_id=%s WHERE id=%s", (total_ms, summarize_fail_reason(log, proc.returncode), int(options.get('feature_id') or feature_id), task_id))
    except Exception as e:
        reason = '运行异常：' + str(e)
        log_path.write_text(reason, encoding='utf-8')
        db.exec("UPDATE tasks SET status='failed', error_text=%s, feature_id=%s WHERE id=%s", (reason, int(options.get('feature_id') or feature_id), task_id))
# __V6_WORKER_RUNNER_V55_END__




# IAPT_WHITELIST_RUNNER_HARD_GUARD_V61_BEGIN
# v61: worker 主解密硬拦截。即使 API 或客户端被绕过，保护期内也不能执行。
try:
    import datetime as _v61r_dt, json as _v61r_json, re as _v61r_re, hashlib as _v61r_hashlib, zipfile as _v61r_zipfile
except Exception as _v61r_import_err:
    print('[IAPT_V61R_IMPORT_WARN]', _v61r_import_err)


def _v61r_parse_features(v):
    if v is None: return set()
    if isinstance(v, (list, tuple, set)): src = v
    else:
        s = str(v).strip()
        try:
            j = _v61r_json.loads(s); src = j if isinstance(j, list) else [j]
        except Exception: src = _v61r_re.split(r'[^0-9]+', s)
    out = set()
    for x in src:
        try:
            if str(x).strip() != '': out.add(int(x))
        except Exception: pass
    return out


def _v61r_user_has_bypass7(user_id):
    try:
        u = db.one('SELECT id,subscription_id FROM users WHERE id=%s', (int(user_id),))
        if not u: return False
        sid = u.get('subscription_id') if isinstance(u, dict) else None
        rows = []
        try: rows += db.all('SELECT * FROM subscriptions WHERE sub_id=%s', (sid,)) or []
        except Exception: pass
        try: rows += db.all('SELECT * FROM subscriptions WHERE id=%s', (sid,)) or []
        except Exception: pass
        for r in rows:
            if not isinstance(r, dict): continue
            feats = set()
            for k in ('features_json','features','feature_ids','feature_json'):
                feats |= _v61r_parse_features(r.get(k))
            if 7 in feats or 999 in feats: return True
    except Exception as e: print('[IAPT_V61R] bypass warn:', e)
    return False


def _v61r_dt_parse(v):
    if v is None or v == '': return None
    if isinstance(v, _v61r_dt.datetime): return v.replace(tzinfo=None)
    s = str(v).strip().replace('T',' ').replace('Z','').replace('/','-')
    s = _v61r_re.sub(r'\.\d+$', '', s)
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d %H:%M','%Y-%m-%d'):
        try: return _v61r_dt.datetime.strptime(s[:19], fmt)
        except Exception: pass
    return None


def _v61r_protecting(exp):
    dt = _v61r_dt_parse(exp)
    return True if dt is None else dt > _v61r_dt.datetime.now()


def _v61r_norm_hash(s):
    s = str(s or '').strip().lower(); return s if _v61r_re.fullmatch(r'[0-9a-f]{32,128}', s) else ''

def _v61r_norm_pkg(s):
    s = _v61r_re.sub(r'\.(apk|dex|zip)$', '', str(s or '').strip().lower(), flags=_v61r_re.I)
    return s if _v61r_re.match(r'^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$', s) else ''

def _v61r_guess_pkg(name):
    n = str(name or '').split('/')[-1].split('\\')[-1]
    n = _v61r_re.sub(r'\.(apk|dex|zip)$', '', n, flags=_v61r_re.I)
    return _v61r_norm_pkg(n)


def _v61r_file_sha(path):
    try:
        p = Path(path)
        if not p.exists() or not p.is_file(): return ''
        h = _v61r_hashlib.sha256()
        with p.open('rb') as f:
            for b in iter(lambda: f.read(1024 * 1024), b''): h.update(b)
        return h.hexdigest()
    except Exception: return ''


def _v61r_zip_entry_hashes(path):
    out = []
    try:
        with _v61r_zipfile.ZipFile(path, 'r') as z:
            for n in sorted(z.namelist()):
                ln = n.lower()
                if ln.endswith('.dex') or ln in ('androidmanifest.xml', 'resources.arsc'):
                    try: out.append(_v61r_hashlib.sha256(z.read(n)).hexdigest())
                    except Exception: pass
    except Exception: pass
    return out


def _v61r_collect(task, options, apk_path):
    pkgs = []
    for k in ('package_name','package','pkg','packageName','app_package','client_package_name','original_package_name','apk_package'):
        v = options.get(k) if isinstance(options, dict) else None
        if v: pkgs.append(str(v))
    if isinstance(task, dict):
        for k in ('apk_name','filename','name'):
            if task.get(k):
                gp = _v61r_guess_pkg(task.get(k))
                if gp: pkgs.append(gp)
    hashes = []
    for k in ('code_hash','codeHash','hash','sha256','file_hash','fileHash','apk_sha256','apkSha256','apk_hash','apkHash','code_sha256','codeSha256','original_apk_sha256','client_apk_sha256','upload_apk_sha256'):
        h = _v61r_norm_hash(options.get(k) if isinstance(options, dict) else '')
        if h: hashes.append(h)
    if isinstance(task, dict):
        for k in ('apk_sha256','code_hash','file_hash','sha256'):
            h = _v61r_norm_hash(task.get(k))
            if h: hashes.append(h)
    fh = _v61r_file_sha(apk_path)
    if fh: hashes.append(fh)
    hashes += _v61r_zip_entry_hashes(apk_path)
    return [p for p in dict.fromkeys([_v61r_norm_pkg(x) for x in pkgs]) if p], [h for h in dict.fromkeys([_v61r_norm_hash(x) for x in hashes]) if h]


def _v61r_find(pkgs, hashes):
    pkgset = set(pkgs or [])
    hashset = set(hashes or [])
    rows = []
    if hashset:
        ph = ','.join(['%s'] * len(hashset))
        try: rows += db.all('SELECT * FROM decrypt_whitelist WHERE LOWER(code_hash) IN (' + ph + ') ORDER BY id DESC LIMIT 80', tuple(hashset)) or []
        except Exception as e: print('[IAPT_V61R] hash query warn:', e)
    if pkgset:
        pp = ','.join(['%s'] * len(pkgset))
        try: rows += db.all('SELECT * FROM decrypt_whitelist WHERE LOWER(package_name) IN (' + pp + ') ORDER BY id DESC LIMIT 80', tuple(pkgset)) or []
        except Exception as e: print('[IAPT_V61R] package query warn:', e)
    seen = set()
    for r in rows:
        if not isinstance(r, dict): continue
        rid = r.get('id')
        if rid in seen: continue
        seen.add(rid)
        exp = r.get('expire_at') or r.get('expire_time') or r.get('expires_at')
        if not _v61r_protecting(exp): continue
        rh = _v61r_norm_hash(r.get('code_hash') or r.get('hash') or r.get('sha256') or r.get('file_hash'))
        rp = _v61r_norm_pkg(r.get('package_name') or r.get('package') or r.get('pkg') or r.get('packageName'))
        if (rh and rh in hashset) or (rp and rp in pkgset):
            return {'package_name': rp, 'code_hash': rh, 'expire_at': str(exp or ''), 'id': rid, 'match_mode': 'hash' if (rh and rh in hashset) else 'package'}
    return None


def _v61r_check_task(task_id):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
    if not task: return None
    try: uid = int(task.get('user_id') or 0)
    except Exception: uid = 0
    if uid and _v61r_user_has_bypass7(uid): return None
    try: options = _v61r_json.loads(task.get('options_json') or '{}')
    except Exception: options = {}
    apk_path = APP_STORAGE / 'uploads' / f"{task['task_no']}.apk"
    pkgs, hashes = _v61r_collect(task, options, apk_path)
    hit = _v61r_find(pkgs, hashes)
    if hit:
        msg = '白名单保护中，到期前禁止解密'
        if hit.get('package_name'): msg += '：' + str(hit.get('package_name'))
        if hit.get('expire_at'): msg += '，到期 ' + str(hit.get('expire_at'))
        msg += '，匹配方式 ' + str(hit.get('match_mode') or '')
        return msg
    return None


try:
    _IAPT_V61_ORIG_RUN_TASK = run_task
    def run_task(task_id: int):
        msg = _v61r_check_task(task_id)
        if msg:
            try:
                task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
                log_path = APP_STORAGE / 'tasks' / f"{task['task_no']}.log"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text(msg, encoding='utf-8')
            except Exception: pass
            try: db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (msg, task_id))
            except Exception as e: print('[IAPT_V61R] update task failed:', e)
            print('[IAPT_V61_BLOCK_RUNNER]', task_id, msg)
            return
        return _IAPT_V61_ORIG_RUN_TASK(task_id)
    print('[OK] IAPT_WHITELIST_RUNNER_HARD_GUARD_V61 installed')
except Exception as e:
    print('[IAPT_V61R_INIT_WARN]', e)
# IAPT_WHITELIST_RUNNER_HARD_GUARD_V61_END


# IAPT_WHITELIST_RUNNER_GUARD_V60_BEGIN
# v60: worker 主解密入口二次校验。即使 API 被绕过，白名单保护期内也不能执行。
try:
    import datetime as _v60r_dt, json as _v60r_json, re as _v60r_re, hashlib as _v60r_hashlib
except Exception as _v60r_import_err:
    print('[IAPT_V60R_IMPORT_WARN]', _v60r_import_err)


def _v60r_parse_features(v):
    if v is None: return set()
    if isinstance(v, (list, tuple, set)): src = v
    else:
        s = str(v).strip()
        try:
            j = _v60r_json.loads(s); src = j if isinstance(j, list) else [j]
        except Exception: src = _v60r_re.split(r'[^0-9]+', s)
    out = set()
    for x in src:
        try:
            if str(x).strip() != '': out.add(int(x))
        except Exception: pass
    return out


def _v60r_user_has_bypass7(user_id):
    try:
        u = db.one('SELECT id,subscription_id FROM users WHERE id=%s', (int(user_id),))
        if not u: return False
        sid = u.get('subscription_id') if isinstance(u, dict) else None
        rows = []
        try: rows += db.all('SELECT * FROM subscriptions WHERE sub_id=%s', (sid,)) or []
        except Exception: pass
        try: rows += db.all('SELECT * FROM subscriptions WHERE id=%s', (sid,)) or []
        except Exception: pass
        for r in rows:
            if not isinstance(r, dict): continue
            feats = set()
            for k in ('features_json','features','feature_ids','feature_json'):
                feats |= _v60r_parse_features(r.get(k))
            if 7 in feats or 999 in feats: return True
    except Exception as e: print('[IAPT_V60R] bypass warn:', e)
    return False


def _v60r_dt_parse(v):
    if v is None or v == '': return None
    if isinstance(v, _v60r_dt.datetime): return v.replace(tzinfo=None)
    s = str(v).strip().replace('T',' ').replace('Z','').replace('/','-')
    s = _v60r_re.sub(r'\.\d+$', '', s)
    for fmt in ('%Y-%m-%d %H:%M:%S','%Y-%m-%d %H:%M','%Y-%m-%d'):
        try: return _v60r_dt.datetime.strptime(s[:19], fmt)
        except Exception: pass
    return None


def _v60r_protecting(exp):
    dt = _v60r_dt_parse(exp)
    return True if dt is None else dt > _v60r_dt.datetime.now()


def _v60r_norm_hash(s):
    s = str(s or '').strip().lower(); return s if _v60r_re.fullmatch(r'[0-9a-f]{32,128}', s) else ''

def _v60r_norm_pkg(s):
    return _v60r_re.sub(r'\.(apk|dex|zip)$', '', str(s or '').strip().lower(), flags=_v60r_re.I)

def _v60r_guess_pkg(name):
    n = str(name or '').split('/')[-1].split('\\')[-1]
    n = _v60r_re.sub(r'\.(apk|dex|zip)$', '', n, flags=_v60r_re.I)
    return n if _v60r_re.match(r'^[a-zA-Z][A-Za-z0-9_]*(\.[A-Za-z0-9_]+)+$', n) else ''


def _v60r_file_sha(path):
    try:
        p = Path(path)
        if not p.exists() or not p.is_file(): return ''
        h = _v60r_hashlib.sha256()
        with p.open('rb') as f:
            for b in iter(lambda: f.read(1024 * 1024), b''): h.update(b)
        return h.hexdigest()
    except Exception: return ''


def _v60r_collect(task, options, apk_path):
    pkgs = []
    for k in ('package_name','package','pkg','packageName','app_package','client_package_name','original_package_name','apk_package'):
        v = options.get(k) if isinstance(options, dict) else None
        if v: pkgs.append(str(v))
    for k in ('apk_name','filename','name'):
        if isinstance(task, dict) and task.get(k):
            gp = _v60r_guess_pkg(task.get(k))
            if gp: pkgs.append(gp)
    hashes = []
    for k in ('code_hash','codeHash','hash','sha256','file_hash','fileHash','apk_sha256','apkSha256','apk_hash','apkHash','code_sha256','codeSha256','original_apk_sha256','client_apk_sha256','upload_apk_sha256'):
        h = _v60r_norm_hash(options.get(k) if isinstance(options, dict) else '')
        if h: hashes.append(h)
    if isinstance(task, dict):
        h = _v60r_norm_hash(task.get('apk_sha256'))
        if h: hashes.append(h)
    fh = _v60r_file_sha(apk_path)
    if fh: hashes.append(fh)
    return [p for p in dict.fromkeys([_v60r_norm_pkg(x) for x in pkgs]) if p], [h for h in dict.fromkeys(hashes) if h]


def _v60r_find(pkgs, hashes):
    if not hashes: return None
    ph = ','.join(['%s'] * len(hashes))
    try: rows = db.all('SELECT * FROM decrypt_whitelist WHERE LOWER(code_hash) IN (' + ph + ') ORDER BY id DESC LIMIT 50', tuple(hashes)) or []
    except Exception as e:
        print('[IAPT_V60R] query warn:', e); rows = []
    pkgset = set(pkgs or [])
    for r in rows:
        if not isinstance(r, dict): continue
        rh = _v60r_norm_hash(r.get('code_hash') or r.get('hash') or r.get('sha256') or r.get('file_hash'))
        if rh not in hashes: continue
        rp = _v60r_norm_pkg(r.get('package_name') or r.get('package') or r.get('pkg') or r.get('packageName'))
        if pkgset and rp and rp not in pkgset: continue
        exp = r.get('expire_at') or r.get('expire_time') or r.get('expires_at')
        if _v60r_protecting(exp): return {'package_name': rp, 'code_hash': rh, 'expire_at': str(exp or ''), 'id': r.get('id')}
    return None


def _v60r_check_task(task_id):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
    if not task: return None
    try: uid = int(task.get('user_id') or 0)
    except Exception: uid = 0
    if uid and _v60r_user_has_bypass7(uid): return None
    try: options = _v60r_json.loads(task.get('options_json') or '{}')
    except Exception: options = {}
    apk_path = APP_STORAGE / 'uploads' / f"{task['task_no']}.apk"
    pkgs, hashes = _v60r_collect(task, options, apk_path)
    hit = _v60r_find(pkgs, hashes)
    if hit:
        msg = '白名单保护中，到期前禁止解密'
        if hit.get('package_name'): msg += '：' + str(hit.get('package_name'))
        if hit.get('expire_at'): msg += '，到期 ' + str(hit.get('expire_at'))
        return msg
    return None


try:
    _IAPT_V60_ORIG_RUN_TASK = run_task
    def run_task(task_id: int):
        msg = _v60r_check_task(task_id)
        if msg:
            try:
                task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,))
                log_path = APP_STORAGE / 'tasks' / f"{task['task_no']}.log"
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_text(msg, encoding='utf-8')
            except Exception: pass
            db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (msg, task_id))
            return
        return _IAPT_V60_ORIG_RUN_TASK(task_id)
    print('[OK] IAPT_WHITELIST_RUNNER_GUARD_V60 installed')
except Exception as e:
    print('[IAPT_V60R_INIT_WARN]', e)
# IAPT_WHITELIST_RUNNER_GUARD_V60_END



# IAPT_V82_DYNAMIC_SPLIT_MINIMAL: dynamic-key off keeps outer-mode auto; do not force fixed.

# IAPT_V126_FINAL_BUILD_CMD_OVERRIDE_BEGIN
# v126: final runtime build_cmd override.
# - keep existing whitelist/run_task wrappers
# - v55 run_task resolves build_cmd at runtime, so this last definition is the effective one
# - dynamic key permission is read from DB by task_no/out_dir -> tasks.user_id -> users.subscription_id -> subscriptions.features_json
def _iapt_v126_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or isinstance(v, bool):
        return out
    if isinstance(v, int):
        out.add(v)
        return out
    if isinstance(v, (list, tuple, set)):
        for x in v:
            out |= _iapt_v126_parse_features(x)
        return out
    if isinstance(v, dict):
        for k, x in v.items():
            if str(k).lower() in (
                "features", "feature_ids", "features_json", "feature_list",
                "subscription_features", "permissions", "feature_json",
                "_server_feature_ids"
            ):
                out |= _iapt_v126_parse_features(x)
        return out
    s = str(v).strip()
    if not s:
        return out
    try:
        return _iapt_v126_parse_features(_json.loads(s))
    except Exception:
        pass
    for n in _re.findall(r"-?\d+", s):
        try:
            out.add(int(n))
        except Exception:
            pass
    return out


def _iapt_v126_table_columns(table):
    try:
        rows = db.all("SHOW COLUMNS FROM " + table) or []
        out = []
        for r in rows:
            if isinstance(r, dict):
                out.append(str(r.get("Field") or r.get("field") or ""))
            elif r:
                out.append(str(r[0]))
        return [x for x in out if x]
    except Exception:
        return []


def _iapt_v126_task_from_outdir(out_dir):
    try:
        task_no = Path(out_dir).name
        if task_no:
            t = db.one("SELECT * FROM tasks WHERE task_no=%s ORDER BY id DESC LIMIT 1", (task_no,))
            if isinstance(t, dict):
                return t
    except Exception:
        pass
    return {}


def _iapt_v126_user_features(user_id):
    feats = set()
    try:
        uid = int(user_id)
    except Exception:
        return feats

    try:
        u = db.one("SELECT * FROM users WHERE id=%s", (uid,))
    except Exception as e:
        print("[IAPT_V126] user query warn:", e)
        u = None
    if not isinstance(u, dict):
        return feats

    for k in ("features_json", "features", "feature_ids", "feature_json", "permissions"):
        feats |= _iapt_v126_parse_features(u.get(k))

    sid_values = []
    for k in ("subscription_id", "sub_id", "subscription", "subscriptionId", "vip_id", "plan_id"):
        v = u.get(k)
        if v not in (None, "") and v not in sid_values:
            sid_values.append(v)

    sub_cols = set(_iapt_v126_table_columns("subscriptions"))
    query_cols = []
    for c in ("sub_id", "id"):
        if c in sub_cols:
            query_cols.append(c)
    if not query_cols:
        query_cols = ["sub_id"]

    seen = set()
    for sid in sid_values:
        for col in query_cols:
            try:
                rows = db.all("SELECT * FROM subscriptions WHERE " + col + "=%s", (sid,)) or []
            except Exception as e:
                print("[IAPT_V126] subscription query warn:", col, e)
                continue
            for r in rows:
                if not isinstance(r, dict):
                    continue
                key = tuple((x, r.get(x)) for x in ("id", "sub_id", "name") if x in r)
                if key in seen:
                    continue
                seen.add(key)
                for k in ("features_json", "features", "feature_ids", "feature_json", "permissions"):
                    feats |= _iapt_v126_parse_features(r.get(k))
    return feats


def _iapt_v126_dynamic_allowed(options, out_dir):
    options = dict(options or {})
    task = _iapt_v126_task_from_outdir(out_dir)

    # 只把 DB 里的订阅功能作为主要来源，避免客户端自己传 dynamic_key 白嫖。
    feats = set()
    uid = None
    try:
        uid = int(task.get("user_id"))
    except Exception:
        try:
            uid = int(options.get("user_id"))
        except Exception:
            uid = None

    if uid is not None:
        feats |= _iapt_v126_user_features(uid)

    # 兼容服务端已经写入的 server features，但不信任客户端 dynamic_key。
    for k in ("_server_feature_ids", "subscription_features", "features", "features_json", "feature_ids", "feature_json", "permissions"):
        feats |= _iapt_v126_parse_features(options.get(k))

    try:
        task_fid = int(task.get("feature_id") or options.get("feature_id") or 0)
    except Exception:
        task_fid = 0

    # 兜底：uid=0 是你当前维护/内部账号；如果 DB 订阅表异常，但任务 feature_id=4，则允许动态 key。
    # 普通用户不能靠 options.dynamic_key 放行。
    allowed = (999 in feats) or (0 in feats) or (4 in feats) or (uid == 0 and task_fid == 4)
    return allowed, feats, task, task_fid, uid


def _iapt_v126_truthy(v):
    return v in (True, 1, "1", "true", "TRUE", "True", "yes", "YES", "on", "ON")


def _iapt_v126_clean_find(v):
    import re as _re
    out = []
    seen = set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        # 客户端旧默认入口不作为 find 限制，否则会只输出 mian.iyu。
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})

    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def add_bool(api_name, flag):
        if _iapt_v126_truthy(options.get(api_name)):
            cmd.append(flag)

    dynamic_allowed, feats, task, task_fid, uid = _iapt_v126_dynamic_allowed(options, out_dir)

    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")
    add_value("post_key", "--post-key")
    add_value("key_xor", "--key-xor")
    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")

    find_targets = _iapt_v126_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v126_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v126_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    if dynamic_allowed:
        cmd.extend(["--mode", "auto", "--outer-mode", "auto", "--restore-fn-names", "auto"])
    else:
        cmd.extend(["--mode", "fast", "--outer-mode", "fixed", "--restore-fn-names", "off", "--no-key-cache", "--no-dynamic-key"])

    print("[IAPT_V126] uid=%s task_feature_id=%s db_features=%s dynamic_allowed=%s max_output_files=%s find=%s" % (
        uid, task_fid, sorted(feats), dynamic_allowed, max_out, find_targets
    ))
    print("[IAPT_V126] cmd=" + " ".join(map(str, cmd)))
    return cmd
# IAPT_V126_FINAL_BUILD_CMD_OVERRIDE_END

# IAPT_V127_DYNAMIC_KEY_TOGGLE_FINAL_BEGIN
# v127 final override:
# dynamic key needs BOTH:
#   1) server-side entitlement from DB features: 0 or 4
#   2) this task explicitly requests dynamic_key=true
# Never allow because feature_id==4 alone, otherwise "off" tasks still run dynamic.
def _iapt_v127_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or isinstance(v, bool):
        return out
    if isinstance(v, int):
        out.add(v); return out
    if isinstance(v, (list, tuple, set)):
        for x in v:
            out |= _iapt_v127_parse_features(x)
        return out
    if isinstance(v, dict):
        for k, x in v.items():
            if str(k).lower() in ("features","feature_ids","features_json","feature_list","subscription_features","permissions","feature_json","_server_feature_ids"):
                out |= _iapt_v127_parse_features(x)
        return out
    st = str(v).strip()
    if not st:
        return out
    try:
        return _iapt_v127_parse_features(_json.loads(st))
    except Exception:
        pass
    for n in _re.findall(r"-?\d+", st):
        try: out.add(int(n))
        except Exception: pass
    return out


def _iapt_v127_truthy(v):
    return v in (True, 1, "1", "true", "TRUE", "True", "yes", "YES", "on", "ON")


def _iapt_v127_table_columns(table):
    try:
        rows = db.all("SHOW COLUMNS FROM " + table) or []
        cols = []
        for r in rows:
            if isinstance(r, dict):
                cols.append(str(r.get("Field") or r.get("field") or ""))
            elif r:
                cols.append(str(r[0]))
        return [x for x in cols if x]
    except Exception:
        return []


def _iapt_v127_task_from_outdir(out_dir):
    try:
        task_no = Path(out_dir).name
        if task_no:
            t = db.one("SELECT * FROM tasks WHERE task_no=%s ORDER BY id DESC LIMIT 1", (task_no,))
            if isinstance(t, dict):
                return t
    except Exception as e:
        print("[IAPT_V127] task query warn:", e)
    return {}


def _iapt_v127_user_features(uid):
    feats = set()
    try:
        uid = int(uid)
    except Exception:
        return feats
    try:
        u = db.one("SELECT * FROM users WHERE id=%s", (uid,))
    except Exception as e:
        print("[IAPT_V127] user query warn:", e)
        u = None
    if not isinstance(u, dict):
        return feats

    for k in ("features_json","features","feature_ids","feature_json","permissions"):
        feats |= _iapt_v127_parse_features(u.get(k))

    sid_values = []
    for k in ("subscription_id","sub_id","subscription","subscriptionId","vip_id","plan_id"):
        v = u.get(k)
        if v not in (None, "") and v not in sid_values:
            sid_values.append(v)

    sub_cols = set(_iapt_v127_table_columns("subscriptions"))
    query_cols = []
    for c in ("sub_id", "id"):
        if c in sub_cols:
            query_cols.append(c)
    if not query_cols:
        query_cols = ["sub_id"]

    for sid in sid_values:
        for col in query_cols:
            try:
                rows = db.all("SELECT * FROM subscriptions WHERE " + col + "=%s", (sid,)) or []
            except Exception as e:
                print("[IAPT_V127] subscription query warn:", col, e)
                continue
            for r in rows:
                if not isinstance(r, dict):
                    continue
                for k in ("features_json","features","feature_ids","feature_json","permissions"):
                    feats |= _iapt_v127_parse_features(r.get(k))
    return feats


def _iapt_v127_clean_find(v):
    import re as _re
    out = []
    seen = set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name); out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})

    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    task = _iapt_v127_task_from_outdir(out_dir)
    try:
        uid = int(task.get("user_id") if isinstance(task, dict) and task.get("user_id") is not None else options.get("user_id"))
    except Exception:
        uid = None

    server_features = set()
    if uid is not None:
        server_features |= _iapt_v127_user_features(uid)
    for k in ("_server_feature_ids","subscription_features","features","features_json","feature_ids","feature_json","permissions"):
        server_features |= _iapt_v127_parse_features(options.get(k))

    entitlement = (999 in server_features) or (0 in server_features) or (4 in server_features)
    request_dynamic = _iapt_v127_truthy(options.get("dynamic_key")) or _iapt_v127_truthy(options.get("server_dynamic_key")) or _iapt_v127_truthy(options.get("enable_dynamic_key"))

    # 关键：必须两者同时满足。feature_id==4 不再自动放行。
    dynamic_allowed = bool(entitlement and request_dynamic)

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def add_bool(api_name, flag):
        if _iapt_v127_truthy(options.get(api_name)):
            cmd.append(flag)

    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")
    add_value("post_key", "--post-key")
    add_value("key_xor", "--key-xor")
    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")

    find_targets = _iapt_v127_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v127_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v127_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    if dynamic_allowed:
        cmd.extend(["--mode", "auto", "--outer-mode", "auto", "--restore-fn-names", "auto"])
    else:
        cmd.extend(["--mode", "fast", "--outer-mode", "fixed", "--restore-fn-names", "off", "--no-key-cache", "--no-dynamic-key"])

    print("[IAPT_V127] uid=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_allowed=%s max_output_files=%s find=%s" % (
        uid, sorted(server_features), entitlement, request_dynamic, dynamic_allowed, max_out, find_targets
    ))
    print("[IAPT_V127] cmd=" + " ".join(map(str, cmd)))
    return cmd
# IAPT_V127_DYNAMIC_KEY_TOGGLE_FINAL_END

# IAPT_V128_DYNAMIC_KEY_HARD_ROUTE_BEGIN
# v128:
# 1) feature_id=4 is treated as the dynamic-key route.
# 2) Dynamic route must have BOTH server entitlement(0/4) and options.dynamic_key=true.
# 3) If not, fail before subprocess/cache-save.
# 4) build_cmd at file end is the effective global build_cmd used by V55 run_task.
def _iapt_v128_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or isinstance(v, bool):
        return out
    if isinstance(v, int):
        out.add(v); return out
    if isinstance(v, (list, tuple, set)):
        for x in v:
            out |= _iapt_v128_parse_features(x)
        return out
    if isinstance(v, dict):
        for k, x in v.items():
            if str(k).lower() in ("features","feature_ids","features_json","feature_list","subscription_features","permissions","feature_json","_server_feature_ids"):
                out |= _iapt_v128_parse_features(x)
        return out
    s = str(v).strip()
    if not s:
        return out
    try:
        return _iapt_v128_parse_features(_json.loads(s))
    except Exception:
        pass
    for n in _re.findall(r"-?\d+", s):
        try:
            out.add(int(n))
        except Exception:
            pass
    return out


def _iapt_v128_truthy(v):
    return v in (True, 1, "1", "true", "TRUE", "True", "yes", "YES", "on", "ON")


def _iapt_v128_table_columns(table):
    try:
        rows = db.all("SHOW COLUMNS FROM " + table) or []
        cols = []
        for r in rows:
            if isinstance(r, dict):
                cols.append(str(r.get("Field") or r.get("field") or ""))
            elif r:
                cols.append(str(r[0]))
        return [x for x in cols if x]
    except Exception as e:
        print("[IAPT_V128] show columns warn:", table, e)
        return []


def _iapt_v128_get_task(task_id=None, out_dir=None):
    try:
        if task_id is not None:
            t = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
            if isinstance(t, dict):
                return t
    except Exception as e:
        print("[IAPT_V128] task id query warn:", e)
    try:
        if out_dir is not None:
            task_no = Path(out_dir).name
            if task_no:
                t = db.one("SELECT * FROM tasks WHERE task_no=%s ORDER BY id DESC LIMIT 1", (task_no,))
                if isinstance(t, dict):
                    return t
    except Exception as e:
        print("[IAPT_V128] task_no query warn:", e)
    return {}


def _iapt_v128_user_features(uid):
    feats = set()
    try:
        uid = int(uid)
    except Exception:
        return feats
    try:
        u = db.one("SELECT * FROM users WHERE id=%s", (uid,))
    except Exception as e:
        print("[IAPT_V128] user query warn:", e)
        u = None
    if not isinstance(u, dict):
        return feats

    for k in ("features_json","features","feature_ids","feature_json","permissions"):
        feats |= _iapt_v128_parse_features(u.get(k))

    sid_values = []
    for k in ("subscription_id","sub_id","subscription","subscriptionId","vip_id","plan_id"):
        v = u.get(k)
        if v not in (None, "") and v not in sid_values:
            sid_values.append(v)

    sub_cols = set(_iapt_v128_table_columns("subscriptions"))
    query_cols = []
    for c in ("sub_id", "id"):
        if c in sub_cols:
            query_cols.append(c)
    if not query_cols:
        query_cols = ["sub_id"]

    for sid in sid_values:
        for col in query_cols:
            try:
                rows = db.all("SELECT * FROM subscriptions WHERE " + col + "=%s", (sid,)) or []
            except Exception as e:
                print("[IAPT_V128] subscription query warn:", col, e)
                continue
            for r in rows:
                if not isinstance(r, dict):
                    continue
                for k in ("features_json","features","feature_ids","feature_json","permissions"):
                    feats |= _iapt_v128_parse_features(r.get(k))
    return feats


def _iapt_v128_clean_find(v):
    import re as _re
    out, seen = [], set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _iapt_v128_eval(task, options):
    options = dict(options or {})
    task = task if isinstance(task, dict) else {}

    try:
        uid = int(task.get("user_id") if task.get("user_id") is not None else options.get("user_id"))
    except Exception:
        uid = None

    try:
        task_feature_id = int(task.get("feature_id") if task.get("feature_id") is not None else options.get("feature_id") or 0)
    except Exception:
        task_feature_id = 0

    try:
        opt_feature_id = int(options.get("feature_id") or 0)
    except Exception:
        opt_feature_id = 0

    server_features = set()
    if uid is not None:
        server_features |= _iapt_v128_user_features(uid)
    for k in ("_server_feature_ids","subscription_features","features","features_json","feature_ids","feature_json","permissions"):
        server_features |= _iapt_v128_parse_features(options.get(k))

    entitlement = (999 in server_features) or (0 in server_features) or (4 in server_features)
    request_dynamic = _iapt_v128_truthy(options.get("dynamic_key")) or _iapt_v128_truthy(options.get("server_dynamic_key")) or _iapt_v128_truthy(options.get("enable_dynamic_key"))

    # feature_id=4 是动态 key 路线，不允许 dynamic_key=false 或无权限时继续跑普通解密。
    dynamic_route = (task_feature_id == 4) or (opt_feature_id == 4) or ("dynamic_key" in options) or ("server_dynamic_key" in options) or ("enable_dynamic_key" in options)
    dynamic_allowed = bool(entitlement and request_dynamic)

    return {
        "uid": uid,
        "task_feature_id": task_feature_id,
        "opt_feature_id": opt_feature_id,
        "server_features": server_features,
        "entitlement": entitlement,
        "request_dynamic": request_dynamic,
        "dynamic_route": dynamic_route,
        "dynamic_allowed": dynamic_allowed,
    }


def _iapt_v128_fail_task(task_id, reason):
    try:
        task = _iapt_v128_get_task(task_id=task_id)
        task_no = str(task.get("task_no") or task_id)
        log_path = APP_STORAGE / "tasks" / (task_no + ".log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(reason + "\n", encoding="utf-8")
    except Exception as e:
        print("[IAPT_V128] write fail log warn:", e)
    try:
        db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (reason, int(task_id)))
    except Exception as e:
        print("[IAPT_V128] update task fail warn:", e)


try:
    _IAPT_V128_ORIG_RUN_TASK = run_task
    def run_task(task_id: int):
        task = _iapt_v128_get_task(task_id=task_id)
        try:
            import json as _json
            options = _json.loads(task.get("options_json") or "{}") if isinstance(task, dict) else {}
            if not isinstance(options, dict):
                options = {}
        except Exception:
            options = {}
        ev = _iapt_v128_eval(task, options)
        print("[IAPT_V128] precheck task=%s uid=%s task_feature_id=%s opt_feature_id=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_route=%s dynamic_allowed=%s" % (
            task_id, ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["server_features"]), ev["entitlement"], ev["request_dynamic"], ev["dynamic_route"], ev["dynamic_allowed"]
        ))
        if ev["dynamic_route"] and not ev["dynamic_allowed"]:
            if not ev["request_dynamic"]:
                reason = "未开启动态 key 获取，动态 key 路线禁止解密"
            elif not ev["entitlement"]:
                reason = "订阅未包含动态 key 获取功能，禁止解密"
            else:
                reason = "动态 key 权限校验失败，禁止解密"
            _iapt_v128_fail_task(task_id, "[IAPT_V128_BLOCK] " + reason)
            return
        return _IAPT_V128_ORIG_RUN_TASK(task_id)
except Exception as _e:
    print("[IAPT_V128] run_task wrap warn:", _e)


# IAPT_SIGNATURE_SOKEY_V285_HELPERS_BEGIN
def _iapt_v285_truthy(value):
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in (
        "1", "true", "yes", "on", "y",
    )


def _iapt_v285_drop_cli(argv, name, takes_value=True):
    clean = []
    index = 0
    prefix = name + "="
    while index < len(argv):
        item = str(argv[index])
        if item == name:
            index += (
                2 if takes_value and index + 1 < len(argv)
                else 1
            )
            continue
        if item.startswith(prefix):
            index += 1
            continue
        clean.append(argv[index])
        index += 1
    argv[:] = clean


def _iapt_v285_feature_numbers(value):
    import json as _iapt_v285_json
    import re as _iapt_v285_re

    if value is None or value == "":
        return set()

    if isinstance(value, bool):
        return set()

    if isinstance(value, (int, float)):
        try:
            return {int(value)}
        except Exception:
            return set()

    if isinstance(value, (list, tuple, set)):
        out = set()
        for item in value:
            out.update(_iapt_v285_feature_numbers(item))
        return out

    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return set()
        if raw.startswith(("{", "[")):
            try:
                return _iapt_v285_feature_numbers(
                    _iapt_v285_json.loads(raw)
                )
            except Exception:
                pass
        return {
            int(item)
            for item in _iapt_v285_re.findall(r"\d+", raw)
        }

    return set()


def _iapt_v285_requested_feature_15(task, options):
    # Do not inspect subscription lists, server feature lists, or entitlements:
    # those describe what the user owns, not what this task requested.
    request_keys = (
        "feature_id",
        "task_feature_id",
        "opt_feature_id",
        "requested_feature_id",
        "request_feature_id",
    )

    for mapping in (task, options):
        if not isinstance(mapping, dict):
            continue
        for key in request_keys:
            if 15 in _iapt_v285_feature_numbers(mapping.get(key)):
                return True
    return False


def _iapt_v285_zip_state(apk_path):
    import zipfile as _iapt_v285_zipfile

    state = {
        "marker": False,
        "signature_present": False,
        "signature_nonempty": False,
        "signature_bytes": 0,
    }

    with _iapt_v285_zipfile.ZipFile(apk_path) as archive:
        names = {
            str(item.filename).replace("\\", "/").lower():
            item.filename
            for item in archive.infolist()
            if not item.is_dir()
        }

        state["marker"] = (
            "meta-inf/iapt/server_sokey" in names
        )

        sig_name = names.get("assets/extra_conf1g.xml")
        if sig_name:
            raw = archive.read(sig_name)[:1048576]
            state["signature_present"] = True
            state["signature_bytes"] = len(raw)

            # 空文件、只有 BOM/NUL/空白都按“空配置”处理。
            cleaned = (
                raw.replace(b"\xef\xbb\xbf", b"")
                .replace(b"\x00", b"")
                .strip()
            )
            state["signature_nonempty"] = bool(cleaned)

    return state


def _iapt_v285_extract_sokey(apk_path):
    import sys as _iapt_v285_sys
    from pathlib import Path as _IaptV285Path

    try:
        from .tools.iapt_sokey_static_v2 import (
            extract_sokey_from_apk as extractor,
        )
    except (ImportError, ValueError):
        try:
            from app.tools.iapt_sokey_static_v2 import (
                extract_sokey_from_apk as extractor,
            )
        except (ImportError, ValueError):
            tools = _IaptV285Path(__file__).resolve().parent / "tools"
            if str(tools) not in _iapt_v285_sys.path:
                _iapt_v285_sys.path.insert(0, str(tools))
            from iapt_sokey_static_v2 import (
                extract_sokey_from_apk as extractor,
            )

    return extractor(apk_path)


def _iapt_v285_finalize_command(
    cmd,
    apk_path,
    options,
    task,
    sokey_enum_requested=False,
):
    import re as _iapt_v285_re

    options = options if isinstance(options, dict) else {}
    task = task if isinstance(task, dict) else {}

    state = _iapt_v285_zip_state(apk_path)

    # 正确的 extra_conf1g.xml 规则：
    #   空 -> verify
    #   任意非空内容 -> skip
    # 文件缺失是异常情况，无法证明关闭签名，因此默认 verify。
    signature_mode = (
        "skip"
        if state["signature_present"]
        and state["signature_nonempty"]
        else "verify"
    )

    _iapt_v285_drop_cli(cmd, "--signature-mode", True)
    _iapt_v285_drop_cli(cmd, "--signature-bytes-hex", True)
    cmd.extend(["--signature-mode", signature_mode])

    if signature_mode == "verify":
        signature_hex = str(
            options.get("signature_bytes_hex") or ""
        ).strip()
        if signature_hex:
            cmd.extend(["--signature-bytes-hex", signature_hex])

    option_request = _iapt_v285_truthy(
        options.get("server_sokey")
    )
    # Feature 15 is shared by historical builds with the dynamic-key pool.
    # Infer server_sokey from feature 15 only when this is not a pool request.
    pool_mode = str(
        options.get("server_key_pool_mode") or ""
    ).strip().lower()
    pool_ref = str(
        options.get("server_key_pool_ref") or ""
    ).strip()
    pool_request = (
        pool_mode in ("selected", "enum", "so_match")
        or bool(pool_ref)
    )
    feature_request = (
        not pool_request
        and _iapt_v285_requested_feature_15(task, options)
    )
    marker_request = bool(state["marker"])
    server_sokey_requested = (
        option_request or feature_request or marker_request
    )

    sources = []
    if option_request:
        sources.append("option")
    if feature_request:
        sources.append("feature15")
    if marker_request:
        sources.append("apk-marker")

    if server_sokey_requested:
        if bool(sokey_enum_requested):
            raise RuntimeError(
                "服务器获取 sokey 不能与手动 sokey 枚举同时开启"
            )

        _iapt_v285_drop_cli(cmd, "--server-sokey-static", False)
        _iapt_v285_drop_cli(cmd, "--hidden", True)

        hidden, metadata = _iapt_v285_extract_sokey(apk_path)
        if isinstance(hidden, bytes):
            hidden_text = hidden.decode("ascii", "strict")
        else:
            hidden_text = str(hidden or "").strip()

        if not _iapt_v285_re.fullmatch(
            r"[A-Za-z0-9]{10}Q{10}W{10}EE",
            hidden_text,
        ):
            raise RuntimeError(
                "服务器从 libygsiyu.so 恢复的 sokey 格式无效"
            )

        cmd.extend(["--hidden", hidden_text])
        print(
            "[IAPT_V285] server sokey passed as exact --hidden: "
            "request=%s strategy=%s entries=%s"
            % (
                ",".join(sources) or "unknown",
                metadata.get("strategy"),
                ",".join(
                    metadata.get("successful_entries") or []
                ),
            ),
            flush=True,
        )

    print(
        "[IAPT_V285] parameter config: "
        "signature_present=%s signature_bytes=%s "
        "signature_mode=%s server_sokey=%s request=%s"
        % (
            int(state["signature_present"]),
            int(state["signature_bytes"]),
            signature_mode,
            int(server_sokey_requested),
            ",".join(sources) or "none",
        ),
        flush=True,
    )

    return {
        "signature_mode": signature_mode,
        "server_sokey": server_sokey_requested,
        "request_sources": sources,
    }
# IAPT_SIGNATURE_SOKEY_V285_HELPERS_END
def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})
    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    task = _iapt_v128_get_task(out_dir=out_dir)
    ev = _iapt_v128_eval(task, options)

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def add_bool(api_name, flag):
        if _iapt_v128_truthy(options.get(api_name)):
            cmd.append(flag)

    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")
    add_value("post_key", "--post-key")
    add_value("key_xor", "--key-xor")
    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")

    find_targets = _iapt_v128_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v128_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v128_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    if ev["dynamic_allowed"]:
        cmd.extend(["--mode", "auto", "--outer-mode", "auto", "--restore-fn-names", "auto"])
    else:
        cmd.extend(["--mode", "fast", "--outer-mode", "fixed", "--restore-fn-names", "off", "--no-key-cache", "--no-dynamic-key"])

    # IAPT_SIGNATURE_SOKEY_V285_CALL_BEGIN
    _iapt_v285_finalize_command(
        cmd,
        apk_path,
        options,
        locals().get("task") or {},
        locals().get("sokey_enum_requested", False),
    )
    # IAPT_SIGNATURE_SOKEY_V285_CALL_END
    print("[IAPT_V128] build uid=%s task_feature_id=%s opt_feature_id=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_route=%s dynamic_allowed=%s max_output_files=%s find=%s" % (
        ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["server_features"]), ev["entitlement"], ev["request_dynamic"], ev["dynamic_route"], ev["dynamic_allowed"], max_out, find_targets
    ))
    print("[IAPT_V128] cmd=" + " ".join(map(str, cmd)))
    return cmd
# IAPT_V128_DYNAMIC_KEY_HARD_ROUTE_END


# IAPT_V129_STRICT_DYNKEY_BEGIN
# v129: final gate after v128. Do not trust client options for entitlement.
def _iapt_v129_truthy(v):
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_v129_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or v == "":
        return out
    def walk(x):
        if x is None or isinstance(x, bool):
            return
        if isinstance(x, int):
            out.add(int(x)); return
        if isinstance(x, (list, tuple, set)):
            for i in x: walk(i)
            return
        if isinstance(x, dict):
            for k in ("features_json", "features", "feature_ids", "feature_json", "permissions"):
                if k in x: walk(x.get(k))
            return
        s = str(x).strip()
        if not s:
            return
        try:
            walk(_json.loads(s)); return
        except Exception:
            pass
        for n in _re.findall(r"-?\d+", s):
            try: out.add(int(n))
            except Exception: pass
    walk(v)
    return out


def _iapt_v129_get_task(task_id=None, out_dir=None):
    try:
        if task_id is not None:
            return db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
        if out_dir is not None:
            task_no = Path(out_dir).name
            return db.one("SELECT * FROM tasks WHERE task_no=%s", (task_no,)) or {}
    except Exception as e:
        print("[IAPT_V129] get task warn:", e)
    return {}


def _iapt_v129_strict_dynamic_entitlement(uid):
    feats, sub_ids = set(), set()
    if uid is None:
        return False, feats, sub_ids
    try:
        uid = int(uid)
    except Exception:
        return False, feats, sub_ids
    rows = []
    try:
        rows += list(db.all("SELECT s.sub_id,s.features_json FROM user_subscriptions us JOIN subscriptions s ON us.sub_id=s.sub_id WHERE us.user_id=%s AND us.sub_id<>0 AND (us.expire_at IS NULL OR us.expire_at>NOW())", (uid,)) or [])
    except Exception as e:
        print("[IAPT_V129] user_subscriptions warn:", e)
    try:
        rows += list(db.all("SELECT s.sub_id,s.features_json FROM users u JOIN subscriptions s ON u.subscription_id=s.sub_id WHERE u.id=%s AND u.subscription_id<>0 AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())", (uid,)) or [])
    except Exception as e:
        print("[IAPT_V129] users.subscription_id warn:", e)
    for r in rows:
        try:
            sid = int(r.get("sub_id") or 0)
        except Exception:
            sid = 0
        if sid == 0:
            continue
        sub_ids.add(sid)
        feats |= _iapt_v129_parse_features(r.get("features_json"))
    return ((999 in feats) or (0 in feats) or (4 in feats)), feats, sub_ids


def _iapt_v129_eval(task, options):
    task = task if isinstance(task, dict) else {}
    options = dict(options or {})
    try: uid = int(task.get("user_id") if task.get("user_id") is not None else options.get("user_id"))
    except Exception: uid = None
    try: task_feature_id = int(task.get("feature_id") if task.get("feature_id") is not None else 0)
    except Exception: task_feature_id = 0
    try: opt_feature_id = int(options.get("feature_id") or 0)
    except Exception: opt_feature_id = 0
    request_dynamic = _iapt_v129_truthy(options.get("dynamic_key")) or _iapt_v129_truthy(options.get("server_dynamic_key")) or _iapt_v129_truthy(options.get("enable_dynamic_key"))
    dynamic_route = (task_feature_id == 4) or (opt_feature_id == 4) or request_dynamic
    entitlement, feats, sub_ids = _iapt_v129_strict_dynamic_entitlement(uid)
    dynamic_allowed = bool(dynamic_route and request_dynamic and entitlement)
    return {"uid": uid, "task_feature_id": task_feature_id, "opt_feature_id": opt_feature_id, "request_dynamic": request_dynamic, "dynamic_route": dynamic_route, "dynamic_allowed": dynamic_allowed, "server_features": feats, "sub_ids": sub_ids, "entitlement": entitlement}


def _iapt_v129_fail_task(task_id, reason):
    try:
        task = _iapt_v129_get_task(task_id=task_id)
        task_no = str(task.get("task_no") or task_id)
        log_path = APP_STORAGE / "tasks" / (task_no + ".log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(reason + "\n", encoding="utf-8")
    except Exception as e:
        print("[IAPT_V129] write fail log warn:", e)
    try:
        db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (reason, int(task_id)))
    except Exception as e:
        print("[IAPT_V129] update task fail warn:", e)


def _iapt_v129_clean_find(v):
    import re as _re
    out, seen = [], set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name); out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})
    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)
    task = _iapt_v129_get_task(out_dir=out_dir)
    ev = _iapt_v129_eval(task, options)
    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]
    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])
    def add_bool(api_name, flag):
        if _iapt_v129_truthy(options.get(api_name)):
            cmd.append(flag)
    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")
    if ev["dynamic_allowed"]:
        add_value("post_key", "--post-key")
        add_value("key_xor", "--key-xor")
    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")
    find_targets = _iapt_v129_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v129_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v129_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")
    try: max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception: max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])
    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")
    if ev["dynamic_allowed"]:
        cmd.extend(["--mode", "auto", "--outer-mode", "auto", "--restore-fn-names", "auto"])
    else:
        cmd.extend(["--mode", "fast", "--outer-mode", "fixed", "--restore-fn-names", "off", "--no-key-cache", "--no-dynamic-key"])
    # IAPT_SIGNATURE_SOKEY_V285_CALL_BEGIN
    _iapt_v285_finalize_command(
        cmd,
        apk_path,
        options,
        locals().get("task") or {},
        locals().get("sokey_enum_requested", False),
    )
    # IAPT_SIGNATURE_SOKEY_V285_CALL_END
    print("[IAPT_V129] build uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_route=%s dynamic_allowed=%s max_output_files=%s find=%s" % (
        ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_dynamic"], ev["dynamic_route"], ev["dynamic_allowed"], max_out, find_targets
    ))
    print("[IAPT_V129] cmd=" + " ".join(map(str, cmd)))
    return cmd

try:
    _IAPT_V129_BASE_RUN_TASK = globals().get("_IAPT_V128_ORIG_RUN_TASK") or globals().get("_IAPT_V123_ORIG_RUN_TASK") or run_task
    def run_task(task_id: int):
        task = _iapt_v129_get_task(task_id=task_id)
        try:
            options = json.loads(task.get("options_json") or "{}") if isinstance(task, dict) else {}
            if not isinstance(options, dict): options = {}
        except Exception:
            options = {}
        ev = _iapt_v129_eval(task, options)
        print("[IAPT_V129] precheck task=%s uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_route=%s dynamic_allowed=%s" % (
            task_id, ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_dynamic"], ev["dynamic_route"], ev["dynamic_allowed"]
        ))
        if ev["dynamic_route"] and not ev["dynamic_allowed"]:
            reason = "订阅未包含动态Key" if ev["request_dynamic"] else "未开启动态Key"
            _iapt_v129_fail_task(task_id, "[IAPT_V129_BLOCK] " + reason)
            return
        return _IAPT_V129_BASE_RUN_TASK(task_id)
except Exception as _iapt_v129_e:
    print("[IAPT_V129] run_task wrap warn:", _iapt_v129_e)
# IAPT_V129_STRICT_DYNKEY_END


# IAPT_V130_STATIC_AUTO_GATE_BEGIN
# v130: 静态高级算法始终允许 outer-mode auto；只禁止无权限的服务器动态Key获取。
def _iapt_v130_truthy(v):
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_v130_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or v == "":
        return out
    def walk(x):
        if x is None or isinstance(x, bool):
            return
        if isinstance(x, int):
            out.add(int(x)); return
        if isinstance(x, (list, tuple, set)):
            for i in x: walk(i)
            return
        if isinstance(x, dict):
            for k in ("features_json", "features", "feature_ids", "feature_json", "permissions"):
                if k in x: walk(x.get(k))
            return
        sx = str(x).strip()
        if not sx:
            return
        try:
            walk(_json.loads(sx)); return
        except Exception:
            pass
        for n in _re.findall(r"-?\d+", sx):
            try: out.add(int(n))
            except Exception: pass
    walk(v)
    return out


def _iapt_v130_get_task(task_id=None, out_dir=None):
    try:
        if task_id is not None:
            return db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
        if out_dir is not None:
            task_no = Path(out_dir).name
            return db.one("SELECT * FROM tasks WHERE task_no=%s ORDER BY id DESC LIMIT 1", (task_no,)) or {}
    except Exception as e:
        print("[IAPT_V130] get task warn:", e)
    return {}


def _iapt_v130_dynamic_entitlement(uid):
    feats, sub_ids = set(), set()
    try:
        uid = int(uid)
    except Exception:
        return False, feats, sub_ids
    queries = [
        ("SELECT s.sub_id,s.features_json FROM user_subscriptions us JOIN subscriptions s ON us.sub_id=s.sub_id WHERE us.user_id=%s AND us.sub_id<>0 AND (us.expire_at IS NULL OR us.expire_at>NOW())", (uid,)),
        ("SELECT s.sub_id,s.features_json FROM users u JOIN subscriptions s ON u.subscription_id=s.sub_id WHERE u.id=%s AND u.subscription_id<>0 AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())", (uid,)),
    ]
    for sql, args in queries:
        try:
            rows = db.all(sql, args) or []
        except Exception as e:
            print("[IAPT_V130] entitlement query warn:", e)
            rows = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            try:
                sid = int(r.get("sub_id") or 0)
            except Exception:
                sid = 0
            if sid == 0:
                continue
            sub_ids.add(sid)
            feats |= _iapt_v130_parse_features(r.get("features_json"))
    return ((999 in feats) or (0 in feats) or (4 in feats)), feats, sub_ids


def _iapt_v130_eval(task, options):
    task = task if isinstance(task, dict) else {}
    options = dict(options or {})
    try:
        uid = int(task.get("user_id") if task.get("user_id") is not None else options.get("user_id"))
    except Exception:
        uid = None
    try:
        task_feature_id = int(task.get("feature_id") if task.get("feature_id") is not None else 0)
    except Exception:
        task_feature_id = 0
    try:
        opt_feature_id = int(options.get("feature_id") or 0)
    except Exception:
        opt_feature_id = 0

    request_server_dynamic = (
        _iapt_v130_truthy(options.get("dynamic_key")) or
        _iapt_v130_truthy(options.get("server_dynamic_key")) or
        _iapt_v130_truthy(options.get("enable_dynamic_key"))
    )
    manual_key = bool(str(options.get("post_key") or "").strip() and str(options.get("key_xor") or "").strip())
    entitlement, feats, sub_ids = _iapt_v130_dynamic_entitlement(uid)
    dynamic_allowed = bool(request_server_dynamic and entitlement)
    return {
        "uid": uid,
        "task_feature_id": task_feature_id,
        "opt_feature_id": opt_feature_id,
        "request_server_dynamic": request_server_dynamic,
        "manual_key": manual_key,
        "entitlement": entitlement,
        "server_features": feats,
        "sub_ids": sub_ids,
        "dynamic_allowed": dynamic_allowed,
    }


def _iapt_v130_fail_task(task_id, reason):
    try:
        task = _iapt_v130_get_task(task_id=task_id)
        task_no = str(task.get("task_no") or task_id)
        log_path = APP_STORAGE / "tasks" / (task_no + ".log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(reason + "\n", encoding="utf-8")
    except Exception as e:
        print("[IAPT_V130] write fail log warn:", e)
    try:
        db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (reason, int(task_id)))
    except Exception as e:
        print("[IAPT_V130] update task fail warn:", e)


def _iapt_v130_clean_find(v):
    import re as _re
    out, seen = [], set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name); out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})
    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    task = _iapt_v130_get_task(out_dir=out_dir)
    ev = _iapt_v130_eval(task, options)

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def add_bool(api_name, flag):
        if _iapt_v130_truthy(options.get(api_name)):
            cmd.append(flag)

    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")

    if ev["manual_key"] or ev["dynamic_allowed"]:
        add_value("post_key", "--post-key")
        add_value("key_xor", "--key-xor")

    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")

    find_targets = _iapt_v130_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v130_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v130_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    cmd.extend(["--mode", "auto", "--outer-mode", "auto", "--restore-fn-names", "auto"])
    if not ev["dynamic_allowed"]:
        if not ev["manual_key"]:
            cmd.append("--no-dynamic-key")
        cmd.append("--no-key-cache")

    # IAPT_SIGNATURE_SOKEY_V285_CALL_BEGIN
    _iapt_v285_finalize_command(
        cmd,
        apk_path,
        options,
        locals().get("task") or {},
        locals().get("sokey_enum_requested", False),
    )
    # IAPT_SIGNATURE_SOKEY_V285_CALL_END
    print("[IAPT_V130] build uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_server_dynamic=%s manual_key=%s dynamic_allowed=%s max_output_files=%s find=%s" % (
        ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_server_dynamic"], ev["manual_key"], ev["dynamic_allowed"], max_out, find_targets
    ))
    print("[IAPT_V130] cmd=" + " ".join(map(str, cmd)))
    return cmd

try:
    _IAPT_V130_BASE_RUN_TASK = (
        globals().get("_IAPT_V129_BASE_RUN_TASK") or
        globals().get("_IAPT_V128_ORIG_RUN_TASK") or
        globals().get("_IAPT_V123_ORIG_RUN_TASK") or
        run_task
    )
    def run_task(task_id: int):
        task = _iapt_v130_get_task(task_id=task_id)
        try:
            options = json.loads(task.get("options_json") or "{}") if isinstance(task, dict) else {}
            if not isinstance(options, dict): options = {}
        except Exception:
            options = {}
        ev = _iapt_v130_eval(task, options)
        print("[IAPT_V130] precheck task=%s uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_server_dynamic=%s manual_key=%s dynamic_allowed=%s" % (
            task_id, ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_server_dynamic"], ev["manual_key"], ev["dynamic_allowed"]
        ))
        if ev["request_server_dynamic"] and not ev["dynamic_allowed"]:
            _iapt_v130_fail_task(task_id, "[IAPT_V130_BLOCK] 订阅未包含动态Key")
            return
        return _IAPT_V130_BASE_RUN_TASK(task_id)
except Exception as _iapt_v130_e:
    print("[IAPT_V130] run_task wrap warn:", _iapt_v130_e)
# IAPT_V130_STATIC_AUTO_GATE_END


# IAPT_V131_AUTO_FIXED_GATE_BEGIN
# v131:
# - 不开“获取动态Key”：--mode auto --outer-mode fixed --no-dynamic-key --no-key-cache
# - 开“获取动态Key”且非0订阅含功能0/4：--mode auto --outer-mode auto
# - 不信任客户端 features_json/feature_ids/permissions
def _iapt_v131_truthy(v):
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_v131_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or v == "":
        return out
    def walk(x):
        if x is None or isinstance(x, bool):
            return
        if isinstance(x, int):
            out.add(int(x)); return
        if isinstance(x, (list, tuple, set)):
            for i in x: walk(i)
            return
        if isinstance(x, dict):
            for k in ("features_json", "features", "feature_ids", "feature_json", "permissions"):
                if k in x: walk(x.get(k))
            return
        sx = str(x).strip()
        if not sx:
            return
        try:
            walk(_json.loads(sx)); return
        except Exception:
            pass
        for n in _re.findall(r"-?\d+", sx):
            try: out.add(int(n))
            except Exception: pass
    walk(v)
    return out


def _iapt_v131_get_task(task_id=None, out_dir=None):
    try:
        if task_id is not None:
            return db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
        if out_dir is not None:
            task_no = Path(out_dir).name
            return db.one("SELECT * FROM tasks WHERE task_no=%s ORDER BY id DESC LIMIT 1", (task_no,)) or {}
    except Exception as e:
        print("[IAPT_V131] get task warn:", e)
    return {}


def _iapt_v131_dynamic_entitlement(uid):
    feats, sub_ids = set(), set()
    try:
        uid = int(uid)
    except Exception:
        return False, feats, sub_ids
    queries = [
        ("SELECT s.sub_id,s.features_json FROM user_subscriptions us JOIN subscriptions s ON us.sub_id=s.sub_id WHERE us.user_id=%s AND us.sub_id<>0 AND (us.expire_at IS NULL OR us.expire_at>NOW())", (uid,)),
        ("SELECT s.sub_id,s.features_json FROM users u JOIN subscriptions s ON u.subscription_id=s.sub_id WHERE u.id=%s AND u.subscription_id<>0 AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())", (uid,)),
    ]
    for sql, args in queries:
        try:
            rows = db.all(sql, args) or []
        except Exception as e:
            print("[IAPT_V131] entitlement query warn:", e)
            rows = []
        for r in rows:
            if not isinstance(r, dict):
                continue
            try:
                sid = int(r.get("sub_id") or 0)
            except Exception:
                sid = 0
            if sid == 0:
                continue
            sub_ids.add(sid)
            feats |= _iapt_v131_parse_features(r.get("features_json"))
    return ((999 in feats) or (0 in feats) or (4 in feats)), feats, sub_ids


def _iapt_v131_eval(task, options):
    task = task if isinstance(task, dict) else {}
    options = dict(options or {})
    try:
        uid = int(task.get("user_id") if task.get("user_id") is not None else options.get("user_id"))
    except Exception:
        uid = None
    try:
        task_feature_id = int(task.get("feature_id") if task.get("feature_id") is not None else 0)
    except Exception:
        task_feature_id = 0
    try:
        opt_feature_id = int(options.get("feature_id") or 0)
    except Exception:
        opt_feature_id = 0
    request_fetch = (
        _iapt_v131_truthy(options.get("dynamic_key")) or
        _iapt_v131_truthy(options.get("server_dynamic_key")) or
        _iapt_v131_truthy(options.get("enable_dynamic_key"))
    )
    manual_key = bool(str(options.get("post_key") or "").strip() and str(options.get("key_xor") or "").strip())
    entitlement, feats, sub_ids = _iapt_v131_dynamic_entitlement(uid)
    fetch_allowed = bool(request_fetch and entitlement)
    return {
        "uid": uid,
        "task_feature_id": task_feature_id,
        "opt_feature_id": opt_feature_id,
        "request_fetch": request_fetch,
        "manual_key": manual_key,
        "entitlement": entitlement,
        "server_features": feats,
        "sub_ids": sub_ids,
        "fetch_allowed": fetch_allowed,
    }


def _iapt_v131_fail_task(task_id, reason):
    try:
        task = _iapt_v131_get_task(task_id=task_id)
        task_no = str(task.get("task_no") or task_id)
        log_path = APP_STORAGE / "tasks" / (task_no + ".log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(reason + "\n", encoding="utf-8")
    except Exception as e:
        print("[IAPT_V131] write fail log warn:", e)
    try:
        db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (reason, int(task_id)))
    except Exception as e:
        print("[IAPT_V131] update task fail warn:", e)


def _iapt_v131_clean_find(v):
    import re as _re
    out, seen = [], set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name); out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})
    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    task = _iapt_v131_get_task(out_dir=out_dir)
    ev = _iapt_v131_eval(task, options)

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def add_bool(api_name, flag):
        if _iapt_v131_truthy(options.get(api_name)):
            cmd.append(flag)

    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")

    if ev["manual_key"] or ev["fetch_allowed"]:
        add_value("post_key", "--post-key")
        add_value("key_xor", "--key-xor")

    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")

    find_targets = _iapt_v131_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v131_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v131_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    cmd.extend(["--mode", "auto"])
    if ev["fetch_allowed"] or ev["manual_key"]:
        cmd.extend(["--outer-mode", "auto", "--restore-fn-names", "auto"])
    else:
        cmd.extend(["--outer-mode", "fixed", "--restore-fn-names", "auto", "--no-dynamic-key", "--no-key-cache"])

    # IAPT_SIGNATURE_SOKEY_V285_CALL_BEGIN
    _iapt_v285_finalize_command(
        cmd,
        apk_path,
        options,
        locals().get("task") or {},
        locals().get("sokey_enum_requested", False),
    )
    # IAPT_SIGNATURE_SOKEY_V285_CALL_END
    print("[IAPT_V131] build uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_fetch=%s manual_key=%s fetch_allowed=%s max_output_files=%s find=%s" % (
        ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_fetch"], ev["manual_key"], ev["fetch_allowed"], max_out, find_targets
    ))
    print("[IAPT_V131] cmd=" + " ".join(map(str, cmd)))
    return cmd

try:
    _IAPT_V131_BASE_RUN_TASK = (
        globals().get("_IAPT_V130_BASE_RUN_TASK") or
        globals().get("_IAPT_V129_BASE_RUN_TASK") or
        globals().get("_IAPT_V128_ORIG_RUN_TASK") or
        globals().get("_IAPT_V123_ORIG_RUN_TASK") or
        run_task
    )
    def run_task(task_id: int):
        task = _iapt_v131_get_task(task_id=task_id)
        try:
            options = json.loads(task.get("options_json") or "{}") if isinstance(task, dict) else {}
            if not isinstance(options, dict): options = {}
        except Exception:
            options = {}
        ev = _iapt_v131_eval(task, options)
        print("[IAPT_V131] precheck task=%s uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_fetch=%s manual_key=%s fetch_allowed=%s" % (
            task_id, ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_fetch"], ev["manual_key"], ev["fetch_allowed"]
        ))
        if ev["request_fetch"] and not ev["fetch_allowed"]:
            _iapt_v131_fail_task(task_id, "[IAPT_V131_BLOCK] 订阅未包含动态Key")
            return
        return _IAPT_V131_BASE_RUN_TASK(task_id)
except Exception as _iapt_v131_e:
    print("[IAPT_V131] run_task wrap warn:", _iapt_v131_e)
# IAPT_V131_AUTO_FIXED_GATE_END


# IAPT_V130_STATIC_AUTO_NO_DYNKEY_BEGIN
# v130: static advanced algorithms must remain available without dynamic key.
# Dynamic key entitlement still only comes from server DB, not client options.

def _iapt_v130_truthy(v):
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_v130_parse_features(v):
    import json as _json, re as _re
    out = set()
    if v is None or v == "":
        return out
    def walk(x):
        if x is None or isinstance(x, bool):
            return
        if isinstance(x, int):
            out.add(int(x)); return
        if isinstance(x, (list, tuple, set)):
            for i in x:
                walk(i)
            return
        if isinstance(x, dict):
            for k in ("features_json", "features", "feature_ids", "feature_json", "permissions"):
                if k in x:
                    walk(x.get(k))
            return
        s = str(x).strip()
        if not s:
            return
        try:
            walk(_json.loads(s)); return
        except Exception:
            pass
        for n in _re.findall(r"-?\d+", s):
            try:
                out.add(int(n))
            except Exception:
                pass
    walk(v)
    return out


def _iapt_v130_get_task(task_id=None, out_dir=None):
    try:
        if task_id is not None:
            return db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
        if out_dir is not None:
            task_no = Path(out_dir).name
            return db.one("SELECT * FROM tasks WHERE task_no=%s", (task_no,)) or {}
    except Exception as e:
        print("[IAPT_V130] get task warn:", e)
    return {}


def _iapt_v130_strict_dynamic_entitlement(uid):
    feats, sub_ids = set(), set()
    if uid is None:
        return False, feats, sub_ids
    try:
        uid = int(uid)
    except Exception:
        return False, feats, sub_ids
    rows = []
    try:
        rows += list(db.all(
            "SELECT s.sub_id,s.features_json FROM user_subscriptions us "
            "JOIN subscriptions s ON us.sub_id=s.sub_id "
            "WHERE us.user_id=%s AND us.sub_id<>0 AND (us.expire_at IS NULL OR us.expire_at>NOW())",
            (uid,)
        ) or [])
    except Exception as e:
        print("[IAPT_V130] user_subscriptions warn:", e)
    try:
        rows += list(db.all(
            "SELECT s.sub_id,s.features_json FROM users u "
            "JOIN subscriptions s ON u.subscription_id=s.sub_id "
            "WHERE u.id=%s AND u.subscription_id<>0 AND (u.subscription_expire IS NULL OR u.subscription_expire>NOW())",
            (uid,)
        ) or [])
    except Exception as e:
        print("[IAPT_V130] users.subscription_id warn:", e)
    for r in rows:
        try:
            sid = int(r.get("sub_id") or 0)
        except Exception:
            sid = 0
        if sid == 0:
            continue
        sub_ids.add(sid)
        feats |= _iapt_v130_parse_features(r.get("features_json"))
    return ((999 in feats) or (0 in feats) or (4 in feats)), feats, sub_ids


def _iapt_v130_eval(task, options):
    task = task if isinstance(task, dict) else {}
    options = dict(options or {})
    try:
        uid = int(task.get("user_id") if task.get("user_id") is not None else options.get("user_id"))
    except Exception:
        uid = None
    try:
        task_feature_id = int(task.get("feature_id") if task.get("feature_id") is not None else 0)
    except Exception:
        task_feature_id = 0
    try:
        opt_feature_id = int(options.get("feature_id") or 0)
    except Exception:
        opt_feature_id = 0
    request_dynamic = (
        _iapt_v130_truthy(options.get("dynamic_key")) or
        _iapt_v130_truthy(options.get("server_dynamic_key")) or
        _iapt_v130_truthy(options.get("enable_dynamic_key"))
    )
    entitlement, feats, sub_ids = _iapt_v130_strict_dynamic_entitlement(uid)
    dynamic_allowed = bool(request_dynamic and entitlement)
    return {
        "uid": uid,
        "task_feature_id": task_feature_id,
        "opt_feature_id": opt_feature_id,
        "request_dynamic": request_dynamic,
        "dynamic_allowed": dynamic_allowed,
        "server_features": feats,
        "sub_ids": sub_ids,
        "entitlement": entitlement,
    }


def _iapt_v130_fail_task(task_id, reason):
    try:
        task = _iapt_v130_get_task(task_id=task_id)
        task_no = str(task.get("task_no") or task_id)
        log_path = APP_STORAGE / "tasks" / (task_no + ".log")
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.write_text(reason + "\n", encoding="utf-8")
    except Exception as e:
        print("[IAPT_V130] write fail log warn:", e)
    try:
        db.exec("UPDATE tasks SET status='failed', error_text=%s WHERE id=%s", (reason, int(task_id)))
    except Exception as e:
        print("[IAPT_V130] update task fail warn:", e)


def _iapt_v130_clean_find(v):
    import re as _re
    out, seen = [], set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})
    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    task = _iapt_v130_get_task(out_dir=out_dir)
    ev = _iapt_v130_eval(task, options)

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    def add_bool(api_name, flag):
        if _iapt_v130_truthy(options.get(api_name)):
            cmd.append(flag)

    add_value("user_password", "--user-password")
    add_value("fb", "--fb")
    add_value("hidden", "--hidden")

    if ev["dynamic_allowed"]:
        add_value("post_key", "--post-key")
        add_value("key_xor", "--key-xor")

    add_value("fast_c", "--fast-c")
    add_value("threads", "--threads")

    find_targets = _iapt_v130_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_v130_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_v130_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    add_bool("dex_enum", "--dex-enum")
    add_value("dex_enum_start", "--dex-enum-start")
    add_value("dex_enum_limit", "--dex-enum-limit")
    add_value("dex_enum_windows", "--dex-enum-windows")
    add_bool("hidden_enum", "--hidden-enum")
    add_value("hidden_prefix", "--hidden-prefix")
    add_value("hidden_charset", "--hidden-charset")
    add_value("hidden_candidates", "--hidden-candidates")
    add_value("hidden_candidates_file", "--hidden-candidates-file")
    add_value("max_hidden_candidates", "--max-hidden-candidates")
    add_value("enum_workers", "--enum-workers")
    add_value("enum_chunk_size", "--enum-chunk-size")
    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    cmd.extend(["--mode", "auto", "--outer-mode", "auto", "--restore-fn-names", "auto"])

    if not ev["dynamic_allowed"]:
        cmd.extend(["--no-key-cache", "--no-dynamic-key"])

    # IAPT_SIGNATURE_SOKEY_V285_CALL_BEGIN
    _iapt_v285_finalize_command(
        cmd,
        apk_path,
        options,
        locals().get("task") or {},
        locals().get("sokey_enum_requested", False),
    )
    # IAPT_SIGNATURE_SOKEY_V285_CALL_END
    print("[IAPT_V130] build uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_allowed=%s max_output_files=%s find=%s" % (
        ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_dynamic"], ev["dynamic_allowed"], max_out, find_targets
    ))
    print("[IAPT_V130] cmd=" + " ".join(map(str, cmd)))
    return cmd


try:
    _IAPT_V130_BASE_RUN_TASK = globals().get("_IAPT_V129_BASE_RUN_TASK") or globals().get("_IAPT_V128_ORIG_RUN_TASK") or globals().get("_IAPT_V123_ORIG_RUN_TASK") or run_task

    def run_task(task_id: int):
        task = _iapt_v130_get_task(task_id=task_id)
        try:
            options = json.loads(task.get("options_json") or "{}") if isinstance(task, dict) else {}
            if not isinstance(options, dict):
                options = {}
        except Exception:
            options = {}

        ev = _iapt_v130_eval(task, options)
        print("[IAPT_V130] precheck task=%s uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request_dynamic=%s dynamic_allowed=%s" % (
            task_id, ev["uid"], ev["task_feature_id"], ev["opt_feature_id"], sorted(ev["sub_ids"]), sorted(ev["server_features"]), ev["entitlement"], ev["request_dynamic"], ev["dynamic_allowed"]
        ))

        if ev["request_dynamic"] and not ev["entitlement"]:
            _iapt_v130_fail_task(task_id, "[IAPT_V130_BLOCK] 订阅未包含动态Key")
            return

        return _IAPT_V130_BASE_RUN_TASK(task_id)
except Exception as _iapt_v130_e:
    print("[IAPT_V130] run_task wrap warn:", _iapt_v130_e)
# IAPT_V130_STATIC_AUTO_NO_DYNKEY_END

# IAPT_DYNAMIC_KEY_FEATURE_SCHEMES_BEGIN

def _iapt_vfp_feature_version(options) -> int:
    try:
        value = int((options or {}).get("dynamic_key_feature_version") or 1)
    except Exception:
        value = 1
    return 1 if value <= 0 else min(value, 100)


def _iapt_vfp_validated_features(apk_path: Path, options: dict):
    """Validate the uploaded SO's own fingerprint and return all client ABI features.

    Only the first SO is uploaded for automatic extraction.  Its claimed ABI
    fingerprint must match the server calculation; the remaining ABI fingerprints
    are learned as metadata for the same client APK.
    """
    from .dynamic_key_pool import (
        extract_all_so_from_bytes, normalize_feature_map, so_feature_sha256,
    )
    version = _iapt_vfp_feature_version(options)
    claimed = normalize_feature_map((options or {}).get("dynamic_key_features"), version=version)
    data = Path(apk_path).read_bytes()
    rows = extract_all_so_from_bytes(data, str((options or {}).get("original_filename") or Path(apk_path).name))
    if not rows:
        raise RuntimeError("上传内容没有 libygsiyu.so")
    selected = rows[0]
    selected_abi = str(selected.get("abi") or "unknown").strip().lower()
    hinted_abi = str((options or {}).get("dynamic_key_sample_abi") or "").strip().lower()
    # Direct one-SO uploads lose the original lib/<abi>/ path. Prefer the
    # client-supplied ABI only when that ABI is also present in the signed
    # fingerprint map; the actual SHA-256 still has to match server calculation.
    if claimed and hinted_abi in claimed:
        selected_abi = hinted_abi
    selected_sha = so_feature_sha256(bytes(selected.get("data") or b""))
    if claimed:
        claimed_sha = str(claimed.get(selected_abi) or "").lower()
        if not claimed_sha or claimed_sha != selected_sha:
            raise RuntimeError("客户端动态库指纹与上传 SO 不一致")
    else:
        claimed = {selected_abi: selected_sha}
    return claimed, selected, version


def _iapt_vfp_record_server_extract(apk_path: Path, out_dir: Path, task: dict, options: dict):
    # IAPT_VERIFIED_DYNAMIC_POOL_V272
    # SO 静态扫描只能得到候选值；真正可用的完整密钥必须以解密器成功时
    # 选中的 selected_post/selected_xor 为准，因此这里不再提前写入密钥池。
    return None


def _iapt_vfp_attach_pool_features(apk_path: Path, options: dict, pool_ref: str):
    from .dynamic_key_pool import resolve_ref, attach_features
    selected = resolve_ref(pool_ref)
    if not selected:
        return None
    features, _row, version = _iapt_vfp_validated_features(apk_path, options)
    return attach_features(
        int(selected.get("id") or 0), features,
        source_type="pool_match",
        normalizer_version=version,
    )

# IAPT_DYNAMIC_KEY_FEATURE_SCHEMES_END

# IAPT_TASK_DEX_ENUM_FB_RANGE_FIX_BEGIN
def _iapt_task_truthy(v):
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_task_clean_find(v):
    import re as _re
    out, seen = [], set()
    for part in _re.split(r"[,;\n\r]+", str(v or "")):
        name = part.strip().strip("\"'")
        low = name.lower().replace("\\", "/").lstrip("/")
        if not name or low in ("mian", "main", "mian.iyu", "main.iyu"):
            continue
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def build_cmd(apk_path: Path, out_dir: Path, options: dict):
    options = dict(options or {})
    if "_iapt_v55_is_v6" in globals() and _iapt_v55_is_v6(options):
        return _iapt_v55_build_cmd_v6(apk_path, out_dir, options)

    if "_iapt_v131_get_task" in globals() and "_iapt_v131_eval" in globals():
        task = _iapt_v131_get_task(out_dir=out_dir)
        ev = _iapt_v131_eval(task, options)
        dynamic_allowed = bool(ev.get("fetch_allowed") or ev.get("manual_key"))
        log_tag = "IAPT_TASK_FIX_V131"
        log_args = (
            ev.get("uid"), ev.get("task_feature_id"), ev.get("opt_feature_id"),
            sorted(ev.get("sub_ids") or []), sorted(ev.get("server_features") or []),
            ev.get("entitlement"), ev.get("request_fetch"), ev.get("manual_key"),
            ev.get("fetch_allowed"),
        )
    else:
        task = _iapt_v130_get_task(out_dir=out_dir) if "_iapt_v130_get_task" in globals() else {}
        ev = _iapt_v130_eval(task, options) if "_iapt_v130_eval" in globals() else {}
        dynamic_allowed = bool(ev.get("dynamic_allowed"))
        log_tag = "IAPT_TASK_FIX_V130"
        log_args = (
            ev.get("uid"), ev.get("task_feature_id"), ev.get("opt_feature_id"),
            sorted(ev.get("sub_ids") or []), sorted(ev.get("server_features") or []),
            ev.get("entitlement"), ev.get("request_dynamic"), False,
            ev.get("dynamic_allowed"),
        )

    cmd = [_iapt_runner_python(), str(SCRIPT), "--apk", str(apk_path), "--outdir", str(out_dir)]

    def add_value(api_name, flag):
        v = options.get(api_name)
        if v is not None and str(v).strip() != "":
            cmd.extend([flag, str(v).strip()])

    sokey_enum_requested = _iapt_task_truthy(options.get("sokey_enum"))
    dexkey_enum_requested = _iapt_task_truthy(options.get("dexkey_enum"))
    pool_mode = str(options.get("server_key_pool_mode") or "").strip().lower()
    pool_ref = str(options.get("server_key_pool_ref") or "").strip()
    pool_requested = pool_mode in ("enum", "selected")
    # Function 4 (server extraction) and function 15 (pool selection) are kept
    # separate.  For automatic server extraction, record the scheme immediately
    # from the single uploaded SO plus all client-computed ABI fingerprints.
    if dynamic_allowed and not pool_requested and not _iapt_task_truthy(options.get("custom_dynamic_key")):
        # 预提取只用于尽早学习方案，绝不能阻断真正解密。某些 ARM/新编译器
        # SO 的独立提取器可能暂时识别不了，但完整解密器仍能从实际外层验证中
        # 取得正确 key；成功钩子会再按最终选中值入池。
        try:
            _iapt_vfp_record_server_extract(apk_path, out_dir, task, options)
        except Exception as exc:
            print("[IAPT_DYNAMIC_SCHEME] pre-extract skipped; continue decrypt: %s: %s" % (type(exc).__name__, exc))
    manual_key_requested = _iapt_task_truthy(options.get("custom_dynamic_key")) or bool(
        str(options.get("post_key") or "").strip() or str(options.get("key_xor") or "").strip()
    )
    manual_key_pair = bool(str(options.get("post_key") or "").strip() and str(options.get("key_xor") or "").strip())
    if manual_key_requested and not manual_key_pair:
        raise RuntimeError("自定义动态Key必须同时填写 post_key 和 key_xor")
    # V193：功能14/999授权后，池枚举可与 SO/DexKey 枚举并行。
    # 授权已经在 API 创建任务阶段按数据库真实订阅完成；worker 只执行
    # 已持久化的候选轴，不再二次制造互斥。
    joint_pool_enum_requested = pool_mode == "enum" and (sokey_enum_requested or dexkey_enum_requested)
    if pool_requested:
        from .dynamic_key_pool import list_decrypted, resolve_ref, write_pool_file
        if pool_mode == "selected":
            selected = resolve_ref(pool_ref)
            if not selected:
                raise RuntimeError("选择的服务器动态Key不存在或已停用")
            pool_entries = [selected]
        else:
            pool_entries = list_decrypted()
            if not pool_entries:
                raise RuntimeError("服务器动态Key池为空")
        pool_path = out_dir / ".tmp" / "server_dynamic_key_pool.json"
        write_pool_file(pool_path, pool_entries)
        cmd.extend(["--key-pool-file", str(pool_path), "--redact-selected-keys"])
        options["_server_key_pool_count"] = len(pool_entries)

    # 自动提取结果在真正解密成功前不写入可用密钥池。成功钩子会从日志读取
    # 实际通过验证的 key 再以 verified=True 保存，避免把“第一个静态候选”误当正确 key。

    add_value("user_password", "--user-password")
    # The client must explicitly decide signature handling.  Missing/invalid
    # values are skip; never fall back to the decrypter's auto mode.
    signature_mode = str(options.get("signature_mode") or "skip").strip().lower()
    if signature_mode not in ("skip", "verify"):
        signature_mode = "skip"
    cmd.extend(["--signature-mode", signature_mode])
    add_value("signature_bytes_hex", "--signature-bytes-hex")
    # 严格枚举：开启对应枚举后，服务端不把客户端已知值传给解密器。
    if not dexkey_enum_requested:
        add_value("fb", "--fb")
    if not sokey_enum_requested:
        add_value("hidden", "--hidden")

    if dynamic_allowed and not pool_requested:
        add_value("post_key", "--post-key")
        add_value("key_xor", "--key-xor")

    add_value("fast_c", "--fast-c")

    # 普通解密并发只由服务端控制，旧客户端传来的 threads 被忽略。
    # --threads 是所有历史解密器都支持的稳定参数；--normal-workers 仅作为
    # 新解密器的兼容别名。这里不再重复传入别名，避免旧脚本因未知参数退出。
    normal_workers = max(1, min(32, int(IAPT_NORMAL_WORKERS or 32)))
    cmd.extend(["--threads", str(normal_workers)])

    find_targets = _iapt_task_clean_find(options.get("find"))
    if find_targets:
        cmd.extend(["--find", ",".join(find_targets)])
        if _iapt_task_truthy(options.get("find_recursive")):
            cmd.append("--find-recursive")
    elif _iapt_task_truthy(options.get("find_recursive")):
        cmd.append("--find-recursive")

    try:
        max_out = int(str(options.get("max_output_files") or "0").strip())
    except Exception:
        max_out = 0
    if max_out > 1:
        cmd.extend(["--max-output-files", str(max_out)])

    if _iapt_task_truthy(options.get("dex_enum")):
        cmd.append("--dex-enum")
        cmd.extend(["--dex-enum-start", str(int(options.get("dex_enum_start") or 1000000))])
        cmd.extend(["--dex-enum-limit", str(int(options.get("dex_enum_limit") or 20000))])
        cmd.extend(["--dex-enum-windows", str(int(options.get("dex_enum_windows") or 1))])

    if sokey_enum_requested:
        cmd.append("--sokey-enum")
        cmd.extend(["--sokey-enum-seconds", str(int(options.get("sokey_enum_seconds") or 180))])
        cmd.extend(["--sokey-enum-files", str(int(options.get("sokey_enum_files") or 1))])
        cmd.extend(["--sokey-max-candidates", str(int(options.get("sokey_max_candidates") or 0))])
        cmd.append("--sokey-c-batch")

    if dexkey_enum_requested:
        cmd.append("--dexkey-enum")
        cmd.extend(["--dexkey-enum-start", str(int(options.get("dexkey_enum_start") or 1736417))])
        cmd.extend(["--dexkey-enum-stop", str(int(options.get("dexkey_enum_stop") or 5936417))])
        cmd.append("--dexkey-c-batch")
        # Standalone dexkey enum remains strict.  Joint enum may use the DEX
        # constant as a verified priority probe, then falls back to exhaustive
        # two-dimensional enumeration when the hint is absent or wrong.
        if not sokey_enum_requested:
            cmd.append("--no-dexkey-dex-hint")

    if sokey_enum_requested or dexkey_enum_requested or _iapt_task_truthy(options.get("dex_enum")):
        # 仅允许服务端控制枚举并发；忽略旧客户端 options.enum_workers。
        # 解密器当前最多支持 32 个并发进程，因此这里上限固定为 32。
        workers = max(1, min(32, int(IAPT_ENUM_WORKERS or 32)))
        cmd.extend(["--enum-workers", str(workers)])

    if sokey_enum_requested or dexkey_enum_requested:
        cmd.extend(["--dexkey-mian-prefix-kb", str(int(options.get("dexkey_mian_prefix_kb") or 64))])
        cmd.extend(["--dexkey-max-so-keysets", str(int(options.get("dexkey_max_so_keysets") or 16))])
        if _iapt_task_truthy(options.get("enum_quiet", True)):
            cmd.append("--enum-quiet")
        if _iapt_task_truthy(options.get("no_python_fallback", True)):
            cmd.append("--no-python-fallback")
        if sokey_enum_requested and dexkey_enum_requested:
            cmd.extend(["--joint-dex-chunk-size", str(int(options.get("joint_dex_chunk_size") or 512))])
            lanes = int(options.get("joint_hidden_lanes") or 0)
            if lanes > 0:
                cmd.extend(["--joint-hidden-lanes", str(lanes)])
            cmd.append("--joint-dex-hint-first" if IAPT_JOINT_DEX_HINT_FIRST else "--no-joint-dex-hint-first")
            cmd.extend(["--joint-fast-hidden-limit", str(int(IAPT_JOINT_FAST_HIDDEN_LIMIT or 0))])
            cmd.extend(["--joint-fast-hidden-batch-size", str(int(IAPT_JOINT_FAST_HIDDEN_BATCH_SIZE or 8))])
            cmd.append("--joint-no-hint-hidden-major" if IAPT_JOINT_NO_HINT_HIDDEN_MAJOR else "--no-joint-no-hint-hidden-major")
            cmd.extend(["--joint-no-hint-min-hidden", str(int(IAPT_JOINT_NO_HINT_MIN_HIDDEN or 16))])

    add_value("member_marker_mode", "--member-marker-mode")
    add_value("member_name_scan", "--member-name-scan")
    add_value("member_batch_size", "--member-batch-size")

    cmd.extend(["--mode", "auto", "--restore-fn-names", "auto"])
    if sokey_enum_requested or dexkey_enum_requested:
        # SO Key 枚举本身只依赖 bsh/util/lib 的 mtime 候选，不要求
        # libygsiyu.so。池枚举并行时，外层 post/xor 只由服务器池提供；
        # 没有样本 SO 时也显式关闭本地动态 Key 提取，避免错误报缺 SO。
        sample_has_ygsiyu = False
        try:
            if zipfile.is_zipfile(apk_path):
                with zipfile.ZipFile(apk_path, 'r') as _v193_zf:
                    sample_has_ygsiyu = any(
                        (not _v193_i.is_dir()) and
                        _v193_i.filename.replace('\\', '/').rsplit('/', 1)[-1].lower() == 'libygsiyu.so'
                        for _v193_i in _v193_zf.infolist()
                    )
            else:
                sample_has_ygsiyu = Path(apk_path).read_bytes()[:4] == b'\x7fELF'
        except Exception:
            sample_has_ygsiyu = False
        if pool_requested or not sample_has_ygsiyu:
            cmd.extend(["--outer-mode", "auto", "--no-dynamic-key", "--no-key-cache"])
        else:
            cmd.extend(["--outer-mode", "auto", "--no-key-cache"])
    elif pool_requested:
        # Key池只使用服务器保存的常量，不重新从样本SO提取Key。outer公式仍使用auto，
        # 因此隐藏SO的APK也可用池中Key尝试通用/静态公式。
        cmd.extend(["--outer-mode", "auto", "--no-dynamic-key", "--no-key-cache"])
    elif manual_key_requested:
        # 自定义动态 Key 是严格校验模式：只允许用户输入的这一对常量，
        # 禁止服务器池、通用常量、SO 自动提取以及本地/共享缓存回退。
        cmd.extend(["--outer-mode", "auto", "--strict-manual-key", "--no-dynamic-key", "--no-key-cache"])
    elif dynamic_allowed:
        cmd.extend(["--outer-mode", "auto"])
    else:
        # 默认动态 Key 只固定 post/xor 常量，并不保证使用旧 fixed outer 公式。
        # 允许 outer-mode auto 解析不同版本的 outer 派生表达式，但保留
        # --no-dynamic-key，确保不会从 SO 提取自定义 post/xor，也不需要功能4。
        cmd.extend(["--outer-mode", "auto", "--no-dynamic-key", "--no-key-cache"])

    # IAPT_SIGNATURE_SOKEY_V285_CALL_BEGIN
    _iapt_v285_finalize_command(
        cmd,
        apk_path,
        options,
        locals().get("task") or {},
        locals().get("sokey_enum_requested", False),
    )
    # IAPT_SIGNATURE_SOKEY_V285_CALL_END
    print("[%s] build uid=%s task_feature_id=%s opt_feature_id=%s sub_ids=%s server_features=%s entitlement=%s request=%s manual_key=%s allowed=%s max_output_files=%s find=%s dex_enum=%s sokey_enum=%s dexkey_enum=%s" % (
        log_tag, log_args[0], log_args[1], log_args[2], log_args[3], log_args[4],
        log_args[5], log_args[6], log_args[7], log_args[8], max_out, find_targets,
        _iapt_task_truthy(options.get("dex_enum")), sokey_enum_requested, dexkey_enum_requested,
    ))
    print("[%s] cmd=%s" % (log_tag, " ".join(map(str, cmd))))
    return cmd
# IAPT_TASK_DEX_ENUM_FB_RANGE_FIX_END


# IAPT_SOURCE_RESTORE_RUNNER_V1_BEGIN
_IAPT_SOURCE_RESTORE_PREV_RUN_TASK = run_task


def _iapt_source_restore_truthy(v) -> bool:
    if v is True or v == 1:
        return True
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_source_restore_opt(options: dict, key: str, default: bool = True) -> bool:
    if not isinstance(options, dict) or key not in options:
        return bool(default)
    return _iapt_source_restore_truthy(options.get(key))


def _iapt_source_restore_is_task(task: dict, options: dict) -> bool:
    try:
        if int(task.get("feature_id") or options.get("feature_id") or 0) == 8:
            return True
    except Exception:
        pass
    ver = str(options.get("decrypt_version") or options.get("task_version") or "").strip().lower()
    return ver in ("restore", "source_restore") or _iapt_source_restore_truthy(options.get("source_restore"))


def _iapt_clear_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for p in list(path.iterdir()):
        if p.is_dir():
            shutil.rmtree(p, ignore_errors=True)
        else:
            try:
                p.unlink()
            except Exception:
                pass


def _iapt_run_source_restore_task(task_id: int, task: dict, options: dict) -> None:
    apk_path = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
    out_dir = APP_STORAGE / "tasks" / task["task_no"]
    log_path = APP_STORAGE / "tasks" / f"{task['task_no']}.log"
    tmp_root = APP_STORAGE / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="source_restore_", dir=str(tmp_root)))
    tmp_zip = work_dir / "restored.zip"
    out_dir.mkdir(parents=True, exist_ok=True)
    db.exec("UPDATE tasks SET status='running', out_dir=%s, log_path=%s, feature_id=8, decrypt_version='restore' WHERE id=%s", (str(out_dir), str(log_path), task_id))
    t0 = time.perf_counter()
    try:
        if not apk_path.exists() or apk_path.stat().st_size <= 0:
            raise RuntimeError("源码 ZIP 不存在或为空")

        # Canonicalize the uploaded project separately so resource merging uses
        # the same trusted src/** and res/** interpretation as every other
        # source task.  Do not scan arbitrary members from the raw archive.
        uploaded_layout_dir = work_dir / "uploaded_layout"
        uploaded_layout_report = _iapt_extract_zip_to_dir(apk_path, uploaded_layout_dir)

        from .tools.iapp_deobfuscate import deobfuscate
        deobfuscate(
            apk_path,
            tmp_zip,
            workdir=work_dir,
            restore_props=_iapt_source_restore_opt(options, "restore_props", True),
            restore_events=_iapt_source_restore_opt(options, "restore_events", True),
            rename_vars=_iapt_source_restore_opt(options, "rename_vars", True),
            rename_files=_iapt_source_restore_opt(options, "rename_files", True),
            rename_functions=_iapt_source_restore_opt(options, "rename_functions", True),
            restore_resource_names=_iapt_source_restore_opt(options, "restore_resource_names", True),
        )
        if not tmp_zip.exists() or tmp_zip.stat().st_size <= 0:
            raise RuntimeError("混淆还原未生成输出 ZIP")
        output_layout = _iapt_extract_zip_to_dir(tmp_zip, out_dir)

        # IAPT_SOURCE_RESTORE_RES_MERGE_V153:
        # The client source-restore archive contains src/** and, when resource
        # name restoration is enabled, res/**.  Some deobfuscator builds only
        # write src/** to their result ZIP.  Preserve a generated res/** tree
        # when present; otherwise merge the uploaded res/** tree without
        # overwriting any file produced by the deobfuscator.
        restore_resource_names = _iapt_source_restore_opt(
            options,
            "restore_resource_names",
            True,
        )
        uploaded_res_files = 0
        merged_res_files = 0
        generated_res_files = 0

        try:
            generated_res_files = sum(
                1 for item in (out_dir / "res").rglob("*")
                if item.is_file()
            ) if (out_dir / "res").is_dir() else 0
        except Exception:
            generated_res_files = 0

        if restore_resource_names:
            try:
                uploaded_res_root = uploaded_layout_dir / "res"
                if uploaded_res_root.is_dir():
                    for source in sorted(uploaded_res_root.rglob("*")):
                        if not source.is_file() or source.is_symlink():
                            continue
                        relative = source.relative_to(uploaded_res_root)
                        if any(part in ("", ".", "..") or part.startswith(".") for part in relative.parts):
                            continue
                        uploaded_res_files += 1
                        destination = out_dir / "res" / relative
                        if destination.is_file():
                            continue
                        destination.parent.mkdir(parents=True, exist_ok=True)
                        shutil.copy2(source, destination)
                        merged_res_files += 1
            except Exception as merge_error:
                raise RuntimeError(
                    "资源名还原结果合并 res/** 失败："
                    + str(merge_error)
                )

        final_res_files = 0
        try:
            final_res_files = sum(
                1 for item in (out_dir / "res").rglob("*")
                if item.is_file()
            ) if (out_dir / "res").is_dir() else 0
        except Exception:
            final_res_files = 0

        if (
            restore_resource_names
            and uploaded_res_files > 0
            and final_res_files <= 0
        ):
            raise RuntimeError(
                "客户端上传包包含 res/**，但服务端最终没有生成或合并 res/**"
            )

        count, total = scan_files(task_id, out_dir)
        total_ms = (time.perf_counter() - t0) * 1000.0
        if count <= 0:
            raise RuntimeError("混淆还原没有输出文件")
        log = (
            "### IAPT source restore\n"
            f"input={apk_path}\n"
            f"out_dir={out_dir}\n"
            f"uploaded_layout={json.dumps(uploaded_layout_report, ensure_ascii=False, sort_keys=True)}\n"
            f"output_layout={json.dumps(output_layout, ensure_ascii=False, sort_keys=True)}\n"
            f"files={count}\n"
            f"bytes={total}\n"
            f"restore_resource_names={int(bool(restore_resource_names))}\n"
            f"uploaded_res_files={uploaded_res_files}\n"
            f"generated_res_files={generated_res_files}\n"
            f"merged_res_files={merged_res_files}\n"
            f"final_res_files={final_res_files}\n"
            f"total_ms={total_ms:.2f}\n"
        )
        log_path.write_text(log, encoding="utf-8", errors="replace")
        db.exec("""
            UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
            version_name=%s, version_code=%s, feature_id=8, decrypt_version='restore'
            WHERE id=%s
        """, (float(total_ms), "混淆还原", "", "restore", "", task_id))
        settle_decrypt_quota_once(task_id)
    except Exception as e:
        reason = "混淆还原失败：" + str(e)
        try:
            log_path.write_text(reason, encoding="utf-8", errors="replace")
        except Exception:
            pass
        db.exec("UPDATE tasks SET status='failed', error_text=%s, feature_id=8, decrypt_version='restore' WHERE id=%s", (reason, task_id))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return
    try:
        options = json.loads(task.get("options_json") or "{}")
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_source_restore_is_task(task, options):
        return _iapt_run_source_restore_task(int(task_id), task, options)
    return _IAPT_SOURCE_RESTORE_PREV_RUN_TASK(int(task_id))
# IAPT_SOURCE_RESTORE_RUNNER_V1_END


# IAPT_SOURCE_RESTORE_V3_AND_NUMERIC_TASK_V2_BEGIN
_IAPT_RESTORE_V2_PREV_RUN_TASK = run_task


def _iapt_zip_dir(src_dir: Path, out_zip: Path) -> None:
    import zipfile as _zipfile
    out_zip.parent.mkdir(parents=True, exist_ok=True)
    with _zipfile.ZipFile(out_zip, "w", compression=_zipfile.ZIP_DEFLATED) as z:
        for p in sorted(src_dir.rglob("*")):
            if not p.is_file():
                continue
            try:
                rel = p.relative_to(src_dir).as_posix()
            except Exception:
                continue
            if not rel or rel.startswith(".tmp/") or "/.tmp/" in rel:
                continue
            z.write(p, rel)


def _iapt_extract_zip_to_dir(src_zip: Path, out_dir: Path) -> dict:
    # V173: source-oriented tasks are normalized at execution time, not later
    # by the download endpoint.  This accepts canonical src/res, one project
    # wrapper, and the two legacy source-only layouts, while rejecting path
    # traversal, symlinks, duplicate members and ambiguous multi-project ZIPs.
    from .source_layout import extract_source_project_zip
    return extract_source_project_zip(src_zip, out_dir)


def _iapt_apply_source_deobfuscation_to_outdir(task_id: int, task: dict, options: dict) -> None:
    out_dir_raw = task.get("out_dir")
    if not out_dir_raw:
        return
    out_dir = Path(out_dir_raw)
    if not out_dir.exists() or not out_dir.is_dir():
        return
    tmp_root = APP_STORAGE / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="v3_source_deobf_", dir=str(tmp_root)))
    src_zip = work_dir / "source.zip"
    restored_zip = work_dir / "restored.zip"
    try:
        _iapt_zip_dir(out_dir, src_zip)
        if not src_zip.exists() or src_zip.stat().st_size <= 0:
            return
        from .tools.iapp_deobfuscate import deobfuscate
        deobfuscate(
            src_zip,
            restored_zip,
            workdir=work_dir,
            restore_props=True,
            restore_events=True,
            rename_vars=True,
            rename_files=True,
            rename_functions=True,
            restore_resource_names=True,
        )
        _iapt_extract_zip_to_dir(restored_zip, out_dir)
        count, total = scan_files(task_id, out_dir)
        try:
            log_path = task.get("log_path")
            if log_path:
                with open(log_path, "a", encoding="utf-8", errors="replace") as f:
                    f.write(f"\n[IAPT source-deobf] applied to V3 output files={count} bytes={total}\n")
        except Exception:
            pass
    except Exception as e:
        try:
            log_path = task.get("log_path")
            if log_path:
                with open(log_path, "a", encoding="utf-8", errors="replace") as f:
                    f.write("\n[IAPT source-deobf] failed: " + str(e) + "\n")
        except Exception:
            pass
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def _iapt_is_numeric_source_restore_task(task: dict, options: dict) -> bool:
    options = options if isinstance(options, dict) else {}
    task = task if isinstance(task, dict) else {}
    ver = str(options.get("decrypt_version") or task.get("decrypt_version") or options.get("task_version") or "").strip().lower()
    # V3 动态修复不是“上传源码 ZIP + 单独 DEX”的 fn_restore 任务。
    # 它必须继续走普通 V3 解密，解密完成后由 iapp_auto_decrypt 从 APK DEX
    # 提取数字函数映射并直接替换已解密成员。
    if ver in ("v3", "3", "iapp_v3") and _iapt_source_restore_truthy(options.get("v3_dynamic_restore")):
        return False
    return ver in ("fn_restore", "numeric_restore") or _iapt_source_restore_truthy(options.get("numeric_source_restore"))


def _iapt_run_numeric_source_restore_task(task_id: int, task: dict, options: dict) -> None:
    src_zip = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
    dex_path = APP_STORAGE / "uploads" / f"{task['task_no']}.dex"
    out_dir = APP_STORAGE / "tasks" / task["task_no"]
    log_path = APP_STORAGE / "tasks" / f"{task['task_no']}.log"
    tmp_root = APP_STORAGE / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="numeric_restore_", dir=str(tmp_root)))
    db.exec("UPDATE tasks SET status='running', out_dir=%s, log_path=%s, feature_id=5, decrypt_version='fn_restore' WHERE id=%s", (str(out_dir), str(log_path), task_id))
    t0 = time.perf_counter()
    try:
        if not src_zip.exists() or src_zip.stat().st_size <= 0:
            raise RuntimeError("源码 ZIP 不存在或为空")
        if not dex_path.exists() or dex_path.stat().st_size <= 0:
            raise RuntimeError("DEX 文件不存在或为空")
        layout_report = _iapt_extract_zip_to_dir(src_zip, out_dir)
        attachment = dex_path
        attachment_data = attachment.read_bytes()
        primary_dex = attachment_data if attachment_data.startswith(b"dex\n") else None
        if primary_dex is None and zipfile.is_zipfile(attachment):
            with zipfile.ZipFile(attachment, "r") as _iapec_zip:
                _dex_names = sorted(
                    [n for n in _iapec_zip.namelist() if re.fullmatch(r"(?:.*/)?classes\d*\.dex", n.replace('\\','/'), flags=re.I)],
                    key=lambda n: (0 if Path(n).name.lower()=="classes.dex" else 1, n.lower()),
                )
                if _dex_names:
                    primary_dex = _iapec_zip.read(_dex_names[0])
        if not primary_dex or not primary_dex.startswith(b"dex\n"):
            raise RuntimeError("上传的 DEX/APK/ZIP/JAR 中没有有效 classes*.dex")
        from .tools.iapp_auto_decrypt import maybe_restore_numeric_function_names
        stats = maybe_restore_numeric_function_names(
            attachment,
            out_dir,
            mode="on",
            backup=False,
            member_sources=None,
            primary_dex=primary_dex,
            threads=int(options.get("threads") or 4),
            dex_enum=False,
        )
        count, total = scan_files(task_id, out_dir)
        total_ms = (time.perf_counter() - t0) * 1000.0
        log_path.write_text(
            "### IAPT numeric source restore\n"
            f"src={src_zip}\n"
            f"dex_optional={dex_path if dex_path.exists() else ''}\n"
            f"source_tree_dex_scan=on\n"
            f"out_dir={out_dir}\n"
            f"layout={json.dumps(layout_report, ensure_ascii=False, sort_keys=True)}\n"
            f"stats={json.dumps(stats, ensure_ascii=False, sort_keys=True)}\n"
            f"files={count}\nbytes={total}\ntotal_ms={total_ms:.2f}\n",
            encoding="utf-8",
            errors="replace",
        )
        db.exec("""
            UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
            version_name=%s, version_code=%s, feature_id=5, decrypt_version='fn_restore'
            WHERE id=%s
        """, (float(total_ms), "动态修复", "", "fn_restore", "", task_id))
        settle_decrypt_quota_once(task_id)
    except Exception as e:
        reason = "动态修复失败：" + str(e)
        try:
            log_path.write_text(reason, encoding="utf-8", errors="replace")
        except Exception:
            pass
        db.exec("UPDATE tasks SET status='failed', error_text=%s, feature_id=5, decrypt_version='fn_restore' WHERE id=%s", (reason, task_id))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return
    try:
        options = json.loads(task.get("options_json") or "{}")
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_is_numeric_source_restore_task(task, options):
        return _iapt_run_numeric_source_restore_task(int(task_id), task, options)
    result = _IAPT_RESTORE_V2_PREV_RUN_TASK(int(task_id))
    try:
        fresh = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
        if fresh and str(fresh.get("status") or "") == "done":
            fid = int(fresh.get("feature_id") or 1)
            ver = str(fresh.get("decrypt_version") or "").strip().lower()
            if fid not in (6, 8) and ver not in ("restore", "fn_restore", "numeric_restore"):
                _iapt_apply_source_deobfuscation_to_outdir(int(task_id), fresh, options)
    except Exception as e:
        logger.warning("V3 source deobfuscation postprocess failed: %s", e)
    return result
# IAPT_SOURCE_RESTORE_V3_AND_NUMERIC_TASK_V2_END

# IAPT_STATIC_DEX_SOURCE_RESTORE_RUNNER_V1_BEGIN
_IAPT_STATIC_DEX_RESTORE_PREV_RUN_TASK = run_task


def _iapt_is_static_dex_source_restore_task(task: dict, options: dict) -> bool:
    try:
        options = options if isinstance(options, dict) else {}
        task = task if isinstance(task, dict) else {}
        ver = str(options.get("decrypt_version") or task.get("decrypt_version") or "").strip().lower()
        # 兼容已经提交的旧客户端任务：旧版错误地在 V3 动态修复时写入
        # dex_static_restore=true。只要它仍明确是 V3 动态修复，就不能被功能8
        # 的静态 DEX 源码还原分流截走。
        inline_v3_dynamic = (
            ver in ("v3", "3", "iapp_v3", "")
            and (
                _iapt_source_restore_truthy(options.get("v3_dynamic_restore"))
                or _iapt_source_restore_truthy(options.get("numeric_restore"))
                or _iapt_source_restore_truthy(options.get("dynamic_restore"))
                or str(options.get("restore_fn_names") or "").strip().lower() in ("auto", "on", "true", "1")
            )
            and not _iapt_source_restore_truthy(options.get("source_restore"))
        )
        if inline_v3_dynamic:
            return False
        if ver in ("dex_restore", "static_dex_restore", "source_dex_restore"):
            return True
        if _iapt_source_restore_truthy(options.get("dex_static_restore")):
            return True
    except Exception:
        pass
    return False


def _iapt_run_static_dex_source_restore_task(task_id: int, task: dict, options: dict) -> None:
    src_zip = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
    dex_path = APP_STORAGE / "uploads" / f"{task['task_no']}.dex"
    out_dir = APP_STORAGE / "tasks" / task["task_no"]
    log_path = APP_STORAGE / "tasks" / f"{task['task_no']}.log"
    tmp_root = APP_STORAGE / "tmp"
    tmp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix="static_dex_restore_", dir=str(tmp_root)))
    tmp_zip = work_dir / "static_dex_restored.zip"
    out_dir.mkdir(parents=True, exist_ok=True)
    db.exec("UPDATE tasks SET status='running', out_dir=%s, log_path=%s, feature_id=8, decrypt_version='dex_restore' WHERE id=%s", (str(out_dir), str(log_path), task_id))
    t0 = time.perf_counter()
    try:
        if not src_zip.exists() or src_zip.stat().st_size <= 0:
            raise RuntimeError("源码 ZIP 不存在或为空")
        dex_inputs = []
        if dex_path.exists() and dex_path.stat().st_size > 0:
            # Optional explicit DEX/APK/ZIP/JAR bundle.  The source zip may also
            # contain apk/lib/*, so a separate dex upload is no longer required.
            try:
                head = dex_path.read_bytes()[:8]
                if head.startswith(b"dex\n") or zipfile.is_zipfile(dex_path):
                    dex_inputs.append(dex_path)
                else:
                    raise RuntimeError("上传的 DEX 附加文件不是 dex/apk/zip/jar")
            except Exception as _e:
                if isinstance(_e, RuntimeError):
                    raise
                raise RuntimeError("读取 DEX 附加文件失败：" + str(_e))
        from .tools.iapp_deobfuscate import deobfuscate
        deobfuscate(
            src_zip,
            tmp_zip,
            workdir=work_dir,
            restore_props=_iapt_source_restore_opt(options, "restore_props", True),
            restore_events=_iapt_source_restore_opt(options, "restore_events", True),
            rename_vars=_iapt_source_restore_opt(options, "rename_vars", True),
            rename_files=_iapt_source_restore_opt(options, "rename_files", True),
            rename_functions=_iapt_source_restore_opt(options, "rename_functions", True),
            restore_resource_names=_iapt_source_restore_opt(options, "restore_resource_names", True),
            dex_restore=True,
            dex_paths=dex_inputs,
            flat_v3=_iapt_source_restore_opt(options, "flat_v3", True),
            dex_only=_iapt_source_restore_opt(options, "dex_only", False),
        )
        if not tmp_zip.exists() or tmp_zip.stat().st_size <= 0:
            raise RuntimeError("DEX 还原未生成输出 ZIP")
        layout_report = _iapt_extract_zip_to_dir(tmp_zip, out_dir)
        count, total = scan_files(task_id, out_dir)
        total_ms = (time.perf_counter() - t0) * 1000.0
        log = (
            "### IAPT static DEX source restore\n"
            f"src={src_zip}\n"
            f"dex_optional={dex_path if dex_path.exists() else ''}\n"
            f"source_tree_dex_scan=on\n"
            f"out_dir={out_dir}\n"
            f"layout={json.dumps(layout_report, ensure_ascii=False, sort_keys=True)}\n"
            f"files={count}\nbytes={total}\ntotal_ms={total_ms:.2f}\n"
            f"options={json.dumps(options, ensure_ascii=False, sort_keys=True)}\n"
        )
        log_path.write_text(log, encoding="utf-8", errors="replace")
        db.exec("""
            UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
            version_name=%s, version_code=%s, feature_id=8, decrypt_version='dex_restore'
            WHERE id=%s
        """, (float(total_ms), "DEX还原", "", "dex_restore", "", task_id))
        settle_decrypt_quota_once(task_id)
    except Exception as e:
        reason = "DEX还原失败：" + str(e)
        try:
            log_path.write_text(reason, encoding="utf-8", errors="replace")
        except Exception:
            pass
        db.exec("UPDATE tasks SET status='failed', error_text=%s, feature_id=8, decrypt_version='dex_restore' WHERE id=%s", (reason, task_id))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return
    try:
        options = json.loads(task.get("options_json") or "{}")
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_is_static_dex_source_restore_task(task, options):
        return _iapt_run_static_dex_source_restore_task(int(task_id), task, options)
    return _IAPT_STATIC_DEX_RESTORE_PREV_RUN_TASK(int(task_id))
# IAPT_STATIC_DEX_SOURCE_RESTORE_RUNNER_V1_END

# IAPT_OUTPUT_LAYOUT_V1_BEGIN
# 最终输出规范：
# 1) 删除仅用于调试/重命名映射的 deobfuscation_map.txt；
# 2) 若输出被额外套在“包名目录”中，将该目录内容合并到 ZIP 根目录；
# 3) 重新生成文件索引，使详情页和下载 ZIP 与磁盘内容一致。
_IAPT_OUTPUT_LAYOUT_PREV_RUN_TASK = run_task


def _iapt_output_is_package_dir_name(name: str) -> bool:
    try:
        return bool(re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]*(?:\.[A-Za-z_$][A-Za-z0-9_$]*)+", str(name or "").strip()))
    except Exception:
        return False


def _iapt_output_unique_path(dst: Path) -> Path:
    if not dst.exists():
        return dst
    stem, suffix = dst.stem, dst.suffix
    for i in range(2, 10000):
        candidate = dst.with_name(f"{stem}_{i}{suffix}")
        if not candidate.exists():
            return candidate
    raise RuntimeError("输出文件重名过多：" + str(dst.name))


def _iapt_output_merge_tree(src: Path, dst: Path) -> None:
    dst.mkdir(parents=True, exist_ok=True)
    for child in list(src.iterdir()):
        target = dst / child.name
        if child.is_dir():
            if target.exists() and target.is_file():
                target = _iapt_output_unique_path(target)
                shutil.move(str(child), str(target))
            else:
                _iapt_output_merge_tree(child, target)
                try:
                    child.rmdir()
                except Exception:
                    pass
        else:
            if target.exists():
                try:
                    if target.is_file() and child.read_bytes() == target.read_bytes():
                        child.unlink()
                        continue
                except Exception:
                    pass
                target = _iapt_output_unique_path(target)
            shutil.move(str(child), str(target))


def _iapt_normalize_decrypt_output(task_id: int, task: dict) -> None:
    out_raw = str((task or {}).get("out_dir") or "").strip()
    if not out_raw:
        return
    out_dir = Path(out_raw)
    if not out_dir.is_dir():
        return

    for p in list(out_dir.rglob("deobfuscation_map.txt")):
        try:
            if p.is_file():
                p.unlink()
        except Exception:
            pass

    package_name = str((task or {}).get("package_name") or "").strip()
    candidates = []
    if package_name:
        direct = out_dir / package_name
        if direct.is_dir():
            candidates.append(direct)
    if not candidates:
        visible_dirs = [p for p in out_dir.iterdir() if p.is_dir() and p.name != ".tmp"]
        visible_files = [p for p in out_dir.iterdir() if p.is_file() and p.name != "deobfuscation_map.txt"]
        package_dirs = [p for p in visible_dirs if _iapt_output_is_package_dir_name(p.name)]
        if len(package_dirs) == 1 and (len(visible_dirs) == 1 or not visible_files):
            candidates.append(package_dirs[0])

    if candidates:
        package_dir = candidates[0]
        if package_dir.resolve() != out_dir.resolve():
            _iapt_output_merge_tree(package_dir, out_dir)
            try:
                shutil.rmtree(package_dir, ignore_errors=True)
            except Exception:
                pass

    for p in sorted([x for x in out_dir.rglob("*") if x.is_dir() and x.name != ".tmp"], key=lambda x: len(x.parts), reverse=True):
        try:
            p.rmdir()
        except Exception:
            pass
    scan_files(int(task_id), out_dir)


def run_task(task_id: int):
    result = _IAPT_OUTPUT_LAYOUT_PREV_RUN_TASK(int(task_id))
    try:
        fresh = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
        if fresh and str(fresh.get("status") or "").lower() == "done":
            fid = int(fresh.get("feature_id") or 1)
            ver = str(fresh.get("decrypt_version") or "v3").strip().lower()
            if fid not in (6, 8) and ver not in ("v6", "restore", "source_restore", "dex_restore", "static_dex_restore"):
                _iapt_normalize_decrypt_output(int(task_id), fresh)
    except Exception as e:
        logger.warning("IAPT output layout normalize failed: %s", e)
    return result
# IAPT_OUTPUT_LAYOUT_V1_END



# __IAPT_V7_REUSE_DECRYPTED_SHELL_BEGIN__
# v7: --find and owner metadata reuse the completed task's decrypted outer
# container.  They never rerun outer-key resolution, sokey/dexkey enumeration,
# APK upload charging, or the full decrypt pipeline.
_IAPT_REUSE_LOCKS = {}
_IAPT_REUSE_LOCKS_GUARD = threading.Lock()
_IAPT_REUSE_SESSION_VERSION = 7
_IAPT_PROJECT_META_PARSER_VERSION = 182


def _iapt_reuse_lock(task_id: int):
    key = int(task_id)
    with _IAPT_REUSE_LOCKS_GUARD:
        lock = _IAPT_REUSE_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _IAPT_REUSE_LOCKS[key] = lock
        return lock


def _iapt_read_log_tail(path_value, max_bytes: int = 16 * 1024 * 1024) -> str:
    try:
        p = Path(str(path_value or ''))
        if not p.is_file():
            return ''
        size = p.stat().st_size
        with p.open('rb') as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            return f.read().decode('utf-8', 'replace')
    except Exception:
        return ''


def _iapt_task_options(task: dict) -> dict:
    try:
        obj = json.loads((task or {}).get('options_json') or '{}')
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _iapt_last_match(text: str, patterns, flags=re.I | re.M):
    value = ''
    for pattern in patterns:
        try:
            for m in re.finditer(pattern, text or '', flags=flags):
                value = str(m.group(1)).strip()
        except Exception:
            continue
    return value


def _iapt_resolve_reuse_values(task: dict, out_dir: Path) -> dict:
    from .tools.iapp_auto_decrypt import _trace_from_json, parse_hidden_value, _hidden_from_prefix

    tmp = out_dir / '.tmp'
    session_path = tmp / 'reuse_session_v7.json'
    container_path = tmp / 'container_plain.bin'
    if not container_path.is_file():
        raise RuntimeError('当前任务没有保留已解密外壳 container_plain.bin，无法免解密查找')

    # Fast path: values already verified against mian.iyu.
    try:
        saved = json.loads(session_path.read_text(encoding='utf-8'))
        if int(saved.get('version') or 0) == _IAPT_REUSE_SESSION_VERSION:
            return saved
    except Exception:
        pass

    options = _iapt_task_options(task)
    log_text = _iapt_read_log_tail((task or {}).get('log_path'))
    cache_obj = {}
    cache_path = tmp / 'outer_key_cache.json'
    try:
        cache_obj = json.loads(cache_path.read_text(encoding='utf-8')) if cache_path.is_file() else {}
    except Exception:
        cache_obj = {}

    trace = {}
    try:
        trace = _trace_from_json(cache_obj.get('trace') or {})
    except Exception:
        trace = {}

    post_key = str(options.get('post_key') or '').strip().replace(' ', '')
    key_xor = str(options.get('key_xor') or '').strip().replace(' ', '')
    if not post_key:
        post_key = str(cache_obj.get('post_key') or '').strip()
    if not key_xor:
        key_xor = str(cache_obj.get('key_xor') or '').strip()
    if not post_key:
        post_key = _iapt_last_match(log_text, [r'SLKY_POST_KEY\s*=\s*([0-9a-fA-F]+)'])
    if not key_xor:
        key_xor = _iapt_last_match(log_text, [r'KEY_XOR_CONST\s*=\s*([0-9a-fA-F]+)'])

    hidden_text = str(options.get('hidden') or options.get('sokey') or '').strip()
    hidden_pat = r'([A-Za-z0-9]{10}Q{10}W{10}E{2})'
    if not hidden_text:
        hidden_text = _iapt_last_match(log_text, [
            r'selected\s+hidden\s*=\s*(?:hidden\[\d+\]\s*)?' + hidden_pat,
            r'hidden\[\d+\]\s*=\s*' + hidden_pat,
            r'(?:^|\n)\[\+\]\s+hidden\s*=\s*' + hidden_pat,
        ])
    if not hidden_text:
        all_hidden = re.findall(hidden_pat, log_text or '', flags=re.I)
        hidden_text = all_hidden[-1] if all_hidden else ''

    fb_text = str(options.get('fb') or options.get('dexkey') or options.get('client_dexkey') or '').strip()
    if not re.fullmatch(r'-?\d+', fb_text or ''):
        fb_text = _iapt_last_match(log_text, [
            r'selected\s+f\.b\(\)\s*=\s*(-?\d+)',
            r'(?:^|\n)\[\+\]\s+f\.b\(\)\s*=\s*(-?\d+)',
        ])

    member_ctx = ''
    raw_ctx = trace.get('member_ctx') if isinstance(trace, dict) else None
    if isinstance(raw_ctx, bytes):
        member_ctx = raw_ctx.decode('utf-8', 'replace').strip()
    elif raw_ctx:
        member_ctx = str(raw_ctx).strip()
    if not member_ctx:
        member_ctx = _iapt_last_match(log_text, [r'member\s+ctx\s*=\s*([A-Za-z0-9_-]+)']) or 'post'

    member_key_mode = ''
    raw_mode = trace.get('member_key_mode') if isinstance(trace, dict) else None
    if isinstance(raw_mode, bytes):
        member_key_mode = raw_mode.decode('utf-8', 'replace').strip()
    elif raw_mode:
        member_key_mode = str(raw_mode).strip()
    if not member_key_mode:
        member_key_mode = _iapt_last_match(log_text, [r'member\s+key\s*=\s*([A-Za-z0-9_-]+)']) or 'xor'

    if not re.fullmatch(r'[0-9a-fA-F]+', key_xor or '') or len(key_xor) % 2:
        raise RuntimeError('旧任务缺少 KEY_XOR_CONST，无法从已解密外壳继续查找')
    if member_ctx.lower() != 'nopost' and (not re.fullmatch(r'[0-9a-fA-F]+', post_key or '') or len(post_key) % 2):
        raise RuntimeError('旧任务缺少 SLKY_POST_KEY，无法从已解密外壳继续查找')
    if not hidden_text:
        raise RuntimeError('旧任务日志中没有最终 sokey/hidden，无法从已解密外壳继续查找')
    try:
        if len(hidden_text) == 10:
            hidden = _hidden_from_prefix(hidden_text)
        else:
            hidden = parse_hidden_value(hidden_text)
    except Exception as e:
        raise RuntimeError('旧任务中的 sokey/hidden 格式无效：' + str(e))
    if not re.fullmatch(r'-?\d+', fb_text or ''):
        raise RuntimeError('旧任务日志中没有最终 dexkey/f.b()，无法从已解密外壳继续查找')

    resolved = {
        'version': _IAPT_REUSE_SESSION_VERSION,
        'post_key': post_key.lower(),
        'key_xor': key_xor.lower(),
        'hidden_hex': hidden.hex(),
        'fb': str(int(fb_text)),
        'member_ctx': member_ctx.lower(),
        'member_key_mode': member_key_mode.lower(),
        'container_size': int(container_path.stat().st_size),
    }
    return resolved


def _iapt_load_reuse_context(task_or_id):
    from .tools.iapp_auto_decrypt import (
        SlkyContext, NoPostSlkyContext, try_decrypt_member, looks_like_iapp_plain,
    )
    task = task_or_id if isinstance(task_or_id, dict) else db.one('SELECT * FROM tasks WHERE id=%s', (int(task_or_id),))
    if not task:
        raise RuntimeError('任务不存在')
    if not task.get('out_dir'):
        raise RuntimeError('任务没有输出目录')
    out_dir = Path(task['out_dir'])
    values = _iapt_resolve_reuse_values(task, out_dir)
    container_path = out_dir / '.tmp' / 'container_plain.bin'
    container_plain = container_path.read_bytes()
    hidden = bytes.fromhex(values['hidden_hex'])
    key_xor = bytes.fromhex(values['key_xor'])
    if values.get('member_ctx') == 'nopost':
        ctx = NoPostSlkyContext()
    else:
        ctx = SlkyContext(bytes.fromhex(values['post_key']), use_c=False)
    fb = values['fb']
    mode = values.get('member_key_mode') or 'xor'

    # This only decrypts one member from the already-plain container.  It does
    # not derive an outer key and does not enumerate anything.
    mian = try_decrypt_member(container_plain, ctx, key_xor, 'mian.iyu', hidden, fb, mode)
    if not mian or not looks_like_iapp_plain(mian):
        raise RuntimeError('已解密外壳的复用参数校验失败，未重新枚举')

    try:
        session_path = out_dir / '.tmp' / 'reuse_session_v7.json'
        session_path.write_text(json.dumps(values, ensure_ascii=False, sort_keys=True, indent=2), encoding='utf-8')
    except Exception:
        pass

    apk_path = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
    return {
        'task': task,
        'out_dir': out_dir,
        'apk_path': apk_path if apk_path.is_file() else None,
        'container_plain': container_plain,
        'ctx': ctx,
        'key_xor': key_xor,
        'hidden': hidden,
        'fb': fb,
        'member_key_mode': mode,
    }


def find_from_task_shell(task_id: int, names, recursive: bool = False, max_output_files=None) -> dict:
    from .tools.iapp_auto_decrypt import decrypt_members_recursive, normalize_find_names, safe_out_name

    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise RuntimeError('任务不存在')
    if str(task.get('status') or '') != 'done':
        raise RuntimeError('任务尚未完成，不能复用解密外壳查找')
    targets = normalize_find_names(names if isinstance(names, list) else [names])
    if not targets:
        raise ValueError('请输入文件名')
    if len(targets) > 50:
        raise ValueError('一次最多查找 50 个文件名')

    with _iapt_reuse_lock(int(task_id)):
        env = _iapt_load_reuse_context(task)
        out_dir = env['out_dir']
        before = {f.get('rel_path') for f in list_task_files(task) if f.get('rel_path')}
        try:
            max_new = int(max_output_files) if max_output_files not in (None, '', 0, '0') else 500
        except Exception:
            max_new = 500
        max_new = max(1, min(5000, max_new))
        normal = max(1, int(IAPT_NORMAL_WORKERS or 1))
        found = decrypt_members_recursive(
            env['container_plain'], env['ctx'], env['key_xor'], env['hidden'], env['fb'],
            b'', out_dir, targets, skip_existing=set(),
            threads=max(1, min(8, normal)),
            processes=(max(1, min(4, normal)) if recursive else 1),
            member_key_mode=env['member_key_mode'],
            only_manual=not bool(recursive),
            max_new_members=max_new,
            verbose=False,
            scan_mode='hybrid',
            member_batch_size=8,
            member_marker_mode='auto',
            member_marker_wave_size=96,
            defer_writes=False,
        )
        scan_files(int(task_id), out_dir)
        rows = list_task_files(task)
        by_path = {str(x.get('rel_path') or ''): x for x in rows}

        logical_names = []
        for name in targets + list(found.keys()):
            if name not in logical_names:
                logical_names.append(name)
        items = []
        seen_paths = set()
        for name in logical_names:
            rel = safe_out_name(name)
            row = by_path.get(rel)
            if not row or rel in seen_paths:
                continue
            seen_paths.add(rel)
            item = dict(row)
            item['source_name'] = name
            item['new'] = rel not in before
            items.append(item)
        not_found = [name for name in targets if safe_out_name(name) not in by_path]
        return {
            'ok': True,
            'task_id': int(task_id),
            'status': 'done',
            'reused_decrypted_shell': True,
            'reran_outer_decrypt': False,
            'reran_enumeration': False,
            'recursive': bool(recursive),
            'requested': targets,
            'items': items,
            'found_count': len(items),
            'added_count': sum(1 for x in items if x.get('new')),
            'not_found': not_found,
            'file_count': len(rows),
        }


def extract_project_meta_from_task_shell(task_or_id) -> dict:
    from .tools.iapp_auto_decrypt import decrypt_iapt_project_meta

    task = task_or_id if isinstance(task_or_id, dict) else db.one('SELECT * FROM tasks WHERE id=%s', (int(task_or_id),))
    if not task or not task.get('out_dir'):
        return {}
    out_dir = Path(task['out_dir'])
    cache_path = out_dir / '.tmp' / 'project_meta_v7.json'
    try:
        cached = json.loads(cache_path.read_text(encoding='utf-8'))
        if int(cached.get('_parser_version') or 0) == _IAPT_PROJECT_META_PARSER_VERSION:
            cached.pop('_parser_version', None)
            return cached
    except Exception:
        pass

    with _iapt_reuse_lock(int(task.get('id') or 0)):
        env = _iapt_load_reuse_context(task)
        package = str(task.get('package_name') or '').strip()
        if not package and env.get('apk_path'):
            try:
                package = str(meta_from_apk_path(env['apk_path']).get('package_name') or '').strip()
            except Exception:
                package = ''
        meta = decrypt_iapt_project_meta(
            env['container_plain'], env['ctx'], env['key_xor'], env['hidden'], env['fb'],
            package, env['member_key_mode'], env.get('apk_path'),
        ) or {}
        if meta:
            meta['project_decrypted'] = True
            meta['reused_decrypted_shell'] = True
            try:
                save = dict(meta)
                save['_parser_version'] = _IAPT_PROJECT_META_PARSER_VERSION
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                cache_path.write_text(json.dumps(save, ensure_ascii=False, sort_keys=True, indent=2), encoding='utf-8')
            except Exception:
                pass
        return meta
# __IAPT_V7_REUSE_DECRYPTED_SHELL_END__

# __IAPT_V8_PROJECT_OUTPUT_AND_CANCEL_BEGIN__
# v8 behavior:
# 1) <package>.project is metadata/internal by default and is not exposed by a
#    normal full decrypt.  It is kept when the user explicitly requested it or
#    when an already-decrypted source file references it.  A later /find call
#    writes it normally and is not pruned.
# 2) local decrypt subprocesses run in their own process group and publish a PID
#    file, allowing a queued/running task to be cancelled without restarting API.

import signal as _iapt_v8_signal

_IAPT_V8_PROJECT_PREV_NORMALIZE = _iapt_normalize_decrypt_output
_IAPT_V8_CANCEL_LOCK = threading.RLock()
_IAPT_V8_RUNNING_PROCS = {}
_IAPT_V8_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process
_IAPT_V8_PREV_RUN_TASK = run_task


def _iapt_v8_cancel_marker(task: dict) -> Path:
    task_no = str((task or {}).get('task_no') or '')
    out_raw = str((task or {}).get('out_dir') or '').strip()
    out_dir = Path(out_raw) if out_raw else (APP_STORAGE / 'tasks' / task_no)
    return out_dir / '.tmp' / 'cancel.request'


def _iapt_v8_pid_file(task: dict, out_dir: Path | None = None) -> Path:
    if out_dir is None:
        out_raw = str((task or {}).get('out_dir') or '').strip()
        out_dir = Path(out_raw) if out_raw else (APP_STORAGE / 'tasks' / str((task or {}).get('task_no') or ''))
    return Path(out_dir) / '.tmp' / 'decrypt.pid'


def _iapt_v8_task_options(task: dict) -> dict:
    try:
        obj = json.loads((task or {}).get('options_json') or '{}')
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _iapt_v8_split_find_values(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        out = []
        for item in value:
            out.extend(_iapt_v8_split_find_values(item))
        return out
    return [x.strip().strip('"\'') for x in re.split(r'[,;\n\r]+', str(value)) if x.strip().strip('"\'')]


def _iapt_v8_requested_project(task: dict, project_file: Path, out_dir: Path) -> bool:
    opts = _iapt_v8_task_options(task)
    wanted = _iapt_v8_split_find_values(opts.get('find'))
    if not wanted:
        return False
    try:
        rel = project_file.relative_to(out_dir).as_posix()
    except Exception:
        rel = project_file.name
    aliases = {project_file.name.lower(), rel.lower(), rel.replace('\\', '/').lower()}
    for name in wanted:
        n = str(name or '').replace('\\', '/').lstrip('./').lower()
        if n in aliases or n.endswith('/' + project_file.name.lower()):
            return True
    return False


def _iapt_v8_blob_contains_name(blob: bytes, names: set[str]) -> bool:
    if not blob:
        return False
    for name in names:
        if not name:
            continue
        raw = name.encode('utf-8', 'ignore')
        if raw and raw in blob:
            return True
        try:
            if name.encode('utf-16le') in blob or name.encode('utf-16be') in blob:
                return True
        except Exception:
            pass
    return False


def _iapt_v8_project_referenced(out_dir: Path, project_file: Path) -> bool:
    try:
        rel = project_file.relative_to(out_dir).as_posix()
    except Exception:
        rel = project_file.name
    names = {
        project_file.name,
        rel,
        rel.replace('/', '\\'),
    }
    # The project file itself obviously contains its own name sometimes; skip it.
    text_exts = set(TEXT_EXTS) | {'.java', '.js', '.lua', '.properties', '.cfg', '.ini', '.html', '.htm'}
    checked = 0
    for fp in out_dir.rglob('*'):
        if not fp.is_file() or fp == project_file:
            continue
        try:
            rel_fp = fp.relative_to(out_dir).as_posix()
        except Exception:
            continue
        if rel_fp.startswith('.tmp/') or '/.tmp/' in rel_fp:
            continue
        try:
            size = fp.stat().st_size
        except Exception:
            continue
        # Source files are normally tiny.  Permit small extensionless members too,
        # while avoiding a second full scan of large binary blobs.
        if fp.suffix.lower() not in text_exts and size > 2 * 1024 * 1024:
            continue
        if size > 16 * 1024 * 1024:
            continue
        try:
            blob = fp.read_bytes()
        except Exception:
            continue
        checked += 1
        if _iapt_v8_blob_contains_name(blob, names):
            return True
        if checked >= 20000:
            break
    return False


def _iapt_v8_prune_automatic_project_files(task_id: int, task: dict) -> int:
    out_raw = str((task or {}).get('out_dir') or '').strip()
    if not out_raw:
        return 0
    out_dir = Path(out_raw)
    if not out_dir.is_dir():
        return 0
    removed = 0
    for project_file in list(out_dir.rglob('*.project')):
        try:
            if not project_file.is_file():
                continue
            rel = project_file.relative_to(out_dir).as_posix()
            if rel.startswith('.tmp/') or '/.tmp/' in rel:
                continue
            if _iapt_v8_requested_project(task, project_file, out_dir):
                continue
            if _iapt_v8_project_referenced(out_dir, project_file):
                continue
            project_file.unlink()
            removed += 1
            logger.info('IAPT v8 hide automatic project output task=%s file=%s', task_id, rel)
        except Exception as e:
            logger.warning('IAPT v8 project prune failed: %s', e)
    if removed:
        scan_files(int(task_id), out_dir)
    return removed


def _iapt_normalize_decrypt_output(task_id: int, task: dict) -> None:
    _IAPT_V8_PROJECT_PREV_NORMALIZE(int(task_id), task)
    try:
        fresh = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),)) or task
        _iapt_v8_prune_automatic_project_files(int(task_id), fresh)
    except Exception as e:
        logger.warning('IAPT v8 project visibility normalize failed: %s', e)


def _iapt_v8_proc_cmdline(pid: int) -> str:
    try:
        return Path('/proc') .joinpath(str(int(pid)), 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace')
    except Exception:
        return ''


def _iapt_v8_is_decrypt_pid(pid: int) -> bool:
    cmdline = _iapt_v8_proc_cmdline(pid)
    return ('iapp_auto_decrypt.py' in cmdline) or ('iapp_dex2iyu_v6.py' in cmdline)


def run_decrypt_process(cmd: list, apk_path: Path, out_dir: Path, options: dict, task: dict, env: dict | None = None) -> _IaptProcResult:
    # Preserve the existing remote DEX path.  Local runs use Popen so they can be
    # addressed by PID/process group.  This path is used by the ordinary V3 job.
    if _iapt_truthy((options or {}).get('dex_enum')):
        try:
            remote = _run_remote_dex_process(cmd, apk_path, out_dir, options, task)
            if remote is not None:
                return remote
        except Exception as e:
            logger.warning('远程 DEX 枚举失败，回退本机执行: %s', e)

    task_id = int((task or {}).get('id') or 0)
    marker = _iapt_v8_cancel_marker(task)
    if marker.exists() or str((db.one('SELECT status FROM tasks WHERE id=%s', (task_id,)) or {}).get('status') or '').lower() == 'cancelled':
        return _IaptProcResult(130, '[IAPT_CANCELLED] task cancelled before subprocess start\n')

    out_dir = Path(out_dir)
    pid_file = _iapt_v8_pid_file(task, out_dir)
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env=env,
        start_new_session=True,
    )
    with _IAPT_V8_CANCEL_LOCK:
        _IAPT_V8_RUNNING_PROCS[task_id] = proc
    try:
        pid_file.write_text(str(proc.pid), encoding='ascii')
    except Exception:
        pass
    try:
        stdout, _ = proc.communicate()
        return _IaptProcResult(proc.returncode, stdout or '')
    finally:
        with _IAPT_V8_CANCEL_LOCK:
            _IAPT_V8_RUNNING_PROCS.pop(task_id, None)
        try:
            pid_file.unlink(missing_ok=True)
        except Exception:
            pass


def cancel_task_process(task_id: int, reason: str = '用户已停止解密') -> dict:
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise RuntimeError('任务不存在')
    status = str(task.get('status') or '').lower()
    if status in ('done', 'failed', 'cancelled'):
        return {'ok': True, 'task_id': int(task_id), 'status': status, 'signal_sent': False, 'message': '任务已经结束'}

    marker = _iapt_v8_cancel_marker(task)
    marker.parent.mkdir(parents=True, exist_ok=True)
    try:
        marker.write_text(str(reason or '用户已停止解密'), encoding='utf-8')
    except Exception:
        pass

    pid = 0
    with _IAPT_V8_CANCEL_LOCK:
        proc = _IAPT_V8_RUNNING_PROCS.get(int(task_id))
        if proc is not None:
            try:
                pid = int(proc.pid)
            except Exception:
                pid = 0
    if not pid:
        try:
            pid = int(_iapt_v8_pid_file(task).read_text(encoding='ascii').strip())
        except Exception:
            pid = 0

    signal_sent = False
    if pid > 1 and _iapt_v8_is_decrypt_pid(pid):
        try:
            os.killpg(pid, _iapt_v8_signal.SIGTERM)
            signal_sent = True
        except ProcessLookupError:
            pass
        except Exception as e:
            logger.warning('IAPT cancel SIGTERM failed task=%s pid=%s: %s', task_id, pid, e)

        if signal_sent:
            def _force_kill_later(target_pid: int):
                time.sleep(3.0)
                try:
                    if _iapt_v8_is_decrypt_pid(target_pid):
                        os.killpg(target_pid, _iapt_v8_signal.SIGKILL)
                except Exception:
                    pass
            threading.Thread(target=_force_kill_later, args=(pid,), daemon=True, name='iapt-cancel-kill').start()

    db.exec("UPDATE tasks SET status='cancelled', error_text=%s WHERE id=%s", (str(reason or '用户已停止解密'), int(task_id)))
    return {
        'ok': True,
        'task_id': int(task_id),
        'status': 'cancelled',
        'signal_sent': bool(signal_sent),
        'pid': int(pid or 0),
        'message': '已发送停止信号' if signal_sent else ('已取消排队任务' if status == 'queued' else '任务已标记为停止'),
    }


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        return
    marker = _iapt_v8_cancel_marker(task)
    if str(task.get('status') or '').lower() == 'cancelled' or marker.exists():
        try:
            db.exec("UPDATE tasks SET status='cancelled', error_text=COALESCE(NULLIF(error_text,''),%s) WHERE id=%s", ('用户已停止解密', int(task_id)))
        except Exception:
            pass
        return
    result = _IAPT_V8_PREV_RUN_TASK(int(task_id))
    # The inner historical runner may write failed/done after SIGTERM.  The
    # marker is authoritative and restores the final state to cancelled.
    if marker.exists():
        try:
            reason = marker.read_text(encoding='utf-8', errors='ignore').strip() or '用户已停止解密'
        except Exception:
            reason = '用户已停止解密'
        try:
            db.exec("UPDATE tasks SET status='cancelled', error_text=%s WHERE id=%s", (reason, int(task_id)))
        except Exception:
            pass
    return result

# __IAPT_V8_PROJECT_OUTPUT_AND_CANCEL_END__

# __IAPT_V10_RELIABLE_CANCEL_BEGIN__
# v10: make per-task cancellation reliable even when the in-memory Popen map is
# unavailable (for example after a worker/thread transition).  A task PID is
# validated against its task_no/out_dir and known iapt tools before its process
# group is signalled.

def _iapt_v10_process_info(pid: int) -> tuple[str, int]:
    try:
        pid = int(pid)
        cmd = Path('/proc') .joinpath(str(pid), 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace')
        return cmd, int(os.getpgid(pid))
    except Exception:
        return '', 0


def _iapt_v10_known_task_process(cmdline: str, task: dict) -> bool:
    if not cmdline:
        return False
    known = (
        'iapp_auto_decrypt.py', 'iapp_dex2iyu_v6.py', 'iapt_v6_dispatch.py',
        'iapp_static_dex_restore.py', 'iapp_deobfuscate.py',
    )
    if not any(x in cmdline for x in known):
        return False
    task_no = str((task or {}).get('task_no') or '').strip()
    out_dir = str((task or {}).get('out_dir') or '').strip()
    # Current task commands always contain either the task-specific upload path
    # or output directory.  Keep a known-tool fallback for freshly-started jobs
    # whose DB out_dir has not yet been written.
    if task_no and task_no in cmdline:
        return True
    if out_dir and out_dir in cmdline:
        return True
    return bool(task_no and (str(APP_STORAGE / 'uploads' / (task_no + '.apk')) in cmdline))


def _iapt_v10_find_task_pids(task: dict) -> list[int]:
    found = []
    for entry in Path('/proc').iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        cmdline, _ = _iapt_v10_process_info(pid)
        if _iapt_v10_known_task_process(cmdline, task):
            found.append(pid)
    return sorted(set(found))


def _iapt_v10_signal_group(pgid: int, sig) -> bool:
    try:
        if int(pgid) > 1:
            os.killpg(int(pgid), sig)
            return True
    except ProcessLookupError:
        pass
    except Exception as exc:
        logger.warning('IAPT v10 killpg failed pgid=%s sig=%s: %s', pgid, sig, exc)
    return False


def cancel_task_process(task_id: int, reason: str = '用户已停止解密') -> dict:
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise RuntimeError('任务不存在')
    status = str(task.get('status') or '').lower()
    if status in ('done', 'failed', 'cancelled'):
        return {
            'ok': True, 'task_id': int(task_id), 'status': status,
            'signal_sent': False, 'pid': 0, 'pgids': [], 'message': '任务已经结束',
        }

    marker = _iapt_v8_cancel_marker(task)
    marker.parent.mkdir(parents=True, exist_ok=True)
    try:
        marker.write_text(str(reason or '用户已停止解密'), encoding='utf-8')
    except Exception:
        pass

    candidate_pids = []
    with _IAPT_V8_CANCEL_LOCK:
        proc = _IAPT_V8_RUNNING_PROCS.get(int(task_id))
        if proc is not None:
            try:
                candidate_pids.append(int(proc.pid))
            except Exception:
                pass
    try:
        candidate_pids.append(int(_iapt_v8_pid_file(task).read_text(encoding='ascii').strip()))
    except Exception:
        pass
    candidate_pids.extend(_iapt_v10_find_task_pids(task))

    pgids = []
    valid_pids = []
    for pid in sorted(set(x for x in candidate_pids if int(x or 0) > 1)):
        cmdline, pgid = _iapt_v10_process_info(pid)
        if pgid > 1 and _iapt_v10_known_task_process(cmdline, task):
            valid_pids.append(pid)
            pgids.append(pgid)
    pgids = sorted(set(pgids))

    signal_sent = False
    for pgid in pgids:
        signal_sent = _iapt_v10_signal_group(pgid, _iapt_v8_signal.SIGTERM) or signal_sent

    if pgids:
        def _force_kill_later(groups: tuple[int, ...], task_snapshot: dict):
            time.sleep(3.0)
            for group in groups:
                # Only kill a surviving group if at least one process still
                # validates as belonging to this task.
                still_owned = False
                for pid in _iapt_v10_find_task_pids(task_snapshot):
                    _, current_group = _iapt_v10_process_info(pid)
                    if current_group == group:
                        still_owned = True
                        break
                if still_owned:
                    _iapt_v10_signal_group(group, _iapt_v8_signal.SIGKILL)
        threading.Thread(
            target=_force_kill_later,
            args=(tuple(pgids), dict(task)),
            daemon=True,
            name='iapt-v10-cancel-kill',
        ).start()

    db.exec(
        "UPDATE tasks SET status='cancelled', error_text=%s WHERE id=%s",
        (str(reason or '用户已停止解密'), int(task_id)),
    )
    return {
        'ok': True,
        'task_id': int(task_id),
        'status': 'cancelled',
        'signal_sent': bool(signal_sent),
        'pid': int(valid_pids[0] if valid_pids else 0),
        'pids': valid_pids,
        'pgids': pgids,
        'message': (
            '已停止任务及其子进程' if signal_sent
            else ('已取消排队任务' if status == 'queued' else '任务已标记停止；未发现仍存活的任务进程')
        ),
    }
# __IAPT_V10_RELIABLE_CANCEL_END__

# __IAPT_V11_SHELL_FIND_BEGIN__
# v11: use a dedicated shell-find endpoint and a direct exact-member path for
# <package>.project.  This code never creates a task, never reopens the APK,
# never resolves an outer key, and never reruns sokey/dexkey enumeration.
_IAPT_V11_PREV_FIND_FROM_TASK_SHELL = find_from_task_shell


def _iapt_v11_project_candidates(task: dict, requested: str, out_dir: Path) -> list[str]:
    """Return plausible internal project member names, exact request first."""
    values = []

    def add(value):
        value = str(value or '').strip().replace('\\', '/').lstrip('./')
        if not value or not value.lower().endswith('.project'):
            return
        # Internal iApp members are root names.  Preserve an explicit root name;
        # for a path-like request also try its basename.
        for item in (value, value.rsplit('/', 1)[-1]):
            if item and item not in values:
                values.append(item)

    add(requested)
    add(str((task or {}).get('package_name') or '') + '.project')

    # Metadata parsing may already have discovered the exact project filename.
    for cache_name in ('project_meta_v7.json', 'project_meta_v6.json', 'project_meta.json'):
        try:
            obj = json.loads((out_dir / '.tmp' / cache_name).read_text(encoding='utf-8'))
            if isinstance(obj, dict):
                add(obj.get('project_file'))
        except Exception:
            pass

    # Also accept the project_file emitted by previous decrypt logs.
    log_text = _iapt_read_log_tail((task or {}).get('log_path'))
    try:
        for match in re.finditer(r'"project_file"\s*:\s*"([^"\\]*(?:\\.[^"\\]*)*)"', log_text or '', flags=re.I):
            try:
                add(json.loads('"' + match.group(1) + '"'))
            except Exception:
                add(match.group(1))
    except Exception:
        pass
    return values


def _iapt_v11_decrypt_project_member(env: dict, task: dict, requested: str):
    """Decrypt one .project member directly from container_plain.bin.

    Returns (internal_name, plaintext) or (None, None).  The alternate member
    key mode fallback is cheap and useful for older tasks whose trace omitted
    member_key_mode; it still uses the already-decrypted outer container.
    """
    from .tools.iapp_auto_decrypt import try_decrypt_member

    out_dir = Path(env['out_dir'])
    modes = []
    for mode in (str(env.get('member_key_mode') or 'xor').lower(), 'xor', 'direct'):
        if mode in ('xor', 'direct') and mode not in modes:
            modes.append(mode)

    for internal_name in _iapt_v11_project_candidates(task, requested, out_dir):
        for mode in modes:
            try:
                plain = try_decrypt_member(
                    env['container_plain'], env['ctx'], env['key_xor'], internal_name,
                    env['hidden'], env['fb'], mode,
                )
            except Exception:
                plain = None
            if plain is not None and len(plain) > 0:
                return internal_name, plain
    return None, None


def find_from_task_shell(task_id: int, names, recursive: bool = False, max_output_files=None) -> dict:
    """Task-list filename lookup using an already decrypted container.

    V3 uses the reusable member shell.  Ancient four-character-sokey tasks use
    their saved old_outer_container.bin and never rerun dexkey/sokey enumeration.
    """
    from .tools.iapp_auto_decrypt import normalize_find_names, safe_out_name

    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise RuntimeError('任务不存在')
    if str(task.get('status') or '').lower() != 'done':
        raise RuntimeError('任务尚未完成，不能复用解密外壳查找')

    targets = normalize_find_names(names if isinstance(names, list) else [names])
    if not targets:
        raise ValueError('请输入文件名')
    if len(targets) > 50:
        raise ValueError('一次最多查找 50 个文件名')

    # 远古方案：复用任务中保存的外层明文，按旧版文件名哈希和成员 key
    # 直接解出请求文件；不创建新任务，也不重新枚举 dexkey/sokey。
    task_version = str(task.get('decrypt_version') or '').strip().lower()
    out_dir = Path(str(task.get('out_dir') or ''))
    outer_path = out_dir / '.tmp' / 'old_outer_container.bin'
    report_path = out_dir / 'old_iapp_report.json'
    is_old_task = task_version in ('old', 'legacy', 'old_iapp', 'iapp_old') or (outer_path.is_file() and report_path.is_file())
    if is_old_task:
        from .tools.iapp_old_decrypt import decrypt_members
        if not outer_path.is_file() or not report_path.is_file():
            raise RuntimeError('远古方案任务缺少可复用的成员容器，请重新提交任务')
        report = json.loads(report_path.read_text(encoding='utf-8', errors='replace'))
        sokey = str(report.get('sokey') or '').strip()
        main_file = str(report.get('main_file') or 'mian.iyu').strip()
        if len(sokey) != 4:
            raise RuntimeError('远古方案任务报告缺少4位sokey')
        apk_path = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
        before = {str(x.get('rel_path') or '') for x in list_task_files(task)}
        member_report = decrypt_members(
            outer_path.read_bytes(), sokey, apk_path, out_dir,
            find_names=targets, find_only=True, main_file=main_file,
        )
        scan_files(int(task_id), out_dir)
        indexed = {str(x.get('rel_path') or ''): x for x in list_task_files(task)}
        items = []
        for row in member_report.get('members') or []:
            rel = str(row.get('output') or '')
            if not rel:
                continue
            item = dict(indexed.get(rel) or {})
            item.update({
                'rel_path': rel,
                'source_name': str(row.get('resolved_name') or rel),
                'member_index': int(row.get('index') or 0),
                'name_hash': str(row.get('name_hash') or ''),
                'new': rel not in before,
                'ancient_scheme': True,
            })
            items.append(item)
        return {
            'ok': True, 'task_id': int(task_id), 'status': 'done',
            'implementation': 'ancient-shell-find-v1',
            'reused_decrypted_shell': True, 'created_task': False,
            'reran_outer_decrypt': False, 'reran_enumeration': False,
            'recursive': bool(recursive), 'requested': targets,
            'items': items, 'found_count': len(items),
            'added_count': sum(1 for x in items if x.get('new')),
            'not_found': list(member_report.get('missing_find_names') or []),
            'file_count': len(list_task_files(task)),
        }
    project_targets = [x for x in targets if str(x).lower().endswith('.project')]
    other_targets = [x for x in targets if x not in project_targets]

    with _iapt_reuse_lock(int(task_id)):
        before_rows = list_task_files(task)
        before_paths = {str(x.get('rel_path') or '') for x in before_rows}
        project_items = []
        project_missing = []

        if project_targets:
            env = _iapt_load_reuse_context(task)
            out_dir = Path(env['out_dir'])
            for requested in project_targets:
                internal_name, plain = _iapt_v11_decrypt_project_member(env, task, requested)
                if plain is None:
                    project_missing.append(requested)
                    continue

                # Write the requested filename when it is a simple root member;
                # otherwise use the actual internal root name.  This keeps the
                # user's expected com.xxx.project visible in the ZIP/index.
                requested_root = str(requested or '').replace('\\', '/').rsplit('/', 1)[-1]
                output_name = requested_root if requested_root.lower().endswith('.project') else internal_name
                rel_path = safe_out_name(output_name)
                output_path = out_dir / rel_path
                output_path.write_bytes(plain)
                project_items.append({
                    'rel_path': rel_path,
                    'size_bytes': len(plain),
                    'source_name': requested,
                    'internal_name': internal_name,
                    'new': rel_path not in before_paths,
                    'direct_project': True,
                })

            if project_items:
                scan_files(int(task_id), out_dir)
                indexed = {str(x.get('rel_path') or ''): x for x in list_task_files(task)}
                for item in project_items:
                    row = indexed.get(item['rel_path'])
                    if row:
                        keep = dict(item)
                        keep.update(row)
                        keep['source_name'] = item['source_name']
                        keep['internal_name'] = item['internal_name']
                        keep['new'] = item['new']
                        keep['direct_project'] = True
                        item.clear(); item.update(keep)

        other_result = None
        if other_targets:
            other_result = _IAPT_V11_PREV_FIND_FROM_TASK_SHELL(
                int(task_id), other_targets, recursive=bool(recursive),
                max_output_files=max_output_files,
            )

        items = list(project_items)
        not_found = list(project_missing)
        added_count = sum(1 for x in project_items if x.get('new'))
        file_count = len(list_task_files(task))
        if other_result:
            items.extend(list(other_result.get('items') or []))
            not_found.extend(list(other_result.get('not_found') or []))
            added_count += int(other_result.get('added_count') or 0)
            file_count = int(other_result.get('file_count') or file_count)

        return {
            'ok': True,
            'task_id': int(task_id),
            'status': 'done',
            'implementation': 'shell-find-v11',
            'reused_decrypted_shell': True,
            'created_task': False,
            'reran_outer_decrypt': False,
            'reran_enumeration': False,
            'recursive': bool(recursive),
            'requested': targets,
            'items': items,
            'found_count': len(items),
            'added_count': added_count,
            'not_found': not_found,
            'file_count': file_count,
        }
# __IAPT_V11_SHELL_FIND_END__

# __IAPT_V14_DURABLE_SHELL_BEGIN__
# Keep the already-decrypted outer container in two places:
#   1) task output/.tmp/container_plain.bin (legacy/current lookup path)
#   2) storage/task_shells/<task_no>/container_plain.bin (durable fallback)
# Find never creates a task and never performs sokey/dexkey enumeration.
_IAPT_V14_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process
_IAPT_V14_PREV_RESOLVE_REUSE_VALUES = _iapt_resolve_reuse_values


def _iapt_v14_shell_store_dir(task: dict) -> Path:
    task_no = str((task or {}).get('task_no') or '').strip()
    if not task_no:
        task_no = 'task_' + str(int((task or {}).get('id') or 0))
    return APP_STORAGE / 'task_shells' / task_no


def _iapt_v14_valid_plain(path: Path) -> bool:
    try:
        return path.is_file() and int(path.stat().st_size) >= 32
    except Exception:
        return False


def _iapt_v14_link_or_copy(src: Path, dst: Path) -> None:
    src = Path(src)
    dst = Path(dst)
    if not _iapt_v14_valid_plain(src):
        raise RuntimeError('invalid shell source: ' + str(src))
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        if dst.exists():
            if dst.samefile(src):
                return
            if dst.stat().st_size == src.stat().st_size:
                return
            dst.unlink()
    except Exception:
        try:
            dst.unlink(missing_ok=True)
        except Exception:
            pass
    try:
        os.link(src, dst)
        return
    except Exception:
        pass
    tmp = dst.with_name(dst.name + '.tmp.' + str(os.getpid()))
    try:
        with src.open('rb') as rf, tmp.open('wb') as wf:
            shutil.copyfileobj(rf, wf, length=4 * 1024 * 1024)
        os.replace(tmp, dst)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def _iapt_v14_copy_small(src: Path, dst: Path) -> None:
    try:
        if not src.is_file() or src.stat().st_size > 8 * 1024 * 1024:
            return
        dst.parent.mkdir(parents=True, exist_ok=True)
        data = src.read_bytes()
        tmp = dst.with_name(dst.name + '.tmp.' + str(os.getpid()))
        tmp.write_bytes(data)
        os.replace(tmp, dst)
    except Exception:
        pass


def _iapt_v14_candidates_from_text(text: str) -> list[Path]:
    out = []
    for pat in (
        r'->\s*([^\r\n]+?container_plain\.bin)',
        r'(?<![A-Za-z0-9_./-])(/[^\r\n\x00]*?container_plain\.bin)',
    ):
        try:
            for m in re.finditer(pat, text or '', flags=re.I):
                raw = str(m.group(1) or '').strip().strip('"\'')
                if raw:
                    p = Path(raw)
                    if p not in out:
                        out.append(p)
        except Exception:
            pass
    return out


def _iapt_v14_shell_candidates(task: dict, out_dir: Path, extra_text: str = '') -> list[Path]:
    out_dir = Path(out_dir)
    durable = _iapt_v14_shell_store_dir(task)
    candidates = [
        out_dir / '.tmp' / 'container_plain.bin',
        durable / 'container_plain.bin',
    ]
    try:
        _texts = [extra_text, _iapt_read_log_tail((task or {}).get('log_path'))]
        for _text in _texts:
            candidates.extend(_iapt_v14_candidates_from_text(_text))
            # Old successful logs often print only the outer_key_cache.json path.
            # Its sibling container_plain.bin is the already-decrypted shell.
            for _m in re.finditer(r'(/[^\r\n\x00]*?outer_key_cache\.json)', _text or '', flags=re.I):
                _cache_from_log = Path(str(_m.group(1) or '').strip().strip('\"\''))
                candidates.append(_cache_from_log.parent / 'container_plain.bin')
    except Exception:
        pass
    try:
        for p in out_dir.rglob('container_plain.bin'):
            candidates.append(p)
    except Exception:
        pass

    # A successful run may have placed the plain container in the shared outer
    # cache. Resolve it by fingerprint without decrypting the APK again.
    cache_candidates = [out_dir / '.tmp' / 'outer_key_cache.json', durable / 'outer_key_cache.json']
    try:
        cache_candidates.extend(out_dir.rglob('outer_key_cache.json'))
    except Exception:
        pass
    for cache_path in cache_candidates:
        try:
            obj = json.loads(Path(cache_path).read_text(encoding='utf-8'))
            fp = str(obj.get('fingerprint') or '').strip()
            if not fp:
                continue
            from .tools.iapp_auto_decrypt import shared_outer_cache_path
            candidates.append(shared_outer_cache_path(fp).parent / 'container_plain.bin')
        except Exception:
            pass

    unique = []
    seen = set()
    for p in candidates:
        try:
            key = str(Path(p).resolve())
        except Exception:
            key = str(p)
        if key in seen:
            continue
        seen.add(key)
        unique.append(Path(p))
    return unique


def _iapt_v14_materialize_shell(task: dict, out_dir: Path, extra_text: str = '') -> Path:
    out_dir = Path(out_dir)
    exact = out_dir / '.tmp' / 'container_plain.bin'
    durable_dir = _iapt_v14_shell_store_dir(task)
    durable = durable_dir / 'container_plain.bin'

    source = None
    for candidate in _iapt_v14_shell_candidates(task, out_dir, extra_text):
        if _iapt_v14_valid_plain(candidate):
            source = candidate
            break
    if source is None:
        checked = [str(x) for x in _iapt_v14_shell_candidates(task, out_dir, extra_text)[:12]]
        raise RuntimeError(
            '没有找到已解密外壳；已检查：' + ', '.join(checked) +
            '。本操作没有重新枚举，也没有创建任务'
        )

    _iapt_v14_link_or_copy(source, exact)
    _iapt_v14_link_or_copy(exact, durable)

    # Keep the small key/session metadata beside both copies. This is metadata
    # only; it does not expose the file in the downloadable ZIP.
    names = (
        'outer_key_cache.json', 'reuse_session_v7.json',
        'reuse_session_v14.json', 'project_meta_v7.json',
        'project_meta_v6.json', 'project_meta.json',
    )
    for name in names:
        a = out_dir / '.tmp' / name
        b = durable_dir / name
        if a.is_file():
            _iapt_v14_copy_small(a, b)
        elif b.is_file():
            _iapt_v14_copy_small(b, a)
    return exact


def _iapt_v14_sync_after_decrypt(task: dict, out_dir: Path, stdout: str = '') -> None:
    try:
        exact = _iapt_v14_materialize_shell(task, out_dir, stdout)
        logger.info(
            'IAPT v14 shell retained task=%s path=%s bytes=%s durable=%s',
            (task or {}).get('id'), exact, exact.stat().st_size,
            _iapt_v14_shell_store_dir(task) / 'container_plain.bin',
        )
    except Exception as exc:
        # Do not turn an otherwise valid decrypt into a failed task. The log is
        # explicit so diagnose_iapt can show why shell reuse is unavailable.
        logger.warning('IAPT v14 shell retain failed task=%s: %s', (task or {}).get('id'), exc)


def run_decrypt_process(cmd: list, apk_path: Path, out_dir: Path, options: dict, task: dict, env: dict | None = None) -> _IaptProcResult:
    env2 = dict(env or os.environ.copy())
    durable_dir = _iapt_v14_shell_store_dir(task)
    durable_dir.mkdir(parents=True, exist_ok=True)
    env2['IAPT_DURABLE_SHELL_DIR'] = str(durable_dir)
    result = _IAPT_V14_PREV_RUN_DECRYPT_PROCESS(
        cmd, apk_path, out_dir, options, task, env=env2,
    )
    _iapt_v14_sync_after_decrypt(task, Path(out_dir), result.stdout or '')
    return result


def _iapt_resolve_reuse_values(task: dict, out_dir: Path) -> dict:
    # Repair the exact legacy location from the durable/shared copy first, then
    # use the already-tested v7/v11 value resolver. No APK decryption occurs.
    _iapt_v14_materialize_shell(task, Path(out_dir))
    return _IAPT_V14_PREV_RESOLVE_REUSE_VALUES(task, Path(out_dir))


def iapt_v14_shell_status(task_id: int) -> dict:
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        raise RuntimeError('任务不存在')
    out_raw = str(task.get('out_dir') or '').strip()
    out_dir = Path(out_raw) if out_raw else (APP_STORAGE / 'tasks' / str(task.get('task_no') or ''))
    candidates = _iapt_v14_shell_candidates(task, out_dir)
    return {
        'task_id': int(task_id),
        'task_no': str(task.get('task_no') or ''),
        'out_dir': str(out_dir),
        'candidates': [
            {'path': str(p), 'exists': p.is_file(), 'size': int(p.stat().st_size) if p.is_file() else 0}
            for p in candidates[:20]
        ],
    }
# __IAPT_V14_DURABLE_SHELL_END__

# __IAPT_V18_6_6_V6_FINALIZE_BEGIN__
# v18.6.6: distinguish "slow" from "finished but never finalized".
# A DEX task can already have all output files written while the parent waits
# forever for EOF on stdout (an inherited fd/non-daemon descendant keeps the
# pipe open).  The V6 tool writes .tmp/v6_complete.json atomically at the end;
# this runner treats that marker as authoritative and finalizes immediately.
def _iapt_v1866_is_v6_cmd(cmd) -> bool:
    try:
        text = ' '.join(str(x) for x in (cmd or []))
    except Exception:
        text = str(cmd or '')
    return ('iapt_v6_dispatch.py' in text) or ('iapp_dex2iyu_v6.py' in text)


def _iapt_v1866_timeout_seconds(options=None) -> int:
    vals = []
    if isinstance(options, dict):
        vals += [options.get('v6_timeout_sec'), options.get('timeout_sec'), options.get('v6_timeout')]
    vals += [os.environ.get('IAPT_V6_TIMEOUT_SEC'), os.environ.get('IAPT_TASK_TIMEOUT_SEC')]
    for v in vals:
        try:
            if v is not None and str(v).strip() != '':
                n = int(float(str(v).strip()))
                if n > 0:
                    return max(60, min(n, 24 * 3600))
        except Exception:
            pass
    return 1800


def _iapt_v1866_read_complete_marker(out_dir: Path):
    path = Path(out_dir) / '.tmp' / 'v6_complete.json'
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
        if isinstance(data, dict) and data.get('ok') is True:
            return data
    except Exception:
        pass
    return None


_IAPT_V1866_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process


def run_decrypt_process(cmd: list, apk_path: Path, out_dir: Path, options: dict, task: dict, env: dict | None = None) -> _IaptProcResult:
    if not _iapt_v1866_is_v6_cmd(cmd):
        return _IAPT_V1866_PREV_RUN_DECRYPT_PROCESS(cmd, apk_path, out_dir, options, task, env=env)

    import queue as _q
    import signal as _signal

    task_id = int((task or {}).get('id') or 0)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tmp_dir = out_dir / '.tmp'
    tmp_dir.mkdir(parents=True, exist_ok=True)
    complete_path = tmp_dir / 'v6_complete.json'
    # Never accept a marker left by a previous attempt.
    try:
        complete_path.unlink(missing_ok=True)
    except Exception:
        pass

    marker = _iapt_v8_cancel_marker(task) if '_iapt_v8_cancel_marker' in globals() else (tmp_dir / 'cancel.request')
    pid_file = _iapt_v8_pid_file(task, out_dir) if '_iapt_v8_pid_file' in globals() else (tmp_dir / 'decrypt.pid')
    heartbeat = tmp_dir / 'heartbeat.json'
    timeout = _iapt_v1866_timeout_seconds(options)
    env2 = dict(env or os.environ.copy())
    env2.setdefault('PYTHONIOENCODING', 'utf-8')
    env2.setdefault('PYTHONUTF8', '1')
    env2.setdefault('LANG', 'C.UTF-8')
    env2.setdefault('LC_ALL', 'C.UTF-8')
    env2.setdefault('IAPT_V6_TIMEOUT_SEC', str(timeout))

    if marker.exists():
        return _IaptProcResult(130, '[IAPT_CANCELLED] V6 task cancelled before subprocess start\n')

    started = time.time()
    lines = []
    proc = None
    q = _q.Queue()
    reader_done = False
    exited_at = None

    def _kill_group(sig):
        if proc is None:
            return False
        try:
            os.killpg(proc.pid, sig)
            return True
        except Exception:
            try:
                proc.send_signal(sig)
                return True
            except Exception:
                return False

    def _drain_queue(limit_seconds=0.4):
        nonlocal reader_done
        deadline = time.time() + max(0.0, float(limit_seconds))
        while time.time() <= deadline:
            try:
                item = q.get_nowait()
            except _q.Empty:
                time.sleep(0.01)
                continue
            if item is None:
                reader_done = True
                break
            lines.append(str(item))

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            env=env2,
            start_new_session=True,
        )
        try:
            pid_file.write_text(str(proc.pid), encoding='ascii')
        except Exception:
            pass
        try:
            with _IAPT_V8_CANCEL_LOCK:
                _IAPT_V8_RUNNING_PROCS[task_id] = proc
        except Exception:
            pass

        def _reader():
            try:
                if proc.stdout is not None:
                    for line in iter(proc.stdout.readline, ''):
                        q.put(line)
            except Exception as exc:
                q.put('[IAPT_V6_READER_WARN] %s\n' % exc)
            finally:
                q.put(None)

        threading.Thread(target=_reader, daemon=True, name='iapt-v6-stdout-reader').start()
        last_db_touch = 0.0
        complete_seen_at = None

        while True:
            now = time.time()
            if now - last_db_touch >= 15:
                last_db_touch = now
                try:
                    heartbeat.write_text(json.dumps({
                        'task_id': task_id, 'pid': int(proc.pid), 'time': int(now),
                        'elapsed': int(now - started), 'timeout': int(timeout),
                        'cmd': ' '.join(str(x) for x in (cmd or []))[:1000],
                    }, ensure_ascii=False), encoding='utf-8')
                    try:
                        db.exec('UPDATE tasks SET updated_at=NOW() WHERE id=%s AND status=%s', (task_id, 'running'))
                    except Exception:
                        pass
                except Exception:
                    pass

            try:
                item = q.get(timeout=0.20)
                if item is None:
                    reader_done = True
                else:
                    lines.append(str(item))
                    if len(lines) > 20000:
                        lines = lines[:2000] + ['\n[IAPT_V6_LOG_TRUNCATED]\n'] + lines[-12000:]
            except _q.Empty:
                pass

            complete = _iapt_v1866_read_complete_marker(out_dir)
            if complete is not None:
                if complete_seen_at is None:
                    complete_seen_at = now
                # Give the tool a brief chance to flush its final lines.  If it
                # remains alive, it is cleanup/pipe leakage, not useful work.
                if proc.poll() is None and now - complete_seen_at >= 0.75:
                    _kill_group(_signal.SIGTERM)
                    try:
                        proc.wait(timeout=0.75)
                    except Exception:
                        _kill_group(_signal.SIGKILL)
                        try: proc.wait(timeout=0.75)
                        except Exception: pass
                _drain_queue(0.35)
                lines.append('\n[IAPT_V18_6_6_RESULT_READY] 输出已完整写入，任务已立即结算。\n')
                return _IaptProcResult(0, ''.join(lines))

            rc = proc.poll()
            if rc is not None:
                if exited_at is None:
                    exited_at = now
                if reader_done:
                    return _IaptProcResult(int(rc), ''.join(lines))
                # Never wait forever for EOF after the process has exited.  A
                # descendant may still own the inherited stdout file descriptor.
                if now - exited_at >= 1.25:
                    _drain_queue(0.25)
                    try:
                        if proc.stdout is not None:
                            proc.stdout.close()
                    except Exception:
                        pass
                    lines.append('\n[IAPT_V18_6_6_PIPE_EOF_BYPASS] 主进程已退出，忽略被继承的 stdout 管道。\n')
                    return _IaptProcResult(int(rc), ''.join(lines))

            if marker.exists():
                _kill_group(_signal.SIGTERM)
                try: proc.wait(timeout=1.0)
                except Exception:
                    _kill_group(_signal.SIGKILL)
                return _IaptProcResult(130, ''.join(lines) + '\n[IAPT_CANCELLED] V6 task cancelled\n')

            if now - started > timeout:
                _kill_group(_signal.SIGTERM)
                try: proc.wait(timeout=2.0)
                except Exception:
                    _kill_group(_signal.SIGKILL)
                return _IaptProcResult(124, ''.join(lines) + '\n[IAPT_V6_TIMEOUT] V6反编译超时 %s 秒，已停止该任务。\n' % timeout)
    finally:
        try:
            with _IAPT_V8_CANCEL_LOCK:
                _IAPT_V8_RUNNING_PROCS.pop(task_id, None)
        except Exception:
            pass
        try:
            pid_file.unlink(missing_ok=True)
        except Exception:
            pass
        try:
            if proc is not None and proc.stdout is not None:
                proc.stdout.close()
        except Exception:
            pass


def _iapt_v1866_promote_legacy_complete_output(out_dir: Path):
    """Create a marker for v18.6.5 jobs that finished files but hung before DB finalization."""
    out_dir = Path(out_dir)
    marker = out_dir / '.tmp' / 'v6_complete.json'
    if marker.is_file():
        return
    validation_path = out_dir / 'deep_code' / 'iyu_validation.json'
    report_path = out_dir / 'deep_code' / 'recovery_report.json'
    src_dir = out_dir / 'src'
    try:
        validation = json.loads(validation_path.read_text(encoding='utf-8'))
        iyu_count = len(list(src_dir.glob('*.iyu'))) if src_dir.is_dir() else 0
        report_ok = report_path.is_file() and report_path.stat().st_size > 20
        valid_ok = bool(validation.get('ok')) and int(validation.get('files') or validation.get('xml_ok') or 0) > 0
        if iyu_count > 0 and valid_ok and report_ok:
            marker.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                'ok': True, 'tool_version': 'legacy-v18.6.5-output-detected',
                'elapsed_ms': 0, 'file_count': iyu_count,
                'finished_at': int(max(validation_path.stat().st_mtime, report_path.stat().st_mtime)),
                'promoted_by': 'v18.6.6',
            }
            tmp = marker.with_suffix('.tmp')
            tmp.write_text(json.dumps(payload, ensure_ascii=False), encoding='utf-8')
            os.replace(tmp, marker)
    except Exception:
        pass


def _iapt_v1866_finalize_marker_task(task: dict) -> bool:
    """Finalize an output-complete V6 row without rerunning decompilation."""
    try:
        task_id = int(task.get('id'))
        out_raw = str(task.get('out_dir') or '').strip()
        out_dir = Path(out_raw) if out_raw else (APP_STORAGE / 'tasks' / str(task.get('task_no') or ''))
        _iapt_v1866_promote_legacy_complete_output(out_dir)
        meta = _iapt_v1866_read_complete_marker(out_dir)
        if not meta:
            return False
        count, total = scan_files(task_id, out_dir)
        if count <= 0:
            return False
        total_ms = float(meta.get('elapsed_ms') or 0)
        db.exec("UPDATE tasks SET status='done',file_count=%s,total_bytes=%s,total_ms=%s,error_text=NULL WHERE id=%s AND status='running'", (count, total, total_ms, task_id))
        try:
            settle_decrypt_quota_once(task_id)
        except Exception:
            pass
        # A lingering process is cleanup-only after the atomic result marker.
        try:
            pid = int((out_dir / '.tmp' / 'decrypt.pid').read_text(encoding='ascii').strip())
            if pid > 1:
                os.killpg(pid, __import__('signal').SIGTERM)
        except Exception:
            pass
        return True
    except Exception as exc:
        try: logger.warning('v18.6.6 marker finalize failed task=%s: %s', task.get('id'), exc)
        except Exception: pass
        return False


def iapt_v1864_reconcile_running_v6_tasks(max_age_seconds: int = 0) -> dict:
    repaired, completed = [], []
    try:
        rows = db.all("""
            SELECT id,task_no,out_dir,log_path,status,feature_id,decrypt_version,options_json,created_at,updated_at
            FROM tasks
            WHERE status='running'
              AND (feature_id=6 OR decrypt_version='v6' OR LOCATE('v6', LOWER(COALESCE(options_json,'')))>0)
            ORDER BY id DESC LIMIT 200
        """) or []
    except Exception:
        rows = []
    for task in rows:
        try:
            if _iapt_v1866_finalize_marker_task(task):
                completed.append(int(task.get('id')))
                continue
            out_raw = str(task.get('out_dir') or '').strip()
            out_dir = Path(out_raw) if out_raw else (APP_STORAGE / 'tasks' / str(task.get('task_no') or ''))
            pid = 0
            try: pid = int((out_dir / '.tmp' / 'decrypt.pid').read_text(encoding='ascii').strip())
            except Exception: pass
            alive = False
            if pid > 1:
                try:
                    cmdline = Path('/proc', str(pid), 'cmdline').read_bytes().replace(b'\x00', b' ').decode('utf-8', 'replace')
                    alive = ('iapt_v6_dispatch.py' in cmdline or 'iapp_dex2iyu_v6.py' in cmdline)
                except Exception:
                    alive = False
            if alive:
                continue
            reason = 'V6任务进程已不存在且没有完整结果标记，已自动修正为失败。'
            db.exec('UPDATE tasks SET status=%s,error_text=%s WHERE id=%s AND status=%s', ('failed', reason, int(task.get('id')), 'running'))
            repaired.append(int(task.get('id')))
        except Exception as exc:
            try: logger.warning('v18.6.6 reconcile failed task=%s: %s', task.get('id'), exc)
            except Exception: pass
    return {'ok': True, 'completed': completed, 'repaired': repaired, 'count': len(completed) + len(repaired)}
# __IAPT_V18_6_6_V6_FINALIZE_END__

# IAPT_V35_DYNAMIC_KEY_POOL_SUCCESS_HOOK_BEGIN
_IAPT_V35_POOL_BASE_RUN_TASK = run_task


def _iapt_v35_log_value(text: str, patterns) -> str:
    for pat in patterns:
        m = re.search(pat, text or '', re.I)
        if m:
            return str(m.group(1) or '').strip()
    return ''


def _iapt_v35_norm_hex(value) -> str:
    text = re.sub(r'\s+', '', str(value or '')).lower()
    return text if text and len(text) % 2 == 0 and re.fullmatch(r'[0-9a-f]+', text) else ''


def _iapt_v35_after_v3_success(task_id: int) -> None:
    task = db.one("SELECT * FROM tasks WHERE id=%s", (task_id,)) or {}
    if str(task.get('status') or '').lower() != 'done':
        return
    if int(task.get('feature_id') or 0) == 6 or str(task.get('decrypt_version') or '').lower() == 'v6':
        return
    try:
        options = json.loads(task.get('options_json') or '{}')
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    log_text = ''
    try:
        lp = Path(str(task.get('log_path') or ''))
        if lp.is_file():
            log_text = lp.read_text(encoding='utf-8', errors='ignore')
    except Exception:
        pass

    from .dynamic_key_pool import ensure_verified_key, mark_used
    pool_match = _iapt_v35_log_value(log_text, [r'SERVER_KEY_POOL_MATCH\s*=\s*([A-Za-z0-9]+)'])
    if pool_match:
        try:
            mark_used(pool_match)
            upload_path = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
            if upload_path.is_file() and options.get('dynamic_key_features'):
                _iapt_vfp_attach_pool_features(upload_path, options, pool_match)
        except Exception as exc:
            logger.warning('mark/learn server key pool feature failed: %s', exc)

    custom = _iapt_task_truthy(options.get('custom_dynamic_key')) or bool(options.get('post_key') or options.get('key_xor'))
    automatic = (
        _iapt_task_truthy(options.get('dynamic_key'))
        or _iapt_task_truthy(options.get('server_dynamic_key'))
        or _iapt_task_truthy(options.get('enable_dynamic_key'))
        or int(task.get('feature_id') or 0) == 4
    )
    # 任意成功 V3 解密只要日志给出了最终通过验证的 post/xor，
    # 都应自动进入密钥池。旧逻辑只接受显式 dynamic_key/custom，导致
    # 枚举或普通自动外层验证成功后密钥没有入池。
    selected_post = _iapt_v35_norm_hex(_iapt_v35_log_value(log_text, [r'SLKY_POST_KEY\s*=\s*([0-9a-fA-F]+)']))
    selected_xor = _iapt_v35_norm_hex(_iapt_v35_log_value(log_text, [r'(?:KEY_XOR_CONST|KEY_XOR|xor_key)\s*=\s*([0-9a-fA-F]+)']))
    if not selected_post or not selected_xor:
        return

    if custom:
        # 只有解密器明确报告 manual-strict，且最终选中的 key 与用户输入完全一致，
        # 才能把自定义 key 标为验证成功。自动回退成功不能替用户输入“背书”。
        key_source = _iapt_v35_log_value(log_text, [r'KEY_SOURCE\s*=\s*([A-Za-z0-9_.:-]+)']).lower()
        input_post = _iapt_v35_norm_hex(options.get('post_key'))
        input_xor = _iapt_v35_norm_hex(options.get('key_xor'))
        if key_source != 'manual-strict' or selected_post != input_post or selected_xor != input_xor:
            logger.warning('skip custom key pool write: task=%s source=%s selected/input mismatch', task_id, key_source)
            return
        post_key, xor_key = selected_post, selected_xor
        source_type = 'custom_verified'
    else:
        # 服务器自动提取只在解密成功后入池；selected_post/selected_xor 是实际通过验证的完整密钥。
        post_key, xor_key = selected_post, selected_xor
        source_type = 'server_dynamic_success' if automatic else 'verified_decrypt_success'
    feature_map = options.get('dynamic_key_features')
    feature_version = _iapt_vfp_feature_version(options)
    upload_path = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
    if feature_map and upload_path.is_file():
        try:
            feature_map, _selected_so, feature_version = _iapt_vfp_validated_features(upload_path, options)
        except Exception as exc:
            # Fingerprint metadata is useful for automatic matching, but it must
            # never prevent a key pair that actually decrypted the container from
            # being persisted.  Rebuild fingerprints from the server upload and,
            # if that also fails, store the verified key without fingerprints.
            logger.warning(
                'dynamic key client feature validation failed task=%s; rebuilding on server: %s',
                task_id, exc,
            )
            try:
                from .dynamic_key_pool import (
                    extract_all_so_from_bytes, normalize_feature_map, so_feature_sha256,
                )
                server_features = {}
                for row in extract_all_so_from_bytes(
                    upload_path.read_bytes(),
                    str(task.get('apk_name') or upload_path.name),
                ):
                    abi = str(row.get('abi') or 'unknown').strip().lower()
                    data = bytes(row.get('data') or b'')
                    if data and abi not in server_features:
                        server_features[abi] = so_feature_sha256(data)
                feature_map = normalize_feature_map(
                    server_features, version=feature_version
                )
            except Exception as rebuild_exc:
                logger.warning(
                    'dynamic key server feature rebuild failed task=%s; storing key without features: %s',
                    task_id, rebuild_exc,
                )
                feature_map = {}
    try:
        stored = ensure_verified_key(
            post_key,
            xor_key,
            source_type=source_type,
            source_sha256=str(task.get('apk_sha256') or ''),
            source_name=str(task.get('apk_name') or ''),
            user_id=int(task.get('user_id') or 0),
            features=feature_map,
            normalizer_version=feature_version,
        )
        logger.warning(
            'stored verified dynamic key task=%s ref=%s created=%s features=%s replaced=%s',
            task_id, stored.get('public_id'), stored.get('created'),
            stored.get('feature_count'), len(stored.get('replaced') or []),
        )
    except Exception as exc:
        logger.warning('store dynamic key pool after success failed task=%s: %s', task_id, exc)


def run_task(task_id: int):
    result = None
    try:
        result = _IAPT_V35_POOL_BASE_RUN_TASK(task_id)
        try:
            _iapt_v35_after_v3_success(int(task_id))
        except Exception as exc:
            try:
                logger.warning('V35 dynamic key pool success hook failed task=%s: %s', task_id, exc)
            except Exception:
                pass
        return result
    finally:
        # 原始密钥仅在 worker 私有临时文件中短暂存在；任务结束后立即删除。
        try:
            task = db.one("SELECT out_dir,task_no FROM tasks WHERE id=%s", (int(task_id),)) or {}
            out_raw = str(task.get('out_dir') or '').strip()
            out_dir = Path(out_raw) if out_raw else (APP_STORAGE / 'tasks' / str(task.get('task_no') or ''))
            (out_dir / '.tmp' / 'server_dynamic_key_pool.json').unlink(missing_ok=True)
        except Exception:
            pass
# IAPT_V35_DYNAMIC_KEY_POOL_SUCCESS_HOOK_END

# IAPT_V40_DYNAMIC_KEY_MULTI_ABI_TASK_BEGIN
_IAPT_V39_BASE_RUN_TASK = run_task


def _iapt_v39_is_dynamic_key_task(task: dict, options: dict) -> bool:
    ver = str((task or {}).get('decrypt_version') or '').strip().lower()
    kind = str((options or {}).get('task_kind') or '').strip().lower()
    return ver in ('key', 'dynkey', 'dynamic_key_extract') or kind == 'dynamic_key_extract' or _iapt_truthy((options or {}).get('dynamic_key_extract'))


def _iapt_v40_run_dynamic_key_task(task_id: int, task: dict, options: dict):
    started = time.time()
    task_no = str(task.get('task_no') or task_id)
    upload_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    out_dir = APP_STORAGE / 'tasks' / task_no
    log_path = APP_STORAGE / 'tasks' / f'{task_no}.log'

    try:
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        db.exec(
            "UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='dynkey' WHERE id=%s",
            (str(out_dir), str(log_path), int(task_id)),
        )

        if not upload_path.is_file() or upload_path.stat().st_size <= 0:
            raise RuntimeError('动态Key任务上传文件不存在或为空')

        with _decrypt_semaphore:
            source_data = upload_path.read_bytes()
            from .dynamic_key_pool import (
                extract_all_so_from_bytes,
                extract_primary_key,
                key_text_multi,
                ensure_verified_key,
            )
            libraries = extract_all_so_from_bytes(
                source_data,
                str(options.get('original_filename') or task.get('apk_name') or 'libygsiyu.so'),
            )
            results = []
            pool_refs = []
            success_count = 0
            grouped = {}
            from .dynamic_key_pool import so_feature_sha256, normalize_feature_map
            for row in libraries:
                entry_name = str(row.get('entry_name') or 'libygsiyu.so')
                abi = str(row.get('abi') or 'unknown')
                so_data = bytes(row.get('data') or b'')
                item = {'entry_name': entry_name, 'abi': abi}
                try:
                    post_key, xor_key, extract_meta = extract_primary_key(so_data)
                    item.update({
                        'post_key': post_key,
                        'xor_key': xor_key,
                        'post_candidates': int(extract_meta.get('post_candidates') or 0),
                        'xor_candidates': int(extract_meta.get('xor_candidates') or 0),
                        'post_candidate_values': list(extract_meta.get('post_candidate_values') or []),
                        'xor_candidate_values': list(extract_meta.get('xor_candidate_values') or []),
                        'ambiguous': bool(extract_meta.get('ambiguous')),
                    })
                    pair = (post_key, xor_key)
                    group = grouped.setdefault(pair, {
                        'features': {},
                        'source_sha256': str(row.get('sha256') or hashlib.sha256(so_data).hexdigest()),
                        'source_name': (str(options.get('original_filename') or '') + '::' + entry_name)[:255],
                    })
                    group['features'][abi] = so_feature_sha256(so_data)
                    success_count += 1
                except Exception as exc:
                    item['error'] = f'{type(exc).__name__}: {exc}'
                results.append(item)

            if success_count > 0:
                client_features = normalize_feature_map(
                    options.get('dynamic_key_features'),
                    version=_iapt_vfp_feature_version(options),
                )
                # A normal client auto-extract upload contains one SO plus all ABI
                # fingerprints.  Validate that one SO before accepting the rest.
                if len(libraries) == 1 and client_features and len(grouped) == 1:
                    selected_abi = str(libraries[0].get('abi') or 'unknown').strip().lower()
                    hinted_abi = str(options.get('dynamic_key_sample_abi') or '').strip().lower()
                    if hinted_abi in client_features:
                        selected_abi = hinted_abi
                    server_sha = so_feature_sha256(bytes(libraries[0].get('data') or b''))
                    if client_features.get(selected_abi) != server_sha:
                        raise RuntimeError('客户端动态库指纹与上传 SO 不一致')
                    # One analysed SO learns every ABI fingerprint computed from the
                    # original APK, so the resulting scheme is not left with only one
                    # architecture.
                    next(iter(grouped.values()))['features'] = client_features

                for (post_key, xor_key), group in grouped.items():
                    stored = ensure_verified_key(
                        post_key,
                        xor_key,
                        source_type='standalone_extract',
                        source_sha256=str(group.get('source_sha256') or ''),
                        source_name=str(group.get('source_name') or ''),
                        user_id=int(task.get('user_id') or 0),
                        # Server extraction is directly trusted for pool learning.
                        features=group.get('features') or {},
                        normalizer_version=_iapt_vfp_feature_version(options),
                    )
                    if stored.get('public_id'):
                        pool_refs.append(str(stored.get('public_id')))

            if success_count <= 0:
                failures = '; '.join(
                    f"{x.get('abi')}:{x.get('entry_name')}={x.get('error')}" for x in results
                )
                raise RuntimeError('全部 libygsiyu.so 均未提取到动态Key：' + failures[:3000])

            # The task output directory contains only key.txt.  The standard task
            # downloader therefore produces <source>.zip with key.txt at ZIP root.
            (out_dir / 'key.txt').write_bytes(key_text_multi(results))

        elapsed_ms = int((time.time() - started) * 1000)
        log_lines = [
            '[IAPT_V40_DYNAMIC_KEY_MULTI_ABI_TASK]',
            f'task_id={int(task_id)}',
            f'source={str(options.get("original_filename") or "libygsiyu.so")}',
            f'libraries_total={len(results)}',
            f'libraries_success={success_count}',
            f'libraries_failed={len(results) - success_count}',
            f'pool_entries={len(set(pool_refs))}',
            f'elapsed_ms={elapsed_ms}',
            'result=key.txt',
        ]
        for index, item in enumerate(results, 1):
            status = 'ok' if not item.get('error') else 'failed'
            log_lines.append(
                f'lib[{index}]={item.get("abi")}|{item.get("entry_name")}|{status}'
            )
        log_path.write_text('\n'.join(log_lines) + '\n', encoding='utf-8')
        count, total = scan_files(int(task_id), out_dir)
        db.exec(
            """
            UPDATE tasks SET status='done',app_name=%s,file_count=%s,total_bytes=%s,
                total_ms=%s,error_text=NULL,out_dir=%s,log_path=%s,decrypt_version='dynkey'
            WHERE id=%s
            """,
            (f'动态Key提取（{success_count}/{len(results)}库）', count, total, elapsed_ms, str(out_dir), str(log_path), int(task_id)),
        )
        settle_decrypt_quota_once(int(task_id))
        return {
            'ok': True,
            'task_id': int(task_id),
            'status': 'done',
            'file_count': count,
            'total_bytes': total,
            'library_count': len(results),
            'success_count': success_count,
            'elapsed_ms': elapsed_ms,
        }
    except Exception as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        reason = '动态Key提取失败：' + str(exc)
        try:
            log_path.write_text(
                '[IAPT_V40_DYNAMIC_KEY_MULTI_ABI_FAILED]\n' + reason + f'\nelapsed_ms={elapsed_ms}\n',
                encoding='utf-8',
            )
        except Exception:
            pass
        db.exec(
            "UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,out_dir=%s,log_path=%s,decrypt_version='dynkey' WHERE id=%s",
            (elapsed_ms, reason[-4000:], str(out_dir), str(log_path), int(task_id)),
        )
        return {'ok': False, 'task_id': int(task_id), 'status': 'failed', 'error': reason}

def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),)) or {}
    try:
        options = json.loads(task.get('options_json') or '{}')
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_v39_is_dynamic_key_task(task, options):
        return _iapt_v40_run_dynamic_key_task(int(task_id), task, options)
    return _IAPT_V39_BASE_RUN_TASK(int(task_id))
# IAPT_V40_DYNAMIC_KEY_MULTI_ABI_TASK_END

# IAPT_V56_STANDALONE_SERVER_SOKEY_TASK_BEGIN
_IAPT_V56_BASE_RUN_TASK = run_task


def _iapt_v56_is_server_sokey_task(task: dict, options: dict) -> bool:
    ver = str((task or {}).get('decrypt_version') or (options or {}).get('decrypt_version') or '').strip().lower()
    kind = str((options or {}).get('task_kind') or '').strip().lower()
    return (
        ver in ('sokey', 'server_sokey_extract')
        or kind == 'server_sokey_extract'
        or _iapt_truthy((options or {}).get('server_sokey_extract'))
    )


def _iapt_v56_run_server_sokey_task(task_id: int, task: dict, options: dict):
    started = time.time()
    task_no = str(task.get('task_no') or task_id)
    upload_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    out_dir = APP_STORAGE / 'tasks' / task_no
    log_path = APP_STORAGE / 'tasks' / f'{task_no}.log'

    try:
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        db.exec(
            "UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='sokey' WHERE id=%s",
            (str(out_dir), str(log_path), int(task_id)),
        )

        if not upload_path.is_file() or upload_path.stat().st_size <= 0:
            raise RuntimeError('SO Key 任务上传文件不存在或为空')

        with _decrypt_semaphore:
            source_data = upload_path.read_bytes()
            from .dynamic_key_pool import extract_all_so_from_bytes
            from .tools.iapt_sokey_static_v2 import extract_sokey_from_so_bytes

            libraries = extract_all_so_from_bytes(
                source_data,
                str(options.get('original_filename') or task.get('apk_name') or 'libygsiyu.so'),
            )
            results = []
            successful = []
            for row in libraries:
                entry_name = str(row.get('entry_name') or 'libygsiyu.so')
                abi = str(row.get('abi') or 'unknown')
                so_data = bytes(row.get('data') or b'')
                item = {'entry_name': entry_name, 'abi': abi}
                try:
                    value, metadata = extract_sokey_from_so_bytes(so_data, label=entry_name)
                    sokey = value.decode('ascii', 'strict') if isinstance(value, bytes) else str(value or '').strip()
                    if not re.fullmatch(r'[A-Za-z0-9]{10}Q{10}W{10}EE', sokey):
                        raise RuntimeError('提取结果不符合 SO Key 格式')
                    item.update({
                        'sokey': sokey,
                        'strategy': str((metadata or {}).get('strategy') or ''),
                        'offset': (metadata or {}).get('offset'),
                        'so_sha256': str((metadata or {}).get('so_sha256') or row.get('sha256') or ''),
                    })
                    successful.append(item)
                except Exception as exc:
                    item['error'] = f'{type(exc).__name__}: {exc}'
                results.append(item)

            if not successful:
                failures = '; '.join(
                    f"{x.get('abi')}:{x.get('entry_name')}={x.get('error')}" for x in results
                )
                raise RuntimeError('全部 libygsiyu.so 均未提取到 SO Key：' + failures[:3000])

            unique = sorted({str(item.get('sokey') or '') for item in successful if item.get('sokey')})
            if len(unique) != 1:
                details = ' | '.join(
                    f"{item.get('abi')}:{item.get('entry_name')}={item.get('sokey')}" for item in successful
                )
                raise RuntimeError('多 ABI SO Key 不一致：' + details[:3000])
            selected = unique[0]

            output = [
                selected,
                f'SOKEY={selected}',
                f'SOURCE={str(options.get("original_filename") or task.get("apk_name") or "libygsiyu.so")}',
                f'LIBRARIES_TOTAL={len(results)}',
                f'LIBRARIES_SUCCESS={len(successful)}',
                f'LIBRARIES_FAILED={len(results) - len(successful)}',
                '',
            ]
            for index, item in enumerate(results, 1):
                output.append(f'[{index}]')
                output.append(f'ABI={item.get("abi") or "unknown"}')
                output.append(f'ENTRY={item.get("entry_name") or "libygsiyu.so"}')
                if item.get('error'):
                    output.append('STATUS=failed')
                    output.append(f'ERROR={item.get("error")}')
                else:
                    output.append('STATUS=ok')
                    output.append(f'SOKEY={item.get("sokey")}')
                    output.append(f'STRATEGY={item.get("strategy") or "unknown"}')
                    output.append(f'SO_SHA256={item.get("so_sha256") or ""}')
                    if item.get('offset') is not None:
                        output.append(f'OFFSET={item.get("offset")}')
                output.append('')
            (out_dir / 'sokey.txt').write_text('\n'.join(output), encoding='utf-8')

        elapsed_ms = int((time.time() - started) * 1000)
        log_lines = [
            '[IAPT_V56_STANDALONE_SERVER_SOKEY_TASK]',
            f'task_id={int(task_id)}',
            f'source={str(options.get("original_filename") or "libygsiyu.so")}',
            f'libraries_total={len(results)}',
            f'libraries_success={len(successful)}',
            f'libraries_failed={len(results) - len(successful)}',
            f'sokey={selected}',
            f'elapsed_ms={elapsed_ms}',
            'result=sokey.txt',
        ]
        for index, item in enumerate(results, 1):
            status = 'ok' if not item.get('error') else 'failed'
            log_lines.append(f'lib[{index}]={item.get("abi")}|{item.get("entry_name")}|{status}')
        log_path.write_text('\n'.join(log_lines) + '\n', encoding='utf-8')

        count, total = scan_files(int(task_id), out_dir)
        db.exec(
            """
            UPDATE tasks SET status='done',app_name=%s,file_count=%s,total_bytes=%s,
                total_ms=%s,error_text=NULL,out_dir=%s,log_path=%s,decrypt_version='sokey'
            WHERE id=%s
            """,
            (
                f'服务器 SO Key 提取（{len(successful)}/{len(results)}库）',
                count, total, elapsed_ms, str(out_dir), str(log_path), int(task_id),
            ),
        )
        settle_decrypt_quota_once(int(task_id))
        return {
            'ok': True,
            'task_id': int(task_id),
            'status': 'done',
            'file_count': count,
            'total_bytes': total,
            'library_count': len(results),
            'success_count': len(successful),
            'sokey': selected,
            'elapsed_ms': elapsed_ms,
        }
    except Exception as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        reason = '服务器 SO Key 提取失败：' + str(exc)
        try:
            log_path.write_text(
                '[IAPT_V56_STANDALONE_SERVER_SOKEY_FAILED]\n' + reason + f'\nelapsed_ms={elapsed_ms}\n',
                encoding='utf-8',
            )
        except Exception:
            pass
        db.exec(
            "UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,out_dir=%s,log_path=%s,decrypt_version='sokey' WHERE id=%s",
            (elapsed_ms, reason[-4000:], str(out_dir), str(log_path), int(task_id)),
        )
        return {'ok': False, 'task_id': int(task_id), 'status': 'failed', 'error': reason}


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),)) or {}
    try:
        options = json.loads(task.get('options_json') or '{}')
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_v56_is_server_sokey_task(task, options):
        return _iapt_v56_run_server_sokey_task(int(task_id), task, options)
    return _IAPT_V56_BASE_RUN_TASK(int(task_id))
# IAPT_V56_STANDALONE_SERVER_SOKEY_TASK_END

# IAPT_DYNAMIC_KEY_POOL_END_TO_END_V3_BEGIN
# Final wrapper: this block is intentionally last so every task route (normal V3,
# standalone dynamic-key extraction, local executor and Celery worker) passes
# through the same persistence/audit path.
_IAPT_POOL_E2E_BASE_RUN_TASK = run_task


def _iapt_pool_e2e_append_log(task: dict, line: str) -> None:
    try:
        path = Path(str((task or {}).get("log_path") or ""))
        if not path:
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8", errors="replace") as fp:
            fp.write("\n" + str(line).rstrip() + "\n")
    except Exception:
        pass


def _iapt_pool_e2e_hex(value) -> str:
    text = re.sub(r"\s+", "", str(value or "")).lower()
    if text and len(text) % 2 == 0 and re.fullmatch(r"[0-9a-f]+", text):
        return text
    return ""


def _iapt_pool_e2e_options(task: dict) -> dict:
    try:
        value = json.loads((task or {}).get("options_json") or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _iapt_pool_e2e_out_dir(task: dict) -> Path:
    raw = str((task or {}).get("out_dir") or "").strip()
    if raw:
        return Path(raw)
    return APP_STORAGE / "tasks" / str((task or {}).get("task_no") or "")


def _iapt_pool_e2e_manifest_pair(out_dir: Path) -> list[dict]:
    path = Path(out_dir) / ".tmp" / "verified_dynamic_key.json"
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(obj, dict) or obj.get("verified") is not True:
            return []
        post = _iapt_pool_e2e_hex(obj.get("post_key"))
        xor = _iapt_pool_e2e_hex(obj.get("key_xor"))
        if not post or not xor:
            return []
        return [{
            "post_key": post,
            "xor_key": xor,
            "abi": "",
            "origin": "verified_manifest",
            "key_source": str(obj.get("key_source") or "verified-decrypt"),
        }]
    except Exception:
        return []


def _iapt_pool_e2e_log_pair(task: dict) -> list[dict]:
    try:
        path = Path(str((task or {}).get("log_path") or ""))
        text = path.read_text(encoding="utf-8", errors="ignore") if path.is_file() else ""
    except Exception:
        text = ""
    post_matches = re.findall(r"SLKY_POST_KEY\s*=\s*([0-9a-fA-F]+)", text, flags=re.I)
    xor_matches = re.findall(r"(?:KEY_XOR_CONST|KEY_XOR|xor_key)\s*=\s*([0-9a-fA-F]+)", text, flags=re.I)
    post = _iapt_pool_e2e_hex(post_matches[-1] if post_matches else "")
    xor = _iapt_pool_e2e_hex(xor_matches[-1] if xor_matches else "")
    if not post or not xor:
        return []
    source = ""
    source_matches = re.findall(r"KEY_SOURCE\s*=\s*([^\s\r\n]+)", text, flags=re.I)
    if source_matches:
        source = str(source_matches[-1])
    return [{
        "post_key": post,
        "xor_key": xor,
        "abi": "",
        "origin": "task_log",
        "key_source": source,
    }]


def _iapt_pool_e2e_key_file_pairs(out_dir: Path) -> list[dict]:
    path = Path(out_dir) / "key.txt"
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []
    rows, current = [], {"abi": ""}
    for raw in lines + [""]:
        line = raw.strip()
        m = re.match(r"^\[([^\]]+)\]", line)
        if m:
            if current.get("post_key") and current.get("xor_key"):
                rows.append(dict(current))
            current = {"abi": str(m.group(1) or "").strip().lower()}
            continue
        if line.lower().startswith("post_key:"):
            current["post_key"] = _iapt_pool_e2e_hex(line.split(":", 1)[1])
        elif line.lower().startswith("xor_key:"):
            current["xor_key"] = _iapt_pool_e2e_hex(line.split(":", 1)[1])
        elif not line and current.get("post_key") and current.get("xor_key"):
            rows.append(dict(current))
            current = {"abi": ""}
    for row in rows:
        row["origin"] = "standalone_key_file"
        row["key_source"] = "standalone_extract"
    return rows


def _iapt_pool_e2e_pairs(task: dict, options: dict, out_dir: Path) -> list[dict]:
    kind = str(options.get("task_kind") or "").strip().lower()
    ver = str((task or {}).get("decrypt_version") or options.get("decrypt_version") or "").strip().lower()
    standalone = kind == "dynamic_key_extract" or ver in ("key", "dynkey", "dynamic_key_extract")
    rows = _iapt_pool_e2e_key_file_pairs(out_dir) if standalone else []
    if not rows:
        rows = _iapt_pool_e2e_manifest_pair(out_dir)
    if not rows:
        rows = _iapt_pool_e2e_log_pair(task)
    out, seen = [], set()
    for row in rows:
        post = _iapt_pool_e2e_hex(row.get("post_key"))
        xor = _iapt_pool_e2e_hex(row.get("xor_key"))
        abi = str(row.get("abi") or "").strip().lower()
        key = (post, xor, abi)
        if not post or not xor or key in seen:
            continue
        seen.add(key)
        clean = dict(row)
        clean.update({"post_key": post, "xor_key": xor, "abi": abi})
        out.append(clean)
    return out


def _iapt_pool_e2e_server_features(task: dict, options: dict) -> tuple[dict, dict]:
    """Return (all_features, features_by_abi), recomputed from the server upload."""
    from .dynamic_key_pool import extract_all_so_from_bytes, normalize_feature_map, so_feature_sha256
    version = _iapt_vfp_feature_version(options) if "_iapt_vfp_feature_version" in globals() else 1
    upload = APP_STORAGE / "uploads" / (str((task or {}).get("task_no") or "") + ".apk")
    all_features, by_abi = {}, {}
    if upload.is_file():
        try:
            for item in extract_all_so_from_bytes(
                upload.read_bytes(), str((task or {}).get("apk_name") or upload.name)
            ):
                abi = str(item.get("abi") or "unknown").strip().lower()
                data = bytes(item.get("data") or b"")
                if not data:
                    continue
                sha = so_feature_sha256(data)
                if abi not in all_features:
                    all_features[abi] = sha
                by_abi.setdefault(abi, {})[abi] = sha
        except Exception as exc:
            logger.warning("pool e2e server feature rebuild failed task=%s: %s", task.get("id"), exc)
    if not all_features:
        all_features = normalize_feature_map(
            options.get("dynamic_key_features"), version=version
        )
        by_abi = {abi: {abi: sha} for abi, sha in all_features.items()}
    return all_features, by_abi


def _iapt_pool_e2e_dynamic_intent(task: dict, options: dict) -> bool:
    if int((task or {}).get("feature_id") or options.get("feature_id") or 0) == 4:
        return True
    kind = str(options.get("task_kind") or "").strip().lower()
    ver = str((task or {}).get("decrypt_version") or options.get("decrypt_version") or "").strip().lower()
    if kind == "dynamic_key_extract" or ver in ("key", "dynkey", "dynamic_key_extract"):
        return True
    for name in (
        "dynamic_key", "server_dynamic_key", "enable_dynamic_key",
        "custom_dynamic_key", "post_key", "key_xor",
    ):
        if options.get(name):
            return True
    return False


def _iapt_pool_e2e_should_sync(task: dict, options: dict, pairs: list[dict]) -> bool:
    return bool(pairs) and _iapt_pool_e2e_dynamic_intent(task, options)


def _iapt_pool_e2e_sync_task(task_id: int, *, force: bool = False) -> dict:
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    if not task:
        return {"ok": False, "task_id": int(task_id), "reason": "task-not-found"}
    if str(task.get("status") or "").strip().lower() != "done":
        return {"ok": False, "task_id": int(task_id), "reason": "task-not-done"}
    if int(task.get("feature_id") or 0) in (6, 8):
        return {"ok": False, "task_id": int(task_id), "reason": "unsupported-feature"}

    options = _iapt_pool_e2e_options(task)
    out_dir = _iapt_pool_e2e_out_dir(task)
    pairs = _iapt_pool_e2e_pairs(task, options, out_dir)
    intent = _iapt_pool_e2e_dynamic_intent(task, options)
    if not force and not intent:
        return {"ok": False, "task_id": int(task_id), "reason": "not-dynamic"}
    if not pairs:
        _iapt_pool_e2e_append_log(task, "[IAPT_DYNAMIC_KEY_POOL] failed: verified key result missing")
        return {"ok": False, "task_id": int(task_id), "reason": "verified-key-missing"}

    from .dynamic_key_pool import ensure_verified_key, visible_verified_count
    all_features, by_abi = _iapt_pool_e2e_server_features(task, options)
    version = _iapt_vfp_feature_version(options) if "_iapt_vfp_feature_version" in globals() else 1
    # Group identical pairs before saving.  A multi-ABI extraction commonly
    # reports the same pair four times; all ABI fingerprints belong to one pool
    # scheme and must be persisted in a single call.
    grouped_pairs = {}
    for pair in pairs:
        group_key = (pair["post_key"], pair["xor_key"])
        group = grouped_pairs.setdefault(group_key, {
            "post_key": pair["post_key"],
            "xor_key": pair["xor_key"],
            "abis": [],
            "origins": [],
            "key_sources": [],
        })
        abi = str(pair.get("abi") or "").strip().lower()
        if abi and abi not in group["abis"]:
            group["abis"].append(abi)
        origin = str(pair.get("origin") or "")
        if origin and origin not in group["origins"]:
            group["origins"].append(origin)
        key_source = str(pair.get("key_source") or "")
        if key_source and key_source not in group["key_sources"]:
            group["key_sources"].append(key_source)

    results = []
    for group in grouped_pairs.values():
        features = {}
        if group["abis"]:
            for abi in group["abis"]:
                features.update(by_abi.get(abi) or {})
        else:
            features = dict(all_features or {})
        if not features:
            features = dict(all_features or {})
        custom = bool(options.get("custom_dynamic_key") or options.get("post_key") or options.get("key_xor"))
        key_sources = [str(x).strip().lower() for x in group["key_sources"] if str(x).strip()]
        if custom:
            in_post = _iapt_pool_e2e_hex(options.get("post_key"))
            in_xor = _iapt_pool_e2e_hex(options.get("key_xor"))
            if key_sources and "manual-strict" not in key_sources:
                _iapt_pool_e2e_append_log(task, "[IAPT_DYNAMIC_KEY_POOL] skipped: custom key was not manual-strict")
                continue
            if in_post and group["post_key"] != in_post:
                continue
            if in_xor and group["xor_key"] != in_xor:
                continue
        standalone = "standalone_key_file" in group["origins"]
        source_type = "standalone_extract" if standalone else (
            "custom_verified" if custom else "server_dynamic_success"
        )
        stored = ensure_verified_key(
            group["post_key"],
            group["xor_key"],
            source_type=source_type,
            source_sha256=str(task.get("apk_sha256") or options.get("source_sha256") or ""),
            source_name=str(task.get("apk_name") or options.get("original_filename") or ""),
            user_id=int(task.get("user_id") or 0),
            features=features or {},
            normalizer_version=version,
        )
        item = {
            "ref": stored.get("public_id"),
            "id": stored.get("id"),
            "created": bool(stored.get("created")),
            "already_present": bool(stored.get("already_present")),
            "feature_count": int(stored.get("feature_count") or 0),
            "abis": list(group["abis"]),
            "origins": list(group["origins"]),
        }
        results.append(item)
        _iapt_pool_e2e_append_log(
            task,
            "[IAPT_DYNAMIC_KEY_POOL] stored "
            f"ref={item['ref']} id={item['id']} created={item['created']} "
            f"already_present={item['already_present']} features={item['feature_count']} "
            f"abis={','.join(item['abis']) or 'all'} origins={','.join(item['origins'])}",
        )
    if not results:
        return {"ok": False, "task_id": int(task_id), "reason": "no-pair-persisted"}
    return {
        "ok": True,
        "task_id": int(task_id),
        "stored": results,
        "visible_verified_count": visible_verified_count(),
    }


def reconcile_dynamic_key_pool(limit: int = 200) -> dict:
    limit = max(1, min(int(limit or 200), 2000))
    rows = db.all(
        "SELECT id FROM tasks WHERE status='done' ORDER BY id DESC LIMIT " + str(limit)
    ) or []
    checked = stored = failed = 0
    details = []
    for row in rows:
        task_id = int(row.get("id") or 0)
        if task_id <= 0:
            continue
        checked += 1
        try:
            result = _iapt_pool_e2e_sync_task(task_id)
            if result.get("ok"):
                stored += 1
                details.append({"task_id": task_id, "ok": True, "count": len(result.get("stored") or [])})
        except Exception as exc:
            failed += 1
            details.append({"task_id": task_id, "ok": False, "error": str(exc)[:500]})
            task = db.one("SELECT * FROM tasks WHERE id=%s", (task_id,)) or {}
            _iapt_pool_e2e_append_log(task, "[IAPT_DYNAMIC_KEY_POOL] failed: " + str(exc))
    from .dynamic_key_pool import visible_verified_count
    return {
        "ok": failed == 0,
        "checked": checked,
        "stored_tasks": stored,
        "failed": failed,
        "visible_verified_count": visible_verified_count(),
        "details": details[-50:],
    }


def run_task(task_id: int):
    result = _IAPT_POOL_E2E_BASE_RUN_TASK(int(task_id))
    try:
        _iapt_pool_e2e_sync_task(int(task_id))
    except Exception as exc:
        task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
        _iapt_pool_e2e_append_log(task, "[IAPT_DYNAMIC_KEY_POOL] failed: " + str(exc))
        logger.exception("dynamic key end-to-end pool sync failed task=%s", task_id)
    return result
# IAPT_DYNAMIC_KEY_POOL_END_TO_END_V3_END

# IAPT_IACT_DYNAMIC_RESTORE_V1_BEGIN

def _iapt_iact_restore_is_task(task: dict, options: dict) -> bool:
    options = options if isinstance(options, dict) else {}
    version = str(options.get('decrypt_version') or task.get('decrypt_version') or '').strip().lower()
    return _iapt_source_restore_truthy(options.get('iact_dynamic_decrypt')) or version in ('iact', 'iact_restore')


def _iapt_run_iact_restore_task(task_id: int, task: dict, options: dict) -> None:
    src_zip = APP_STORAGE / 'uploads' / f"{task['task_no']}.apk"
    out_dir = APP_STORAGE / 'tasks' / task['task_no']
    log_path = APP_STORAGE / 'tasks' / f"{task['task_no']}.log"
    tmp_root = APP_STORAGE / 'tmp'
    tmp_root.mkdir(parents=True, exist_ok=True)
    work_dir = Path(tempfile.mkdtemp(prefix='iact_restore_', dir=str(tmp_root)))
    db.exec("UPDATE tasks SET status='running', out_dir=%s, log_path=%s, feature_id=5, decrypt_version='iact' WHERE id=%s", (str(out_dir), str(log_path), task_id))
    started = time.perf_counter()
    try:
        if not src_zip.exists() or src_zip.stat().st_size <= 0:
            raise RuntimeError('源码 ZIP 不存在或为空')
        shutil.rmtree(out_dir, ignore_errors=True)
        layout_report = _iapt_extract_zip_to_dir(src_zip, out_dir)
        from .tools.iapt_iact_dynamic_restore import restore_tree
        report = restore_tree(out_dir / 'src', write_report=False)
        private_report = out_dir / '.tmp' / 'iact_dynamic_restore_report.json'
        private_report.parent.mkdir(parents=True, exist_ok=True)
        private_report.write_text(
            json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True) + '\n',
            encoding='utf-8',
        )
        count, total = scan_files(task_id, out_dir)
        total_ms = (time.perf_counter() - started) * 1000.0
        log_path.write_text(
            '### IAPT iACT dynamic restore\n'
            f'src={src_zip}\n'
            'dex_uploaded=false\n'
            f'layout={json.dumps(layout_report, ensure_ascii=False, sort_keys=True)}\n'
            f'mapping_version={report.get("mapping_version")}\n'
            f'mapping_pairs={report.get("mapping_pairs")}\n'
            f'changed_files={report.get("changed_files")}\n'
            f'replacements={report.get("replacement_count")}\n'
            f'files={count}\nbytes={total}\ntotal_ms={total_ms:.2f}\n',
            encoding='utf-8', errors='replace',
        )
        db.exec('''
            UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
            version_name=%s, version_code=%s, feature_id=5, decrypt_version='iact'
            WHERE id=%s
        ''', (float(total_ms), 'iACT动态解密', '', 'iact_restore', '', task_id))
        settle_decrypt_quota_once(task_id)
    except Exception as exc:
        reason = 'iACT动态解密失败：' + str(exc)
        try:
            log_path.write_text(reason, encoding='utf-8', errors='replace')
        except Exception:
            pass
        db.exec("UPDATE tasks SET status='failed', error_text=%s, feature_id=5, decrypt_version='iact' WHERE id=%s", (reason, task_id))
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


_IAPT_IACT_PREV_RUN_TASK = run_task


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if task:
        try:
            options = json.loads(task.get('options_json') or '{}')
            if not isinstance(options, dict):
                options = {}
        except Exception:
            options = {}
        if _iapt_iact_restore_is_task(task, options):
            return _iapt_run_iact_restore_task(int(task_id), task, options)
    return _IAPT_IACT_PREV_RUN_TASK(int(task_id))
# IAPT_IACT_DYNAMIC_RESTORE_V1_END

# IAPT_HIDDEN_RESOURCE_RESTORE_V6_BEGIN
# Feature 17 is a static QiuShui resource-container normalizer. It must not
# change the user's dynamic-restore/deobfuscation choice. In particular,
# --restore-fn-names off is only injected when dynamic/source restore is NOT
# enabled; if dynamic restore is enabled, keep or synchronize its own mode.
_IAPT_HIDDEN_RESOURCE_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process


def _iapt_hidden_resource_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on', 'y')
    return False


def _iapt_hidden_resource_requested(options, task) -> bool:
    options = options if isinstance(options, dict) else {}
    return (
        _iapt_hidden_resource_truthy(options.get('anti_qiushui'))
        or _iapt_hidden_resource_truthy(options.get('hidden_resource_restore'))
    )


def _iapt_hidden_resource_should_skip(cmd, options, task) -> bool:
    return not _iapt_hidden_resource_requested(options, task)


def _iapt_hidden_resource_restore_mode(options: dict) -> str:
    options = options if isinstance(options, dict) else {}
    return str(options.get('restore_fn_names') or '').strip().lower()


def _iapt_hidden_resource_explicit_restore(options: dict) -> bool:
    options = options if isinstance(options, dict) else {}
    restore_mode = _iapt_hidden_resource_restore_mode(options)
    return (
        restore_mode not in ('', 'off', 'false', '0', 'none')
        or _iapt_hidden_resource_truthy(options.get('dex_static_restore'))
        or _iapt_hidden_resource_truthy(options.get('numeric_restore'))
        or _iapt_hidden_resource_truthy(options.get('dynamic_restore'))
    )


def _iapt_hidden_resource_clean_options(options: dict) -> dict:
    out = dict(options or {})
    for key in (
        'client_cipher_entry', 'client_cipher_locator',
        'client_cipher_obfuscated', 'client_cipher_sidecar_entries',
        'client_cipher_sidecar_count', 'client_cipher_size',
        'client_lib_so_missing',
    ):
        out.pop(key, None)
    out['anti_qiushui'] = True
    out['hidden_resource_restored'] = True
    out['hidden_resource_restore_version'] = 6

    # Feature17 only normalizes the hidden lib/resource container. If the user
    # did NOT enable dynamic/source restore, explicitly disable restore output.
    # If the user DID enable dynamic/source restore, do not force off here.
    if not _iapt_hidden_resource_explicit_restore(out):
        out['restore_fn_names'] = 'off'
        out['dex_static_restore'] = False
        out['restore_props'] = False
        out['restore_events'] = False
        out['rename_vars'] = False
        out['rename_files'] = False
        out['rename_functions'] = False
        out['restore_resource_names'] = False
        out['auto_deobfuscate'] = False
        out['auto_obfuscation_restore'] = False
        out['deobfuscate'] = False
    return out


def _iapt_hidden_resource_desired_restore_cli(cleaned_options: dict):
    """Return restore-fn-names value to force, or None to leave command alone."""
    cleaned_options = cleaned_options if isinstance(cleaned_options, dict) else {}
    mode = _iapt_hidden_resource_restore_mode(cleaned_options)
    if not _iapt_hidden_resource_explicit_restore(cleaned_options):
        return 'off'
    if mode in ('', 'off', 'false', '0', 'none'):
        # Dynamic/static restore was enabled through another flag. In that case
        # do not append an off value; preserve the existing command's mode.
        return None
    return mode


def _iapt_hidden_resource_rewrite_cmd(
    cmd, old_apk: Path, new_apk: Path, cleaned_options: dict
) -> list:
    """Rewrite only the APK path, and force --restore-fn-names only when needed.

    --restore-fn-names off is a dynamic-restore control value. It is injected
    only for non-dynamic/non-source-restore decrypt tasks to stop the old hard
    coded auto restore path. When dynamic restore is enabled, this wrapper must
    not turn it off.
    """
    old_text, new_text = str(old_apk), str(new_apk)
    raw = [str(x) for x in (cmd or [])]
    desired_restore = _iapt_hidden_resource_desired_restore_cli(cleaned_options)
    out = []
    index = 0
    while index < len(raw):
        value = raw[index]
        if value == old_text:
            out.append(new_text)
            index += 1
            continue
        if value == '--apk':
            out.append(value)
            if index + 1 < len(raw):
                out.append(new_text)
                index += 2
            else:
                out.append(new_text)
                index += 1
            continue
        if desired_restore is not None and value == '--restore-fn-names':
            index += 2 if index + 1 < len(raw) else 1
            continue
        if desired_restore is not None and value.startswith('--restore-fn-names='):
            index += 1
            continue
        out.append(value)
        index += 1

    if desired_restore is not None:
        out.extend(['--restore-fn-names', desired_restore])
    return out


def _iapt_hidden_resource_log(report: dict) -> str:
    compact = {
        'algorithm': report.get('algorithm'),
        'cipher_size': report.get('cipher_size'),
        'sidecar_size': report.get('sidecar_size'),
        'inner_zip_size': report.get('inner_zip_size'),
        'inner_entry_count': report.get('entry_count'),
        'assets_lib_size': report.get('assets_lib_size'),
        'assets_lib_sha256': report.get('assets_lib_sha256'),
        'overlay_mode': report.get('overlay_mode'),
        'overlay_count': report.get('overlay_count'),
        'normalized_apk_sha256': report.get('normalized_apk_sha256'),
    }
    return '[IAPT_ANTI_QIUSHUI] ' + json.dumps(
        compact, ensure_ascii=False, sort_keys=True, default=str
    ) + '\n'


def _iapt_hidden_resource_missing(reason: str = '') -> _IaptProcResult:
    detail = str(reason or '').strip()
    text = '没有找到lib.so文件'
    if detail:
        text = '[IAPT_ANTI_QIUSHUI] ' + detail[:1000] + '\n' + text
    return _IaptProcResult(2, text + '\n')


def run_decrypt_process(
    cmd: list,
    apk_path: Path,
    out_dir: Path,
    options: dict,
    task: dict,
    env: dict | None = None,
) -> _IaptProcResult:
    if _iapt_hidden_resource_should_skip(cmd, options, task):
        return _IAPT_HIDDEN_RESOURCE_PREV_RUN_DECRYPT_PROCESS(
            cmd, apk_path, out_dir, options, task, env=env
        )

    work_dir = None
    try:
        from .tools.iapt_hidden_resource_restore import maybe_build_normalized_apk

        cleaned_options = _iapt_hidden_resource_clean_options(options)
        tmp_root = APP_STORAGE / 'tmp'
        tmp_root.mkdir(parents=True, exist_ok=True)
        work_dir = Path(tempfile.mkdtemp(prefix='anti_qiushui_', dir=str(tmp_root)))
        normalized_apk = work_dir / 'normalized.apk'
        report = maybe_build_normalized_apk(apk_path, normalized_apk, options)

        if not report.get('normalized'):
            reason = str(report.get('reason') or 'unknown')
            if reason == 'canonical-container-present':
                command = _iapt_hidden_resource_rewrite_cmd(
                    cmd, Path(apk_path), Path(apk_path), cleaned_options
                )
                return _IAPT_HIDDEN_RESOURCE_PREV_RUN_DECRYPT_PROCESS(
                    command, apk_path, out_dir,
                    cleaned_options, task, env=env
                )
            return _iapt_hidden_resource_missing(reason)

        command = _iapt_hidden_resource_rewrite_cmd(
            cmd, Path(apk_path), normalized_apk, cleaned_options
        )
        result = _IAPT_HIDDEN_RESOURCE_PREV_RUN_DECRYPT_PROCESS(
            command,
            normalized_apk,
            out_dir,
            cleaned_options,
            task,
            env=env,
        )
        result.stdout = _iapt_hidden_resource_log(report) + (result.stdout or '')
        return result
    except Exception as exc:
        logger.exception('anti-QiuShui lib.so extraction failed')
        return _iapt_hidden_resource_missing(
            type(exc).__name__ + ': ' + str(exc)
        )
    finally:
        if work_dir is not None:
            shutil.rmtree(work_dir, ignore_errors=True)
# IAPT_HIDDEN_RESOURCE_RESTORE_V6_END

# IAPT_V3_DEXKEY_FALLBACK_DEOBF_SPLIT_V1_BEGIN
# 1. C dexkey 批处理仍作为快速路径，但未命中时必须允许 Python 验证回退。
# 2. 功能5动态修复只处理数字函数/DEX映射，不等于功能8源码混淆还原。
# 3. 普通 V3、动态 Key、sokey、枚举和反秋水任务均禁止自动重命名。
_IAPT_V3_FIX_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process


def _iapt_v3_fix_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in (
            "1", "true", "yes", "on", "auto", "enabled"
        )
    return False


def _iapt_v3_fix_int(value, default=0) -> int:
    try:
        return int(value)
    except Exception:
        return default


def _iapt_v3_fix_numeric(options, task) -> bool:
    options = options if isinstance(options, dict) else {}
    task = task if isinstance(task, dict) else {}

    feature_ids = (
        options.get("primary_feature_id"),
        options.get("feature_id"),
        task.get("feature_id"),
    )
    if any(_iapt_v3_fix_int(value) == 5 for value in feature_ids):
        return True

    return (
        _iapt_v3_fix_truthy(options.get("numeric_source_restore"))
        or _iapt_v3_fix_truthy(options.get("dynamic_restore"))
        or str(options.get("restore_fn_names") or "").strip().lower()
           in ("auto", "on", "true", "1")
    )


def _iapt_v3_fix_source_restore(options, task) -> bool:
    options = options if isinstance(options, dict) else {}
    task = task if isinstance(task, dict) else {}

    feature_ids = (
        options.get("primary_feature_id"),
        options.get("feature_id"),
        task.get("feature_id"),
    )
    if any(_iapt_v3_fix_int(value) == 8 for value in feature_ids):
        return True

    version = str(
        options.get("decrypt_version")
        or options.get("task_version")
        or task.get("decrypt_version")
        or ""
    ).strip().lower()

    return (
        _iapt_v3_fix_truthy(options.get("source_restore"))
        or version in (
            "restore",
            "source_restore",
            "dex_restore",
            "static_dex_restore",
        )
    )


def _iapt_v3_fix_drop_flags(command, flags):
    flags = set(flags)
    result = []
    values = {"0", "1", "true", "false", "on", "off", "yes", "no"}
    index = 0

    while index < len(command):
        token = str(command[index])
        matched = False

        for flag in flags:
            if token == flag:
                matched = True
                index += 1
                if (
                    index < len(command)
                    and str(command[index]).strip().lower() in values
                ):
                    index += 1
                break

            if token.startswith(flag + "="):
                matched = True
                index += 1
                break

        if not matched:
            result.append(token)
            index += 1

    return result


def _iapt_v3_fix_force_value(command, flag, value):
    result = []
    index = 0
    found = False

    while index < len(command):
        token = str(command[index])

        if token == flag:
            result.extend((flag, value))
            found = True
            index += 2 if index + 1 < len(command) else 1
            continue

        if token.startswith(flag + "="):
            result.append(flag + "=" + value)
            found = True
            index += 1
            continue

        result.append(token)
        index += 1

    return result


def run_decrypt_process(
    cmd,
    apk_path,
    out_dir,
    options,
    task,
    env=None,
):
    import os

    opts = dict(options or {})
    task_data = task if isinstance(task, dict) else {}
    command = [str(value) for value in (cmd or [])]

    # 不允许客户端或旧任务再次强制 C-only。
    opts["no_python_fallback"] = False
    opts["python_fallback"] = True
    opts["allow_python_fallback"] = True
    opts["dexkey_python_fallback"] = True

    for key in (
        "disable_python_fallback",
        "c_only",
        "fixed_fast_only",
        "dexkey_c_only",
    ):
        opts.pop(key, None)

    command = _iapt_v3_fix_drop_flags(
        command,
        (
            "--no-python-fallback",
            "--disable-python-fallback",
            "--c-only",
            "--fixed-fast-only",
            "--dexkey-c-only",
        ),
    )

    numeric_restore = _iapt_v3_fix_numeric(opts, task_data)
    source_restore = _iapt_v3_fix_source_restore(opts, task_data)

    if numeric_restore:
        opts["numeric_source_restore"] = True
        opts["dynamic_restore"] = True

    # 功能8才允许变量、文件、函数、属性、事件和资源名混淆还原。
    if not source_restore:
        opts["source_restore"] = False
        opts["restore_props"] = False
        opts["restore_events"] = False
        opts["rename_vars"] = False
        opts["rename_files"] = False
        opts["rename_functions"] = False
        opts["restore_resource_names"] = False
        opts["auto_deobfuscate"] = False
        opts["auto_obfuscation_restore"] = False
        opts["deobfuscate"] = False

        command = _iapt_v3_fix_drop_flags(
            command,
            (
                "--source-restore",
                "--restore-props",
                "--restore-events",
                "--rename-vars",
                "--rename-files",
                "--rename-functions",
                "--restore-resource-names",
                "--auto-deobfuscate",
                "--auto-obfuscation-restore",
                "--deobfuscate",
            ),
        )

    # 未开启功能5时，数字函数恢复也必须关闭。
    if not numeric_restore and not source_restore:
        opts["restore_fn_names"] = "off"
        opts["dex_static_restore"] = False
        command = _iapt_v3_fix_force_value(
            command,
            "--restore-fn-names",
            "off",
        )
        command = _iapt_v3_fix_drop_flags(
            command,
            ("--dex-static-restore",),
        )

    runtime_env = dict(os.environ if env is None else env)
    for key in (
        "IAPT_NO_PYTHON_FALLBACK",
        "IAPT_DEXKEY_NO_PYTHON_FALLBACK",
        "IAPT_DEXKEY_C_ONLY",
        "IAPT_FIXED_FAST_ONLY",
    ):
        runtime_env.pop(key, None)

    runtime_env["IAPT_ALLOW_PYTHON_FALLBACK"] = "1"
    runtime_env["IAPT_DEXKEY_PYTHON_FALLBACK"] = "1"

    return _IAPT_V3_FIX_PREV_RUN_DECRYPT_PROCESS(
        command,
        apk_path,
        out_dir,
        opts,
        task,
        env=runtime_env,
    )
# IAPT_V3_DEXKEY_FALLBACK_DEOBF_SPLIT_V1_END

# IAPT_NO_DEFAULT_SOURCE_DEOBF_V4_BEGIN
# 普通 V3 / 反秋水解密不能在任务完成后再自动跑 iapp_deobfuscate。
# 之前即使命令行 --restore-fn-names off，decrypt_runner 仍会对所有 done 的 V3
# 输出套一层源码混淆还原，导致 page1.iyu/page2.iyu 等“原始界面名”被直接输出。
# 这里保留显式动态修复/DEX还原/源码还原，普通解密和功能17只做解密/资源前置恢复。
_IAPT_NO_DEFAULT_SOURCE_DEOBF_V4_PREV_APPLY = globals().get('_iapt_apply_source_deobfuscation_to_outdir')


def _iapt_no_default_deobf_v4_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ('1', 'true', 'yes', 'on', 'y')
    return False


def _iapt_no_default_deobf_v4_inline_v3_numeric(task: dict, options: dict) -> bool:
    task = task if isinstance(task, dict) else {}
    options = options if isinstance(options, dict) else {}
    ver = str(
        options.get('decrypt_version')
        or options.get('task_version')
        or task.get('decrypt_version')
        or 'v3'
    ).strip().lower()
    if ver not in ('', 'v3', '3', 'iapp_v3'):
        return False
    try:
        feature_ids = (
            int(options.get('primary_feature_id') or 0),
            int(options.get('feature_id') or 0),
            int(task.get('feature_id') or 0),
        )
    except Exception:
        feature_ids = (0,)
    numeric = (
        5 in feature_ids
        or _iapt_no_default_deobf_v4_truthy(options.get('v3_dynamic_restore'))
        or _iapt_no_default_deobf_v4_truthy(options.get('numeric_restore'))
        or _iapt_no_default_deobf_v4_truthy(options.get('dynamic_restore'))
        or str(options.get('restore_fn_names') or '').strip().lower() in ('auto', 'on', 'true', '1')
    )
    source_restore = (
        8 in feature_ids
        or _iapt_no_default_deobf_v4_truthy(options.get('source_restore'))
        or str(options.get('decrypt_version') or '').strip().lower() in (
            'restore', 'source_restore', 'dex_restore', 'static_dex_restore', 'source_dex_restore'
        )
    )
    return bool(numeric and not source_restore)


def _iapt_no_default_deobf_v4_explicit_restore(task: dict, options: dict) -> bool:
    task = task if isinstance(task, dict) else {}
    options = options if isinstance(options, dict) else {}

    # V3 动态修复已经在 iapp_auto_decrypt 的成员解密之后完成数字函数表替换。
    # 这里若再调用 iapp_deobfuscate，会把变量、文件、事件、资源名等也全量还原，
    # 正是“动态修复显示/运行成还原”的根因。
    if _iapt_no_default_deobf_v4_inline_v3_numeric(task, options):
        return False

    # These task versions are explicit restore/deobfuscation tasks, not ordinary V3 decrypt.
    ver = str(
        options.get('decrypt_version')
        or options.get('task_version')
        or task.get('decrypt_version')
        or ''
    ).strip().lower()
    if ver in ('restore', 'source_restore', 'fn_restore', 'numeric_restore',
               'dex_restore', 'static_dex_restore', 'source_dex_restore'):
        return True

    # restore_fn_names is the authoritative switch for normal decrypt output.
    restore_mode = str(options.get('restore_fn_names') or 'off').strip().lower()
    if restore_mode not in ('', 'off', 'false', '0', 'none'):
        return True

    # Numeric/dynamic/static restore flags must be explicit.  anti_qiushui / hidden_resource_restore
    # deliberately are NOT included here; feature17 is only a lib.so/resource pre-step.
    for key in (
        'dex_static_restore', 'numeric_restore', 'dynamic_restore',
        'source_restore', 'numeric_source_restore',
        'auto_deobfuscate', 'auto_obfuscation_restore', 'deobfuscate',
    ):
        if _iapt_no_default_deobf_v4_truthy(options.get(key)):
            return True

    # Fine-grained source-deobfuscate toggles only count when explicitly true.
    for key in (
        'restore_props', 'restore_events', 'rename_vars',
        'rename_files', 'rename_functions', 'restore_resource_names',
    ):
        if key in options and _iapt_no_default_deobf_v4_truthy(options.get(key)):
            return True
    return False


def _iapt_apply_source_deobfuscation_to_outdir(task_id: int, task: dict, options: dict) -> None:
    prev = _IAPT_NO_DEFAULT_SOURCE_DEOBF_V4_PREV_APPLY
    if not callable(prev):
        return None
    if _iapt_no_default_deobf_v4_explicit_restore(task, options):
        return prev(task_id, task, options)
    try:
        log_path = (task or {}).get('log_path') if isinstance(task, dict) else None
        if log_path:
            with open(log_path, 'a', encoding='utf-8', errors='replace') as f:
                if _iapt_no_default_deobf_v4_inline_v3_numeric(task, options):
                    f.write('\n[IAPT V3 dynamic-restore] numeric DEX-table replacement already completed inline; skipped full source deobfuscation\n')
                else:
                    f.write('\n[IAPT no-default-deobf V4] skipped source deobfuscation postprocess; restore_fn_names=off\n')
    except Exception:
        pass
    return None
# IAPT_NO_DEFAULT_SOURCE_DEOBF_V4_END

# IAPT_QIUSHUI_RESOURCE_EXPORT_V12_BEGIN
# Feature 17 exports only res/** after successful decrypt. assets/** remains
# private and ordinary decrypt/deobfuscation behavior is unchanged.
_IAPT_QS_RESOURCE_EXPORT_V12_PREV_RUN = globals().get("run_decrypt_process")


def _iapt_qs_resource_export_v12_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_qs_resource_export_v12_requested(options: dict, task: dict) -> bool:
    options = options if isinstance(options, dict) else {}
    task = task if isinstance(task, dict) else {}
    kind = str(options.get("task_kind") or task.get("task_kind") or "").strip().lower()
    version = str(options.get("decrypt_version") or options.get("task_version") or task.get("decrypt_version") or "").strip().lower()
    if kind in ("dynamic_key_extract", "server_sokey_extract", "standalone_so_extract", "standalone_dynamic_key_extract", "sokey_extract") or version in ("key", "dynkey", "dynamic_key_extract", "sokey", "server_sokey"):
        return False
    return any(_iapt_qs_resource_export_v12_truthy(options.get(k)) for k in (
        "anti_qiushui", "hidden_resource_restore", "hidden_resource_restored", "anti_qiushui_resource_export"
    ))


def run_decrypt_process(cmd: list, apk_path: Path, out_dir: Path, options: dict, task: dict, env: dict | None = None) -> _IaptProcResult:
    previous = _IAPT_QS_RESOURCE_EXPORT_V12_PREV_RUN
    if not callable(previous):
        raise RuntimeError("resource export wrapper: previous run_decrypt_process unavailable")
    result = previous(cmd, apk_path, out_dir, options, task, env=env)
    if int(getattr(result, "returncode", 1)) != 0 or not _iapt_qs_resource_export_v12_requested(options, task):
        return result
    try:
        from .tools.iapt_qiushui_resource_export import export_resources
        report = export_resources(Path(apk_path), Path(out_dir), options or {})
        compact = {
            "version": report.get("version"), "exported": report.get("exported"),
            "written_count": report.get("written_count"), "res_count": report.get("res_count"),
            "assets_res_count": report.get("assets_res_count"), "inner_available": report.get("inner_available"),
        }
        result.stdout = (result.stdout or "") + "\n[IAPT_QIUSHUI_RESOURCE_EXPORT] " + json.dumps(compact, ensure_ascii=False, sort_keys=True, default=str) + "\n"
    except Exception as exc:
        logger.exception("anti-QiuShui res export failed task=%s", (task or {}).get("id"))
        result.stdout = (result.stdout or "") + "\n[IAPT_QIUSHUI_RESOURCE_EXPORT][WARN] " + type(exc).__name__ + ": " + str(exc)[:1200] + "\n"
    return result
# IAPT_QIUSHUI_RESOURCE_EXPORT_V12_END

# IAPT_OUTPUT_SCOPE_V13_BEGIN
# IAPT_OUTPUT_SCOPE_RESOURCE_PUBLISH_FIX_V1
# Truth on disk is authoritative.  Targeted tasks are re-scanned before every
# preview/download so stale manifests cannot claim 77 files while only 38 exist.
# Public roots are intentionally strict:
#   anti-QiuShui / feature 17 -> res/**
#   source/DEX restore with resource restoration -> src/** + res/**
#   ordinary source output -> legacy src/** only
# assets/** is never public.

def _iapt_output_v13_truthy(value, default=False) -> bool:
    if value is None:
        return bool(default)
    if value is True or value == 1:
        return True
    if value is False or value == 0:
        return False
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("1", "true", "yes", "on", "y"):
            return True
        if low in ("0", "false", "no", "off", "n", "none", ""):
            return False
    return bool(default)


def _iapt_output_v13_options(task: dict) -> dict:
    task = task if isinstance(task, dict) else {}
    raw = task.get("options_json")
    if isinstance(raw, dict):
        return dict(raw)
    try:
        obj = json.loads(raw or "{}")
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _iapt_output_v13_is_qiushui(task: dict, options: dict) -> bool:
    for key in ("anti_qiushui", "hidden_resource_restore", "hidden_resource_restored", "anti_qiushui_resource_export"):
        if _iapt_output_v13_truthy(options.get(key)):
            return True
    for key in ("anti_qiushui_feature_id", "hidden_resource_feature_id"):
        try:
            if int(options.get(key) or 0) == 17:
                return True
        except Exception:
            pass
    return False


def _iapt_output_v13_is_source_resource_restore(task: dict, options: dict) -> bool:
    task = task if isinstance(task, dict) else {}
    options = options if isinstance(options, dict) else {}
    try:
        feature_id = int(task.get("feature_id") or options.get("feature_id") or 0)
    except Exception:
        feature_id = 0
    version = str(
        options.get("decrypt_version")
        or options.get("task_version")
        or task.get("decrypt_version")
        or ""
    ).strip().lower()

    # Preview/download may still see the original task snapshot with feature_id=0.
    # The client's source_restore=true flag is authoritative and must publish
    # the restored res/** tree instead of silently falling back to src-only mode.
    source_restore_requested = _iapt_output_v13_truthy(
        options.get("source_restore"),
        default=False,
    )
    explicit = (
        feature_id == 8
        or version in (
            "restore", "source_restore", "dex_restore", "static_dex_restore",
            "source_dex_restore",
        )
        or source_restore_requested
    )

    # Only an explicit false disables restored resource publication.
    return explicit and _iapt_output_v13_truthy(
        options.get("restore_resource_names"),
        default=True,
    )


def _iapt_output_v13_filter(rows: list[dict], roots: tuple[str, ...]) -> list[dict]:
    out = []
    for row in rows or []:
        rel = str((row or {}).get("rel_path") or "").replace("\\", "/").lstrip("./")
        if rel.startswith(roots):
            item = dict(row)
            item["rel_path"] = rel
            out.append(item)
    out.sort(key=lambda x: str(x.get("rel_path") or ""))
    return out


def _iapt_output_v13_try_reexport_qiushui(task: dict, out_dir: Path, options: dict) -> None:
    # Existing feature-17 tasks created before the resource exporter may have a
    # stale manifest and no res tree.  Rebuild once from the retained upload.
    try:
        if any(p.is_file() for p in (out_dir / "res").rglob("*")):
            return
    except Exception:
        pass
    try:
        task_no = str((task or {}).get("task_no") or "").strip()
        if not task_no:
            return
        apk = APP_STORAGE / "uploads" / (task_no + ".apk")
        if not apk.is_file():
            return
        from .tools.iapt_qiushui_resource_export import export_resources
        export_resources(apk, out_dir, options or {})
    except Exception as exc:
        try:
            logger.warning("V13 anti-QiuShui res re-export skipped: %s", exc)
        except Exception:
            pass


def _finish_public_file_rows(task: dict, files: list[dict]) -> list[dict]:
    if not task or not task.get("out_dir"):
        return []
    out_dir = Path(task["out_dir"])
    options = _iapt_output_v13_options(task)
    is_qiushui = _iapt_output_v13_is_qiushui(task, options)
    is_source_res = _iapt_output_v13_is_source_resource_restore(task, options)

    if is_qiushui:
        _iapt_output_v13_try_reexport_qiushui(task, out_dir, options)

    # Never trust an old index for the two resource-producing modes.  Re-scan
    # physical files, then apply the exact public roots.
    if is_qiushui or is_source_res:
        clean = _sanitize_public_file_rows(out_dir, _scan_out_files(out_dir))
        clean = _iapt_output_v13_filter(clean, ("res/",) if is_qiushui else ("src/", "res/"))
    else:
        clean = _sanitize_public_file_rows(out_dir, files)
        if (out_dir / "src").is_dir():
            clean = _src_only_public_rows(out_dir, clean)

    _write_file_index(out_dir, clean)
    _sync_public_file_counts(task, clean)
    return clean
# IAPT_OUTPUT_SCOPE_V13_END


# IAPT_HOTFIX_V5_MAINFILE_AND_AUTO_RESOURCE_BEGIN
# 修正点：
# 1) iAct 等项目主文件不是 mian.iyu，未填写“自定义主文件”时自动重试候选主文件。
# 2) “反加密样本”未显式开启时，若普通 V3 失败且 APK 无 assets/lib.so，则尝试一次隐藏资源归一化。
_IAPT_HOTFIX_V5_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process

def _iapt_v5_cmd_has_flag(cmd, flag: str) -> bool:
    return any(str(x) == flag or str(x).startswith(flag + '=') for x in (cmd or []))

def _iapt_v5_cmd_replace_value(cmd, flag: str, value: str):
    out=[]; i=0; found=False
    raw=[str(x) for x in (cmd or [])]
    while i < len(raw):
        if raw[i] == flag:
            out.extend([flag, value]); found=True; i += 2 if i + 1 < len(raw) else 1; continue
        if raw[i].startswith(flag + '='):
            out.append(flag + '=' + value); found=True; i += 1; continue
        out.append(raw[i]); i += 1
    if not found:
        out.extend([flag, value])
    return out

def _iapt_v5_apk_has_assets_lib(apk_path: Path) -> bool:
    try:
        import zipfile
        with zipfile.ZipFile(apk_path, 'r') as zf:
            return any((not x.is_dir()) and x.filename.replace('\\','/').lower() == 'assets/lib.so' for x in zf.infolist())
    except Exception:
        return False

def _iapt_v5_main_candidates(options: dict, cmd: list) -> list[str]:
    raw=[]
    for k in ('main_file','custom_main_file','entry_file'):
        v=str((options or {}).get(k) or '').strip().replace('\\','/').lstrip('/')
        if v: raw.append(v)
    # 通用 + 已验证样本。保持少量候选，避免把错误参数误判为成功。
    raw += ['mian.iyu','main.iyu','lianyi.iyu','home.iyu','index.iyu','start.iyu']
    out=[]; seen=set()
    import re as _re
    for x in raw:
        if not x or x in seen: continue
        if '..' in x or not _re.fullmatch(r'[A-Za-z0-9_./\-\u0080-\uffff]+\.(?:mjava|myu|iyu|mlua|mjs|ijs|ilua|ijava)', x, flags=_re.I):
            continue
        seen.add(x); out.append(x)
    return out

def _iapt_v5_should_retry_main(result: _IaptProcResult) -> bool:
    if not result or int(result.returncode or 0) == 0:
        return False
    s = str(result.stdout or '')
    return ('mian.iyu verification failed' in s or 'mian.iyu start marker not found' in s or
            'no valid SLKY_POST_KEY' in s or 'all key/outer candidates failed' in s or
            'mian.iyu decrypt failed' in s)

def run_decrypt_process(cmd, apk_path, out_dir, options, task, env=None):
    # IAPT_HOTFIX_V7_STRICT_PARAMS:
    # 服务端不再自动补“反加密样本”、不再自动轮询主文件、也不再自动补任何解密参数。
    # 主文件、反加密样本、sokey/dexkey/签名等均以客户端显式提交的 options 为准。
    return _IAPT_HOTFIX_V5_PREV_RUN_DECRYPT_PROCESS([str(x) for x in (cmd or [])], apk_path, out_dir, dict(options or {}), task, env=env)
# IAPT_HOTFIX_V5_MAINFILE_AND_AUTO_RESOURCE_END

# IAPT_OLD_IAPP_SEPARATE_PIPELINE_V1_BEGIN
# Old four-character-sokey projects use a completely different container
# format.  Route them before the V3 post_key/key_xor pipeline so algorithms
# and parameters can never be mixed.
_IAPT_OLD_IAPP_PREV_RUN_TASK = run_task


def _iapt_old_iapp_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on", "y")
    return False


def _iapt_old_iapp_is_special_task(task: dict, options: dict) -> bool:
    kind = str(options.get("task_kind") or task.get("task_kind") or "").strip().lower()
    ver = str(options.get("decrypt_version") or options.get("task_version") or task.get("decrypt_version") or "").strip().lower()
    return kind in (
        "dynamic_key_extract", "server_sokey_extract", "standalone_so_extract",
        "standalone_dynamic_key_extract", "sokey_extract", "source_restore",
    ) or ver in (
        "v6", "6", "key", "dynkey", "dynamic_key_extract", "sokey",
        "server_sokey", "restore", "source_restore", "fn_restore",
        "numeric_restore", "dex_restore", "static_dex_restore",
        "source_dex_restore", "iact", "iact_restore",
    )


def _iapt_old_iapp_requested(task: dict, options: dict, apk_path: Path) -> tuple[bool, dict]:
    version = str(
        options.get("decrypt_version") or options.get("task_version")
        or task.get("decrypt_version") or ""
    ).strip().lower()
    explicit = (
        _iapt_old_iapp_truthy(options.get("legacy_iapp"))
        or _iapt_old_iapp_truthy(options.get("old_iapp"))
        or version in ("old", "legacy", "old_iapp", "iapp_old")
    )
    if _iapt_old_iapp_is_special_task(task, options):
        return False, {"old_iapp": False, "reason": "special-task"}
    if explicit:
        return True, {"old_iapp": True, "reason": "explicit-option"}
    # Server-side fallback protects older clients: a Base64/AES assets/lib.so
    # is an unambiguous old-iApp feature and must not enter V3.
    if version not in ("", "v3", "3", "iapp_v3"):
        return False, {"old_iapp": False, "reason": "different-version"}
    try:
        from .tools.iapp_old_decrypt import detect_old_iapp_apk
        probe = detect_old_iapp_apk(apk_path)
        return bool(probe.get("old_iapp")), probe
    except Exception as exc:
        return False, {"old_iapp": False, "reason": f"probe-error: {type(exc).__name__}: {exc}"}


def _iapt_run_old_iapp_task(task_id: int, task: dict, options: dict, probe: dict) -> None:
    apk_path = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
    out_dir = APP_STORAGE / "tasks" / task["task_no"]
    log_path = APP_STORAGE / "tasks" / f"{task['task_no']}.log"
    started = time.perf_counter()
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    clean = dict(options or {})
    clean["legacy_iapp"] = True
    clean["old_iapp"] = True
    clean["old_iapp_probe"] = probe
    clean["decrypt_version"] = "v3"
    clean["task_version"] = "v3"
    clean["no_dynamic_key"] = True
    # Never leak V3-only inputs into the old decryptor.
    for key in (
        "dynamic_key", "custom_dynamic_key", "post_key", "key_xor",
        "server_key_pool_mode", "server_key_pool_ref", "dynamic_key_features",
        "dynamic_key_sample_entry", "dynamic_key_sample_abi",
        "anti_qiushui", "hidden_resource_restore", "hidden_resource_restored",
        "dex_static_restore",
    ):
        clean.pop(key, None)
    # Enumeration concurrency is controlled by server configuration.
    try:
        clean["enum_workers"] = max(1, int(IAPT_ENUM_WORKERS or 1))
    except Exception:
        clean["enum_workers"] = 1
    # IAPT_HOTFIX_V7_STRICT_OLD_PARAMS:
    # 远古方案只负责切换旧版算法，不自动补 dexkey 枚举、server_sokey 或签名校验。
    # 客户端本地明文特征提取到的 4 位 sokey 会作为 hidden 参数传入；
    # “sokey（服务器获取）”才会触发服务端字符表分析。
    clean.setdefault("signature_mode", "skip")
    clean.setdefault("dexkey_enum_start", 3_100_000)
    clean.setdefault("dexkey_enum_stop", 10_000_000)

    feature_id = int(task.get("feature_id") or clean.get("feature_id") or 1)
    db.exec(
        "UPDATE tasks SET status='running', out_dir=%s, log_path=%s, decrypt_version='v3' WHERE id=%s",
        (str(out_dir), str(log_path), int(task_id)),
    )

    _decrypt_semaphore.acquire()
    try:
        from .tools.iapp_old_decrypt import decrypt_old_iapp_apk
        report = decrypt_old_iapp_apk(apk_path, out_dir, clean)
        total_ms = float(report.get("total_ms") or ((time.perf_counter() - started) * 1000.0))
        count, total = scan_files(int(task_id), out_dir)
        log_lines = [
            "### IAPT old-iApp separate pipeline v1",
            "probe=" + json.dumps(probe, ensure_ascii=False, sort_keys=True, default=str),
            "options=" + json.dumps(clean, ensure_ascii=False, sort_keys=True, default=str),
            f"sokey={report.get('sokey', '')}",
            f"dexkey={report.get('dexkey', '')}",
            f"lib_key={report.get('lib_key', '')}",
            f"main_file={report.get('main_file', 'mian.iyu')}",
            f"members={report.get('decrypted_count', 0)}/{report.get('member_count', 0)}",
            f"resolved_names={report.get('resolved_name_count', 0)}",
            f"unknown_names={report.get('unknown_name_count', 0)}",
            f"files={count}", f"bytes={total}", f"total_ms={total_ms:.2f}",
        ]
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8", errors="replace")
        if count <= 0:
            raise RuntimeError("old-iApp decrypt succeeded but produced no source files")
        db.exec(
            """
            UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
            version_name=%s, version_code=%s, feature_id=%s, decrypt_version='v3',
            error_text=NULL WHERE id=%s
            """,
            (
                total_ms, str(report.get("app_name") or ""), str(report.get("package_name") or ""),
                str(report.get("version_name") or ""), str(report.get("version_code") or ""),
                feature_id, int(task_id),
            ),
        )
        settle_decrypt_quota_once(int(task_id))
        try:
            if task.get("apk_sha256") and task.get("options_hash"):
                from .cache import save_source_cache, cleanup_source_cache
                cleanup_source_cache()
                save_source_cache(
                    int(task_id), task.get("apk_sha256"), task.get("options_hash"),
                    feature_id, str(out_dir),
                )
        except Exception:
            logger.exception("old-iApp source cache save failed task=%s", task_id)
    except Exception as exc:
        total_ms = (time.perf_counter() - started) * 1000.0
        reason = "解密失败：" + str(exc)
        try:
            old_log = ""
            if log_path.exists():
                old_log = log_path.read_text(encoding="utf-8", errors="replace")
            log_path.write_text(old_log + reason + "\n", encoding="utf-8", errors="replace")
        except Exception:
            pass
        db.exec(
            "UPDATE tasks SET status='failed', total_ms=%s, error_text=%s, feature_id=%s, decrypt_version='v3' WHERE id=%s",
            (float(total_ms), reason[-4000:], feature_id, int(task_id)),
        )
    finally:
        _decrypt_semaphore.release()


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if task:
        try:
            options = json.loads(task.get("options_json") or "{}")
            if not isinstance(options, dict):
                options = {}
        except Exception:
            options = {}
        apk_path = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
        requested, probe = _iapt_old_iapp_requested(task, options, apk_path)
        if requested:
            return _iapt_run_old_iapp_task(int(task_id), task, options, probe)
    return _IAPT_OLD_IAPP_PREV_RUN_TASK(int(task_id))
# IAPT_OLD_IAPP_SEPARATE_PIPELINE_V1_END

# IAPT_HOTFIX_V6_PARAM_STRICT_BEGIN
# V6: do not invent parameters.  Old-iApp uses only explicit UI/server flags;
# dexkey enumeration, server sokey and signature verification are enabled only
# when the task options contain the corresponding parameter.  V3 retry features
# are also no longer automatic: anti-encrypted-sample and main_file are driven
# by client parameters.
_IAPT_HOTFIX_V6_BASE_RUN_DECRYPT_PROCESS = globals().get('_IAPT_HOTFIX_V5_PREV_RUN_DECRYPT_PROCESS', run_decrypt_process)

def run_decrypt_process(cmd, apk_path, out_dir, options, task, env=None):
    # Bypass the V5 auto anti-sample retry and auto main-file candidate retry.
    return _IAPT_HOTFIX_V6_BASE_RUN_DECRYPT_PROCESS(cmd, apk_path, out_dir, options, task, env=env)


def _iapt_run_old_iapp_task(task_id: int, task: dict, options: dict, probe: dict) -> None:
    apk_path = APP_STORAGE / "uploads" / f"{task['task_no']}.apk"
    out_dir = APP_STORAGE / "tasks" / task["task_no"]
    log_path = APP_STORAGE / "tasks" / f"{task['task_no']}.log"
    started = time.perf_counter()
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)

    clean = dict(options or {})
    clean["legacy_iapp"] = True
    clean["old_iapp"] = True
    clean["old_iapp_probe"] = probe
    clean["decrypt_version"] = "v3"
    clean["task_version"] = "v3"
    clean["no_dynamic_key"] = True
    for key in (
        "dynamic_key", "custom_dynamic_key", "post_key", "key_xor",
        "server_key_pool_mode", "server_key_pool_ref", "dynamic_key_features",
        "dynamic_key_sample_entry", "dynamic_key_sample_abi",
        "anti_qiushui", "hidden_resource_restore", "hidden_resource_restored",
        "v3_dynamic_restore", "dex_static_restore",
    ):
        clean.pop(key, None)
    _ancient_restore = (
        _iapt_truthy(clean.get("ancient_dynamic_restore"))
        or _iapt_truthy(clean.get("numeric_restore"))
        or _iapt_truthy(clean.get("dynamic_restore"))
        or str(clean.get("restore_fn_names") or "").strip().lower() in ("auto", "on", "true", "1")
    )
    if _ancient_restore:
        clean["ancient_dynamic_restore"] = True
        clean["numeric_restore"] = True
        clean["dynamic_restore"] = True
        clean["restore_fn_names"] = "on"
    else:
        clean["ancient_dynamic_restore"] = False
        clean["numeric_restore"] = False
        clean["dynamic_restore"] = False
        clean["restore_fn_names"] = "off"
    try:
        clean["enum_workers"] = max(1, int(IAPT_ENUM_WORKERS or 1))
    except Exception:
        clean["enum_workers"] = 1

    # No automatic key/signature parameter creation here.  The client decides:
    #   sokey: hidden / server_sokey / sokey_enum
    #   dexkey: fb,dexkey / dexkey_enum
    #   signature: signature_mode=verify
    clean.setdefault("signature_mode", "skip")
    clean.setdefault("dexkey_enum_start", 3_100_000)
    clean.setdefault("dexkey_enum_stop", 10_000_000)

    feature_id = int(task.get("feature_id") or clean.get("feature_id") or 1)
    db.exec(
        "UPDATE tasks SET status='running', out_dir=%s, log_path=%s, decrypt_version='v3' WHERE id=%s",
        (str(out_dir), str(log_path), int(task_id)),
    )

    _decrypt_semaphore.acquire()
    try:
        from .tools.iapp_old_decrypt import decrypt_old_iapp_apk
        report = decrypt_old_iapp_apk(apk_path, out_dir, clean)
        total_ms = float(report.get("total_ms") or ((time.perf_counter() - started) * 1000.0))
        count, total = scan_files(int(task_id), out_dir)
        log_lines = [
            "### IAPT old-iApp separate pipeline v6-param-strict",
            "probe=" + json.dumps(probe, ensure_ascii=False, sort_keys=True, default=str),
            "options=" + json.dumps(clean, ensure_ascii=False, sort_keys=True, default=str),
            f"sokey={report.get('sokey', '')}",
            f"dexkey={report.get('dexkey', '')}",
            f"lib_key={report.get('lib_key', '')}",
            f"main_file={report.get('main_file', 'mian.iyu')}",
            f"members={report.get('decrypted_count', 0)}/{report.get('member_count', 0)}",
            f"resolved_names={report.get('resolved_name_count', 0)}",
            f"unknown_names={report.get('unknown_name_count', 0)}",
            f"files={count}", f"bytes={total}", f"total_ms={total_ms:.2f}",
        ]
        log_path.write_text("\n".join(log_lines) + "\n", encoding="utf-8", errors="replace")
        if count <= 0:
            raise RuntimeError("old-iApp decrypt succeeded but produced no source files")
        db.exec(
            """
            UPDATE tasks SET status='done', total_ms=%s, app_name=%s, package_name=%s,
            version_name=%s, version_code=%s, feature_id=%s, decrypt_version='v3',
            error_text=NULL WHERE id=%s
            """,
            (
                total_ms, str(report.get("app_name") or ""), str(report.get("package_name") or ""),
                str(report.get("version_name") or ""), str(report.get("version_code") or ""),
                feature_id, int(task_id),
            ),
        )
        settle_decrypt_quota_once(int(task_id))
        try:
            if task.get("apk_sha256") and task.get("options_hash"):
                from .cache import save_source_cache, cleanup_source_cache
                cleanup_source_cache()
                save_source_cache(int(task_id), task.get("apk_sha256"), task.get("options_hash"), feature_id, str(out_dir))
        except Exception:
            logger.exception("old-iApp source cache save failed task=%s", task_id)
    except Exception as exc:
        total_ms = (time.perf_counter() - started) * 1000.0
        reason = "解密失败：" + str(exc)
        try:
            old_log = log_path.read_text(encoding="utf-8", errors="replace") if log_path.exists() else ""
            log_path.write_text(old_log + reason + "\n", encoding="utf-8", errors="replace")
        except Exception:
            pass
        db.exec(
            "UPDATE tasks SET status='failed', total_ms=%s, error_text=%s, feature_id=%s, decrypt_version='v3' WHERE id=%s",
            (float(total_ms), reason[-4000:], feature_id, int(task_id)),
        )
    finally:
        _decrypt_semaphore.release()
# IAPT_HOTFIX_V6_PARAM_STRICT_END

# IAPT_V8_EXPLICIT_DUAL_SCRIPT_DISPATCH_BEGIN
# Final dispatcher.  This block is intentionally last.
#
# Current/V3 and ancient/four-character-sokey projects are executed by two
# different scripts.  No APK-content probe may switch the algorithm here.
# Only the client/task parameter selects the ancient script:
#   decrypt_scheme=ancient, or legacy_iapp/old_iapp=true.
_IAPT_V8_PREVIOUS_FINAL_RUN_TASK = globals().get('_IAPT_OLD_IAPP_PREV_RUN_TASK', run_task)
IAPT_V3_SCRIPT = Path(__file__).resolve().parent / 'tools' / 'iapp_v3_decrypt_entry.py'
IAPT_ANCIENT_SCRIPT = Path(__file__).resolve().parent / 'tools' / 'iapp_ancient_decrypt_entry.py'
# The pre-existing V3 task builder reads SCRIPT at runtime.
SCRIPT = IAPT_V3_SCRIPT


def _iapt_v8_scheme(options: dict) -> str:
    scheme = str((options or {}).get('decrypt_scheme') or '').strip().lower()
    if scheme == 'ancient':
        return 'ancient'
    if _iapt_truthy((options or {}).get('legacy_iapp')) or _iapt_truthy((options or {}).get('old_iapp')):
        return 'ancient'
    return 'v3'


def _iapt_v8_first_text(options: dict, *keys: str) -> str:
    for key in keys:
        value = str((options or {}).get(key) or '').strip()
        if value:
            return value
    return ''


def _iapt_v8_build_ancient_cmd(apk_path: Path, out_dir: Path, options: dict) -> list[str]:
    cmd = [sys.executable, str(IAPT_ANCIENT_SCRIPT), '--apk', str(apk_path), '--outdir', str(out_dir)]

    sokey_enum = _iapt_truthy(options.get('sokey_enum'))
    server_sokey = _iapt_truthy(options.get('server_sokey'))
    dexkey_enum = _iapt_truthy(options.get('dexkey_enum')) or _iapt_truthy(options.get('dex_enum'))

    # Explicit values are used only when the corresponding alternative mode is off.
    sokey = _iapt_v8_first_text(options, 'hidden', 'sokey', 'client_sokey')
    dexkey = _iapt_v8_first_text(options, 'fb', 'dexkey', 'client_dexkey', 'client_fb_auto')
    if sokey and not sokey_enum and not server_sokey:
        cmd += ['--sokey', sokey]
    if dexkey and not dexkey_enum:
        cmd += ['--dexkey', dexkey]
    if sokey_enum:
        cmd.append('--sokey-enum')
        alphabet = _iapt_v8_first_text(options, 'old_sokey_alphabet')
        if alphabet:
            cmd += ['--old-sokey-alphabet', alphabet]
    if server_sokey:
        cmd.append('--server-sokey')
    if dexkey_enum:
        cmd.append('--dexkey-enum')
        if str(options.get('dexkey_enum_start') or '').strip():
            cmd += ['--dexkey-enum-start', str(int(options.get('dexkey_enum_start')))]
        if str(options.get('dexkey_enum_stop') or '').strip():
            cmd += ['--dexkey-enum-stop', str(int(options.get('dexkey_enum_stop')))]
        if str(options.get('enum_workers') or '').strip():
            cmd += ['--enum-workers', str(max(0, int(options.get('enum_workers'))))]
        if str(options.get('enum_chunk_size') or '').strip():
            cmd += ['--enum-chunk-size', str(max(1, int(options.get('enum_chunk_size'))))]

    signature_mode = str(options.get('signature_mode') or 'skip').strip().lower()
    if signature_mode not in ('skip', 'verify'):
        signature_mode = 'skip'
    cmd += ['--signature-mode', signature_mode]
    signature_hex = _iapt_v8_first_text(options, 'signature_bytes_hex')
    if signature_hex:
        cmd += ['--signature-bytes-hex', signature_hex]

    password = _iapt_v8_first_text(options, 'user_password', 'password')
    if password:
        cmd += ['--password', password]
    main_file = _iapt_v8_first_text(options, 'main_file', 'custom_main_file', 'entry_file')
    if main_file:
        cmd += ['--main-file', main_file]
    find_value = options.get('find')
    if isinstance(find_value, (list, tuple)):
        for item in find_value:
            item = str(item or '').strip()
            if item:
                cmd += ['--find', item]
    elif str(find_value or '').strip():
        cmd += ['--find', str(find_value).strip()]
    if _iapt_truthy(options.get('find_recursive')):
        cmd.append('--find-recursive')

    restore_requested = (
        _iapt_truthy(options.get('ancient_dynamic_restore'))
        or _iapt_truthy(options.get('numeric_restore'))
        or _iapt_truthy(options.get('dynamic_restore'))
        or str(options.get('restore_fn_names') or '').strip().lower() in ('auto', 'on', 'true', '1')
    )
    if restore_requested:
        # Run numeric function-name restore after ancient member decryption, using the uploaded APK DEX table.
        cmd += ['--restore-fn-names', 'on']
    return cmd


def _iapt_v8_run_ancient_task(task_id: int, task: dict, options: dict) -> None:
    apk_path = APP_STORAGE / 'uploads' / f"{task['task_no']}.apk"
    out_dir = APP_STORAGE / 'tasks' / task['task_no']
    log_path = APP_STORAGE / 'tasks' / f"{task['task_no']}.log"
    started = time.perf_counter()
    feature_id = int(task.get('feature_id') or options.get('feature_id') or 1)
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    db.exec(
        "UPDATE tasks SET status='running',out_dir=%s,log_path=%s,decrypt_version='v3',error_text=NULL WHERE id=%s",
        (str(out_dir), str(log_path), int(task_id)),
    )
    cmd = _iapt_v8_build_ancient_cmd(apk_path, out_dir, dict(options or {}))
    _decrypt_semaphore.acquire()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=None)
        output = proc.stdout or ''
        log_path.write_text(
            '[IAPT_V8] decrypt_script=ancient\n'
            + '[IAPT_V8] command=' + json.dumps(cmd, ensure_ascii=False) + '\n'
            + output,
            encoding='utf-8', errors='replace',
        )
        if proc.returncode != 0:
            raise RuntimeError(f'ancient decrypt process exited {proc.returncode}: ' + output[-3000:])
        report_path = out_dir / 'old_iapp_report.json'
        if not report_path.is_file():
            raise RuntimeError('ancient decrypt process did not create old_iapp_report.json')
        report = json.loads(report_path.read_text(encoding='utf-8'))
        if not isinstance(report, dict) or report.get('ok') is not True:
            raise RuntimeError('ancient decrypt report is invalid')
        count, total = scan_files(int(task_id), out_dir)
        if count <= 0:
            raise RuntimeError('ancient decrypt succeeded but produced no source files')
        total_ms = float(report.get('total_ms') or ((time.perf_counter() - started) * 1000.0))
        db.exec(
            """
            UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,
            version_name=%s,version_code=%s,feature_id=%s,decrypt_version='v3',error_text=NULL
            WHERE id=%s
            """,
            (
                total_ms, str(report.get('app_name') or ''), str(report.get('package_name') or ''),
                str(report.get('version_name') or ''), str(report.get('version_code') or ''),
                feature_id, int(task_id),
            ),
        )
        settle_decrypt_quota_once(int(task_id))
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        reason = '解密失败：' + str(exc)
        try:
            previous = log_path.read_text(encoding='utf-8', errors='replace') if log_path.exists() else ''
            log_path.write_text(previous + '\n' + reason + '\n', encoding='utf-8', errors='replace')
        except Exception:
            pass
        db.exec(
            "UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,feature_id=%s,decrypt_version='v3' WHERE id=%s",
            (float(elapsed), reason[-4000:], feature_id, int(task_id)),
        )
    finally:
        _decrypt_semaphore.release()


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        return _IAPT_V8_PREVIOUS_FINAL_RUN_TASK(int(task_id))
    try:
        options = json.loads(task.get('options_json') or '{}')
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_v8_scheme(options) == 'ancient':
        return _iapt_v8_run_ancient_task(int(task_id), task, options)
    # Explicit V3/default path.  Bypass the previous APK-content old-format probe.
    return _IAPT_V8_PREVIOUS_FINAL_RUN_TASK(int(task_id))
# IAPT_V8_EXPLICIT_DUAL_SCRIPT_DISPATCH_END

# IAPT_V10_SINGLE_SCRIPT_ROUTER_BEGIN
# Final authoritative task router installed by the self-contained repair script.
# It is intentionally the final run_task definition in this module.
_IAPT_V10_PREVIOUS_RUN_TASK = run_task
_IAPT_V10_ROOT = Path(__file__).resolve().parent / 'tools' / 'iapt_v10'
_IAPT_V10_V3 = _IAPT_V10_ROOT / 'v3_entry.py'
_IAPT_V10_ANCIENT = _IAPT_V10_ROOT / 'ancient_entry.py'


def _iapt_v10_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on', 'y')


def _iapt_v10_text(options: dict, *keys: str) -> str:
    for key in keys:
        value = str((options or {}).get(key) or '').strip()
        if value:
            return value
    return ''


def _iapt_v10_options(task: dict) -> dict:
    try:
        obj = json.loads((task or {}).get('options_json') or '{}')
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}


def _iapt_v10_probe(apk_path: Path) -> dict:
    result = {'scheme': 'v3', 'ancient': False, 'anti': False, 'reason': 'default'}
    try:
        import base64 as _b64
        with zipfile.ZipFile(apk_path, 'r') as zf:
            infos = [x for x in zf.infolist() if not x.is_dir()]
            by_name = {x.filename.replace('\\', '/').lower(): x for x in infos}
            if 'meta-inf/iapt/decrypt_scheme_ancient' in by_name:
                return {'scheme': 'ancient', 'ancient': True, 'anti': False, 'reason': 'client-marker'}
            anti_marker = 'meta-inf/iapt/anti_encrypted_sample' in by_name
            lib = by_name.get('assets/lib.so')
            ygs = any(n == 'libygsiyu.so' or n.endswith('/libygsiyu.so') for n in by_name)
            if lib is not None and 0 < int(lib.file_size or 0) <= 256 * 1024 * 1024:
                raw = zf.read(lib.filename)
                compact = b''.join(raw.split())
                old = False
                if len(compact) >= 64 and len(compact) % 4 == 0 and re.fullmatch(rb'[A-Za-z0-9+/]*={0,2}', compact):
                    try:
                        decoded = _b64.b64decode(compact, validate=True)
                        old = len(decoded) >= 16 and len(decoded) % 16 == 0
                    except Exception:
                        old = False
                if old:
                    return {'scheme': 'ancient', 'ancient': True, 'anti': False, 'reason': 'base64-aes-container'}
                anti = bool(anti_marker or (ygs and len(raw) >= 16 and len(raw) % 16 == 0))
                return {'scheme': 'v3', 'ancient': False, 'anti': anti, 'reason': 'client-anti-marker' if anti_marker else ('modern-canonical' if anti else 'canonical')}
            if anti_marker:
                return {'scheme': 'v3', 'ancient': False, 'anti': True, 'reason': 'client-anti-marker'}
            for info in infos:
                name = info.filename.replace('\\', '/')
                low = name.lower()
                size = int(info.file_size or 0)
                if size < 64 * 1024 or size > 512 * 1024 * 1024 or not low.startswith('assets/'):
                    continue
                non_ascii = sum(1 for ch in name if ord(ch) > 127)
                if len(name) >= 256 or name.count('/') >= 16 or non_ascii >= 16:
                    return {'scheme': 'v3', 'ancient': False, 'anti': True, 'reason': 'hidden-resource-wrapper'}
    except Exception as exc:
        result['error'] = type(exc).__name__ + ': ' + str(exc)
    return result


def _iapt_v10_regular(task: dict, options: dict) -> bool:
    task = task if isinstance(task, dict) else {}
    options = options if isinstance(options, dict) else {}
    kind = str(options.get('task_kind') or task.get('task_kind') or '').strip().lower()
    if kind and kind not in ('decrypt', 'v3', 'iapp'):
        return False

    # Standalone feature runners must never be swallowed by the late V3/ancient
    # family router.  Let the earlier dedicated run_task wrappers handle them.
    if _iapt_v10_truthy(options.get('dynamic_key_extract')) or _iapt_v10_truthy(options.get('server_sokey_extract')):
        return False

    versions = {
        str(task.get('decrypt_version') or '').strip().lower(),
        str(options.get('decrypt_version') or '').strip().lower(),
        str(options.get('task_version') or '').strip().lower(),
    }
    versions.discard('')
    standalone_versions = {
        'v6', '6',
        'key', 'dynkey', 'dynamic_key', 'dynamic_key_extract',
        'sokey', 'server_sokey', 'server_sokey_extract',
        'restore', 'source_restore',
        'fn_restore', 'numeric_restore', 'numeric_source_restore',
        'dex_restore', 'static_dex_restore', 'source_dex_restore',
        'iact', 'iact_restore',
    }
    if versions.intersection(standalone_versions):
        return False

    # Reuse the authoritative detectors so compatibility aliases and the
    # inline-V3 dynamic-restore exception stay exactly aligned with the actual
    # dedicated runners.  A detector failure must not break normal V3 tasks.
    for detector_name in (
        '_iapt_iact_restore_is_task',
        '_iapt_is_static_dex_source_restore_task',
        '_iapt_is_numeric_source_restore_task',
        '_iapt_source_restore_is_task',
        '_iapt_v39_is_dynamic_key_task',
    ):
        detector = globals().get(detector_name)
        if callable(detector):
            try:
                if detector(task, options):
                    return False
            except Exception:
                pass

    try:
        # Feature 6 is V6; feature 8 is standalone source restoration.
        if int(task.get('feature_id') or options.get('feature_id') or 0) in (6, 8):
            return False
    except Exception:
        pass
    return True


def _iapt_v10_explicit_ancient(options: dict) -> bool:
    return str((options or {}).get('decrypt_scheme') or '').strip().lower() == 'ancient' or _iapt_v10_truthy((options or {}).get('legacy_iapp')) or _iapt_v10_truthy((options or {}).get('old_iapp'))


def _iapt_v10_prepare_pool(out_dir: Path, options: dict) -> Path | None:
    mode = str((options or {}).get('server_key_pool_mode') or '').strip().lower()
    if mode not in ('selected', 'enum'):
        return None
    from .dynamic_key_pool import list_decrypted, resolve_ref, write_pool_file
    if mode == 'selected':
        ref = str((options or {}).get('server_key_pool_ref') or '').strip()
        row = resolve_ref(ref)
        if not row:
            raise RuntimeError('选择的服务器动态Key不存在或已停用')
        rows = [row]
    else:
        rows = list_decrypted()
        if not rows:
            raise RuntimeError('服务器动态Key池为空')
    path = out_dir / '.tmp' / 'v10_dynamic_key_pool.json'
    path.parent.mkdir(parents=True, exist_ok=True)
    write_pool_file(path, rows)
    return path


def _iapt_v10_ancient_cmd(apk: Path, out_dir: Path, options: dict) -> list[str]:
    cmd = [sys.executable, str(_IAPT_V10_ANCIENT), '--apk', str(apk), '--outdir', str(out_dir)]
    sokey_enum = _iapt_v10_truthy(options.get('sokey_enum'))
    dex_enum = _iapt_v10_truthy(options.get('dexkey_enum')) or _iapt_v10_truthy(options.get('dex_enum'))
    server_sokey = _iapt_v10_truthy(options.get('server_sokey'))
    sokey = _iapt_v10_text(options, 'hidden', 'sokey', 'client_sokey')
    dexkey = _iapt_v10_text(options, 'fb', 'dexkey', 'client_dexkey', 'client_fb_auto', 'fb_auto')
    if sokey and not sokey_enum and not server_sokey:
        cmd += ['--sokey', sokey]
    if dexkey and not dex_enum:
        cmd += ['--dexkey', dexkey]
    if sokey_enum:
        cmd.append('--sokey-enum')
        alphabet = _iapt_v10_text(options, 'old_sokey_alphabet')
        if alphabet:
            cmd += ['--old-sokey-alphabet', alphabet]
    if server_sokey:
        cmd.append('--server-sokey')
    if dex_enum:
        cmd.append('--dexkey-enum')
        start = _iapt_v10_text(options, 'dexkey_enum_start', 'dex_enum_start')
        stop = _iapt_v10_text(options, 'dexkey_enum_stop', 'dex_enum_stop')
        if start:
            cmd += ['--dexkey-enum-start', start]
        if stop:
            cmd += ['--dexkey-enum-stop', stop]
        workers = _iapt_v10_text(options, 'enum_workers')
        if workers:
            cmd += ['--enum-workers', workers]
    mode = str(options.get('signature_mode') or 'auto').strip().lower()
    cmd += ['--signature-mode', mode if mode in ('skip', 'verify', 'auto') else 'auto']
    for flag, keys in (
        ('--signature-bytes-hex', ('signature_bytes_hex',)),
        ('--password', ('user_password', 'password')),
        ('--main-file', ('main_file', 'custom_main_file', 'entry_file', 'auto_main_file')),
    ):
        value = _iapt_v10_text(options, *keys)
        if value:
            cmd += [flag, value]
    find_value = options.get('find') or options.get('search_filename')
    if isinstance(find_value, (list, tuple)):
        for value in find_value:
            if str(value or '').strip():
                cmd += ['--find', str(value).strip()]
    elif str(find_value or '').strip():
        cmd += ['--find', str(find_value).strip()]
    if _iapt_v10_truthy(options.get('find_recursive')):
        cmd.append('--find-recursive')
    return cmd


def _iapt_v10_v3_cmd(apk: Path, out_dir: Path, options: dict, probe: dict) -> list[str]:
    cmd = [sys.executable, str(_IAPT_V10_V3), '--apk', str(apk), '--outdir', str(out_dir)]
    for flag, keys in (
        ('--hidden', ('hidden', 'sokey', 'client_sokey')),
        ('--fb', ('fb', 'dexkey', 'client_dexkey', 'client_fb_auto', 'fb_auto')),
        ('--user-password', ('user_password', 'password')),
        ('--signature-mode', ('signature_mode',)),
        ('--signature-bytes-hex', ('signature_bytes_hex',)),
        ('--post-key', ('post_key',)),
        ('--key-xor', ('key_xor',)),
        ('--main-file', ('main_file', 'custom_main_file', 'entry_file', 'auto_main_file')),
        ('--fast-c', ('fast_c',)),
        ('--restore-fn-names', ('restore_fn_names',)),
        ('--threads', ('threads',)),
        ('--member-marker-mode', ('member_marker_mode',)),
        ('--member-name-scan', ('member_name_scan',)),
        ('--member-batch-size', ('member_batch_size',)),
    ):
        value = _iapt_v10_text(options, *keys)
        if value:
            cmd += [flag, value]
    if not _iapt_v10_text(options, 'signature_mode'):
        cmd += ['--signature-mode', 'skip']
    find_value = options.get('find') or options.get('search_filename')
    if isinstance(find_value, (list, tuple)):
        for value in find_value:
            if str(value or '').strip():
                cmd += ['--find', str(value).strip()]
    elif str(find_value or '').strip():
        cmd += ['--find', str(find_value).strip()]
    if _iapt_v10_truthy(options.get('find_recursive')):
        cmd.append('--find-recursive')
    max_files = _iapt_v10_text(options, 'max_output_files')
    if max_files:
        cmd += ['--max-output-files', max_files]
    if _iapt_v10_truthy(options.get('dynamic_key')):
        cmd.append('--dynamic-key')
    if _iapt_v10_truthy(options.get('server_sokey')):
        cmd.append('--server-sokey')
    anti = bool(probe.get('anti')) or any(_iapt_v10_truthy(options.get(k)) for k in ('anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore'))
    if anti:
        cmd.append('--anti-encrypted-sample')
    if _iapt_v10_truthy(options.get('no_key_cache')):
        cmd.append('--no-key-cache')
    if _iapt_v10_truthy(options.get('sokey_enum')):
        cmd.append('--sokey-enum')
        for flag, key in (('--sokey-enum-seconds', 'sokey_enum_seconds'), ('--sokey-enum-files', 'sokey_enum_files'), ('--sokey-max-candidates', 'sokey_max_candidates')):
            value = _iapt_v10_text(options, key)
            if value:
                cmd += [flag, value]
    if _iapt_v10_truthy(options.get('dexkey_enum')) or _iapt_v10_truthy(options.get('dex_enum')):
        cmd.append('--dexkey-enum')
        start = _iapt_v10_text(options, 'dexkey_enum_start', 'dex_enum_start')
        stop = _iapt_v10_text(options, 'dexkey_enum_stop', 'dex_enum_stop')
        if start:
            cmd += ['--dexkey-enum-start', start]
        if stop:
            cmd += ['--dexkey-enum-stop', stop]
        if _iapt_v10_truthy(options.get('no_dexkey_dex_hint')):
            cmd.append('--no-dexkey-dex-hint')
    if _iapt_v10_truthy(options.get('enum_quiet')):
        cmd.append('--enum-quiet')
    if _iapt_v10_truthy(options.get('no_python_fallback')):
        cmd.append('--no-python-fallback')
    pool_file = _iapt_v10_prepare_pool(out_dir, options)
    if pool_file is not None:
        cmd += ['--key-pool-file', str(pool_file), '--redact-selected-keys']
    if _iapt_v10_truthy(options.get('custom_dynamic_key')) or (_iapt_v10_text(options, 'post_key') and _iapt_v10_text(options, 'key_xor')):
        cmd.append('--strict-manual-key')
    return cmd


def _iapt_v10_fail_summary(output: str, code: int) -> str:
    try:
        return summarize_fail_reason(output, code)
    except Exception:
        lines = [x.strip() for x in str(output or '').splitlines() if x.strip()]
        return ('exit=' + str(code) + ' ' + ' | '.join(lines[-12:]))[-3500:]


def _iapt_v10_execute(task_id: int, task: dict, options: dict, scheme: str, probe: dict):
    apk = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
    out_dir = APP_STORAGE / 'tasks' / str(task.get('task_no') or '')
    log_path = APP_STORAGE / 'tasks' / (str(task.get('task_no') or '') + '.log')
    started = time.perf_counter()
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(out_dir, ignore_errors=True)
    out_dir.mkdir(parents=True, exist_ok=True)
    db.exec("UPDATE tasks SET status='running',out_dir=%s,log_path=%s,decrypt_version=%s,error_text=NULL WHERE id=%s", (str(out_dir), str(log_path), ('ancient' if str(scheme).lower() == 'ancient' else 'v3'), int(task_id)))
    cmd = _iapt_v10_ancient_cmd(apk, out_dir, options) if scheme == 'ancient' else _iapt_v10_v3_cmd(apk, out_dir, options, probe)
    header = '[IAPT_V10] decrypt_script=' + scheme + '\n[IAPT_V10] probe=' + json.dumps(probe, ensure_ascii=False, sort_keys=True) + '\n[IAPT_V10] options=' + json.dumps(options, ensure_ascii=False, sort_keys=True, default=str) + '\n[IAPT_V10] command=' + json.dumps(cmd, ensure_ascii=False) + '\n'
    env = os.environ.copy()
    env.update({'PYTHONIOENCODING': 'utf-8', 'PYTHONUTF8': '1', 'LANG': 'C.UTF-8', 'LC_ALL': 'C.UTF-8'})


    # IAPT V180: the authoritative V10/V91 executor calls subprocess.run()
    # directly, so later run_decrypt_process wrappers are not involved. Build
    # the whitelist probe after the output directory reset and pass it through
    # the exact environment used by this subprocess.
    whitelist_prepared = None
    if str(scheme).strip().lower() == 'v3':
        whitelist_probe_builder = globals().get('_v168r_probe_config')
        if callable(whitelist_probe_builder):
            whitelist_prepared = whitelist_probe_builder(apk, out_dir, task)
            if whitelist_prepared:
                _wl_payload, _wl_probe_path, _wl_result_path = whitelist_prepared
                env['IAPT_WHITELIST_PACKAGE_SIGNATURES_V168'] = str(_wl_probe_path)
                env['IAPT_WHITELIST_PACKAGE_SIGNATURES_RESULT_V168'] = str(_wl_result_path)
                header += '[IAPT_V180_EXECUTOR_WHITELIST] enabled=1 probe=' + str(_wl_probe_path) + '\n'
            else:
                header += '[IAPT_V180_EXECUTOR_WHITELIST] enabled=0\n'

    _decrypt_semaphore.acquire()
    try:
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env, timeout=None)
        output = proc.stdout or ''
        log_path.write_text(header + output, encoding='utf-8', errors='replace')


        # Exit 93 is a successful protection decision, not an ordinary decrypt
        # error. Mark it so the outer V169 run_task wrapper performs the same
        # final key/file redaction as the older run_decrypt_process path.
        if int(proc.returncode) == 93:
            marker = globals().get('_v169_mark')
            scrubber = globals().get('_v169_scrub')
            if callable(marker):
                marker(int(task_id))
            if callable(scrubber):
                scrubber(int(task_id))
            return {
                'ok': False,
                'task_id': int(task_id),
                'status': 'failed',
                'error': '白名单保护',
                'error_text': '白名单保护',
                'message': '白名单保护',
                'error_code': 'whitelist_protected',
                'whitelist_protected': True,
                'file_count': 0,
                'total_bytes': 0,
            }

        if int(proc.returncode) != 0:
            raise RuntimeError(_iapt_v10_fail_summary(output, int(proc.returncode)))
        # IAPT_NATIVE_COMPILE_RESTORE_RUNNER_BEGIN
        # After ancient or V3 decryption has produced project source files, reconnect
        # every 12-hex event placeholder with Aid_YuCodeX methods in classes*.dex.
        native_compile_enabled = any(_iapt_v10_truthy(options.get(key)) for key in (
            'native_compile_restore',
            'v3_native_compile_restore',
            'ancient_native_compile_restore',
        ))
        if native_compile_enabled:
            try:
                try:
                    from .tools.iapp_native_compile_restore import restore_native_compiled_events
                except ImportError:
                    from app.tools.iapp_native_compile_restore import restore_native_compiled_events
                native_report = restore_native_compiled_events(apk, out_dir)
                native_line = '[IAPT_NATIVE_COMPILE_RESTORE] ' + json.dumps(
                    native_report, ensure_ascii=False, sort_keys=True, default=str)
                with log_path.open('a', encoding='utf-8', errors='replace') as native_log:
                    native_log.write('\n' + native_line + '\n')
                if not native_report.get('ok', False):
                    raise RuntimeError('原生编译修复器未能读取有效 DEX')
            except Exception as native_exc:
                raise RuntimeError('原生编译修复失败：' + str(native_exc))
        # IAPT_NATIVE_COMPILE_RESTORE_RUNNER_END

        count, total = scan_files(int(task_id), out_dir)
        if count <= 0:
            raise RuntimeError(scheme + ' engine returned no files')
        elapsed = (time.perf_counter() - started) * 1000.0
        meta = {}
        try:
            meta = parse_meta(output)
            meta = merge_meta_nonempty(meta_from_apk_path(apk), meta)
        except Exception:
            pass
        if scheme == 'ancient':
            report_file = out_dir / 'old_iapp_report.json'
            if not report_file.is_file():
                raise RuntimeError('ancient engine did not create old_iapp_report.json')
            report = json.loads(report_file.read_text(encoding='utf-8'))
            if not isinstance(report, dict) or report.get('ok') is not True:
                raise RuntimeError('ancient engine report is invalid')
            for key in ('app_name', 'package_name', 'version_name', 'version_code', 'total_ms'):
                if str(report.get(key) or '').strip():
                    meta[key] = report.get(key)
        total_ms = float(meta.get('total_ms') or elapsed)
        db.exec("UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,decrypt_version=%s,error_text=NULL WHERE id=%s", (total_ms, str(meta.get('app_name') or ''), str(meta.get('package_name') or ''), str(meta.get('version_name') or ''), str(meta.get('version_code') or ''), ('ancient' if str(scheme).lower() == 'ancient' else 'v3'), int(task_id)))
        settle_decrypt_quota_once(int(task_id))
        return {'ok': True, 'task_id': int(task_id), 'scheme': scheme, 'files': count, 'bytes': total}
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        reason = '解密失败：' + str(exc)
        try:
            previous = log_path.read_text(encoding='utf-8', errors='replace') if log_path.exists() else header
            log_path.write_text(previous + '\n' + reason + '\n', encoding='utf-8', errors='replace')
        except Exception:
            pass
        db.exec("UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,decrypt_version=%s WHERE id=%s", (float(elapsed), reason[-4000:], ('ancient' if str(scheme).lower() == 'ancient' else 'v3'), int(task_id)))
        return {'ok': False, 'task_id': int(task_id), 'scheme': scheme, 'error': reason}
    finally:
        _decrypt_semaphore.release()


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
    if not task:
        return _IAPT_V10_PREVIOUS_RUN_TASK(int(task_id))
    options = _iapt_v10_options(task)
    if not _iapt_v10_regular(task, options):
        return _IAPT_V10_PREVIOUS_RUN_TASK(int(task_id))
    apk = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
    if not apk.is_file():
        return _IAPT_V10_PREVIOUS_RUN_TASK(int(task_id))
    probe = _iapt_v10_probe(apk)
    scheme = 'ancient' if (_iapt_v10_explicit_ancient(options) or bool(probe.get('ancient'))) else 'v3'
    options['decrypt_scheme'] = scheme
    if scheme == 'ancient':
        options['legacy_iapp'] = True
        options['old_iapp'] = True
        # Explicitly remove every current-family key field before building the
        # ancient subprocess command.  This makes QE/post/xor mixing impossible.
        for key in ('post_key', 'key_xor', 'custom_dynamic_key', 'dynamic_key', 'server_key_pool_mode', 'server_key_pool_ref', 'anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore'):
            options.pop(key, None)
        if not any(str(options.get(k) or '').strip() for k in ('fb', 'dexkey', 'client_dexkey', 'client_fb_auto', 'fb_auto')) and not _iapt_v10_truthy(options.get('dexkey_enum')) and not _iapt_v10_truthy(options.get('dex_enum')):
            options['dexkey_enum'] = True
        if _iapt_v10_truthy(options.get('dexkey_enum')) or _iapt_v10_truthy(options.get('dex_enum')):
            options.setdefault('dexkey_enum_start', 3100000)
            options.setdefault('dexkey_enum_stop', 10000000)
            options['enum_quiet'] = True
    elif bool(probe.get('anti')):
        options['anti_encrypted_sample'] = True
        options['anti_qiushui'] = True
        options['hidden_resource_restore'] = True
    try:
        db.exec('UPDATE tasks SET options_json=%s WHERE id=%s', (json.dumps(options, ensure_ascii=False, separators=(',', ':')), int(task_id)))
    except Exception:
        pass
    return _iapt_v10_execute(int(task_id), task, options, scheme, probe)
# IAPT_V10_SINGLE_SCRIPT_ROUTER_END

# IAPT_V82_SOURCE_VERIFIED_ROUTER_BEGIN
_IAPT_V82_PREVIOUS_NON_V10_RUN_TASK = globals().get("_IAPT_V10_PREVIOUS_RUN_TASK")
_IAPT_V82_BASE_EXECUTE = globals().get("_iapt_v10_execute")
_IAPT_V82_V3_CMD_BASE = globals().get("_iapt_v10_v3_cmd")

IAPT_ROUTER_VERSION = "V82-source-verified"

def _iapt_v82_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in ("1", "true", "yes", "on", "y")

def _iapt_v82_old_sokey(value) -> str:
    import re as _re
    text = str(value or "").strip()
    return text if _re.fullmatch(r"[A-Za-z0-9]{4}", text) else ""

def _iapt_v82_new_hidden(value) -> str:
    import re as _re
    text = str(value or "").strip()
    if not text:
        return ""
    if _re.fullmatch(r"[A-Za-z0-9]{10}Q{10}W{10}EE", text):
        return text
    if _re.fullmatch(r"[A-Za-z0-9]{10}", text):
        return text + ("Q" * 10) + ("W" * 10) + "EE"
    if text.lower().startswith("hex:"):
        raw_hex = text[4:].strip()
        try:
            raw = bytes.fromhex(raw_hex).decode("ascii", "strict")
        except Exception:
            return ""
        return "hex:" + raw_hex if _re.fullmatch(r"[A-Za-z0-9]{10}Q{10}W{10}EE", raw) else ""
    if len(text) == 64 and _re.fullmatch(r"[0-9A-Fa-f]{64}", text):
        try:
            raw = bytes.fromhex(text).decode("ascii", "strict")
        except Exception:
            return ""
        return text if _re.fullmatch(r"[A-Za-z0-9]{10}Q{10}W{10}EE", raw) else ""
    return ""

def _iapt_v82_options(task: dict) -> dict:
    try:
        value = json.loads((task or {}).get("options_json") or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}

def _iapt_v82_first_old_sokey(options: dict) -> str:
    for key in ("old_sokey", "sokey", "hidden", "client_sokey"):
        value = _iapt_v82_old_sokey((options or {}).get(key))
        if value:
            return value
    return ""

def _iapt_v82_first_new_hidden(options: dict) -> str:
    for key in ("hidden", "sokey", "client_sokey"):
        value = _iapt_v82_new_hidden((options or {}).get(key))
        if value:
            return value
    return ""

def _iapt_v82_special_task(task: dict, options: dict) -> bool:
    kind = str((options or {}).get("task_kind") or "").strip().lower()
    if kind and kind not in ("decrypt", "v3", "iapp", "ancient", "old", "legacy"):
        return True
    version = str(
        (options or {}).get("decrypt_version")
        or (options or {}).get("task_version")
        or (task or {}).get("decrypt_version")
        or ""
    ).strip().lower()
    if version in (
        "v6", "6", "key", "dynkey", "dynamic_key_extract",
        "sokey", "server_sokey_extract", "restore", "source_restore",
        "fn_restore", "dex_restore", "iact", "iact_restore",
    ):
        return True
    if _iapt_v82_truthy((options or {}).get("dynamic_key_extract")):
        return True
    if _iapt_v82_truthy((options or {}).get("server_sokey_extract")):
        return True
    try:
        return int((task or {}).get("feature_id") or 0) == 6
    except Exception:
        return False

def _iapt_v82_native_new_hidden(apk_path: Path) -> tuple[str, dict]:
    try:
        from .tools.iapt_v10.iapp_auto_decrypt import extract_hidden_candidates
    except Exception:
        from app.tools.iapt_v10.iapp_auto_decrypt import extract_hidden_candidates

    rows = []
    errors = []
    with zipfile.ZipFile(apk_path, "r") as zf:
        infos = [
            info for info in zf.infolist()
            if not info.is_dir()
            and (
                info.filename.replace("\\", "/").lower() == "libygsiyu.so"
                or info.filename.replace("\\", "/").lower().endswith("/libygsiyu.so")
            )
        ]
        for info in infos:
            try:
                candidates = extract_hidden_candidates(zf.read(info), 8)
            except Exception as exc:
                errors.append(f"{info.filename}: {type(exc).__name__}: {exc}")
                continue
            normalized = []
            for candidate in candidates:
                if isinstance(candidate, bytes):
                    text = candidate.decode("ascii", "ignore")
                else:
                    text = str(candidate or "")
                value = _iapt_v82_new_hidden(text)
                if value and value not in normalized:
                    normalized.append(value)
            if normalized:
                rows.append((info.filename, normalized))

    all_values = []
    for _, values in rows:
        for value in values:
            if value not in all_values:
                all_values.append(value)

    if len(all_values) == 1:
        return all_values[0], {
            "strategy": "new-native-plaintext",
            "entries": [{"name": name, "candidates": values} for name, values in rows],
        }
    if len(all_values) > 1:
        return "", {
            "strategy": "new-native-conflict",
            "candidates": all_values,
            "entries": [{"name": name, "candidates": values} for name, values in rows],
        }
    return "", {"strategy": "new-native-none", "errors": errors}

def _iapt_v82_old_probe(apk_path: Path) -> tuple[bool, str, dict]:
    try:
        from .tools.iapt_v10.iapp_old_decrypt import (
            detect_old_iapp_apk,
            extract_legacy_sokey_from_apk,
        )
    except Exception:
        from app.tools.iapt_v10.iapp_old_decrypt import (
            detect_old_iapp_apk,
            extract_legacy_sokey_from_apk,
        )

    try:
        detection = detect_old_iapp_apk(apk_path)
    except Exception as exc:
        detection = {"old_iapp": False, "reason": f"{type(exc).__name__}: {exc}"}

    old_sokey = ""
    try:
        old_sokey, sokey_meta = extract_legacy_sokey_from_apk(apk_path)
        old_sokey = _iapt_v82_old_sokey(old_sokey)
    except Exception as exc:
        sokey_meta = {"error": f"{type(exc).__name__}: {exc}"}

    return bool(detection.get("old_iapp")) or bool(old_sokey), old_sokey, {
        "container_detection": detection,
        "plaintext_sokey": sokey_meta,
    }

def _iapt_v82_hidden_resource_probe(apk_path: Path) -> dict:
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                name = info.filename.replace("\\", "/").lstrip("/")
                low = name.lower()
                size = int(info.file_size or 0)
                parts = [part for part in low.split("/") if part]
                base = parts[-1] if parts else low
                if (
                    low.startswith("assets/.")
                    or "/." in low
                    or low.startswith("assets/iapt_hidden")
                    or low.startswith("res/raw/iapt_")
                    or len(low) >= 180
                    or any(len(part) >= 96 for part in parts)
                    or (
                        size >= 1024
                        and (low.startswith("assets/") or low.startswith("res/raw/"))
                        and (
                            base.endswith(".dat")
                            or base.endswith(".bin")
                            or "." not in base
                        )
                    )
                ):
                    return {"hit": True, "resource": name}
    except Exception as exc:
        return {"hit": False, "error": f"{type(exc).__name__}: {exc}"}
    return {"hit": False}

def _iapt_v82_route(task: dict, options: dict, apk_path: Path) -> dict:
    options = dict(options or {})
    explicit_scheme = str(
        options.get("decrypt_scheme")
        or options.get("engine")
        or options.get("route")
        or ""
    ).strip().lower()

    old_key = _iapt_v82_first_old_sokey(options)
    new_hidden = _iapt_v82_first_new_hidden(options)

    if (
        explicit_scheme in ("ancient", "old", "legacy", "webcat")
        or _iapt_v82_truthy(options.get("legacy_iapp"))
        or _iapt_v82_truthy(options.get("old_iapp"))
    ):
        return {"scheme": "ancient", "reason": "explicit-old", "old_sokey": old_key, "new_hidden": ""}

    if old_key and not new_hidden:
        return {"scheme": "ancient", "reason": "explicit-old-4char-sokey", "old_sokey": old_key, "new_hidden": ""}

    if new_hidden:
        return {"scheme": "v3", "reason": "explicit-new-hidden", "old_sokey": "", "new_hidden": new_hidden}

    old_detected, extracted_old_key, old_meta = _iapt_v82_old_probe(apk_path)
    new_native_hidden, new_meta = _iapt_v82_native_new_hidden(apk_path)

    if old_detected and new_native_hidden:
        strict_old = bool((old_meta.get("container_detection") or {}).get("old_iapp"))
        if strict_old:
            return {
                "scheme": "ancient", "reason": "strict-old-container",
                "old_sokey": extracted_old_key, "new_hidden": "",
                "probe": {"old": old_meta, "new": new_meta},
            }
        return {
            "scheme": "v3", "reason": "new-native-hidden-over-loose-old-text",
            "old_sokey": "", "new_hidden": new_native_hidden,
            "probe": {"old": old_meta, "new": new_meta},
        }

    if old_detected:
        return {
            "scheme": "ancient",
            "reason": "server-old-plaintext" if extracted_old_key else "strict-old-container",
            "old_sokey": extracted_old_key, "new_hidden": "",
            "probe": {"old": old_meta, "new": new_meta},
        }

    if new_native_hidden:
        return {
            "scheme": "v3", "reason": "server-new-native-hidden",
            "old_sokey": "", "new_hidden": new_native_hidden,
            "probe": {"old": old_meta, "new": new_meta},
        }

    hidden_resource = _iapt_v82_hidden_resource_probe(apk_path)
    if hidden_resource.get("hit"):
        return {
            "scheme": "v3", "reason": "hidden-resource",
            "old_sokey": "", "new_hidden": "", "anti": True,
            "probe": {"old": old_meta, "new": new_meta, "hidden_resource": hidden_resource},
        }

    return {
        "scheme": "v3", "reason": "default-v3",
        "old_sokey": "", "new_hidden": "",
        "probe": {"old": old_meta, "new": new_meta, "hidden_resource": hidden_resource},
    }

def _iapt_v82_prepare_options(options: dict, route: dict) -> dict:
    prepared = dict(options or {})
    for key in ("hidden", "sokey", "old_sokey", "client_sokey"):
        prepared.pop(key, None)

    scheme = str(route.get("scheme") or "v3")
    if scheme == "ancient":
        old_key = _iapt_v82_old_sokey(route.get("old_sokey"))
        prepared["decrypt_scheme"] = "ancient"
        prepared["decrypt_version"] = "ancient"
        prepared["task_version"] = "ancient"
        prepared["legacy_iapp"] = True
        prepared["old_iapp"] = True

        for key in (
            "post_key", "key_xor", "custom_dynamic_key", "dynamic_key",
            "server_key_pool_mode", "server_key_pool_ref",
            "anti_encrypted_sample", "anti_qiushui",
            "hidden_resource_restore",
        ):
            prepared.pop(key, None)

        if old_key:
            prepared["sokey"] = old_key
            prepared["server_sokey"] = False
        elif not _iapt_v82_truthy(prepared.get("sokey_enum")):
            prepared["server_sokey"] = True

        # Old-iApp always needs the numeric dexkey.  Many legacy clients can
        # detect the four-character sokey but cannot recover f.b() from newer
        # obfuscated DEX layouts.  Do not let such tasks fall into the ancient
        # subprocess without a dexkey source; enable the old-family range enum
        # automatically unless an explicit dexkey was supplied.
        has_dexkey = False
        for _dk in ("fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"):
            if str(prepared.get(_dk) or "").strip():
                has_dexkey = True
                break
        if not has_dexkey and not _iapt_v82_truthy(prepared.get("dexkey_enum")) and not _iapt_v82_truthy(prepared.get("dex_enum")):
            prepared["dexkey_enum"] = True
        if _iapt_v82_truthy(prepared.get("dexkey_enum")) or _iapt_v82_truthy(prepared.get("dex_enum")):
            prepared.setdefault("dexkey_enum_start", 3_100_000)
            prepared.setdefault("dexkey_enum_stop", 10_000_000)
            prepared["enum_quiet"] = True
    else:
        new_hidden = _iapt_v82_new_hidden(route.get("new_hidden"))
        prepared["decrypt_scheme"] = "v3"
        prepared["decrypt_version"] = "v3"
        prepared["task_version"] = "v3"
        prepared.pop("legacy_iapp", None)
        prepared.pop("old_iapp", None)
        if new_hidden:
            prepared["hidden"] = new_hidden
        if route.get("anti"):
            prepared["anti_encrypted_sample"] = True

    prepared["_iapt_v82_router"] = {
        "version": IAPT_ROUTER_VERSION,
        "scheme": scheme,
        "reason": route.get("reason"),
        "old_sokey_present": bool(route.get("old_sokey")),
        "new_hidden_present": bool(route.get("new_hidden")),
    }
    return prepared

def _iapt_v82_persist_route(task_id: int, prepared: dict, route: dict) -> None:
    scheme = "ancient" if route.get("scheme") == "ancient" else "v3"
    db.exec(
        "UPDATE tasks SET options_json=%s,decrypt_version=%s WHERE id=%s",
        (
            json.dumps(prepared, ensure_ascii=False, separators=(",", ":"), sort_keys=True),
            scheme,
            int(task_id),
        ),
    )

def _iapt_v82_route_and_persist(task_id: int, stage: str = "runner") -> tuple[dict, dict, dict]:
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    options = _iapt_v82_options(task)
    if not task or _iapt_v82_special_task(task, options):
        return task, options, {"scheme": "passthrough", "reason": "special-task"}

    apk_path = APP_STORAGE / "uploads" / (str(task.get("task_no") or "") + ".apk")
    if not apk_path.is_file():
        return task, options, {"scheme": "passthrough", "reason": "apk-missing"}

    route = _iapt_v82_route(task, options, apk_path)
    prepared = _iapt_v82_prepare_options(options, route)
    _iapt_v82_persist_route(int(task_id), prepared, route)

    print(
        "[IAPT_V82_ROUTER] stage=%s task=%s scheme=%s reason=%s old_sokey=%s new_hidden=%s"
        % (
            stage, int(task_id), route.get("scheme"), route.get("reason"),
            bool(route.get("old_sokey")), bool(route.get("new_hidden")),
        ),
        flush=True,
    )
    return task, prepared, route

def _iapt_v10_ancient_cmd(apk: Path, out_dir: Path, options: dict) -> list[str]:
    cmd = [sys.executable, str(_IAPT_V10_ANCIENT), "--apk", str(apk), "--outdir", str(out_dir)]
    sokey_enum = _iapt_v82_truthy((options or {}).get("sokey_enum"))
    dex_enum = _iapt_v82_truthy((options or {}).get("dexkey_enum")) or _iapt_v82_truthy((options or {}).get("dex_enum"))
    server_sokey = _iapt_v82_truthy((options or {}).get("server_sokey"))

    old_sokey = _iapt_v82_first_old_sokey(options or {})
    dexkey = ""
    for key in ("fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"):
        value = str((options or {}).get(key) or "").strip()
        if value:
            dexkey = value
            break

    if old_sokey and not sokey_enum and not server_sokey:
        cmd += ["--sokey", old_sokey]
    if dexkey and not dex_enum:
        cmd += ["--dexkey", dexkey]
    if sokey_enum:
        cmd.append("--sokey-enum")
        alphabet = str((options or {}).get("old_sokey_alphabet") or "").strip()
        if alphabet:
            cmd += ["--old-sokey-alphabet", alphabet]
    if server_sokey:
        cmd.append("--server-sokey")
    if dex_enum:
        cmd.append("--dexkey-enum")
        start = str((options or {}).get("dexkey_enum_start") or (options or {}).get("dex_enum_start") or "").strip()
        stop = str((options or {}).get("dexkey_enum_stop") or (options or {}).get("dex_enum_stop") or "").strip()
        if start:
            cmd += ["--dexkey-enum-start", start]
        if stop:
            cmd += ["--dexkey-enum-stop", stop]
        workers = str((options or {}).get("enum_workers") or "").strip()
        if workers:
            cmd += ["--enum-workers", workers]

    signature_mode = str((options or {}).get("signature_mode") or "auto").strip().lower()
    cmd += ["--signature-mode", signature_mode if signature_mode in ("skip", "verify", "auto") else "auto"]

    for flag, keys in (
        ("--signature-bytes-hex", ("signature_bytes_hex",)),
        ("--password", ("user_password", "password")),
        ("--main-file", ("main_file", "custom_main_file", "entry_file", "auto_main_file")),
    ):
        value = ""
        for key in keys:
            candidate = str((options or {}).get(key) or "").strip()
            if candidate:
                value = candidate
                break
        if value:
            cmd += [flag, value]

    find_value = (options or {}).get("find") or (options or {}).get("search_filename")
    if isinstance(find_value, (list, tuple)):
        for value in find_value:
            value = str(value or "").strip()
            if value:
                cmd += ["--find", value]
    elif str(find_value or "").strip():
        cmd += ["--find", str(find_value).strip()]
    if _iapt_v82_truthy((options or {}).get("find_recursive")):
        cmd.append("--find-recursive")
    return cmd

def _iapt_v10_v3_cmd(apk: Path, out_dir: Path, options: dict, probe: dict) -> list[str]:
    if not callable(_IAPT_V82_V3_CMD_BASE):
        raise RuntimeError("V82: original V10 V3 command builder is unavailable")
    cleaned = dict(options or {})
    new_hidden = _iapt_v82_first_new_hidden(cleaned)
    for key in ("hidden", "sokey", "old_sokey", "client_sokey"):
        cleaned.pop(key, None)
    if new_hidden:
        cleaned["hidden"] = new_hidden
    return _IAPT_V82_V3_CMD_BASE(apk, out_dir, cleaned, probe)

def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        if callable(_IAPT_V82_PREVIOUS_NON_V10_RUN_TASK):
            return _IAPT_V82_PREVIOUS_NON_V10_RUN_TASK(int(task_id))
        return None

    options = _iapt_v82_options(task)
    if _iapt_v82_special_task(task, options):
        if callable(_IAPT_V82_PREVIOUS_NON_V10_RUN_TASK):
            return _IAPT_V82_PREVIOUS_NON_V10_RUN_TASK(int(task_id))
        return None

    task, prepared, route = _iapt_v82_route_and_persist(int(task_id), stage="runner")
    if route.get("scheme") == "passthrough":
        if callable(_IAPT_V82_PREVIOUS_NON_V10_RUN_TASK):
            return _IAPT_V82_PREVIOUS_NON_V10_RUN_TASK(int(task_id))
        return None

    if not callable(_IAPT_V82_BASE_EXECUTE):
        raise RuntimeError("V82: original V10 executor is unavailable")

    scheme = "ancient" if route.get("scheme") == "ancient" else "v3"
    probe = {
        "scheme": scheme,
        "ancient": scheme == "ancient",
        "anti": bool(route.get("anti")),
        "reason": route.get("reason"),
        "v82_probe": route.get("probe") or {},
    }
    result = _IAPT_V82_BASE_EXECUTE(int(task_id), task, prepared, scheme, probe)
    try:
        db.exec("UPDATE tasks SET decrypt_version=%s WHERE id=%s", (scheme, int(task_id)))
    except Exception:
        pass
    return result

print("IAPT_SOURCE_VERIFIED_ROUTER_V82 installed")
# IAPT_V82_SOURCE_VERIFIED_ROUTER_END

# IAPT_V84_ANCIENT_4CHAR_PARAMETER_BEGIN
# Authoritative final router for old four-character-sokey projects.
# Missing dexkey uses static f.b() extraction from the uploaded DEX (the
# "dexkey parameter" path). Enumeration is only retained when explicitly
# requested by the client/user.
_IAPT_V84_PREVIOUS_RUN_TASK = run_task
_IAPT_V84_EXECUTE = globals().get("_iapt_v10_execute")
IAPT_ROUTER_VERSION = "V84-ancient-4char-parameter-route"


def _iapt_v84_truthy(value) -> bool:
    if value is True or value == 1:
        return True
    return str(value or "").strip().lower() in ("1", "true", "yes", "on", "y")


def _iapt_v84_old_sokey(value) -> str:
    import re as _re
    text = str(value or "").strip()
    return text if _re.fullmatch(r"[A-Za-z0-9]{4}", text) else ""


def _iapt_v84_options(task: dict) -> dict:
    try:
        value = json.loads((task or {}).get("options_json") or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}


def _iapt_v84_regular(task: dict, options: dict) -> bool:
    fn = globals().get("_iapt_v10_regular")
    if callable(fn):
        try:
            return bool(fn(task, options))
        except Exception:
            pass
    kind = str((options or {}).get("task_kind") or (task or {}).get("task_kind") or "").strip().lower()
    return kind in ("", "decrypt", "v3", "iapp")


def _iapt_v84_probe(apk_path: Path, options: dict) -> dict:
    explicit = (
        str((options or {}).get("decrypt_scheme") or "").strip().lower() == "ancient"
        or _iapt_v84_truthy((options or {}).get("legacy_iapp"))
        or _iapt_v84_truthy((options or {}).get("old_iapp"))
        or any(_iapt_v84_old_sokey((options or {}).get(k)) for k in ("old_sokey", "sokey", "hidden", "client_sokey"))
    )
    old_probe = {"old_iapp": False, "reason": "not-probed"}
    try:
        from .tools.iapp_old_decrypt import detect_old_iapp_apk
        old_probe = detect_old_iapp_apk(apk_path)
    except Exception as exc:
        old_probe = {"old_iapp": False, "reason": f"{type(exc).__name__}: {exc}"}
    if explicit or bool(old_probe.get("old_iapp")):
        return {
            "scheme": "ancient",
            "ancient": True,
            "anti": False,
            "reason": "explicit-or-4char" if explicit else "base64-aes-old-container",
            "old_probe": old_probe,
        }
    modern = {"scheme": "v3", "ancient": False, "anti": False, "reason": "default-v3"}
    fn = globals().get("_iapt_v10_probe")
    if callable(fn):
        try:
            value = fn(apk_path)
            if isinstance(value, dict):
                modern.update(value)
        except Exception as exc:
            modern["probe_error"] = f"{type(exc).__name__}: {exc}"
    # A strict old Base64/AES container always wins over modern hidden probing.
    if bool(old_probe.get("old_iapp")):
        modern.update({"scheme": "ancient", "ancient": True, "anti": False, "reason": "base64-aes-old-container"})
    modern["old_probe"] = old_probe
    return modern


def _iapt_v84_prepare_ancient(apk_path: Path, options: dict, probe: dict) -> dict:
    prepared = dict(options or {})
    prepared["decrypt_scheme"] = "ancient"
    prepared["decrypt_version"] = "ancient"
    prepared["task_version"] = "ancient"
    prepared["legacy_iapp"] = True
    prepared["old_iapp"] = True

    for key in (
        "post_key", "key_xor", "custom_dynamic_key", "dynamic_key",
        "server_key_pool_mode", "server_key_pool_ref", "anti_encrypted_sample",
        "anti_qiushui", "hidden_resource_restore", "hidden_resource_restored",
        "numeric_restore", "dynamic_restore", "v3_dynamic_restore",
        "dex_static_restore", "restore_fn_names",
    ):
        prepared.pop(key, None)

    # Preserve only a true four-character ancient key. Modern 10/32-byte
    # hidden values are removed so they cannot reach the old engine.
    explicit_sokey = ""
    for key in ("old_sokey", "sokey", "hidden", "client_sokey"):
        explicit_sokey = _iapt_v84_old_sokey(prepared.get(key))
        if explicit_sokey:
            break
    extracted_sokey = ""
    sokey_meta = {}
    try:
        from .tools.iapp_old_decrypt import extract_legacy_sokey_from_apk
        extracted_sokey, sokey_meta = extract_legacy_sokey_from_apk(apk_path)
    except Exception as exc:
        sokey_meta = {"error": f"{type(exc).__name__}: {exc}"}
    selected_sokey = explicit_sokey or _iapt_v84_old_sokey(extracted_sokey)
    for key in ("hidden", "client_sokey"):
        prepared.pop(key, None)
    if selected_sokey:
        prepared["sokey"] = selected_sokey
        prepared["old_sokey"] = selected_sokey
        prepared["server_sokey"] = False
    elif not _iapt_v84_truthy(prepared.get("sokey_enum")):
        # Static multi-ABI extraction, not sokey enumeration.
        prepared["server_sokey"] = True
    prepared["old_sokey_probe"] = sokey_meta
    # IAPT_NATIVE_COMPILE_RESTORE_ANCIENT_BEGIN
    # Keep the native-compile flag when the ancient sanitizer removes V3-only
    # options. It shares feature 5 and the DEX upload channel with dynamic repair.
    native_compile_enabled = (
        _iapt_v84_truthy(prepared.get("native_compile_restore"))
        or _iapt_v84_truthy(prepared.get("ancient_native_compile_restore"))
        or _iapt_v84_truthy(prepared.get("v3_native_compile_restore"))
    )
    prepared["native_compile_restore"] = native_compile_enabled
    prepared["ancient_native_compile_restore"] = native_compile_enabled
    prepared["v3_native_compile_restore"] = False
    # IAPT_NATIVE_COMPILE_RESTORE_ANCIENT_END

    # V150: old/ancient-iApp may enable numeric dynamic restore, but it must remain inside the ancient pipeline.
    restore_enabled = (
        _iapt_v84_truthy(prepared.get("ancient_dynamic_restore"))
        or _iapt_v84_truthy(prepared.get("numeric_restore"))
        or _iapt_v84_truthy(prepared.get("dynamic_restore"))
        or str(prepared.get("restore_fn_names") or "").strip().lower() in ("auto", "on", "true", "1")
    )
    if restore_enabled:
        prepared["ancient_dynamic_restore"] = True
        prepared["v3_dynamic_restore"] = False
        prepared["numeric_restore"] = True
        prepared["dynamic_restore"] = True
        prepared["restore_fn_names"] = "on"
        prepared["require_dex_upload"] = True
        prepared["primary_feature_id"] = 5
    else:
        prepared["ancient_dynamic_restore"] = False
        prepared["v3_dynamic_restore"] = False
        prepared["numeric_restore"] = False
        prepared["dynamic_restore"] = False
        prepared["restore_fn_names"] = "off"
        if native_compile_enabled:
            prepared["primary_feature_id"] = 5
            prepared["require_dex_upload"] = True
        else:
            prepared.pop("primary_feature_id", None)
            prepared.pop("require_dex_upload", None)

    # A previous buggy client/main sanitizer marked missing dexkey as an
    # automatic enumeration. Remove that marker and require the dexkey parameter.
    auto_enum_marker = _iapt_v84_truthy(prepared.get("client_old_dexkey_enum_auto"))
    manual_dex_enum = (
        (_iapt_v84_truthy(prepared.get("dexkey_enum")) or _iapt_v84_truthy(prepared.get("dex_enum")))
        and not auto_enum_marker
    )
    explicit_dexkey = ""
    for key in ("fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"):
        value = str(prepared.get(key) or "").strip()
        if value:
            explicit_dexkey = value
            break
    if explicit_dexkey:
        prepared["fb"] = explicit_dexkey
        prepared["dexkey_auto"] = False
        prepared.pop("client_fb_dex_fallback", None)
        prepared.pop("dexkey_enum", None)
        prepared.pop("dex_enum", None)
    elif manual_dex_enum:
        prepared["dexkey_enum"] = True
        prepared.setdefault("dexkey_enum_start", 3_100_000)
        prepared.setdefault("dexkey_enum_stop", 10_000_000)
    else:
        for key in (
            "dexkey_enum", "dex_enum", "dexkey_enum_start", "dexkey_enum_stop",
            "dex_enum_start", "dex_enum_stop", "client_old_dexkey_enum_auto",
            "disable_client_dexkey_auto", "enum_quiet", "no_python_fallback",
        ):
            prepared.pop(key, None)
        prepared["dexkey_auto"] = False
        prepared["client_old_dexkey_parameter_required"] = True

    prepared.setdefault("signature_mode", "auto")
    prepared["_iapt_v84_router"] = {
        "version": IAPT_ROUTER_VERSION,
        "scheme": "ancient",
        "reason": probe.get("reason"),
        "sokey": selected_sokey,
        "sokey_length": len(selected_sokey),
        "dexkey_mode": "parameter" if explicit_dexkey else ("manual-enum" if manual_dex_enum else "parameter-required"),
    }
    return prepared


def _iapt_v84_prepare_v3(options: dict, probe: dict) -> dict:
    prepared = dict(options or {})
    prepared["decrypt_scheme"] = "v3"
    prepared["decrypt_version"] = "v3"
    prepared["task_version"] = "v3"
    prepared.pop("legacy_iapp", None)
    prepared.pop("old_iapp", None)
    prepared.pop("old_sokey", None)
    prepared.pop("dexkey_auto", None)
    prepared.pop("client_dexkey_auto", None)
    if bool(probe.get("anti")):
        prepared["anti_encrypted_sample"] = True
        prepared["anti_qiushui"] = True
        prepared["hidden_resource_restore"] = True
    prepared["_iapt_v84_router"] = {"version": IAPT_ROUTER_VERSION, "scheme": "v3", "reason": probe.get("reason")}
    return prepared


def _iapt_v84_route_and_persist(task_id: int, stage: str = "runner") -> tuple[dict, dict, dict]:
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    options = _iapt_v84_options(task)
    if not task or not _iapt_v84_regular(task, options):
        return task, options, {"scheme": "passthrough", "reason": "special-task"}
    apk_path = APP_STORAGE / "uploads" / (str(task.get("task_no") or "") + ".apk")
    if not apk_path.is_file():
        return task, options, {"scheme": "passthrough", "reason": "apk-missing"}
    probe = _iapt_v84_probe(apk_path, options)
    prepared = _iapt_v84_prepare_ancient(apk_path, options, probe) if probe.get("scheme") == "ancient" else _iapt_v84_prepare_v3(options, probe)
    scheme = "ancient" if probe.get("scheme") == "ancient" else "v3"
    fixed_feature_id = int(task.get("feature_id") or 1)
    if scheme == "ancient" and fixed_feature_id == 6:
        fixed_feature_id = int(prepared.get("primary_feature_id") or prepared.get("feature_id") or 1)
        if fixed_feature_id == 6: fixed_feature_id = 1
    db.exec(
        "UPDATE tasks SET options_json=%s,decrypt_version=%s,feature_id=%s WHERE id=%s",
        (json.dumps(prepared, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str), scheme, fixed_feature_id, int(task_id)),
    )
    task["decrypt_version"] = scheme
    task["feature_id"] = fixed_feature_id
    print(
        "[IAPT_V84_ROUTER] stage=%s task=%s scheme=%s reason=%s sokey=%s dexkey_mode=%s"
        % (
            stage, int(task_id), scheme, probe.get("reason"),
            str((prepared.get("_iapt_v84_router") or {}).get("sokey") or ""),
            str((prepared.get("_iapt_v84_router") or {}).get("dexkey_mode") or ""),
        ),
        flush=True,
    )
    return task, prepared, probe


def _iapt_v10_ancient_cmd(apk: Path, out_dir: Path, options: dict) -> list[str]:
    cmd = [sys.executable, str(_IAPT_V10_ANCIENT), "--apk", str(apk), "--outdir", str(out_dir)]
    sokey_enum = _iapt_v84_truthy((options or {}).get("sokey_enum"))
    dex_enum = _iapt_v84_truthy((options or {}).get("dexkey_enum")) or _iapt_v84_truthy((options or {}).get("dex_enum"))
    old_sokey = ""
    for key in ("old_sokey", "sokey", "hidden", "client_sokey"):
        old_sokey = _iapt_v84_old_sokey((options or {}).get(key))
        if old_sokey:
            break
    dexkey = ""
    for key in ("fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"):
        value = str((options or {}).get(key) or "").strip()
        if value:
            dexkey = value
            break
    if old_sokey and not sokey_enum:
        cmd += ["--sokey", old_sokey]
    elif not sokey_enum:
        cmd.append("--server-sokey")
    if sokey_enum:
        cmd.append("--sokey-enum")
        alphabet = str((options or {}).get("old_sokey_alphabet") or "").strip()
        if alphabet:
            cmd += ["--old-sokey-alphabet", alphabet]
    if dexkey and not dex_enum:
        cmd += ["--dexkey", dexkey]
    elif dex_enum:
        cmd.append("--dexkey-enum")
        start = str((options or {}).get("dexkey_enum_start") or (options or {}).get("dex_enum_start") or "").strip()
        stop = str((options or {}).get("dexkey_enum_stop") or (options or {}).get("dex_enum_stop") or "").strip()
        if start:
            cmd += ["--dexkey-enum-start", start]
        if stop:
            cmd += ["--dexkey-enum-stop", stop]
        workers = str((options or {}).get("enum_workers") or "").strip()
        if workers:
            cmd += ["--enum-workers", workers]
    elif _iapt_v84_truthy((options or {}).get("dexkey_auto")):
        # Optional explicit server static extraction. It is never enabled automatically.
        cmd.append("--dexkey-auto")
    mode = str((options or {}).get("signature_mode") or "auto").strip().lower()
    cmd += ["--signature-mode", mode if mode in ("skip", "verify", "auto") else "auto"]
    for flag, keys in (
        ("--signature-bytes-hex", ("signature_bytes_hex",)),
        ("--password", ("user_password", "password")),
        ("--main-file", ("main_file", "custom_main_file", "entry_file", "auto_main_file")),
    ):
        value = ""
        for key in keys:
            candidate = str((options or {}).get(key) or "").strip()
            if candidate:
                value = candidate
                break
        if value:
            cmd += [flag, value]
    find_value = (options or {}).get("find") or (options or {}).get("search_filename")
    if isinstance(find_value, (list, tuple)):
        for value in find_value:
            if str(value or "").strip():
                cmd += ["--find", str(value).strip()]
    elif str(find_value or "").strip():
        cmd += ["--find", str(find_value).strip()]
    if _iapt_v84_truthy((options or {}).get("find_recursive")):
        cmd.append("--find-recursive")
    return cmd


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return _IAPT_V84_PREVIOUS_RUN_TASK(int(task_id))
    options = _iapt_v84_options(task)
    if not _iapt_v84_regular(task, options):
        return _IAPT_V84_PREVIOUS_RUN_TASK(int(task_id))
    task, prepared, probe = _iapt_v84_route_and_persist(int(task_id), stage="runner-v84")
    if probe.get("scheme") == "passthrough":
        return _IAPT_V84_PREVIOUS_RUN_TASK(int(task_id))
    if not callable(_IAPT_V84_EXECUTE):
        raise RuntimeError("V84 ancient executor is unavailable")
    scheme = "ancient" if probe.get("scheme") == "ancient" else "v3"
    return _IAPT_V84_EXECUTE(int(task_id), task, prepared, scheme, probe)


print("IAPT_ANCIENT_4CHAR_PARAMETER_V84 installed")
# IAPT_V84_ANCIENT_4CHAR_PARAMETER_END


# IAPT_V85_ANCIENT_FAST_MONOTONIC_BEGIN
# Ancient tasks run in-process: PyCryptodome/cryptography already execute AES in
# native code, so removing the extra Python process gives the useful speedup.
# An atomic queued->running claim prevents duplicate queue deliveries or stale
# workers from writing failed after another execution has completed.
_IAPT_V85_PREVIOUS_RUN_TASK = run_task
IAPT_ROUTER_VERSION = "V87-ancient-invariant-c-multichannel"


def _iapt_v85_atomic_claim(task_id: int, out_dir: Path, log_path: Path) -> bool:
    c = db.conn()
    try:
        with c.cursor() as cur:
            cur.execute(
                "UPDATE tasks SET status='running',out_dir=%s,log_path=%s,"
                "decrypt_version='ancient',error_text=NULL "
                "WHERE id=%s AND status IN ('queued','pending')",
                (str(out_dir), str(log_path), int(task_id)),
            )
            return int(cur.rowcount or 0) == 1
    finally:
        c.close()


def _iapt_v85_conditional_status(task_id: int, status: str, sql_tail: str, args: tuple) -> bool:
    c = db.conn()
    try:
        with c.cursor() as cur:
            cur.execute(
                "UPDATE tasks SET status=%s," + sql_tail + " WHERE id=%s AND status='running'",
                (status,) + tuple(args) + (int(task_id),),
            )
            return int(cur.rowcount or 0) == 1
    finally:
        c.close()


def _iapt_v85_lock_path(task_no: str) -> Path:
    lock_dir = APP_STORAGE / "tasks" / ".execution_locks"
    lock_dir.mkdir(parents=True, exist_ok=True)
    return lock_dir / (str(task_no or "unknown") + ".ancient.lock")


def _iapt_v85_acquire_lock(task_no: str):
    path = _iapt_v85_lock_path(task_no)
    try:
        if path.exists() and time.time() - path.stat().st_mtime > 6 * 3600:
            path.unlink(missing_ok=True)
    except Exception:
        pass
    fd = os.open(str(path), os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    os.write(fd, ("pid=%s time=%s\n" % (os.getpid(), time.time())).encode("ascii"))
    os.close(fd)
    return path


def _iapt_v85_report_valid(out_dir: Path) -> dict | None:
    path = out_dir / "old_iapp_report.json"
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        return report if isinstance(report, dict) and report.get("ok") is True else None
    except Exception:
        return None


def _iapt_v85_ancient_execute(task_id: int, task: dict, options: dict, probe: dict):
    task_no = str(task.get("task_no") or "")
    apk = APP_STORAGE / "uploads" / (task_no + ".apk")
    out_dir = APP_STORAGE / "tasks" / task_no
    log_path = APP_STORAGE / "tasks" / (task_no + ".log")
    out_dir.parent.mkdir(parents=True, exist_ok=True)
    lock_path = None
    started = time.perf_counter()
    try:
        try:
            lock_path = _iapt_v85_acquire_lock(task_no)
        except FileExistsError:
            current = db.one("SELECT status FROM tasks WHERE id=%s", (int(task_id),)) or {}
            return {"ok": str(current.get("status") or "") == "done", "task_id": int(task_id), "scheme": "ancient", "duplicate": True, "status": current.get("status")}

        if not _iapt_v85_atomic_claim(int(task_id), out_dir, log_path):
            current = db.one("SELECT status FROM tasks WHERE id=%s", (int(task_id),)) or {}
            return {"ok": str(current.get("status") or "") == "done", "task_id": int(task_id), "scheme": "ancient", "duplicate": True, "status": current.get("status")}

        shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        header = (
            "[IAPT_V85] executor=ancient-in-process-native-aes\n"
            "[IAPT_V85] atomic_claim=true\n"
            "[IAPT_V85] probe=" + json.dumps(probe, ensure_ascii=False, sort_keys=True, default=str) + "\n"
            "[IAPT_V85] options=" + json.dumps(options, ensure_ascii=False, sort_keys=True, default=str) + "\n"
        )
        log_path.write_text(header, encoding="utf-8")

        from .tools.iapt_v10.iapp_old_decrypt import decrypt_old_iapp_apk
        _decrypt_semaphore.acquire()
        try:
            report = decrypt_old_iapp_apk(apk, out_dir, options)
        finally:
            _decrypt_semaphore.release()

        count, total = scan_files(int(task_id), out_dir)
        if count <= 0 or not isinstance(report, dict) or report.get("ok") is not True:
            raise RuntimeError("ancient engine returned an invalid/empty result")
        elapsed = (time.perf_counter() - started) * 1000.0
        total_ms = float(report.get("total_ms") or elapsed)
        summary = {k: report.get(k) for k in (
            "family", "sokey", "sokey_source", "dexkey", "dexkey_source",
            "member_count", "decrypted_count", "written_count", "resolved_name_count",
            "unknown_name_count", "dynamic_restore", "total_ms",
        )}
        with (out_dir / ".tmp" / "ancient_complete.json").open("w", encoding="utf-8") as fp:
            json.dump(summary, fp, ensure_ascii=False, separators=(",", ":"))
        with log_path.open("a", encoding="utf-8") as fp:
            fp.write("[IAPT_V85] report=" + json.dumps(summary, ensure_ascii=False, separators=(",", ":")) + "\n")

        updated = _iapt_v85_conditional_status(
            int(task_id), "done",
            "total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,"
            "decrypt_version='ancient',error_text=NULL",
            (
                total_ms, str(report.get("app_name") or ""), str(report.get("package_name") or ""),
                str(report.get("version_name") or ""), str(report.get("version_code") or ""),
            ),
        )
        if updated:
            settle_decrypt_quota_once(int(task_id))
            return {"ok": True, "task_id": int(task_id), "scheme": "ancient", "files": count, "bytes": total, "total_ms": total_ms}
        current = db.one("SELECT status FROM tasks WHERE id=%s", (int(task_id),)) or {}
        return {"ok": False, "task_id": int(task_id), "scheme": "ancient", "status": current.get("status"), "cancelled_or_superseded": True}
    except Exception as exc:
        elapsed = (time.perf_counter() - started) * 1000.0
        reason = "解密失败：" + str(exc)
        try:
            current = db.one("SELECT status FROM tasks WHERE id=%s", (int(task_id),)) or {}
            # A valid report plus indexed output means the engine completed; recover
            # from a late bookkeeping/logging exception instead of exposing a false fail.
            report = _iapt_v85_report_valid(out_dir) if str(current.get("status") or "") == "running" else None
            if report:
                count, total = scan_files(int(task_id), out_dir)
                if count > 0 and _iapt_v85_conditional_status(
                    int(task_id), "done",
                    "total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,"
                    "decrypt_version='ancient',error_text=NULL",
                    (
                        float(report.get("total_ms") or elapsed), str(report.get("app_name") or ""),
                        str(report.get("package_name") or ""), str(report.get("version_name") or ""),
                        str(report.get("version_code") or ""),
                    ),
                ):
                    settle_decrypt_quota_once(int(task_id))
                    return {"ok": True, "task_id": int(task_id), "scheme": "ancient", "files": count, "bytes": total, "recovered": True}
        except Exception:
            pass
        try:
            with log_path.open("a", encoding="utf-8") as fp:
                fp.write("[IAPT_V85] " + reason + "\n")
        except Exception:
            pass
        _iapt_v85_conditional_status(
            int(task_id), "failed", "total_ms=%s,error_text=%s,decrypt_version='ancient'",
            (float(elapsed), reason[-4000:]),
        )
        return {"ok": False, "task_id": int(task_id), "scheme": "ancient", "error": reason}
    finally:
        if lock_path is not None:
            try:
                lock_path.unlink(missing_ok=True)
            except Exception:
                pass


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return _IAPT_V85_PREVIOUS_RUN_TASK(int(task_id))
    options = _iapt_v84_options(task)
    if not _iapt_v84_regular(task, options):
        return _IAPT_V85_PREVIOUS_RUN_TASK(int(task_id))
    task, prepared, probe = _iapt_v84_route_and_persist(int(task_id), stage="runner-v85")
    if probe.get("scheme") == "ancient":
        return _iapt_v85_ancient_execute(int(task_id), task, prepared, probe)
    return _IAPT_V85_PREVIOUS_RUN_TASK(int(task_id))


print("IAPT_ANCIENT_FAST_MONOTONIC_V85 installed")
# IAPT_V85_ANCIENT_FAST_MONOTONIC_END

# IAPT_V91_STRICT_OLD_BASE64_BEGIN
# Final router guard: only the old Base64/AES assets/lib.so container is allowed
# to become the ancient scheme.  Four-character sokey strings are not a family
# detector because modern libygsiyu.so samples can contain 4-char collisions.
_IAPT_V91_PREVIOUS_RUN_TASK = run_task
IAPT_ROUTER_VERSION = "V91-strict-old-base64-v3-project-summary"

def _iapt_v91_options(task: dict) -> dict:
    try:
        value = json.loads((task or {}).get("options_json") or "{}")
        return value if isinstance(value, dict) else {}
    except Exception:
        return {}

def _iapt_v91_regular(task: dict, options: dict) -> bool:
    fn = globals().get("_iapt_v84_regular") or globals().get("_iapt_v10_regular")
    if callable(fn):
        try:
            return bool(fn(task, options))
        except Exception:
            pass
    kind = str((options or {}).get("task_kind") or (task or {}).get("task_kind") or "").strip().lower()
    return kind in ("", "decrypt", "v3", "iapp", "ancient")

def _iapt_v91_probe(apk_path: Path, options: dict) -> dict:
    old_probe = {"old_iapp": False, "reason": "not-probed"}
    try:
        from .tools.iapp_old_decrypt import detect_old_iapp_apk
        old_probe = detect_old_iapp_apk(apk_path)
    except Exception as exc:
        old_probe = {"old_iapp": False, "reason": f"{type(exc).__name__}: {exc}"}
    if bool(old_probe.get("old_iapp")):
        return {"scheme": "ancient", "ancient": True, "anti": False, "reason": "strict-old-base64-aes-container", "old_probe": old_probe}
    modern = {"scheme": "v3", "ancient": False, "anti": False, "reason": "strict-old-base64-negative-default-v3", "old_probe": old_probe}
    fn = globals().get("_iapt_v10_probe")
    if callable(fn):
        try:
            value = fn(apk_path)
            if isinstance(value, dict):
                modern.update(value)
        except Exception as exc:
            modern["probe_error"] = f"{type(exc).__name__}: {exc}"
    # Override older client/server markers.  A modern sample may submit
    # decrypt_scheme=ancient because of a false 4-char sokey; that must not win.
    if str(modern.get("scheme") or "").strip().lower() == "ancient" or bool(modern.get("ancient")):
        modern.update({"scheme": "v3", "ancient": False, "reason": "forced-v3-strict-old-base64-negative"})
    return modern

def _iapt_v91_route_and_persist(task_id: int, stage: str = "runner-v91"):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    options = _iapt_v91_options(task)
    if not task or not _iapt_v91_regular(task, options):
        return task, options, {"scheme": "passthrough", "reason": "special-task"}
    apk_path = APP_STORAGE / "uploads" / (str(task.get("task_no") or "") + ".apk")
    if not apk_path.is_file():
        return task, options, {"scheme": "passthrough", "reason": "apk-missing"}
    probe = _iapt_v91_probe(apk_path, options)
    if probe.get("scheme") == "ancient":
        prepared = _iapt_v84_prepare_ancient(apk_path, options, probe) if callable(globals().get("_iapt_v84_prepare_ancient")) else dict(options or {})
        scheme = "ancient"
    else:
        prepared = _iapt_v84_prepare_v3(options, probe) if callable(globals().get("_iapt_v84_prepare_v3")) else dict(options or {})
        prepared["decrypt_scheme"] = "v3"; prepared["decrypt_version"] = "v3"; prepared["task_version"] = "v3"
        for k in ("legacy_iapp", "old_iapp", "old_sokey", "old_sokey_probe"):
            prepared.pop(k, None)
        scheme = "v3"
    fixed_feature_id = int(task.get("feature_id") or 1)
    if scheme == "ancient" and fixed_feature_id == 6:
        fixed_feature_id = int(prepared.get("primary_feature_id") or prepared.get("feature_id") or 1)
        if fixed_feature_id == 6:
            fixed_feature_id = 1
    prepared["_iapt_v91_router"] = {"version": IAPT_ROUTER_VERSION, "scheme": scheme, "reason": probe.get("reason"), "old_probe": probe.get("old_probe")}
    db.exec(
        "UPDATE tasks SET options_json=%s,decrypt_version=%s,feature_id=%s WHERE id=%s",
        (json.dumps(prepared, ensure_ascii=False, separators=(",", ":"), sort_keys=True, default=str), scheme, fixed_feature_id, int(task_id)),
    )
    task["decrypt_version"] = scheme; task["feature_id"] = fixed_feature_id
    print("[IAPT_V91_ROUTER] stage=%s task=%s scheme=%s reason=%s" % (stage, int(task_id), scheme, probe.get("reason")), flush=True)
    return task, prepared, probe

def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),))
    if not task:
        return _IAPT_V91_PREVIOUS_RUN_TASK(int(task_id))
    options = _iapt_v91_options(task)
    if not _iapt_v91_regular(task, options):
        return _IAPT_V91_PREVIOUS_RUN_TASK(int(task_id))
    task, prepared, probe = _iapt_v91_route_and_persist(int(task_id), stage="runner-v91")
    if probe.get("scheme") == "passthrough":
        return _IAPT_V91_PREVIOUS_RUN_TASK(int(task_id))
    executor = globals().get("_iapt_v10_execute") or globals().get("_IAPT_V84_EXECUTE")
    if not callable(executor):
        raise RuntimeError("V91 executor is unavailable")
    scheme = "ancient" if probe.get("scheme") == "ancient" else "v3"
    return executor(int(task_id), task, prepared, scheme, probe)

# Keep .project members in downloadable ZIPs.  V91 intentionally disables the
# older automatic pruner because users need 包名.project in 解密情况/output.
def _iapt_v8_prune_automatic_project_files(task_id: int, task: dict) -> int:
    return 0

print("IAPT_V91_STRICT_OLD_BASE64_ROUTER installed")
# IAPT_V91_STRICT_OLD_BASE64_END


# IAPT_V92_RUNNER_STRICT_CLIENT_PARAMS_BEGIN
IAPT_ROUTER_VERSION = "V92-minimal-upload-client-old-params"
try:
    _IAPT_V92_PREV_PROBE = _iapt_v91_probe
except Exception:
    _IAPT_V92_PREV_PROBE = None

def _iapt_v91_probe(apk_path: Path, options: dict) -> dict:
    try:
        from .tools.iapp_old_decrypt import detect_old_iapp_apk
        old_probe = detect_old_iapp_apk(apk_path)
    except Exception as exc:
        old_probe = {"old_iapp": False, "reason": f"{type(exc).__name__}: {exc}"}
    if bool(old_probe.get("old_iapp")):
        return {"scheme":"ancient", "ancient":True, "anti":False, "reason":"v92-strict-assets-libso-base64", "old_probe": old_probe}
    modern = {"scheme":"v3", "ancient":False, "anti":False, "reason":"v92-strict-base64-negative", "old_probe": old_probe}
    try:
        if callable(globals().get('_iapt_v10_probe')):
            value = _iapt_v10_probe(apk_path)
            if isinstance(value, dict):
                modern.update(value)
    except Exception as exc:
        modern['probe_error'] = f"{type(exc).__name__}: {exc}"
    modern['scheme'] = 'v3'; modern['ancient'] = False
    return modern

print("IAPT_V92_RUNNER_STRICT_CLIENT_PARAMS installed")
# IAPT_V92_RUNNER_STRICT_CLIENT_PARAMS_END

# IAPT_V94_STRICT_OLD_ROUTER_BEGIN
# Runner-side guard paired with main.py V94.  Four-character strings and stale
# client flags are not enough to route modern V3/V6 into the ancient executor.
# A task is ancient only when the upload carries the fixed old marker or the
# original APK is detected by the old Base64/AES container probe.
IAPT_ROUTER_VERSION = "V94-project-is-src-output-root-source-normalizer"
try:
    _IAPT_V94_PREV_RUN_TASK = run_task
except Exception:
    _IAPT_V94_PREV_RUN_TASK = None

def _iapt_v94_runner_opts(task: dict) -> dict:
    try:
        raw = (task or {}).get('options_json')
        obj = json.loads(raw or '{}') if not isinstance(raw, dict) else dict(raw)
        return obj if isinstance(obj, dict) else {}
    except Exception:
        return {}

def _iapt_v94_runner_bool(v):
    if v is True or v == 1:
        return True
    return str(v or '').strip().lower() in ('1','true','yes','on','y','auto')

def _iapt_v94_zip_has_marker(apk_path: Path) -> bool:
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            return any(n.replace('\\','/').lower() == 'meta-inf/iapt/decrypt_scheme_ancient' for n in zf.namelist())
    except Exception:
        return False

def _iapt_v94_strict_old_probe(apk_path: Path, options: dict) -> dict:
    requested = (
        str((options or {}).get('decrypt_scheme') or '').strip().lower() == 'ancient'
        or str((options or {}).get('decrypt_version') or (options or {}).get('task_version') or '').strip().lower() in ('ancient','old','legacy','old_iapp','iapp_old')
        or _iapt_v94_runner_bool((options or {}).get('legacy_iapp'))
        or _iapt_v94_runner_bool((options or {}).get('old_iapp'))
    )
    old_probe = {'old_iapp': False, 'reason': 'not-probed'}
    try:
        from .tools.iapp_old_decrypt import detect_old_iapp_apk
        old_probe = detect_old_iapp_apk(apk_path)
    except Exception as exc:
        old_probe = {'old_iapp': False, 'reason': f'{type(exc).__name__}: {exc}'}
    marker = _iapt_v94_zip_has_marker(apk_path)
    if requested and (marker or bool(old_probe.get('old_iapp'))):
        return {'scheme':'ancient','ancient':True,'anti':False,'reason':'v94-explicit-old-marker-or-old-container','old_probe':old_probe,'old_marker':marker}
    modern = {'scheme':'v3','ancient':False,'anti':False,'reason':'v94-modern-default','old_probe':old_probe,'old_marker':marker}
    try:
        if callable(globals().get('_iapt_v10_probe')):
            value = _iapt_v10_probe(apk_path)
            if isinstance(value, dict):
                modern.update(value)
    except Exception as exc:
        modern['probe_error'] = f'{type(exc).__name__}: {exc}'
    # The final family decision wins over any older probe output.
    modern['scheme'] = 'v3'; modern['ancient'] = False
    return modern

# Override the V91/V92 probe name used by the existing route_and_persist wrapper.
def _iapt_v91_probe(apk_path: Path, options: dict) -> dict:
    return _iapt_v94_strict_old_probe(apk_path, options or {})

def run_task(task_id: int):
    if _IAPT_V94_PREV_RUN_TASK is None:
        raise RuntimeError('previous run_task unavailable')
    return _IAPT_V94_PREV_RUN_TASK(int(task_id))

print('IAPT_V94_STRICT_OLD_ROUTER installed')
# IAPT_V94_STRICT_OLD_ROUTER_END


# IAPT_V109_HIDDEN_RESOURCE_AUTODEX_BEGIN
# V109: For hidden-resource/anti-encrypted V3 samples that have no canonical
# assets/lib.so, the original upload may not let the client extract fb/dexkey.
# Add server-side dexkey enum only for hidden-resource V3 tasks, never for ancient.
try:
    import os as _iapt_v109_os
    import json as _iapt_v109_json
    from pathlib import Path as _IAPT_V109_Path
    _IAPT_V109_PREV_RUN_DECRYPT_PROCESS = run_decrypt_process

    def _iapt_v109_truthy(value):
        if value is True or value == 1:
            return True
        if value is False or value == 0 or value is None:
            return False
        if isinstance(value, str):
            return value.strip().lower() in ('1','true','yes','on','y')
        return bool(value)

    def _iapt_v109_is_ancient(options, task):
        text = ' '.join(str(x or '') for x in [
            (options or {}).get('scheme'), (options or {}).get('decrypt_scheme'), (options or {}).get('task_family'),
            (task or {}).get('scheme'), (task or {}).get('decrypt_scheme'), (task or {}).get('task_family'), (task or {}).get('decrypt_version')
        ]).lower()
        return 'ancient' in text or 'old-iapp' in text or 'old_iapp' in text

    def _iapt_v109_hidden_v3_requested(options, task):
        if _iapt_v109_is_ancient(options, task):
            return False
        options = options if isinstance(options, dict) else {}
        task = task if isinstance(task, dict) else {}
        for k in ('anti_qiushui','anti_encrypt','anti_encrypted_sample','hidden_resource_restore','hidden_resource_restored','anti_qiushui_resource_export'):
            if _iapt_v109_truthy(options.get(k)) or _iapt_v109_truthy(task.get(k)):
                return True
        try:
            if int(options.get('anti_qiushui_feature_id') or options.get('hidden_resource_feature_id') or task.get('feature_id') or 0) == 17:
                return True
        except Exception:
            pass
        return False

    def _iapt_v109_cmd_has(cmd, *flags):
        ss = {str(x) for x in (cmd or [])}
        return any(f in ss for f in flags)

    def _iapt_v109_extend_cmd_for_dexkey(cmd):
        cmd = [str(x) for x in (cmd or [])]
        if _iapt_v109_cmd_has(cmd, '--fb', '--dexkey', '--dex-key', '--dexkey-enum', '--dex-enum'):
            return cmd, False
        start = _iapt_v109_os.environ.get('IAPT_HIDDEN_DEXKEY_ENUM_START', '3100000')
        stop = _iapt_v109_os.environ.get('IAPT_HIDDEN_DEXKEY_ENUM_STOP', '10000000')
        workers = _iapt_v109_os.environ.get('IAPT_ENUM_WORKERS', '32')
        cmd.extend(['--dexkey-enum', '--dexkey-c-batch', '--dexkey-enum-start', str(start), '--dexkey-enum-stop', str(stop)])
        if '--enum-workers' not in cmd:
            cmd.extend(['--enum-workers', str(workers)])
        return cmd, True

    def run_decrypt_process(cmd, apk_path, out_dir, options, task, env=None):
        opts = dict(options or {})
        if _iapt_v109_hidden_v3_requested(opts, task) and _iapt_v109_truthy(_iapt_v109_os.environ.get('IAPT_HIDDEN_AUTO_DEXKEY_ENUM','1')):
            new_cmd, changed = _iapt_v109_extend_cmd_for_dexkey(cmd)
            if changed:
                opts['dexkey_enum'] = True
                opts['dexkey_auto_for_hidden_resource'] = True
                try:
                    d = _IAPT_V109_Path(out_dir) / '.tmp'
                    d.mkdir(parents=True, exist_ok=True)
                    d.joinpath('v109_hidden_auto_dexkey.json').write_text(_iapt_v109_json.dumps({
                        'enabled': True,
                        'reason': 'hidden-resource V3 task lacked fb/dexkey in client upload',
                        'workers': _iapt_v109_os.environ.get('IAPT_ENUM_WORKERS', '32'),
                    }, ensure_ascii=False), encoding='utf-8')
                except Exception:
                    pass
                return _IAPT_V109_PREV_RUN_DECRYPT_PROCESS(new_cmd, apk_path, out_dir, opts, task, env=env)
        return _IAPT_V109_PREV_RUN_DECRYPT_PROCESS(cmd, apk_path, out_dir, options, task, env=env)

    IAPT_V109_HIDDEN_RESOURCE_AUTODEX = {
        'enabled': True,
        'scope': 'hidden-resource V3 only; ancient remains manual/parameter mode',
        'workers_env': 'IAPT_ENUM_WORKERS',
    }
    print('IAPT_V109_HIDDEN_RESOURCE_AUTODEX installed')
except Exception as _iapt_v109_hidden_autodex_error:
    try: print('IAPT_V109_HIDDEN_AUTODEX_INSTALL_FAILED', repr(_iapt_v109_hidden_autodex_error))
    except Exception: pass
# IAPT_V109_HIDDEN_RESOURCE_AUTODEX_END

# IAPT_V110_ACTIVE_V3_ROUTE_FIX_BEGIN
# V109 patched run_decrypt_process(), but the active V82/V10 path builds a V10
# subprocess command directly.  Patch the command builder actually used by the
# final router: hidden-resource V3 samples get normalisation flags, exact pool
# matching, and C enum parameters before v3_entry.py is launched.
try:
    _IAPT_V110_V3_CMD_BASE = _iapt_v10_v3_cmd

    def _iapt_v110_truthy(value):
        if value is True or value == 1:
            return True
        return str(value or "").strip().lower() in ("1", "true", "yes", "on", "y")

    def _iapt_v110_text(options, *keys):
        for key in keys:
            value = str((options or {}).get(key) or "").strip()
            if value:
                return value
        return ""

    def _iapt_v110_add_once(command, flag, value=None):
        if flag in command:
            return
        command.append(flag)
        if value is not None and str(value).strip():
            command.append(str(value).strip())

    def _iapt_v110_is_anti(options, probe):
        if bool((probe or {}).get("anti")):
            return True
        return any(_iapt_v110_truthy((options or {}).get(key)) for key in (
            "anti_encrypted_sample", "anti_qiushui", "hidden_resource_restore",
            "client_hidden_resource_detected", "client_anti_qiushui_detected",
        ))

    def _iapt_v110_has_hidden(options):
        value = _iapt_v110_text(options, "hidden", "sokey", "client_sokey")
        return len(value) >= 10

    def _iapt_v110_has_fb(options):
        return bool(_iapt_v110_text(options, "fb", "dexkey", "client_dexkey", "client_fb_auto", "fb_auto"))

    def _iapt_v110_autofill_hidden_v3(apk, options, probe):
        if not _iapt_v110_is_anti(options, probe):
            return None
        auto = {
            "normalise": True,
            "pool_ref": "",
            "sokey_enum": False,
            "dexkey_enum": False,
        }
        # Exact SO-feature matching is a single indexed query and avoids waiting
        # for the client pool UI before a hidden-resource task can use its scheme.
        manual_keys = bool(_iapt_v110_text(options, "post_key") and _iapt_v110_text(options, "key_xor"))
        pool_mode = str((options or {}).get("server_key_pool_mode") or "").strip().lower()
        if not manual_keys and pool_mode not in ("selected", "enum"):
            try:
                from .dynamic_key_pool import resolve_apk_feature_ref
                matched = resolve_apk_feature_ref(apk)
            except Exception as exc:
                matched = None
                try:
                    print("IAPT_V110_POOL_MATCH_WARN", type(exc).__name__, str(exc))
                except Exception:
                    pass
            if isinstance(matched, dict) and str(matched.get("ref") or "").strip():
                options["server_key_pool_mode"] = "selected"
                options["server_key_pool_ref"] = str(matched.get("ref")).strip()
                options["client_v110_server_pool_auto"] = True
                options["client_v110_pool_abi"] = str(matched.get("abi") or "")
                options["client_v110_pool_feature"] = str(matched.get("feature_sha256") or "")
                options.pop("dynamic_key", None)
                auto["pool_ref"] = str(matched.get("ref")).strip()
            else:
                # Packed libygsiyu.so can be unpacked server-side when the optional
                # Unicorn runtime is installed.  Do not force --no-dynamic-key.
                options["dynamic_key"] = True
                options["client_v110_server_dynamic_auto"] = True

        if not _iapt_v110_has_hidden(options) and not _iapt_v110_truthy(options.get("sokey_enum")):
            options["sokey_enum"] = True
            options.setdefault("sokey_enum_seconds", 180)
            options.setdefault("sokey_enum_files", 1)
            options.setdefault("sokey_max_candidates", 0)
            options["client_v110_hidden_auto_sokey_enum"] = True
            auto["sokey_enum"] = True

        if not _iapt_v110_has_fb(options) and not (_iapt_v110_truthy(options.get("dexkey_enum")) or _iapt_v110_truthy(options.get("dex_enum"))):
            options["dexkey_enum"] = True
            options.setdefault("dexkey_enum_start", 1736417)
            options.setdefault("dexkey_enum_stop", 10000000)
            options["client_v110_hidden_auto_dexkey_enum"] = True
            auto["dexkey_enum"] = True

        workers = str(os.environ.get("IAPT_ENUM_WORKERS", "32") or "32").strip()
        options["enum_workers"] = workers
        options["fast_c"] = "on"
        options["dexkey_c_batch"] = True
        options["sokey_c_batch"] = True
        options["full_c_enum"] = True
        options["enum_quiet"] = True
        # A fixed-C miss must be allowed to continue into the broad C formula set.
        options.pop("no_python_fallback", None)
        return auto

    def _iapt_v10_v3_cmd(apk: Path, out_dir: Path, options: dict, probe: dict) -> list[str]:
        mutable = options if isinstance(options, dict) else dict(options or {})
        auto = _iapt_v110_autofill_hidden_v3(apk, mutable, probe)
        command = _IAPT_V110_V3_CMD_BASE(apk, out_dir, mutable, probe)
        if auto is not None:
            workers = str(mutable.get("enum_workers") or os.environ.get("IAPT_ENUM_WORKERS", "32") or "32")
            if _iapt_v110_truthy(mutable.get("sokey_enum")):
                _iapt_v110_add_once(command, "--sokey-c-batch")
            if _iapt_v110_truthy(mutable.get("dexkey_enum")) or _iapt_v110_truthy(mutable.get("dex_enum")):
                _iapt_v110_add_once(command, "--dexkey-c-batch")
            _iapt_v110_add_once(command, "--full-c-enum")
            _iapt_v110_add_once(command, "--enum-workers", workers)
            _iapt_v110_add_once(command, "--enum-quiet")
            try:
                print("IAPT_V110_ACTIVE_V3_ROUTE", json.dumps(auto, ensure_ascii=False, separators=(",", ":")), "cmd=", json.dumps(command, ensure_ascii=False))
            except Exception:
                pass
        return command

    IAPT_V110_ACTIVE_V3_ROUTE = {
        "patched_target": "_iapt_v10_v3_cmd used by V82/V10 executor",
        "hidden_normalise": "v3_entry.py --anti-encrypted-sample",
        "auto_exact_pool_match": True,
        "auto_sokey_enum": True,
        "auto_dexkey_enum": True,
        "c_enum_workers": int(os.environ.get("IAPT_ENUM_WORKERS", "32") or 32),
    }
except Exception as _iapt_v110_route_error:
    try:
        print("IAPT_V110_ACTIVE_V3_ROUTE_INSTALL_FAILED", repr(_iapt_v110_route_error))
    except Exception:
        pass
# IAPT_V110_ACTIVE_V3_ROUTE_FIX_END

# IAPT_V113_NORMALIZED_ROUTE_EXPLICIT_ENUM_BEGIN
# Hidden-resource restoration and exact current-family sokey resolution now
# happen inside v3_entry.py after assets/lib.so has been restored.  The outer
# router must preserve the user's explicit enumeration choices and must not
# silently enable sokey enumeration, dexkey enumeration, or joint full-C mode.
try:
    _IAPT_V113_BASE_V3_CMD = globals().get('_IAPT_V110_V3_CMD_BASE') or globals().get('_IAPT_V82_V3_CMD_BASE')

    def _iapt_v113_truthy(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on')

    def _iapt_v113_add_once(command, flag, value=None):
        if flag in command:
            if value is not None:
                index = command.index(flag)
                if index + 1 < len(command):
                    command[index + 1] = str(value)
            return
        command.append(flag)
        if value is not None:
            command.append(str(value))

    def _iapt_v113_drop(command, flag, takes_value=False):
        while flag in command:
            index = command.index(flag)
            del command[index]
            if takes_value and index < len(command):
                del command[index]

    def _iapt_v10_v3_cmd(apk: Path, out_dir: Path, options: dict, probe: dict) -> list[str]:
        if not callable(_IAPT_V113_BASE_V3_CMD):
            raise RuntimeError('V113: original V3 command builder unavailable')
        mutable = dict(options or {})
        anti = bool((probe or {}).get('anti')) or any(
            _iapt_v113_truthy(mutable.get(key))
            for key in ('anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore')
        )
        if anti:
            mutable['anti_encrypted_sample'] = True
            # Packed libygsiyu.so can still be analysed by the normal engine.
            # This is not key enumeration and does not change user-selected flags.
            if not (_iapt_v113_truthy(mutable.get('custom_dynamic_key')) or
                    str(mutable.get('server_key_pool_mode') or '').strip().lower() in ('selected', 'enum')):
                mutable.setdefault('dynamic_key', True)

        command = _IAPT_V113_BASE_V3_CMD(apk, out_dir, mutable, probe)

        # Remove automatic V110/V112 enumeration artefacts in case the captured
        # base was already wrapped on a partially upgraded server.
        explicit_sokey = _iapt_v113_truthy((options or {}).get('sokey_enum'))
        explicit_dex = (_iapt_v113_truthy((options or {}).get('dexkey_enum')) or
                        _iapt_v113_truthy((options or {}).get('dex_enum')))
        explicit_full = _iapt_v113_truthy((options or {}).get('full_c_enum'))
        if not explicit_sokey:
            for flag, takes in (
                ('--sokey-enum', False), ('--sokey-c-batch', False),
                ('--sokey-enum-seconds', True), ('--sokey-enum-files', True),
                ('--sokey-max-candidates', True),
            ):
                _iapt_v113_drop(command, flag, takes)
        if not explicit_dex:
            for flag, takes in (
                ('--dexkey-enum', False), ('--dexkey-c-batch', False),
                ('--dexkey-enum-start', True), ('--dexkey-enum-stop', True),
                ('--no-dexkey-dex-hint', False),
            ):
                _iapt_v113_drop(command, flag, takes)
        if not explicit_full:
            _iapt_v113_drop(command, '--full-c-enum', False)

        workers = str((options or {}).get('enum_workers') or os.environ.get('IAPT_ENUM_WORKERS', '32') or '32')
        normal_workers = str((options or {}).get('threads') or os.environ.get('IAPT_NORMAL_WORKERS', '32') or '32')
        if explicit_sokey:
            _iapt_v113_add_once(command, '--sokey-c-batch')
        if explicit_dex:
            _iapt_v113_add_once(command, '--dexkey-c-batch')
        if explicit_full:
            _iapt_v113_add_once(command, '--full-c-enum')
        if explicit_sokey or explicit_dex or explicit_full:
            _iapt_v113_add_once(command, '--enum-workers', workers)
            _iapt_v113_add_once(command, '--enum-quiet')
        _iapt_v113_add_once(command, '--fast-c', str((options or {}).get('fast_c') or 'on'))
        _iapt_v113_add_once(command, '--threads', normal_workers)

        try:
            print('IAPT_V113_EXPLICIT_ENUM_ROUTE', json.dumps({
                'anti': anti,
                'sokey_enum': explicit_sokey,
                'dexkey_enum': explicit_dex,
                'full_c_enum': explicit_full,
                'workers': workers,
                'command': command,
            }, ensure_ascii=False, separators=(',', ':')), flush=True)
        except Exception:
            pass
        return command

    def _iapt_v112_task_timeout(options: dict, scheme: str) -> int:
        # Keep process-group cleanup but no longer impose V112's fixed 300s
        # anti-sample limit.  Explicit time-based sokey enumeration gets its
        # configured duration plus a completion margin.
        if str(scheme or '').lower() == 'ancient':
            default = 1200
        elif _iapt_v113_truthy((options or {}).get('sokey_enum')):
            try:
                default = int((options or {}).get('sokey_enum_seconds') or 180) + 300
            except Exception:
                default = 900
        elif (_iapt_v113_truthy((options or {}).get('dexkey_enum')) or
              _iapt_v113_truthy((options or {}).get('dex_enum'))):
            default = 1200
        else:
            default = 900
        try:
            value = int(os.environ.get('IAPT_V3_TASK_TIMEOUT_SEC', str(default)) or default)
        except Exception:
            value = default
        return max(60, min(value, 7200))

    IAPT_V113_ROUTE = {
        'version': 'V113-normalize-libso-first-explicit-enum',
        'hidden_resolution': 'inside-v3-entry-after-normalized-assets-lib.so',
        'automatic_sokey_enum': False,
        'automatic_dexkey_enum': False,
        'full_c_enum': 'explicit-only',
        'enum_workers': int(os.environ.get('IAPT_ENUM_WORKERS', '32') or 32),
        'process_group_cleanup': True,
    }
except Exception as _iapt_v113_error:
    try:
        print('IAPT_V113_INSTALL_FAILED', repr(_iapt_v113_error), flush=True)
    except Exception:
        pass
# IAPT_V113_NORMALIZED_ROUTE_EXPLICIT_ENUM_END

# IAPT_V116_STRICT_ANTI_LINEAR_DOWNLOAD_BEGIN
# V116 invariants:
# 1. Hidden-container restoration is controlled only by the final client task
#    options. Detector/probe results are diagnostic and never enable it.
# 2. Every enumeration switch is forwarded exactly as submitted.
# 3. assets/res is exported only when the client explicitly requests resource decryption.
try:
    _IAPT_V116_ROUTE_BASE = _iapt_v82_route
    _IAPT_V116_CMD_BASE = _iapt_v10_v3_cmd
    _IAPT_V116_EXECUTE_BASE = _IAPT_V82_BASE_EXECUTE

    def _iapt_v116_truthy(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        return str(value or '').strip().lower() in ('1', 'true', 'yes', 'on', 'y')

    def _iapt_v116_explicit_anti(options):
        options = options if isinstance(options, dict) else {}
        return any(_iapt_v116_truthy(options.get(key)) for key in (
            'anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore'
        ))

    def _iapt_v116_apk_marker(apk_path, marker_name):
        try:
            import zipfile as _iapt_v116_zipfile
            wanted = str(marker_name or '').replace('\\', '/').lower()
            with _iapt_v116_zipfile.ZipFile(str(apk_path), 'r') as archive:
                return any(
                    (not item.is_dir()) and item.filename.replace('\\', '/').lower() == wanted
                    for item in archive.infolist()
                )
        except Exception:
            return False

    def _iapt_v116_drop(command, flag, takes_value=False):
        while flag in command:
            index = command.index(flag)
            del command[index]
            if takes_value and index < len(command):
                del command[index]

    def _iapt_v116_add(command, flag, value=None):
        if flag in command:
            if value is not None:
                index = command.index(flag)
                if index + 1 < len(command):
                    command[index + 1] = str(value)
            return
        command.append(flag)
        if value is not None:
            command.append(str(value))

    def _iapt_v82_route(task: dict, options: dict, apk_path: Path) -> dict:
        route = dict(_IAPT_V116_ROUTE_BASE(task, options, apk_path) or {})
        explicit_anti = _iapt_v116_explicit_anti(options)
        # Probe data may classify the sample, but it cannot alter the submitted
        # feature switch.  This prevents hidden containers from being restored
        # when the user manually turned the switch off after auto-detection.
        route['anti'] = bool(explicit_anti)
        if str(route.get('reason') or '').startswith('hidden-resource'):
            route['reason'] = 'hidden-resource-explicit' if explicit_anti else 'hidden-resource-disabled'
        return route

    def _iapt_v10_v3_cmd(apk: Path, out_dir: Path, options: dict, probe: dict) -> list[str]:
        explicit_anti = _iapt_v116_explicit_anti(options)
        clean_probe = dict(probe or {})
        clean_probe['anti'] = bool(explicit_anti)
        command = list(_IAPT_V116_CMD_BASE(apk, out_dir, options, clean_probe))

        if explicit_anti:
            _iapt_v116_add(command, '--anti-encrypted-sample')
        else:
            _iapt_v116_drop(command, '--anti-encrypted-sample')

        # Independent inner-source switch. It does not imply or enable the
        # outer hidden-lib/anti-encrypted-sample path.
        anti_iapec = _iapt_v116_truthy((options or {}).get('anti_iapec_encryption'))
        if anti_iapec:
            _iapt_v116_add(command, '--anti-iapec-encryption')
        else:
            _iapt_v116_drop(command, '--anti-iapec-encryption')

        skip_resources = (
            _iapt_v116_truthy((options or {}).get('no_decrypt_resource_files')) or
            _iapt_v116_truthy((options or {}).get('skip_anti_resources')) or
            _iapt_v116_apk_marker(apk, 'META-INF/iapt/no_decrypt_resource_files')
        )
        if explicit_anti and skip_resources:
            _iapt_v116_add(command, '--skip-anti-resources')
        else:
            _iapt_v116_drop(command, '--skip-anti-resources')

        sokey_enum = _iapt_v116_truthy((options or {}).get('sokey_enum'))
        dexkey_enum = (_iapt_v116_truthy((options or {}).get('dexkey_enum')) or
                       _iapt_v116_truthy((options or {}).get('dex_enum')))
        full_c_enum = _iapt_v116_truthy((options or {}).get('full_c_enum'))
        for flag, enabled in (
            ('--sokey-enum', sokey_enum),
            ('--sokey-c-batch', sokey_enum),
            ('--dexkey-enum', dexkey_enum),
            ('--dexkey-c-batch', dexkey_enum),
            ('--full-c-enum', full_c_enum),
        ):
            if enabled:
                _iapt_v116_add(command, flag)
            else:
                _iapt_v116_drop(command, flag)
        if not sokey_enum:
            for flag in ('--sokey-enum-seconds', '--sokey-enum-files', '--sokey-max-candidates'):
                _iapt_v116_drop(command, flag, True)
        if not dexkey_enum:
            for flag in ('--dexkey-enum-start', '--dexkey-enum-stop'):
                _iapt_v116_drop(command, flag, True)
            _iapt_v116_drop(command, '--no-dexkey-dex-hint')
        if sokey_enum or dexkey_enum or full_c_enum:
            workers = str((options or {}).get('enum_workers') or os.environ.get('IAPT_ENUM_WORKERS', '32') or '32')
            _iapt_v116_add(command, '--enum-workers', workers)
            _iapt_v116_add(command, '--enum-quiet')
        else:
            _iapt_v116_drop(command, '--enum-workers', True)
            _iapt_v116_drop(command, '--enum-quiet')


        # IAPT_ANTI_RUNTIME_V2_V116_DIRECT_BEGIN
        if explicit_anti:
            _iapt_v2_version = str(
                (options or {}).get('decrypt_version')
                or (options or {}).get('task_version')
                or 'v3'
            ).strip().lower()
            try:
                _iapt_v2_feature_id = int(
                    (options or {}).get('feature_id') or 0
                )
            except Exception:
                _iapt_v2_feature_id = 0

            if (
                _iapt_v2_version in ('v3', '3', 'iapp_v3')
                and _iapt_v2_feature_id != 6
            ):
                _iapt_v2_wrapper = (
                    Path(__file__).resolve().parent
                    / 'tools'
                    / 'iapt_v10'
                    / 'iapt_anti_runtime_entry.py'
                )
                if not _iapt_v2_wrapper.is_file():
                    raise RuntimeError(
                        'V2 anti runtime entry missing: '
                        + str(_iapt_v2_wrapper)
                    )

                _iapt_v2_script_index = None
                for _iapt_v2_index, _iapt_v2_value in enumerate(command):
                    _iapt_v2_base = (
                        str(_iapt_v2_value)
                        .replace('\\', '/')
                        .rsplit('/', 1)[-1]
                        .lower()
                    )
                    if _iapt_v2_base in (
                        'v3_entry.py',
                        'iapp_v3_decrypt_entry.py',
                        'iapp_auto_decrypt.py',
                    ):
                        _iapt_v2_script_index = _iapt_v2_index
                        break

                if _iapt_v2_script_index is None:
                    raise RuntimeError(
                        'V2 V116 route cannot locate V3 entry: '
                        + repr(command)
                    )

                _iapt_v2_old_entry = str(
                    command[_iapt_v2_script_index]
                )
                command[_iapt_v2_script_index] = str(
                    _iapt_v2_wrapper
                )
                _iapt_v116_add(
                    command,
                    '--anti-encrypted-sample',
                )

                print(
                    '[IAPT_ANTI_RUNTIME_V2] '
                    'v116_direct_routed=true old_entry='
                    + repr(_iapt_v2_old_entry)
                    + ' cmd='
                    + json.dumps(
                        command,
                        ensure_ascii=False,
                    ),
                    flush=True,
                )
        # IAPT_ANTI_RUNTIME_V2_V116_DIRECT_END

        print('IAPT_V116_COMMAND ' + json.dumps({
            'anti': explicit_anti,
            'skip_anti_resources': skip_resources,
            'probe_anti_ignored': bool((probe or {}).get('anti')) and not explicit_anti,
            'sokey_enum': sokey_enum,
            'dexkey_enum': dexkey_enum,
            'full_c_enum': full_c_enum,
            'command': command,
        }, ensure_ascii=False, separators=(',', ':')), flush=True)
        return command

    def _iapt_v116_options(task):
        raw = (task or {}).get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            obj = json.loads(raw or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v116_public_rows(task, out_dir):
        task = task if isinstance(task, dict) else {}
        options = _iapt_v116_options(task)
        anti = _iapt_v116_explicit_anti(options)
        skip_resources = (
            _iapt_v116_truthy(options.get('no_decrypt_resource_files')) or
            _iapt_v116_truthy(options.get('skip_anti_resources'))
        )
        try:
            feature_id = int(task.get('feature_id') or options.get('feature_id') or 0)
        except Exception:
            feature_id = 0
        versions = {
            str(task.get('decrypt_version') or '').strip().lower(),
            str(options.get('decrypt_version') or '').strip().lower(),
            str(options.get('task_version') or '').strip().lower(),
        }
        versions.discard('')
        source_restore = (
            feature_id == 8
            or bool(versions.intersection({
                'restore', 'source_restore', 'dex_restore',
                'static_dex_restore', 'source_dex_restore',
            }))
            or _iapt_v116_truthy(options.get('source_restore'))
        )
        restore_value = options.get('restore_resource_names')
        restore_resources = (
            True if restore_value is None
            else _iapt_v116_truthy(restore_value)
        )

        rows = _sanitize_public_file_rows(out_dir, _scan_out_files(out_dir))
        public = []
        for row in rows:
            rel = str((row or {}).get('rel_path') or '').replace('\\', '/').lstrip('./')
            if source_restore:
                allowed = (
                    rel.startswith('src/')
                    or (restore_resources and rel.startswith('res/'))
                )
            else:
                allowed = (
                    rel.startswith('src/')
                    or (
                        anti
                        and not skip_resources
                        and rel.startswith('assets/res/')
                    )
                )
            if not allowed:
                continue
            item = dict(row)
            item['rel_path'] = rel
            public.append(item)
        public.sort(key=lambda item: str(item.get('rel_path') or ''))
        return public

    def _finish_public_file_rows(task: dict, files: list[dict]) -> list[dict]:
        if not task or not task.get('out_dir'):
            return []
        out_dir = Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        public = _iapt_v116_public_rows(task, out_dir)
        _write_file_index(out_dir, public)
        _sync_public_file_counts(task, public)
        return public

    def _iapt_v116_actual_sources(rows):
        out = []
        for row in rows or []:
            rel = str((row or {}).get('rel_path') or '').replace('\\', '/').lower()
            if rel.startswith('src/') and rel.endswith(('.iyu', '.myu', '.java')):
                out.append(rel)
        return out

    def _iapt_v116_execute(task_id: int, task: dict, options: dict, scheme: str, probe: dict):
        result = _IAPT_V116_EXECUTE_BASE(int(task_id), task, options, scheme, probe)
        if str(scheme or '').lower() != 'v3' or not isinstance(result, dict) or not result.get('ok'):
            return result
        fresh = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),)) or task or {}
        rows = list_task_files(fresh)
        actual = _iapt_v116_actual_sources(rows)
        if not actual:
            reason = '解密失败：V3 只生成了 .project/元数据，没有生成 mian.iyu 或其他实际源码文件'
            db.exec(
                "UPDATE tasks SET status='failed',error_text=%s,file_count=0,total_bytes=0 WHERE id=%s",
                (reason, int(task_id)),
            )
            result = dict(result)
            result.update({'ok': False, 'status': 'failed', 'error': reason, 'files': 0, 'bytes': 0})
            return result
        count = len(rows)
        total = sum(int((row or {}).get('size_bytes') or 0) for row in rows)
        db.exec('UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s', (count, total, int(task_id)))
        result = dict(result)
        result.update({'files': count, 'bytes': total, 'actual_source_files': len(actual)})
        return result

    _IAPT_V82_BASE_EXECUTE = _iapt_v116_execute

    IAPT_V116_ROUTE = {
        'version': 'V116-anti-resource-toggle-client-compact-512k',
        'hidden_restore': 'final-client-parameter-only',
        'probe_can_enable_anti': False,
        'enumeration': 'exact-client-flags',
        'source_output': 'src/**',
        'anti_resource_output': 'assets/res/** only when client unchecks no_decrypt_resource_files',
        'anti_resource_default': 'skip',
        'apk_res_output': False,
        'project_only_success': False,
    }
except Exception as _iapt_v116_error:
    print('IAPT_V116_INSTALL_FAILED ' + repr(_iapt_v116_error), flush=True)
# IAPT_V116_STRICT_ANTI_LINEAR_DOWNLOAD_END

# IAPT_V118_RUNNER_INVARIANT_BEGIN
# The final worker route must agree with task creation.  A compact ancient APK
# carries a route marker, so even a legacy options rewrite cannot make the
# worker execute the V3 engine and overwrite decrypt_version after refresh.
try:
    import zipfile as _iapt_v118_zipfile
    _IAPT_V118_ANCIENT_MARKER = 'META-INF/iapt/decrypt_scheme_ancient'

    def _iapt_v118_has_ancient_marker(apk_path):
        try:
            with _iapt_v118_zipfile.ZipFile(str(apk_path), 'r') as archive:
                wanted = _IAPT_V118_ANCIENT_MARKER.lower()
                return any(
                    (not item.is_dir())
                    and item.filename.replace('\\', '/').lstrip('/').lower() == wanted
                    for item in archive.infolist()
                )
        except Exception:
            return False

    def _iapt_v118_option_ancient(options):
        options = options if isinstance(options, dict) else {}
        for key in ('client_route_lock', 'client_final_scheme', 'decrypt_scheme', 'decrypt_version', 'task_version'):
            if str(options.get(key) or '').strip().lower() in ('ancient', 'old', 'legacy', 'ancient-marker-v118'):
                return True
        return _iapt_v82_truthy(options.get('legacy_iapp')) or _iapt_v82_truthy(options.get('old_iapp'))

    _IAPT_V118_ROUTE_BASE = _iapt_v82_route

    def _iapt_v82_route(task, options, apk_path):
        marker = _iapt_v118_has_ancient_marker(apk_path)
        explicit = _iapt_v118_option_ancient(options)
        if marker or explicit:
            old_sokey = _iapt_v82_first_old_sokey(options or {})
            if not old_sokey:
                try:
                    _detected, _candidate, _meta = _iapt_v82_old_probe(apk_path)
                    old_sokey = _iapt_v82_old_sokey(_candidate)
                except Exception:
                    old_sokey = ''
            return {
                'scheme': 'ancient',
                'reason': 'ancient-upload-marker-v118' if marker else 'explicit-ancient-v118',
                'old_sokey': old_sokey,
                'new_hidden': '',
                'anti': False,
                'probe': {'marker': marker, 'explicit': explicit},
            }
        return _IAPT_V118_ROUTE_BASE(task, options, apk_path)

    _IAPT_V118_PREPARE_BASE = _iapt_v82_prepare_options

    def _iapt_v82_prepare_options(options, route):
        prepared = _IAPT_V118_PREPARE_BASE(options, route)
        if str((route or {}).get('scheme') or '').lower() == 'ancient':
            prepared['decrypt_scheme'] = 'ancient'
            prepared['decrypt_version'] = 'ancient'
            prepared['task_version'] = 'ancient'
            prepared['client_final_scheme'] = 'ancient'
            prepared['client_scheme_explicit'] = True
            prepared['client_route_lock'] = 'ancient-marker-v118'
            prepared['legacy_iapp'] = True
            prepared['old_iapp'] = True
        return prepared

    _IAPT_V118_ANCIENT_CMD_BASE = _iapt_v10_ancient_cmd

    def _iapt_v10_ancient_cmd(apk, out_dir, options):
        command = list(_IAPT_V118_ANCIENT_CMD_BASE(apk, out_dir, options))
        dex_enum = _iapt_v82_truthy((options or {}).get('dexkey_enum')) or _iapt_v82_truthy((options or {}).get('dex_enum'))
        if dex_enum and '--enum-workers' not in command:
            command += ['--enum-workers', str(os.environ.get('IAPT_ENUM_WORKERS', '32') or '32')]
        return command

    IAPT_V118_ROUTE = {
        'version': 'V118-marker-locked-ancient-route',
        'marker_first': True,
        'worker_cannot_rewrite_ancient_to_v3': True,
        'ancient_engine': 'iapp_old_decrypt.py',
        'enum_workers': int(os.environ.get('IAPT_ENUM_WORKERS', '32') or 32),
    }
    print('IAPT_V118_RUNNER installed', flush=True)
except Exception as _iapt_v118_runner_exc:
    print('IAPT_V118_RUNNER_INSTALL_FAILED', repr(_iapt_v118_runner_exc), flush=True)
# IAPT_V118_RUNNER_INVARIANT_END


# IAPT_V124_DIRECT_ANCIENT_RUNNER_BEGIN
try:
    import json as _iapt_v124_json
    import os as _iapt_v124_os
    import subprocess as _iapt_v124_subprocess
    import time as _iapt_v124_time
    import shutil as _iapt_v124_shutil
    import zipfile as _iapt_v124_zipfile
    from pathlib import Path as _iapt_v124_Path

    IAPT_V124_RUNNER_VERSION = 'V124-direct-old-iapp-sokey-failfast-client-flags'
    _IAPT_V124_BASE_RUN_TASK = globals().get('run_task')

    def _iapt_v124_bool(v):
        if v is True or v == 1: return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y')

    def _iapt_v124_options(task):
        try:
            obj = _iapt_v124_json.loads((task or {}).get('options_json') or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v124_is_ancient_options(options):
        options = options if isinstance(options, dict) else {}
        for key in ('client_submission_path','client_route_lock','client_final_scheme','decrypt_scheme','decrypt_version','task_version','public_scheme'):
            value = str(options.get(key) or '').strip().lower()
            if value in ('decrypt-ancient','ancient','old','legacy','old_iapp','iapp_old','webcat') or value.startswith('ancient-endpoint'):
                return True
        return _iapt_v124_bool(options.get('legacy_iapp')) or _iapt_v124_bool(options.get('old_iapp'))

    def _iapt_v124_zip_has_ancient_marker(path):
        try:
            with _iapt_v124_zipfile.ZipFile(path, 'r') as zf:
                names = {str(n or '').replace('\\','/').lower() for n in zf.namelist()}
            return 'meta-inf/iapt/decrypt_scheme_ancient' in names
        except Exception:
            return False

    def _iapt_v124_first(options, *keys):
        for k in keys:
            v = str((options or {}).get(k) or '').strip()
            if v:
                return v
        return ''

    def _iapt_v124_old_script():
        here = _iapt_v124_Path(__file__).resolve().parent
        for p in (here / 'tools' / 'iapt_v10' / 'iapp_old_decrypt.py', here / 'tools' / 'iapp_old_decrypt.py'):
            if p.is_file(): return p
        raise RuntimeError('iapp_old_decrypt.py not found')

    def _iapt_v124_public_scan(task_id, out_dir):
        fn = globals().get('scan_files')
        if callable(fn):
            try: return fn(int(task_id), out_dir)
            except Exception: pass
        count = 0; total = 0
        for p in _iapt_v124_Path(out_dir).rglob('*'):
            if p.is_file():
                count += 1; total += int(p.stat().st_size or 0)
        return count, total

    def _iapt_v124_parse_report(out_dir, stdout):
        meta = {}
        report_path = _iapt_v124_Path(out_dir) / 'old_iapp_report.json'
        if report_path.is_file():
            try:
                report = _iapt_v124_json.loads(report_path.read_text(encoding='utf-8', errors='ignore'))
                if isinstance(report, dict):
                    for key in ('app_name','package_name','version_name','version_code','total_ms'):
                        if str(report.get(key) or '').strip(): meta[key] = report.get(key)
            except Exception: pass
        if not meta:
            fn = globals().get('parse_meta')
            if callable(fn):
                try: meta = fn(stdout or '') or {}
                except Exception: meta = {}
        return meta

    def _iapt_v124_fail_task(task_id, task, options, reason, started=None):
        task_no = str((task or {}).get('task_no') or '')
        out_dir = APP_STORAGE / 'tasks' / task_no
        log_path = APP_STORAGE / 'tasks' / (task_no + '.log')
        out_dir.mkdir(parents=True, exist_ok=True)
        if started is None: started = _iapt_v124_time.perf_counter()
        elapsed = (_iapt_v124_time.perf_counter() - started) * 1000.0
        text = _iapt_v124_json.dumps(options or {}, ensure_ascii=False, separators=(',', ':'))
        try:
            log_path.write_text('[IAPT_V124] ancient fail-fast\n' + str(reason) + '\n', encoding='utf-8', errors='replace')
        except Exception: pass
        try:
            db.exec("UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,decrypt_version='ancient',options_json=%s WHERE id=%s", (float(elapsed), str(reason)[-4000:], text, int(task_id)))
        except Exception:
            pass
        return {'ok': False, 'task_id': int(task_id), 'scheme': 'ancient', 'error': str(reason)}

    def _iapt_v124_direct_ancient(task_id, task, options):
        task_no = str((task or {}).get('task_no') or '')
        apk = APP_STORAGE / 'uploads' / (task_no + '.apk')
        out_dir = APP_STORAGE / 'tasks' / task_no
        log_path = APP_STORAGE / 'tasks' / (task_no + '.log')
        started = _iapt_v124_time.perf_counter()
        if not apk.is_file():
            return _iapt_v124_fail_task(task_id, task, options, '上传文件不存在：' + str(apk), started)
        # Keep all client flags exactly as submitted.  Only public family fields are normalized.
        options = dict(options or {})
        options.update({'decrypt_scheme':'ancient','decrypt_version':'ancient','task_version':'ancient','public_scheme':'ancient','client_final_scheme':'ancient','legacy_iapp':True,'old_iapp':True})
        sokey = _iapt_v124_first(options, 'old_sokey', 'sokey', 'hidden', 'client_sokey')
        probe = options.get('old_sokey_probe') if isinstance(options.get('old_sokey_probe'), dict) else {}
        probe_error = str(probe.get('error') or '').strip()
        manual_sokey = _iapt_v124_bool(options.get('client_ancient_sokey_manual')) or _iapt_v124_bool(options.get('client_sokey_manual')) or _iapt_v124_bool(options.get('manual_sokey'))
        client_auto_sokey = _iapt_v124_bool(options.get('client_ancient_sokey_auto'))
        wants_sokey_enum = _iapt_v124_bool(options.get('sokey_enum')) or _iapt_v124_bool(options.get('sokey_c_batch'))
        wants_server_sokey = _iapt_v124_bool(options.get('server_sokey'))
        # User-confirmed rule: if automatic old-iApp sokey extraction failed, fail immediately;
        # do not hide it by running dexkey enum for minutes.  Manual sokey input and explicit
        # sokey/server enumeration are still honored as client parameters.
        if probe_error and client_auto_sokey and not manual_sokey and not wants_sokey_enum and not wants_server_sokey:
            return _iapt_v124_fail_task(task_id, task, options, '远古sokey提取失败：' + probe_error, started)
        if not sokey and not wants_sokey_enum and not wants_server_sokey:
            return _iapt_v124_fail_task(task_id, task, options, '远古sokey提取失败：客户端未提交sokey，也未开启sokey枚举/服务器提取', started)
        text = _iapt_v124_json.dumps(options, ensure_ascii=False, separators=(',', ':'))
        _iapt_v124_shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        db.exec("UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='ancient',options_json=%s WHERE id=%s", (str(out_dir), str(log_path), text, int(task_id)))
        script = _iapt_v124_old_script()
        pyexe = _iapt_v124_os.environ.get('PYTHON') or _iapt_v124_os.sys.executable
        cmd = [pyexe, str(script), '--apk', str(apk), '--outdir', str(out_dir)]
        dexkey = _iapt_v124_first(options, 'dexkey', 'fb', 'client_dexkey')
        if sokey: cmd += ['--sokey', sokey]
        if dexkey: cmd += ['--dexkey', dexkey]
        # Exact client flags.  No automatic enum enable/disable here.
        if _iapt_v124_bool(options.get('dexkey_enum')) or _iapt_v124_bool(options.get('dex_enum')):
            cmd.append('--dexkey-enum')
        if _iapt_v124_bool(options.get('server_sokey')):
            cmd.append('--server-sokey')
        # Current old-iApp engine has no --sokey-enum CLI; keep the flag in options/logs and let
        # older engines with server-sokey handle it, but do not convert it to another mode.
        sig_hex = _iapt_v124_first(options, 'signature_bytes_hex', 'signature_hex', 'cert_hex')
        sig_mode = str(options.get('signature_mode') or '').strip().lower()
        if sig_mode == 'verify' or sig_hex:
            cmd += ['--signature-mode', 'verify']
        if sig_hex:
            cmd += ['--signature-bytes-hex', sig_hex]
        password = _iapt_v124_first(options, 'password', 'user_password')
        if password: cmd += ['--password', password]
        main_file = _iapt_v124_first(options, 'main_file', 'mainFile')
        if main_file: cmd += ['--main-file', main_file]
        env = _iapt_v124_os.environ.copy(); env.update({'PYTHONIOENCODING':'utf-8','PYTHONUTF8':'1','LANG':'C.UTF-8','LC_ALL':'C.UTF-8'})
        header = '[IAPT_V124] direct ancient runner\n[IAPT_V124] command=' + _iapt_v124_json.dumps(cmd, ensure_ascii=False) + '\n[IAPT_V124] options=' + text + '\n'
        sem = globals().get('_decrypt_semaphore'); acquired = False
        try:
            if sem is not None:
                sem.acquire(); acquired = True
            proc = _iapt_v124_subprocess.run(cmd, stdout=_iapt_v124_subprocess.PIPE, stderr=_iapt_v124_subprocess.STDOUT, text=True, env=env, timeout=360)
            output = proc.stdout or ''
            log_path.write_text(header + output, encoding='utf-8', errors='replace')
            if int(proc.returncode) != 0:
                raise RuntimeError(('old-iApp exit=%s ' % proc.returncode) + output[-3000:])
            count, total = _iapt_v124_public_scan(int(task_id), out_dir)
            if count <= 0: raise RuntimeError('old-iApp engine returned no files')
            meta = _iapt_v124_parse_report(out_dir, output)
            total_ms = float(meta.get('total_ms') or ((_iapt_v124_time.perf_counter() - started) * 1000.0))
            db.exec("UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,file_count=%s,total_bytes=%s,decrypt_version='ancient',error_text=NULL WHERE id=%s", (total_ms, str(meta.get('app_name') or ''), str(meta.get('package_name') or ''), str(meta.get('version_name') or ''), str(meta.get('version_code') or ''), int(count), int(total), int(task_id)))
            fn = globals().get('settle_decrypt_quota_once')
            if callable(fn):
                try: fn(int(task_id))
                except Exception: pass
            return {'ok': True, 'task_id': int(task_id), 'scheme': 'ancient', 'files': count, 'bytes': total}
        except Exception as exc:
            return _iapt_v124_fail_task(task_id, task, options, '远古解密失败：' + str(exc), started)
        finally:
            if acquired:
                try: sem.release()
                except Exception: pass

    def run_task(task_id: int):
        task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
        if not task:
            return _IAPT_V124_BASE_RUN_TASK(int(task_id)) if callable(_IAPT_V124_BASE_RUN_TASK) else None
        options = _iapt_v124_options(task)
        apk = APP_STORAGE / 'uploads' / (str(task.get('task_no') or '') + '.apk')
        ancient = str((task or {}).get('decrypt_version') or '').strip().lower() == 'ancient' or _iapt_v124_is_ancient_options(options) or (apk.is_file() and _iapt_v124_zip_has_ancient_marker(apk))
        if ancient:
            return _iapt_v124_direct_ancient(int(task_id), task, options)
        return _IAPT_V124_BASE_RUN_TASK(int(task_id)) if callable(_IAPT_V124_BASE_RUN_TASK) else None

    IAPT_V124_ROUTE = {'version': IAPT_V124_RUNNER_VERSION, 'direct_old_iapp': True, 'sokey_failfast': True, 'client_flags_exact': True, 'enum_workers': int(_iapt_v124_os.environ.get('IAPT_ENUM_WORKERS','32') or 32)}
    print('IAPT_V124_DIRECT_ANCIENT_RUNNER installed', flush=True)
except Exception as _iapt_v124_runner_exc:
    print('IAPT_V124_DIRECT_ANCIENT_RUNNER_INSTALL_FAILED', repr(_iapt_v124_runner_exc), flush=True)
# IAPT_V124_DIRECT_ANCIENT_RUNNER_END

# IAPT_V126_RUNNER_STRICT_ANCIENT_BEGIN
try:
    IAPT_V126_RUNNER_VERSION = 'V126-runner-strict-family-classifier'
    def _iapt_v126_runner_bool(v):
        if v is True or v == 1:
            return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y')
    def _iapt_v126_runner_is_ancient_options(options):
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
        return _iapt_v126_runner_bool(options.get('legacy_iapp')) or _iapt_v126_runner_bool(options.get('old_iapp'))
    globals()['_iapt_v121_runner_is_ancient_options'] = _iapt_v126_runner_is_ancient_options
    print('IAPT_V126_RUNNER strict classifier installed', flush=True)
except Exception as _iapt_v126_runner_exc:
    print('IAPT_V126_RUNNER_INSTALL_FAILED', repr(_iapt_v126_runner_exc), flush=True)
# IAPT_V126_RUNNER_STRICT_ANCIENT_END


# IAPT_V128_DIRECT_ANCIENT_RUNNER_BEGIN
try:
    import json as _iapt_v128_json, os as _iapt_v128_os, subprocess as _iapt_v128_subprocess, shutil as _iapt_v128_shutil, time as _iapt_v128_time, sys as _iapt_v128_sys
    from pathlib import Path as _iapt_v128_Path
    IAPT_V128_RUNNER_VERSION='V128-direct-ancient-runner-fast-c-old-engine'
    _IAPT_V128_BASE_RUN_TASK=globals().get('run_task')
    def _iapt_v128_bool(v):
        if v is True or v == 1: return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y')
    def _iapt_v128_options(task):
        try:
            obj=_iapt_v128_json.loads((task or {}).get('options_json') or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception: return {}
    def _iapt_v128_family(opt, task=None):
        opt=opt if isinstance(opt, dict) else {}
        for k in ('client_final_scheme','decrypt_scheme','task_version','public_scheme'):
            v=str(opt.get(k) or '').strip().lower()
            if v in ('ancient','old_iapp','iapp_old','legacy-old'): return 'ancient'
            if v in ('v3','v6','modern','new'): return 'v3' if v in ('modern','new') else v
        path=str(opt.get('client_submission_path') or '').strip().lower(); lock=str(opt.get('client_route_lock') or '').strip().lower()
        if path in ('decrypt-ancient','ancient-decrypt') or lock.startswith('ancient-') or str(opt.get('v3_upload_mode') or '').startswith('ancient_'): return 'ancient'
        if _iapt_v128_bool(opt.get('client_ancient_minimal_upload')) and str(opt.get('client_cipher_entry') or '').replace('\\','/').lower() == 'assets/lib.so': return 'ancient'
        if task is not None:
            dbv=str((task or {}).get('decrypt_version') or '').strip().lower()
            if dbv in ('ancient','v3','v6'): return dbv
        return ''
    def _iapt_v128_first(opt,*keys):
        for k in keys:
            v=opt.get(k)
            if v is not None and str(v).strip()!='': return str(v).strip()
        return ''
    def _iapt_v128_old_script():
        here=_iapt_v128_Path(__file__).resolve().parent
        for p in (here/'tools'/'iapt_v10'/'iapp_old_decrypt.py', here/'tools'/'iapp_old_decrypt.py'):
            if p.is_file(): return p
        raise RuntimeError('iapp_old_decrypt.py not found')
    def _iapt_v128_scan_source(out_dir):
        root=_iapt_v128_Path(out_dir); count=0; total=0; source_count=0
        for p in root.rglob('*'):
            if not p.is_file(): continue
            rel=str(p.relative_to(root)).replace('\\','/')
            if rel.startswith('.tmp/') or rel in ('analysis_report.txt','old_iapp_report.json'): continue
            count += 1
            try: total += int(p.stat().st_size or 0)
            except Exception: pass
            if rel.startswith('src/') and p.suffix.lower() in ('.iyu','.myu','.mjava','.java','.mlua','.mjs','.ijs','.ijava'):
                source_count += 1
        return count,total,source_count
    def _iapt_v128_fail(task_id, task, opt, msg, started=None):
        if started is None: started=_iapt_v128_time.perf_counter()
        task_no=str((task or {}).get('task_no') or '')
        out=APP_STORAGE/'tasks'/task_no; out.mkdir(parents=True, exist_ok=True)
        logp=APP_STORAGE/'tasks'/(task_no+'.log')
        try: logp.write_text('[IAPT_V128] ancient fail\n'+str(msg)+'\n', encoding='utf-8', errors='replace')
        except Exception: pass
        text=_iapt_v128_json.dumps(opt or {}, ensure_ascii=False, separators=(',',':'))
        try: db.exec("UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,decrypt_version='ancient',options_json=%s WHERE id=%s", (((_iapt_v128_time.perf_counter()-started)*1000.0), str(msg)[-4000:], text, int(task_id)))
        except Exception: pass
        return {'ok':False,'scheme':'ancient','error':str(msg)}
    def _iapt_v128_run_ancient(task_id, task, opt):
        started=_iapt_v128_time.perf_counter(); opt=dict(opt or {})
        task_no=str((task or {}).get('task_no') or '')
        apk=APP_STORAGE/'uploads'/(task_no+'.apk')
        out=APP_STORAGE/'tasks'/task_no; logp=APP_STORAGE/'tasks'/(task_no+'.log')
        opt.update({'decrypt_scheme':'ancient','decrypt_version':'ancient','task_version':'ancient','public_scheme':'ancient','client_final_scheme':'ancient'})
        if not apk.is_file(): return _iapt_v128_fail(task_id, task, opt, '上传文件不存在：'+str(apk), started)
        probe=opt.get('old_sokey_probe') if isinstance(opt.get('old_sokey_probe'), dict) else {}
        probe_err=str(probe.get('error') or '').strip()
        manual=_iapt_v128_bool(opt.get('client_ancient_sokey_manual')) or _iapt_v128_bool(opt.get('client_sokey_manual')) or _iapt_v128_bool(opt.get('manual_sokey'))
        auto=_iapt_v128_bool(opt.get('client_ancient_sokey_auto'))
        wants_sokey_enum=_iapt_v128_bool(opt.get('sokey_enum')) or _iapt_v128_bool(opt.get('sokey_c_batch'))
        wants_server_sokey=_iapt_v128_bool(opt.get('server_sokey'))
        if probe_err and auto and not manual and not wants_sokey_enum and not wants_server_sokey:
            return _iapt_v128_fail(task_id, task, opt, '远古sokey提取失败：'+probe_err, started)
        sokey=_iapt_v128_first(opt,'old_sokey','sokey','hidden','client_sokey')
        if not sokey and not wants_sokey_enum and not wants_server_sokey:
            return _iapt_v128_fail(task_id, task, opt, '远古sokey提取失败：客户端未提交sokey，也未开启sokey枚举/服务器提取', started)
        _iapt_v128_shutil.rmtree(out, ignore_errors=True); out.mkdir(parents=True, exist_ok=True)
        text=_iapt_v128_json.dumps(opt, ensure_ascii=False, separators=(',',':'))
        db.exec("UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='ancient',options_json=%s WHERE id=%s", (str(out),str(logp),text,int(task_id)))
        cmd=[_iapt_v128_os.environ.get('PYTHON') or _iapt_v128_sys.executable, str(_iapt_v128_old_script()), '--apk', str(apk), '--outdir', str(out)]
        if sokey: cmd += ['--sokey', sokey]
        dexkey=_iapt_v128_first(opt,'dexkey','fb','client_dexkey')
        if dexkey: cmd += ['--dexkey', dexkey]
        if _iapt_v128_bool(opt.get('dexkey_enum')) or _iapt_v128_bool(opt.get('dex_enum')): cmd += ['--dexkey-enum']
        if wants_sokey_enum: cmd += ['--sokey-enum']
        if wants_server_sokey: cmd += ['--server-sokey']
        sig=_iapt_v128_first(opt,'signature_bytes_hex','signature_hex','cert_hex')
        if str(opt.get('signature_mode') or '').strip().lower() == 'verify' or sig:
            cmd += ['--signature-mode','verify']
        else:
            cmd += ['--signature-mode','skip']
        if sig: cmd += ['--signature-bytes-hex', sig]
        pw=_iapt_v128_first(opt,'password','user_password')
        if pw: cmd += ['--password', pw]
        mf=_iapt_v128_first(opt,'main_file','mainFile')
        if mf: cmd += ['--main-file', mf]
        if opt.get('dexkey_enum_start') not in (None,''): cmd += ['--dexkey-enum-start', str(opt.get('dexkey_enum_start'))]
        if opt.get('dexkey_enum_stop') not in (None,''): cmd += ['--dexkey-enum-stop', str(opt.get('dexkey_enum_stop'))]
        workers=str(opt.get('enum_workers') or _iapt_v128_os.environ.get('IAPT_OLD_ENUM_WORKERS') or _iapt_v128_os.environ.get('IAPT_ENUM_WORKERS') or '32')
        if workers: cmd += ['--enum-workers', workers]
        if opt.get('enum_chunk_size') not in (None,''): cmd += ['--enum-chunk-size', str(opt.get('enum_chunk_size'))]
        env=_iapt_v128_os.environ.copy(); env.update({'PYTHONIOENCODING':'utf-8','PYTHONUTF8':'1','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','IAPT_OLD_FAST_ENUM':'1','IAPT_OLD_ENUM_WORKERS':workers or '32'})
        header='[IAPT_V128] direct ancient runner fast old engine\ncommand='+_iapt_v128_json.dumps(cmd, ensure_ascii=False)+'\noptions='+text+'\n'
        try: logp.write_text(header+'started\n', encoding='utf-8', errors='replace')
        except Exception: pass
        try:
            proc=_iapt_v128_subprocess.run(cmd, stdout=_iapt_v128_subprocess.PIPE, stderr=_iapt_v128_subprocess.STDOUT, text=True, env=env, timeout=int(opt.get('ancient_timeout') or 480))
            output=proc.stdout or ''
            logp.write_text(header+output, encoding='utf-8', errors='replace')
            if int(proc.returncode) != 0: raise RuntimeError(('old-iApp exit=%s ' % proc.returncode)+output[-3000:])
            count,total,source_count=_iapt_v128_scan_source(out)
            if count <= 0 or source_count <= 0: raise RuntimeError('old-iApp engine returned no source files')
            total_ms=(_iapt_v128_time.perf_counter()-started)*1000.0
            rp=out/'old_iapp_report.json'; meta={}
            if rp.is_file():
                try:
                    meta=_iapt_v128_json.loads(rp.read_text(encoding='utf-8', errors='ignore')) or {}; total_ms=float(meta.get('total_ms') or total_ms)
                except Exception: pass
            summary='方案：远古'
            if meta.get('sokey'): summary += '\nsokey：'+str(meta.get('sokey'))
            if meta.get('dexkey'): summary += '\ndexkey：'+str(meta.get('dexkey'))
            if meta.get('decrypted_count') or meta.get('member_count'): summary += '\n成员解密：%s/%s' % (meta.get('decrypted_count') or 0, meta.get('member_count') or 0)
            db.exec("UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,file_count=%s,total_bytes=%s,decrypt_version='ancient',error_text=NULL WHERE id=%s", (total_ms,str(meta.get('app_name') or ''),str(meta.get('package_name') or ''),str(meta.get('version_name') or ''),str(meta.get('version_code') or ''),int(count),int(total),int(task_id)))
            return {'ok':True,'scheme':'ancient','files':count,'bytes':total}
        except Exception as e:
            return _iapt_v128_fail(task_id, task, opt, '远古解密失败：'+str(e), started)
    def run_task(task_id:int):
        task=db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
        if not task:
            return _IAPT_V128_BASE_RUN_TASK(int(task_id)) if callable(_IAPT_V128_BASE_RUN_TASK) else None
        opt=_iapt_v128_options(task)
        if _iapt_v128_family(opt, task) == 'ancient': return _iapt_v128_run_ancient(int(task_id), task, opt)
        return _IAPT_V128_BASE_RUN_TASK(int(task_id)) if callable(_IAPT_V128_BASE_RUN_TASK) else None
    IAPT_V128_ROUTE={'version':IAPT_V128_RUNNER_VERSION,'exact_client_flags':True,'fast_old_engine':True,'enum_workers':int(_iapt_v128_os.environ.get('IAPT_ENUM_WORKERS','32') or 32)}
    print('IAPT_V128_DIRECT_ANCIENT_RUNNER installed', flush=True)
except Exception as _iapt_v128_exc:
    print('IAPT_V128_DIRECT_ANCIENT_RUNNER_INSTALL_FAILED', repr(_iapt_v128_exc), flush=True)
# IAPT_V128_DIRECT_ANCIENT_RUNNER_END

# IAPT_V130H_ANCIENT_RUNNER_BEGIN
try:
    import json as _j, os as _os, sys as _sys, subprocess as _sp, shutil as _shutil, time as _time, signal as _signal
    from pathlib import Path as _Path
    IAPT_V130H_VERSION = 'V130H-ancient-engine-hardtimeout-patchfix'
    _IAPT_V130H_BASE_RUN_TASK = globals().get('run_task')

    def _v130h_truthy(v):
        if v is True or v == 1:
            return True
        return str(v or '').strip().lower() in ('1','true','yes','on','y')

    def _v130h_opts(task):
        try:
            x = _j.loads((task or {}).get('options_json') or '{}')
            return x if isinstance(x, dict) else {}
        except Exception:
            return {}

    def _v130h_is_ancient(opt, task=None):
        opt = opt if isinstance(opt, dict) else {}
        for k in ('client_final_scheme','decrypt_scheme','task_version','public_scheme'):
            if str(opt.get(k) or '').strip().lower() == 'ancient':
                return True
        if str(opt.get('client_submission_path') or '').strip().lower() in ('decrypt-ancient','ancient-decrypt'):
            return True
        if str(opt.get('client_route_lock') or '').strip().lower().startswith('ancient'):
            return True
        if str(opt.get('v3_upload_mode') or '').startswith('ancient_'):
            return True
        if _v130h_truthy(opt.get('legacy_iapp')) or _v130h_truthy(opt.get('old_iapp')):
            return True
        if task is not None and str((task or {}).get('decrypt_version') or '').strip().lower() == 'ancient':
            return True
        return False

    def _v130h_first(opt, *keys):
        for k in keys:
            v = opt.get(k)
            if v is not None and str(v).strip() != '':
                return str(v).strip()
        return ''

    def _v130h_old_script():
        base = _Path(__file__).resolve().parent
        for p in (base/'tools'/'iapt_v10'/'iapp_old_decrypt.py', base/'tools'/'iapp_old_decrypt.py'):
            if p.is_file():
                return p
        raise RuntimeError('old-iApp decryptor not found')

    def _v130h_scan(out_dir):
        out_dir = _Path(out_dir)
        count = total = source = 0
        for p in out_dir.rglob('*'):
            if not p.is_file():
                continue
            rel = str(p.relative_to(out_dir)).replace('\\','/')
            if rel.startswith('.tmp/') or rel in ('analysis_report.txt','old_iapp_report.json','output_files.json'):
                continue
            count += 1
            try:
                total += int(p.stat().st_size or 0)
            except Exception:
                pass
            low = rel.lower()
            if low.startswith('src/') and low.endswith(('.iyu','.myu','.mjava','.ijava','.java','.mlua','.ilua','.mjs','.ijs')):
                source += 1
        return count, total, source

    def _v130h_update_fail(task_id, task, opt, msg, started):
        task_no = str((task or {}).get('task_no') or '')
        out = APP_STORAGE / 'tasks' / task_no
        out.mkdir(parents=True, exist_ok=True)
        logp = APP_STORAGE / 'tasks' / (task_no + '.log')
        try:
            with open(logp, 'a', encoding='utf-8', errors='replace') as f:
                f.write('\n[IAPT_V130H_FAIL] ' + str(msg) + '\n')
        except Exception:
            pass
        opt = dict(opt or {})
        opt.update({'decrypt_scheme':'ancient','decrypt_version':'ancient','task_version':'ancient','public_scheme':'ancient','iapt_v130h_error':str(msg)})
        try:
            db.exec("UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,decrypt_version='ancient',options_json=%s WHERE id=%s", (((_time.perf_counter()-started)*1000.0), str(msg)[-4000:], _j.dumps(opt, ensure_ascii=False, separators=(',',':')), int(task_id)))
        except Exception as e:
            print('[IAPT_V130H] fail update warn', repr(e), flush=True)
        return {'ok': False, 'error': str(msg), 'scheme': 'ancient'}

    def _v130h_run_ancient(task_id, task, opt):
        started = _time.perf_counter()
        opt = dict(opt or {})
        task_no = str((task or {}).get('task_no') or '')
        apk = APP_STORAGE / 'uploads' / (task_no + '.apk')
        out = APP_STORAGE / 'tasks' / task_no
        logp = APP_STORAGE / 'tasks' / (task_no + '.log')
        opt.update({'decrypt_scheme':'ancient','decrypt_version':'ancient','task_version':'ancient','public_scheme':'ancient','runner_version':IAPT_V130H_VERSION})
        if not apk.is_file():
            return _v130h_update_fail(task_id, task, opt, '上传文件不存在：' + str(apk), started)

        sokey = _v130h_first(opt, 'old_sokey', 'sokey', 'hidden', 'client_sokey')
        wants_sokey_enum = _v130h_truthy(opt.get('sokey_enum')) or _v130h_truthy(opt.get('sokey_c_batch'))
        wants_server_sokey = _v130h_truthy(opt.get('server_sokey'))
        probe = opt.get('old_sokey_probe') if isinstance(opt.get('old_sokey_probe'), dict) else {}
        probe_err = str(probe.get('error') or '').strip()
        manual = _v130h_truthy(opt.get('client_ancient_sokey_manual')) or _v130h_truthy(opt.get('manual_sokey'))
        auto = _v130h_truthy(opt.get('client_ancient_sokey_auto'))
        if probe_err and auto and not manual and not wants_sokey_enum and not wants_server_sokey:
            return _v130h_update_fail(task_id, task, opt, '远古sokey提取失败：' + probe_err, started)
        if not sokey and not wants_sokey_enum and not wants_server_sokey:
            return _v130h_update_fail(task_id, task, opt, '远古sokey提取失败：客户端未提交sokey，也未开启sokey枚举/服务器提取', started)

        _shutil.rmtree(out, ignore_errors=True)
        out.mkdir(parents=True, exist_ok=True)
        cmd = [_os.environ.get('PYTHON') or _sys.executable, str(_v130h_old_script()), '--apk', str(apk), '--outdir', str(out)]
        if sokey:
            cmd += ['--sokey', sokey]
        dexkey = _v130h_first(opt, 'dexkey', 'fb', 'client_dexkey')
        if dexkey:
            cmd += ['--dexkey', dexkey]
        if _v130h_truthy(opt.get('dexkey_enum')) or _v130h_truthy(opt.get('dex_enum')):
            cmd += ['--dexkey-enum']
        if wants_sokey_enum:
            cmd += ['--sokey-enum']
        if wants_server_sokey:
            cmd += ['--server-sokey']
        if opt.get('dexkey_enum_start') not in (None, ''):
            cmd += ['--dexkey-enum-start', str(opt.get('dexkey_enum_start'))]
        if opt.get('dexkey_enum_stop') not in (None, ''):
            cmd += ['--dexkey-enum-stop', str(opt.get('dexkey_enum_stop'))]
        workers = str(opt.get('enum_workers') or _os.environ.get('IAPT_OLD_ENUM_WORKERS') or _os.environ.get('IAPT_ENUM_WORKERS') or '32')
        cmd += ['--enum-workers', workers]
        if opt.get('enum_chunk_size') not in (None, ''):
            cmd += ['--enum-chunk-size', str(opt.get('enum_chunk_size'))]
        if _v130h_truthy(opt.get('no_python_fallback')):
            cmd += ['--no-python-fallback']
        sigmode = str(opt.get('signature_mode') or '').strip().lower()
        if sigmode in ('verify','skip'):
            cmd += ['--signature-mode', sigmode]
        if opt.get('signature_bytes_hex'):
            cmd += ['--signature-bytes-hex', str(opt.get('signature_bytes_hex'))]

        env = _os.environ.copy()
        env.update({'PYTHONIOENCODING':'utf-8','PYTHONUTF8':'1','LANG':'C.UTF-8','LC_ALL':'C.UTF-8','IAPT_OLD_FAST_ENUM':'1','IAPT_OLD_ENUM_WORKERS':workers,'IAPT_OLD_NO_PYTHON_FALLBACK':'1' if _v130h_truthy(opt.get('no_python_fallback')) else '0'})
        opt['actual_ancient_command'] = ' '.join(cmd)
        opt['actual_ancient_engine'] = str(_v130h_old_script())
        text = _j.dumps(opt, ensure_ascii=False, separators=(',',':'))
        db.exec("UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='ancient',options_json=%s WHERE id=%s", (str(out), str(logp), text, int(task_id)))
        header = '[IAPT_V130H] direct ancient runner\ncmd=' + _j.dumps(cmd, ensure_ascii=False) + '\noptions=' + text + '\n'
        logp.write_text(header + 'stage=spawn\n', encoding='utf-8', errors='replace')
        timeout = int(opt.get('ancient_timeout') or _os.environ.get('IAPT_ANCIENT_TIMEOUT_SEC') or 180)
        proc = None
        try:
            proc = _sp.Popen(cmd, stdout=_sp.PIPE, stderr=_sp.STDOUT, text=True, env=env, start_new_session=True)
            try:
                output, _ = proc.communicate(timeout=timeout)
            except _sp.TimeoutExpired:
                try:
                    _os.killpg(proc.pid, _signal.SIGKILL)
                except Exception:
                    try: proc.kill()
                    except Exception: pass
                try:
                    output, _ = proc.communicate(timeout=3)
                except Exception:
                    output = ''
                logp.write_text(header + (output or '') + '\n[IAPT_V130H_TIMEOUT]\n', encoding='utf-8', errors='replace')
                return _v130h_update_fail(task_id, task, opt, '远古解密超时：%s秒；请检查sokey/dexkey/签名或C枚举器' % timeout, started)
            output = output or ''
            logp.write_text(header + output, encoding='utf-8', errors='replace')
            if int(proc.returncode or 0) != 0:
                raise RuntimeError(('old-iApp exit=%s ' % proc.returncode) + output[-5000:])
            count, total, source = _v130h_scan(out)
            if source <= 0:
                raise RuntimeError('old-iApp engine returned no source files; files=%s' % count)
            meta = {}
            rp = out / 'old_iapp_report.json'
            if rp.is_file():
                try: meta = _j.loads(rp.read_text(encoding='utf-8', errors='ignore') or '{}')
                except Exception: meta = {}
            total_ms = float(meta.get('total_ms') or ((_time.perf_counter()-started)*1000.0))
            db.exec("UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,version_name=%s,version_code=%s,file_count=%s,total_bytes=%s,decrypt_version='ancient',error_text=NULL WHERE id=%s", (total_ms, str(meta.get('app_name') or (task or {}).get('app_name') or ''), str(meta.get('package_name') or (task or {}).get('package_name') or ''), str(meta.get('version_name') or (task or {}).get('version_name') or ''), str(meta.get('version_code') or (task or {}).get('version_code') or ''), int(count), int(total), int(task_id)))
            return {'ok': True, 'scheme': 'ancient', 'files': count, 'bytes': total}
        except Exception as e:
            if proc is not None and proc.poll() is None:
                try: _os.killpg(proc.pid, _signal.SIGKILL)
                except Exception: pass
            return _v130h_update_fail(task_id, task, opt, '远古解密失败：' + str(e), started)

    def run_task(task_id: int):
        task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),))
        if task:
            opt = _v130h_opts(task)
            if _v130h_is_ancient(opt, task):
                return _v130h_run_ancient(int(task_id), task, opt)
        return _IAPT_V130H_BASE_RUN_TASK(int(task_id)) if callable(_IAPT_V130H_BASE_RUN_TASK) else None

    IAPT_V130H_ROUTE = {'version': IAPT_V130H_VERSION, 'timeout_sec': 180, 'direct_ancient_runner': True}
    print('[IAPT_V130H] ancient runner installed', flush=True)
except Exception as _e:
    print('[IAPT_V130H] install failed', repr(_e), flush=True)
# IAPT_V130H_ANCIENT_RUNNER_END

# IAPT_V152_NONV3_PUBLIC_OUTPUT_BEGIN
# IAPT_RESOURCE_RESTORE_FINAL_V152_FIX_V1
try:
    def _iapt_v152_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            obj = json.loads(raw or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v152_truthy(value):
        if value is True or value == 1:
            return True
        if value is False or value == 0 or value is None:
            return False
        return str(value).strip().lower() in ('1', 'true', 'yes', 'on', 'y')

    def _iapt_v152_standalone(task, options=None):
        task = task if isinstance(task, dict) else {}
        options = options if isinstance(options, dict) else _iapt_v152_options(task)
        kind = str(options.get('task_kind') or task.get('task_kind') or '').strip().lower()
        versions = {
            str(task.get('decrypt_version') or '').strip().lower(),
            str(options.get('decrypt_version') or '').strip().lower(),
            str(options.get('task_version') or '').strip().lower(),
        }
        versions.discard('')
        standalone_versions = {
            'v6', '6', 'key', 'dynkey', 'dynamic_key', 'dynamic_key_extract',
            'sokey', 'server_sokey', 'server_sokey_extract',
            'restore', 'source_restore', 'fn_restore', 'numeric_restore',
            'numeric_source_restore', 'dex_restore', 'static_dex_restore',
            'source_dex_restore', 'iact', 'iact_restore',
        }
        standalone_kinds = {
            'v6', 'dynamic_key_extract', 'standalone_dynamic_key_extract',
            'server_sokey_extract', 'standalone_so_extract', 'sokey_extract',
            'source_restore', 'source_dex_restore', 'static_dex_restore',
            'numeric_source_restore', 'iact_restore',
        }
        if versions.intersection(standalone_versions) or kind in standalone_kinds:
            return True
        for key in (
            'dynamic_key_extract', 'server_sokey_extract', 'source_restore',
            'numeric_source_restore', 'static_dex_restore', 'iact_dynamic_decrypt',
        ):
            if _iapt_v152_truthy(options.get(key)):
                return True
        apk_name = str(task.get('apk_name') or '').strip().lower()
        app_name = str(task.get('app_name') or '').strip().lower()
        if apk_name.endswith(('_sokey.zip', '_iact.zip', '_numeric.zip', '_dex_restore.zip', '_src.zip')):
            return True
        if any(token in app_name for token in ('动态key提取', '服务器获取sokey', 'so key 提取', '源码还原', 'dex还原', 'iact')):
            return True
        try:
            if int(task.get('feature_id') or options.get('feature_id') or 0) in (6, 8):
                return True
        except Exception:
            pass
        return False

    def _iapt_v152_source_restore_with_resources(task, options, out_dir):
        task = task if isinstance(task, dict) else {}
        options = options if isinstance(options, dict) else {}
        out_dir = Path(str(out_dir or task.get('out_dir') or ''))

        try:
            feature_id = int(task.get('feature_id') or options.get('feature_id') or 0)
        except Exception:
            feature_id = 0

        versions = {
            str(task.get('decrypt_version') or '').strip().lower(),
            str(options.get('decrypt_version') or '').strip().lower(),
            str(options.get('task_version') or '').strip().lower(),
        }
        versions.discard('')
        kind = str(
            options.get('task_kind')
            or task.get('task_kind')
            or ''
        ).strip().lower()

        requested = (
            feature_id == 8
            or bool(versions.intersection({
                'restore', 'source_restore', 'dex_restore',
                'static_dex_restore', 'source_dex_restore',
            }))
            or kind in {
                'source_restore', 'source_dex_restore',
                'static_dex_restore',
            }
            or _iapt_v152_truthy(options.get('source_restore'))
        )

        # Detail/download can receive an old task snapshot.  Recognize a
        # completed restore from its stable disk/log evidence.
        app_name = str(task.get('app_name') or '').strip().lower()
        evidence = (
            '混淆还原' in app_name
            or '源码还原' in app_name
            or (out_dir / 'deobfuscation_map.txt').is_file()
        )
        log_path = Path(str(task.get('log_path') or ''))
        if not evidence and log_path.is_file():
            try:
                evidence = 'IAPT source restore' in log_path.read_text(
                    encoding='utf-8',
                    errors='ignore',
                )
            except Exception:
                evidence = False

        requested = requested or (
            (out_dir / 'src').is_dir()
            and (out_dir / 'res').is_dir()
            and evidence
        )

        value = options.get('restore_resource_names')
        enabled = True if value is None else _iapt_v152_truthy(value)
        return bool(requested and enabled)


    def _iapt_v152_public_rows(task, out_dir):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(out_dir or task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        options = _iapt_v152_options(task)
        rows = _sanitize_public_file_rows(
            out_dir,
            _scan_out_files(out_dir),
        )

        if _iapt_v152_source_restore_with_resources(
            task,
            options,
            out_dir,
        ):
            # The restore output is standalone.  Publish all sanitized members,
            # including res/**, and use the same rows for preview/download/count.
            return rows

        if _iapt_v152_standalone(task, options):
            return rows

        legacy = globals().get('_iapt_v116_public_rows')
        if callable(legacy):
            try:
                return _sanitize_public_file_rows(
                    out_dir,
                    legacy(task, out_dir),
                )
            except Exception:
                pass

        src = [
            item for item in rows
            if str(
                item.get('rel_path') or ''
            ).replace('\\', '/').startswith('src/')
        ]
        return src if (out_dir / 'src').is_dir() else rows

    def _finish_public_file_rows(task, files=None):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(task.get('out_dir') or ''))
        rows = _iapt_v152_public_rows(task, out_dir)
        if out_dir.is_dir():
            _write_file_index(out_dir, rows)
        _sync_public_file_counts(task, rows)
        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            task = dict(task_or_id)
        else:
            task = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not task or not task.get('out_dir'):
            return []
        return _finish_public_file_rows(task)

    IAPT_V152_NONV3_PUBLIC_OUTPUT = {
        'version': 'V152-nonv3-all-sanitized-output',
        'v3': 'existing src/assets-res policy preserved',
        'standalone_and_nonv3': 'all sanitized output members',
        'old_empty_manifest': 'rescanned from disk on every detail/download request',
    }
    print('IAPT_V152_NONV3_PUBLIC_OUTPUT installed', flush=True)
except Exception as _iapt_v152_output_error:
    print('IAPT_V152_NONV3_PUBLIC_OUTPUT_FAILED ' + repr(_iapt_v152_output_error), flush=True)
# IAPT_V152_NONV3_PUBLIC_OUTPUT_END




# IAPT_SOURCE_RESTORE_SRC_RES_SOURCE_COUNT_V153_BEGIN
# Final output contract for source deobfuscation:
#   restore_resource_names=false -> publish src/**
#   restore_resource_names=true  -> publish src/** + res/**
#   tasks.file_count             -> source files only
#   tasks.total_bytes            -> all published/downloadable bytes
try:
    _IAPT_V153_PREVIOUS_SCAN_FILES = scan_files

    def _iapt_v153_truthy(value, default=False):
        if value is None:
            return bool(default)
        if value is True or value == 1:
            return True
        if value is False or value == 0:
            return False
        low = str(value).strip().lower()
        if low in ("1", "true", "yes", "on", "y"):
            return True
        if low in ("0", "false", "no", "off", "n", "none", ""):
            return False
        return bool(default)


    def _iapt_v153_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get("options_json")
        if isinstance(raw, dict):
            return dict(raw)
        try:
            value = json.loads(raw or "{}")
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}


    def _iapt_v153_is_source_restore(task, options, out_dir):
        task = task if isinstance(task, dict) else {}
        options = options if isinstance(options, dict) else {}
        out_dir = Path(str(out_dir or task.get("out_dir") or ""))

        try:
            feature_id = int(
                task.get("feature_id")
                or options.get("feature_id")
                or 0
            )
        except Exception:
            feature_id = 0

        versions = {
            str(task.get("decrypt_version") or "").strip().lower(),
            str(options.get("decrypt_version") or "").strip().lower(),
            str(options.get("task_version") or "").strip().lower(),
        }
        versions.discard("")

        task_kind = str(
            options.get("task_kind")
            or task.get("task_kind")
            or ""
        ).strip().lower()
        app_name = str(task.get("app_name") or "").strip().lower()

        explicit = (
            feature_id == 8
            or bool(versions.intersection({
                "restore",
                "source_restore",
                "source_dex_restore",
                "static_dex_restore",
                "dex_restore",
            }))
            or task_kind in {
                "source_restore",
                "source_dex_restore",
                "static_dex_restore",
            }
            or _iapt_v153_truthy(options.get("source_restore"))
            or "混淆还原" in app_name
            or "源码还原" in app_name
        )

        # Old task snapshots may not contain the final feature/version fields.
        # A real restore output has a src tree plus stable restore evidence.
        evidence = (out_dir / "deobfuscation_map.txt").is_file()
        log_path = Path(str(task.get("log_path") or ""))
        if not evidence and log_path.is_file():
            try:
                evidence = (
                    "IAPT source restore"
                    in log_path.read_text(
                        encoding="utf-8",
                        errors="ignore",
                    )
                )
            except Exception:
                evidence = False

        return bool(
            explicit
            or (
                (out_dir / "src").is_dir()
                and evidence
            )
        )


    def _iapt_v153_restore_resources_enabled(task, options, out_dir):
        if not _iapt_v153_is_source_restore(task, options, out_dir):
            return False

        value = options.get("restore_resource_names")
        if value is not None:
            return _iapt_v153_truthy(value)

        # For old task snapshots, the completed res tree is authoritative.
        try:
            return any(
                path.is_file()
                for path in (Path(out_dir) / "res").rglob("*")
            )
        except Exception:
            return False


    def _iapt_v153_filter_restore_rows(rows, include_res):
        output = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            relative = str(
                row.get("rel_path") or ""
            ).replace("\\", "/").lstrip("./")
            allowed = (
                relative.startswith("src/")
                or (
                    include_res
                    and relative.startswith("res/")
                )
            )
            if not allowed:
                continue
            item = dict(row)
            item["rel_path"] = relative
            output.append(item)
        output.sort(
            key=lambda item: str(item.get("rel_path") or "")
        )
        return output


    def _iapt_v153_public_rows(task, out_dir):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(out_dir or task.get("out_dir") or ""))
        if not out_dir.is_dir():
            return []

        options = _iapt_v153_options(task)
        if _iapt_v153_is_source_restore(
            task,
            options,
            out_dir,
        ):
            rows = _sanitize_public_file_rows(
                out_dir,
                _scan_out_files(out_dir),
            )
            include_res = _iapt_v153_restore_resources_enabled(
                task,
                options,
                out_dir,
            )
            return _iapt_v153_filter_restore_rows(
                rows,
                include_res,
            )

        # Preserve every non-source-restore output rule already installed by
        # V152/V116 and the anti-resource pipeline.
        previous = globals().get("_iapt_v152_public_rows")
        if callable(previous):
            return _sanitize_public_file_rows(
                out_dir,
                previous(task, out_dir),
            )

        return _sanitize_public_file_rows(
            out_dir,
            _scan_out_files(out_dir),
        )


    def _iapt_v153_is_source_file(relative):
        relative = str(relative or "").replace("\\", "/").lower()
        if not relative.startswith("src/"):
            return False
        return relative.endswith((
            ".iyu",
            ".myu",
            ".mjava",
            ".ijava",
            ".java",
            ".mlua",
            ".ilua",
            ".mjs",
            ".ijs",
        ))


    def _iapt_v153_sync_counts(task, public_rows):
        task = task if isinstance(task, dict) else {}
        try:
            task_id = int(task.get("id") or 0)
        except Exception:
            task_id = 0
        if task_id <= 0:
            return

        source_count = sum(
            1 for row in (public_rows or [])
            if _iapt_v153_is_source_file(
                (row or {}).get("rel_path")
            )
        )
        downloadable_bytes = sum(
            int((row or {}).get("size_bytes") or 0)
            for row in (public_rows or [])
        )

        try:
            current_count = int(task.get("file_count") or -1)
        except Exception:
            current_count = -1
        try:
            current_bytes = int(task.get("total_bytes") or -1)
        except Exception:
            current_bytes = -1

        if (
            current_count != source_count
            or current_bytes != downloadable_bytes
        ):
            db.exec(
                "UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s",
                (
                    source_count,
                    downloadable_bytes,
                    task_id,
                ),
            )
            task["file_count"] = source_count
            task["total_bytes"] = downloadable_bytes


    def _finish_public_file_rows(task, files=None):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(task.get("out_dir") or ""))
        rows = _iapt_v153_public_rows(task, out_dir)
        if out_dir.is_dir():
            # The index/manifest intentionally contains both src and res.
            _write_file_index(out_dir, rows)

        options = _iapt_v153_options(task)
        if _iapt_v153_is_source_restore(
            task,
            options,
            out_dir,
        ):
            # Only source files affect the displayed task file_count.
            _iapt_v153_sync_counts(task, rows)
        else:
            _sync_public_file_counts(task, rows)
        return rows


    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            task = dict(task_or_id)
        else:
            task = db.one(
                "SELECT * FROM tasks WHERE id=%s",
                (task_or_id,),
            )
        if not task or not task.get("out_dir"):
            return []
        return _finish_public_file_rows(task)


    def scan_files(task_id, out_dir):
        task = db.one(
            "SELECT * FROM tasks WHERE id=%s",
            (int(task_id),),
        ) or {
            "id": int(task_id),
            "out_dir": str(out_dir),
        }
        task["out_dir"] = str(out_dir)
        rows = _finish_public_file_rows(task)
        source_count = sum(
            1 for row in rows
            if _iapt_v153_is_source_file(
                (row or {}).get("rel_path")
            )
        )
        total = sum(
            int((row or {}).get("size_bytes") or 0)
            for row in rows
        )

        options = _iapt_v153_options(task)
        if _iapt_v153_is_source_restore(
            task,
            options,
            out_dir,
        ):
            return source_count, total

        return len(rows), total


    IAPT_SOURCE_RESTORE_SRC_RES_SOURCE_COUNT_V153 = {
        "download_roots_when_enabled": ["src/**", "res/**"],
        "download_roots_when_disabled": ["src/**"],
        "file_count": "source files under src/** only",
        "total_bytes": "all downloadable src/** + res/** bytes",
        "manifest": "all downloadable rows, never source-count truncated",
    }
    print(
        "IAPT_SOURCE_RESTORE_SRC_RES_SOURCE_COUNT_V153 installed",
        flush=True,
    )
except Exception as _iapt_v153_error:
    print(
        "IAPT_SOURCE_RESTORE_SRC_RES_SOURCE_COUNT_V153_FAILED "
        + repr(_iapt_v153_error),
        flush=True,
    )
# IAPT_SOURCE_RESTORE_SRC_RES_SOURCE_COUNT_V153_END

# IAPT_ANTI_FINAL_ROUTE_IDEMPOTENT_V1_BEGIN
try:
    _IAPT_ANTI_FINAL_PREV_BUILD_CMD = build_cmd

    def _iapt_anti_final_truthy(value):
        if value is True or value == 1:
            return True
        if value is False or value == 0 or value is None:
            return False
        return str(value).strip().lower() in ('1', 'true', 'yes', 'on', 'y')

    def _iapt_anti_final_requested(options):
        options = options if isinstance(options, dict) else {}
        return any(_iapt_anti_final_truthy(options.get(key)) for key in (
            'anti_encrypted_sample', 'anti_qiushui', 'hidden_resource_restore',
            'static_resource_analysis', 'static_parameter_analysis',
        ))

    def build_cmd(apk_path: Path, out_dir: Path, options: dict):
        options = dict(options or {})
        command = list(_IAPT_ANTI_FINAL_PREV_BUILD_CMD(apk_path, out_dir, options))
        if not _iapt_anti_final_requested(options):
            return command
        version = str(options.get('decrypt_version') or options.get('task_version') or '').strip().lower()
        try:
            feature_id = int(options.get('feature_id') or 0)
        except Exception:
            feature_id = 0
        if version in ('v6', '6') or feature_id == 6:
            return command

        wrapper = Path(__file__).resolve().parent / 'tools' / 'iapt_v10' / 'iapt_anti_runtime_entry.py'
        if not wrapper.is_file():
            raise RuntimeError('anti runtime entry missing: ' + str(wrapper))

        accepted = {
            'v3_entry.py', 'iapp_v3_decrypt_entry.py', 'iapp_auto_decrypt.py',
            'iapt_anti_runtime_entry.py',
        }
        index = None
        old_entry = ''
        for i, value in enumerate(command):
            name = Path(str(value).replace('\\', '/')).name.lower()
            if name in accepted:
                index = i
                old_entry = name
                break
        if index is None:
            raise RuntimeError('anti route cannot locate V3/core entry: ' + repr(command))
        if old_entry != 'iapt_anti_runtime_entry.py':
            command[index] = str(wrapper)
        if '--anti-encrypted-sample' not in command:
            command.insert(index + 1, '--anti-encrypted-sample')
        skip = _iapt_anti_final_truthy(options.get('skip_anti_resources')) or _iapt_anti_final_truthy(options.get('no_decrypt_resource_files'))
        if skip and '--skip-anti-resources' not in command:
            command.append('--skip-anti-resources')
        print('[IAPT_ANTI_FINAL_ROUTE] old_entry=' + old_entry + ' cmd=' + json.dumps(command, ensure_ascii=False), flush=True)
        return command

    print('[IAPT_ANTI_FINAL_ROUTE] installed', flush=True)
except Exception as _iapt_anti_final_route_error:
    print('[IAPT_ANTI_FINAL_ROUTE] install failed ' + repr(_iapt_anti_final_route_error), flush=True)
# IAPT_ANTI_FINAL_ROUTE_IDEMPOTENT_V1_END

# IAPT_SOURCE_RESTORE_RES_SELFHEAL_V154_BEGIN
# Final source-restore contract and old-task repair:
#   * explicit restore_resource_names=false -> src/** only
#   * otherwise source restore defaults to src/** + res/**
#   * a detail/download request repairs a missing res/** tree from the original
#     uploaded source archive, including archives with a project-root prefix
#   * file_count remains source-code-only; public manifest contains src + res
try:
    import stat as _iapt_v154_stat
    import zipfile as _iapt_v154_zipfile

    _IAPT_V154_PREVIOUS_PUBLIC_ROWS = globals().get('_iapt_v153_public_rows')

    def _iapt_v154_truthy(value, default=False):
        if value is None:
            return bool(default)
        if value is True or value == 1:
            return True
        if value is False or value == 0:
            return False
        low = str(value).strip().lower()
        if low in ('1', 'true', 'yes', 'on', 'y'):
            return True
        if low in ('0', 'false', 'no', 'off', 'n', 'none', ''):
            return False
        return bool(default)


    def _iapt_v154_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            value = json.loads(raw or '{}')
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}


    def _iapt_v154_is_source_restore(task, options, out_dir):
        previous = globals().get('_iapt_v153_is_source_restore')
        if callable(previous):
            try:
                if previous(task, options, out_dir):
                    return True
            except Exception:
                pass
        task = task if isinstance(task, dict) else {}
        options = options if isinstance(options, dict) else {}
        try:
            feature_id = int(task.get('feature_id') or options.get('feature_id') or 0)
        except Exception:
            feature_id = 0
        versions = {
            str(task.get('decrypt_version') or '').strip().lower(),
            str(options.get('decrypt_version') or '').strip().lower(),
            str(options.get('task_version') or '').strip().lower(),
        }
        versions.discard('')
        return bool(
            feature_id == 8
            or versions.intersection({
                'restore', 'source_restore', 'source_dex_restore',
                'static_dex_restore', 'dex_restore',
            })
            or _iapt_v154_truthy(options.get('source_restore'))
            or '混淆还原' in str(task.get('app_name') or '')
            or '源码还原' in str(task.get('app_name') or '')
        )


    def _iapt_v154_resources_enabled(task, options, out_dir):
        if not _iapt_v154_is_source_restore(task, options, out_dir):
            return False
        # The worker/deobfuscator default has always been True.  Therefore an
        # absent field in an old task snapshot means enabled; only an explicit
        # false may suppress res/** publication and repair.
        if 'restore_resource_names' in options:
            return _iapt_v154_truthy(options.get('restore_resource_names'))
        return True


    def _iapt_v154_count_files(root):
        root = Path(root)
        if not root.is_dir():
            return 0
        try:
            return sum(1 for path in root.rglob('*') if path.is_file())
        except Exception:
            return 0


    def _iapt_v154_report_path(out_dir):
        return Path(out_dir) / '.tmp' / 'source_restore_res_v154.json'


    def _iapt_v154_write_report(out_dir, report):
        path = _iapt_v154_report_path(out_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        payload = dict(report or {})
        payload['version'] = 154
        payload['updated_at'] = int(time.time())
        tmp = path.with_suffix('.json.tmp')
        tmp.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2) + '\n',
            encoding='utf-8',
        )
        os.replace(tmp, path)
        return payload


    def _iapt_v154_upload_archive(task):
        task = task if isinstance(task, dict) else {}
        candidates = []
        for key in ('upload_path', 'apk_path', 'source_path'):
            value = str(task.get(key) or '').strip()
            if value:
                candidates.append(Path(value))
        task_no = str(task.get('task_no') or '').strip()
        if task_no:
            candidates.append(Path(APP_STORAGE) / 'uploads' / (task_no + '.apk'))
        seen = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except Exception:
                resolved = candidate
            key = str(resolved)
            if key in seen:
                continue
            seen.add(key)
            try:
                if resolved.is_file() and resolved.stat().st_size > 0:
                    return resolved
            except Exception:
                continue
        return None


    def _iapt_v154_safe_parts(raw_name):
        name = str(raw_name or '').replace('\\', '/')
        while name.startswith('./'):
            name = name[2:]
        if not name or name.startswith('/') or '\x00' in name:
            return None
        # Reject Windows absolute paths as well as traversal and empty pieces.
        if len(name) >= 2 and name[1] == ':':
            return None
        parts = tuple(part for part in name.split('/') if part)
        if not parts or any(part in ('.', '..') for part in parts):
            return None
        return parts


    def _iapt_v154_select_resource_entries(archive):
        src_prefixes = set()
        resource_rows = {}
        for info in archive.infolist():
            if info.is_dir():
                continue
            parts = _iapt_v154_safe_parts(info.filename)
            if not parts:
                continue
            mode = (int(info.external_attr or 0) >> 16) & 0o170000
            if mode == _iapt_v154_stat.S_IFLNK:
                continue
            lower = tuple(part.lower() for part in parts)
            for index, part in enumerate(lower):
                if part == 'src' and index + 1 < len(parts):
                    src_prefixes.add(lower[:index])
                    break
            for index, part in enumerate(lower):
                if part != 'res' or index + 1 >= len(parts):
                    continue
                # assets/res belongs to APK resource recovery, not the uploaded
                # source-project res tree used by the deobfuscation feature.
                if index > 0 and lower[index - 1] == 'assets':
                    continue
                prefix = lower[:index]
                resource_rows.setdefault(prefix, []).append((info, parts, index))
                break

        if not resource_rows:
            return (), [], {'candidate_count': 0, 'has_sibling_src': False}

        ranked = sorted(
            resource_rows.items(),
            key=lambda item: (
                0 if item[0] in src_prefixes else 1,
                -len(item[1]),
                len(item[0]),
                '/'.join(item[0]),
            ),
        )
        prefix, rows = ranked[0]
        return prefix, rows, {
            'candidate_count': len(resource_rows),
            'has_sibling_src': prefix in src_prefixes,
        }


    def _iapt_v154_repair_res_tree(task, out_dir, options=None, force=False):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(out_dir or task.get('out_dir') or ''))
        options = dict(options) if isinstance(options, dict) else _iapt_v154_options(task)
        report = {
            'task_id': int(task.get('id') or 0) if str(task.get('id') or '').isdigit() else 0,
            'task_no': str(task.get('task_no') or ''),
            'out_dir': str(out_dir),
            'restore_resource_names': bool(
                _iapt_v154_resources_enabled(task, options, out_dir)
            ),
            'existing_res_files': _iapt_v154_count_files(out_dir / 'res'),
            'uploaded_res_files': 0,
            'merged_res_files': 0,
            'preserved_res_files': 0,
            'final_res_files': 0,
            'selected_prefix': '',
            'archive': '',
            'status': 'not-source-restore',
        }

        if not _iapt_v154_is_source_restore(task, options, out_dir):
            report['final_res_files'] = report['existing_res_files']
            return _iapt_v154_write_report(out_dir, report)
        if not report['restore_resource_names']:
            report['status'] = 'explicitly-disabled'
            report['final_res_files'] = report['existing_res_files']
            return _iapt_v154_write_report(out_dir, report)
        if not out_dir.is_dir():
            report['status'] = 'missing-output-dir'
            return report

        archive_path = _iapt_v154_upload_archive(task)
        if archive_path is None:
            report['status'] = 'missing-upload-archive'
            report['final_res_files'] = report['existing_res_files']
            return _iapt_v154_write_report(out_dir, report)
        report['archive'] = str(archive_path)

        lock_path = out_dir / '.tmp' / 'source_restore_res_v154.lock'
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        lock_handle = lock_path.open('a+b')
        try:
            try:
                import fcntl as _iapt_v154_fcntl
                _iapt_v154_fcntl.flock(
                    lock_handle.fileno(),
                    _iapt_v154_fcntl.LOCK_EX,
                )
            except Exception:
                pass

            try:
                with _iapt_v154_zipfile.ZipFile(archive_path, 'r') as source:
                    prefix, rows, selection = _iapt_v154_select_resource_entries(source)
                    report.update(selection)
                    report['selected_prefix'] = '/'.join(prefix)
                    report['uploaded_res_files'] = len(rows)
                    if not rows:
                        report['status'] = 'archive-has-no-source-res'
                    else:
                        base = out_dir.resolve()
                        copied_bytes = 0
                        for info, parts, res_index in rows:
                            suffix = parts[res_index + 1:]
                            if not suffix:
                                continue
                            relative = Path('res', *suffix)
                            destination = out_dir / relative
                            try:
                                destination.resolve().relative_to(base)
                            except Exception:
                                continue
                            if destination.is_file():
                                report['preserved_res_files'] += 1
                                continue

                            size = int(info.file_size or 0)
                            if size < 0 or size > 1024 * 1024 * 1024:
                                raise RuntimeError(
                                    'resource member size is unsafe: '
                                    + str(info.filename)
                                )
                            copied_bytes += size
                            if copied_bytes > 8 * 1024 * 1024 * 1024:
                                raise RuntimeError('resource archive expands beyond 8 GiB')

                            destination.parent.mkdir(parents=True, exist_ok=True)
                            temporary = destination.with_name(
                                destination.name + '.iapt-v154.tmp-' + str(os.getpid())
                            )
                            try:
                                with source.open(info, 'r') as input_stream:
                                    with temporary.open('wb') as output_stream:
                                        shutil.copyfileobj(
                                            input_stream,
                                            output_stream,
                                            length=1024 * 1024,
                                        )
                                os.replace(temporary, destination)
                            finally:
                                try:
                                    temporary.unlink(missing_ok=True)
                                except Exception:
                                    pass
                            report['merged_res_files'] += 1
                        report['status'] = 'repaired' if report['merged_res_files'] else 'already-complete'
            except _iapt_v154_zipfile.BadZipFile as error:
                report['status'] = 'upload-is-not-zip'
                report['error'] = str(error)
            except Exception as error:
                report['status'] = 'repair-failed'
                report['error'] = type(error).__name__ + ': ' + str(error)

            report['final_res_files'] = _iapt_v154_count_files(out_dir / 'res')
            return _iapt_v154_write_report(out_dir, report)
        finally:
            try:
                lock_handle.close()
            except Exception:
                pass


    def _iapt_v154_source_file(relative):
        previous = globals().get('_iapt_v153_is_source_file')
        if callable(previous):
            try:
                return bool(previous(relative))
            except Exception:
                pass
        relative = str(relative or '').replace('\\', '/').lower()
        return relative.startswith('src/') and relative.endswith((
            '.iyu', '.myu', '.mjava', '.ijava', '.java',
            '.mlua', '.ilua', '.mjs', '.ijs',
        ))


    def _iapt_v154_filter_rows(rows, include_res):
        output = []
        for row in rows or []:
            if not isinstance(row, dict):
                continue
            relative = str(row.get('rel_path') or '').replace('\\', '/').lstrip('./')
            if not (
                relative.startswith('src/')
                or (include_res and relative.startswith('res/'))
            ):
                continue
            item = dict(row)
            item['rel_path'] = relative
            output.append(item)
        output.sort(key=lambda item: str(item.get('rel_path') or ''))
        return output


    def _iapt_v154_public_rows(task, out_dir):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(out_dir or task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        options = _iapt_v154_options(task)
        if _iapt_v154_is_source_restore(task, options, out_dir):
            include_res = _iapt_v154_resources_enabled(task, options, out_dir)
            _iapt_v154_repair_res_tree(task, out_dir, options)
            rows = _sanitize_public_file_rows(out_dir, _scan_out_files(out_dir))
            return _iapt_v154_filter_rows(rows, include_res)

        if callable(_IAPT_V154_PREVIOUS_PUBLIC_ROWS):
            return _sanitize_public_file_rows(
                out_dir,
                _IAPT_V154_PREVIOUS_PUBLIC_ROWS(task, out_dir),
            )
        return _sanitize_public_file_rows(out_dir, _scan_out_files(out_dir))


    def _iapt_v154_sync_task_fields(task, rows):
        task = task if isinstance(task, dict) else {}
        try:
            task_id = int(task.get('id') or 0)
        except Exception:
            task_id = 0
        if task_id <= 0:
            return

        rows = list(rows or [])
        source_count = sum(
            1 for row in rows
            if _iapt_v154_source_file((row or {}).get('rel_path'))
        )
        src_rows = [
            row for row in rows
            if str((row or {}).get('rel_path') or '').replace('\\', '/').startswith('src/')
        ]
        source_public_count = len(src_rows)
        source_public_bytes = sum(int((row or {}).get('size_bytes') or 0) for row in src_rows)
        total_bytes = sum(int((row or {}).get('size_bytes') or 0) for row in rows)

        assignments = ['file_count=%s', 'total_bytes=%s']
        values = [source_count, total_bytes]
        task['file_count'] = source_count
        task['total_bytes'] = total_bytes

        # A completed old task may already have been fully authorized when only
        # src/** was visible.  In that exact case, extend its downloadable
        # manifest to the omitted res/** rows without changing quota charges or
        # any ownership/feature checks.  Partially authorized tasks remain
        # untouched and keep their previous quota-limited range.
        status = str(task.get('status') or '').strip().lower()
        try:
            downloadable_count = int(task.get('downloadable_file_count') or 0)
        except Exception:
            downloadable_count = 0
        try:
            downloadable_bytes = int(task.get('downloadable_bytes') or 0)
        except Exception:
            downloadable_bytes = 0
        fully_authorized_src = (
            status in ('done', 'success', 'completed')
            and source_public_count > 0
            and downloadable_count >= source_public_count
            and downloadable_bytes >= source_public_bytes
        )
        if fully_authorized_src:
            assignments.extend([
                'downloadable_file_count=%s',
                'downloadable_bytes=%s',
            ])
            values.extend([len(rows), total_bytes])
            task['downloadable_file_count'] = len(rows)
            task['downloadable_bytes'] = total_bytes

        values.append(task_id)
        try:
            db.exec(
                'UPDATE tasks SET ' + ','.join(assignments) + ' WHERE id=%s',
                tuple(values),
            )
        except Exception:
            # Older schemas may not have downloadable_* columns.  The essential
            # source-only count and full public byte total still remain valid.
            db.exec(
                'UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s',
                (source_count, total_bytes, task_id),
            )


    def _finish_public_file_rows(task, files=None):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(task.get('out_dir') or ''))
        rows = _iapt_v154_public_rows(task, out_dir)
        if out_dir.is_dir():
            # This overwrites stale V13/V116/V152 manifests on every detail or
            # download request.  The manifest is the complete downloadable set,
            # while tasks.file_count stays source-code-only.
            _write_file_index(out_dir, rows)

        options = _iapt_v154_options(task)
        if _iapt_v154_is_source_restore(task, options, out_dir):
            _iapt_v154_sync_task_fields(task, rows)
        else:
            _sync_public_file_counts(task, rows)
        return rows


    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            task = dict(task_or_id)
        else:
            task = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not task or not task.get('out_dir'):
            return []
        return _finish_public_file_rows(task)


    def scan_files(task_id, out_dir):
        task = db.one(
            'SELECT * FROM tasks WHERE id=%s',
            (int(task_id),),
        ) or {
            'id': int(task_id),
            'out_dir': str(out_dir),
        }
        task['out_dir'] = str(out_dir)
        rows = _finish_public_file_rows(task)
        options = _iapt_v154_options(task)
        total = sum(int((row or {}).get('size_bytes') or 0) for row in rows)
        if _iapt_v154_is_source_restore(task, options, out_dir):
            return sum(
                1 for row in rows
                if _iapt_v154_source_file((row or {}).get('rel_path'))
            ), total
        return len(rows), total


    IAPT_SOURCE_RESTORE_RES_SELFHEAL_V154 = {
        'redownload_old_task': 'repair missing res from original upload archive',
        'archive_layouts': ['res/**', '<project>/res/**'],
        'manifest': 'src/** + res/** unless explicitly disabled',
        'file_count': 'source-code extensions under src/** only',
        'quota': 'never modifies actual_quota_cost or decrypt_quota_deducted',
    }
    print('IAPT_SOURCE_RESTORE_RES_SELFHEAL_V154 installed', flush=True)
except Exception as _iapt_v154_error:
    print(
        'IAPT_SOURCE_RESTORE_RES_SELFHEAL_V154_FAILED '
        + repr(_iapt_v154_error),
        flush=True,
    )
# IAPT_SOURCE_RESTORE_RES_SELFHEAL_V154_END

# IAPT_SOURCE_RESTORE_POSTDECRYPT_RES_ONLY_V157_BEGIN
# Source-restore resource publication policy:
#   src/** -> publish normally
#   res/** identical to the original uploaded archive -> hide
#   res/** with a new path or changed bytes -> publish
#   resources-section destinations in deobfuscation_map.txt -> publish
# This removes pre-decryption resource copies without guessing obfuscated names.
try:
    import zipfile as _iapt_v157_zipfile
    import zlib as _iapt_v157_zlib

    _IAPT_V157_PREVIOUS_PUBLIC_ROWS = globals().get(
        '_iapt_v154_public_rows'
    )

    def _iapt_v157_normalize_rel(value):
        relative = str(value or '').replace('\\', '/')
        while relative.startswith('./'):
            relative = relative[2:]
        return relative.lstrip('/')


    def _iapt_v157_options(task):
        previous = globals().get('_iapt_v154_options')
        if callable(previous):
            try:
                return dict(previous(task) or {})
            except Exception:
                pass
        task = task if isinstance(task, dict) else {}
        raw = task.get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            value = json.loads(raw or '{}')
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}


    def _iapt_v157_is_source_restore(task, options, out_dir):
        previous = globals().get('_iapt_v154_is_source_restore')
        if callable(previous):
            try:
                return bool(previous(task, options, out_dir))
            except Exception:
                pass
        return False


    def _iapt_v157_resources_enabled(task, options, out_dir):
        previous = globals().get('_iapt_v154_resources_enabled')
        if callable(previous):
            try:
                return bool(previous(task, options, out_dir))
            except Exception:
                pass
        return False


    def _iapt_v157_map_targets(out_dir):
        targets = set()
        path = Path(out_dir) / 'deobfuscation_map.txt'
        if not path.is_file():
            return targets
        section = ''
        try:
            lines = path.read_text(
                encoding='utf-8',
                errors='replace',
            ).splitlines()
        except Exception:
            return targets
        for raw in lines:
            line = raw.strip()
            if line.startswith('## '):
                section = line[3:].strip().lower()
                continue
            if section != 'resources' or ' -> ' not in line:
                continue
            destination = _iapt_v157_normalize_rel(
                line.split(' -> ', 1)[1].strip()
            )
            if destination.lower().startswith('res/'):
                targets.add(destination)
        return targets


    def _iapt_v157_original_res_manifest(task):
        report = {
            'archive': '',
            'status': 'missing-upload-archive',
            'selected_prefix': '',
            'entries': 0,
        }
        archive_finder = globals().get('_iapt_v154_upload_archive')
        archive_path = None
        if callable(archive_finder):
            try:
                archive_path = archive_finder(task)
            except Exception:
                archive_path = None
        if archive_path is None:
            return {}, report

        report['archive'] = str(archive_path)
        try:
            with _iapt_v157_zipfile.ZipFile(archive_path, 'r') as archive:
                selector = globals().get(
                    '_iapt_v154_select_resource_entries'
                )
                if not callable(selector):
                    report['status'] = 'missing-resource-selector'
                    return {}, report
                prefix, rows, selection = selector(archive)
                report.update(selection or {})
                report['selected_prefix'] = '/'.join(prefix)
                manifest = {}
                for info, parts, res_index in rows:
                    suffix = tuple(parts[res_index + 1:])
                    if not suffix:
                        continue
                    relative = _iapt_v157_normalize_rel(
                        'res/' + '/'.join(suffix)
                    )
                    manifest[relative] = {
                        'size': int(info.file_size or 0),
                        'crc32': int(info.CRC or 0) & 0xFFFFFFFF,
                    }
                report['entries'] = len(manifest)
                report['status'] = 'ok'
                return manifest, report
        except _iapt_v157_zipfile.BadZipFile as error:
            report['status'] = 'upload-is-not-zip'
            report['error'] = str(error)
        except Exception as error:
            report['status'] = 'manifest-error'
            report['error'] = type(error).__name__ + ': ' + str(error)
        return {}, report


    def _iapt_v157_crc32(path):
        value = 0
        with Path(path).open('rb') as stream:
            while True:
                chunk = stream.read(1024 * 1024)
                if not chunk:
                    break
                value = _iapt_v157_zlib.crc32(chunk, value)
        return value & 0xFFFFFFFF


    def _iapt_v157_filter_source_restore_rows(task, out_dir, rows):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(out_dir or task.get('out_dir') or ''))
        options = _iapt_v157_options(task)
        include_res = _iapt_v157_resources_enabled(
            task,
            options,
            out_dir,
        )
        original, archive_report = _iapt_v157_original_res_manifest(task)
        map_targets = _iapt_v157_map_targets(out_dir)
        archive_comparable = archive_report.get('status') == 'ok'

        public = []
        kept_res = []
        hidden_res = []
        counters = {
            'src_files': 0,
            'disk_res_files': 0,
            'public_res_files': 0,
            'hidden_unchanged_res_files': 0,
            'kept_map_targets': 0,
            'kept_new_paths': 0,
            'kept_changed_in_place': 0,
        }

        for raw in rows or []:
            if not isinstance(raw, dict):
                continue
            relative = _iapt_v157_normalize_rel(
                raw.get('rel_path')
            )
            lower = relative.lower()

            if lower.startswith('src/'):
                item = dict(raw)
                item['rel_path'] = relative
                public.append(item)
                counters['src_files'] += 1
                continue

            if not lower.startswith('res/'):
                continue
            counters['disk_res_files'] += 1
            if not include_res:
                continue

            path = out_dir / relative
            reason = ''
            if relative in map_targets:
                reason = 'deobfuscation-map-target'
                counters['kept_map_targets'] += 1
            elif archive_comparable:
                original_item = original.get(relative)
                if original_item is None:
                    reason = 'new-path'
                    counters['kept_new_paths'] += 1
                else:
                    try:
                        current_size = int(path.stat().st_size)
                        if current_size != int(original_item['size']):
                            reason = 'changed-size'
                        else:
                            current_crc = _iapt_v157_crc32(path)
                            if current_crc != int(original_item['crc32']):
                                reason = 'changed-crc32'
                        if reason:
                            counters['kept_changed_in_place'] += 1
                    except Exception:
                        reason = ''
            else:
                # Fail closed when the original archive cannot be compared:
                # only explicit deobfuscation-map targets may be published.
                reason = ''

            if not reason:
                counters['hidden_unchanged_res_files'] += 1
                hidden_res.append(relative)
                continue

            item = dict(raw)
            item['rel_path'] = relative
            public.append(item)
            counters['public_res_files'] += 1
            kept_res.append({
                'path': relative,
                'reason': reason,
            })

        public.sort(
            key=lambda item: str(item.get('rel_path') or '')
        )

        report = {
            'version': 157,
            'task_id': task.get('id'),
            'task_no': task.get('task_no'),
            'out_dir': str(out_dir),
            'restore_resource_names': bool(include_res),
            'archive_manifest': archive_report,
            'map_targets': sorted(map_targets),
            **counters,
            'public_res': kept_res,
            'hidden_res_sample': hidden_res[:100],
            'policy': (
                'publish new/changed/map-target res only; '
                'hide resources identical to original upload'
            ),
            'updated_at': int(time.time()),
        }
        try:
            report_path = (
                out_dir / '.tmp/source_restore_res_v157.json'
            )
            report_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = report_path.with_suffix('.json.tmp')
            temporary.write_text(
                json.dumps(
                    report,
                    ensure_ascii=False,
                    indent=2,
                ) + '\n',
                encoding='utf-8',
            )
            os.replace(temporary, report_path)
        except Exception:
            pass
        return public


    def _iapt_v157_public_rows(task, out_dir):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(out_dir or task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return []
        options = _iapt_v157_options(task)
        if _iapt_v157_is_source_restore(task, options, out_dir):
            rows = _sanitize_public_file_rows(
                out_dir,
                _scan_out_files(out_dir),
            )
            return _iapt_v157_filter_source_restore_rows(
                task,
                out_dir,
                rows,
            )

        if callable(_IAPT_V157_PREVIOUS_PUBLIC_ROWS):
            return _sanitize_public_file_rows(
                out_dir,
                _IAPT_V157_PREVIOUS_PUBLIC_ROWS(task, out_dir),
            )
        return _sanitize_public_file_rows(
            out_dir,
            _scan_out_files(out_dir),
        )


    def _iapt_v157_source_file(relative):
        previous = globals().get('_iapt_v154_source_file')
        if callable(previous):
            try:
                return bool(previous(relative))
            except Exception:
                pass
        relative = _iapt_v157_normalize_rel(relative).lower()
        return relative.startswith('src/')


    def _iapt_v157_sync_task_fields(task, rows):
        task = task if isinstance(task, dict) else {}
        try:
            task_id = int(task.get('id') or 0)
        except Exception:
            task_id = 0
        if task_id <= 0:
            return

        rows = list(rows or [])
        source_count = sum(
            1 for row in rows
            if _iapt_v157_source_file(
                (row or {}).get('rel_path')
            )
        )
        total_bytes = sum(
            int((row or {}).get('size_bytes') or 0)
            for row in rows
        )

        assignments = ['file_count=%s', 'total_bytes=%s']
        values = [source_count, total_bytes]
        task['file_count'] = source_count
        task['total_bytes'] = total_bytes

        try:
            current_downloadable = int(
                task.get('downloadable_file_count') or 0
            )
        except Exception:
            current_downloadable = 0
        if current_downloadable >= len(rows):
            assignments.extend([
                'downloadable_file_count=%s',
                'downloadable_bytes=%s',
            ])
            values.extend([len(rows), total_bytes])
            task['downloadable_file_count'] = len(rows)
            task['downloadable_bytes'] = total_bytes

        values.append(task_id)
        try:
            db.exec(
                'UPDATE tasks SET '
                + ','.join(assignments)
                + ' WHERE id=%s',
                tuple(values),
            )
        except Exception:
            db.exec(
                'UPDATE tasks SET file_count=%s,total_bytes=%s '
                'WHERE id=%s',
                (source_count, total_bytes, task_id),
            )


    def _finish_public_file_rows(task, files=None):
        task = task if isinstance(task, dict) else {}
        out_dir = Path(str(task.get('out_dir') or ''))
        rows = _iapt_v157_public_rows(task, out_dir)
        if out_dir.is_dir():
            _write_file_index(out_dir, rows)

        options = _iapt_v157_options(task)
        if _iapt_v157_is_source_restore(
            task,
            options,
            out_dir,
        ):
            _iapt_v157_sync_task_fields(task, rows)
        else:
            _sync_public_file_counts(task, rows)
        return rows


    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            task = dict(task_or_id)
        else:
            task = db.one(
                'SELECT * FROM tasks WHERE id=%s',
                (task_or_id,),
            )
        if not task or not task.get('out_dir'):
            return []
        return _finish_public_file_rows(task)


    def scan_files(task_id, out_dir):
        task = db.one(
            'SELECT * FROM tasks WHERE id=%s',
            (int(task_id),),
        ) or {
            'id': int(task_id),
            'out_dir': str(out_dir),
        }
        task['out_dir'] = str(out_dir)
        rows = _finish_public_file_rows(task)
        options = _iapt_v157_options(task)
        total = sum(
            int((row or {}).get('size_bytes') or 0)
            for row in rows
        )
        if _iapt_v157_is_source_restore(
            task,
            options,
            out_dir,
        ):
            return sum(
                1 for row in rows
                if _iapt_v157_source_file(
                    (row or {}).get('rel_path')
                )
            ), total
        return len(rows), total


    IAPT_SOURCE_RESTORE_POSTDECRYPT_RES_ONLY_V157 = {
        'src': 'published normally',
        'res_identical_to_upload': 'hidden',
        'res_new_path': 'published',
        'res_changed_in_place': 'published',
        'res_map_target': 'published',
        'file_count': 'source files only',
    }
    print(
        'IAPT_SOURCE_RESTORE_POSTDECRYPT_RES_ONLY_V157 installed',
        flush=True,
    )
except Exception as _iapt_v157_error:
    print(
        'IAPT_SOURCE_RESTORE_POSTDECRYPT_RES_ONLY_V157_FAILED '
        + repr(_iapt_v157_error),
        flush=True,
    )
# IAPT_SOURCE_RESTORE_POSTDECRYPT_RES_ONLY_V157_END

# IAPT_SOURCE_RESTORE_FILENAME_DIFF_V158_BEGIN
try:
    import json as _iapt_v158_json
    import os as _iapt_v158_os
    import time as _iapt_v158_time
    import unicodedata as _iapt_v158_unicodedata
    import zipfile as _iapt_v158_zipfile
    from pathlib import Path as _IAPT_V158_Path

    def _iapt_v158_normalize_rel(value):
        rel = str(value or "").replace("\\", "/")
        while rel.startswith("./"):
            rel = rel[2:]
        return rel.lstrip("/")


    def _iapt_v158_filename(value):
        rel = _iapt_v158_normalize_rel(value).rstrip("/")
        if not rel:
            return ""
        return _iapt_v158_unicodedata.normalize(
            "NFC",
            rel.rsplit("/", 1)[-1],
        )


    def _iapt_v158_original_resource_filenames(task):
        report = {
            "status": "missing-upload-archive",
            "archive": "",
            "selected_prefix": "",
            "archive_resource_files": 0,
            "unique_filenames": 0,
            "duplicate_filename_count": 0,
            "comparison": "basename-exact-case-sensitive-unicode-nfc",
        }

        finder = globals().get("_iapt_v154_upload_archive")
        selector = globals().get("_iapt_v154_select_resource_entries")
        if not callable(finder) or not callable(selector):
            report["status"] = "missing-v154-resource-reader"
            return set(), report

        try:
            archive_path = finder(task)
        except Exception as error:
            report["status"] = "upload-lookup-error"
            report["error"] = type(error).__name__ + ": " + str(error)
            return set(), report

        if archive_path is None:
            return set(), report

        report["archive"] = str(archive_path)
        try:
            with _iapt_v158_zipfile.ZipFile(archive_path, "r") as archive:
                prefix, rows, selection = selector(archive)
                report.update(selection or {})
                report["selected_prefix"] = "/".join(prefix)

                names = []
                for info, parts, res_index in rows:
                    suffix = tuple(parts[res_index + 1:])
                    if not suffix:
                        continue
                    filename = _iapt_v158_filename(suffix[-1])
                    if filename:
                        names.append(filename)

                unique = set(names)
                report["archive_resource_files"] = len(names)
                report["unique_filenames"] = len(unique)
                report["duplicate_filename_count"] = len(names) - len(unique)
                report["status"] = "ok"
                return unique, report

        except _iapt_v158_zipfile.BadZipFile as error:
            report["status"] = "upload-is-not-zip"
            report["error"] = str(error)
        except Exception as error:
            report["status"] = "filename-manifest-error"
            report["error"] = type(error).__name__ + ": " + str(error)

        return set(), report


    def _iapt_v157_filter_source_restore_rows(task, out_dir, rows):
        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V158_Path(
            str(out_dir or task.get("out_dir") or "")
        )
        options = _iapt_v157_options(task)
        include_res = _iapt_v157_resources_enabled(
            task,
            options,
            out_dir,
        )

        original_names, archive_report = (
            _iapt_v158_original_resource_filenames(task)
        )
        comparable = archive_report.get("status") == "ok"

        public = []
        public_res = []
        hidden_res = []
        src_files = 0
        disk_res_files = 0
        public_res_files = 0
        hidden_existing = 0
        unavailable = 0

        for raw in rows or []:
            if not isinstance(raw, dict):
                continue

            rel = _iapt_v158_normalize_rel(raw.get("rel_path"))
            lower = rel.lower()

            if lower.startswith("src/"):
                item = dict(raw)
                item["rel_path"] = rel
                public.append(item)
                src_files += 1
                continue

            if not lower.startswith("res/"):
                continue

            disk_res_files += 1
            if not include_res:
                continue

            filename = _iapt_v158_filename(rel)

            if not comparable:
                unavailable += 1
                hidden_res.append({
                    "path": rel,
                    "filename": filename,
                    "reason": "comparison-unavailable",
                })
                continue

            if filename in original_names:
                hidden_existing += 1
                hidden_res.append({
                    "path": rel,
                    "filename": filename,
                    "reason": "filename-existed-in-upload",
                })
                continue

            item = dict(raw)
            item["rel_path"] = rel
            public.append(item)
            public_res_files += 1
            public_res.append({
                "path": rel,
                "filename": filename,
                "reason": "filename-not-in-upload",
            })

        public.sort(key=lambda item: str(item.get("rel_path") or ""))

        report = {
            "version": 158,
            "task_id": task.get("id"),
            "task_no": task.get("task_no"),
            "out_dir": str(out_dir),
            "restore_resource_names": bool(include_res),
            "archive_filename_manifest": archive_report,
            "src_files": src_files,
            "disk_res_files": disk_res_files,
            "public_res_files": public_res_files,
            "hidden_existing_filename_files": hidden_existing,
            "comparison_unavailable_files": unavailable,
            "public_res": public_res,
            "hidden_res_sample": hidden_res[:200],
            "policy": (
                "exact case-sensitive Unicode-NFC basename only; "
                "upload has filename => hide; "
                "upload lacks filename => publish"
            ),
            "path_comparison": False,
            "content_comparison": False,
            "crc_comparison": False,
            "deobfuscation_map_override": False,
            "updated_at": int(_iapt_v158_time.time()),
        }

        try:
            report_path = out_dir / ".tmp/source_restore_res_v158.json"
            report_path.parent.mkdir(parents=True, exist_ok=True)
            temporary = report_path.with_suffix(".json.tmp")
            temporary.write_text(
                _iapt_v158_json.dumps(
                    report,
                    ensure_ascii=False,
                    indent=2,
                ) + "\n",
                encoding="utf-8",
            )
            _iapt_v158_os.replace(temporary, report_path)
        except Exception:
            pass

        return public


    IAPT_SOURCE_RESTORE_FILENAME_DIFF_V158 = {
        "comparison": "basename only",
        "case_sensitive": True,
        "unicode_normalization": "NFC",
        "path_comparison": False,
        "content_comparison": False,
        "crc_comparison": False,
        "deobfuscation_map_override": False,
        "upload_has_filename": "hide",
        "upload_lacks_filename": "publish",
        "file_count": "source files only",
    }
    print(
        "IAPT_SOURCE_RESTORE_FILENAME_DIFF_V158 installed",
        flush=True,
    )
except Exception as _iapt_v158_error:
    print(
        "IAPT_SOURCE_RESTORE_FILENAME_DIFF_V158_FAILED "
        + repr(_iapt_v158_error),
        flush=True,
    )
# IAPT_SOURCE_RESTORE_FILENAME_DIFF_V158_END

# IAPT_ANTI_RESOURCE_FILENAME_DIFF_V159_BEGIN
# Anti-encrypted-sample resource contract:
#   skip_anti_resources / no_decrypt_resource_files true -> src/** only
#   both false -> src/** plus new-name assets/res/** files
# The uploaded APK filename set is built from both assets/res/** and res/**.
# Comparison uses exact case-sensitive basenames after Unicode NFC normalization.
try:
    import json as _iapt_v159_json
    import os as _iapt_v159_os
    import time as _iapt_v159_time
    import unicodedata as _iapt_v159_unicodedata
    import zipfile as _iapt_v159_zipfile
    from pathlib import Path as _IAPT_V159_Path

    _IAPT_V159_PREVIOUS_FINISH = globals().get(
        "_finish_public_file_rows"
    )

    def _iapt_v159_truthy(value):
        if value is True or value == 1:
            return True
        if value is False or value == 0 or value is None:
            return False
        return str(value).strip().lower() in (
            "1", "true", "yes", "on", "y",
        )


    def _iapt_v159_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get("options_json")
        if isinstance(raw, dict):
            return dict(raw)
        try:
            value = _iapt_v159_json.loads(raw or "{}")
            return value if isinstance(value, dict) else {}
        except Exception:
            return {}


    def _iapt_v159_anti_requested(options):
        options = options if isinstance(options, dict) else {}
        existing = globals().get("_iapt_v116_explicit_anti")
        if callable(existing):
            try:
                return bool(existing(options))
            except Exception:
                pass
        return any(
            _iapt_v159_truthy(options.get(key))
            for key in (
                "anti_encrypted_sample",
                "anti_qiushui",
                "hidden_resource_restore",
            )
        )


    def _iapt_v159_upload_archive(task):
        task = task if isinstance(task, dict) else {}

        existing = globals().get("_iapt_v154_upload_archive")
        if callable(existing):
            try:
                value = existing(task)
                if value is not None:
                    path = _IAPT_V159_Path(value)
                    if path.is_file():
                        return path
            except Exception:
                pass

        candidates = []
        for key in (
            "upload_path",
            "apk_path",
            "source_path",
        ):
            value = str(task.get(key) or "").strip()
            if value:
                candidates.append(_IAPT_V159_Path(value))

        task_no = str(task.get("task_no") or "").strip()
        if task_no:
            try:
                candidates.append(
                    _IAPT_V159_Path(APP_STORAGE)
                    / "uploads"
                    / (task_no + ".apk")
                )
            except Exception:
                pass

        seen = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve()
            except Exception:
                resolved = candidate

            token = str(resolved)
            if token in seen:
                continue
            seen.add(token)

            try:
                if (
                    resolved.is_file()
                    and resolved.stat().st_size > 0
                ):
                    return resolved
            except Exception:
                continue

        return None


    def _iapt_v159_normalize_rel(value):
        relative = str(value or "").replace("\\", "/")
        while relative.startswith("./"):
            relative = relative[2:]
        return relative.lstrip("/")


    def _iapt_v159_basename(value):
        relative = _iapt_v159_normalize_rel(
            value
        ).rstrip("/")
        if not relative:
            return ""
        return _iapt_v159_unicodedata.normalize(
            "NFC",
            relative.rsplit("/", 1)[-1],
        )


    def _iapt_v159_original_apk_resource_names(task):
        report = {
            "status": "missing-upload-apk",
            "archive": "",
            "assets_res_files": 0,
            "standard_res_files": 0,
            "resource_files": 0,
            "unique_filenames": 0,
            "duplicate_filename_count": 0,
            "comparison": (
                "exact case-sensitive Unicode-NFC basename"
            ),
        }

        archive_path = _iapt_v159_upload_archive(task)
        if archive_path is None:
            return set(), report

        report["archive"] = str(archive_path)
        names = []

        try:
            with _iapt_v159_zipfile.ZipFile(
                archive_path,
                "r",
            ) as archive:
                for info in archive.infolist():
                    if info.is_dir():
                        continue

                    relative = _iapt_v159_normalize_rel(
                        info.filename
                    )
                    parts = tuple(
                        part
                        for part in relative.split("/")
                        if part
                    )
                    lower = tuple(
                        part.lower()
                        for part in parts
                    )

                    is_assets_res = (
                        len(parts) >= 3
                        and lower[0] == "assets"
                        and lower[1] == "res"
                    )
                    is_standard_res = (
                        len(parts) >= 2
                        and lower[0] == "res"
                    )

                    if not (
                        is_assets_res
                        or is_standard_res
                    ):
                        continue

                    filename = _iapt_v159_basename(
                        parts[-1]
                    )
                    if not filename:
                        continue

                    names.append(filename)
                    if is_assets_res:
                        report["assets_res_files"] += 1
                    else:
                        report["standard_res_files"] += 1

            unique = set(names)
            report["resource_files"] = len(names)
            report["unique_filenames"] = len(unique)
            report["duplicate_filename_count"] = (
                len(names) - len(unique)
            )
            report["status"] = "ok"
            return unique, report

        except _iapt_v159_zipfile.BadZipFile as error:
            report["status"] = "upload-is-not-apk-zip"
            report["error"] = str(error)
        except Exception as error:
            report["status"] = "resource-name-read-error"
            report["error"] = (
                type(error).__name__
                + ": "
                + str(error)
            )

        return set(), report


    def _iapt_v159_skip_resources(
        task,
        options,
        archive_path=None,
    ):
        options = (
            options
            if isinstance(options, dict)
            else {}
        )
        if (
            _iapt_v159_truthy(
                options.get(
                    "no_decrypt_resource_files"
                )
            )
            or _iapt_v159_truthy(
                options.get("skip_anti_resources")
            )
        ):
            return True

        marker_check = globals().get(
            "_iapt_v116_apk_marker"
        )
        if callable(marker_check):
            try:
                archive = (
                    archive_path
                    or _iapt_v159_upload_archive(task)
                )
                if (
                    archive is not None
                    and marker_check(
                        archive,
                        (
                            "META-INF/iapt/"
                            "no_decrypt_resource_files"
                        ),
                    )
                ):
                    return True
            except Exception:
                pass

        return False


    def _iapt_v159_anti_public_rows(
        task,
        out_dir,
        options,
    ):
        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V159_Path(
            str(out_dir or task.get("out_dir") or "")
        )

        rows = _sanitize_public_file_rows(
            out_dir,
            _scan_out_files(out_dir),
        )
        archive_path = _iapt_v159_upload_archive(task)
        skip_resources = _iapt_v159_skip_resources(
            task,
            options,
            archive_path,
        )

        original_names, archive_report = (
            _iapt_v159_original_apk_resource_names(
                task
            )
        )
        comparable = (
            archive_report.get("status") == "ok"
        )

        public = []
        public_resources = []
        hidden_resources = []

        counters = {
            "src_files": 0,
            "disk_assets_res_files": 0,
            "public_assets_res_files": 0,
            "hidden_existing_filename_files": 0,
            "comparison_unavailable_files": 0,
        }

        for raw in rows:
            if not isinstance(raw, dict):
                continue

            relative = _iapt_v159_normalize_rel(
                raw.get("rel_path")
            )
            lower = relative.lower()

            if lower.startswith("src/"):
                item = dict(raw)
                item["rel_path"] = relative
                public.append(item)
                counters["src_files"] += 1
                continue

            if not lower.startswith("assets/res/"):
                continue

            counters["disk_assets_res_files"] += 1

            if skip_resources:
                hidden_resources.append({
                    "path": relative,
                    "filename": (
                        _iapt_v159_basename(relative)
                    ),
                    "reason": "resource-restore-disabled",
                })
                continue

            filename = _iapt_v159_basename(relative)

            if not comparable:
                counters[
                    "comparison_unavailable_files"
                ] += 1
                hidden_resources.append({
                    "path": relative,
                    "filename": filename,
                    "reason": (
                        "upload-apk-comparison-unavailable"
                    ),
                })
                continue

            if filename in original_names:
                counters[
                    "hidden_existing_filename_files"
                ] += 1
                hidden_resources.append({
                    "path": relative,
                    "filename": filename,
                    "reason": (
                        "filename-existed-in-upload-apk"
                    ),
                })
                continue

            item = dict(raw)
            item["rel_path"] = relative
            public.append(item)
            counters[
                "public_assets_res_files"
            ] += 1
            public_resources.append({
                "path": relative,
                "filename": filename,
                "reason": (
                    "filename-not-in-upload-apk"
                ),
            })

        public.sort(
            key=lambda item: str(
                item.get("rel_path") or ""
            )
        )

        report = {
            "version": 159,
            "task_id": task.get("id"),
            "task_no": task.get("task_no"),
            "out_dir": str(out_dir),
            "anti_requested": True,
            "skip_resources": bool(skip_resources),
            "archive_resource_manifest": (
                archive_report
            ),
            **counters,
            "public_assets_res": public_resources,
            "hidden_assets_res_sample": (
                hidden_resources[:200]
            ),
            "policy": (
                "anti sample publishes src/** plus "
                "assets/res/** files whose exact "
                "basename did not exist under the "
                "uploaded APK assets/res/** or res/**"
            ),
            "path_comparison": False,
            "content_comparison": False,
            "crc_comparison": False,
            "updated_at": int(
                _iapt_v159_time.time()
            ),
        }

        try:
            report_path = (
                out_dir
                / ".tmp/"
                "anti_resource_filename_diff_v159.json"
            )
            report_path.parent.mkdir(
                parents=True,
                exist_ok=True,
            )
            temporary = report_path.with_suffix(
                ".json.tmp"
            )
            temporary.write_text(
                _iapt_v159_json.dumps(
                    report,
                    ensure_ascii=False,
                    indent=2,
                )
                + "\n",
                encoding="utf-8",
            )
            _iapt_v159_os.replace(
                temporary,
                report_path,
            )
        except Exception:
            pass

        return public


    def _finish_public_file_rows(task, files=None):
        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V159_Path(
            str(task.get("out_dir") or "")
        )
        options = _iapt_v159_options(task)

        if (
            out_dir.is_dir()
            and _iapt_v159_anti_requested(options)
        ):
            rows = _iapt_v159_anti_public_rows(
                task,
                out_dir,
                options,
            )
            _write_file_index(out_dir, rows)
            _sync_public_file_counts(task, rows)
            return rows

        if callable(_IAPT_V159_PREVIOUS_FINISH):
            return _IAPT_V159_PREVIOUS_FINISH(
                task,
                files,
            )
        return []


    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            task = dict(task_or_id)
        else:
            task = db.one(
                "SELECT * FROM tasks WHERE id=%s",
                (task_or_id,),
            )
        if not task or not task.get("out_dir"):
            return []
        return _finish_public_file_rows(task)


    IAPT_ANTI_RESOURCE_FILENAME_DIFF_V159 = {
        "anti_resource_root": "assets/res/**",
        "skip_true": "src/** only",
        "skip_false": (
            "src/** plus new-filename assets/res/**"
        ),
        "uploaded_apk_name_roots": [
            "assets/res/**",
            "res/**",
        ],
        "comparison": (
            "exact case-sensitive Unicode-NFC basename"
        ),
        "upload_has_filename": "hide",
        "upload_lacks_filename": "publish",
    }
    print(
        "IAPT_ANTI_RESOURCE_FILENAME_DIFF_V159 "
        "installed",
        flush=True,
    )
except Exception as _iapt_v159_error:
    print(
        "IAPT_ANTI_RESOURCE_FILENAME_DIFF_V159_FAILED "
        + repr(_iapt_v159_error),
        flush=True,
    )
# IAPT_ANTI_RESOURCE_FILENAME_DIFF_V159_END

# IAPT_WHITELIST_PACKAGE_SIGNATURE_RUNNER_V168_BEGIN
# V168 exact policy:
# - feature 7 is the only bypass condition;
# - admin status alone does not bypass;
# - users without feature 7 extract the current APK package;
# - only active V163 rows for that exact package are loaded;
# - deterministic Base64 signatures are passed to the local decrypt process;
# - only the single verified main member is inspected before any other member.
try:
    import datetime as _v168r_dt
    import json as _v168r_json
    import os as _v168r_os
    import re as _v168r_re
    from pathlib import Path as _V168RPath
    from app.whitelist_signature_v163 import (
        SCHEME_VERSION as _V168R_SCHEME,
        compute_final_sha256 as _v168r_compute_final_sha256,
        expire_to_milliseconds as _v168r_expire_to_milliseconds,
        extract_package_name as _v168r_extract_package_name,
        signature_base64 as _v168r_signature_base64,
    )
except Exception as _v168r_import_error:
    print(
        '[IAPT_WL_V168_IMPORT_ERROR]',
        repr(_v168r_import_error),
        flush=True,
    )
    raise


def _v168r_as_dict(value):
    return value if isinstance(value, dict) else {}


def _v168r_parse_features(value):
    if value is None:
        return set()

    if isinstance(value, (list, tuple, set)):
        source = value
    else:
        text = str(value).strip()
        try:
            parsed = _v168r_json.loads(text)
            source = (
                parsed
                if isinstance(
                    parsed,
                    list,
                )
                else [parsed]
            )
        except Exception:
            source = _v168r_re.split(
                r'[^0-9]+',
                text,
            )

    result = set()
    for item in source:
        try:
            text = str(item).strip()
            if text:
                result.add(int(text))
        except Exception:
            pass
    return result


def _v168r_user_has_feature7(user_id):
    """
    Only an active subscription that explicitly contains integer feature 7
    may bypass. Admin/permission flags are intentionally ignored.
    """
    try:
        user_id = int(user_id or 0)
    except Exception:
        user_id = 0

    if user_id <= 0:
        return False

    rows = []

    try:
        rows.extend(
            list(
                db.all(
                    'SELECT s.sub_id,s.features_json '
                    'FROM user_subscriptions us '
                    'JOIN subscriptions s ON us.sub_id=s.sub_id '
                    'WHERE us.user_id=%s '
                    'AND us.sub_id<>0 '
                    'AND (us.expire_at IS NULL '
                    'OR us.expire_at>NOW())',
                    (user_id,),
                )
                or []
            )
        )
    except Exception as exc:
        print(
            '[IAPT_WL_V168_FEATURE7_EXTRA_WARN]',
            repr(exc),
            flush=True,
        )

    try:
        rows.extend(
            list(
                db.all(
                    'SELECT s.sub_id,s.features_json '
                    'FROM users u '
                    'JOIN subscriptions s '
                    'ON u.subscription_id=s.sub_id '
                    'WHERE u.id=%s '
                    'AND u.subscription_id<>0 '
                    'AND (u.subscription_expire IS NULL '
                    'OR u.subscription_expire>NOW())',
                    (user_id,),
                )
                or []
            )
        )
    except Exception as exc:
        print(
            '[IAPT_WL_V168_FEATURE7_PRIMARY_WARN]',
            repr(exc),
            flush=True,
        )

    features = set()
    sub_ids = set()

    for row in rows:
        if not isinstance(row, dict):
            continue

        try:
            sub_id = int(
                row.get('sub_id')
                or 0
            )
        except Exception:
            sub_id = 0

        if sub_id <= 0:
            continue

        sub_ids.add(sub_id)
        features |= _v168r_parse_features(
            row.get('features_json')
        )

    has_feature7 = 7 in features or 999 in features


    return has_feature7
def _v168r_parse_expire(value):
    if value is None or value == '':
        return None

    if isinstance(
        value,
        _v168r_dt.datetime,
    ):
        return value.replace(
            tzinfo=None
        )

    if isinstance(
        value,
        _v168r_dt.date,
    ):
        return _v168r_dt.datetime(
            value.year,
            value.month,
            value.day,
        )

    text = str(value).strip()
    if not text or text.lower() in (
        'none',
        'null',
        'never',
        '永久',
    ):
        return None

    text = (
        text.replace('T', ' ')
        .replace('Z', '')
        .replace('/', '-')
        .strip()
    )
    text = _v168r_re.sub(
        r'\.\d+$',
        '',
        text,
    )
    text = _v168r_re.sub(
        r'\s*[+-]\d\d:?\d\d$',
        '',
        text,
    )

    for fmt in (
        '%Y-%m-%d %H:%M:%S',
        '%Y-%m-%d %H:%M',
        '%Y-%m-%d',
    ):
        try:
            return _v168r_dt.datetime.strptime(
                text[:19],
                fmt,
            )
        except Exception:
            pass

    try:
        return (
            _v168r_dt.datetime
            .fromisoformat(text)
            .replace(tzinfo=None)
        )
    except Exception:
        # An invalid non-empty expiration is not treated as permanent.
        return _v168r_dt.datetime.min


def _v168r_is_active(value):
    parsed = _v168r_parse_expire(
        value
    )
    return (
        parsed is None
        or parsed > _v168r_dt.datetime.now()
    )


def _v168r_normalize_package(value):
    package_name = str(
        value
        or ''
    ).strip()

    if _v168r_re.fullmatch(
        r'[A-Za-z][A-Za-z0-9_]*'
        r'(?:\.[A-Za-z0-9_]+)+',
        package_name,
    ):
        return package_name

    return ''


def _v168r_package_name(apk_path, task):
    task = _v168r_as_dict(task)

    try:
        package_name = _v168r_normalize_package(
            _v168r_extract_package_name(
                _V168RPath(apk_path)
            )
        )
    except Exception as exc:
        package_name = ''
        print(
            '[IAPT_WL_V168_PACKAGE_EXTRACT_WARN]',
            repr(exc),
            flush=True,
        )

    if package_name:
        return package_name, 'apk'

    for key in (
        'package_name',
        'package',
        'pkg',
        'app_package',
        'packageName',
    ):
        package_name = _v168r_normalize_package(
            task.get(key)
        )
        if package_name:
            return package_name, 'task.' + key

    return '', ''


def _v168r_rows_for_package(package_name):
    """
    Query only this APK package and only records that are currently active.
    No full-table signature scan is performed.
    """
    rows = db.all(
        'SELECT id,package_name,final_sha256,'
        'expire_at,token_version '
        'FROM decrypt_whitelist '
        'WHERE package_name=%s '
        'AND token_version=%s '
        'AND (expire_at IS NULL OR expire_at>NOW()) '
        'ORDER BY id DESC '
        'LIMIT 100',
        (
            package_name,
            _V168R_SCHEME,
        ),
    )
    if rows is None:
        rows = []

    print(
        '[IAPT_WL_V168_DB] '
        'package=%s active_rows=%s'
        % (
            package_name,
            len(rows),
        ),
        flush=True,
    )

    return rows
def _v168r_probe_config(
    apk_path,
    out_dir,
    task,
):
    task = _v168r_as_dict(task)

    try:
        user_id = int(
            task.get('user_id')
            or 0
        )
    except Exception:
        user_id = 0

    if _v168r_user_has_feature7(
        user_id
    ):
        print(
            '[IAPT_WL_V168_FEATURE7_BYPASS] '
            'user_id=%s'
            % user_id,
            flush=True,
        )
        return None

    package_name, package_source = (
        _v168r_package_name(
            apk_path,
            task,
        )
    )

    if not package_name:
        print(
            '[IAPT_WL_V168_PACKAGE_EMPTY] '
            'user_id=%s'
            % user_id,
            flush=True,
        )
        return None

    print(
        '[IAPT_WL_V168_ENFORCE] '
        'user_id=%s feature7=0 '
        'package=%s source=%s'
        % (
            user_id,
            package_name,
            package_source,
        ),
        flush=True,
    )

    records = []
    expired = 0
    invalid = 0

    for raw in _v168r_rows_for_package(
        package_name
    ):
        row = _v168r_as_dict(raw)

        if not _v168r_is_active(
            row.get('expire_at')
        ):
            expired += 1
            continue

        # V176: the database source of truth is package_name + expire_at.
        # Recompute the complete whitelist digest for every task instead of
        # trusting a previously stored hash. This exactly mirrors generation
        # in the admin API and makes a changed expiration invalidate the old
        # embedded public-key text immediately.
        try:
            expire_ms = _v168r_expire_to_milliseconds(
                row.get('expire_at')
            )
            final_sha256 = _v168r_compute_final_sha256(
                package_name,
                expire_ms,
            )
        except Exception as exc:
            invalid += 1
            print(
                '[IAPT_WL_V176_RECOMPUTE_WARN] '
                'row_id=%s error=%r'
                % (row.get('id'), exc),
                flush=True,
            )
            continue

        stored_final_sha256 = str(
            row.get('final_sha256')
            or ''
        ).strip().lower()

        if (
            stored_final_sha256
            and stored_final_sha256 != final_sha256
        ):
            print(
                '[IAPT_WL_V176_STORED_DIGEST_STALE] '
                'row_id=%s package=%s'
                % (row.get('id'), package_name),
                flush=True,
            )

        # RSA PKCS#1 v1.5 signing is deterministic here. The service performs
        # the private-key operation again and compares the resulting Base64
        # value with the text found in the verified main member; it never tries
        # to decrypt the embedded value with the private key.
        signature = _v168r_signature_base64(
            final_sha256
        )

        records.append({
            'id': row.get('id'),
            'package_name': package_name,
            'final_sha256': final_sha256,
            'stored_final_sha256': stored_final_sha256,
            'expire_ms': expire_ms,
            'expire_at': (
                ''
                if row.get('expire_at')
                in (None, '')
                else str(
                    row.get('expire_at')
                )
            ),
            'signature_base64': signature,
        })

    print(
        '[IAPT_WL_V168_RECORDS] '
        'active=%s expired=%s invalid=%s'
        % (
            len(records),
            expired,
            invalid,
        ),
        flush=True,
    )

    if not records:
        return None

    root = _V168RPath(out_dir)
    private = root / '.tmp'
    private.mkdir(
        parents=True,
        exist_ok=True,
    )

    probe_path = (
        private
        / 'whitelist_package_signatures_v168.json'
    )
    result_path = (
        private
        / 'whitelist_package_signatures_result_v168.json'
    )

    payload = {
        'version': 167,
        'user_id': user_id,
        'feature7': False,
        'package_name': package_name,
        'package_source': package_source,
        'records': records,
        'result_path': str(result_path),
    }

    temporary = probe_path.with_name(
        probe_path.name + '.tmp'
    )
    temporary.write_text(
        _v168r_json.dumps(
            payload,
            ensure_ascii=False,
            indent=2,
            default=str,
        ) + '\n',
        encoding='utf-8',
    )
    _v168r_os.replace(
        temporary,
        probe_path,
    )

    try:
        _v168r_os.chmod(
            probe_path,
            0o600,
        )
    except Exception:
        pass

    try:
        result_path.unlink(
            missing_ok=True
        )
    except Exception:
        pass

    return (
        payload,
        probe_path,
        result_path,
    )


# Disable the legacy package/hash-only worker guards.
# V168 blocks only after finding an active deterministic signature in the
# decrypted main member.
def _v61r_check_task(task_id):
    return None


def _v60r_check_task(task_id):
    return None


try:
    _IAPT_WL_V168_BASE_RUN_DECRYPT_PROCESS = (
        run_decrypt_process
    )

    def run_decrypt_process(
        cmd,
        apk_path,
        out_dir,
        options,
        task,
        env=None,
    ):
        prepared = _v168r_probe_config(
            apk_path,
            out_dir,
            task,
        )

        if not prepared:
            return (
                _IAPT_WL_V168_BASE_RUN_DECRYPT_PROCESS(
                    cmd,
                    apk_path,
                    out_dir,
                    options,
                    task,
                    env=env,
                )
            )

        (
            payload,
            probe_path,
            result_path,
        ) = prepared

        child_env = dict(
            env
            or _v168r_os.environ.copy()
        )
        child_env[
            'IAPT_WHITELIST_PACKAGE_SIGNATURES_V168'
        ] = str(probe_path)
        child_env[
            'IAPT_WHITELIST_PACKAGE_SIGNATURES_RESULT_V168'
        ] = str(result_path)

        # The probe is a local private file. Preserve the already-generated
        # command and its enum range, but force the process transport local.
        route_options = dict(
            options
            or {}
        )
        if route_options.get('dex_enum'):
            route_options['dex_enum'] = False
            print(
                '[IAPT_WL_V168_LOCAL_ROUTE] '
                'package has active signatures; '
                'command arguments remain unchanged',
                flush=True,
            )

        result = (
            _IAPT_WL_V168_BASE_RUN_DECRYPT_PROCESS(
                cmd,
                apk_path,
                out_dir,
                route_options,
                task,
                env=child_env,
            )
        )

        if int(
            getattr(
                result,
                'returncode',
                0,
            )
            or 0
        ) == 93:
            message = (
                '这是白名单样本，'
                '主文件包含当前包名的有效签名，'
                '保护期内禁止解密'
            )
            try:
                if result_path.is_file():
                    details = _v168r_json.loads(
                        result_path.read_text(
                            'utf-8'
                        )
                    )
                    if (
                        isinstance(details, dict)
                        and details.get('message')
                    ):
                        message = str(
                            details.get('message')
                        )
            except Exception as exc:
                print(
                    '[IAPT_WL_V168_RESULT_WARN]',
                    repr(exc),
                    flush=True,
                )

            result.stdout = (
                (result.stdout or '')
                + '\n'
                + '[IAPT_WHITELIST_PACKAGE_SIGNATURE_BLOCK] '
                + message
                + '\n'
            )

        return result

    print(
        '[OK] '
        'IAPT_WHITELIST_PACKAGE_SIGNATURE_RUNNER_V168 '
        'installed',
        flush=True,
    )
except Exception as _v168r_init_error:
    print(
        '[IAPT_WL_V168_INIT_ERROR]',
        repr(_v168r_init_error),
        flush=True,
    )
    raise
# IAPT_WHITELIST_PACKAGE_SIGNATURE_RUNNER_V168_END

# IAPT_WHITELIST_RESULT_REDACTION_V169_BEGIN
try:
    import json as _v169_json
    import os as _v169_os
    import shutil as _v169_shutil
    import threading as _v169_threading
    from pathlib import Path as _V169Path
except Exception as _v169_import_error:
    print('[IAPT_WL_V169_IMPORT_ERROR]', repr(_v169_import_error), flush=True)
    raise

_V169_MESSAGE = '白名单保护'
_V169_BLOCKED_TASK_IDS = set()
_V169_LOCK = _v169_threading.RLock()
_V169_MARKERS = (
    'IAPT_WHITELIST_PACKAGE_SIGNATURE_BLOCK',
    'IAPT_WL_V168_PACKAGE_SIGNATURE_BLOCK',
    'IAPT_WHITELIST_ACTIVE_SIGNATURE_BLOCK',
    'IAPT_WL_V167_ACTIVE_SIGNATURE_BLOCK',
    'IAPT_WL_V166_MAIN_CONTAINS_BLOCK',
)


def _v169_dict(value):
    return value if isinstance(value, dict) else {}


def _v169_task_id(task):
    try:
        return int(_v169_dict(task).get('id') or 0)
    except Exception:
        return 0


def _v169_blocked_result(result):
    try:
        if int(getattr(result, 'returncode', 0) or 0) == 93:
            return True
    except Exception:
        pass

    text = (
        str(getattr(result, 'stdout', '') or '')
        + '\n'
        + str(getattr(result, 'stderr', '') or '')
    )
    return any(marker in text for marker in _V169_MARKERS)


def _v169_mark(task_id):
    try:
        task_id = int(task_id or 0)
    except Exception:
        return
    if task_id > 0:
        with _V169_LOCK:
            _V169_BLOCKED_TASK_IDS.add(task_id)


def _v169_marked(task_id):
    try:
        task_id = int(task_id or 0)
    except Exception:
        return False
    with _V169_LOCK:
        return task_id in _V169_BLOCKED_TASK_IDS


def _v169_unmark(task_id):
    try:
        task_id = int(task_id or 0)
    except Exception:
        return
    with _V169_LOCK:
        _V169_BLOCKED_TASK_IDS.discard(task_id)


def _v169_columns():
    result = {}
    for raw in (db.all('SHOW COLUMNS FROM tasks') or []):
        row = _v169_dict(raw)
        name = str(row.get('Field') or row.get('field') or '').strip()
        if name:
            result[name] = row
    return result


def _v169_empty(row):
    row = _v169_dict(row)
    typ = str(row.get('Type') or row.get('type') or '').lower()
    nullable = str(row.get('Null') or row.get('null') or '').upper() == 'YES'
    if nullable:
        return None
    if any(token in typ for token in ('int', 'decimal', 'float', 'double', 'bit', 'bool')):
        return 0
    return ''


def _v169_clean_files(task):
    task = _v169_dict(task)
    out_dir = _V169Path(str(task.get('out_dir') or ''))

    if out_dir.is_dir():
        for child in list(out_dir.iterdir()):
            if child.name == '.tmp':
                continue
            try:
                if child.is_dir() and not child.is_symlink():
                    _v169_shutil.rmtree(child)
                else:
                    child.unlink(missing_ok=True)
            except Exception as exc:
                print('[IAPT_WL_V169_CLEAN_WARN]', str(child), repr(exc), flush=True)

        private = out_dir / '.tmp'
        private.mkdir(parents=True, exist_ok=True)

        for path in list(private.rglob('*')):
            if not path.is_file():
                continue
            low = path.name.lower()
            if any(token in low for token in (
                'decrypt_report',
                'ancient_report',
                'project_meta',
                'decrypt_summary',
                'selected_key',
                'selected_sokey',
                'selected_dexkey',
            )):
                try:
                    path.unlink(missing_ok=True)
                except Exception:
                    pass

        marker = private / 'whitelist_protected_v169.json'
        temporary = marker.with_name(marker.name + '.tmp')
        temporary.write_text(
            _v169_json.dumps(
                {
                    'version': 169,
                    'whitelist_protected': True,
                    'error_code': 'whitelist_protected',
                    'message': _V169_MESSAGE,
                },
                ensure_ascii=False,
                indent=2,
            ) + '\n',
            encoding='utf-8',
        )
        _v169_os.replace(temporary, marker)

    log_path = str(task.get('log_path') or '').strip()
    if not log_path:
        task_no = str(task.get('task_no') or '').strip()
        if task_no:
            try:
                log_path = str(APP_STORAGE / 'tasks' / (task_no + '.log'))
            except Exception:
                log_path = ''

    if log_path:
        try:
            path = _V169Path(log_path)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                '[IAPT_WHITELIST_PROTECTED]\n白名单保护\n',
                encoding='utf-8',
            )
        except Exception as exc:
            print('[IAPT_WL_V169_LOG_WARN]', repr(exc), flush=True)


def _v169_scrub(task_id):
    try:
        task_id = int(task_id or 0)
    except Exception:
        task_id = 0
    if task_id <= 0:
        return

    task = _v169_dict(db.one('SELECT * FROM tasks WHERE id=%s', (task_id,)))
    if not task:
        return

    columns = _v169_columns()
    assignments = []
    values = []

    def put(name, value):
        if name not in columns:
            return
        assignments.append('`' + name.replace('`', '``') + '`=%s')
        values.append(value)

    for name, value in (
        ('status', 'failed'),
        ('error_text', _V169_MESSAGE),
        ('error', _V169_MESSAGE),
        ('message', _V169_MESSAGE),
        ('result_text', _V169_MESSAGE),
        ('error_code', 'whitelist_protected'),
        ('whitelist_protected', 1),
    ):
        put(name, value)

    for name in (
        'file_count',
        'total_bytes',
        'downloadable_file_count',
        'downloadable_bytes',
        'public_file_count',
        'public_output_file_count',
        'client_output_file_count',
        'result_file_count',
        'output_file_count',
        'decrypted_file_count',
    ):
        put(name, 0)

    for name in (
        'decrypt_summary',
        'decrypt_report',
        'decrypt_report_json',
        'ancient_report',
        'ancient_report_json',
        'project_meta',
        'project_meta_json',
        'project_file',
        'sokey',
        'selected_sokey',
        'hidden',
        'dexkey',
        'selected_dexkey',
        'fb',
        'decrypt_info',
        'decrypt_info_json',
        'decrypt_result',
        'decrypt_result_json',
        'result_json',
        'report_json',
        'output_json',
        'analysis_json',
        'dynamic_restore',
        'dynamic_restore_json',
    ):
        if name in columns:
            put(name, _v169_empty(columns[name]))

    if assignments:
        values.append(task_id)
        db.exec(
            'UPDATE tasks SET ' + ','.join(assignments) + ' WHERE id=%s',
            tuple(values),
        )

    _v169_clean_files(task)
    print('[IAPT_WL_V169_TASK_REDACTED] task_id=%s' % task_id, flush=True)


def _v169_minimal_process(result):
    try:
        result.stdout = '[IAPT_WHITELIST_PROTECTED]\n白名单保护\n'
    except Exception:
        pass
    try:
        result.stderr = ''
    except Exception:
        pass
    try:
        result.returncode = 93
    except Exception:
        pass
    return result


try:
    _IAPT_WL_V169_BASE_RUN_DECRYPT_PROCESS = run_decrypt_process

    def run_decrypt_process(cmd, apk_path, out_dir, options, task, env=None):
        result = _IAPT_WL_V169_BASE_RUN_DECRYPT_PROCESS(
            cmd,
            apk_path,
            out_dir,
            options,
            task,
            env=env,
        )

        if not _v169_blocked_result(result):
            return result

        task_id = _v169_task_id(task)
        _v169_mark(task_id)

        try:
            _v169_scrub(task_id)
        except Exception as exc:
            print('[IAPT_WL_V169_PRE_SCRUB_WARN]', task_id, repr(exc), flush=True)

        return _v169_minimal_process(result)

    _IAPT_WL_V169_BASE_RUN_TASK = run_task

    def run_task(task_id: int):
        blocked = False
        try:
            result = _IAPT_WL_V169_BASE_RUN_TASK(task_id)
            blocked = _v169_marked(task_id)
            if not blocked:
                return result
        except Exception:
            blocked = _v169_marked(task_id)
            if not blocked:
                raise
            result = None
        finally:
            if _v169_marked(task_id):
                try:
                    _v169_scrub(task_id)
                finally:
                    _v169_unmark(task_id)

        return {
            'ok': False,
            'task_id': int(task_id),
            'status': 'failed',
            'error': _V169_MESSAGE,
            'error_text': _V169_MESSAGE,
            'message': _V169_MESSAGE,
            'error_code': 'whitelist_protected',
            'whitelist_protected': True,
            'file_count': 0,
            'total_bytes': 0,
        }

    print('[OK] IAPT_WHITELIST_RESULT_REDACTION_V169 installed', flush=True)

except Exception as _v169_init_error:
    print('[IAPT_WL_V169_INIT_ERROR]', repr(_v169_init_error), flush=True)
    raise
# IAPT_WHITELIST_RESULT_REDACTION_V169_END

# IAPT_WHITELIST_AND_OUTPUT_LAYOUT_V170_BEGIN
# V170 final compatibility layer:
# 1. A whitelist-protected task exposes only the fixed whitelist message.  In
#    particular, options_json and stale/cache-facing key fields are scrubbed.
# 2. Some V3 engines write decrypted source members at the task root while the
#    public-output policy only accepts src/**.  Move only recognized source
#    files into src/** before the final public scan so successful decryptions
#    are not misreported as empty.
# 3. Numeric/iACT source repair keeps the project layout (src/** and res/**).
try:
    import json as _iapt_v170_json
    import os as _iapt_v170_os
    import shutil as _iapt_v170_shutil
    from pathlib import Path as _IAPT_V170_Path

    _IAPT_V170_WHITELIST_MESSAGE = '白名单保护'
    _IAPT_V170_SOURCE_SUFFIXES = {
        '.iyu', '.myu', '.ijava', '.mjava', '.java',
        '.ilua', '.mlua', '.lua', '.ijs', '.mjs', '.js', '.project',
    }
    _IAPT_V170_SOURCE_NAMES = {
        'mian.iyu', 'main.iyu',
    }

    def _iapt_v170_options(task):
        task = task if isinstance(task, dict) else {}
        raw = task.get('options_json')
        if isinstance(raw, dict):
            return dict(raw)
        try:
            obj = _iapt_v170_json.loads(raw or '{}')
            return obj if isinstance(obj, dict) else {}
        except Exception:
            return {}

    def _iapt_v170_truthy(value):
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return value != 0
        return str(value or '').strip().lower() in {
            '1', 'true', 'yes', 'on', 'enabled', 'enable',
        }

    def _iapt_v170_whitelist_task(task):
        task = task if isinstance(task, dict) else {}
        options = _iapt_v170_options(task)
        if any(_iapt_v170_truthy(task.get(name)) for name in (
            'whitelist_protected', 'is_whitelist_protected',
            'protected_by_whitelist',
        )):
            return True
        if any(_iapt_v170_truthy(options.get(name)) for name in (
            'whitelist_protected', 'is_whitelist_protected',
            'protected_by_whitelist',
        )):
            return True
        text = ' '.join(str(task.get(name) or '') for name in (
            'error_code', 'error_text', 'error', 'message', 'result_text',
            'decrypt_summary', 'status_text',
        )).lower()
        text += ' ' + ' '.join(str(options.get(name) or '') for name in (
            'error_code', 'error_text', 'error', 'message', 'result_text',
        )).lower()
        return any(marker in text for marker in (
            '白名单保护', '白名单样本', 'whitelist_protected',
            'iapt_whitelist_protected',
            'iapt_whitelist_package_signature_block',
            'iapt_wl_v168_package_signature_block',
        ))

    def _iapt_v170_task_versions(task, options):
        values = {
            str((task or {}).get('decrypt_version') or '').strip().lower(),
            str((task or {}).get('task_version') or '').strip().lower(),
            str((task or {}).get('task_kind') or '').strip().lower(),
            str((options or {}).get('decrypt_version') or '').strip().lower(),
            str((options or {}).get('task_version') or '').strip().lower(),
            str((options or {}).get('task_kind') or '').strip().lower(),
        }
        values.discard('')
        return values

    def _iapt_v170_is_anti(task, options):
        try:
            feature_id = int((task or {}).get('feature_id') or (options or {}).get('feature_id') or 0)
        except Exception:
            feature_id = 0
        return feature_id == 7 or any(
            _iapt_v170_truthy((options or {}).get(name))
            for name in (
                'anti_encrypted_sample', 'anti_sample',
                'anti_qiushui', 'qiushui_anti',
            )
        )

    def _iapt_v170_is_source_file(path):
        path = _IAPT_V170_Path(path)
        name = path.name.lower()
        return name in _IAPT_V170_SOURCE_NAMES or path.suffix.lower() in _IAPT_V170_SOURCE_SUFFIXES

    def _iapt_v170_collision_path(target):
        if not target.exists():
            return target
        stem = target.stem
        suffix = target.suffix
        for index in range(1, 10000):
            candidate = target.with_name('%s.v170_%d%s' % (stem, index, suffix))
            if not candidate.exists():
                return candidate
        raise RuntimeError('unable to allocate source output name: ' + str(target))

    def _iapt_v170_normalize_source_layout(task):
        """Normalize only known public source roots to out_dir/src and out_dir/res.

        Security rule: never publish a file merely because it has a source-code
        suffix somewhere below the task directory.  Accepted physical layouts are:

          * out_dir/src/** and out_dir/res/** (already canonical);
          * one unambiguous project wrapper containing <wrapper>/src/**, with the
            sibling <wrapper>/res/** optionally merged;
          * recognized source files directly in out_dir (legacy V3/deobfuscator
            output only).

        Other directories remain private and are never remapped into src/**.
        """
        task = task if isinstance(task, dict) else {}
        if _iapt_v170_whitelist_task(task):
            return 0
        out_dir = _IAPT_V170_Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return 0
        options = _iapt_v170_options(task)
        if _iapt_v170_is_anti(task, options):
            # Anti-encrypted tasks have a dedicated src/assets-res policy.
            return 0

        versions = _iapt_v170_task_versions(task, options)
        # Utility-only jobs do not contain project source and must remain flat.
        if versions.intersection({
            'v6', '6', 'key', 'dynkey', 'dynamic_key',
            'dynamic_key_extract', 'sokey', 'server_sokey',
            'server_sokey_extract',
        }):
            return 0
        if any(_iapt_v170_truthy(options.get(name)) for name in (
            'dynamic_key_extract', 'server_sokey_extract',
        )):
            return 0

        try:
            feature_id = int(task.get('feature_id') or options.get('feature_id') or 0)
        except Exception:
            feature_id = 0
        standalone_source = (
            feature_id in {5, 8}
            or bool(versions.intersection({
                'restore', 'source_restore', 'fn_restore',
                'numeric_restore', 'numeric_source_restore',
                'dex_restore', 'static_dex_restore',
                'source_dex_restore', 'iact', 'iact_restore',
            }))
            or any(_iapt_v170_truthy(options.get(name)) for name in (
                'source_restore', 'numeric_source_restore',
                'static_dex_restore', 'iact_dynamic_decrypt',
            ))
        )

        src_dir = out_dir / 'src'
        res_dir = out_dir / 'res'
        private_root = out_dir / '.iapt_internal' / 'layout_v172'
        moved = 0
        conflicts = 0

        # V173: repair existing source-only jobs before the strict public scan.
        # This is intentionally limited to restore/iACT task types selected by
        # standalone_source.  The helper accepts only canonical src/res, one
        # explicit project wrapper, root source members, or a legacy wrapper
        # carrying mian/main (or .project + real source).  It never recursively
        # promotes arbitrary code-looking files from ordinary decrypt outputs.
        if standalone_source:
            try:
                from .source_layout import canonicalize_legacy_source_task
                legacy_report = canonicalize_legacy_source_task(out_dir)
                moved += int(legacy_report.get('moved') or 0)
                conflicts += int(legacy_report.get('conflicts') or 0)
                if legacy_report.get('ambiguous_wrappers'):
                    print(
                        '[IAPT_V173_LEGACY_LAYOUT_AMBIGUOUS] task_id=%s wrappers=%s' % (
                            task.get('id'), legacy_report.get('ambiguous_wrappers'),
                        ),
                        flush=True,
                    )
            except Exception as legacy_error:
                print(
                    '[IAPT_V173_LEGACY_LAYOUT_FAILED] task_id=%s error=%s' % (
                        task.get('id'), repr(legacy_error),
                    ),
                    flush=True,
                )

        def _same_file(left, right):
            try:
                if left.stat().st_size != right.stat().st_size:
                    return False
                with left.open('rb') as a, right.open('rb') as b:
                    while True:
                        ca = a.read(1024 * 1024)
                        cb = b.read(1024 * 1024)
                        if ca != cb:
                            return False
                        if not ca:
                            return True
            except Exception:
                return False

        def _private_collision(source, rel, label):
            nonlocal conflicts
            target = private_root / 'conflicts' / label / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                target = _iapt_v170_collision_path(target)
            _iapt_v170_shutil.move(str(source), str(target))
            conflicts += 1

        def _merge_tree(source_root, target_root, label):
            nonlocal moved
            if not source_root.is_dir() or source_root.resolve() == target_root.resolve():
                return
            members = []
            for source in source_root.rglob('*'):
                try:
                    if not source.is_file() or source.is_symlink():
                        continue
                    rel = source.relative_to(source_root)
                    if any(part in ('', '.', '..') or str(part).startswith('.') for part in rel.parts):
                        continue
                    members.append((source, rel))
                except Exception:
                    continue
            for source, rel in members:
                target = target_root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.exists():
                    if target.is_file() and _same_file(source, target):
                        source.unlink(missing_ok=True)
                        moved += 1
                    else:
                        _private_collision(source, rel, label)
                    continue
                _iapt_v170_shutil.move(str(source), str(target))
                moved += 1

        # Old clients or old task results may contain exactly one project wrapper
        # (<project>/src and optionally <project>/res).  Only that named root is
        # normalized.  Ambiguous multi-project output is deliberately left private.
        if standalone_source and not (src_dir.is_dir() and any(p.is_file() for p in src_dir.rglob('*'))):
            wrapper_parents = []
            for candidate in out_dir.rglob('src'):
                try:
                    if not candidate.is_dir() or candidate.is_symlink():
                        continue
                    rel = candidate.relative_to(out_dir)
                    if len(rel.parts) < 2 or len(rel.parts) > 4:
                        continue
                    low_parts = tuple(str(part).lower() for part in rel.parts)
                    if any(part.startswith('.') for part in rel.parts):
                        continue
                    if any(part in {'logs', 'reports', 'analysis', 'deep_code', 'assets', 'apk', '__pycache__'} for part in low_parts[:-1]):
                        continue
                    if not any(p.is_file() for p in candidate.rglob('*')):
                        continue
                    parent = candidate.parent
                    if parent not in wrapper_parents:
                        wrapper_parents.append(parent)
                except Exception:
                    continue
            if len(wrapper_parents) == 1:
                wrapper = wrapper_parents[0]
                label = wrapper.relative_to(out_dir).as_posix().replace('/', '_') or 'project'
                _merge_tree(wrapper / 'src', src_dir, label + '_src')
                _merge_tree(wrapper / 'res', res_dir, label + '_res')
            elif len(wrapper_parents) > 1:
                print(
                    '[IAPT_V172_LAYOUT_AMBIGUOUS] task_id=%s wrappers=%s' % (
                        task.get('id'),
                        [p.relative_to(out_dir).as_posix() for p in wrapper_parents[:8]],
                    ),
                    flush=True,
                )

        # Legacy V3/deobfuscator output can place generated source files directly
        # at the task root.  Only immediate children are accepted; nested files are
        # never inferred to be public source.
        root_sources = []
        try:
            for path in out_dir.iterdir():
                if path.is_file() and not path.is_symlink() and _iapt_v170_is_source_file(path):
                    root_sources.append(path)
        except Exception:
            root_sources = []

        for path in root_sources:
            target = src_dir / path.name
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.exists():
                if target.is_file() and _same_file(path, target):
                    path.unlink(missing_ok=True)
                    moved += 1
                else:
                    _private_collision(path, _IAPT_V170_Path(path.name), 'root_src')
                continue
            _iapt_v170_shutil.move(str(path), str(target))
            moved += 1

        # Remove only empty wrapper directories.  Never delete or publish the
        # remaining non-canonical tree.
        if moved:
            for directory in sorted(
                (p for p in out_dir.rglob('*') if p.is_dir()),
                key=lambda p: len(p.parts),
                reverse=True,
            ):
                try:
                    rel = directory.relative_to(out_dir)
                    if not rel.parts or rel.parts[0].lower() in {
                        'src', 'res', 'assets', 'apk', '.tmp', '.iapt_internal',
                    }:
                        continue
                    directory.rmdir()
                except Exception:
                    pass
            print(
                '[IAPT_V172_SOURCE_LAYOUT_FIXED] task_id=%s moved=%s conflicts_private=%s' % (
                    task.get('id'), moved, conflicts,
                ),
                flush=True,
            )
        return moved

    # Strengthen the V169 scrubber.  The wrapper intentionally keeps the same
    # global name because the installed V169 run_task resolves it at runtime.
    _IAPT_V170_BASE_WHITELIST_SCRUB = globals().get('_v169_scrub')

    def _v169_scrub(task_id):
        if callable(_IAPT_V170_BASE_WHITELIST_SCRUB):
            _IAPT_V170_BASE_WHITELIST_SCRUB(task_id)
        try:
            task_id = int(task_id or 0)
        except Exception:
            task_id = 0
        if task_id <= 0:
            return
        task = db.one('SELECT * FROM tasks WHERE id=%s', (task_id,)) or {}
        columns = _v169_columns() if callable(globals().get('_v169_columns')) else {}
        if not columns:
            return

        assignments = []
        values = []

        def put(name, value):
            if name not in columns:
                return
            assignments.append('`' + name.replace('`', '``') + '`=%s')
            values.append(value)

        minimal = _iapt_v170_json.dumps({
            'whitelist_protected': True,
            'error_code': 'whitelist_protected',
            'message': _IAPT_V170_WHITELIST_MESSAGE,
        }, ensure_ascii=False, separators=(',', ':'))

        for name in (
            'options_json', 'client_options_json', 'request_options_json',
            'request_json', 'params_json', 'payload_json',
        ):
            put(name, minimal)

        for name in (
            'sokey', 'old_sokey', 'selected_sokey', 'client_sokey', 'hidden',
            'dexkey', 'selected_dexkey', 'client_dexkey', 'fb', 'f_b',
            'selected_key', 'dynamic_key', 'dynamic_keys', 'post_key',
            'xor_key', 'aes_key', 'key_source', 'key_pool_json',
            'decrypt_summary', 'decrypt_report', 'decrypt_report_json',
            'ancient_report', 'ancient_report_json', 'decrypt_info',
            'decrypt_info_json', 'decrypt_result', 'decrypt_result_json',
            'result_json', 'report_json', 'output_json', 'analysis_json',
            'dynamic_restore', 'dynamic_restore_json', 'project_meta',
            'project_meta_json', 'project_file', 'stdout', 'stderr',
            'command', 'command_json', 'cmdline', 'worker_output',
        ):
            if name in columns:
                put(name, _v169_empty(columns[name]))

        for name, value in (
            ('status', 'failed'),
            ('error_code', 'whitelist_protected'),
            ('error_text', _IAPT_V170_WHITELIST_MESSAGE),
            ('error', _IAPT_V170_WHITELIST_MESSAGE),
            ('message', _IAPT_V170_WHITELIST_MESSAGE),
            ('result_text', _IAPT_V170_WHITELIST_MESSAGE),
            ('whitelist_protected', 1),
        ):
            put(name, value)
        for name in (
            'file_count', 'total_bytes', 'downloadable_file_count',
            'downloadable_bytes', 'public_file_count',
            'public_output_file_count', 'client_output_file_count',
            'result_file_count', 'output_file_count', 'decrypted_file_count',
        ):
            put(name, 0)

        if assignments:
            values.append(task_id)
            db.exec(
                'UPDATE tasks SET ' + ','.join(assignments) + ' WHERE id=%s',
                tuple(values),
            )
        try:
            _v169_clean_files(task)
            out_dir = _IAPT_V170_Path(str(task.get('out_dir') or ''))
            if out_dir.is_dir():
                private = out_dir / '.tmp'
                if private.exists():
                    for child in list(private.iterdir()):
                        try:
                            if child.is_dir() and not child.is_symlink():
                                _iapt_v170_shutil.rmtree(child)
                            else:
                                child.unlink(missing_ok=True)
                        except Exception:
                            pass
                private.mkdir(parents=True, exist_ok=True)
                marker = private / 'whitelist_protected_v170.json'
                marker.write_text(minimal + '\n', encoding='utf-8')
        except Exception:
            pass
        print('[IAPT_WL_V170_OPTIONS_REDACTED] task_id=%s' % task_id, flush=True)

    _IAPT_V170_PREVIOUS_FINISH = globals().get('_finish_public_file_rows')

    def _finish_public_file_rows(task, files=None):
        task = task if isinstance(task, dict) else {}
        out_dir = _IAPT_V170_Path(str(task.get('out_dir') or ''))
        if not out_dir.is_dir():
            return []

        if _iapt_v170_whitelist_task(task):
            try:
                _write_file_index(out_dir, [])
            except Exception:
                pass
            _sync_public_file_counts(task, [])
            return []

        _iapt_v170_normalize_source_layout(task)

        rows = []
        if callable(_IAPT_V170_PREVIOUS_FINISH):
            try:
                rows = _IAPT_V170_PREVIOUS_FINISH(task, files)
            except TypeError:
                rows = _IAPT_V170_PREVIOUS_FINISH(task)
        rows = rows if isinstance(rows, list) else []

        # Last-resort compatibility for old tasks whose stale manifest was
        # empty: rebuild from disk after layout normalization.  This fallback
        # never publishes diagnostics and does not alter the anti policy.
        if not rows:
            options = _iapt_v170_options(task)
            if not _iapt_v170_is_anti(task, options):
                scanned = _sanitize_public_file_rows(out_dir, _scan_out_files(out_dir))
                versions = _iapt_v170_task_versions(task, options)
                try:
                    feature_id = int(task.get('feature_id') or options.get('feature_id') or 0)
                except Exception:
                    feature_id = 0
                standalone_source = (
                    feature_id in {5, 8}
                    or bool(versions.intersection({
                        'restore', 'source_restore', 'fn_restore',
                        'numeric_restore', 'numeric_source_restore',
                        'dex_restore', 'static_dex_restore',
                        'source_dex_restore', 'iact', 'iact_restore',
                    }))
                    or any(_iapt_v170_truthy(options.get(name)) for name in (
                        'source_restore', 'numeric_source_restore',
                        'static_dex_restore', 'iact_dynamic_decrypt',
                    ))
                )
                allowed = []
                for row in scanned:
                    rel = str((row or {}).get('rel_path') or '').replace('\\', '/').lstrip('./')
                    if rel.startswith('src/') or (standalone_source and rel.startswith('res/')):
                        item = dict(row)
                        item['rel_path'] = rel
                        allowed.append(item)
                rows = sorted(allowed, key=lambda item: str(item.get('rel_path') or ''))
                if rows:
                    _write_file_index(out_dir, rows)
                    _sync_public_file_counts(task, rows)

        return rows

    def list_task_files(task_or_id):
        if isinstance(task_or_id, dict):
            task = dict(task_or_id)
        else:
            task = db.one('SELECT * FROM tasks WHERE id=%s', (task_or_id,))
        if not task or not task.get('out_dir'):
            return []
        if _iapt_v170_whitelist_task(task):
            try:
                task_id = int(task.get('id') or 0)
                if task_id > 0:
                    _v169_scrub(task_id)
            except Exception:
                pass
            return _finish_public_file_rows(task)
        return _finish_public_file_rows(task)

    IAPT_WHITELIST_AND_OUTPUT_LAYOUT_V170 = {
        'whitelist_result': 'message only; key/options/report fields scrubbed',
        'ordinary_decrypt_output': 'recognized root source moved into src/**',
        'numeric_dynamic_restore': 'src/** plus res/** preserved',
        'stale_empty_manifest': 'safe disk rescan after normalization',
    }
    print('[OK] IAPT_WHITELIST_AND_OUTPUT_LAYOUT_V170 installed', flush=True)
except Exception as _iapt_v170_error:
    print('[IAPT_WHITELIST_AND_OUTPUT_LAYOUT_V170_FAILED]', repr(_iapt_v170_error), flush=True)
    raise
# IAPT_WHITELIST_AND_OUTPUT_LAYOUT_V170_END


# IAPT_V190_FEATURE999_RUNNER_ENTITLEMENT

# IAPT_V193_JOINT_TRIPLE_ENUM_AUTO_POOL
# Worker command and verified-pool persistence changes are applied in-place.

# IAPT_V201_EXACT_STANDALONE_TASK_BEGIN
_IAPT_V201_DYNAMIC_TASK_BASE_RUN_TASK = run_task


def _iapt_v201_run_dynamic_key_task(task_id: int, task: dict, options: dict):
    started = time.time()
    task_no = str(task.get('task_no') or task_id)
    upload_path = APP_STORAGE / 'uploads' / f'{task_no}.apk'
    out_dir = APP_STORAGE / 'tasks' / task_no
    log_path = APP_STORAGE / 'tasks' / f'{task_no}.log'
    try:
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        out_dir.mkdir(parents=True, exist_ok=True)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        db.exec(
            "UPDATE tasks SET status='running',out_dir=%s,log_path=%s,error_text=NULL,decrypt_version='dynkey' WHERE id=%s",
            (str(out_dir), str(log_path), int(task_id)),
        )
        if not upload_path.is_file() or upload_path.stat().st_size <= 0:
            raise RuntimeError('动态Key任务上传文件不存在或为空')

        with _decrypt_semaphore:
            source_data = upload_path.read_bytes()
            from .dynamic_key_pool import (
                extract_all_so_from_bytes, extract_primary_key, key_text_multi,
                store_key, so_feature_sha256, normalize_feature_map,
            )
            libraries = extract_all_so_from_bytes(
                source_data,
                str(options.get('original_filename') or task.get('apk_name') or 'libygsiyu.so'),
            )
            results = []
            grouped = {}
            for row in libraries:
                entry_name = str(row.get('entry_name') or 'libygsiyu.so')
                abi = str(row.get('abi') or 'unknown').strip().lower()
                so_data = bytes(row.get('data') or b'')
                item = {'entry_name': entry_name, 'abi': abi}
                try:
                    post_key, xor_key, meta = extract_primary_key(so_data)
                    item.update({
                        'post_key': post_key,
                        'xor_key': xor_key,
                        'extractor_build': str(meta.get('extractor_build') or ''),
                        'post_key_bytes': int(meta.get('post_key_bytes') or len(bytes.fromhex(post_key))),
                        'xor_key_bytes': int(meta.get('xor_key_bytes') or len(bytes.fromhex(xor_key))),
                    })
                    pair = (post_key, xor_key)
                    group = grouped.setdefault(pair, {
                        'features': {},
                        'source_sha256': str(row.get('sha256') or hashlib.sha256(so_data).hexdigest()),
                        'source_name': (str(options.get('original_filename') or '') + '::' + entry_name)[:255],
                    })
                    group['features'][abi] = so_feature_sha256(so_data)
                except Exception as exc:
                    item['error'] = '%s: %s' % (type(exc).__name__, exc)
                results.append(item)

            success_count = sum(1 for row in results if not row.get('error'))
            if success_count <= 0:
                failures = '; '.join('%s:%s=%s' % (x.get('abi'), x.get('entry_name'), x.get('error')) for x in results)
                raise RuntimeError('全部 libygsiyu.so 均未静态提取到唯一动态Key：' + failures[:3000])
            if len(grouped) != 1:
                details = []
                for (post, xor), group in grouped.items():
                    details.append('abis=%s post=%s xor=%s' % (
                        ','.join(sorted((group.get('features') or {}).keys())), post, xor
                    ))
                raise RuntimeError('不同 ABI 的确定性静态结果不一致，拒绝写入密钥池：' + ' | '.join(details)[:3000])

            (post_key, xor_key), group = next(iter(grouped.items()))
            client_features = normalize_feature_map(
                options.get('dynamic_key_features'),
                version=_iapt_vfp_feature_version(options),
            )
            if len(libraries) == 1 and client_features:
                selected_abi = str(libraries[0].get('abi') or 'unknown').strip().lower()
                hinted_abi = str(options.get('dynamic_key_sample_abi') or '').strip().lower()
                if hinted_abi in client_features:
                    selected_abi = hinted_abi
                server_sha = so_feature_sha256(bytes(libraries[0].get('data') or b''))
                if client_features.get(selected_abi) != server_sha:
                    raise RuntimeError('客户端动态库指纹与上传 SO 不一致')
                group['features'] = client_features

            stored = store_key(
                post_key,
                xor_key,
                source_type='standalone_exact_v201',
                source_sha256=str(group.get('source_sha256') or ''),
                source_name=str(group.get('source_name') or ''),
                user_id=int(task.get('user_id') or 0),
                verified=True,
                features=group.get('features') or {},
                normalizer_version=_iapt_vfp_feature_version(options),
                authoritative=True,
            )
            pool_ref = str(stored.get('public_id') or '')
            (out_dir / 'key.txt').write_bytes(key_text_multi(results))

        elapsed_ms = int((time.time() - started) * 1000)
        log_lines = [
            '[IAPT_V201_EXACT_STANDALONE_DYNAMIC_KEY]',
            'task_id=%d' % int(task_id),
            'source=%s' % str(options.get('original_filename') or 'libygsiyu.so'),
            'libraries_total=%d' % len(results),
            'libraries_success=%d' % success_count,
            'libraries_failed=%d' % (len(results) - success_count),
            'post_key_bytes=%d' % len(bytes.fromhex(post_key)),
            'xor_key_bytes=%d' % len(bytes.fromhex(xor_key)),
            'pool_ref=%s' % pool_ref,
            'result=key.txt',
            'elapsed_ms=%d' % elapsed_ms,
        ]
        for index, item in enumerate(results, 1):
            log_lines.append('lib[%d]=%s|%s|%s' % (
                index, item.get('abi'), item.get('entry_name'),
                'ok' if not item.get('error') else 'failed',
            ))
        log_path.write_text('\n'.join(log_lines) + '\n', encoding='utf-8')
        count, total = scan_files(int(task_id), out_dir)
        db.exec(
            """
            UPDATE tasks SET status='done',app_name=%s,file_count=%s,total_bytes=%s,
                total_ms=%s,error_text=NULL,out_dir=%s,log_path=%s,decrypt_version='dynkey'
            WHERE id=%s
            """,
            ('动态Key确定性静态提取（%d/%d库）' % (success_count, len(results)), count, total,
             elapsed_ms, str(out_dir), str(log_path), int(task_id)),
        )
        settle_decrypt_quota_once(int(task_id))
        return {
            'ok': True, 'task_id': int(task_id), 'status': 'done',
            'file_count': count, 'total_bytes': total, 'library_count': len(results),
            'success_count': success_count, 'pool_ref': pool_ref, 'elapsed_ms': elapsed_ms,
        }
    except Exception as exc:
        elapsed_ms = int((time.time() - started) * 1000)
        reason = '动态Key提取失败：' + str(exc)
        try:
            log_path.write_text('[IAPT_V201_EXACT_STANDALONE_DYNAMIC_KEY_FAILED]\n' + reason + '\nelapsed_ms=%d\n' % elapsed_ms, encoding='utf-8')
        except Exception:
            pass
        db.exec(
            "UPDATE tasks SET status='failed',total_ms=%s,error_text=%s,out_dir=%s,log_path=%s,decrypt_version='dynkey' WHERE id=%s",
            (elapsed_ms, reason[-4000:], str(out_dir), str(log_path), int(task_id)),
        )
        return {'ok': False, 'task_id': int(task_id), 'status': 'failed', 'error': reason}


def run_task(task_id: int):
    task = db.one('SELECT * FROM tasks WHERE id=%s', (int(task_id),)) or {}
    try:
        options = json.loads(task.get('options_json') or '{}')
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_v39_is_dynamic_key_task(task, options):
        return _iapt_v201_run_dynamic_key_task(int(task_id), task, options)
    return _IAPT_V201_DYNAMIC_TASK_BASE_RUN_TASK(int(task_id))
# IAPT_V201_EXACT_STANDALONE_TASK_END

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD_BEGIN
_IAPT_V191_PREVIOUS_RUN_TASK = run_task

def run_task(task_id: int):
    from .task_feature_guard_v191 import enforce_task_or_mark_failed
    if not enforce_task_or_mark_failed(int(task_id), stage='decrypt_runner_final'):
        return {'ok': False, 'error': 'task feature denied'}
    return _IAPT_V191_PREVIOUS_RUN_TASK(int(task_id))
# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD_END

# IAPT_V1912_EXECUTION_DATABASE_FEATURE_GUARD

# IAPT_NATIVE_COMPILE_PACKAGE_FINAL_BEGIN
# Final package-tree postprocessor. This wrapper stays after every historical
# run_task definition so all V3/ancient execution paths receive the repair.
_IAPT_NATIVE_COMPILE_PACKAGE_FINAL_BASE_RUN_TASK = run_task


def _iapt_native_compile_package_truthy(value):
    if value is True or value == 1:
        return True
    if value is False or value == 0 or value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _iapt_native_compile_feature5_entitled(task: dict) -> bool:
    """Check feature 5 without mutating a basic task or surfacing an auto hint."""
    try:
        from .task_feature_guard_v191 import assert_task_entitled
        probe = {
            "id": int(task.get("id") or 0),
            "user_id": task.get("user_id"),
            "feature_id": 0,
            "decrypt_version": task.get("decrypt_version") or "",
            "options_json": json.dumps({"primary_feature_id": 5}, ensure_ascii=False),
        }
        assert_task_entitled(probe, stage="native_compile_auto_probe")
        return True
    except Exception:
        return False


def _iapt_native_compile_append_log(log_path: Path, label: str, payload) -> None:
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        with log_path.open("a", encoding="utf-8", errors="replace") as fp:
            fp.write("\n[" + str(label) + "] " + json.dumps(
                payload, ensure_ascii=False, sort_keys=True, default=str
            ) + "\n")
    except Exception:
        pass


def _iapt_native_compile_package_postprocess(task_id: int, result):
    if isinstance(result, dict) and result.get("ok") is False:
        return result
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    status = str(task.get("status") or "").strip().lower()
    if status and status not in {"done", "success", "completed"}:
        return result

    task_no = str(task.get("task_no") or task_id)
    apk_path = APP_STORAGE / "uploads" / (task_no + ".apk")
    out_dir = Path(str(task.get("out_dir") or (APP_STORAGE / "tasks" / task_no)))
    log_path = Path(str(task.get("log_path") or (APP_STORAGE / "tasks" / (task_no + ".log"))))
    if not apk_path.is_file() or not out_dir.is_dir():
        return result
    try:
        options = json.loads(task.get("options_json") or "{}")
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    requested = any(_iapt_native_compile_package_truthy(options.get(key)) for key in (
        "native_compile_restore",
        "v3_native_compile_restore",
        "ancient_native_compile_restore",
    ))

    try:
        from .tools.iapp_native_compile_restore import (
            inspect_native_compiled_events,
            restore_native_compiled_events,
        )
        probe = inspect_native_compiled_events(apk_path, out_dir)
    except Exception as exc:
        _iapt_native_compile_append_log(log_path, "IAPT_NATIVE_COMPILE_PACKAGE_PROBE_ERROR", {
            "error": f"{type(exc).__name__}: {exc}", "requested": requested,
        })
        return result

    if int(probe.get("placeholder_count") or 0) <= 0:
        return result
    auto_detected = bool(probe.get("detected"))
    if not requested and not auto_detected:
        return result

    entitled = _iapt_native_compile_feature5_entitled(task)
    if not entitled:
        # No client warning is generated for an automatic probe without feature 5.
        _iapt_native_compile_append_log(log_path, "IAPT_NATIVE_COMPILE_PACKAGE_SKIPPED", {
            "reason": "feature-5-not-entitled", "requested": requested,
            "placeholder_count": int(probe.get("placeholder_count") or 0),
            "matched_placeholder_count": int(probe.get("matched_placeholder_count") or 0),
        })
        return result

    report = restore_native_compiled_events(apk_path, out_dir)
    _iapt_native_compile_append_log(log_path, "IAPT_NATIVE_COMPILE_PACKAGE_RESTORE", report)
    replaced = int(report.get("replaced_count") or 0)
    if replaced <= 0:
        return result

    count, total = scan_files(int(task_id), out_dir)
    try:
        db.exec(
            "UPDATE tasks SET file_count=%s,total_bytes=%s WHERE id=%s",
            (int(count), int(total), int(task_id)),
        )
    except Exception:
        pass
    if isinstance(result, dict):
        result = dict(result)
        result["file_count"] = int(count)
        result["total_bytes"] = int(total)
        result["native_compile_replaced"] = replaced
        result["native_compile_package"] = report.get("manifest_package") or ""
    return result



def _iapt_is_native_compile_source_task(task: dict, options: dict) -> bool:
    options = options if isinstance(options, dict) else {}
    version = str(options.get('decrypt_version') or task.get('decrypt_version') or options.get('task_version') or '').strip().lower()
    return bool(
        _iapt_native_compile_package_truthy(options.get('native_compile_source_restore'))
        or version in {'native_compile_restore', 'native_compile_source_restore'}
    )


def _iapt_merge_native_source_reports(reports):
    valid = [dict(row) for row in reports if isinstance(row, dict)]
    if not valid:
        return {}
    merged = dict(valid[-1])
    merged['rounds'] = len(valid)
    merged['replaced_count'] = sum(int(row.get('replaced_count') or 0) for row in valid)
    merged['unknown_replaced_count'] = sum(int(row.get('unknown_replaced_count') or 0) for row in valid)
    merged['unresolved_count'] = int(valid[-1].get('unresolved_count') or 0)
    changed, seen = [], set()
    for row in valid:
        for item in row.get('files_changed') or []:
            marker = str(item)
            if marker not in seen:
                seen.add(marker)
                changed.append(item)
    merged['files_changed'] = changed
    return merged



def _iapt_build_synthetic_old_report(input_path: Path, out_dir: Path) -> bool:
    """Rebuild the minimal old-iApp member hash table from the project tree.

    Downloaded project ZIPs normally omit old_iapp_report.json.  The original
    APK still contains the four-character sokey, while each _unknown filename
    contains its original MD5 name hash.  That is sufficient for the exact V3
    filename fixpoint parser; no second container decryption is needed.
    """
    try:
        from .tools.iapp_old_decrypt import extract_legacy_sokey_from_apk, md5_hex, OLD_START_SALT
        sokey, sokey_meta = extract_legacy_sokey_from_apk(input_path)
    except Exception:
        return False
    src_root = out_dir / 'src'
    if not src_root.is_dir():
        return False
    unknown_re = re.compile(r'^(?:\d+_)?([0-9a-fA-F]{32})\.bin$')
    members = []
    resolved = 0
    unknown = 0
    for index, path in enumerate(sorted((p for p in src_root.rglob('*') if p.is_file()), key=lambda p: str(p).lower())):
        rel = str(path.relative_to(src_root)).replace('\\', '/')
        match = unknown_re.fullmatch(path.name) if rel.startswith('_unknown/') else None
        if match:
            name_hash = match.group(1).lower()
            resolved_name = ''
            unknown += 1
        else:
            name_hash = md5_hex(str(sokey) + str(OLD_START_SALT) + rel)
            resolved_name = rel
            resolved += 1
        members.append({
            'index': index,
            'name_hash': name_hash,
            'resolved_name': resolved_name,
            'output': 'src/' + rel,
            'plain_size': int(path.stat().st_size),
        })
    if not members:
        return False
    report = {
        'ok': True,
        'family': 'old-iapp-standalone-reconstructed',
        'sokey': str(sokey),
        'sokey_source': 'apk-static-standalone',
        'sokey_metadata': sokey_meta,
        'member_count': len(members),
        'decrypted_count': len(members),
        'written_count': len(members),
        'resolved_name_count': resolved,
        'unknown_name_count': unknown,
        'members': members,
        'standalone_reconstructed': True,
    }
    (out_dir / 'old_iapp_report.json').write_text(
        json.dumps(report, ensure_ascii=False, separators=(',', ':')),
        encoding='utf-8')
    return True

def _iapt_run_native_compile_source_task(task_id: int, task: dict, options: dict):
    task_no = str(task.get('task_no') or task_id)
    src_zip = APP_STORAGE / 'uploads' / (task_no + '.apk')
    dex_path = APP_STORAGE / 'uploads' / (task_no + '.dex')
    out_dir = APP_STORAGE / 'tasks' / task_no
    log_path = APP_STORAGE / 'tasks' / (task_no + '.log')
    db.exec("UPDATE tasks SET status='running',out_dir=%s,log_path=%s,feature_id=5,decrypt_version='native_compile_restore' WHERE id=%s", (str(out_dir), str(log_path), int(task_id)))
    started = time.perf_counter()
    try:
        if not src_zip.is_file() or src_zip.stat().st_size <= 0:
            raise RuntimeError('源码 ZIP 不存在或为空')
        if not dex_path.is_file() or dex_path.stat().st_size <= 0:
            raise RuntimeError('DEX/APK/ZIP/JAR 不存在或为空')
        layout = _iapt_extract_zip_to_dir(src_zip, out_dir)
        from .tools.iapp_native_compile_restore import restore_native_compiled_events
        reports = []
        for round_index in range(1, 6):
            report = restore_native_compiled_events(dex_path, out_dir)
            if not isinstance(report, dict) or report.get('ok') is not True:
                raise RuntimeError('原生编译修复器未能读取有效 DEX')
            reports.append(report)
            if int(report.get('unresolved_count') or 0) <= 0:
                break
            if int(report.get('replaced_count') or 0) <= 0:
                break
        merged = _iapt_merge_native_source_reports(reports)
        finalize = {}
        report_path = out_dir / 'old_iapp_report.json'
        if not report_path.is_file():
            _iapt_build_synthetic_old_report(dex_path, out_dir)
        if report_path.is_file():
            from .tools.iapp_ancient_v3_finalize import finalize_ancient_v3_output
            finalize = finalize_ancient_v3_output(out_dir, merged)
            renamed = int(((finalize or {}).get('filename_rescan') or {}).get('resolved_this_round') or 0)
            if renamed > 0 or int(merged.get('unresolved_count') or 0) > 0:
                post = restore_native_compiled_events(dex_path, out_dir)
                if isinstance(post, dict) and post.get('ok') is True:
                    reports.append(post)
                    merged = _iapt_merge_native_source_reports(reports)
                    finalize = finalize_ancient_v3_output(out_dir, merged)
        count, total = scan_files(int(task_id), out_dir)
        elapsed = (time.perf_counter() - started) * 1000.0
        unknown = int((((finalize or {}).get('filename_rescan') or {}).get('unknown_remaining') or 0))
        log_path.write_text(
            '### IAPT standalone native compile restore\n'
            + f'src={src_zip}\ninput={dex_path}\nout_dir={out_dir}\n'
            + 'layout=' + json.dumps(layout, ensure_ascii=False, sort_keys=True, default=str) + '\n'
            + 'native=' + json.dumps(merged, ensure_ascii=False, sort_keys=True, default=str) + '\n'
            + 'finalize=' + json.dumps(finalize, ensure_ascii=False, sort_keys=True, default=str) + '\n'
            + f'unknown_files={unknown}\nfiles={count}\nbytes={total}\ntotal_ms={elapsed:.2f}\n',
            encoding='utf-8', errors='replace')
        package_name = str(merged.get('manifest_package') or '')
        update_sql = (
            "UPDATE tasks SET status='done',total_ms=%s,app_name=%s,package_name=%s,"
            "version_name=%s,version_code=%s,feature_id=5,decrypt_version='native_compile_restore',"
            "file_count=%s,total_bytes=%s WHERE id=%s"
        )
        db.exec(update_sql, (float(elapsed), '原生编译修复', package_name, 'native_compile_restore', '', int(count), int(total), int(task_id)))
        settle_decrypt_quota_once(int(task_id))
        return {'ok': True, 'task_id': int(task_id), 'file_count': int(count), 'total_bytes': int(total), 'unknown_file_count': unknown, 'native_compile_report': merged}
    except Exception as exc:
        reason = '原生编译修复失败：' + str(exc)
        try:
            log_path.write_text(reason, encoding='utf-8', errors='replace')
        except Exception:
            pass
        db.exec("UPDATE tasks SET status='failed',error_text=%s,feature_id=5,decrypt_version='native_compile_restore' WHERE id=%s", (reason, int(task_id)))
        return {'ok': False, 'task_id': int(task_id), 'error': reason}


def run_task(task_id: int):
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    try:
        options = json.loads(task.get("options_json") or "{}")
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if _iapt_is_native_compile_source_task(task, options):
        return _iapt_run_native_compile_source_task(int(task_id), task, options)
    result = _IAPT_NATIVE_COMPILE_PACKAGE_FINAL_BASE_RUN_TASK(int(task_id))
    try:
        return _iapt_native_compile_package_postprocess(int(task_id), result)
    except Exception as exc:
        try:
            task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
            task_no = str(task.get("task_no") or task_id)
            log_path = Path(str(task.get("log_path") or (APP_STORAGE / "tasks" / (task_no + ".log"))))
            _iapt_native_compile_append_log(log_path, "IAPT_NATIVE_COMPILE_PACKAGE_FINAL_ERROR", {
                "error": f"{type(exc).__name__}: {exc}",
            })
        except Exception:
            pass
        return result
# IAPT_NATIVE_COMPILE_PACKAGE_FINAL_END


# IAPT_ANTI_IAPEC_PACKAGE_FINAL_BEGIN
# Runs after the native-compile package repair. Normal V3 also decodes during
# recursive member extraction, while this final pass catches ancient output,
# downloaded/project trees and any encrypted strings revealed by later repair.
_IAPT_ANTI_IAPEC_BASE_RUN_TASK = run_task

def _iapt_anti_iapec_truthy(value):
    if value is True or value == 1:
        return True
    if value is False or value == 0 or value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}

def _iapt_anti_iapec_postprocess(task_id: int, result):
    if isinstance(result, dict) and result.get("ok") is False:
        return result
    task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
    try:
        options = json.loads(task.get("options_json") or "{}")
        if not isinstance(options, dict):
            options = {}
    except Exception:
        options = {}
    if not _iapt_anti_iapec_truthy(options.get("anti_iapec_encryption")):
        return result
    status = str(task.get("status") or "").strip().lower()
    if status and status not in {"done", "success", "completed"}:
        return result
    task_no = str(task.get("task_no") or task_id)
    apk_path = APP_STORAGE / "uploads" / (task_no + ".apk")
    out_dir = Path(str(task.get("out_dir") or (APP_STORAGE / "tasks" / task_no)))
    log_path = Path(str(task.get("log_path") or (APP_STORAGE / "tasks" / (task_no + ".log"))))
    if not out_dir.is_dir():
        return result
    from .tools.iapt_v10.iapt_iapec_restore import restore_iapec_project
    report = restore_iapec_project(out_dir, apk_path if apk_path.is_file() else None, enabled=True)
    # Old-container filenames can exist only inside the just-decoded source.
    # Reuse the same normal-V3 parser/fixpoint finalizer after anti-iAPEC.
    finalize = {}
    if (out_dir / "old_iapp_report.json").is_file():
        try:
            from .tools.iapp_ancient_v3_finalize import finalize_ancient_v3_output
            finalize = finalize_ancient_v3_output(out_dir, {})
        except Exception as exc:
            report.setdefault("errors", []).append({"error": f"filename-finalize:{type(exc).__name__}:{exc}"})
    count, total = scan_files(int(task_id), out_dir)
    options["anti_iapec_encryption"] = True
    options["anti_iapec_detected"] = bool(report.get("detected"))
    options["anti_iapec_restored_count"] = int(report.get("restored_count") or 0)
    options["anti_iapec_remaining_count"] = int(report.get("remaining_count") or 0)
    try:
        db.exec(
            "UPDATE tasks SET options_json=%s,file_count=%s,total_bytes=%s WHERE id=%s",
            (json.dumps(options, ensure_ascii=False, separators=(",", ":")), int(count), int(total), int(task_id)),
        )
    except Exception:
        pass
    _iapt_native_compile_append_log(log_path, "IAPT_ANTI_IAPEC_RESTORE", {
        "report": report,
        "filename_finalize": finalize,
        "independent_from_anti_encrypted_sample": True,
    })
    if isinstance(result, dict):
        result = dict(result)
        result["anti_iapec_encryption"] = True
        result["anti_iapec_restored_count"] = int(report.get("restored_count") or 0)
        result["anti_iapec_remaining_count"] = int(report.get("remaining_count") or 0)
        result["file_count"] = int(count)
        result["total_bytes"] = int(total)
    return result

def run_task(task_id: int):
    result = _IAPT_ANTI_IAPEC_BASE_RUN_TASK(int(task_id))
    try:
        return _iapt_anti_iapec_postprocess(int(task_id), result)
    except Exception as exc:
        try:
            task = db.one("SELECT * FROM tasks WHERE id=%s", (int(task_id),)) or {}
            task_no = str(task.get("task_no") or task_id)
            log_path = Path(str(task.get("log_path") or (APP_STORAGE / "tasks" / (task_no + ".log"))))
            _iapt_native_compile_append_log(log_path, "IAPT_ANTI_IAPEC_FINAL_ERROR", {
                "error": f"{type(exc).__name__}: {exc}",
            })
        except Exception:
            pass
        return result
# IAPT_ANTI_IAPEC_PACKAGE_FINAL_END

# IAPT_IAPEC_SPLIT_V13_RUNNER_BEGIN
_IAPT_IAPEC_SPLIT_V13_PREV_RUN_TASK = run_task

def _iapt_iapec_v13_truthy(value):
    if value is True or value == 1: return True
    if value is False or value == 0 or value is None: return False
    return str(value).strip().lower() in {'1','true','yes','on','y'}

def _iapt_iapec_v13_primary_dex(path):
    try:
        p=Path(path)
        data=p.read_bytes()
        if data.startswith(b'dex\n'): return data
        if zipfile.is_zipfile(p):
            with zipfile.ZipFile(p,'r') as zf:
                names=sorted([n for n in zf.namelist() if re.fullmatch(r'(?:.*/)?classes\d*\.dex',n.replace('\\','/'),flags=re.I)], key=lambda n:(0 if Path(n).name.lower()=='classes.dex' else 1,n.lower()))
                if names: return zf.read(names[0])
    except Exception: pass
    return None

def _iapt_iapec_v13_append_log(path, label, payload):
    try:
        Path(path).parent.mkdir(parents=True,exist_ok=True)
        with Path(path).open('a',encoding='utf-8',errors='replace') as f:
            f.write('\n['+label+'] '+json.dumps(payload,ensure_ascii=False,sort_keys=True)+'\n')
    except Exception: pass

def _iapt_iapec_v13_postprocess(task_id, result):
    task=db.one('SELECT * FROM tasks WHERE id=%s',(int(task_id),)) or {}
    if str(task.get('status') or '').strip().lower() not in {'done','success','completed'}: return result
    try:
        options=json.loads(task.get('options_json') or '{}')
        if not isinstance(options,dict): options={}
    except Exception: options={}
    task_no=str(task.get('task_no') or task_id)
    out_dir=Path(str(task.get('out_dir') or (APP_STORAGE/'tasks'/task_no)))
    if not out_dir.is_dir(): return result
    normal_apk=APP_STORAGE/'uploads'/(task_no+'.apk')
    attachment=APP_STORAGE/'uploads'/(task_no+'.dex')
    source_attachment=attachment if attachment.is_file() else normal_apk
    log_path=Path(str(task.get('log_path') or (APP_STORAGE/'tasks'/(task_no+'.log'))))
    combined={}

    # Feature 17: high-efficiency encrypted strings only.
    if _iapt_iapec_v13_truthy(options.get('anti_iapec_encryption')):
        from .tools.iapt_v10.iapt_iapec_restore import restore_iapec_project
        combined['efficient']=restore_iapec_project(out_dir, normal_apk if normal_apk.is_file() else source_attachment, enabled=True)

    # Feature 5: iAPEC numeric dispatcher plus the historical random-number table.
    dynamic=any(_iapt_iapec_v13_truthy(options.get(k)) for k in (
        'numeric_source_restore','numeric_restore','dynamic_restore','v3_dynamic_restore','ancient_dynamic_restore','iapec_numeric_dynamic_restore'
    )) or str(options.get('restore_fn_names') or '').strip().lower() in {'on','auto','true','1'}
    if dynamic:
        from .tools.iapt_v10.iapt_iapec_dynamic_restore import restore_iapec_dynamic_project
        combined['iapec_dynamic']=restore_iapec_dynamic_project(out_dir, source_attachment if source_attachment.is_file() else None, enabled=True)
        # Re-run legacy numeric restore after high-efficiency decoding reveals new calls.
        try:
            from .tools.iapp_auto_decrypt import maybe_restore_numeric_function_names
            primary=_iapt_iapec_v13_primary_dex(source_attachment)
            if primary:
                combined['legacy_numeric']=maybe_restore_numeric_function_names(source_attachment,out_dir,mode='on',backup=False,member_sources=None,primary_dex=primary,threads=int(options.get('threads') or 4),dex_enum=False)
        except Exception as exc:
            combined['legacy_numeric_error']=f'{type(exc).__name__}: {exc}'

    # Feature 17: independent self-destruction/control-type recovery.
    if _iapt_iapec_v13_truthy(options.get('anti_iapec_self_destruct')):
        from .tools.iapt_v10.iapt_iapec_self_destruct_restore import restore_iapec_self_destruct_project
        combined['self_destruct']=restore_iapec_self_destruct_project(out_dir, normal_apk if normal_apk.is_file() else source_attachment, enabled=True)

    # All newly revealed references participate in the normal V3 filename fixpoint.
    if combined and (out_dir/'old_iapp_report.json').is_file():
        try:
            from .tools.iapp_ancient_v3_finalize import finalize_ancient_v3_output
            combined['filename_finalize']=finalize_ancient_v3_output(out_dir,{})
        except Exception as exc:
            combined['filename_finalize_error']=f'{type(exc).__name__}: {exc}'
    if combined:
        count,total=scan_files(int(task_id),out_dir)
        options['iapec_v13']=combined
        try: db.exec('UPDATE tasks SET options_json=%s,file_count=%s,total_bytes=%s WHERE id=%s',(json.dumps(options,ensure_ascii=False,separators=(',',':')),int(count),int(total),int(task_id)))
        except Exception: pass
        _iapt_iapec_v13_append_log(log_path,'IAPT_IAPEC_SPLIT_V13',combined)
        if isinstance(result,dict):
            result=dict(result); result['iapec_v13']=combined; result['file_count']=int(count); result['total_bytes']=int(total)
    return result

def run_task(task_id: int):
    result=_IAPT_IAPEC_SPLIT_V13_PREV_RUN_TASK(int(task_id))
    try: return _iapt_iapec_v13_postprocess(int(task_id),result)
    except Exception as exc:
        try:
            task=db.one('SELECT * FROM tasks WHERE id=%s',(int(task_id),)) or {}
            no=str(task.get('task_no') or task_id)
            _iapt_iapec_v13_append_log(APP_STORAGE/'tasks'/(no+'.log'),'IAPT_IAPEC_SPLIT_V13_ERROR',{'error':f'{type(exc).__name__}: {exc}'})
        except Exception: pass
        return result
# IAPT_IAPEC_SPLIT_V13_RUNNER_END
