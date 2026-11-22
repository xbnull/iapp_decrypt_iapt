#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# iAPT V6 dispatcher. Finds and calls the real V6 static decrypt tool. Never falls back to V3.
import argparse
import subprocess
import sys
import os
import signal
from pathlib import Path


def _skip_path(p: Path) -> bool:
    name = p.name.lower()
    if name in {'iapp_auto_decrypt.py', 'iapt_v6_dispatch.py', 'iapp_v6_protector.py', 'iapp_static_dex_restore.py', 'iapp_deobfuscate.py', 'iapp_v6_event_vm.py'}:
        return True
    bad_parts = {'venv', '__pycache__', 'storage', '.git'}
    return any(part in bad_parts for part in p.parts)


def find_tools(root: Path):
    here = Path(__file__).resolve().parent
    candidates = []
    fixed = [
        here / 'iapp_dex2iyu_v6.py', here / 'iapp_dex2iyu.py', here / 'dex2iyu.py', here / 'iapp_v6_decrypt.py',
        here / 'iapp_v6_static_decrypt.py', here / 'v6_decrypt.py', here / 'v6_static_decrypt.py',
        root / 'iapp_dex2iyu.py', root / 'dex2iyu.py', root / 'tools' / 'iapp_dex2iyu.py',
        root / 'tools' / 'iapp_v6_decrypt.py',
    ]
    for p in fixed:
        if p.exists() and p.is_file() and not _skip_path(p):
            candidates.append(p.resolve())
    try:
        for p in root.rglob('*.py'):
            if _skip_path(p):
                continue
            n = p.name.lower()
            if ('dex2iyu' in n) or ('v6' in n and ('decrypt' in n or 'static' in n or 'iapp' in n)):
                candidates.append(p.resolve())
    except Exception:
        pass
    out, seen = [], set()
    for p in candidates:
        if p in seen:
            continue
        seen.add(p); out.append(p)
    return out


def is_raw_dex(inp: Path) -> bool:
    """Detect DEX by file magic, because uploads are stored as <task_no>.apk."""
    try:
        with inp.open('rb') as f:
            return f.read(4) == b'dex\n'
    except Exception:
        return False


def _run_attempt(cmd, timeout: int):
    """Run one tool in its own process group and always reap the whole group."""
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        start_new_session=True, bufsize=1,
    )
    try:
        out, _ = proc.communicate(timeout=timeout)
        return proc.returncode, out or ''
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGTERM)
        except Exception:
            try: proc.terminate()
            except Exception: pass
        try:
            out, _ = proc.communicate(timeout=2)
        except Exception:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except Exception:
                try: proc.kill()
                except Exception: pass
            try: out, _ = proc.communicate(timeout=2)
            except Exception: out = ''
        raise subprocess.TimeoutExpired(cmd, timeout, output=out)


def build_attempts(tool: Path, inp: Path, outdir: Path, args):
    n = tool.name.lower()
    extra = []
    if args.package: extra += ['--package', args.package]
    if args.find: extra += ['--find', args.find]
    if args.max_output_files: extra += ['--max-output-files', str(args.max_output_files)]
    if args.threads: extra += ['--threads', str(args.threads)]
    # Raw DEX V6 tasks already receive full V6 source and deep_code. Running
    # JADX on the same DEX delays completion heavily, so only APK/ZIP runs Java
    # recovery by default.
    if args.no_java or is_raw_dex(inp) or inp.suffix.lower() == '.dex': extra += ['--no-java']
    if args.advanced_analysis: extra += ['--advanced-analysis']
    if args.protector_analysis: extra += ['--protector-analysis']
    if 'iapp_dex2iyu_v6' in n:
        return [[sys.executable, str(tool), '--apk', str(inp), '--outdir', str(outdir)] + [x for x in extra if x not in ('--find','--max-output-files','--threads')]]
    if 'dex2iyu' in n:
        return [
            [sys.executable, str(tool), '--apk', str(inp), '--outdir', str(outdir)] + extra,
            [sys.executable, str(tool), str(inp), '-o', str(outdir)] + extra,
        ]
    return [
        [sys.executable, str(tool), '--apk', str(inp), '--outdir', str(outdir)] + extra,
        [sys.executable, str(tool), '--input', str(inp), '--outdir', str(outdir)] + extra,
        [sys.executable, str(tool), str(inp), '-o', str(outdir)] + extra,
    ]


def has_output(outdir: Path) -> bool:
    if not outdir.exists():
        return False
    for p in outdir.rglob('*'):
        if p.is_file() and '/.tmp/' not in p.as_posix():
            return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--input', required=True)
    ap.add_argument('--outdir', required=True)
    ap.add_argument('--package')
    ap.add_argument('--find')
    ap.add_argument('--max-output-files')
    ap.add_argument('--threads')
    ap.add_argument('--no-java', action='store_true')
    ap.add_argument('--advanced-analysis', '--analyze-interpreter', action='store_true')
    ap.add_argument('--protector-analysis', action='store_true')
    args = ap.parse_args()
    inp = Path(args.input).resolve()
    outdir = Path(args.outdir).resolve()
    root = Path(__file__).resolve().parents[2]
    outdir.mkdir(parents=True, exist_ok=True)
    print('[IAPT v55] V6 dispatcher start')
    print('[IAPT v55] input=', inp)
    print('[IAPT v55] outdir=', outdir)
    tools = find_tools(root)
    print('[IAPT v55] V6 tool candidates:', ', '.join(str(x) for x in tools) or '(none)')
    if not tools:
        print('[IAPT v55] ERROR: 未找到 V6 解密工具。请放置 app/tools/iapp_dex2iyu.py 或 app/tools/iapp_v6_decrypt.py。')
        return 1
    last_logs = []
    for tool in tools:
        for cmd in build_attempts(tool, inp, outdir, args):
            print('[IAPT v55] try:', ' '.join(cmd))
            try:
                code, output = _run_attempt(cmd, timeout=int(os.environ.get('IAPT_V6_ATTEMPT_TIMEOUT','300')))
            except Exception as e:
                msg = 'RUN_EXCEPTION ' + repr(e)
                print('[IAPT v55]', msg)
                last_logs.append((tool, cmd, 999, msg))
                continue
            print(output or '')
            if code == 0 and has_output(outdir):
                print('[IAPT v55] V6 decrypt OK:', tool)
                return 0
            last_logs.append((tool, cmd, code, (output or '')[-2000:]))
    print('[IAPT v55] ERROR: V6 工具已找到但全部执行失败。')
    for tool, cmd, code, tail in last_logs[-6:]:
        print('--- tool:', tool)
        print('--- code:', code)
        print('--- cmd:', ' '.join(cmd))
        print(tail)
    return 1


if __name__ == '__main__':
    raise SystemExit(main())
