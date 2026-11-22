#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IAPT V10 ancient iApp engine.

This process only understands the old four-character-sokey format.  It never
imports the current-generation QE/post/xor decryptor.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
from iapp_old_decrypt import decrypt_old_iapp_apk  # noqa: E402


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="IAPT V10 ancient iApp decryptor")
    p.add_argument("--apk", required=True, type=Path)
    p.add_argument("--outdir", required=True, type=Path)
    p.add_argument("--sokey", default="")
    p.add_argument("--dexkey", default="")
    p.add_argument("--sokey-enum", action="store_true")
    p.add_argument("--dexkey-enum", action="store_true")
    p.add_argument("--dexkey-auto", action="store_true", help="statically resolve old f.b()/dexkey from uploaded classes*.dex; no enumeration")
    p.add_argument("--server-sokey", action="store_true")
    p.add_argument("--signature-mode", choices=("skip", "verify", "auto"), default="auto")
    p.add_argument("--signature-bytes-hex", default="")
    p.add_argument("--password", default=None)
    p.add_argument("--main-file", default="mian.iyu")
    p.add_argument("--find", action="append", default=[])
    p.add_argument("--find-recursive", action="store_true")
    p.add_argument("--dexkey-enum-start", type=int, default=3_100_000)
    p.add_argument("--dexkey-enum-stop", type=int, default=10_000_000)
    p.add_argument("--enum-workers", type=int, default=0)
    p.add_argument("--enum-chunk-size", type=int, default=20_000)
    p.add_argument("--old-sokey-alphabet", default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    return p


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    args.apk = args.apk.resolve()
    args.outdir = args.outdir.resolve()
    args.outdir.mkdir(parents=True, exist_ok=True)
    print("[IAPT_V10] decrypt_script=ancient", flush=True)
    sokey = str(args.sokey or "").strip()
    if sokey and not args.sokey_enum and not args.server_sokey and len(sokey) != 4:
        raise SystemExit("ancient sokey must be exactly 4 characters")
    options = {
        "legacy_iapp": True,
        "old_iapp": True,
        "decrypt_scheme": "ancient",
        "hidden": sokey,
        "fb": str(args.dexkey or "").strip(),
        "sokey_enum": bool(args.sokey_enum),
        "dexkey_enum": bool(args.dexkey_enum),
        "dexkey_auto": bool(args.dexkey_auto),
        "server_sokey": bool(args.server_sokey),
        "signature_mode": args.signature_mode,
        "signature_bytes_hex": args.signature_bytes_hex,
        "user_password": args.password,
        "main_file": args.main_file,
        "find": list(args.find or []),
        "find_recursive": bool(args.find_recursive),
        "dexkey_enum_start": int(args.dexkey_enum_start),
        "dexkey_enum_stop": int(args.dexkey_enum_stop),
        "enum_workers": int(args.enum_workers),
        "enum_chunk_size": int(args.enum_chunk_size),
        "old_sokey_alphabet": args.old_sokey_alphabet,
    }
    report = decrypt_old_iapp_apk(args.apk, args.outdir, options)
    summary = {k: report.get(k) for k in (
        "ok", "family", "app_name", "package_name", "sokey", "dexkey",
        "member_count", "decrypted_count", "written_count", "total_ms"
    )}
    print("IAPT_V10_ANCIENT_REPORT=" + json.dumps(summary, ensure_ascii=False, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
