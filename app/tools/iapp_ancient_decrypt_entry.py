#!/usr/bin/env python3
"""Strict entry point for ancient iApp four-character-sokey containers.

It accepts only ancient-scheme parameters and never imports/calls the V3
post_key/xor_key/QE-salt decryptor.
"""
from __future__ import annotations
import argparse
import json
import sys
from pathlib import Path

try:
    from .iapp_old_decrypt import decrypt_old_iapp_apk
except ImportError:
    # Direct script execution from app/tools.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from iapp_old_decrypt import decrypt_old_iapp_apk  # type: ignore


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(description="Ancient iApp four-character-sokey decryptor")
    ap.add_argument("--apk", required=True, type=Path)
    ap.add_argument("--outdir", required=True, type=Path)
    ap.add_argument("--sokey", default="")
    ap.add_argument("--dexkey", default="")
    ap.add_argument("--sokey-enum", action="store_true")
    ap.add_argument("--dexkey-enum", action="store_true")
    ap.add_argument("--dexkey-auto", action="store_true", help="statically resolve old f.b()/dexkey from uploaded classes*.dex; no enumeration")
    ap.add_argument("--server-sokey", action="store_true")
    ap.add_argument("--signature-mode", choices=("skip", "verify", "auto"), default="auto")
    ap.add_argument("--signature-bytes-hex", default="")
    ap.add_argument("--password", default=None)
    ap.add_argument("--main-file", default="mian.iyu")
    ap.add_argument("--find", action="append", default=[])
    ap.add_argument("--find-recursive", action="store_true")
    ap.add_argument("--dexkey-enum-start", type=int, default=3_100_000)
    ap.add_argument("--dexkey-enum-stop", type=int, default=10_000_000)
    ap.add_argument("--enum-workers", type=int, default=0)
    ap.add_argument("--enum-chunk-size", type=int, default=20_000)
    ap.add_argument("--old-sokey-alphabet", default="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
    ap.add_argument("--restore-fn-names", choices=("off", "auto", "on"), default="off")
    return ap


def main(argv=None) -> int:
    print("[IAPT_V8] decrypt_script=ancient", flush=True)
    args = build_parser().parse_args(argv)
    options = {
        "legacy_iapp": True,
        "old_iapp": True,
        "decrypt_scheme": "ancient",
        "hidden": args.sokey,
        "fb": args.dexkey,
        "sokey_enum": bool(args.sokey_enum),
        "dexkey_enum": bool(args.dexkey_enum),
        "dexkey_auto": bool(args.dexkey_auto),
        "server_sokey": bool(args.server_sokey),
        "signature_mode": args.signature_mode,
        "signature_bytes_hex": args.signature_bytes_hex,
        "user_password": args.password,
        "main_file": args.main_file,
        "find": args.find,
        "find_recursive": bool(args.find_recursive),
        "dexkey_enum_start": int(args.dexkey_enum_start),
        "dexkey_enum_stop": int(args.dexkey_enum_stop),
        "enum_workers": int(args.enum_workers),
        "enum_chunk_size": int(args.enum_chunk_size),
        "old_sokey_alphabet": args.old_sokey_alphabet,
        "restore_fn_names": args.restore_fn_names,
        "ancient_dynamic_restore": args.restore_fn_names in ("auto", "on"),
        "numeric_restore": args.restore_fn_names in ("auto", "on"),
        "dynamic_restore": args.restore_fn_names in ("auto", "on"),
    }
    report = decrypt_old_iapp_apk(args.apk, args.outdir, options)
    summary = {k: report.get(k) for k in (
        "ok", "family", "app_name", "package_name", "sokey", "dexkey",
        "member_count", "decrypted_count", "written_count", "total_ms"
    )}
    print("IAPT_ANCIENT_REPORT=" + json.dumps(summary, ensure_ascii=False, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
