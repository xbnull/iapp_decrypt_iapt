#!/usr/bin/env python3
"""Strict entry point for current-generation iApp/V3 containers.

This wrapper intentionally exposes only the V3 decryptor.  Ancient four-character
sokey containers are handled by iapp_ancient_decrypt_entry.py and must never reach
this process.
"""
from __future__ import annotations
import runpy
import sys
from pathlib import Path


def main() -> int:
    print("[IAPT_V8] decrypt_script=v3", flush=True)
    target = Path(__file__).with_name("iapp_auto_decrypt.py")
    sys.argv[0] = str(target)
    runpy.run_path(str(target), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
