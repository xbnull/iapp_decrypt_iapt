#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Compatibility entry for the V10 static resource analyzer."""
from __future__ import annotations
import importlib.util
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
V10 = HERE / "iapt_v10"
if str(V10) not in sys.path:
    sys.path.insert(0, str(V10))
TARGET = V10 / "iapt_static_resource_analyzer.py"
spec = importlib.util.spec_from_file_location("_iapt_v10_static_resource_analyzer", TARGET)
if spec is None or spec.loader is None:
    raise ImportError("cannot load V10 static resource analyzer")
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)
for name in dir(module):
    if name.startswith("_") and name not in {"__all__"}:
        continue
    globals()[name] = getattr(module, name)

if __name__ == "__main__":
    raise SystemExit(module.main())
