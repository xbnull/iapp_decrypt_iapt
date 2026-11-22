#!/usr/bin/env python3
from pathlib import Path
import sys
ROOT = Path(__file__).resolve().parent / "iapt_v10"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from iapt_static_parameter_analyzer import *
if __name__ == "__main__":
    raise SystemExit(main())
