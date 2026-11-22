#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Deprecated emergency compatibility hook for anti-encrypted V3 tasks.

The normal path is fully structure-driven: resource-source graphs restore the
canonical container and static SO/DEX/VM analysis recovers runtime parameters.
``PROFILES`` intentionally stays empty so sample hashes cannot mask regressions.
"""
from __future__ import annotations
import hashlib
import zipfile
from pathlib import Path
from typing import Dict, Optional, Tuple

PROFILES: Dict[str, Dict[str, str]] = {
    # Intentionally empty.  Current anti-encryption families are recovered from
    # container/SO/DEX structure; container-hash parameter profiles would hide
    # regressions and are kept only as an API-compatible emergency hook.
}

def canonical_container(apk: Path | str) -> Tuple[bytes, str]:
    apk = Path(apk)
    with zipfile.ZipFile(apk, "r") as archive:
        matches = [
            info for info in archive.infolist()
            if not info.is_dir()
            and info.filename.replace("\\", "/").lower() == "assets/lib.so"
        ]
        if len(matches) != 1:
            raise ValueError("expected exactly one canonical assets/lib.so, got %d" % len(matches))
        data = archive.read(matches[0])
    return data, hashlib.sha256(data).hexdigest()

def resolve_profile(apk: Path | str) -> Optional[Dict[str, str]]:
    data, digest = canonical_container(apk)
    profile = PROFILES.get(digest)
    if profile is None:
        return None
    result = dict(profile)
    result["container_sha256"] = digest
    result["container_size"] = str(len(data))
    return result
