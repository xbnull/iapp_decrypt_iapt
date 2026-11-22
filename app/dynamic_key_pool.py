from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import secrets
import zipfile
from pathlib import Path
from typing import Iterable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import db
from .config import APP_SECRET
import threading

_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_AAD = b"iapt-dynamic-key-pool-v1"
_FEATURE_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_FEATURE_VERSION = 1
_SOKEY_PREFIX = b"YDXFKCDOTN"
_SOKEY_REPL = b"0" * 32
_KNOWN_ABIS = {"arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64"}


def ensure_schema() -> None:
    db.exec(
        """
        CREATE TABLE IF NOT EXISTS dynamic_key_pool (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            public_id VARCHAR(64) NOT NULL,
            key_hash CHAR(64) NOT NULL,
            post_key_enc LONGTEXT NOT NULL,
            xor_key_enc LONGTEXT NOT NULL,
            source_type VARCHAR(32) NOT NULL DEFAULT 'unknown',
            source_sha256 CHAR(64) NULL,
            source_name VARCHAR(255) NULL,
            first_user_id BIGINT NULL,
            verified TINYINT NOT NULL DEFAULT 0,
            success_count INT NOT NULL DEFAULT 1,
            use_count INT NOT NULL DEFAULT 0,
            enabled TINYINT NOT NULL DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            last_used_at DATETIME NULL,
            UNIQUE KEY uk_dynamic_key_pool_public(public_id),
            KEY idx_dynamic_key_pool_hash(key_hash),
            KEY idx_dynamic_key_pool_enabled(enabled,id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    # Old installations used a unique key-pair index.  A single post/xor pair may
    # correspond to multiple separately compiled SO schemes, so key_hash is now a
    # normal lookup index and the SO fingerprints decide whether schemes merge.
    try:
        db.exec("ALTER TABLE dynamic_key_pool DROP INDEX uk_dynamic_key_pool_hash")
    except Exception:
        pass
    try:
        db.exec("ALTER TABLE dynamic_key_pool ADD KEY idx_dynamic_key_pool_hash(key_hash)")
    except Exception:
        pass
    db.exec(
        """
        CREATE TABLE IF NOT EXISTS dynamic_key_features (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            dynamic_key_id BIGINT NOT NULL,
            abi VARCHAR(32) NOT NULL,
            feature_sha256 CHAR(64) NOT NULL,
            normalizer_version INT NOT NULL DEFAULT 1,
            source_type VARCHAR(32) NOT NULL DEFAULT 'unknown',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            UNIQUE KEY uk_dynamic_key_feature(abi,feature_sha256,normalizer_version),
            UNIQUE KEY uk_dynamic_key_feature_scheme_abi(dynamic_key_id,abi,normalizer_version),
            KEY idx_dynamic_key_feature_key(dynamic_key_id),
            KEY idx_dynamic_key_feature_lookup(abi,feature_sha256)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )
    try:
        db.exec("ALTER TABLE dynamic_key_features ADD UNIQUE KEY uk_dynamic_key_feature_scheme_abi(dynamic_key_id,abi,normalizer_version)")
    except Exception:
        pass


def _master_key() -> bytes:
    return hashlib.sha256((str(APP_SECRET) + "|dynamic-key-pool-v1").encode("utf-8")).digest()


def _encrypt_hex(value: str) -> str:
    raw = bytes.fromhex(normalize_hex(value, "key"))
    nonce = secrets.token_bytes(12)
    cipher = AESGCM(_master_key()).encrypt(nonce, raw, _AAD)
    return base64.urlsafe_b64encode(nonce + cipher).decode("ascii")


def _decrypt_hex(value: str) -> str:
    blob = base64.urlsafe_b64decode(str(value).encode("ascii"))
    if len(blob) < 13:
        raise ValueError("invalid encrypted key")
    raw = AESGCM(_master_key()).decrypt(blob[:12], blob[12:], _AAD)
    return raw.hex()


def normalize_hex(value, label: str = "key") -> str:
    text = str(value or "").strip().replace(" ", "").lower()
    if not text or len(text) % 2 or not _HEX_RE.fullmatch(text):
        raise ValueError(f"{label} 必须是偶数长度十六进制")
    return text


def _key_hash(post_key: str, xor_key: str) -> str:
    return hashlib.sha256((post_key + "\0" + xor_key).encode("ascii")).hexdigest()



def normalize_abi(value: str) -> str:
    abi = str(value or "").strip().lower().replace("\\", "/")
    if "/" in abi:
        parts = [x for x in abi.split("/") if x]
        for part in reversed(parts):
            if part in _KNOWN_ABIS:
                return part
    if abi in _KNOWN_ABIS:
        return abi
    return abi[:32] if abi else "unknown"


def normalize_feature_map(value, *, version: int = _FEATURE_VERSION) -> dict[str, str]:
    if value in (None, ""):
        return {}
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except Exception:
            return {}
    if isinstance(value, list):
        converted = {}
        for row in value:
            if not isinstance(row, dict):
                continue
            abi = row.get("abi")
            sha = row.get("feature_sha256") or row.get("sha256") or row.get("feature")
            if abi is not None and sha is not None:
                converted[str(abi)] = str(sha)
        value = converted
    if not isinstance(value, dict):
        return {}
    out: dict[str, str] = {}
    for raw_abi, raw_sha in value.items():
        abi = normalize_abi(raw_abi)
        sha = str(raw_sha or "").strip().lower()
        if abi != "unknown" and _FEATURE_HEX_RE.fullmatch(sha):
            out[abi] = sha
    return out


def _is_hex_byte(value: int) -> bool:
    return 48 <= value <= 57 or 65 <= value <= 70 or 97 <= value <= 102


def normalize_so_for_feature(data: bytes) -> tuple[bytes, int]:
    """Normalize only the per-APK 32-byte sokey slot; native code remains intact."""
    raw = bytes(data or b"")
    if not raw:
        return raw, 0
    out = bytearray(raw)
    count = 0
    limit = len(out) - 32
    i = 0
    while i <= limit:
        first10 = bytes(out[i:i + 10])
        prefix_ok = first10 == _SOKEY_PREFIX or all(_is_hex_byte(x) for x in first10)
        if (prefix_ok and bytes(out[i + 10:i + 20]) == b"Q" * 10
                and bytes(out[i + 20:i + 30]) == b"W" * 10
                and bytes(out[i + 30:i + 32]) == b"EE"):
            out[i:i + 32] = _SOKEY_REPL
            count += 1
            i += 32
            continue
        i += 1
    return bytes(out), count


def so_feature_sha256(data: bytes) -> str:
    normalized, _ = normalize_so_for_feature(data)
    return hashlib.sha256(normalized).hexdigest()


def list_features(dynamic_key_id: int) -> dict[str, str]:
    ensure_schema()
    rows = db.all(
        "SELECT abi,feature_sha256 FROM dynamic_key_features "
        "WHERE dynamic_key_id=%s AND normalizer_version=%s ORDER BY id ASC",
        (int(dynamic_key_id), int(_FEATURE_VERSION)),
    ) or []
    out: dict[str, str] = {}
    for row in rows:
        abi = normalize_abi(row.get("abi"))
        sha = str(row.get("feature_sha256") or "").lower()
        if abi not in out and _FEATURE_HEX_RE.fullmatch(sha):
            out[abi] = sha
    return out


def _row_key_hash(row: dict) -> str:
    return str((row or {}).get("key_hash") or "").strip().lower()


def _new_pool_row(post: str, xor: str, kh: str, *, source_type: str,
                  source_sha256: str, source_name: str,
                  user_id: Optional[int], verified: bool) -> dict:
    public_id = secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:32]
    rid = db.exec(
        """
        INSERT INTO dynamic_key_pool(
            public_id,key_hash,post_key_enc,xor_key_enc,source_type,source_sha256,
            source_name,first_user_id,verified,success_count,use_count,enabled
        ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,0,1)
        """,
        (
            public_id, kh, _encrypt_hex(post), _encrypt_hex(xor),
            str(source_type or "unknown")[:32],
            str(source_sha256 or "")[:64] or None,
            str(source_name or "")[:255] or None,
            int(user_id) if user_id is not None else None,
            1 if verified else 0,
        ),
    )
    return {"id": int(rid), "public_id": public_id, "created": True}


def _merge_same_key_schemes(target_id: int, other_ids: Iterable[int]) -> None:
    target_id = int(target_id)
    for raw_id in other_ids:
        other_id = int(raw_id)
        if other_id <= 0 or other_id == target_id:
            continue
        try:
            # The feature uniqueness key does not include dynamic_key_id, so an
            # in-place owner change preserves every ABI fingerprint without a
            # delete/reinsert window.
            db.exec(
                "UPDATE dynamic_key_features SET dynamic_key_id=%s,updated_at=NOW() WHERE dynamic_key_id=%s",
                (target_id, other_id),
            )
            db.exec("UPDATE dynamic_key_pool SET enabled=0,updated_at=NOW() WHERE id=%s", (other_id,))
        except Exception:
            pass


def attach_features(
    dynamic_key_id: int,
    features,
    *,
    source_type: str = "unknown",
    normalizer_version: int = _FEATURE_VERSION,
    expected_key_hash: str = "",
    authoritative: bool = False,
) -> dict:
    ensure_schema()
    rid = int(dynamic_key_id or 0)
    if rid <= 0:
        raise ValueError("无效动态密钥方案")
    row = db.one("SELECT id,key_hash FROM dynamic_key_pool WHERE id=%s", (rid,))
    if not row:
        raise ValueError("动态密钥方案不存在")
    if expected_key_hash and _row_key_hash(row) != str(expected_key_hash).lower():
        raise ValueError("动态密钥方案与提取密钥不一致")
    clean = normalize_feature_map(features, version=normalizer_version)
    added, existing, conflicts, skipped, replaced = [], [], [], [], []
    for abi, sha in clean.items():
        # One scheme keeps one fingerprint per ABI.  Matching another ABI is what
        # allows the new architecture to be supplemented into this scheme.
        current = db.one(
            "SELECT id,feature_sha256 FROM dynamic_key_features "
            "WHERE dynamic_key_id=%s AND abi=%s AND normalizer_version=%s LIMIT 1",
            (rid, abi, int(normalizer_version)),
        )
        if current:
            if str(current.get("feature_sha256") or "").lower() == sha:
                existing.append(abi)
            else:
                skipped.append({"abi": abi, "feature_sha256": sha, "reason": "scheme-already-has-abi"})
            continue

        owner = db.one(
            "SELECT f.id,f.dynamic_key_id,p.key_hash FROM dynamic_key_features f "
            "JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id "
            "WHERE f.abi=%s AND f.feature_sha256=%s AND f.normalizer_version=%s LIMIT 1",
            (abi, sha, int(normalizer_version)),
        )
        if owner:
            owner_id = int(owner.get("dynamic_key_id") or 0)
            if owner_id == rid:
                existing.append(abi)
            elif _row_key_hash(owner) == _row_key_hash(row):
                # The exact fingerprint and key are the same, so transfer this
                # missing ABI to the first matched scheme rather than creating a
                # duplicate client match.
                db.exec(
                    "UPDATE dynamic_key_features SET dynamic_key_id=%s,source_type=%s,updated_at=NOW() WHERE id=%s",
                    (rid, str(source_type or "unknown")[:32], int(owner.get("id") or 0)),
                )
                left = db.one("SELECT COUNT(*) AS c FROM dynamic_key_features WHERE dynamic_key_id=%s", (owner_id,)) or {}
                if int(left.get("c") or 0) <= 0:
                    db.exec("UPDATE dynamic_key_pool SET enabled=0,updated_at=NOW() WHERE id=%s", (owner_id,))
                added.append(abi)
            else:
                if authoritative:
                    # A key pair that has actually decrypted the outer container is
                    # stronger evidence than a standalone/static extraction.  Move
                    # the exact ABI fingerprint to the verified-success scheme and
                    # retire the stale owner when it no longer owns any fingerprints.
                    db.exec(
                        "UPDATE dynamic_key_features SET dynamic_key_id=%s,source_type=%s,updated_at=NOW() WHERE id=%s",
                        (rid, str(source_type or "verified_success")[:32], int(owner.get("id") or 0)),
                    )
                    left = db.one(
                        "SELECT COUNT(*) AS c FROM dynamic_key_features WHERE dynamic_key_id=%s",
                        (owner_id,),
                    ) or {}
                    if int(left.get("c") or 0) <= 0:
                        db.exec(
                            "UPDATE dynamic_key_pool SET enabled=0,updated_at=NOW() WHERE id=%s",
                            (owner_id,),
                        )
                    replaced.append({
                        "abi": abi,
                        "feature_sha256": sha,
                        "old_owner_id": owner_id,
                    })
                    added.append(abi)
                else:
                    conflicts.append({"abi": abi, "feature_sha256": sha, "owner_id": owner_id})
            continue
        db.exec(
            "INSERT INTO dynamic_key_features(dynamic_key_id,abi,feature_sha256,normalizer_version,source_type) "
            "VALUES(%s,%s,%s,%s,%s)",
            (rid, abi, sha, int(normalizer_version), str(source_type or "unknown")[:32]),
        )
        added.append(abi)
    return {
        "added": added,
        "existing": existing,
        "conflicts": conflicts,
        "skipped": skipped,
        "replaced": replaced,
    }


def admin_replace_features(
    dynamic_key_id: int,
    features,
    *,
    normalizer_version: int = _FEATURE_VERSION,
    source_type: str = "admin",
) -> dict:
    """Replace the editable ABI fingerprint set for one scheme.

    Empty input removes all fingerprints from the scheme.  A fingerprint owned by
    another scheme may be moved only when both schemes use the same key pair;
    fingerprints bound to a different key are rejected instead of overwritten.
    """
    ensure_schema()
    rid = int(dynamic_key_id or 0)
    if rid <= 0:
        raise ValueError("无效动态密钥方案")
    target = db.one("SELECT id,key_hash FROM dynamic_key_pool WHERE id=%s", (rid,))
    if not target:
        raise ValueError("动态密钥方案不存在")
    clean = normalize_feature_map(features, version=normalizer_version)
    target_hash = _row_key_hash(target)
    same_key_owners: set[int] = set()
    for abi, sha in clean.items():
        owner = db.one(
            "SELECT f.dynamic_key_id,p.key_hash FROM dynamic_key_features f "
            "JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id "
            "WHERE f.abi=%s AND f.feature_sha256=%s AND f.normalizer_version=%s LIMIT 1",
            (abi, sha, int(normalizer_version)),
        )
        if not owner:
            continue
        owner_id = int(owner.get("dynamic_key_id") or 0)
        if owner_id == rid:
            continue
        if _row_key_hash(owner) != target_hash:
            raise ValueError(f"{abi} 指纹已属于另一套不同密钥方案 #{owner_id}")
        same_key_owners.add(owner_id)

    # Remove the old per-ABI rows first so an administrator can replace an ABI's
    # fingerprint rather than being blocked by scheme-already-has-abi.
    db.exec(
        "DELETE FROM dynamic_key_features WHERE dynamic_key_id=%s AND normalizer_version=%s",
        (rid, int(normalizer_version)),
    )
    result = attach_features(
        rid,
        clean,
        source_type=source_type,
        normalizer_version=normalizer_version,
        expected_key_hash=target_hash,
    ) if clean else {"added": [], "existing": [], "conflicts": [], "skipped": []}
    if result.get("conflicts"):
        raise ValueError("存在与其他密钥方案冲突的指纹")
    for owner_id in same_key_owners:
        left = db.one("SELECT COUNT(*) AS c FROM dynamic_key_features WHERE dynamic_key_id=%s", (owner_id,)) or {}
        if int(left.get("c") or 0) <= 0:
            db.exec("UPDATE dynamic_key_pool SET enabled=0,updated_at=NOW() WHERE id=%s", (owner_id,))
    result["features"] = list_features(rid)
    result["feature_count"] = len(result["features"])
    return result


def store_key(
    post_key,
    xor_key,
    *,
    source_type: str,
    source_sha256: str = "",
    source_name: str = "",
    user_id: Optional[int] = None,
    verified: bool = False,
    features=None,
    normalizer_version: int = _FEATURE_VERSION,
    authoritative: bool = False,
) -> dict:
    """Store a dynamic-key *scheme*.

    The key pair itself is not a uniqueness boundary.  Schemes merge only when
    the same key pair and at least one exact ABI fingerprint overlap.  The same
    key pair with an entirely different fingerprint set remains a separate row.
    """
    ensure_schema()
    post = normalize_hex(post_key, "post_key")
    xor = normalize_hex(xor_key, "xor_key")
    kh = _key_hash(post, xor)
    clean_features = normalize_feature_map(features, version=normalizer_version)

    matching_ids: list[int] = []
    if clean_features:
        for abi, sha in clean_features.items():
            row = db.one(
                "SELECT p.id,p.key_hash FROM dynamic_key_features f "
                "JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id "
                "WHERE f.abi=%s AND f.feature_sha256=%s AND f.normalizer_version=%s LIMIT 1",
                (abi, sha, int(normalizer_version)),
            )
            if row and _row_key_hash(row) == kh:
                rid = int(row.get("id") or 0)
                if rid > 0 and rid not in matching_ids:
                    matching_ids.append(rid)
    else:
        # Backward-compatible callers without fingerprints update the earliest
        # identical key instead of producing an unbounded number of empty schemes.
        row = db.one("SELECT id FROM dynamic_key_pool WHERE key_hash=%s ORDER BY id ASC LIMIT 1", (kh,))
        if row:
            matching_ids.append(int(row.get("id") or 0))

    created = False
    if matching_ids:
        rid = matching_ids[0]
        db.exec(
            """
            UPDATE dynamic_key_pool
            SET success_count=success_count+1,
                verified=GREATEST(verified,%s),
                enabled=1,
                source_type=CASE WHEN source_type='unknown' THEN %s ELSE source_type END,
                source_sha256=CASE WHEN COALESCE(source_sha256,'')='' THEN %s ELSE source_sha256 END,
                source_name=CASE WHEN COALESCE(source_name,'')='' THEN %s ELSE source_name END,
                updated_at=NOW()
            WHERE id=%s
            """,
            (1 if verified else 0, str(source_type or "unknown")[:32], str(source_sha256 or "")[:64],
             str(source_name or "")[:255], rid),
        )
        row = db.one("SELECT id,public_id FROM dynamic_key_pool WHERE id=%s", (rid,)) or {}
        result = {"id": rid, "public_id": str(row.get("public_id") or ""), "created": False}
    else:
        result = _new_pool_row(
            post, xor, kh,
            source_type=source_type,
            source_sha256=source_sha256,
            source_name=source_name,
            user_id=user_id,
            verified=verified,
        )
        rid = int(result["id"])
        created = True

    feature_result = attach_features(
        rid, clean_features,
        source_type=source_type,
        normalizer_version=normalizer_version,
        expected_key_hash=kh,
        authoritative=bool(authoritative),
    ) if clean_features else {
        "added": [], "existing": [], "conflicts": [], "skipped": [], "replaced": []
    }
    result.update(feature_result)
    result["created"] = created
    result["feature_count"] = len(list_features(rid))
    if clean_features and result["feature_count"] <= 0 and feature_result.get("conflicts"):
        # A fingerprint already owned by a different key is an extraction/data
        # conflict.  Keep the row for audit but never expose it for auto match.
        db.exec("UPDATE dynamic_key_pool SET enabled=0,updated_at=NOW() WHERE id=%s", (rid,))
        result["enabled"] = False
    return result




# IAPT_VERIFIED_KEY_ENSURE_V2_BEGIN
def ensure_verified_key(
    post_key,
    xor_key,
    *,
    source_type: str,
    source_sha256: str = "",
    source_name: str = "",
    user_id: Optional[int] = None,
    features=None,
    normalizer_version: int = _FEATURE_VERSION,
) -> dict:
    """Idempotently make a verified key scheme visible in the pool.

    Re-running the success hook for the same task does not increase counters or
    create duplicates.  An exact ABI fingerprint match is used when available;
    callers without fingerprints fall back to the earliest identical key pair.
    """
    ensure_schema()
    post = normalize_hex(post_key, "post_key")
    xor = normalize_hex(xor_key, "xor_key")
    kh = _key_hash(post, xor)
    clean = normalize_feature_map(features, version=normalizer_version)

    found = None
    if clean:
        for abi, sha in clean.items():
            found = db.one(
                "SELECT p.id,p.public_id,p.key_hash FROM dynamic_key_features f "
                "JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id "
                "WHERE f.abi=%s AND f.feature_sha256=%s AND f.normalizer_version=%s "
                "AND p.key_hash=%s ORDER BY p.id ASC LIMIT 1",
                (abi, sha, int(normalizer_version), kh),
            )
            if found:
                break
    else:
        found = db.one(
            "SELECT id,public_id,key_hash FROM dynamic_key_pool "
            "WHERE key_hash=%s ORDER BY id ASC LIMIT 1",
            (kh,),
        )

    # A previous success hook may have stored the verified pair before client or
    # server fingerprints were available.  Enrich that empty scheme rather than
    # creating a second row for the same task when fingerprints arrive later.
    if not found and clean:
        found = db.one(
            "SELECT p.id,p.public_id,p.key_hash FROM dynamic_key_pool p "
            "LEFT JOIN dynamic_key_features f ON f.dynamic_key_id=p.id "
            "WHERE p.key_hash=%s GROUP BY p.id,p.public_id,p.key_hash "
            "HAVING COUNT(f.id)=0 ORDER BY p.id ASC LIMIT 1",
            (kh,),
        )

    if found:
        rid = int(found.get("id") or 0)
        db.exec(
            "UPDATE dynamic_key_pool SET verified=1,enabled=1,"
            "source_type=CASE WHEN source_type='unknown' THEN %s ELSE source_type END,"
            "source_sha256=CASE WHEN COALESCE(source_sha256,'')='' THEN %s ELSE source_sha256 END,"
            "source_name=CASE WHEN COALESCE(source_name,'')='' THEN %s ELSE source_name END,"
            "updated_at=NOW() WHERE id=%s",
            (
                str(source_type or "verified_success")[:32],
                str(source_sha256 or "")[:64],
                str(source_name or "")[:255],
                rid,
            ),
        )
        feature_result = attach_features(
            rid,
            clean,
            source_type=source_type,
            normalizer_version=normalizer_version,
            expected_key_hash=kh,
            authoritative=True,
        ) if clean else {
            "added": [], "existing": [], "conflicts": [],
            "skipped": [], "replaced": [],
        }
        row = db.one(
            "SELECT id,public_id,enabled,verified FROM dynamic_key_pool WHERE id=%s",
            (rid,),
        ) or {}
        result = {
            "id": rid,
            "public_id": str(row.get("public_id") or found.get("public_id") or ""),
            "created": False,
            "already_present": True,
        }
        result.update(feature_result)
    else:
        result = store_key(
            post,
            xor,
            source_type=source_type,
            source_sha256=source_sha256,
            source_name=source_name,
            user_id=user_id,
            verified=True,
            features=clean,
            normalizer_version=normalizer_version,
            authoritative=True,
        )
        rid = int(result.get("id") or 0)
        # A verified successful decrypt must never remain hidden merely because
        # optional feature metadata was absent or conflicted.
        db.exec(
            "UPDATE dynamic_key_pool SET verified=1,enabled=1,updated_at=NOW() WHERE id=%s",
            (rid,),
        )
        result["already_present"] = False

    row = db.one(
        "SELECT id,public_id,enabled,verified FROM dynamic_key_pool WHERE id=%s",
        (int(result.get("id") or 0),),
    ) or {}
    if not row or int(row.get("enabled") or 0) != 1 or int(row.get("verified") or 0) != 1:
        raise RuntimeError("动态密钥写入后不可见（enabled/verified 校验失败）")
    result["public_id"] = str(row.get("public_id") or result.get("public_id") or "")
    result["enabled"] = True
    result["verified"] = True
    result["feature_count"] = len(list_features(int(row.get("id") or 0)))
    return result


def visible_verified_count() -> int:
    ensure_schema()
    row = db.one(
        "SELECT COUNT(*) AS c FROM dynamic_key_pool WHERE enabled=1 AND verified=1"
    ) or {}
    return int(row.get("c") or 0)
# IAPT_VERIFIED_KEY_ENSURE_V2_END

def list_public() -> list[dict]:
    ensure_schema()
    rows = db.all(
        "SELECT id,public_id,verified,success_count,use_count,created_at "
        "FROM dynamic_key_pool WHERE enabled=1 AND verified=1 ORDER BY id ASC"
    ) or []
    out = []
    for index, row in enumerate(rows, 1):
        rid = int(row.get("id") or 0)
        features = list_features(rid)
        # Schemes without a fingerprint cannot be selected by the lightweight
        # client matcher.  They remain available to pool enumeration/admin tools.
        out.append(
            {
                "ref": str(row.get("public_id") or ""),
                "label": f"动态密钥{index}",
                "verified": bool(row.get("verified")),
                "features": features,
                "feature_count": len(features),
                "normalizer_version": _FEATURE_VERSION,
            }
        )
    return out


def _decode_row(row: dict) -> dict:
    return {
        "id": int(row["id"]),
        "ref": str(row["public_id"]),
        "post_key": _decrypt_hex(row["post_key_enc"]),
        "xor_key": _decrypt_hex(row["xor_key_enc"]),
        "verified": bool(row.get("verified")),
    }


def resolve_ref(public_id: str) -> Optional[dict]:
    ensure_schema()
    ref = str(public_id or "").strip()
    if not ref:
        return None
    row = db.one("SELECT * FROM dynamic_key_pool WHERE public_id=%s AND enabled=1 AND verified=1", (ref,))
    return _decode_row(row) if row else None


def list_decrypted() -> list[dict]:
    ensure_schema()
    rows = db.all("SELECT * FROM dynamic_key_pool WHERE enabled=1 AND verified=1 ORDER BY id ASC") or []
    return [_decode_row(row) for row in rows]


def mark_used(public_id: str) -> None:
    ref = str(public_id or "").strip()
    if ref:
        db.exec("UPDATE dynamic_key_pool SET use_count=use_count+1,last_used_at=NOW() WHERE public_id=%s", (ref,))


def _elf_arch_label(data: bytes, entry_name: str = "") -> str:
    path = str(entry_name or "").replace("\\", "/")
    parts = [x for x in path.split("/") if x]
    known = {"arm64-v8a", "armeabi-v7a", "armeabi", "x86", "x86_64"}
    for part in reversed(parts[:-1]):
        if part.lower() in known:
            return part.lower()
    if len(data) >= 20 and data[:4] == b"\x7fELF":
        machine = int.from_bytes(data[18:20], "little", signed=False)
        return {3: "x86", 40: "armeabi-v7a", 62: "x86_64", 183: "arm64-v8a"}.get(machine, f"elf-{machine}")
    return "unknown"


def extract_all_so_from_bytes(data: bytes, filename: str = "") -> list[dict]:
    """Return every libygsiyu.so from an APK/ZIP, or one direct ELF upload."""
    if not data:
        raise ValueError("上传文件为空")
    name = str(filename or "").replace("\\", "/")
    if data[:4] == b"\x7fELF" or name.lower().endswith(".so"):
        if data[:4] != b"\x7fELF":
            raise ValueError("上传的 SO 不是有效 ELF 文件")
        entry = Path(name or "libygsiyu.so").name
        return [{
            "entry_name": entry,
            "abi": _elf_arch_label(data, entry),
            "data": data,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }]

    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as zf:
            candidates = []
            for info in zf.infolist():
                if info.is_dir():
                    continue
                n = info.filename.replace("\\", "/")
                if n.rsplit("/", 1)[-1].lower() == "libygsiyu.so":
                    candidates.append((n, info))
            if not candidates:
                raise ValueError("APK/ZIP 中没有找到 libygsiyu.so")
            if len(candidates) > 32:
                raise ValueError("libygsiyu.so 数量超过 32 个")

            abi_order = {"arm64-v8a": 0, "armeabi-v7a": 1, "armeabi": 2, "x86_64": 3, "x86": 4}
            candidates.sort(key=lambda x: (abi_order.get(_elf_arch_label(b"", x[0]), 99), x[0].lower()))
            out = []
            total = 0
            for n, info in candidates:
                size = int(info.file_size or 0)
                if size <= 0:
                    continue
                if size > 128 * 1024 * 1024:
                    raise ValueError(f"{n} 超过 128MB")
                total += size
                if total > 512 * 1024 * 1024:
                    raise ValueError("全部 libygsiyu.so 总大小超过 512MB")
                so_data = zf.read(info)
                if so_data[:4] != b"\x7fELF":
                    raise ValueError(f"{n} 不是有效 ELF 文件")
                out.append({
                    "entry_name": n,
                    "abi": _elf_arch_label(so_data, n),
                    "data": so_data,
                    "size": len(so_data),
                    "sha256": hashlib.sha256(so_data).hexdigest(),
                })
            if not out:
                raise ValueError("没有取得有效的 libygsiyu.so")
            return out
    except zipfile.BadZipFile:
        raise ValueError("请选择 APK、ZIP、APKS 或 libygsiyu.so")


def inspect_dynamic_key_upload(data: bytes, filename: str = "") -> dict:
    rows = extract_all_so_from_bytes(data, filename)
    return {
        "source_kind": "so" if data[:4] == b"\x7fELF" else "archive",
        "library_count": len(rows),
        "library_entries": [str(x.get("entry_name") or "") for x in rows],
        "library_abis": [str(x.get("abi") or "unknown") for x in rows],
        "total_so_bytes": sum(int(x.get("size") or 0) for x in rows),
    }


def extract_so_from_bytes(data: bytes, filename: str = "") -> tuple[bytes, str]:
    """Backward-compatible single-library helper; V40 tasks use all libraries."""
    rows = extract_all_so_from_bytes(data, filename)
    first = rows[0]
    return bytes(first["data"]), str(first["entry_name"])

def extract_primary_key(so_data: bytes) -> tuple[str, str, dict]:
    """Extract one ranked key pair from one ABI library.

    The native analyser can produce compatibility/truncation alternatives.  They
    are useful internally during decryption, but are not separate keys and must
    not be dumped into the user-facing key.txt.  This function therefore returns
    only the highest-ranked pair while retaining compact diagnostic counts.
    """
    # Import lazily: the decrypter is large and should not slow normal API startup.
    from .tools import iapp_auto_decrypt as tool

    old = bool(getattr(tool, "IAPT_NO_DYNAMIC_KEY", False))
    try:
        setattr(tool, "IAPT_NO_DYNAMIC_KEY", False)
        posts, xors = tool.auto_extract_key_candidates_from_so(so_data)
        try:
            primary_posts, primary_xors = tool._primary_so_key_candidates(posts, xors)
        except Exception:
            primary_posts, primary_xors = posts[:1], xors[:1]
        primary_posts = list(primary_posts or posts[:1])
        primary_xors = list(primary_xors or xors[:1])
        if not primary_posts or not primary_xors:
            raise ValueError("没有提取到动态 Key")

        selected_post = bytes(primary_posts[0])
        selected_xor = bytes(primary_xors[0])
        post_values = list(dict.fromkeys(bytes(x).hex() for x in posts if x))
        xor_values = list(dict.fromkeys(bytes(x).hex() for x in xors if x))
        post = selected_post.hex()
        xor = selected_xor.hex()
        arch = "unknown"
        try:
            arch = _elf_arch_label(so_data)
        except Exception:
            pass
        return post, xor, {
            "extractor_build": "multiabi-symbol-v2",
            "post_candidates": len(post_values),
            "xor_candidates": len(xor_values),
            # Keep compatibility with callers, but expose only the selected values.
            # Raw alternatives are deliberately not written to task output.
            "post_candidate_values": [post],
            "xor_candidate_values": [xor],
            "post_alternative_count": max(0, len(post_values) - 1),
            "xor_alternative_count": max(0, len(xor_values) - 1),
            "ambiguous": False,
            "abi": arch,
        }
    finally:
        setattr(tool, "IAPT_NO_DYNAMIC_KEY", old)


def key_text(post_key: str, xor_key: str) -> bytes:
    post = normalize_hex(post_key, "post_key")
    xor = normalize_hex(xor_key, "xor_key")
    return (f"post_key: {post}\nxor_key: {xor}\n").encode("utf-8")



def key_text_multi(results: Iterable[dict]) -> bytes:
    """Build a concise multi-ABI key.txt.

    One block is always retained per library/ABI.  Identical pairs are reported
    as such rather than collapsing ABI entries, while lower-ranked byte-window
    candidates are hidden because they are analyser diagnostics, not extra keys.
    """
    rows = list(results or [])
    if not rows:
        raise ValueError("没有可写入的动态 Key 结果")

    success_rows = [x for x in rows if not x.get("error")]
    unique_pairs = []
    seen_pairs = set()
    for row in success_rows:
        post = normalize_hex(row.get("post_key"), "post_key")
        xor = normalize_hex(row.get("xor_key"), "xor_key")
        pair = (post, xor)
        if pair not in seen_pairs:
            seen_pairs.add(pair)
            unique_pairs.append(pair)

    summary = "\n".join([
        "extractor_build: multiabi-symbol-v2",
        f"libraries_total: {len(rows)}",
        f"libraries_success: {len(success_rows)}",
        f"libraries_failed: {len(rows) - len(success_rows)}",
        f"unique_key_pairs: {len(unique_pairs)}",
    ])
    blocks = [summary]

    for row in rows:
        entry = str(row.get("entry_name") or "libygsiyu.so")
        abi = str(row.get("abi") or "unknown")
        title = f"[{abi}] {entry}"
        if row.get("error"):
            blocks.append(title + "\nstatus: failed\nerror: " + str(row.get("error"))[:1000])
            continue
        post = normalize_hex(row.get("post_key"), "post_key")
        xor = normalize_hex(row.get("xor_key"), "xor_key")
        blocks.append(
            title
            + f"\npost_key: {post}"
            + f"\nxor_key: {xor}"
            + "\nstatus: extracted-static"
        )
    return ("\n\n".join(blocks).rstrip() + "\n").encode("utf-8")


def write_pool_file(path: Path, entries: Iterable[dict]) -> int:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    rows = []
    for row in entries:
        rows.append(
            {
                "ref": str(row.get("ref") or row.get("public_id") or ""),
                "post_key": normalize_hex(row.get("post_key"), "post_key"),
                "xor_key": normalize_hex(row.get("xor_key"), "xor_key"),
            }
        )
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps({"version": 1, "keys": rows}, ensure_ascii=False), encoding="utf-8")
    try:
        tmp.chmod(0o600)
    except Exception:
        pass
    tmp.replace(path)
    try:
        path.chmod(0o600)
    except Exception:
        pass
    return len(rows)

# IAPT_ADMIN_DYNAMIC_KEY_POOL_MANAGE_BEGIN
def _admin_clean_sha256(value: str) -> str:
    text = str(value or "").strip().lower()
    if not text:
        return ""
    if len(text) != 64 or not _HEX_RE.fullmatch(text):
        raise ValueError("source_sha256 必须是 64 位十六进制，或留空")
    return text


def admin_list(keyword: str = "", limit: int = 200, offset: int = 0) -> list[dict]:
    """管理员列表：返回完整密钥。调用方必须先完成后台权限校验。"""
    ensure_schema()
    kw = str(keyword or "").strip()
    limit = max(1, min(int(limit or 200), 1000))
    offset = max(0, int(offset or 0))
    where = ""
    params: list = []
    if kw:
        like = "%" + kw + "%"
        where = ("WHERE (public_id LIKE %s OR source_type LIKE %s OR source_name LIKE %s "
                 "OR source_sha256 LIKE %s OR CAST(id AS CHAR)=%s "
                 "OR EXISTS(SELECT 1 FROM dynamic_key_features f "
                 "WHERE f.dynamic_key_id=dynamic_key_pool.id AND f.feature_sha256 LIKE %s))")
        params.extend([like, like, like, like, kw, like])
    rows = db.all(
        f"""
        SELECT id,public_id,key_hash,post_key_enc,xor_key_enc,source_type,source_sha256,
               source_name,first_user_id,verified,success_count,use_count,enabled,
               created_at,updated_at,last_used_at
        FROM dynamic_key_pool
        {where}
        ORDER BY id DESC
        LIMIT %s OFFSET %s
        """,
        tuple(params + [limit, offset]),
    ) or []
    out: list[dict] = []
    for row in rows:
        item = dict(row)
        item["id"] = int(item.get("id") or 0)
        item["verified"] = bool(item.get("verified"))
        item["enabled"] = bool(item.get("enabled"))
        item["success_count"] = int(item.get("success_count") or 0)
        item["use_count"] = int(item.get("use_count") or 0)
        try:
            item["post_key"] = _decrypt_hex(item.pop("post_key_enc"))
            item["xor_key"] = _decrypt_hex(item.pop("xor_key_enc"))
            item["decrypt_error"] = ""
        except Exception as exc:
            item.pop("post_key_enc", None)
            item.pop("xor_key_enc", None)
            item["post_key"] = ""
            item["xor_key"] = ""
            item["decrypt_error"] = str(exc)[:300]
        try:
            item["features"] = list_features(item["id"])
            item["feature_count"] = len(item["features"])
        except Exception:
            item["features"] = {}
            item["feature_count"] = 0
        out.append(item)
    return out


def admin_save(
    *,
    row_id: int = 0,
    post_key: str,
    xor_key: str,
    source_type: str = "admin",
    source_sha256: str = "",
    source_name: str = "",
    first_user_id: Optional[int] = None,
    verified: bool = True,
    enabled: bool = True,
    features=None,
    normalizer_version: int = _FEATURE_VERSION,
) -> dict:
    """管理员新增或编辑密钥；密钥始终加密保存。"""
    ensure_schema()
    rid = max(0, int(row_id or 0))
    post = normalize_hex(post_key, "post_key")
    xor = normalize_hex(xor_key, "xor_key")
    kh = _key_hash(post, xor)
    st = str(source_type or "admin").strip()[:32] or "admin"
    sha = _admin_clean_sha256(source_sha256)
    name = str(source_name or "").strip()[:255]
    uid = int(first_user_id) if first_user_id not in (None, "") else None


    if rid:
        if not db.one("SELECT id FROM dynamic_key_pool WHERE id=%s", (rid,)):
            raise ValueError("密钥不存在")
        db.exec(
            """
            UPDATE dynamic_key_pool
            SET key_hash=%s,post_key_enc=%s,xor_key_enc=%s,source_type=%s,
                source_sha256=%s,source_name=%s,first_user_id=%s,
                verified=%s,enabled=%s,updated_at=NOW()
            WHERE id=%s
            """,
            (
                kh, _encrypt_hex(post), _encrypt_hex(xor), st, sha or None,
                name or None, uid, 1 if verified else 0, 1 if enabled else 0, rid,
            ),
        )
    else:
        public_id = secrets.token_urlsafe(18).replace("-", "").replace("_", "")[:32]
        rid = int(db.exec(
            """
            INSERT INTO dynamic_key_pool(
                public_id,key_hash,post_key_enc,xor_key_enc,source_type,source_sha256,
                source_name,first_user_id,verified,success_count,use_count,enabled
            ) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,1,0,%s)
            """,
            (
                public_id, kh, _encrypt_hex(post), _encrypt_hex(xor), st, sha or None,
                name or None, uid, 1 if verified else 0, 1 if enabled else 0,
            ),
        ))
    # Old clients omit the field and keep existing fingerprints.  The updated
    # management UI always sends a map, including an empty map when the admin
    # intentionally wants to clear all architecture fingerprints.
    if features is not None:
        try:
            admin_replace_features(
                rid,
                features,
                normalizer_version=max(1, min(int(normalizer_version or _FEATURE_VERSION), 100)),
                source_type="admin",
            )
        except Exception:
            if not row_id:
                try:
                    db.exec("DELETE FROM dynamic_key_features WHERE dynamic_key_id=%s", (rid,))
                    db.exec("DELETE FROM dynamic_key_pool WHERE id=%s", (rid,))
                except Exception:
                    pass
            raise
    rows = admin_list(keyword=str(rid), limit=10, offset=0)
    for row in rows:
        if int(row.get("id") or 0) == rid:
            return row
    raise ValueError("保存后读取密钥失败")


# IAPT_ADMIN_KEY_ID_REINDEX_V27_BEGIN
_ADMIN_KEY_ID_REINDEX_LOCK = threading.RLock()


def _admin_dynamic_feature_table_exists() -> bool:
    row = db.one(
        """
        SELECT COUNT(*) AS c
        FROM information_schema.tables
        WHERE table_schema=DATABASE()
          AND table_name='dynamic_key_features'
        """,
    ) or {}
    return int(row.get("c") or 0) > 0


def _admin_compact_dynamic_key_ids() -> dict:
    """把密钥池主表及指纹引用整理为从 1 开始的连续 ID。"""
    ensure_schema()
    with _ADMIN_KEY_ID_REINDEX_LOCK:
        has_features = _admin_dynamic_feature_table_exists()

        # 旧版删除只删主表，可能遗留没有归属的指纹；先清掉，避免迁移时冲突。
        orphan_features = 0
        if has_features:
            before = db.one(
                """
                SELECT COUNT(*) AS c
                FROM dynamic_key_features f
                LEFT JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id
                WHERE p.id IS NULL
                """
            ) or {}
            orphan_features = int(before.get("c") or 0)
            if orphan_features:
                db.exec(
                    """
                    DELETE f
                    FROM dynamic_key_features f
                    LEFT JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id
                    WHERE p.id IS NULL
                    """
                )

        rows = db.all(
            "SELECT id FROM dynamic_key_pool ORDER BY id ASC"
        ) or []

        moved = []
        next_id = 1
        for raw in rows:
            old_id = int(raw.get("id") or 0)
            if old_id <= 0:
                continue

            if old_id != next_id:
                # 按旧 ID 升序移动，目标 ID 此时一定为空，不会撞主键。
                if has_features:
                    db.exec(
                        """
                        UPDATE dynamic_key_features
                        SET dynamic_key_id=%s,updated_at=NOW()
                        WHERE dynamic_key_id=%s
                        """,
                        (next_id, old_id),
                    )
                db.exec(
                    """
                    UPDATE dynamic_key_pool
                    SET id=%s,updated_at=NOW()
                    WHERE id=%s
                    """,
                    (next_id, old_id),
                )
                moved.append({"old_id": old_id, "new_id": next_id})

            next_id += 1

        # 空表时设为 1；非空表时设为 MAX(id)+1。
        next_auto_id = max(1, next_id)
        db.exec(
            "ALTER TABLE dynamic_key_pool AUTO_INCREMENT = %d" % next_auto_id
        )

        return {
            "count": len(rows),
            "moved_count": len(moved),
            "moved": moved,
            "orphan_features_deleted": orphan_features,
            "next_auto_id": next_auto_id,
        }


def admin_delete(row_id: int) -> bool:
    ensure_schema()
    rid = int(row_id or 0)
    if rid <= 0:
        raise ValueError("无效密钥ID")

    with _ADMIN_KEY_ID_REINDEX_LOCK:
        row = db.one(
            "SELECT id FROM dynamic_key_pool WHERE id=%s",
            (rid,),
        )
        if not row:
            return False

        # 先删关联指纹，再删主记录，避免留下错误的 dynamic_key_id。
        if _admin_dynamic_feature_table_exists():
            db.exec(
                "DELETE FROM dynamic_key_features WHERE dynamic_key_id=%s",
                (rid,),
            )

        db.exec(
            "DELETE FROM dynamic_key_pool WHERE id=%s",
            (rid,),
        )

        # 删除后立即把所有剩余 ID 压紧，并重置 AUTO_INCREMENT。
        _admin_compact_dynamic_key_ids()
        return True
# IAPT_ADMIN_KEY_ID_REINDEX_V27_END
# IAPT_ADMIN_DYNAMIC_KEY_POOL_MANAGE_END

# IAPT_DYNAMIC_KEY_DATAFLOW_V274_POOL_BEGIN
# Standalone SO extraction must be authoritative: unsupported layouts fail instead
# of silently putting a ranked 16-byte candidate into the key pool.
from .tools.iapt_static_key_v41 import extract_pair_hex as _iapt_v274_extract_pair_hex
_iapt_v274_original_key_text_multi = key_text_multi

def extract_primary_key(so_data: bytes):
    # Use the validated V275 bridge when available.  The raw v3 extractor is
    # intentionally not authoritative because its high-entropy fallback may
    # select machine-code/literal-pool bytes on otherwise valid multi-ABI SOs.
    try:
        from .tools import iapp_auto_decrypt as tool
        fn = getattr(tool, "_iapt_v275_validated_extract_pair_bytes", None)
        if callable(fn):
            post, xor, meta = fn(so_data)
            return bytes(post).hex(), bytes(xor).hex(), dict(meta or {})
    except Exception:
        # Preserve direct-tool compatibility; the strict parser below will still
        # raise a useful error when neither path supports the layout.
        pass
    return _iapt_v274_extract_pair_hex(so_data)

def key_text_multi(results):
    raw = _iapt_v274_original_key_text_multi(results)
    if not any(str((row or {}).get("extractor_build") or "") == "multiabi-dataflow-v3" for row in (results or [])):
        return raw
    if isinstance(raw, bytes):
        raw = raw.replace(b"multiabi-symbol-v2", b"multiabi-dataflow-v3")
        raw = raw.replace(b"extracted-static", b"extracted-dataflow")
        return raw
    text = str(raw).replace("multiabi-symbol-v2", "multiabi-dataflow-v3")
    return text.replace("extracted-static", "extracted-dataflow")
# IAPT_DYNAMIC_KEY_DATAFLOW_V274_POOL_END


# IAPT_V109_DYNAMIC_POOL_FAST_BEGIN
# V109: make public/admin dynamic key pool listing one-query-per-page instead of N+1 feature lookups.
try:
    import os as _iapt_v109_os

    def _iapt_v109_int(value, default=200, lo=0, hi=500):
        try:
            n = int(value)
        except Exception:
            n = int(default)
        if n < lo:
            n = lo
        if n > hi:
            n = hi
        return n

    def _iapt_v109_feature_rows_for_ids(ids):
        ids = [int(x) for x in (ids or []) if int(x or 0) > 0]
        out = {rid: {} for rid in ids}
        if not ids:
            return out
        placeholders = ','.join(['%s'] * len(ids))
        params = tuple(ids + [int(_FEATURE_VERSION)])
        try:
            rows = db.all(
                'SELECT dynamic_key_id,abi,feature_sha256 FROM dynamic_key_features '
                'WHERE dynamic_key_id IN (' + placeholders + ') AND normalizer_version=%s ORDER BY id ASC',
                params,
            ) or []
        except Exception:
            rows = []
        for row in rows:
            try:
                rid = int(row.get('dynamic_key_id') or 0)
                abi = normalize_abi(row.get('abi'))
                sha = str(row.get('feature_sha256') or '').lower()
                if rid in out and abi not in out[rid] and _FEATURE_HEX_RE.fullmatch(sha):
                    out[rid][abi] = sha
            except Exception:
                pass
        return out

    def list_public(limit=None, offset=0):
        ensure_schema()
        if limit is None:
            limit = _iapt_v109_os.environ.get('IAPT_DYNAMIC_POOL_PUBLIC_LIMIT', '200')
        limit = _iapt_v109_int(limit, 200, 1, 500)
        offset = _iapt_v109_int(offset, 0, 0, 100000000)
        rows = db.all(
            'SELECT id,public_id,verified,success_count,use_count,created_at '
            'FROM dynamic_key_pool WHERE enabled=1 AND verified=1 ORDER BY id ASC LIMIT %s OFFSET %s',
            (limit, offset),
        ) or []
        ids = [int(r.get('id') or 0) for r in rows]
        features_by_id = _iapt_v109_feature_rows_for_ids(ids)
        out = []
        for index, row in enumerate(rows, offset + 1):
            rid = int(row.get('id') or 0)
            features = features_by_id.get(rid, {})
            out.append({
                'ref': str(row.get('public_id') or ''),
                'label': '动态密钥%d' % int(index),
                'verified': bool(row.get('verified')),
                'features': features,
                'feature_count': len(features),
                'normalizer_version': _FEATURE_VERSION,
            })
        return out

    def admin_list(keyword: str = '', limit: int = 200, offset: int = 0):
        ensure_schema()
        kw = str(keyword or '').strip()
        limit = _iapt_v109_int(limit, 200, 1, 200)
        offset = _iapt_v109_int(offset, 0, 0, 100000000)
        where = ''
        params = []
        if kw:
            like = '%' + kw + '%'
            where = (
                'WHERE (public_id LIKE %s OR source_type LIKE %s OR source_name LIKE %s '
                'OR source_sha256 LIKE %s OR CAST(id AS CHAR)=%s '
                'OR EXISTS(SELECT 1 FROM dynamic_key_features f '
                'WHERE f.dynamic_key_id=dynamic_key_pool.id AND f.feature_sha256 LIKE %s))'
            )
            params.extend([like, like, like, like, kw, like])
        sql = (
            'SELECT id,public_id,key_hash,post_key_enc,xor_key_enc,source_type,source_sha256,'
            'source_name,first_user_id,verified,success_count,use_count,enabled,'
            'created_at,updated_at,last_used_at FROM dynamic_key_pool '
            + where +
            ' ORDER BY id DESC LIMIT %s OFFSET %s'
        )
        rows = db.all(sql, tuple(params + [limit, offset])) or []
        ids = [int(r.get('id') or 0) for r in rows]
        features_by_id = _iapt_v109_feature_rows_for_ids(ids)
        out = []
        for row in rows:
            item = dict(row)
            item['id'] = int(item.get('id') or 0)
            item['verified'] = bool(item.get('verified'))
            item['enabled'] = bool(item.get('enabled'))
            item['success_count'] = int(item.get('success_count') or 0)
            item['use_count'] = int(item.get('use_count') or 0)
            try:
                item['post_key'] = _decrypt_hex(item.pop('post_key_enc'))
                item['xor_key'] = _decrypt_hex(item.pop('xor_key_enc'))
                item['decrypt_error'] = ''
            except Exception as exc:
                item.pop('post_key_enc', None)
                item.pop('xor_key_enc', None)
                item['post_key'] = ''
                item['xor_key'] = ''
                item['decrypt_error'] = str(exc)[:300]
            features = features_by_id.get(item['id'], {})
            item['features'] = features
            item['feature_count'] = len(features)
            out.append(item)
        return out

    DYNAMIC_KEY_POOL_V109 = {
        'fast_public_list': True,
        'public_default_limit': int(_iapt_v109_os.environ.get('IAPT_DYNAMIC_POOL_PUBLIC_LIMIT', '200') or 200),
        'n_plus_one_features': False,
        'admin_max_limit': 200,
    }
except Exception as _iapt_v109_dynamic_pool_error:
    try:
        DYNAMIC_KEY_POOL_V109 = {'fast_public_list': False, 'error': repr(_iapt_v109_dynamic_pool_error)}
    except Exception:
        pass
# IAPT_V109_DYNAMIC_POOL_FAST_END

# IAPT_V110_DYNAMIC_POOL_CACHE_BEGIN
# Fast, bounded public pool reads and exact server-side SO-feature matching.
try:
    import os as _iapt_v110_pool_os
    import time as _iapt_v110_pool_time
    import threading as _iapt_v110_pool_threading
    import zipfile as _iapt_v110_pool_zipfile

    _IAPT_V110_ORIG_ENSURE_SCHEMA = ensure_schema
    _IAPT_V110_SCHEMA_READY = False
    _IAPT_V110_SCHEMA_LOCK = _iapt_v110_pool_threading.Lock()
    _IAPT_V110_PUBLIC_CACHE = {"at": 0.0, "limit": 0, "items": []}
    _IAPT_V110_PUBLIC_CACHE_LOCK = _iapt_v110_pool_threading.Lock()

    def ensure_schema() -> None:
        global _IAPT_V110_SCHEMA_READY
        if _IAPT_V110_SCHEMA_READY:
            return
        with _IAPT_V110_SCHEMA_LOCK:
            if _IAPT_V110_SCHEMA_READY:
                return
            _IAPT_V110_ORIG_ENSURE_SCHEMA()
            _IAPT_V110_SCHEMA_READY = True

    def _iapt_v110_pool_int(value, default, lo, hi):
        try:
            number = int(value)
        except Exception:
            number = int(default)
        return max(int(lo), min(int(hi), number))

    def _iapt_v110_features_for_ids(ids):
        ids = [int(x) for x in (ids or []) if int(x or 0) > 0]
        output = {row_id: {} for row_id in ids}
        if not ids:
            return output
        marks = ",".join(["%s"] * len(ids))
        rows = db.all(
            "SELECT dynamic_key_id,abi,feature_sha256 FROM dynamic_key_features "
            "WHERE dynamic_key_id IN (" + marks + ") AND normalizer_version=%s ORDER BY id ASC",
            tuple(ids + [int(_FEATURE_VERSION)]),
        ) or []
        for row in rows:
            try:
                row_id = int(row.get("dynamic_key_id") or 0)
                abi = normalize_abi(row.get("abi"))
                feature = str(row.get("feature_sha256") or "").strip().lower()
                if row_id in output and abi not in output[row_id] and _FEATURE_HEX_RE.fullmatch(feature):
                    output[row_id][abi] = feature
            except Exception:
                pass
        return output

    def _iapt_v110_clear_public_cache():
        with _IAPT_V110_PUBLIC_CACHE_LOCK:
            _IAPT_V110_PUBLIC_CACHE["at"] = 0.0
            _IAPT_V110_PUBLIC_CACHE["limit"] = 0
            _IAPT_V110_PUBLIC_CACHE["items"] = []

    def list_public(limit=None, offset=0) -> list[dict]:
        ensure_schema()
        if limit is None:
            limit = _iapt_v110_pool_os.environ.get("IAPT_DYNAMIC_POOL_PUBLIC_LIMIT", "200")
        limit = _iapt_v110_pool_int(limit, 200, 1, 500)
        offset = _iapt_v110_pool_int(offset, 0, 0, 100000000)
        ttl = _iapt_v110_pool_int(
            _iapt_v110_pool_os.environ.get("IAPT_DYNAMIC_POOL_CACHE_SECONDS", "60"),
            60, 1, 600,
        )
        now = _iapt_v110_pool_time.monotonic()
        if offset == 0:
            with _IAPT_V110_PUBLIC_CACHE_LOCK:
                if (_IAPT_V110_PUBLIC_CACHE["items"]
                        and _IAPT_V110_PUBLIC_CACHE["limit"] == limit
                        and now - float(_IAPT_V110_PUBLIC_CACHE["at"] or 0.0) < ttl):
                    return [dict(item) for item in _IAPT_V110_PUBLIC_CACHE["items"]]
        rows = db.all(
            "SELECT id,public_id,verified,success_count,use_count,created_at "
            "FROM dynamic_key_pool WHERE enabled=1 AND verified=1 "
            "ORDER BY id ASC LIMIT %s OFFSET %s",
            (limit, offset),
        ) or []
        feature_map = _iapt_v110_features_for_ids([int(row.get("id") or 0) for row in rows])
        items = []
        for index, row in enumerate(rows, offset + 1):
            row_id = int(row.get("id") or 0)
            features = feature_map.get(row_id, {})
            items.append({
                "ref": str(row.get("public_id") or ""),
                "label": "动态密钥%d" % int(index),
                "verified": bool(row.get("verified")),
                "features": features,
                "feature_count": len(features),
                "normalizer_version": int(_FEATURE_VERSION),
            })
        if offset == 0:
            with _IAPT_V110_PUBLIC_CACHE_LOCK:
                _IAPT_V110_PUBLIC_CACHE["at"] = now
                _IAPT_V110_PUBLIC_CACHE["limit"] = limit
                _IAPT_V110_PUBLIC_CACHE["items"] = [dict(item) for item in items]
        return items

    def resolve_feature_ref(abi: str, feature_sha256: str):
        ensure_schema()
        abi = normalize_abi(abi)
        feature = str(feature_sha256 or "").strip().lower()
        if abi == "unknown" or not _FEATURE_HEX_RE.fullmatch(feature):
            return None
        row = db.one(
            "SELECT p.public_id FROM dynamic_key_features f "
            "JOIN dynamic_key_pool p ON p.id=f.dynamic_key_id "
            "WHERE f.abi=%s AND f.feature_sha256=%s AND f.normalizer_version=%s "
            "AND p.enabled=1 AND p.verified=1 ORDER BY p.id ASC LIMIT 1",
            (abi, feature, int(_FEATURE_VERSION)),
        )
        return str((row or {}).get("public_id") or "").strip() or None

    def resolve_apk_feature_ref(apk_path):
        path = Path(apk_path)
        if not path.is_file():
            return None
        priority = {"arm64-v8a": 0, "armeabi-v7a": 1, "armeabi": 2, "x86_64": 3, "x86": 4}
        candidates = []
        try:
            with _iapt_v110_pool_zipfile.ZipFile(path, "r") as archive:
                for info in archive.infolist():
                    name = info.filename.replace("\\", "/")
                    if info.is_dir() or not name.lower().endswith("/libygsiyu.so"):
                        continue
                    abi = normalize_abi(name)
                    if abi == "unknown" or info.file_size <= 0 or info.file_size > 64 * 1024 * 1024:
                        continue
                    data = archive.read(info)
                    candidates.append((priority.get(abi, 99), abi, so_feature_sha256(data), name))
        except Exception:
            return None
        for _rank, abi, feature, name in sorted(candidates):
            ref = resolve_feature_ref(abi, feature)
            if ref:
                return {"ref": ref, "abi": abi, "feature_sha256": feature, "entry": name}
        return None

    # Cache invalidation for operations that can change public visibility/features.
    for _iapt_v110_mutation_name in (
        "attach_features", "admin_replace_features", "store_key", "ensure_verified_key",
        "admin_save", "admin_delete",
    ):
        _iapt_v110_original = globals().get(_iapt_v110_mutation_name)
        if not callable(_iapt_v110_original):
            continue
        def _iapt_v110_make_mutation_wrapper(fn):
            def _wrapped(*args, **kwargs):
                result = fn(*args, **kwargs)
                _iapt_v110_clear_public_cache()
                return result
            _wrapped.__name__ = getattr(fn, "__name__", "wrapped")
            _wrapped.__doc__ = getattr(fn, "__doc__", None)
            return _wrapped
        globals()[_iapt_v110_mutation_name] = _iapt_v110_make_mutation_wrapper(_iapt_v110_original)

    DYNAMIC_KEY_POOL_V110 = {
        "schema_once": True,
        "public_cache_seconds": int(_iapt_v110_pool_os.environ.get("IAPT_DYNAMIC_POOL_CACHE_SECONDS", "60") or 60),
        "public_query": "one pool query plus one bulk feature query",
        "exact_feature_resolver": True,
    }
except Exception as _iapt_v110_pool_error:
    try:
        print("IAPT_V110_DYNAMIC_POOL_CACHE_INSTALL_FAILED", repr(_iapt_v110_pool_error))
    except Exception:
        pass
# IAPT_V110_DYNAMIC_POOL_CACHE_END

# IAPT_V201_EXACT_STANDALONE_POOL_BEGIN
_IAPT_V201_PREVIOUS_EXTRACT_PRIMARY_KEY = extract_primary_key
_IAPT_V201_PREVIOUS_KEY_TEXT_MULTI = key_text_multi


def extract_primary_key(so_data: bytes):
    from .tools.iapt_v10 import iapp_auto_decrypt as engine
    from .tools.iapt_v10 import iapt_dynamic_key_exact_v201 as exact
    result = exact.extract(engine, bytes(so_data or b''))
    selected = dict((result or {}).get('selected') or {})
    if str((result or {}).get('status') or '') != 'extracted' or not selected:
        raise ValueError(str((result or {}).get('diagnostic') or '未静态还原出唯一动态 Key'))
    post = normalize_hex(selected.get('post_key'), 'post_key')
    xor = normalize_hex(selected.get('xor_key'), 'xor_key')
    return post, xor, {
        'extractor_build': 'V201-server-effective-cstring-four-abi-static',
        'status': 'extracted-exact-static',
        'static_extracted': True,
        'arch': str((result or {}).get('arch') or 'unknown'),
        'abi': str((result or {}).get('arch') or 'unknown'),
        'post_key_bytes': len(bytes.fromhex(post)),
        'xor_key_bytes': len(bytes.fromhex(xor)),
        'post_candidates': 1,
        'xor_candidates': 1,
        'post_candidate_values': [post],
        'xor_candidate_values': [xor],
        'ambiguous': False,
        'source': str(selected.get('source') or 'effective-cstring-static-dataflow'),
    }


def key_text_multi(results):
    raw = _IAPT_V201_PREVIOUS_KEY_TEXT_MULTI(results)
    if isinstance(raw, bytes):
        raw = raw.replace(b'extractor_build: multiabi-symbol-v2', b'extractor_build: V201-server-effective-cstring-four-abi-static')
        raw = raw.replace(b'status: extracted-static', b'status: extracted-exact-static')
        return raw
    return str(raw).replace('extractor_build: multiabi-symbol-v2', 'extractor_build: V201-server-effective-cstring-four-abi-static').replace('status: extracted-static', 'status: extracted-exact-static')
# IAPT_V201_EXACT_STANDALONE_POOL_END
