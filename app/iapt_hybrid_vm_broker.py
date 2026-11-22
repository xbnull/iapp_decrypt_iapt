#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

try:
    from fastapi import APIRouter, HTTPException
    from pydantic import BaseModel
except Exception:
    APIRouter = None
    HTTPException = RuntimeError
    BaseModel = object

FORMAT = "iapt-hybrid-vm-enrollment-v1"
AAD_DB = "IAPTHVM4-DB|"


class BrokerError(RuntimeError):
    pass


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text, validate=True)


def default_db() -> Path:
    return Path(os.environ.get("IAPT_HVM_DB", "/www/wwwroot/iapt/data/iapt_hvm_keys.sqlite3"))


def master_key() -> bytes:
    raw = os.environ.get("IAPT_HVM_MASTER_KEY_B64", "")
    if not raw:
        raise BrokerError("缺少 IAPT_HVM_MASTER_KEY_B64")
    key = b64d(raw)
    if len(key) != 32:
        raise BrokerError("IAPT_HVM_MASTER_KEY_B64 必须解码为 32 字节")
    return key


def sign_key_path() -> Path:
    return Path(os.environ.get("IAPT_HVM_SIGN_PRIVATE_KEY", "/www/wwwroot/iapt/secrets/hvm/iapt_hvm_sign.pem"))


def transport_secrets() -> dict[str, str]:
    raw = os.environ.get("IAPT_HVM_TRANSPORT_SECRETS_JSON", "") or os.environ.get("APP_SECRETS_JSON", "")
    if not raw:
        legacy = os.environ.get("APP_SECRET", "")
        if legacy:
            return {os.environ.get("APP_SECRET_CURRENT_ID", "legacy"): legacy}
        raise BrokerError("缺少 IAPT_HVM_TRANSPORT_SECRETS_JSON/APP_SECRETS_JSON/APP_SECRET")
    obj = json.loads(raw)
    if not isinstance(obj, dict) or not obj:
        raise BrokerError("传输 keyring 格式错误")
    out = {str(k): str(v) for k, v in obj.items() if str(v)}
    if not out:
        raise BrokerError("传输 keyring 为空")
    return out


def connect(db_path: Path | None = None) -> sqlite3.Connection:
    path = db_path or default_db()
    path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(path, timeout=20)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS hvm_builds(
            build_id TEXT PRIMARY KEY,
            package_name TEXT NOT NULL,
            version_code INTEGER NOT NULL,
            cert_sha256 TEXT NOT NULL,
            binding_hash TEXT NOT NULL,
            hook_dex_name TEXT NOT NULL,
            encrypted_root_key BLOB NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS hvm_nonces(
            nonce TEXT PRIMARY KEY,
            created_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_hvm_nonces_created ON hvm_nonces(created_at);
        CREATE TABLE IF NOT EXISTS hvm_runtime_events(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            build_id TEXT NOT NULL,
            package_name TEXT NOT NULL,
            version_code INTEGER NOT NULL,
            cert_sha256 TEXT NOT NULL,
            binding_hash TEXT NOT NULL,
            assets_manifest_hash TEXT NOT NULL,
            stage TEXT NOT NULL,
            reason TEXT NOT NULL,
            process_name TEXT NOT NULL,
            pid INTEGER NOT NULL,
            event_ts INTEGER NOT NULL,
            received_at INTEGER NOT NULL,
            nonce TEXT NOT NULL UNIQUE
        );
        CREATE INDEX IF NOT EXISTS idx_hvm_runtime_events_build_time ON hvm_runtime_events(build_id,received_at DESC);
        """
    )
    cols = {str(r[1]) for r in con.execute("PRAGMA table_info(hvm_builds)")}
    if "runtime_assets_hash" not in cols:
        con.execute("ALTER TABLE hvm_builds ADD COLUMN runtime_assets_hash TEXT NOT NULL DEFAULT ''")
        con.commit()
    return con


def encrypt_root_key(build_id: str, root_key: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(key).encrypt(nonce, root_key, (AAD_DB + build_id).encode())


def decrypt_root_key(build_id: str, blob: bytes, key: bytes) -> bytes:
    if len(blob) < 28:
        raise BrokerError("数据库密钥包损坏")
    return AESGCM(key).decrypt(blob[:12], blob[12:], (AAD_DB + build_id).encode())


def register_enrollment(enrollment: Path, db_path: Path | None = None, key: bytes | None = None) -> dict[str, Any]:
    obj = json.loads(enrollment.read_text(encoding="utf-8"))
    if obj.get("format") != FORMAT:
        raise BrokerError("enrollment 格式错误")
    root = b64d(str(obj["bound_root_key_b64"]))
    if len(root) != 32:
        raise BrokerError("bound root key 必须是 32 字节")
    build_id = str(obj["build_id"])
    now = int(time.time())
    row = (
        build_id,
        str(obj["package"]),
        int(obj["version_code"]),
        str(obj["cert_sha256"]).lower(),
        str(obj["binding_hash"]).lower(),
        str(obj["hook_dex_name"]),
        encrypt_root_key(build_id, root, key or master_key()),
        now,
        now,
    )
    con = connect(db_path)
    try:
        con.execute(
            """
            INSERT INTO hvm_builds(build_id,package_name,version_code,cert_sha256,binding_hash,hook_dex_name,encrypted_root_key,enabled,created_at,updated_at)
            VALUES(?,?,?,?,?,?,?,1,?,?)
            ON CONFLICT(build_id) DO UPDATE SET
              package_name=excluded.package_name,
              version_code=excluded.version_code,
              cert_sha256=excluded.cert_sha256,
              binding_hash=excluded.binding_hash,
              hook_dex_name=excluded.hook_dex_name,
              encrypted_root_key=excluded.encrypted_root_key,
              runtime_assets_hash='',
              enabled=1,
              updated_at=excluded.updated_at
            """,
            row,
        )
        con.commit()
    finally:
        con.close()
    return {"ok": True, "build_id": build_id, "package": row[1], "version_code": row[2]}


def generate_server_keys(directory: Path) -> dict[str, Any]:
    directory.mkdir(parents=True, exist_ok=True)
    private = ec.generate_private_key(ec.SECP256R1())
    priv_path = directory / "iapt_hvm_sign.pem"
    pub_path = directory / "iapt_hvm_sign_public.der"
    env_path = directory / "iapt_hvm.env"
    priv_path.write_bytes(private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    os.chmod(priv_path, 0o600)
    public_der = private.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    pub_path.write_bytes(public_der)
    transport = "iapt_hvm_" + secrets.token_hex(32)
    key_id = "hvm_" + time.strftime("%Y%m%d")
    env_path.write_text(
        "IAPT_HVM_MASTER_KEY_B64=" + b64e(secrets.token_bytes(32)) + "\n"
        "IAPT_HVM_SIGN_PRIVATE_KEY=" + str(priv_path) + "\n"
        "IAPT_HVM_DB=" + str(directory / "iapt_hvm_keys.sqlite3") + "\n"
        "IAPT_HVM_TRANSPORT_SECRETS_JSON='" + json.dumps({key_id: transport}, separators=(",", ":")) + "'\n",
        encoding="utf-8",
    )
    os.chmod(env_path, 0o600)
    client = {
        "APP_KEY_ID": key_id,
        "TRANSPORT_SECRET": transport,
        "SERVER_SIGN_PUB_B64": b64e(public_der),
    }
    client_path = directory / "client_once.SECRET.json"
    client_path.write_text(json.dumps(client, indent=2) + "\n", encoding="utf-8")
    os.chmod(client_path, 0o600)
    return {
        "ok": True,
        "env_file": str(env_path),
        "client_once": str(client_path),
        "server_sign_pub_b64": client["SERVER_SIGN_PUB_B64"],
        "app_key_id": key_id,
        "transport_secret": transport,
    }


def load_sign_private(path: Path | None = None):
    return serialization.load_pem_private_key((path or sign_key_path()).read_bytes(), password=None)


def canonical_request(obj: dict[str, Any]) -> str:
    keys = ["build_id", "package", "version_code", "cert_sha256", "binding_hash", "hook_dex_name"]
    if str(obj.get("assets_manifest_hash", "")):
        keys.append("assets_manifest_hash")
    keys += ["device_pub_b64", "nonce", "ts", "app_key_id"]
    return "\n".join(str(obj.get(k, "")) for k in keys)


def verify_request(obj: dict[str, Any], *, keyring: dict[str, str] | None = None, now: int | None = None, window: int = 180) -> None:
    now = int(time.time()) if now is None else int(now)
    ts = int(obj.get("ts", 0))
    print(f"[HVM-KEY-TIME] now={now} ts={ts} diff={now-ts} build_id={obj.get('build_id','')} app_key_id={obj.get('app_key_id','')}", flush=True)
    if abs(now - ts) > window:
        raise BrokerError("请求已过期")
    ring = keyring or transport_secrets()
    key_id = str(obj.get("app_key_id", ""))
    if key_id not in ring:
        raise BrokerError("未知 app_key_id")
    expected = hmac.new(ring[key_id].encode(), canonical_request(obj).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(obj.get("sign", ""))):
        raise BrokerError("请求签名错误")


def issue_key(obj: dict[str, Any], *, db_path: Path | None = None, key: bytes | None = None,
              keyring: dict[str, str] | None = None, signing_key=None, now: int | None = None) -> dict[str, Any]:
    verify_request(obj, keyring=keyring, now=now)
    now = int(time.time()) if now is None else int(now)
    nonce = str(obj["nonce"])
    con = connect(db_path)
    try:
        con.execute("DELETE FROM hvm_nonces WHERE created_at<?", (now - 600,))
        try:
            con.execute("INSERT INTO hvm_nonces(nonce,created_at) VALUES(?,?)", (nonce, now))
        except sqlite3.IntegrityError as exc:
            raise BrokerError("重复 nonce") from exc
        row = con.execute("SELECT * FROM hvm_builds WHERE build_id=? AND enabled=1", (str(obj["build_id"]),)).fetchone()
        if row is None:
            raise BrokerError("build 未注册或已停用")
        checks = {
            "package_name": str(obj["package"]),
            "version_code": int(obj["version_code"]),
            "cert_sha256": str(obj["cert_sha256"]).lower(),
            "binding_hash": str(obj["binding_hash"]).lower(),
            "hook_dex_name": str(obj["hook_dex_name"]),
        }
        for col, value in checks.items():
            if row[col] != value:
                raise BrokerError("build 绑定不匹配：" + col)
        assets_hash = str(obj.get("assets_manifest_hash", "")).lower()
        if assets_hash:
            if len(assets_hash) != 64 or any(ch not in "0123456789abcdef" for ch in assets_hash):
                raise BrokerError("assets_manifest_hash 格式错误")
            pinned = str(row["runtime_assets_hash"] or "").lower()
            if pinned and not hmac.compare_digest(pinned, assets_hash):
                raise BrokerError("运行时 assets 完整性绑定不匹配")
            if not pinned:
                cur = con.execute("UPDATE hvm_builds SET runtime_assets_hash=?,updated_at=? WHERE build_id=? AND (runtime_assets_hash='' OR runtime_assets_hash IS NULL)", (assets_hash, now, str(row["build_id"])))
                if cur.rowcount != 1:
                    latest = con.execute("SELECT runtime_assets_hash FROM hvm_builds WHERE build_id=?", (str(row["build_id"]),)).fetchone()
                    latest_pin = str(latest["runtime_assets_hash"] or "").lower() if latest is not None else ""
                    if not latest_pin or not hmac.compare_digest(latest_pin, assets_hash):
                        raise BrokerError("运行时 assets 首次绑定冲突")
        root = decrypt_root_key(str(row["build_id"]), bytes(row["encrypted_root_key"]), key or master_key())
        pub = serialization.load_der_public_key(b64d(str(obj["device_pub_b64"])))
        if not isinstance(pub, rsa.RSAPublicKey) or pub.key_size < 2048:
            raise BrokerError("设备公钥必须是 RSA-2048+")
        wrapped = pub.encrypt(root, padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None))
        expires = now + int(os.environ.get("IAPT_HVM_KEY_TTL_SECONDS", "21600"))
        wrapped_b64 = b64e(wrapped)
        signed_parts = [str(row["build_id"]), wrapped_b64, str(expires), str(row["binding_hash"])]
        if assets_hash:
            signed_parts.append(assets_hash)
        signed = "\n".join(signed_parts).encode()
        signature = (signing_key or load_sign_private()).sign(signed, ec.ECDSA(hashes.SHA256()))
        con.commit()
        result = {
            "build_id": str(row["build_id"]),
            "wrapped_key_b64": wrapped_b64,
            "expires_at": expires,
            "binding_hash": str(row["binding_hash"]),
            "signature_b64": b64e(signature),
        }
        if assets_hash:
            result["assets_manifest_hash"] = assets_hash
        return result
    finally:
        con.close()


def canonical_runtime_event(obj: dict[str, Any]) -> str:
    return "\n".join(str(obj.get(k, "")) for k in (
        "build_id", "package", "version_code", "cert_sha256", "binding_hash",
        "assets_manifest_hash", "stage", "reason", "process", "pid", "nonce", "ts", "app_key_id",
    ))


def record_runtime_event(obj: dict[str, Any], *, db_path: Path | None = None,
                         keyring: dict[str, str] | None = None, now: int | None = None) -> dict[str, Any]:
    now = int(time.time()) if now is None else int(now)
    ts = int(obj.get("ts", 0))
    if abs(now - ts) > 300:
        raise BrokerError("事件已过期")
    ring = keyring or transport_secrets()
    key_id = str(obj.get("app_key_id", ""))
    if key_id not in ring:
        raise BrokerError("未知 app_key_id")
    expected = hmac.new(ring[key_id].encode(), canonical_runtime_event(obj).encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, str(obj.get("sign", ""))):
        raise BrokerError("事件签名错误")
    build_id = str(obj.get("build_id", ""))[:128]
    package = str(obj.get("package", ""))[:255]
    cert = str(obj.get("cert_sha256", "")).lower()
    binding = str(obj.get("binding_hash", "")).lower()
    assets = str(obj.get("assets_manifest_hash", "")).lower()
    stage = str(obj.get("stage", ""))[:48]
    reason = str(obj.get("reason", ""))[:240]
    process = str(obj.get("process", ""))[:96]
    nonce = str(obj.get("nonce", ""))[:128]
    pid = int(obj.get("pid", 0))
    version = int(obj.get("version_code", 0))
    if not build_id or not package or len(cert) != 64 or len(binding) != 64 or len(assets) != 64 or not nonce:
        raise BrokerError("事件字段格式错误")
    con = connect(db_path)
    try:
        row = con.execute("SELECT * FROM hvm_builds WHERE build_id=?", (build_id,)).fetchone()
        if row is None:
            raise BrokerError("build 不存在")
        expected_values = (str(row["package_name"]), int(row["version_code"]), str(row["cert_sha256"]).lower(), str(row["binding_hash"]).lower())
        if expected_values != (package, version, cert, binding):
            raise BrokerError("事件 build 绑定不匹配")
        pinned = str(row["runtime_assets_hash"] or "").lower()
        if pinned and not hmac.compare_digest(pinned, assets):
            reason = ("assets_pin_mismatch:" + reason)[:240]
        con.execute("DELETE FROM hvm_runtime_events WHERE received_at<?", (now - 30 * 86400,))
        try:
            con.execute(
                """INSERT INTO hvm_runtime_events(build_id,package_name,version_code,cert_sha256,binding_hash,assets_manifest_hash,stage,reason,process_name,pid,event_ts,received_at,nonce)
                   VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (build_id, package, version, cert, binding, assets, stage, reason, process, pid, ts, now, nonce),
            )
        except sqlite3.IntegrityError as exc:
            raise BrokerError("重复事件 nonce") from exc
        con.commit()
        return {"ok": True, "stored": True}
    finally:
        con.close()


def set_enabled(build_id: str, enabled: bool, db_path: Path | None = None) -> dict[str, Any]:
    con = connect(db_path)
    try:
        cur = con.execute("UPDATE hvm_builds SET enabled=?,updated_at=? WHERE build_id=?", (1 if enabled else 0, int(time.time()), build_id))
        con.commit()
        if cur.rowcount != 1:
            raise BrokerError("build 不存在")
    finally:
        con.close()
    return {"ok": True, "build_id": build_id, "enabled": enabled}


if APIRouter is not None:
    class HvmKeyRequest(BaseModel):
        build_id: str
        package: str
        version_code: int
        cert_sha256: str
        binding_hash: str
        hook_dex_name: str
        assets_manifest_hash: str = ""
        device_pub_b64: str
        nonce: str
        ts: int
        app_key_id: str
        sign: str

    router = APIRouter(prefix="/api/hvm4", tags=["iAPT Hybrid VM"])

    @router.post("/key")
    def hvm_key(body: HvmKeyRequest):
        try:
            return issue_key(body.model_dump())
        except BrokerError as exc:
            raise HTTPException(status_code=403, detail=str(exc))


    class HvmRuntimeEventRequest(BaseModel):
        build_id: str
        package: str
        version_code: int
        cert_sha256: str
        binding_hash: str
        assets_manifest_hash: str
        stage: str
        reason: str
        process: str
        pid: int
        nonce: str
        ts: int
        app_key_id: str
        sign: str

    @router.post("/runtime-event")
    def hvm_runtime_event(body: HvmRuntimeEventRequest):
        try:
            return record_runtime_event(body.model_dump())
        except BrokerError as exc:
            raise HTTPException(status_code=403, detail=str(exc))


def self_test() -> dict[str, Any]:
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        root = Path(td)
        server = generate_server_keys(root / "keys")
        env: dict[str, str] = {}
        for line in Path(server["env_file"]).read_text().splitlines():
            if not line or "=" not in line:
                continue
            k, v = line.split("=", 1)
            env[k] = v.strip("'")
        master = b64d(env["IAPT_HVM_MASTER_KEY_B64"])
        ring = json.loads(env["IAPT_HVM_TRANSPORT_SECRETS_JSON"])
        enrollment = root / "enroll.json"
        root_key = secrets.token_bytes(32)
        enrollment.write_text(json.dumps({
            "format": FORMAT,
            "build_id": "b1",
            "package": "com.test",
            "version_code": 1,
            "cert_sha256": "ab" * 32,
            "binding_hash": "cd" * 32,
            "hook_dex_name": "classes2.dex",
            "bound_root_key_b64": b64e(root_key),
        }))
        db = root / "db.sqlite3"
        register_enrollment(enrollment, db, master)
        device = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        req = {
            "build_id": "b1", "package": "com.test", "version_code": 1,
            "cert_sha256": "ab" * 32, "binding_hash": "cd" * 32,
            "hook_dex_name": "classes2.dex",
            "device_pub_b64": b64e(device.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)),
            "nonce": "n1", "ts": int(time.time()), "app_key_id": next(iter(ring)),
        }
        req["sign"] = hmac.new(ring[req["app_key_id"]].encode(), canonical_request(req).encode(), hashlib.sha256).hexdigest()
        signing = serialization.load_pem_private_key((root / "keys/iapt_hvm_sign.pem").read_bytes(), password=None)
        out = issue_key(req, db_path=db, key=master, keyring=ring, signing_key=signing, now=req["ts"])
        unwrapped = device.decrypt(b64d(out["wrapped_key_b64"]), padding.OAEP(mgf=padding.MGF1(hashes.SHA1()), algorithm=hashes.SHA256(), label=None))
        assert unwrapped == root_key
        return {"ok": True, "register": True, "issue": True, "device_wrap": True, "signed_response": True}


def main() -> int:
    ap = argparse.ArgumentParser(description="iAPT Hybrid VM cloud key broker")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("self-test")
    init = sub.add_parser("init-keys")
    init.add_argument("--directory", default="/www/wwwroot/iapt/secrets/hvm")
    reg = sub.add_parser("register")
    reg.add_argument("--enrollment", required=True)
    reg.add_argument("--db")
    ena = sub.add_parser("enable")
    ena.add_argument("build_id")
    ena.add_argument("--db")
    dis = sub.add_parser("disable")
    dis.add_argument("build_id")
    dis.add_argument("--db")
    args = ap.parse_args()
    if args.cmd == "self-test":
        out = self_test()
    elif args.cmd == "init-keys":
        out = generate_server_keys(Path(args.directory))
    elif args.cmd == "register":
        out = register_enrollment(Path(args.enrollment), Path(args.db) if args.db else None)
    elif args.cmd == "enable":
        out = set_enabled(args.build_id, True, Path(args.db) if args.db else None)
    else:
        out = set_enabled(args.build_id, False, Path(args.db) if args.db else None)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
