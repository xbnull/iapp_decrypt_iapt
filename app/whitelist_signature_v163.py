from __future__ import annotations

import argparse
import base64
import calendar
import datetime as dt
import hashlib
import os
import re
import stat
import tempfile
import zipfile
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

SCHEME_VERSION = "v163"
KEY_SIZE_BITS = 2048
SIGNATURE_RAW_SIZE = KEY_SIZE_BITS // 8
SIGNATURE_B64_SIZE = ((SIGNATURE_RAW_SIZE + 2) // 3) * 4

APP_ROOT = Path(__file__).resolve().parents[1]
KEY_DIR = Path(os.environ.get("IAPT_WHITELIST_KEY_DIR") or (APP_ROOT / "storage" / "whitelist_keys"))
PRIVATE_KEY_PATH = KEY_DIR / "v163_rsa_private.pem"
PUBLIC_KEY_PATH = KEY_DIR / "v163_rsa_public.pem"
MASTER_KEY_PATH = KEY_DIR / "v163_aes_master.bin"
SALT_PATH = KEY_DIR / "v163_salt.bin"

_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def _atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        try:
            tmp.unlink(missing_ok=True)
        except Exception:
            pass


def ensure_key_material() -> dict:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(KEY_DIR, 0o700)
    except Exception:
        pass

    if not PRIVATE_KEY_PATH.exists():
        key = rsa.generate_private_key(public_exponent=65537, key_size=KEY_SIZE_BITS)
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _atomic_write(PRIVATE_KEY_PATH, private_pem, 0o600)
        _atomic_write(PUBLIC_KEY_PATH, public_pem, 0o644)
    elif not PUBLIC_KEY_PATH.exists():
        key = load_private_key()
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _atomic_write(PUBLIC_KEY_PATH, public_pem, 0o644)

    if not MASTER_KEY_PATH.exists():
        _atomic_write(MASTER_KEY_PATH, os.urandom(32), 0o600)
    if not SALT_PATH.exists():
        _atomic_write(SALT_PATH, os.urandom(32), 0o600)

    for path, mode in (
        (PRIVATE_KEY_PATH, 0o600),
        (PUBLIC_KEY_PATH, 0o644),
        (MASTER_KEY_PATH, 0o600),
        (SALT_PATH, 0o600),
    ):
        try:
            os.chmod(path, mode)
        except Exception:
            pass

    master = MASTER_KEY_PATH.read_bytes()
    salt = SALT_PATH.read_bytes()
    if len(master) != 32:
        raise RuntimeError(f"invalid AES master key length: {len(master)}")
    if len(salt) < 16:
        raise RuntimeError(f"invalid whitelist salt length: {len(salt)}")

    return {
        "scheme": SCHEME_VERSION,
        "key_dir": str(KEY_DIR),
        "private_key": str(PRIVATE_KEY_PATH),
        "public_key": str(PUBLIC_KEY_PATH),
        "master_key": str(MASTER_KEY_PATH),
        "salt": str(SALT_PATH),
        "signature_raw_size": SIGNATURE_RAW_SIZE,
        "signature_base64_size": SIGNATURE_B64_SIZE,
    }


def load_private_key():
    data = PRIVATE_KEY_PATH.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, rsa.RSAPrivateKey):
        raise TypeError("whitelist private key is not RSA")
    if key.key_size != KEY_SIZE_BITS:
        raise ValueError(f"whitelist RSA key size must be {KEY_SIZE_BITS}")
    return key


def _pkcs7(data: bytes) -> bytes:
    padder = PKCS7(128).padder()
    return padder.update(data) + padder.finalize()


def _aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    if len(key) not in (16, 24, 32):
        raise ValueError("invalid AES key length")
    if len(iv) != 16:
        raise ValueError("invalid AES-CBC IV length")
    encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    padded = _pkcs7(plaintext)
    return encryptor.update(padded) + encryptor.finalize()


def normalize_package_name(value: object) -> str:
    package_name = str(value or "").strip()
    if not re.fullmatch(r"[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z0-9_]+)+", package_name):
        raise ValueError("invalid Android package name")
    return package_name


def expire_to_milliseconds(value: object) -> int:
    if value is None or value == "":
        return 0
    if isinstance(value, dt.date) and not isinstance(value, dt.datetime):
        value = dt.datetime(value.year, value.month, value.day)
    if isinstance(value, dt.datetime):
        current = value
    else:
        text = str(value).strip()
        if not text or text.lower() in {"none", "null", "never", "永久"}:
            return 0
        text = text.replace("T", " ").replace("Z", "").replace("/", "-")
        text = re.sub(r"\.\d+$", "", text)
        current = None
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                current = dt.datetime.strptime(text[:19], fmt)
                break
            except ValueError:
                pass
        if current is None:
            current = dt.datetime.fromisoformat(text)
    if current.tzinfo is not None:
        seconds = current.timestamp()
    else:
        # Database timestamps in this project are naive server times. Treat the
        # same wall-clock components as UTC only to obtain a stable integer for
        # token derivation; expiry enforcement still compares the DB datetime.
        seconds = calendar.timegm(current.timetuple()) + current.microsecond / 1_000_000
    milliseconds = int(seconds * 1000)
    if milliseconds < 0 or milliseconds >= 1 << 64:
        raise ValueError("expiry milliseconds out of uint64 range")
    return milliseconds


def compute_final_sha256(package_name: str, expire_ms: int) -> str:
    ensure_key_material()
    package_name = normalize_package_name(package_name)
    expire_ms = int(expire_ms)
    if expire_ms < 0 or expire_ms >= 1 << 64:
        raise ValueError("expiry milliseconds out of uint64 range")

    package_bytes = package_name.encode("utf-8")
    expire_bytes = expire_ms.to_bytes(8, "big", signed=False)
    timestamp_hash = hashlib.sha256(expire_bytes).digest()
    salt = SALT_PATH.read_bytes()
    master_key = MASTER_KEY_PATH.read_bytes()

    # User-specified canonical concatenation:
    # package || server_salt || SHA256(expiry_milliseconds_uint64_be)
    plain = package_bytes + salt + timestamp_hash

    iv1 = hashlib.sha256(b"IAPT-WL-V163-AES1-IV\x00" + plain).digest()[:16]
    aes1_cipher = _aes_cbc_encrypt(master_key, iv1, plain)

    # Preserve the requested Base64 encode -> immediate Base64 decode step.
    aes1_base64 = base64.b64encode(aes1_cipher)
    garbled_bytes = base64.b64decode(aes1_base64, validate=True)

    # XOR with the raw 8-byte expiry timestamp, repeated over the ciphertext.
    mixed = bytes(
        value ^ expire_bytes[index % len(expire_bytes)]
        for index, value in enumerate(garbled_bytes)
    )

    aes2_key = hashlib.sha256(mixed).digest()
    iv2 = hashlib.sha256(b"IAPT-WL-V163-AES2-IV\x00" + mixed).digest()[:16]
    aes2_cipher = _aes_cbc_encrypt(aes2_key, iv2, plain)
    return hashlib.sha256(aes2_cipher).hexdigest()


def normalize_final_sha256(value: object) -> str:
    result = str(value or "").strip().lower()
    if not _HEX64_RE.fullmatch(result):
        raise ValueError("final SHA-256 must be 64 lowercase hex characters")
    return result


def sign_final_sha256(final_sha256: str) -> bytes:
    ensure_key_material()
    digest = bytes.fromhex(normalize_final_sha256(final_sha256))
    return load_private_key().sign(
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(hashes.SHA256()),
    )


def signature_base64(final_sha256: str) -> str:
    value = base64.b64encode(sign_final_sha256(final_sha256)).decode("ascii")
    if len(value) != SIGNATURE_B64_SIZE:
        raise RuntimeError("unexpected whitelist signature length")
    return value


def build_record(package_name: str, expire_value: object) -> dict:
    expire_ms = expire_to_milliseconds(expire_value)
    final_sha256 = compute_final_sha256(package_name, expire_ms)
    public_key = signature_base64(final_sha256)
    return {
        "scheme": SCHEME_VERSION,
        "package_name": normalize_package_name(package_name),
        "expire_ms": expire_ms,
        "final_sha256": final_sha256,
        # User-facing name retained by request. This is a Base64-encoded,
        # deterministic RSA signature, not the PEM public key file.
        "public_key": public_key,
        "signature_base64": public_key,
    }


def _stream_contains_any(handle, needles: Sequence[bytes], chunk_size: int = 1024 * 1024) -> Optional[int]:
    needles = [value for value in needles if value]
    if not needles:
        return None
    overlap_size = max(len(value) for value in needles) - 1
    tail = b""
    while True:
        chunk = handle.read(chunk_size)
        if not chunk:
            return None
        data = tail + chunk
        for index, needle in enumerate(needles):
            if needle in data:
                return index
        tail = data[-overlap_size:] if overlap_size > 0 else b""


def find_signature_in_apk(
    apk_path: Path | str,
    signature_values: Sequence[str],
    *,
    max_entry_size: int = 128 * 1024 * 1024,
    max_total_size: int = 512 * 1024 * 1024,
) -> Optional[dict]:
    path = Path(apk_path)
    needles = [str(value).encode("ascii") for value in signature_values]
    if not path.is_file() or not needles:
        return None

    # Stored/uncompressed entries and APK comments can expose the string in the
    # raw ZIP. Check it cheaply before opening each member.
    with path.open("rb") as handle:
        index = _stream_contains_any(handle, needles)
    if index is not None:
        return {"signature_index": index, "location": "<apk-raw>"}

    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = [info for info in archive.infolist() if not info.is_dir()]
            infos.sort(
                key=lambda info: (
                    0 if info.filename == "assets/lib.so" else 1,
                    0 if Path(info.filename).name.lower() == "lib.so" else 1,
                    0 if info.filename.startswith("assets/") else 1,
                    info.filename,
                )
            )
            total = 0
            for info in infos:
                if info.file_size < 0 or info.file_size > max_entry_size:
                    continue
                total += info.file_size
                if total > max_total_size:
                    break
                try:
                    with archive.open(info, "r") as handle:
                        index = _stream_contains_any(handle, needles)
                except Exception:
                    continue
                if index is not None:
                    return {
                        "signature_index": index,
                        "location": info.filename,
                    }
    except Exception:
        return None
    return None


def extract_package_name(apk_path: Path | str) -> str:
    try:
        from app.tools.iapt_v10.apk_meta_fast import read_apk_meta
        package_name = str((read_apk_meta(Path(apk_path)) or {}).get("package_name") or "").strip()
        return normalize_package_name(package_name)
    except Exception:
        return ""



def ensure_database_schema(db_module) -> dict:
    db_module.exec(
        """
        CREATE TABLE IF NOT EXISTS decrypt_whitelist (
            id BIGINT PRIMARY KEY AUTO_INCREMENT,
            package_name VARCHAR(255) NOT NULL DEFAULT '',
            code_hash VARCHAR(128) NOT NULL DEFAULT '',
            final_sha256 VARCHAR(64) NOT NULL DEFAULT '',
            token_version VARCHAR(16) NOT NULL DEFAULT '',
            expire_at DATETIME NULL,
            note VARCHAR(512) NULL,
            created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP,
            KEY idx_pkg_hash(package_name, code_hash),
            KEY idx_v163_pkg(package_name, token_version),
            KEY idx_v163_final(final_sha256),
            KEY idx_expire(expire_at)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )

    rows = db_module.all("SHOW COLUMNS FROM `decrypt_whitelist`") or []
    columns = {
        str(row.get("Field") or row.get("field") or ""): dict(row)
        for row in rows
        if isinstance(row, dict)
    }

    additions = {
        "final_sha256": "VARCHAR(64) NOT NULL DEFAULT ''",
        "token_version": "VARCHAR(16) NOT NULL DEFAULT ''",
    }
    for name, ddl in additions.items():
        if name not in columns:
            db_module.exec(
                "ALTER TABLE `decrypt_whitelist` ADD COLUMN `"
                + name
                + "` "
                + ddl
            )

    rows = db_module.all("SHOW COLUMNS FROM `decrypt_whitelist`") or []
    columns = {
        str(row.get("Field") or row.get("field") or ""): dict(row)
        for row in rows
        if isinstance(row, dict)
    }

    known_string_sizes = {
        "package_name": 255,
        "package": 255,
        "pkg": 255,
        "pkg_name": 255,
        "app_package": 255,
        "packageName": 255,
        "code_hash": 128,
        "code_sha256": 128,
        "file_hash": 128,
        "apk_sha256": 128,
        "apk_hash": 128,
        "hash": 128,
        "sha256": 128,
        "final_sha256": 64,
        "token_version": 16,
    }
    altered = []
    for name, size in known_string_sizes.items():
        row = columns.get(name)
        if not row:
            continue
        if "generated" in str(row.get("Extra") or "").lower():
            continue
        if (
            str(row.get("Null") or "").upper() == "NO"
            and row.get("Default") is None
        ):
            db_module.exec(
                "ALTER TABLE `decrypt_whitelist` MODIFY COLUMN `"
                + name
                + "` VARCHAR("
                + str(size)
                + ") NOT NULL DEFAULT ''"
            )
            altered.append(name)

    return {
        "table": "decrypt_whitelist",
        "altered_columns": altered,
        "columns": db_module.all(
            "SHOW COLUMNS FROM `decrypt_whitelist`"
        ) or [],
    }

def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ensure-keys", action="store_true")
    parser.add_argument("--package")
    parser.add_argument("--expire", default="")
    parser.add_argument("--final-sha256")
    args = parser.parse_args(list(argv) if argv is not None else None)

    if args.ensure_keys:
        print(ensure_key_material())
        return 0
    if args.package:
        print(build_record(args.package, args.expire))
        return 0
    if args.final_sha256:
        print(signature_base64(args.final_sha256))
        return 0
    parser.error("choose --ensure-keys, --package, or --final-sha256")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
