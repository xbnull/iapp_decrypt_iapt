import base64
import hashlib
import hmac
import secrets
import time
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .config import APP_SECRET, RSA_PRIVATE_KEY_PATH, ZIP_ENCRYPTION


def sha256_hex_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def pkcs7_pad(data: bytes) -> bytes:
    pad = 16 - (len(data) % 16)
    return data + bytes([pad]) * pad


def zip_aes_key(token: str, task_no: str, salt: str, ts: str) -> bytes:
    raw = f'{APP_SECRET}|zip|{token}|{task_no}|{salt}|{ts}'.encode('utf-8')
    return hashlib.sha256(raw).digest()


def load_private_key():
    pem = RSA_PRIVATE_KEY_PATH.read_bytes()
    return serialization.load_pem_private_key(pem, password=None)


def rsa_sign(data: bytes) -> str:
    sig = load_private_key().sign(data, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode('ascii')


def encrypt_zip_for_user(zip_path: Path, token: str, task_no: str) -> tuple[Path, dict]:
    """AES encrypt zip bytes and RSA-sign ciphertext metadata.

    注意：RSA 在这里用于签名/校验，不直接加密大 zip。zip 内容使用 token+time+salt 派生 AES key 加密。
    """
    salt = secrets.token_hex(12)
    ts = str(int(time.time()))
    iv = secrets.token_bytes(16)
    plain = zip_path.read_bytes()
    if ZIP_ENCRYPTION:
        cipher = Cipher(algorithms.AES(zip_aes_key(token, task_no, salt, ts)), modes.CBC(iv), backend=default_backend()).encryptor()
        body = cipher.update(pkcs7_pad(plain)) + cipher.finalize()
        mode = 'aes-cbc-rsa-sign-v1'
    else:
        body = plain
        mode = 'plain-rsa-sign-v1'
    digest = sha256_hex_bytes(body)
    sign_base = '\n'.join([mode, task_no, ts, salt, base64.b64encode(iv).decode('ascii'), digest]).encode('utf-8')
    signature = rsa_sign(sign_base)
    out = zip_path.with_suffix(zip_path.suffix + '.secure') if ZIP_ENCRYPTION else zip_path
    if ZIP_ENCRYPTION:
        out.write_bytes(body)
    headers = {
        'x-zip-mode': mode,
        'x-zip-task': task_no,
        'x-zip-ts': ts,
        'x-zip-salt': salt,
        'x-zip-iv': base64.b64encode(iv).decode('ascii'),
        'x-zip-sha256': digest,
        'x-zip-sign': signature,
        'x-zip-original-size': str(len(plain)),
    }
    return out, headers
