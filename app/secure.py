import base64
import hashlib
import hmac
import json
import time
from typing import Any

from fastapi import HTTPException, Request
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from . import db
from .config import APP_ID, APP_SECRET, SIGN_WINDOW_SECONDS, ALLOW_INSECURE_DEV


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).hexdigest()


def _path_with_query(request: Request) -> str:
    q = request.url.query
    return request.url.path + (('?' + q) if q else '')


def _sign_key(salt: str) -> bytes:
    return hashlib.sha256((APP_SECRET + ':' + salt).encode('utf-8')).digest()


def expected_sign(method: str, path: str, ts: str, nonce: str, salt: str, body_hash: str, token: str = '') -> str:
    raw = '\n'.join([method.upper(), path, ts, nonce, salt, body_hash, token or ''])
    return hmac.new(_sign_key(salt), raw.encode('utf-8'), hashlib.sha256).hexdigest()


def verify_request(request: Request, token: str = '') -> None:
    """校验 APP_ID / 时间戳 / nonce / sign。

    这里不是防抓包方案，只是防止裸接口被直接重放/批量调用。
    客户端需要在每次请求里带：
      X-App-Id, X-Timestamp, X-Nonce, X-Salt, X-Body-Hash, X-Sign
    """
    if ALLOW_INSECURE_DEV:
        return
    h = request.headers
    app_id = h.get('x-app-id', '')
    ts = h.get('x-timestamp', '')
    nonce = h.get('x-nonce', '')
    salt = h.get('x-salt', '')
    body_hash = h.get('x-body-hash', sha256_hex(b''))
    sign = h.get('x-sign', '')
    if app_id != APP_ID or not ts or not nonce or not salt or not sign:
        raise HTTPException(401, '签名参数缺失')
    try:
        ts_int = int(ts)
    except Exception:
        raise HTTPException(401, '时间戳错误')
    now = int(time.time())
    if abs(now - ts_int) > SIGN_WINDOW_SECONDS:
        raise HTTPException(401, '请求已过期')
    calc = expected_sign(request.method, _path_with_query(request), ts, nonce, salt, body_hash, token)
    if not hmac.compare_digest(calc, sign):
        raise HTTPException(401, '签名错误')
    # GET/HEAD/OPTIONS are idempotent and dominate the admin refresh workload.
    # Persisting every read nonce turned simple refreshes into database writes.
    if request.method.upper() in ('GET', 'HEAD', 'OPTIONS'):
        return
    try:
        db.exec('INSERT INTO api_nonces(nonce, created_at) VALUES(%s,NOW())', (nonce,))
    except Exception:
        raise HTTPException(401, '重复请求')


def aes_key(salt: str) -> bytes:
    return hashlib.sha256((APP_SECRET + '|aes|' + salt).encode('utf-8')).digest()


def pkcs7_unpad(data: bytes) -> bytes:
    if not data:
        raise ValueError('empty padded data')
    pad = data[-1]
    if pad < 1 or pad > 16 or data[-pad:] != bytes([pad]) * pad:
        raise ValueError('bad padding')
    return data[:-pad]


def decrypt_json_payload(obj: dict[str, Any], salt: str) -> dict[str, Any]:
    if 'data' not in obj or 'iv' not in obj:
        if ALLOW_INSECURE_DEV:
            return obj
        raise HTTPException(400, '加密参数缺失')
    try:
        ct = base64.b64decode(str(obj['data']))
        iv = base64.b64decode(str(obj['iv']))
        dec = Cipher(algorithms.AES(aes_key(salt)), modes.CBC(iv), backend=default_backend()).decryptor()
        plain = pkcs7_unpad(dec.update(ct) + dec.finalize())
        return json.loads(plain.decode('utf-8'))
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(400, f'参数解密失败: {e}')


async def read_secure_json(request: Request, token: str = '', verify: bool = True) -> dict[str, Any]:
    raw = await request.body()
    if not raw:
        data_obj = {}
    else:
        try:
            data_obj = json.loads(raw.decode('utf-8'))
        except Exception:
            raise HTTPException(400, 'JSON 格式错误')
    body_hash = request.headers.get('x-body-hash', '')
    # body_hash 签的是 data 字段，避免上传/JSON序列化差异；兼容 dev 明文签整包。
    if isinstance(data_obj, dict) and 'data' in data_obj:
        expected_hash = sha256_hex(str(data_obj.get('data', '')))
    else:
        expected_hash = sha256_hex(raw)
    if body_hash and body_hash != expected_hash and not ALLOW_INSECURE_DEV:
        raise HTTPException(400, 'body hash 错误')
    if verify:
        verify_request(request, token)
    salt = request.headers.get('x-salt', '')
    return decrypt_json_payload(data_obj, salt)
