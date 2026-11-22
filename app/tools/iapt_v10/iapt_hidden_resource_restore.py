#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Static restoration of DES-, cyclic-XOR-, and nested-3LKs iApp resources.

The module only reads and rewrites ZIP bytes.  It never imports, loads, starts,
or emulates code from the submitted APK.
"""
from __future__ import annotations

import datetime
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import struct
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

_MIN_CIPHER_SIZE = 64 * 1024
_MAX_CIPHER_SIZE = 512 * 1024 * 1024
_MAX_SIDECAR_SIZE = 8192
_MAX_INNER_ENTRIES = 20000
_MAX_INNER_UNCOMPRESSED = 1024 * 1024 * 1024
_MAX_MEMBER_SIZE = 512 * 1024 * 1024
_MAX_NAME_LENGTH = 16384
_MAX_PATH_DEPTH = 4096
_MARKER_NAME = "META-INF/iapt/hidden-resource-restored.json"


class HiddenResourceRestoreError(ValueError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normal_name(name: str) -> str:
    return str(name or "").replace("\\", "/")


def _safe_zip_name(name: str) -> bool:
    name = _normal_name(name)
    if not name or "\x00" in name or name.startswith("/"):
        return False
    parts = [p for p in name.split("/") if p not in ("", ".")]
    return all(p != ".." for p in parts)


def _pkcs7_unpad(data: bytes, block_size: int) -> bytes:
    if not data:
        raise HiddenResourceRestoreError("DES plaintext is empty")
    n = data[-1]
    if n < 1 or n > block_size or data[-n:] != bytes([n]) * n:
        raise HiddenResourceRestoreError("invalid DES PKCS#5/7 padding")
    return data[:-n]


def _des_ecb_decrypt(ciphertext: bytes, key: bytes) -> bytes:
    if len(key) != 8:
        raise HiddenResourceRestoreError("DES key must be exactly 8 bytes")
    if not ciphertext or len(ciphertext) % 8:
        raise HiddenResourceRestoreError("DES ciphertext is not block aligned")

    try:
        from Crypto.Cipher import DES  # type: ignore
        return DES.new(key, DES.MODE_ECB).decrypt(ciphertext)
    except Exception:
        pass

    # Triple-DES with K1 == K2 == K3 is equivalent to single DES and remains
    # available in cryptography builds where the DES class was removed.
    try:
        from cryptography.hazmat.primitives.ciphers import Cipher, modes
        try:
            from cryptography.hazmat.primitives.ciphers import algorithms
            TripleDES = algorithms.TripleDES
        except (ImportError, AttributeError):
            from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES  # type: ignore
        decryptor = Cipher(TripleDES(key * 3), modes.ECB()).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        pass

    openssl = os.environ.get("OPENSSL") or "openssl"
    commands = [
        [openssl, "enc", "-d", "-des-ecb", "-nopad", "-provider", "legacy", "-provider", "default", "-K", key.hex()],
        [openssl, "enc", "-d", "-des-ecb", "-nopad", "-K", key.hex()],
    ]
    errors: List[str] = []
    for command in commands:
        try:
            proc = subprocess.run(
                command,
                input=ciphertext,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
                timeout=120,
            )
        except Exception as exc:
            errors.append(f"{type(exc).__name__}: {exc}")
            continue
        if proc.returncode == 0:
            return proc.stdout
        errors.append(proc.stderr.decode("utf-8", "replace")[-500:])
    raise HiddenResourceRestoreError(
        "no DES backend is available; install pycryptodome or cryptography (" + "; ".join(errors) + ")"
    )


def derive_des_key_from_sidecar(sidecar: bytes) -> Dict[str, Any]:
    try:
        text = sidecar.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise HiddenResourceRestoreError("sidecar is not valid UTF-8") from exc
    if len(text) <= 34:
        raise HiddenResourceRestoreError("sidecar is too short")

    # Reimplementation of the Java loader:
    #   transformed = metadata.substring(0, len-33) + metadata[-1]
    #   n = int(last char)
    #   position = int(the n digits before last char)
    #   key = transformed.substring(position, position+8).getBytes(UTF_8)[:8]
    transformed = text[:-33] + text[-1]
    if not transformed[-1].isdigit():
        raise HiddenResourceRestoreError("sidecar position digit count is missing")
    position_digits = int(transformed[-1])
    if position_digits < 1 or position_digits > 9:
        raise HiddenResourceRestoreError("sidecar position digit count is invalid")
    if len(transformed) < position_digits + 2:
        raise HiddenResourceRestoreError("sidecar position field is truncated")
    position_text = transformed[-1 - position_digits : -1]
    if not position_text.isdigit():
        raise HiddenResourceRestoreError("sidecar position field is not decimal")
    position = int(position_text)
    if position < 0 or position + 8 > len(transformed):
        raise HiddenResourceRestoreError("sidecar key position is out of range")
    key_text = transformed[position : position + 8]
    key = key_text.encode("utf-8")[:8]
    if len(key) != 8:
        raise HiddenResourceRestoreError("sidecar-derived DES key is shorter than 8 bytes")
    return {
        "metadata_length": len(text),
        "position_digits": position_digits,
        "key_position": position,
        "key_text": key_text,
        "key": key,
        "key_sha256": _sha256(key),
    }


def _candidate_score(info: zipfile.ZipInfo) -> int:
    name = _normal_name(info.filename)
    low = name.lower()
    score = 0
    if low.startswith("assets/"):
        score += 25
    if len(name) >= 256:
        score += 35
    if len(name) >= 1024:
        score += 55
    if name.count("/") >= 16:
        score += 25
    if name.count("/") >= 64:
        score += 35
    non_ascii = sum(1 for ch in name if ord(ch) > 127)
    if non_ascii >= 16:
        score += 25
    if info.file_size >= 1024 * 1024:
        score += 25
    if info.file_size >= 4 * 1024 * 1024:
        score += 20
    if info.file_size and info.compress_size:
        ratio = float(info.compress_size) / float(info.file_size)
        if ratio >= 0.8:
            score += 15
    if "." not in name.rsplit("/", 1)[-1]:
        score += 15
    return score


def _explicit_names(options: Optional[Dict[str, Any]]) -> Tuple[Optional[str], List[str]]:
    options = options or {}
    cipher_name = str(options.get("client_cipher_entry") or "").strip() or None
    raw = options.get("client_cipher_sidecar_entries") or []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            raw = parsed if isinstance(parsed, list) else [raw]
        except Exception:
            raw = [x.strip() for x in raw.replace(";", "\n").splitlines() if x.strip()]
    sidecars = [str(x) for x in raw if str(x).strip()]
    return cipher_name, sidecars


def _find_pairs(
    zf: zipfile.ZipFile,
    options: Optional[Dict[str, Any]] = None,
) -> List[Tuple[zipfile.ZipInfo, zipfile.ZipInfo, int]]:
    infos = [x for x in zf.infolist() if not x.is_dir()]
    by_name = {x.filename: x for x in infos}
    explicit_cipher, explicit_sidecars = _explicit_names(options)
    pairs: List[Tuple[zipfile.ZipInfo, zipfile.ZipInfo, int]] = []

    if explicit_cipher and explicit_cipher in by_name:
        cipher_info = by_name[explicit_cipher]
        candidates = [by_name[n] for n in explicit_sidecars if n in by_name]
        if not candidates:
            candidates = [
                x for x in infos
                if x.filename != cipher_info.filename
                and x.filename.startswith(cipher_info.filename)
                and 0 < x.file_size <= _MAX_SIDECAR_SIZE
                and 1 <= len(x.filename) - len(cipher_info.filename) <= 64
            ]
        for sidecar in candidates:
            pairs.append((cipher_info, sidecar, 1000000))

    ranked_ciphers = []
    for info in infos:
        if not (_MIN_CIPHER_SIZE <= info.file_size <= _MAX_CIPHER_SIZE):
            continue
        if info.file_size % 8:
            continue
        score = _candidate_score(info)
        if score < 90:
            continue
        ranked_ciphers.append((score, info))
    ranked_ciphers.sort(key=lambda row: (-row[0], -row[1].file_size, row[1].filename))

    for score, cipher_info in ranked_ciphers[:16]:
        sidecars = [
            x for x in infos
            if x.filename != cipher_info.filename
            and 0 < x.file_size <= _MAX_SIDECAR_SIZE
            and (
                (
                    x.filename.startswith(cipher_info.filename)
                    and 1 <= len(x.filename) - len(cipher_info.filename) <= 64
                )
                or (
                    cipher_info.filename.startswith(x.filename)
                    and 1 <= len(cipher_info.filename) - len(x.filename) <= 64
                )
            )
        ]
        for sidecar in sorted(sidecars, key=lambda x: (x.file_size, x.filename)):
            pairs.append((cipher_info, sidecar, score))

    dedup: List[Tuple[zipfile.ZipInfo, zipfile.ZipInfo, int]] = []
    seen = set()
    for row in pairs:
        key = (row[0].filename, row[1].filename)
        if key in seen:
            continue
        seen.add(key)
        dedup.append(row)
    return dedup



def _xor_repeat(data: bytes, key: bytes) -> bytes:
    if not key:
        raise HiddenResourceRestoreError("empty XOR key")
    return bytes(value ^ key[index % len(key)] for index, value in enumerate(data))


def _xor_cycle_key_candidates(
    blob: bytes,
    body_offset: int = 16,
    min_period: int = 16,
    max_period: int = 96,
) -> List[Tuple[bytes, int, int]]:
    """Recover cyclic XOR keys from adjacent printable repetitions.

    Older anti-encryption wrappers used a 40-byte key. Newer samples may alter
    the period (41 bytes has been observed). Detect the period from data rather
    than treating 40 as part of the format.
    """
    counts: Dict[bytes, int] = {}
    first: Dict[bytes, int] = {}
    max_run = max_period * 4
    run_re = re.compile(rb"[A-Za-z0-9]{%d,%d}" % (min_period * 2, max_run))

    for match in run_re.finditer(blob):
        run = bytes(match.group(0))
        base = int(match.start())
        run_len = len(run)
        for period in range(min_period, min(max_period, run_len // 2) + 1):
            max_start = min(period, run_len - period * 2 + 1)
            for local_start in range(max_start):
                seq = run[local_start:local_start + period]
                if seq != run[local_start + period:local_start + period * 2]:
                    continue
                absolute = base + local_start
                phase = (absolute - int(body_offset) + 8) % period
                cut = (period - phase) % period
                key = seq[cut:] + seq[:cut] if cut else seq
                counts[key] = counts.get(key, 0) + 1
                first.setdefault(key, absolute)

    rows = [(key, count, first[key]) for key, count in counts.items()]
    rows.sort(key=lambda row: (-row[1], len(row[0]), row[2], row[0]))
    return rows


def _minimal_cycle(key: bytes) -> bytes:
    for period in range(1, len(key) + 1):
        if len(key) % period == 0 and key == key[:period] * (len(key) // period):
            return key[:period]
    return key


def _xor_local(data: bytes, key: bytes, start_index: int = 0) -> bytes:
    period = len(key)
    return bytes(value ^ key[(start_index + index) % period]
                 for index, value in enumerate(data))


def _restore_xor_local_entries(
    ciphertext: bytes,
    key: bytes,
) -> Tuple[bytes, Dict[str, Any]]:
    """Recover ZIP local entries when the XOR phase resets per record."""
    key = _minimal_cycle(bytes(key))
    period = len(key)
    if period < 4:
        raise HiddenResourceRestoreError("cyclic-XOR key is too short")

    signature = b"PK\x03\x04"
    hits: Dict[Tuple[int, str], Tuple[int, str, bytes, int, int, int]] = {}
    for phase_at_record in range(period):
        encrypted_sig = bytes(
            signature[index] ^ key[(phase_at_record + index) % period]
            for index in range(4)
        )
        position = 0
        while True:
            position = ciphertext.find(encrypted_sig, position)
            if position < 0:
                break
            if position + 30 > len(ciphertext):
                break
            try:
                header = _xor_local(
                    ciphertext[position:position + 30], key, phase_at_record
                )
                (
                    sig, version, flags, method, dos_time, dos_date,
                    crc32_value, compressed_size, uncompressed_size,
                    name_length, extra_length,
                ) = struct.unpack("<IHHHHHIIIHH", header)
                if sig != 0x04034B50:
                    raise ValueError("signature")
                if version < 10 or version > 63:
                    raise ValueError("version")
                if flags & 0x0008:
                    raise ValueError("data descriptor")
                if method not in (0, 8):
                    raise ValueError("method")
                if not (1 <= name_length <= _MAX_NAME_LENGTH):
                    raise ValueError("name length")
                if extra_length > 65535:
                    raise ValueError("extra length")
                if compressed_size > _MAX_MEMBER_SIZE or uncompressed_size > _MAX_MEMBER_SIZE:
                    raise ValueError("member size")
                record_size = 30 + name_length + extra_length + compressed_size
                if position + record_size > len(ciphertext):
                    raise ValueError("record range")
                record = _xor_local(
                    ciphertext[position:position + record_size],
                    key,
                    phase_at_record,
                )
                name_raw = record[30:30 + name_length]
                encoding = "utf-8" if flags & 0x0800 else "cp437"
                name = _normal_name(name_raw.decode(encoding, "strict"))
                if not _safe_zip_name(name):
                    raise ValueError("unsafe name")
                data_offset = 30 + name_length + extra_length
                compressed = record[data_offset:data_offset + compressed_size]
                if method == 0:
                    plain = compressed
                else:
                    plain = zlib.decompress(compressed, -15)
                if len(plain) != uncompressed_size:
                    raise ValueError("uncompressed size")
                if (zlib.crc32(plain) & 0xFFFFFFFF) != crc32_value:
                    raise ValueError("crc32")
                identity = (position, name.lower())
                hits[identity] = (
                    position, name, plain, method, dos_time, dos_date
                )
            except Exception:
                pass
            position += 1

    if not hits:
        raise HiddenResourceRestoreError("no verified encrypted ZIP local entries")

    by_name: Dict[str, Tuple[int, str, bytes, int, int, int]] = {}
    for (_, low_name), row in sorted(hits.items()):
        if low_name not in by_name:
            by_name[low_name] = row

    if "assets/lib.so" not in by_name:
        raise HiddenResourceRestoreError(
            f"verified local records ({len(by_name)}) do not contain assets/lib.so"
        )

    output = io.BytesIO()
    total = 0
    with zipfile.ZipFile(output, "w", allowZip64=True) as archive:
        for _, name, plain, method, _dos_time, _dos_date in sorted(
            by_name.values(), key=lambda row: row[0]
        ):
            total += len(plain)
            if total > _MAX_INNER_UNCOMPRESSED:
                raise HiddenResourceRestoreError(
                    "recovered local entries exceed uncompressed safety limit"
                )
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = (
                zipfile.ZIP_DEFLATED if method == 8 else zipfile.ZIP_STORED
            )
            archive.writestr(info, plain)

    rebuilt = output.getvalue()
    inner_meta = _inspect_inner_zip(rebuilt)
    with zipfile.ZipFile(io.BytesIO(rebuilt), "r") as check:
        bad = check.testzip()
        if bad is not None:
            raise HiddenResourceRestoreError(
                "rebuilt local-entry ZIP CRC failed at " + str(bad)
            )
    return rebuilt, {
        "restored": True,
        "algorithm": "cyclic XOR verified local-entry restoration",
        "xor_period": period,
        "xor_key_ascii": key.decode("ascii", "replace"),
        "xor_key_sha256": _sha256(key),
        "local_entry_count": len(by_name),
        "inner_zip_size": len(rebuilt),
        "inner_zip_sha256": _sha256(rebuilt),
        **inner_meta,
    }


def _restore_xor_cycle_inner_zip(ciphertext: bytes) -> Tuple[bytes, Dict[str, Any]]:
    if len(ciphertext) < 16 + 4096:
        raise HiddenResourceRestoreError("cyclic-XOR wrapper is too short")
    body = ciphertext[16:]
    candidates = _xor_cycle_key_candidates(ciphertext, 16)
    if not candidates:
        raise HiddenResourceRestoreError("no repeated cyclic-XOR key candidate found")
    prefixes = [
        b"PK\x03\x04\x0a\x00\x00\x08",
        b"PK\x03\x04\x14\x00\x00\x08",
        b"PK\x03\x04\x0a\x00\x00\x00",
        b"PK\x03\x04\x14\x00\x00\x00",
    ]
    failures: List[str] = []
    for key, repeats, key_offset in candidates[:256]:
        decoded = _xor_repeat(body, key)
        for prefix in prefixes:
            inner = prefix + decoded
            try:
                inner_meta = _inspect_inner_zip(inner)
                with zipfile.ZipFile(io.BytesIO(inner), "r") as zf:
                    bad = zf.testzip()
                    if bad is not None:
                        raise HiddenResourceRestoreError(
                            "inner ZIP CRC failed at " + str(bad)
                        )
                return inner, {
                    "restored": True,
                    "algorithm": "cyclic XOR archive restoration",
                    "wrapper_header_hex": ciphertext[:16].hex(),
                    "xor_period": len(key),
                    "xor_key_ascii": key.decode("ascii", "replace"),
                    "xor_key_sha256": _sha256(key),
                    "xor_key_repeated_hits": repeats,
                    "xor_key_first_offset": key_offset,
                    "zip_prefix_hex": prefix.hex(),
                    "inner_zip_size": len(inner),
                    "inner_zip_sha256": _sha256(inner),
                    **inner_meta,
                }
            except Exception as exc:
                if len(failures) < 16:
                    failures.append(
                        f"period={len(key)}/key@{key_offset}/hits={repeats}/"
                        f"prefix={prefix.hex()}: {type(exc).__name__}: {exc}"
                    )

    local_seen = set()
    for key, repeats, key_offset in candidates[:256]:
        primitive = _minimal_cycle(key)
        if primitive in local_seen:
            continue
        local_seen.add(primitive)
        try:
            inner, local_report = _restore_xor_local_entries(ciphertext, primitive)
            return inner, {
                **local_report,
                "wrapper_header_hex": ciphertext[:16].hex(),
                "xor_key_repeated_hits": repeats,
                "xor_key_first_offset": key_offset,
            }
        except Exception as exc:
            if len(failures) < 32:
                failures.append(
                    f"local/period={len(primitive)}/key@{key_offset}: "
                    f"{type(exc).__name__}: {exc}"
                )
    raise HiddenResourceRestoreError(
        "cyclic-XOR candidates did not produce a valid inner APK: "
        + " | ".join(failures[:16])
    )


# Backward-compatible names for older imports/log parsers.
def _xor40_key_candidates(blob: bytes, body_offset: int = 16):
    return [row for row in _xor_cycle_key_candidates(blob, body_offset)
            if len(row[0]) == 40]


def _restore_xor40_inner_zip(ciphertext: bytes):
    return _restore_xor_cycle_inner_zip(ciphertext)


def _find_xor40_wrappers(zf: zipfile.ZipFile, options: Optional[Dict[str, Any]] = None) -> List[Tuple[zipfile.ZipInfo, int]]:
    explicit, _ = _explicit_names(options)
    rows: List[Tuple[zipfile.ZipInfo, int]] = []
    for info in zf.infolist():
        if info.is_dir() or not (_MIN_CIPHER_SIZE <= info.file_size <= _MAX_CIPHER_SIZE):
            continue
        if explicit and info.filename != explicit:
            continue
        score = _candidate_score(info)
        if len(_normal_name(info.filename)) >= 1000:
            score += 80
        if info.file_size % 8:
            score += 15  # Aohan's wrapper is deliberately not DES aligned.
        if score >= 100:
            rows.append((info, score))
    rows.sort(key=lambda row: (-row[1], -row[0].file_size, row[0].filename))
    return rows[:16]

_IAPT_3LKS_MAGIC = b"3LKs"
_IAPT_3LKS_COUNT_XOR = 17303
_IAPT_3LKS_SIZE_XOR = 16008
_IAPT_3LKS_NAME_LENGTH_XOR = 12776
_IAPT_3LKS_NAME_STREAM_BASE = 146
_IAPT_3LKS_MARKER = "META-INF/iapt/3lks-restored.json"


def _iapt_int32(value: int) -> int:
    value &= 0xFFFFFFFF
    return value if value < 0x80000000 else value - 0x100000000


def _iapt_ushr(value: int, bits: int) -> int:
    return (value & 0xFFFFFFFF) >> bits


def _iapt_java_string_hash(value: str) -> int:
    result = 0
    for character in value:
        result = _iapt_int32(31 * result + ord(character))
    return result


def _iapt_3lks_member_key(name: str) -> int:
    value = (180 ^ 114) - 135
    hashed = _iapt_java_string_hash(name)
    hashed = _iapt_int32(hashed ^ _iapt_ushr(hashed, 16))
    hashed = _iapt_int32(hashed ^ _iapt_ushr(hashed, 8))
    value = _iapt_int32(value ^ hashed) & 0xFF
    return 90 if value == 0 else value


def _iapt_3lks_decrypt_member(name: str, encrypted: bytes) -> bytes:
    key = _iapt_3lks_member_key(name)
    length = len(encrypted)
    state = _iapt_int32(
        70464578 ^ _iapt_int32(-2080271008) ^ key ^ length
        ^ (48 << 8) ^ 29 ^ _iapt_int32(-1640531527)
    )
    if state == 0:
        state = _iapt_int32(324508639)
    output = bytearray(length)
    for index, byte in enumerate(encrypted):
        state = _iapt_int32(state ^ _iapt_int32(state << 13))
        state = _iapt_int32(state ^ _iapt_ushr(state, 17))
        state = _iapt_int32(state ^ _iapt_int32(state << 5))
        stream = _iapt_int32(
            state ^ _iapt_ushr(state, 8) ^ _iapt_ushr(state, 16)
            ^ _iapt_ushr(state, 24) ^ key ^ 48 ^ 29
        )
        output[index] = byte ^ (stream & 0xFF)
    return bytes(output)


def _parse_3lks_container(container: bytes) -> List[Tuple[str, bytes, bytes]]:
    if not container.startswith(_IAPT_3LKS_MAGIC) or len(container) < 12:
        raise HiddenResourceRestoreError("input is not a complete 3LKs container")
    offset = 4
    count = struct.unpack_from(">I", container, offset)[0] ^ _IAPT_3LKS_COUNT_XOR
    offset += 4
    if count < 1 or count > 10000:
        raise HiddenResourceRestoreError(f"3LKs member count is invalid: {count}")
    if offset + count * 4 > len(container):
        raise HiddenResourceRestoreError("3LKs size table is truncated")
    sizes: List[int] = []
    for _ in range(count):
        size = struct.unpack_from(">I", container, offset)[0] ^ _IAPT_3LKS_SIZE_XOR
        offset += 4
        if size < 0 or size > _MAX_MEMBER_SIZE:
            raise HiddenResourceRestoreError(f"3LKs member size is invalid: {size}")
        sizes.append(size)

    members: List[Tuple[str, bytes, bytes]] = []
    seen = set()
    for index, size in enumerate(sizes):
        if offset + 4 > len(container):
            raise HiddenResourceRestoreError("3LKs name length is truncated")
        name_len = (
            struct.unpack_from(">I", container, offset)[0]
            ^ _IAPT_3LKS_NAME_LENGTH_XOR
        )
        offset += 4
        if name_len < 1 or name_len > _MAX_NAME_LENGTH:
            raise HiddenResourceRestoreError(
                f"3LKs member {index} name length is invalid: {name_len}"
            )
        if offset + name_len + size > len(container):
            raise HiddenResourceRestoreError(f"3LKs member {index} exceeds container")
        encrypted_name = container[offset:offset + name_len]
        offset += name_len
        name_bytes = bytes(
            byte ^ ((_IAPT_3LKS_NAME_STREAM_BASE + pos) & 0xFF)
            for pos, byte in enumerate(encrypted_name)
        )
        try:
            name = name_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise HiddenResourceRestoreError(
                f"3LKs member {index} name is not UTF-8"
            ) from exc
        name = _normal_name(name)
        if not _safe_zip_name(name) or name.lower() in seen:
            raise HiddenResourceRestoreError(
                f"3LKs member {index} has unsafe/duplicate name: {name!r}"
            )
        seen.add(name.lower())
        encrypted = container[offset:offset + size]
        offset += size
        members.append((name, encrypted, _iapt_3lks_decrypt_member(name, encrypted)))
    if offset != len(container):
        raise HiddenResourceRestoreError(
            f"3LKs parser left {len(container) - offset} trailing bytes"
        )
    return members


def _iapt_3lks_target_name(name: str) -> str:
    norm = _normal_name(name).lstrip("/")
    low = norm.lower()
    if low == "lib.so":
        return "assets/lib.so"
    if low.startswith("assets/"):
        return norm
    if low.startswith("res/"):
        return "assets/" + norm
    return "assets/" + norm


def _restore_nested_3lks_zip(inner_bytes: bytes) -> Tuple[bytes, Dict[str, Any]]:
    """Restore a nested 3LKs resource bundle when canonical lib.so is absent/decoy."""
    try:
        with zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as source:
            infos = [x for x in source.infolist() if not x.is_dir()]
            canonical = [
                x for x in infos
                if _normal_name(x.filename).lower() == "assets/lib.so"
            ]
            canonical_data = source.read(canonical[0]) if canonical else b""
            if len(canonical_data) >= 64:
                return inner_bytes, {"nested_container": False}

            candidates: List[Tuple[int, str, bytes]] = []
            for info in infos:
                if info.file_size < 12:
                    continue
                try:
                    with source.open(info, "r") as handle:
                        head = handle.read(4)
                    if head == _IAPT_3LKS_MAGIC:
                        data = source.read(info)
                        candidates.append((len(data), info.filename, data))
                except Exception:
                    continue
            if not candidates:
                return inner_bytes, {"nested_container": False}
            candidates.sort(reverse=True)
            _, container_name, container = candidates[0]
            members = _parse_3lks_container(container)
            mapped: Dict[str, Tuple[str, bytes]] = {}
            member_rows: List[Dict[str, Any]] = []
            for name, encrypted, decoded in members:
                target = _iapt_3lks_target_name(name)
                low_target = target.lower()
                if not _safe_zip_name(target) or low_target in mapped:
                    raise HiddenResourceRestoreError(
                        f"3LKs mapped member is unsafe/duplicate: {target!r}"
                    )
                mapped[low_target] = (target, decoded)
                member_rows.append({
                    "name": name,
                    "target": target,
                    "encrypted_size": len(encrypted),
                    "size": len(decoded),
                    "sha256": _sha256(decoded),
                })
            lib_row = mapped.get("assets/lib.so")
            if lib_row is None or len(lib_row[1]) < 64:
                raise HiddenResourceRestoreError(
                    "3LKs did not produce a usable assets/lib.so"
                )

            output = io.BytesIO()
            written = set()
            with zipfile.ZipFile(output, "w", allowZip64=True) as target_zip:
                for info in infos:
                    name = _normal_name(info.filename)
                    low = name.lower()
                    if low in mapped or low == _IAPT_3LKS_MARKER.lower():
                        continue
                    if not _safe_zip_name(name) or low in written:
                        continue
                    target_zip.writestr(_clone_zipinfo(info, name), source.read(info))
                    written.add(low)
                for low, (name, decoded) in mapped.items():
                    zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    target_zip.writestr(zi, decoded)
                    written.add(low)
                marker = {
                    "mode": "static 3LKs member restoration",
                    "container_entry": container_name,
                    "container_size": len(container),
                    "container_sha256": _sha256(container),
                    "member_count": len(members),
                    "members": member_rows,
                }
                zi = zipfile.ZipInfo(
                    _IAPT_3LKS_MARKER,
                    date_time=(1980, 1, 1, 0, 0, 0),
                )
                zi.compress_type = zipfile.ZIP_DEFLATED
                target_zip.writestr(
                    zi,
                    json.dumps(marker, ensure_ascii=False, indent=2).encode("utf-8"),
                )
            rebuilt = output.getvalue()
            with zipfile.ZipFile(io.BytesIO(rebuilt), "r") as check:
                bad = check.testzip()
                if bad is not None:
                    raise HiddenResourceRestoreError(
                        "3LKs rebuilt ZIP CRC failed at " + str(bad)
                    )
                restored_lib = check.read("assets/lib.so")
            return rebuilt, {
                "nested_container": True,
                "nested_algorithm": "3LKs static member transform",
                "nested_entry": container_name,
                "nested_size": len(container),
                "nested_sha256": _sha256(container),
                "nested_member_count": len(members),
                "nested_assets_lib_size": len(restored_lib),
                "nested_assets_lib_sha256": _sha256(restored_lib),
            }
    except zipfile.BadZipFile as exc:
        raise HiddenResourceRestoreError(
            "inner ZIP is corrupt before 3LKs restore"
        ) from exc


def _inspect_inner_zip(data: bytes) -> Dict[str, Any]:
    if len(data) < 4 or data[:2] != b"PK":
        raise HiddenResourceRestoreError("DES plaintext is not a ZIP")
    try:
        with zipfile.ZipFile(io.BytesIO(data), "r") as inner:
            infos = inner.infolist()
            if not infos or len(infos) > _MAX_INNER_ENTRIES:
                raise HiddenResourceRestoreError("inner ZIP entry count is invalid")
            total = 0
            names = set()
            for info in infos:
                name = _normal_name(info.filename)
                if len(name) > _MAX_NAME_LENGTH or name.count("/") > _MAX_PATH_DEPTH:
                    raise HiddenResourceRestoreError("inner ZIP contains an excessive path")
                if not _safe_zip_name(name):
                    raise HiddenResourceRestoreError("inner ZIP contains an unsafe path")
                if info.file_size < 0 or info.file_size > _MAX_MEMBER_SIZE:
                    raise HiddenResourceRestoreError("inner ZIP contains an excessive member")
                total += int(info.file_size)
                if total > _MAX_INNER_UNCOMPRESSED:
                    raise HiddenResourceRestoreError("inner ZIP uncompressed size limit exceeded")
                names.add(name.lower())
            if "assets/lib.so" not in names:
                raise HiddenResourceRestoreError("inner ZIP misses assets/lib.so")
            # Reading these entries validates their local headers and CRC values.
            lib_name = next(x.filename for x in infos if _normal_name(x.filename).lower() == "assets/lib.so")
            lib_data = inner.read(lib_name)
            meta: Dict[str, Any] = {
                "entry_count": len(infos),
                "uncompressed_size": total,
                "assets_lib_size": len(lib_data),
                "assets_lib_sha256": _sha256(lib_data),
            }
            if "androidmanifest.xml" in names:
                manifest_name = next(x.filename for x in infos if _normal_name(x.filename).lower() == "androidmanifest.xml")
                meta["manifest_size"] = len(inner.read(manifest_name))
            if "resources.arsc" in names:
                arsc_name = next(x.filename for x in infos if _normal_name(x.filename).lower() == "resources.arsc")
                meta["resources_arsc_size"] = len(inner.read(arsc_name))
            if "assets/extra_conf1g.xml" in names:
                extra_name = next(x.filename for x in infos if _normal_name(x.filename).lower() == "assets/extra_conf1g.xml")
                meta["extra_conf1g_size"] = len(inner.read(extra_name))
            return meta
    except zipfile.BadZipFile as exc:
        raise HiddenResourceRestoreError("DES plaintext ZIP is corrupt") from exc



def _report_entry_name(name: Any, limit: int = 240) -> str:
    """Keep pathological anti-analysis ZIP names out of logs/reports."""
    text = str(name or "")
    if len(text) <= limit:
        return text
    norm = _normal_name(text)
    depth = norm.count("/")
    tail = norm[-72:]
    digest = hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()[:16]
    return f"<deep-path length={len(text)} depth={depth} sha256={digest} tail={tail!r}>"


def _resource_source_graph(report: Dict[str, Any]) -> Dict[str, Any]:
    """Describe how the canonical assets/lib.so was reached.

    The graph is diagnostic metadata used by the V3 caller; it does not choose
    algorithms.  Every edge corresponds to a parser/decryptor that already
    validated its complete output structure.
    """
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []
    algorithm = str(report.get("algorithm") or "")
    cipher = _report_entry_name(report.get("cipher_entry") or "")
    if cipher:
        nodes.append({"id": "outer-resource", "kind": "apk-entry", "name": cipher})
    if report.get("sidecar_entry"):
        nodes.append({"id": "sidecar", "kind": "apk-entry", "name": _report_entry_name(report.get("sidecar_entry"))})
    if algorithm:
        nodes.append({"id": "transport", "kind": "transform", "name": algorithm})
        edges.append({"from": "outer-resource", "to": "transport", "role": "ciphertext"})
        if report.get("sidecar_entry"):
            edges.append({"from": "sidecar", "to": "transport", "role": "key-material"})
    nodes.append({"id": "inner-zip", "kind": "zip", "size": int(report.get("inner_zip_size") or 0)})
    if algorithm:
        edges.append({"from": "transport", "to": "inner-zip", "role": "decoded"})
    if report.get("nested_container"):
        nodes.append({"id": "nested-3lks", "kind": "container", "name": _report_entry_name(report.get("nested_entry") or ""), "algorithm": str(report.get("nested_algorithm") or "")})
        edges.append({"from": "inner-zip", "to": "nested-3lks", "role": "contains"})
        nodes.append({"id": "canonical-lib", "kind": "apk-entry", "name": "assets/lib.so", "size": int(report.get("nested_assets_lib_size") or report.get("assets_lib_size") or 0)})
        edges.append({"from": "nested-3lks", "to": "canonical-lib", "role": "restores"})
    else:
        nodes.append({"id": "canonical-lib", "kind": "apk-entry", "name": "assets/lib.so", "size": int(report.get("assets_lib_size") or 0)})
        edges.append({"from": "inner-zip", "to": "canonical-lib", "role": "contains"})
    return {"nodes": nodes, "edges": edges, "candidate_count": 1}


def restore_hidden_resource_zip(
    apk_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Tuple[bytes, Dict[str, Any]]:
    apk_path = Path(apk_path)
    if not apk_path.is_file() or not zipfile.is_zipfile(apk_path):
        raise HiddenResourceRestoreError("input is not a readable APK/ZIP")

    failures: List[str] = []
    with zipfile.ZipFile(apk_path, "r") as outer:
        canonical_info = next(
            (
                x for x in outer.infolist()
                if (not x.is_dir())
                and _normal_name(x.filename).lower() == "assets/lib.so"
            ),
            None,
        )
        if canonical_info is not None and int(canonical_info.file_size or 0) >= 64:
            with outer.open(canonical_info, "r") as stream:
                if len(stream.read(64)) == 64:
                    raise HiddenResourceRestoreError("canonical assets/lib.so already exists")
        pairs = _find_pairs(outer, options)

        for cipher_info, sidecar_info, score in pairs:
            try:
                sidecar = outer.read(sidecar_info)
                key_meta = derive_des_key_from_sidecar(sidecar)
                ciphertext = outer.read(cipher_info)
                plain_padded = _des_ecb_decrypt(ciphertext, key_meta["key"])
                plain = _pkcs7_unpad(plain_padded, 8)
                plain, nested_meta = _restore_nested_3lks_zip(plain)
                inner_meta = _inspect_inner_zip(plain)
                report: Dict[str, Any] = {
                    "restored": True,
                    "algorithm": "DES/ECB/PKCS5Padding",
                    "cipher_entry": _report_entry_name(cipher_info.filename),
                    "cipher_size": len(ciphertext),
                    "cipher_sha256": _sha256(ciphertext),
                    "sidecar_entry": _report_entry_name(sidecar_info.filename),
                    "sidecar_size": len(sidecar),
                    "locator_score": score,
                    "position_digits": key_meta["position_digits"],
                    "key_position": key_meta["key_position"],
                    "des_key_sha256": key_meta["key_sha256"],
                    "inner_zip_size": len(plain),
                    "inner_zip_sha256": _sha256(plain),
                    **nested_meta,
                    **inner_meta,
                }
                report["resource_source_graph"] = _resource_source_graph(report)
                return plain, report
            except Exception as exc:
                failures.append(
                    f"{cipher_info.filename[-80:]!r} + {sidecar_info.filename[-80:]!r}: "
                    f"{type(exc).__name__}: {exc}"
                )

        # Cyclic-XOR anti-encryption path: no sidecar, a 16-byte wrapper
        # header, then a variable-period XOR archive. It is tried only after
        # the DES sidecar format so the two families never get mixed.
        for cipher_info, score in _find_xor40_wrappers(outer, options):
            try:
                ciphertext = outer.read(cipher_info)
                plain, xor_report = _restore_xor_cycle_inner_zip(ciphertext)
                report = {
                    **xor_report,
                    "cipher_entry": _report_entry_name(cipher_info.filename),
                    "cipher_size": len(ciphertext),
                    "cipher_sha256": _sha256(ciphertext),
                    "locator_score": score,
                }
                report["resource_source_graph"] = _resource_source_graph(report)
                return plain, report
            except Exception as exc:
                failures.append(
                    f"{cipher_info.filename[-80:]!r}: {type(exc).__name__}: {exc}"
                )
    raise HiddenResourceRestoreError(
        "long-path wrapper candidates did not decrypt to a valid resource ZIP; "
        + " | ".join(failures[:8])
    )


def _clone_zipinfo(info: zipfile.ZipInfo, filename: Optional[str] = None) -> zipfile.ZipInfo:
    out = zipfile.ZipInfo(filename=filename or info.filename, date_time=info.date_time)
    out.compress_type = info.compress_type
    out.comment = info.comment
    out.extra = b""  # do not propagate malformed/oversized custom extra fields
    out.internal_attr = info.internal_attr
    out.external_attr = info.external_attr
    out.create_system = info.create_system
    out.flag_bits = info.flag_bits & 0x800  # keep UTF-8 name flag only
    return out


def _drop_signature(name: str) -> bool:
    low = _normal_name(name).lower()
    if not low.startswith("meta-inf/"):
        return False
    base = low.rsplit("/", 1)[-1]
    return base == "manifest.mf" or base.endswith((".sf", ".rsa", ".dsa", ".ec"))


def _option_truthy(options: Optional[Dict[str, Any]], key: str) -> bool:
    value = (options or {}).get(key)
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value or "").strip().lower() in {"1", "true", "yes", "on", "y"}


def build_normalized_apk(
    apk_path: Path | str,
    output_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Overlay statically restored inner resources on the uploaded compact APK.

    This fixes QiuShui samples whose verifier depends on inner resources such as
    assets/extra_conf1g.xml, AndroidManifest.xml, resources.arsc, or res/*.
    It still preserves outer DEX and native libraries, so feature 17 remains a
    resource/container normalization pre-step and never performs code or source
    deobfuscation by itself.
    """
    apk_path = Path(apk_path)
    output_path = Path(output_path)
    lib_only = (
        _option_truthy(options, "no_decrypt_resource_files")
        or _option_truthy(options, "skip_anti_resources")
    )
    inner_bytes, report = restore_hidden_resource_zip(apk_path, options)
    report["lib_only"] = bool(lib_only)
    report["ordinary_resources_restored"] = not bool(lib_only)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(apk_path, "r") as outer, zipfile.ZipFile(io.BytesIO(inner_bytes), "r") as inner:
        inner_infos = [x for x in inner.infolist() if not x.is_dir()]
        inner_names = {_normal_name(x.filename).lower() for x in inner_infos}
        written = set()
        with zipfile.ZipFile(output_path, "w", allowZip64=True) as out:
            def _preserve_outer_code(low_name: str) -> bool:
                base = low_name.rsplit("/", 1)[-1]
                return (low_name.startswith("lib/") or
                        (base.startswith("classes") and base.endswith(".dex")))

            def _allow_inner_overlay(low_name: str) -> bool:
                if lib_only:
                    return (
                        low_name == "assets/lib.so"
                        or low_name.startswith("bsh/quishui/")
                        or low_name.startswith("bsh/util/lib/")
                        or (low_name.startswith("assets/libtosks") and low_name.endswith(".so"))
                        or low_name in {
                            "assets/extra_conf1g.xml",
                            "assets/userencryption.xml",
                            "assets/.jgapp",
                            "assets/jgapp",
                            "epic.vm",
                        }
                    )
                base = low_name.rsplit("/", 1)[-1]
                if low_name.startswith("lib/"):
                    return False
                if base.startswith("classes") and base.endswith(".dex"):
                    return False
                return True

            def _allow_outer_copy(low_name: str) -> bool:
                if not lib_only:
                    return True
                return (
                    not low_name.startswith("assets/")
                    or low_name in {
                        "assets/lib.so",
                        "assets/extra_conf1g.xml",
                        "assets/userencryption.xml",
                        "assets/.jgapp",
                        "assets/jgapp",
                    }
                    or (low_name.startswith("assets/libtosks") and low_name.endswith(".so"))
                )

            overlay_names = {name for name in inner_names if _allow_inner_overlay(name)}

            for info in outer.infolist():
                if info.is_dir():
                    continue
                name = _normal_name(info.filename)
                low = name.lower()
                if ((low in overlay_names and not _preserve_outer_code(low)) or
                        _drop_signature(name) or not _allow_outer_copy(low)):
                    continue
                # Do not carry the malicious deep wrapper into the normalized APK.
                if len(name) > 2048 or name.count("/") > 128:
                    continue
                if not _safe_zip_name(name) or low in written:
                    continue
                out.writestr(_clone_zipinfo(info, name), outer.read(info))
                written.add(low)

            for info in inner_infos:
                name = _normal_name(info.filename)
                low = name.lower()
                if (not _allow_inner_overlay(low) or _drop_signature(name) or
                        not _safe_zip_name(name) or low in written):
                    continue
                out.writestr(_clone_zipinfo(info, name), inner.read(info))
                written.add(low)

            marker = {
                "mode": (
                    "static hidden-resource lib.so-only overlay"
                    if lib_only
                    else "static hidden-resource ZIP overlay; outer DEX/native preserved; no APK code executed"
                ),
                "source_apk": apk_path.name,
                **report,
            }
            marker_info = zipfile.ZipInfo(_MARKER_NAME, date_time=(1980, 1, 1, 0, 0, 0))
            marker_info.compress_type = zipfile.ZIP_DEFLATED
            out.writestr(marker_info, json.dumps(marker, ensure_ascii=False, indent=2).encode("utf-8"))

    if not zipfile.is_zipfile(output_path):
        raise HiddenResourceRestoreError("normalized APK was not written as a valid ZIP")
    with zipfile.ZipFile(output_path, "r") as check:
        low_to_info = {_normal_name(x.filename).lower(): x for x in check.infolist() if not x.is_dir()}
        if "assets/lib.so" not in low_to_info:
            raise HiddenResourceRestoreError("normalized APK misses assets/lib.so")
        lib_data = check.read(low_to_info["assets/lib.so"])
        if len(lib_data) < 64:
            raise HiddenResourceRestoreError("normalized assets/lib.so is unexpectedly short")
        report.update({
            "normalized": True,
            "overlay_mode": (
                "inner-lib-so-only-preserve-outer-code-native"
                if lib_only
                else "inner-resources-preserve-outer-code-native"
            ),
            "normalized_apk": str(output_path),
            "normalized_apk_size": output_path.stat().st_size,
            "normalized_apk_sha256": hashlib.sha256(output_path.read_bytes()).hexdigest(),
            "normalized_entry_count": len(check.infolist()),
            "overlay_count": sum(1 for x in check.infolist() if _normal_name(x.filename).lower() in {"androidmanifest.xml", "resources.arsc", "assets/lib.so", "assets/extra_conf1g.xml", "assets/userencryption.xml", "assets/.jgapp", "assets/jgapp"} or _normal_name(x.filename).lower().startswith("res/") or _normal_name(x.filename).lower().startswith("assets/res/")),
        })
    return report



# IAPT_STATIC_ASSET_WRAPPER_V2_BEGIN
# Static transport-wrapper recovery.  This layer never changes the normal iApp
# crypto implementation: it only restores bytes that a protector transformed
# before putting the canonical encrypted assets/lib.so into the APK.

_STATIC_WRAPPER_MAX_CANDIDATES = 2
_STATIC_WRAPPER_MAX_PROBE_FILE = 16 * 1024 * 1024
_STATIC_WRAPPER_CONTROL_NAMES = {
    "assets/extra_conf1g.xml",
    "assets/userencryption.xml",
    "assets/.jgapp",
    "assets/jgapp",
}


def _printable_ratio(blob: bytes) -> float:
    blob = bytes(blob or b"")
    if not blob:
        return 0.0
    return sum(1 for value in blob if value in (9, 10, 13) or 32 <= value < 127) / float(len(blob))


def _minimal_period(value: bytes, maximum: int = 32) -> bytes:
    value = bytes(value or b"")
    if not value:
        return b""
    upper = min(len(value), max(1, int(maximum)))
    for size in range(1, upper + 1):
        if all(value[index] == value[index % size] for index in range(len(value))):
            return value[:size]
    return value


def _static_transform_id(transform: Dict[str, Any]) -> str:
    kind = str(transform.get("kind") or "")
    if kind == "xor-repeat":
        return kind + ":" + bytes(transform.get("key") or b"").hex()
    if kind in {"add-byte", "rol-byte", "ror-byte"}:
        return kind + ":" + str(int(transform.get("value") or 0) & 0xFF)
    return kind


def _static_transform_public(transform: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(transform.get("kind") or "")
    result: Dict[str, Any] = {"kind": kind}
    if kind == "xor-repeat":
        key = bytes(transform.get("key") or b"")
        result.update({"key_hex": key.hex(), "key_length": len(key)})
    else:
        result["value"] = int(transform.get("value") or 0) & 0xFF
    return result


def _rol8(value: int, bits: int) -> int:
    bits &= 7
    value &= 0xFF
    return ((value << bits) | (value >> ((8 - bits) & 7))) & 0xFF


def _ror8(value: int, bits: int) -> int:
    bits &= 7
    value &= 0xFF
    return ((value >> bits) | (value << ((8 - bits) & 7))) & 0xFF


def _apply_static_transform(data: bytes, transform: Dict[str, Any]) -> bytes:
    data = bytes(data or b"")
    kind = str(transform.get("kind") or "")
    if kind == "xor-repeat":
        key = bytes(transform.get("key") or b"")
        if not key:
            raise HiddenResourceRestoreError("static XOR wrapper key is empty")
        return bytes((value ^ key[index % len(key)]) for index, value in enumerate(data))
    if kind == "add-byte":
        delta = int(transform.get("value") or 0) & 0xFF
        return bytes(((value + delta) & 0xFF) for value in data)
    if kind == "rol-byte":
        bits = int(transform.get("value") or 0) & 7
        return bytes(_rol8(value, bits) for value in data)
    if kind == "ror-byte":
        bits = int(transform.get("value") or 0) & 7
        return bytes(_ror8(value, bits) for value in data)
    raise HiddenResourceRestoreError("unsupported static asset transform: " + kind)


def _expected_prefixes(low_name: str) -> List[Tuple[bytes, str, int]]:
    low = _normal_name(low_name).lower()
    result: List[Tuple[bytes, str, int]] = []
    if low == "epic.vm":
        result.append((b"Epic", "Epic VM header", 7))
    if low.endswith(".epic") or low.endswith(".dex"):
        for version in (b"035", b"036", b"037", b"038", b"039", b"040", b"041"):
            result.append((b"dex\n" + version + b"\x00", "DEX header", 8))
    if low.endswith(".xml"):
        result.extend([
            (b"<signature>", "signature XML", 14),
            (b"<ok>", "user-encryption XML", 12),
            (b"<?xml", "XML declaration", 10),
            (b"<config", "configuration XML", 9),
        ])
    if low.endswith((".zip", ".jar", ".apk")):
        result.append((b"PK\x03\x04", "ZIP header", 7))
    if low.endswith(".so") and low != "assets/lib.so":
        result.append((b"\x7fELF", "ELF header", 7))
    return result


_GLOBAL_MAGIC_PREFIXES: Tuple[Tuple[bytes, str, int], ...] = (
    (b"PK\x03\x04", "ZIP header", 5),
    (b"\x7fELF", "ELF header", 5),
    (b"dex\n035\x00", "DEX 035 header", 6),
    (b"dex\n036\x00", "DEX 036 header", 6),
    (b"dex\n037\x00", "DEX 037 header", 6),
    (b"dex\n038\x00", "DEX 038 header", 6),
    (b"dex\n039\x00", "DEX 039 header", 6),
    (b"dex\n040\x00", "DEX 040 header", 6),
    (b"\x89PNG\r\n\x1a\n", "PNG header", 4),
    (b"\x1f\x8b\x08", "gzip header", 3),
    (b"SQLite format 3\x00", "SQLite header", 5),
    (b"Epic", "Epic VM header", 4),
)


def _decoded_asset_quality(low_name: str, blob: bytes) -> Tuple[int, str]:
    low = _normal_name(low_name).lower()
    blob = bytes(blob or b"")
    head = blob[:128]
    if low == "assets/extra_conf1g.xml" and b"<signature>" in blob[:4096] and b"</signature>" in blob[:4096]:
        return 18, "valid signature XML"
    if low == "assets/userencryption.xml" and b"<ok>" in blob[:4096] and b"</ok>" in blob[:4096]:
        return 16, "valid user-encryption XML"
    if low.endswith(".xml") and head.lstrip().startswith(b"<") and b">" in head:
        return 10, "plausible XML"
    if blob.startswith(b"dex\n") and len(blob) >= 0x70:
        try:
            file_size = struct.unpack_from("<I", blob, 0x20)[0]
            header_size = struct.unpack_from("<I", blob, 0x24)[0]
            endian_tag = struct.unpack_from("<I", blob, 0x28)[0]
            if header_size == 0x70 and endian_tag == 0x12345678 and file_size >= 0x70:
                return 16, "valid DEX header"
        except Exception:
            pass
        return 0, ""
    for prefix, label, score in _expected_prefixes(low):
        if blob.startswith(prefix):
            return score, label
    for prefix, label, score in _GLOBAL_MAGIC_PREFIXES:
        if blob.startswith(prefix):
            return score, label
    if low in {"assets/.jgapp", "assets/jgapp"} and _printable_ratio(blob[:2048]) >= 0.90:
        return 7, "printable control text"
    return 0, ""


def _infer_transform_from_prefix(raw: bytes, plain_prefix: bytes) -> List[Dict[str, Any]]:
    raw = bytes(raw or b"")
    plain_prefix = bytes(plain_prefix or b"")
    if len(plain_prefix) < 3 or len(raw) < len(plain_prefix):
        return []
    cipher = raw[:len(plain_prefix)]
    found: List[Dict[str, Any]] = []

    xor_key = _minimal_period(bytes((cipher[index] ^ plain_prefix[index]) for index in range(len(plain_prefix))))
    if xor_key and len(xor_key) <= 32 and any(xor_key):
        transform = {"kind": "xor-repeat", "key": xor_key}
        if _apply_static_transform(cipher, transform) == plain_prefix:
            found.append(transform)

    deltas = [((plain_prefix[index] - cipher[index]) & 0xFF) for index in range(len(plain_prefix))]
    if deltas and len(set(deltas)) == 1 and deltas[0] != 0:
        transform = {"kind": "add-byte", "value": deltas[0]}
        if _apply_static_transform(cipher, transform) == plain_prefix:
            found.append(transform)

    for bits in range(1, 8):
        if all(_rol8(cipher[index], bits) == plain_prefix[index] for index in range(len(plain_prefix))):
            found.append({"kind": "rol-byte", "value": bits})
        if all(_ror8(cipher[index], bits) == plain_prefix[index] for index in range(len(plain_prefix))):
            found.append({"kind": "ror-byte", "value": bits})
    return found


def _candidate_asset_entries(zf: zipfile.ZipFile) -> List[zipfile.ZipInfo]:
    infos: List[zipfile.ZipInfo] = []
    for info in zf.infolist():
        if info.is_dir() or int(info.file_size or 0) < 3 or int(info.file_size or 0) > _STATIC_WRAPPER_MAX_PROBE_FILE:
            continue
        low = _normal_name(info.filename).lower()
        if (low == "assets/lib.so" or low.startswith("meta-inf/") or low.startswith("lib/")
                or low.startswith("res/") or low.startswith("assets/res/") or low == "androidmanifest.xml"):
            continue
        # Probe control files, VM/DEX blobs and opaque top-level/assets blobs.
        if (low in _STATIC_WRAPPER_CONTROL_NAMES or low == "epic.vm" or low.endswith((".epic", ".dex", ".xml", ".zip", ".jar", ".apk")) or low.startswith("assets/")):
            infos.append(info)
    infos.sort(key=lambda item: (0 if _normal_name(item.filename).lower() in _STATIC_WRAPPER_CONTROL_NAMES else 1, int(item.file_size or 0), item.filename))
    return infos[:96]


def _asset_wrapper_scope(low_name: str) -> str:
    """Classify evidence by the runtime subsystem that consumes the asset.

    EPIC VM/DEX payloads use a protector-specific transport key and must not be
    treated as evidence that the same key wraps iApp's assets/lib.so.  iApp
    control files are directly coupled to the lib.so decrypt path.
    """
    low = _normal_name(low_name).lower()
    if low == "epic.vm" or low.startswith("assets/epic/") or low.endswith(".epic"):
        return "epic-dex"
    if low in _STATIC_WRAPPER_CONTROL_NAMES:
        return "iapp-control"
    return "generic-asset"


def _zip_stage_distance_seconds(left: Optional[zipfile.ZipInfo], right: Optional[zipfile.ZipInfo]) -> Optional[int]:
    if left is None or right is None:
        return None
    try:
        a = datetime.datetime(*left.date_time)
        b = datetime.datetime(*right.date_time)
        return int(abs((a - b).total_seconds()))
    except Exception:
        return None


def _native_library_scope(name: str, blob: bytes) -> str:
    """Cheaply classify a native library before expensive disassembly."""
    low = _normal_name(name).lower()
    data = bytes(blob or b"")
    if b"dex_protection_xor_key" in data and b".Epic" in data:
        return "epic-dex"
    if b"lib.so" in data and (b"LuaStateFactory" in data or b"com/iapp/app" in data):
        return "iapp-container"
    if any(token in low for token in ("protect", "shell", "jiagu", "guard", "reinforce")):
        return "generic-protector"
    return "unrelated"


def _probe_native_transform_operations(zf: zipfile.ZipFile, transforms: List[Dict[str, Any]]) -> Dict[str, List[str]]:
    """Corroborate simple transform constants in native code without loading it.

    The known-plaintext evidence remains authoritative.  Disassembly only raises
    confidence and can supply fallback single-byte candidates when two ABIs show
    the same immediate byte operation.  Failure to find llvm-objdump/objdump is
    non-fatal.
    """
    wanted: Dict[Tuple[str, int], str] = {}
    for transform in transforms:
        kind = str(transform.get("kind") or "")
        if kind == "xor-repeat" and len(bytes(transform.get("key") or b"")) == 1:
            wanted[("xor", bytes(transform.get("key") or b"")[0])] = _static_transform_id(transform)
        elif kind == "add-byte":
            wanted[("add", int(transform.get("value") or 0) & 0xFF)] = _static_transform_id(transform)
        elif kind in {"rol-byte", "ror-byte"}:
            wanted[(kind[:3], int(transform.get("value") or 0) & 7)] = _static_transform_id(transform)
    if not wanted:
        return {}

    tool = shutil.which("llvm-objdump") or shutil.which("objdump")
    if not tool:
        return {}
    native_infos: List[zipfile.ZipInfo] = []
    for info in zf.infolist():
        low = _normal_name(info.filename).lower()
        if (info.is_dir() or not low.startswith("lib/") or not low.endswith(".so")
                or not 4096 <= int(info.file_size or 0) <= 64 * 1024 * 1024):
            continue
        try:
            blob = zf.read(info)
        except Exception:
            continue
        scope = _native_library_scope(low, blob)
        # For assets/lib.so candidate selection, EPIC's own DEX transport and
        # unrelated native libraries are noise.  Disassemble only code that is
        # statically tied to the iApp container or a generic protector.
        if scope not in {"iapp-container", "generic-protector"}:
            continue
        native_infos.append(info)
    native_infos.sort(key=lambda info: (
        0 if _normal_name(info.filename).lower().endswith("libygsiyu.so") else 1,
        int(info.file_size or 0),
    ))
    evidence: Dict[str, List[str]] = {}
    with tempfile.TemporaryDirectory(prefix="iapt-static-so-") as tmp:
        root = Path(tmp)
        for index, info in enumerate(native_infos[:6]):
            path = root / (str(index) + "-" + Path(_normal_name(info.filename)).name)
            try:
                path.write_bytes(zf.read(info))
                proc = subprocess.run(
                    [tool, "-d", "--no-show-raw-insn", str(path)],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    check=False,
                    timeout=20,
                )
                text = proc.stdout.decode("utf-8", "replace").lower()
            except Exception:
                continue
            for (op, value), transform_id in wanted.items():
                hexv = format(value, "x")
                decv = str(value)
                if op == "xor":
                    patterns = [
                        rf"\b(?:eor|xor[a-z]*)\b[^\n]*(?:#|\$)0x0*{hexv}\b",
                        rf"\b(?:eor|xor[a-z]*)\b[^\n]*(?:#|\$){decv}\b",
                    ]
                elif op == "add":
                    patterns = [
                        rf"\b(?:add|sub)[a-z]*\b[^\n]*(?:#|\$)0x0*{hexv}\b",
                        rf"\b(?:add|sub)[a-z]*\b[^\n]*(?:#|\$){decv}\b",
                    ]
                else:
                    patterns = [rf"\b(?:rol|ror|lsl|lsr)[a-z]*\b[^\n]*(?:#|\$)(?:0x0*{hexv}|{decv})\b"]
                if any(re.search(pattern, text) for pattern in patterns):
                    evidence.setdefault(transform_id, []).append(_normal_name(info.filename) + ":" + op + "-imm-" + str(value))
    return evidence




def probe_static_asset_wrappers(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """Infer a very small set of transport transforms for ``assets/lib.so``.

    The inference is evidence-driven rather than transform-driven.  A candidate
    must restore a complete known control/asset structure, improve over the raw
    bytes, and belong to the iApp container build stage.  EPIC-only DEX/VM
    evidence is retained for diagnostics but can never nominate a lib.so
    transform by itself.  The unchanged normal decryptor remains the final
    verifier in :mod:`v3_entry`.
    """
    infos = zf.infolist()
    lib_info = next(
        (
            item
            for item in infos
            if not item.is_dir()
            and _normal_name(item.filename).lower() == "assets/lib.so"
            and int(item.file_size or 0) >= 64
        ),
        None,
    )
    if lib_info is None:
        return []

    grouped: Dict[str, Dict[str, Any]] = {}
    for info in _candidate_asset_entries(zf):
        low = _normal_name(info.filename).lower()
        try:
            raw = zf.read(info)
        except Exception:
            continue
        before_score, before_reason = _decoded_asset_quality(low, raw)
        for prefix, prefix_label, _prefix_weight in _expected_prefixes(low):
            for transform in _infer_transform_from_prefix(raw, prefix):
                try:
                    restored = _apply_static_transform(raw, transform)
                except Exception:
                    continue
                after_score, after_reason = _decoded_asset_quality(low, restored)
                # Prefix algebra alone is not evidence.  The full file must
                # become more structurally plausible than the original bytes.
                if after_score < 7 or after_score <= before_score:
                    continue
                transform_id = _static_transform_id(transform)
                if not transform_id:
                    continue
                scope = _asset_wrapper_scope(low)
                distance = _zip_stage_distance_seconds(info, lib_info)
                row = grouped.setdefault(
                    transform_id,
                    {
                        "transform": dict(transform),
                        "transform_id": transform_id,
                        "evidence_rows": [],
                        "evidence": [],
                        "native_evidence": [],
                        "score": 0,
                    },
                )
                evidence_row = {
                    "entry": _normal_name(info.filename),
                    "scope": scope,
                    "quality": int(after_score),
                    "reason": after_reason or prefix_label,
                    "raw_quality": int(before_score),
                    "raw_reason": before_reason,
                    "stage_distance_seconds": distance,
                }
                # Avoid counting several guessed XML prefixes for one entry.
                existing = next(
                    (
                        old
                        for old in row["evidence_rows"]
                        if old.get("entry") == evidence_row["entry"]
                        and old.get("scope") == evidence_row["scope"]
                    ),
                    None,
                )
                if existing is None or int(evidence_row["quality"]) > int(existing.get("quality") or 0):
                    if existing is not None:
                        row["evidence_rows"].remove(existing)
                    row["evidence_rows"].append(evidence_row)

    if not grouped:
        return []

    transforms = [dict(row["transform"]) for row in grouped.values()]
    # Complete iApp control-file recovery is already strong proof.  Avoid the
    # expensive native disassembly pass unless at least one transform lacks
    # such proof and would need generic/native corroboration.
    native_probe_transforms: List[Dict[str, Any]] = []
    for candidate_row in grouped.values():
        evidence_rows = list(candidate_row.get("evidence_rows") or [])
        candidate_controls = [
            item for item in evidence_rows
            if item.get("scope") == "iapp-control"
            and int(item.get("quality") or 0) >= 14
            and (
                item.get("stage_distance_seconds") is None
                or int(item.get("stage_distance_seconds") or 0) <= 60
            )
        ]
        non_epic = [item for item in evidence_rows if item.get("scope") != "epic-dex"]
        near_non_epic = [
            item for item in non_epic
            if item.get("stage_distance_seconds") is not None
            and int(item.get("stage_distance_seconds") or 0) <= 60
        ]
        # Native corroboration is useful only for the generic-consensus path.
        # EPIC-only transforms can never nominate assets/lib.so and complete
        # iApp control evidence is already authoritative.
        if (not candidate_controls and len({item.get("entry") for item in non_epic}) >= 2 and near_non_epic):
            native_probe_transforms.append(dict(candidate_row["transform"]))
    native_map = _probe_native_transform_operations(zf, native_probe_transforms) if native_probe_transforms else {}
    accepted: List[Dict[str, Any]] = []
    for transform_id, row in grouped.items():
        evidence_rows = list(row.get("evidence_rows") or [])
        controls = [x for x in evidence_rows if x.get("scope") == "iapp-control"]
        non_epic = [x for x in evidence_rows if x.get("scope") != "epic-dex"]
        near = [
            x
            for x in non_epic
            if x.get("stage_distance_seconds") is not None
            and int(x["stage_distance_seconds"]) <= 60
        ]
        exact_control = [
            x
            for x in controls
            if int(x.get("quality") or 0) >= 14
            and (
                x.get("stage_distance_seconds") is None
                or int(x["stage_distance_seconds"]) <= 60
            )
        ]
        native_evidence = sorted(set(native_map.get(transform_id) or []))

        # Strong path: a complete iApp control file is restored in the same ZIP
        # stage as lib.so.  Generic opaque assets need at least two independent
        # structures plus a native consumer corroboration; one magic prefix is
        # deliberately insufficient.
        strong_control = bool(exact_control)
        generic_consensus = bool(
            len({x.get("entry") for x in non_epic}) >= 2
            and near
            and native_evidence
        )
        if not (strong_control or generic_consensus):
            continue

        score = sum(int(x.get("quality") or 0) for x in non_epic)
        score += 80 if strong_control else 0
        score += 25 if generic_consensus else 0
        score += min(20, 4 * len(native_evidence))
        for item in near:
            distance = int(item.get("stage_distance_seconds") or 0)
            score += 24 if distance <= 12 else 10
        row["score"] = int(score)
        row["native_evidence"] = native_evidence
        row["evidence"] = [
            "%s:%s:scope=%s:distance=%s"
            % (
                item.get("entry"),
                item.get("reason"),
                item.get("scope"),
                item.get("stage_distance_seconds"),
            )
            for item in sorted(
                evidence_rows,
                key=lambda x: (
                    0 if x.get("scope") == "iapp-control" else 1,
                    -(int(x.get("quality") or 0)),
                    str(x.get("entry") or ""),
                ),
            )
        ]
        row["scope_summary"] = sorted({str(x.get("scope")) for x in evidence_rows})
        accepted.append(row)

    accepted.sort(
        key=lambda row: (
            -int(row.get("score") or 0),
            len(bytes((row.get("transform") or {}).get("key") or b""))
            if str((row.get("transform") or {}).get("kind")) == "xor-repeat"
            else 1,
            str(row.get("transform_id") or ""),
        )
    )
    return accepted[:_STATIC_WRAPPER_MAX_CANDIDATES]


def _native_only_transform_candidates(zf: zipfile.ZipFile) -> List[Dict[str, Any]]:
    """Do not guess a lib.so wrapper from isolated native immediates.

    Constants in multi-ABI protector libraries are not data-flow proof that the
    same operation is applied to assets/lib.so.  iAct contains matching XOR
    immediates in helper VMs but its canonical lib.so is not wrapped by them.
    Wrapper candidates must therefore come from known-plaintext/control-file
    evidence or a future reader-to-buffer data-flow analysis, never voting on
    immediates alone.
    """
    return []


def _should_transform_companion(low_name: str, raw: bytes, transform: Dict[str, Any]) -> Tuple[bool, str]:
    low = _normal_name(low_name).lower()
    if low not in _STATIC_WRAPPER_CONTROL_NAMES:
        return False, ""
    try:
        restored = _apply_static_transform(raw, transform)
    except Exception:
        return False, ""
    before, _ = _decoded_asset_quality(low, raw)
    after, reason = _decoded_asset_quality(low, restored)
    if after >= 7 and after > before:
        return True, reason
    if low in {"assets/.jgapp", "assets/jgapp"} and _printable_ratio(restored[:4096]) > _printable_ratio(raw[:4096]) + 0.25:
        return True, "printable control text"
    return False, ""


def build_static_wrapper_normalized_apk(
    apk_path: Path | str,
    output_path: Path | str,
    transform_row: Dict[str, Any],
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Apply one statically inferred transport transform to lib.so/control files."""
    apk_path = Path(apk_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    transform = dict(transform_row.get("transform") or {})
    restored_entries: List[str] = []
    companion_reasons: Dict[str, str] = {}

    with zipfile.ZipFile(apk_path, "r") as src, zipfile.ZipFile(output_path, "w", allowZip64=True) as out:
        has_lib = False
        for info in src.infolist():
            if info.is_dir():
                continue
            name = _normal_name(info.filename)
            low = name.lower()
            if _drop_signature(name) or not _safe_zip_name(name):
                continue
            raw = src.read(info)
            if low == "assets/lib.so":
                if len(raw) < 64:
                    raise HiddenResourceRestoreError("static wrapper candidate has no usable assets/lib.so")
                raw = _apply_static_transform(raw, transform)
                restored_entries.append(name)
                has_lib = True
            else:
                should, reason = _should_transform_companion(low, raw, transform)
                if should:
                    raw = _apply_static_transform(raw, transform)
                    restored_entries.append(name)
                    companion_reasons[name] = reason
            out.writestr(_clone_zipinfo(info, name), raw)

        if not has_lib:
            raise HiddenResourceRestoreError("static wrapper candidate APK misses assets/lib.so")
        marker = {
            "mode": "static asset-wrapper normalization; normal iApp crypto preserved",
            "source_apk": apk_path.name,
            "wrapper": "static-byte-transform-v2",
            "transform": _static_transform_public(transform),
            "score": int(transform_row.get("score") or 0),
            "evidence": list(transform_row.get("evidence") or []),
            "native_evidence": list(transform_row.get("native_evidence") or []),
            "restored_entries": restored_entries,
            "companion_reasons": companion_reasons,
            "anti_encrypted_sample_required": True,
        }
        marker_info = zipfile.ZipInfo(_MARKER_NAME, date_time=(1980, 1, 1, 0, 0, 0))
        marker_info.compress_type = zipfile.ZIP_DEFLATED
        out.writestr(marker_info, json.dumps(marker, ensure_ascii=False, indent=2).encode("utf-8"))

    if not zipfile.is_zipfile(output_path):
        raise HiddenResourceRestoreError("static wrapper normalized APK is invalid")
    with zipfile.ZipFile(output_path, "r") as check:
        by_low = {_normal_name(item.filename).lower(): item for item in check.infolist() if not item.is_dir()}
        lib_info = by_low.get("assets/lib.so")
        if lib_info is None:
            raise HiddenResourceRestoreError("static wrapper normalized APK misses assets/lib.so")
        lib_data = check.read(lib_info)
        extra_text = b""
        if "assets/extra_conf1g.xml" in by_low:
            extra_text = check.read(by_low["assets/extra_conf1g.xml"])
        return {
            "normalized": True,
            "normalizer": "static-byte-transform-v2",
            "overlay_mode": "static-control-assets-preserve-code-native",
            "source_apk": apk_path.name,
            "source_apk_sha256": _sha256(apk_path.read_bytes()),
            "normalized_apk": str(output_path),
            "normalized_apk_size": output_path.stat().st_size,
            "normalized_apk_sha256": _sha256(output_path.read_bytes()),
            "normalized_entry_count": len(check.infolist()),
            "container_size": len(lib_data),
            "container_sha256": _sha256(lib_data),
            "extra_conf_signature_skip": b"<signature>1</signature>" in extra_text,
            "transform": _static_transform_public(transform),
            "transform_id": _static_transform_id(transform),
            "candidate_score": int(transform_row.get("score") or 0),
            "restored_entries": restored_entries,
            "evidence": list(transform_row.get("evidence") or []),
            "native_evidence": list(transform_row.get("native_evidence") or []),
            "ordinary_resources_restored": False,
            "lib_only": bool(
                _option_truthy(options, "no_decrypt_resource_files")
                or _option_truthy(options, "skip_anti_resources")
            ),
        }


def maybe_build_normalized_apk_candidates(
    apk_path: Path | str,
    output_dir: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build ranked static wrapper candidates; the normal decryptor verifies them.

    Returning several candidates is intentional: a protector may use one byte
    transform for VM/DEX metadata and another for assets/lib.so.  The V3 wrapper
    tries candidates in confidence order and accepts only one that the unchanged
    normal iApp decryptor can fully verify.
    """
    apk_path = Path(apk_path)
    output_dir = Path(output_dir)
    if not apk_path.is_file() or not zipfile.is_zipfile(apk_path):
        return [{"normalized": False, "reason": "not-zip"}]
    anti_enabled = any(
        _option_truthy(options, key)
        for key in ("anti_encrypted_sample", "anti_qiushui", "hidden_resource_restore")
    )
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            lib_info = next((item for item in zf.infolist() if not item.is_dir() and _normal_name(item.filename).lower() == "assets/lib.so"), None)
            canonical_present = bool(lib_info is not None and int(lib_info.file_size or 0) >= 64)
            rows = probe_static_asset_wrappers(zf) if anti_enabled and canonical_present else []

        reports: List[Dict[str, Any]] = []
        if rows:
            output_dir.mkdir(parents=True, exist_ok=True)
            for index, row in enumerate(rows):
                target = output_dir / ("candidate-%02d.apk" % (index + 1))
                try:
                    reports.append(build_static_wrapper_normalized_apk(apk_path, target, row, options))
                except HiddenResourceRestoreError as exc:
                    reports.append({
                        "normalized": False,
                        "reason": str(exc),
                        "transform": _static_transform_public(dict(row.get("transform") or {})),
                        "candidate_score": int(row.get("score") or 0),
                    })
            return reports

        if canonical_present:
            return [{"normalized": False, "reason": "canonical-container-present"}]

        # Existing DES/cyclic-XOR/nested-3LKs hidden-resource families.
        output_dir.mkdir(parents=True, exist_ok=True)
        target = output_dir / "hidden-resource-normalized.apk"
        return [build_normalized_apk(apk_path, target, options)]
    except HiddenResourceRestoreError as exc:
        return [{"normalized": False, "reason": str(exc)}]
    except Exception as exc:
        return [{"normalized": False, "reason": type(exc).__name__ + ": " + str(exc)}]


def maybe_build_normalized_apk(
    apk_path: Path | str,
    output_path: Path | str,
    options: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Compatibility API: build the highest-confidence candidate only."""
    output_path = Path(output_path)
    reports = maybe_build_normalized_apk_candidates(apk_path, output_path.parent / (output_path.stem + "-candidates"), options)
    first = next((row for row in reports if row.get("normalized")), None)
    if first is None:
        return reports[0] if reports else {"normalized": False, "reason": "no-normalization-candidate"}
    source = Path(str(first.get("normalized_apk") or ""))
    if source != output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, output_path)
        first = dict(first)
        first["normalized_apk"] = str(output_path)
        first["normalized_apk_size"] = output_path.stat().st_size
        first["normalized_apk_sha256"] = _sha256(output_path.read_bytes())
    return first
# IAPT_STATIC_ASSET_WRAPPER_V2_END

def main(argv: Optional[Sequence[str]] = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Restore DES-wrapped iApp resources without executing the APK")
    parser.add_argument("apk", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    report = build_normalized_apk(args.apk, args.output)
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# IAPT_ANTI_LIB_ONLY_NORMALIZE_V1
