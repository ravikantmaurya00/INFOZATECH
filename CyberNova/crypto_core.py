"""Crypto engine: classical ciphers (educational) + AES-256-GCM with passphrase-derived keys.

Container format (base64 encoded):
  MAGIC(4) | KDF id(1) | KDF param(4) | salt(16) | nonce(12) | ciphertext + GCM tag(16)
The first 37 bytes (the header) are passed to GCM as associated data, so tampering with
the KDF settings, salt or nonce is detected exactly like tampering with the ciphertext.
"""
import base64
import os
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"ETK1"
SALT_LEN, NONCE_LEN, TAG_LEN = 16, 12, 16
HEADER_LEN = len(MAGIC) + 1 + 4 + SALT_LEN + NONCE_LEN  # 37
KDF_IDS = {"scrypt": 1, "pbkdf2": 2}
DEFAULT_PARAM = {"scrypt": 15, "pbkdf2": 600_000}  # scrypt: log2(N); pbkdf2: iterations
# Upper limits stop a crafted file from forcing the server to burn CPU/memory.
MAX_PARAM = {"scrypt": 18, "pbkdf2": 2_000_000}
MIN_PARAM = {"scrypt": 14, "pbkdf2": 100_000}


# ---------------------------------------------------------------- classical ciphers
def _shift_char(ch: str, shift: int) -> str:
    if ch.isascii() and ch.isalpha():
        base = ord("A") if ch.isupper() else ord("a")
        return chr((ord(ch) - base + shift) % 26 + base)
    return ch


def caesar(text: str, shift: int, decrypt: bool = False) -> str:
    shift = -shift if decrypt else shift
    return "".join(_shift_char(c, shift) for c in text)


def caesar_bruteforce(text: str) -> list[dict]:
    """All 26 candidate plaintexts (what an attacker does against a Caesar cipher)."""
    return [{"shift": s, "text": caesar(text, s, decrypt=True)} for s in range(26)]


def vigenere(text: str, key: str, decrypt: bool = False) -> str:
    letters = [ord(k.lower()) - 97 for k in key if k.isascii() and k.isalpha()]
    if not letters:
        raise ValueError("Key must contain at least one letter (A-Z).")
    out, i = [], 0
    for ch in text:
        if ch.isascii() and ch.isalpha():
            k = letters[i % len(letters)]
            out.append(_shift_char(ch, -k if decrypt else k))
            i += 1  # key only advances on letters
        else:
            out.append(ch)
    return "".join(out)


# ---------------------------------------------------------------- AES-256-GCM
def derive_key(passphrase: str, salt: bytes, kdf: str, param: int) -> bytes:
    data = passphrase.encode("utf-8")
    if kdf == "scrypt":
        return Scrypt(salt=salt, length=32, n=2**param, r=8, p=1).derive(data)
    if kdf == "pbkdf2":
        return PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=param).derive(data)
    raise ValueError("Unknown KDF.")


def encrypt_text(plaintext: str, passphrase: str, kdf: str = "scrypt") -> str:
    if kdf not in KDF_IDS:
        raise ValueError("KDF must be 'scrypt' or 'pbkdf2'.")
    if not passphrase:
        raise ValueError("Passphrase is required.")
    param = DEFAULT_PARAM[kdf]
    salt, nonce = os.urandom(SALT_LEN), os.urandom(NONCE_LEN)  # fresh per message
    header = MAGIC + bytes([KDF_IDS[kdf]]) + struct.pack(">I", param) + salt + nonce
    key = derive_key(passphrase, salt, kdf, param)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), header)
    return base64.b64encode(header + ct).decode("ascii")


def decrypt_text(token: str, passphrase: str) -> str:
    try:
        raw = base64.b64decode(token.strip(), validate=True)
    except Exception:
        raise ValueError("Input is not valid Base64.")
    if len(raw) < HEADER_LEN + TAG_LEN or raw[:4] != MAGIC:
        raise ValueError("Not a valid toolkit message.")
    kdf = {v: k for k, v in KDF_IDS.items()}.get(raw[4])
    if kdf is None:
        raise ValueError("Unknown KDF in message header.")
    (param,) = struct.unpack(">I", raw[5:9])
    if not MIN_PARAM[kdf] <= param <= MAX_PARAM[kdf]:
        raise ValueError("KDF cost parameter out of allowed range.")
    salt, nonce = raw[9:25], raw[25:37]
    key = derive_key(passphrase, salt, kdf, param)
    try:
        return AESGCM(key).decrypt(nonce, raw[HEADER_LEN:], raw[:HEADER_LEN]).decode("utf-8")
    except InvalidTag:
        # Deliberately one message: don't reveal whether the passphrase or the data was wrong.
        raise ValueError("Decryption failed: wrong passphrase or the message was modified.")
