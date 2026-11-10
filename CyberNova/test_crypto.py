import base64

import pytest

import crypto_core as cc


def test_caesar_roundtrip_and_known_value():
    assert cc.caesar("Hello, World!", 3) == "Khoor, Zruog!"
    assert cc.caesar("Khoor, Zruog!", 3, decrypt=True) == "Hello, World!"


def test_vigenere_known_value():
    assert cc.vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert cc.vigenere("LXFOPVEFRNHR", "LEMON", decrypt=True) == "ATTACKATDAWN"


@pytest.mark.parametrize("kdf", ["scrypt", "pbkdf2"])
def test_aes_roundtrip(kdf):
    token = cc.encrypt_text("secret ✓", "correct horse battery", kdf)
    assert cc.decrypt_text(token, "correct horse battery") == "secret ✓"


def test_wrong_passphrase_and_tamper_fail():
    token = cc.encrypt_text("hi", "pw-one")
    with pytest.raises(ValueError):
        cc.decrypt_text(token, "pw-two")
    raw = bytearray(base64.b64decode(token))
    raw[-1] ^= 1
    with pytest.raises(ValueError):
        cc.decrypt_text(base64.b64encode(bytes(raw)).decode(), "pw-one")


def test_unique_salt_and_nonce():
    assert cc.encrypt_text("same", "pw") != cc.encrypt_text("same", "pw")
