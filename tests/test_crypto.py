import pytest

from app.crypto.engine import CryptoEngine


def test_roundtrip_rsa_hybrid():
    ce = CryptoEngine()
    priv, pub = ce.generate_rsa_keypair(bits=2048)
    data = b"hello test"
    env = ce.encrypt_hybrid(pub, data)
    out = ce.decrypt_hybrid(priv, env)
    assert out == data
