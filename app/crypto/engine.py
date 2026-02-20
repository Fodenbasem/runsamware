"""Hybrid cryptographic engine (skeleton).

Uses `cryptography` primitives. This is a focused, audit-ready skeleton;
implementers should review parameter choices for their threat model.
"""
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import keywrap
from cryptography.hazmat.primitives import constant_time
from cryptography.hazmat.backends import default_backend
import os


class CryptoEngine:
    """Simple hybrid encryption helper.

    Methods:
    - generate_rsa_keypair
    - encrypt_hybrid (returns dict with encrypted symmetric key + ciphertext + nonce)
    - decrypt_hybrid
    - serialize_private_key / load_private_key
    """

    def __init__(self, backend=None):
        self.backend = backend or default_backend()

    def generate_rsa_keypair(self, bits: int = 3072):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=bits, backend=self.backend)
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_private_key(self, private_key, password: bytes | None = None):
        enc_algo = (serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption())
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_algo,
        )

    def load_private_key(self, data: bytes, password: bytes | None = None):
        return serialization.load_pem_private_key(data, password=password, backend=self.backend)

    def encrypt_hybrid(self, recipient_public_key, plaintext: bytes):
        # Generate symmetric key
        sym_key = os.urandom(32)  # AES-256 key
        nonce = os.urandom(12)
        cipher = Cipher(algorithms.AES(sym_key), modes.GCM(nonce), backend=self.backend)
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        tag = encryptor.tag

        # Encrypt symmetric key with RSA-OAEP
        enc_sym_key = recipient_public_key.encrypt(
            sym_key,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )

        return {"enc_sym_key": enc_sym_key, "nonce": nonce, "ciphertext": ciphertext, "tag": tag}

    def decrypt_hybrid(self, private_key, envelope: dict):
        sym_key = private_key.decrypt(
            envelope["enc_sym_key"],
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
        )
        cipher = Cipher(algorithms.AES(sym_key), modes.GCM(envelope["nonce"], envelope["tag"]), backend=self.backend)
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(envelope["ciphertext"]) + decryptor.finalize()
        return plaintext
