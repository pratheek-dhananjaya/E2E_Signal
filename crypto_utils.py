# crypto_utils.py
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
import os

def compute_shared_secret_hkdf(secret: bytes, salt: bytes = b"", info: bytes = b"x3dh", length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(secret)

def generate_dh_keypair():
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def dh_exchange(priv_key, pub_key):
    return priv_key.exchange(pub_key)

def hkdf(input_key_material, salt=b"", info=b"handshake", length=32):
    hkdf_obj = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf_obj.derive(input_key_material)

def random_bytes(n=32):
    return os.urandom(n)
