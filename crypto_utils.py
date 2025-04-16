import base64
import hmac
import hashlib
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption

def generate_dh_keypair() -> tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def generate_signing_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return private_key, public_key

def dh_exchange(private_key: x25519.X25519PrivateKey, public_key: x25519.X25519PublicKey) -> bytes:
    return private_key.exchange(public_key)

def hkdf(input_key: bytes, salt: bytes = None, info: bytes = b"", length: int = 32) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key)

def encrypt_message(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce

def decrypt_message(key: bytes, ciphertext: bytes, nonce: bytes, associated_data: bytes = b"") -> bytes:
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

def serialize_key(key: x25519.X25519PublicKey | ed25519.Ed25519PublicKey) -> str:
    return base64.b64encode(key.public_bytes(Encoding.Raw, PublicFormat.Raw)).decode('utf-8')

def deserialize_x25519_pubkey(encoded: str) -> x25519.X25519PublicKey:
    key_bytes = base64.b64decode(encoded)
    return x25519.X25519PublicKey.from_public_bytes(key_bytes)

def deserialize_x25519_privkey(encoded: str) -> x25519.X25519PrivateKey:
    key_bytes = base64.b64decode(encoded)
    return x25519.X25519PrivateKey.from_private_bytes(key_bytes)

def deserialize_ed25519_pubkey(encoded: str) -> ed25519.Ed25519PublicKey:
    key_bytes = base64.b64decode(encoded)
    return ed25519.Ed25519PublicKey.from_public_bytes(key_bytes)

def deserialize_ed25519_privkey(encoded: str) -> ed25519.Ed25519PrivateKey:
    key_bytes = base64.b64decode(encoded)
    return ed25519.Ed25519PrivateKey.from_private_bytes(key_bytes)