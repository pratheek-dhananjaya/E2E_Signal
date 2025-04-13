from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
import os
import base64

def generate_dh_keypair():
    """Generate an X25519 key pair."""
    priv = X25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def generate_signing_keypair():
    """Generate an Ed25519 key pair for signing."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    return priv, pub

def dh_exchange(priv_key: X25519PrivateKey, pub_key: X25519PublicKey) -> bytes:
    """Perform X25519 DH exchange."""
    if not isinstance(priv_key, X25519PrivateKey) or not isinstance(pub_key, X25519PublicKey):
        raise ValueError("Invalid key types")
    return priv_key.exchange(pub_key)

def sign_message(priv_key: Ed25519PrivateKey, message: bytes) -> bytes:
    """Sign a message with Ed25519."""
    return priv_key.sign(message)

def verify_signature(pub_key: Ed25519PublicKey, message: bytes, signature: bytes) -> bool:
    """Verify an Ed25519 signature."""
    try:
        pub_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False

def hkdf(input_key_material: bytes, salt: bytes = b"", info: bytes = b"", length: int = 32) -> bytes:
    """Derive keys using HKDF with SHA-256."""
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    )
    return hkdf.derive(input_key_material)

def encrypt_message(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt with AES-256-GCM, returning ciphertext and nonce."""
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)  # 96-bit nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
    return ciphertext, nonce

def decrypt_message(key: bytes, ciphertext: bytes, nonce: bytes, associated_data: bytes = b"") -> bytes:
    """Decrypt with AES-256-GCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, associated_data)

def random_bytes(n: int = 32) -> bytes:
    """Generate random bytes."""
    return os.urandom(n)

def serialize_key(key) -> str:
    """Serialize a public or private key to base64."""
    if hasattr(key, 'public_bytes_raw'):  # Public key
        return base64.b64encode(key.public_bytes_raw()).decode('utf-8')
    return base64.b64encode(key.private_bytes_raw()).decode('utf-8')

def deserialize_x25519_pubkey(key_str: str) -> X25519PublicKey:
    """Deserialize a base64-encoded X25519 public key."""
    return X25519PublicKey.from_public_bytes(base64.b64decode(key_str))

def deserialize_ed25519_pubkey(key_str: str) -> Ed25519PublicKey:
    """Deserialize a base64-encoded Ed25519 public key."""
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(key_str))