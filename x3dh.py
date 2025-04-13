import base64
import logging
from crypto_utils import (
    generate_dh_keypair, generate_signing_keypair, dh_exchange, hkdf,
    sign_message, verify_signature, serialize_key, deserialize_x25519_pubkey, deserialize_ed25519_pubkey
)

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class PreKeyBundle:
    def __init__(self, identity_key, identity_signing_key, signed_prekey, signed_prekey_sig, one_time_prekey=None):
        self.identity_key = identity_key  # IK_B (X25519 public)
        self.identity_signing_key = identity_signing_key  # Ed25519 public
        self.signed_prekey = signed_prekey  # SPK_B (X25519 public)
        self.signed_prekey_sig = signed_prekey_sig  # Signature of SPK_B
        self.one_time_prekey = one_time_prekey  # OPK_B (X25519 public, optional)

    def serialize(self):
        """Serialize bundle for transmission."""
        return {
            "identity_key": serialize_key(self.identity_key),
            "identity_signing_key": serialize_key(self.identity_signing_key),
            "signed_prekey": serialize_key(self.signed_prekey),
            "signed_prekey_sig": base64.b64encode(self.signed_prekey_sig).decode('utf-8'),
            "one_time_prekey": serialize_key(self.one_time_prekey) if self.one_time_prekey else None
        }

    @staticmethod
    def deserialize(data):
        """Deserialize bundle from dict."""
        return PreKeyBundle(
            identity_key=deserialize_x25519_pubkey(data["identity_key"]),
            identity_signing_key=deserialize_ed25519_pubkey(data["identity_signing_key"]),
            signed_prekey=deserialize_x25519_pubkey(data["signed_prekey"]),
            signed_prekey_sig=base64.b64decode(data["signed_prekey_sig"]),
            one_time_prekey=deserialize_x25519_pubkey(data["one_time_prekey"]) if data["one_time_prekey"] else None
        )

def compute_x3dh_initiator(
    alice_identity_priv, alice_identity_signing_priv, alice_ephemeral_priv,
    bob_bundle: PreKeyBundle
):
    """Compute X3DH shared secret as initiator (Alice)."""
    # Verify signed prekey signature
    if not verify_signature(
        bob_bundle.identity_signing_key,
        bob_bundle.signed_prekey.public_bytes_raw(),
        bob_bundle.signed_prekey_sig
    ):
        raise ValueError("Invalid signed prekey signature")

    # DH1: IK_A-SPK_B
    dh1 = dh_exchange(alice_identity_priv, bob_bundle.signed_prekey)
    # DH2: EK_A-IK_B
    dh2 = dh_exchange(alice_ephemeral_priv, bob_bundle.identity_key)
    # DH3: EK_A-SPK_B
    dh3 = dh_exchange(alice_ephemeral_priv, bob_bundle.signed_prekey)
    # DH4: EK_A-OPK_B (if present)
    dh4 = dh_exchange(alice_ephemeral_priv, bob_bundle.one_time_prekey) if bob_bundle.one_time_prekey else b""

    # Concatenate DH outputs (Signal prepends 32 bytes of 0xFF for 3DH, 0x00 for 4DH)
    combined = (b"\xFF" * 32 + dh1 + dh2 + dh3) if not dh4 else (b"\x00" * 32 + dh1 + dh2 + dh3 + dh4)
    logging.debug(f"Initiator combined: {base64.b64encode(combined).decode('utf-8')}")

    # Derive session key (64 bytes: 32 for SK, 32 for initial chain key)
    session_key = hkdf(
        input_key_material=combined,
        info=b"WhisperText",
        length=64
    )
    logging.debug(f"Initiator session_key: {base64.b64encode(session_key).decode('utf-8')}")
    return session_key[:32], session_key[32:], alice_identity_signing_priv.sign(alice_identity_priv.public_key().public_bytes_raw())

def compute_x3dh_responder(
    bob_identity_priv, bob_signed_prekey_priv, bob_one_time_prekey_priv,
    alice_identity_pub, alice_ephemeral_pub
):
    """Compute X3DH shared secret as responder (Bob)."""
    # DH1: IK_A-SPK_B
    dh1 = dh_exchange(bob_signed_prekey_priv, alice_identity_pub)
    # DH2: EK_A-IK_B
    dh2 = dh_exchange(bob_identity_priv, alice_ephemeral_pub)
    # DH3: EK_A-SPK_B
    dh3 = dh_exchange(bob_signed_prekey_priv, alice_ephemeral_pub)
    # DH4: EK_A-OPK_B (if present)
    dh4 = dh_exchange(bob_one_time_prekey_priv, alice_ephemeral_pub) if bob_one_time_prekey_priv else b""

    # Concatenate DH outputs
    combined = (b"\xFF" * 32 + dh1 + dh2 + dh3) if not dh4 else (b"\x00" * 32 + dh1 + dh2 + dh3 + dh4)
    logging.debug(f"Responder combined: {base64.b64encode(combined).decode('utf-8')}")

    # Derive session key
    session_key = hkdf(
        input_key_material=combined,
        info=b"WhisperText",
        length=64
    )
    logging.debug(f"Responder session_key: {base64.b64encode(session_key).decode('utf-8')}")
    return session_key[:32], session_key[32:]