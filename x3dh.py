import base64
import logging
from crypto_utils import dh_exchange, hkdf, serialize_key, deserialize_x25519_pubkey, deserialize_ed25519_pubkey

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class PreKeyBundle:
    def __init__(self, identity_key, identity_signing_key, signed_prekey, signed_prekey_sig, one_time_prekeys):
        self.identity_key = identity_key
        self.identity_signing_key = identity_signing_key
        self.signed_prekey = signed_prekey
        self.signed_prekey_sig = signed_prekey_sig
        self.one_time_prekeys = one_time_prekeys  # List of one-time prekeys

    def serialize(self):
        return {
            "identity_key": serialize_key(self.identity_key),
            "identity_signing_key": serialize_key(self.identity_signing_key),
            "signed_prekey": serialize_key(self.signed_prekey),
            "signed_prekey_sig": base64.b64encode(self.signed_prekey_sig).decode('utf-8'),
            "one_time_prekeys": [serialize_key(opk) for opk in self.one_time_prekeys]
        }

    @staticmethod
    def deserialize(data):
        return PreKeyBundle(
            identity_key=deserialize_x25519_pubkey(data["identity_key"]),
            identity_signing_key=deserialize_ed25519_pubkey(data["identity_signing_key"]),
            signed_prekey=deserialize_x25519_pubkey(data["signed_prekey"]),
            signed_prekey_sig=base64.b64decode(data["signed_prekey_sig"]),
            one_time_prekeys=[deserialize_x25519_pubkey(opk) for opk in data["one_time_prekeys"]]
        )

def compute_x3dh_initiator(
    ik_priv, ik_sign_priv, ek_priv, bundle
) -> tuple[bytes, bytes, bytes]:
    dh1 = dh_exchange(ik_priv, bundle.signed_prekey)
    dh2 = dh_exchange(ek_priv, bundle.identity_key)
    dh3 = dh_exchange(ek_priv, bundle.signed_prekey)
    dh4 = dh_exchange(ek_priv, bundle.one_time_prekeys[0])  # Use first available OPK
    combined = b"\xFF" * 32 + dh1 + dh2 + dh3 + dh4
    session_key = hkdf(combined, info=b"WhisperText", length=64)
    root_key, chain_key = session_key[:32], session_key[32:]
    ik_signature = ik_sign_priv.sign(combined)
    logging.debug(f"Initiator combined: {base64.b64encode(combined).decode('utf-8')[:64]}...")
    logging.debug(f"Initiator session_key: {base64.b64encode(session_key).decode('utf-8')}")
    return root_key, chain_key, ik_signature

def compute_x3dh_responder(
    ik_priv, spk_priv, opk_priv, peer_ik_pub, peer_ek_pub
) -> tuple[bytes, bytes]:
    dh1 = dh_exchange(spk_priv, peer_ik_pub)
    dh2 = dh_exchange(ik_priv, peer_ek_pub)
    dh3 = dh_exchange(spk_priv, peer_ek_pub)
    dh4 = dh_exchange(opk_priv, peer_ek_pub)
    combined = b"\xFF" * 32 + dh1 + dh2 + dh3 + dh4
    session_key = hkdf(combined, info=b"WhisperText", length=64)
    root_key, chain_key = session_key[:32], session_key[32:]
    logging.debug(f"Responder combined: {base64.b64encode(combined).decode('utf-8')[:64]}...")
    logging.debug(f"Responder session_key: {base64.b64encode(session_key).decode('utf-8')}")
    return root_key, chain_key