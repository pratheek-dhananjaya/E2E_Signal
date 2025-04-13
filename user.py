# user.py
from ratchet import DoubleRatchet
from crypto_utils import generate_dh_keypair, compute_shared_secret_hkdf
from x3dh import compute_x3dh_shared_secret
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey


def serialize_public_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )

class User:
    def __init__(self, name):
        self.name = name
        self.ik_priv, self.ik_pub = generate_dh_keypair()
        self.spk_priv, self.spk_pub = generate_dh_keypair()
        self.opk_priv, self.opk_pub = generate_dh_keypair()
        self.ephemeral_priv, self.ephemeral_pub = generate_dh_keypair()

        self.ik_pub_bytes = serialize_public_key(self.ik_pub)
        self.ephemeral_pub_bytes = serialize_public_key(self.ephemeral_pub)

        self.ratchet = None

    def publish_prekey_bundle(self):
        return {
            "identity_key": serialize_public_key(self.ik_pub),
            "signed_prekey": serialize_public_key(self.spk_pub),
            "one_time_prekey": serialize_public_key(self.opk_pub),
        }

    def establish_session_as_initiator(self, peer_bundle: dict, peer_ik_pub: X25519PublicKey):
        session_key = compute_x3dh_shared_secret(
            self.ik_priv,
            self.ephemeral_priv,
            peer_bundle,
            peer_ik_pub,
            X25519PublicKey.from_public_bytes(peer_bundle["signed_prekey"]),
            X25519PublicKey.from_public_bytes(peer_bundle["one_time_prekey"])
        )

        self.ratchet = DoubleRatchet(
            root_key=session_key,
            dh_pair=generate_dh_keypair(),
            remote_dh_pub=X25519PublicKey.from_public_bytes(peer_bundle["signed_prekey"])
        )
        return self.ephemeral_pub

    def establish_session_as_responder(self, peer_ik_pub, peer_epk_pub):
        dh1 = self.spk_priv.exchange(peer_ik_pub)
        dh2 = self.ik_priv.exchange(peer_epk_pub)
        dh3 = self.spk_priv.exchange(peer_epk_pub)
        dh4 = self.opk_priv.exchange(peer_epk_pub)
        session_key = compute_shared_secret_hkdf(dh1 + dh2 + dh3 + dh4)

        self.ratchet = DoubleRatchet(
            root_key=session_key,
            dh_pair=generate_dh_keypair(),
            remote_dh_pub=peer_epk_pub
        )

    def send_message(self, plaintext):
        if isinstance(plaintext, str):
            plaintext = plaintext.encode("utf-8")  # Only encode if it's a string
        return self.ratchet.encrypt(plaintext)  # Now it's safe

    def receive_message(self, peer_dh_pub, ciphertext):
        # Decrypt the message
        decrypted_msg = self.ratchet.decrypt(peer_dh_pub, ciphertext)

        # Attempt to decode the decrypted message as bytes, which may contain non-UTF-8 characters
        try:
            return decrypted_msg.decode('utf-8')
        except UnicodeDecodeError:
            print("Received raw message:", decrypted_msg)
            # If UTF-8 decoding fails, just return the decrypted bytes as a fallback
            return decrypted_msg
