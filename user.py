import base64

from crypto_utils import generate_dh_keypair, generate_signing_keypair, serialize_key, deserialize_x25519_pubkey
from x3dh import PreKeyBundle, compute_x3dh_initiator, compute_x3dh_responder
from ratchet import DoubleRatchet, RatchetMessage
import logging

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class User:
    def __init__(self, name: str):
        self.name = name
        self.ik_priv, self.ik_pub = generate_dh_keypair()
        self.ik_sign_priv, self.ik_sign_pub = generate_signing_keypair()
        self.spk_priv, self.spk_pub = generate_dh_keypair()
        self.spk_sig = self.ik_sign_priv.sign(self.spk_pub.public_bytes_raw())
        self.opk_priv, self.opk_pub = generate_dh_keypair()
        self.ephemeral_priv, self.ephemeral_pub = generate_dh_keypair()
        self.ratchet = None

    def publish_prekey_bundle(self):
        return PreKeyBundle(
            identity_key=self.ik_pub,
            identity_signing_key=self.ik_sign_pub,
            signed_prekey=self.spk_pub,
            signed_prekey_sig=self.spk_sig,
            one_time_prekey=self.opk_pub
        ).serialize()

    def establish_session_as_initiator(self, peer_bundle: dict):
        bundle = PreKeyBundle.deserialize(peer_bundle)
        root_key, chain_key, ik_signature = compute_x3dh_initiator(
            self.ik_priv, self.ik_sign_priv, self.ephemeral_priv, bundle
        )
        dh_pair = generate_dh_keypair()
        self.ratchet = DoubleRatchet(
            root_key=root_key,
            dh_pair=dh_pair,
            remote_dh_pub=dh_pair[1],  # Use own DH key initially; updated by first message
            chain_key=chain_key
        )
        logging.debug(f"Alice ratchet initialized: root_key={base64.b64encode(root_key).decode('utf-8')}")
        return self.ephemeral_pub, self.ik_pub, self.ik_sign_pub, ik_signature

    def establish_session_as_responder(self, peer_ik_pub, peer_ephemeral_pub):
        root_key, chain_key = compute_x3dh_responder(
            self.ik_priv, self.spk_priv, self.opk_priv,
            peer_ik_pub, peer_ephemeral_pub
        )
        dh_pair = generate_dh_keypair()
        self.ratchet = DoubleRatchet(
            root_key=root_key,
            dh_pair=dh_pair,
            remote_dh_pub=dh_pair[1],  # Use own DH key initially; updated by first message
            chain_key=chain_key
        )
        logging.debug(f"Bob ratchet initialized: root_key={base64.b64encode(root_key).decode('utf-8')}")
        return

    def send_message(self, plaintext: str):
        return self.ratchet.encrypt(plaintext.encode('utf-8'))

    def receive_message(self, message: dict) -> str:
        msg = self.ratchet.decrypt(RatchetMessage.deserialize(message))
        return msg.decode('utf-8')