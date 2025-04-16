import base64
import logging
from crypto_utils import generate_dh_keypair, generate_signing_keypair, serialize_key, deserialize_x25519_pubkey
from x3dh import PreKeyBundle, compute_x3dh_initiator, compute_x3dh_responder
from ratchet import SymmetricRatchet, RatchetMessage

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class User:
    def __init__(self, name: str):
        self.name = name
        self.ik_priv, self.ik_pub = generate_dh_keypair()
        self.ik_sign_priv, self.ik_sign_pub = generate_signing_keypair()
        self.spk_priv, self.spk_pub = generate_dh_keypair()
        self.spk_sig = self.ik_sign_priv.sign(self.spk_pub.public_bytes_raw())
        self.opk_pairs = [generate_dh_keypair() for _ in range(10)]  # 10 one-time prekeys
        self.ratchets = {}  # peer_name -> SymmetricRatchet

    def publish_prekey_bundle(self):
        return PreKeyBundle(
            identity_key=self.ik_pub,
            identity_signing_key=self.ik_sign_pub,
            signed_prekey=self.spk_pub,
            signed_prekey_sig=self.spk_sig,
            one_time_prekeys=[opk[1] for opk in self.opk_pairs]
        ).serialize()

    def generate_new_keys(self):
        self.ik_priv, self.ik_pub = generate_dh_keypair()
        self.ik_sign_priv, self.ik_sign_pub = generate_signing_keypair()
        self.spk_priv, self.spk_pub = generate_dh_keypair()
        self.spk_sig = self.ik_sign_priv.sign(self.spk_pub.public_bytes_raw())
        self.opk_pairs = [generate_dh_keypair() for _ in range(10)]
        self.ratchets.clear()
        logging.debug(f"{self.name} generated new keys")

    def establish_session_as_initiator(self, peer_name: str, peer_bundle: dict):
        if peer_name in self.ratchets:
            return None  # Session already exists
        bundle = PreKeyBundle.deserialize(peer_bundle)
        ek_priv, ek_pub = generate_dh_keypair()
        root_key, chain_key, ik_signature = compute_x3dh_initiator(
            self.ik_priv, self.ik_sign_priv, ek_priv, bundle
        )
        self.ratchets[peer_name] = SymmetricRatchet(root_key, chain_key)
        logging.debug(f"{self.name} initialized ratchet for {peer_name}")
        return ek_pub, self.ik_pub, self.ik_sign_pub, ik_signature, bundle.one_time_prekeys[0]

    def establish_session_as_responder(self, peer_name: str, peer_ik_pub, peer_ek_pub, used_opk_pub):
        if peer_name in self.ratchets:
            return  # Session already exists
        for i, (opk_priv, opk_pub) in enumerate(self.opk_pairs):
            if opk_pub.public_bytes_raw() == used_opk_pub.public_bytes_raw():
                root_key, chain_key = compute_x3dh_responder(
                    self.ik_priv, self.spk_priv, opk_priv, peer_ik_pub, peer_ek_pub
                )
                self.ratchets[peer_name] = SymmetricRatchet(root_key, chain_key)
                self.opk_pairs.pop(i)  # Remove used one-time prekey
                logging.debug(f"{self.name} initialized ratchet for {peer_name}, removed OPK")
                return
        raise ValueError("No matching one-time prekey found")

    def update_session(self, peer_name: str, peer_bundle: dict):
        bundle = PreKeyBundle.deserialize(peer_bundle)
        ek_priv, ek_pub = generate_dh_keypair()
        root_key, chain_key, ik_signature = compute_x3dh_initiator(
            self.ik_priv, self.ik_sign_priv, ek_priv, bundle
        )
        self.ratchets[peer_name].update_chain_key(chain_key)
        logging.debug(f"{self.name} updated ratchet for {peer_name}")
        return ek_pub, self.ik_pub, self.ik_sign_pub, ik_signature, bundle.one_time_prekeys[0]

    def send_message(self, peer_name: str, plaintext: str) -> RatchetMessage:
        if peer_name not in self.ratchets:
            raise ValueError(f"No session with {peer_name}")
        return self.ratchets[peer_name].encrypt(plaintext.encode('utf-8'))

    def receive_message(self, peer_name: str, message: dict) -> str:
        if peer_name not in self.ratchets:
            raise ValueError(f"No session with {peer_name}")
        msg = self.ratchets[peer_name].decrypt(RatchetMessage.deserialize(message))
        return msg.decode('utf-8')