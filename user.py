import base64
import json
import logging
import os
from crypto_utils import generate_dh_keypair, generate_signing_keypair, serialize_key, deserialize_x25519_pubkey, deserialize_x25519_privkey, deserialize_ed25519_pubkey, deserialize_ed25519_privkey
from x3dh import PreKeyBundle, compute_x3dh_initiator, compute_x3dh_responder
from ratchet import SymmetricRatchet, RatchetMessage

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class User:
    def __init__(self, name: str):
        self.name = name
        self.key_file = f"{name}_keys.json"
        self.ratchets = {}  # peer_name -> SymmetricRatchet
        if os.path.exists(self.key_file):
            self.load_keys()
        else:
            self.ik_priv, self.ik_pub = generate_dh_keypair()
            self.ik_sign_priv, self.ik_sign_pub = generate_signing_keypair()
            self.spk_priv, self.spk_pub = generate_dh_keypair()
            self.spk_sig = self.ik_sign_priv.sign(self.spk_pub.public_bytes_raw())
            self.opk_pairs = [generate_dh_keypair() for _ in range(10)]  # 10 one-time prekeys
            self.save_keys()

    def save_keys(self):
        data = {
            "ik_priv": base64.b64encode(self.ik_priv.private_bytes_raw()).decode('utf-8'),
            "ik_pub": serialize_key(self.ik_pub),
            "ik_sign_priv": base64.b64encode(self.ik_sign_priv.private_bytes_raw()).decode('utf-8'),
            "ik_sign_pub": serialize_key(self.ik_sign_pub),
            "spk_priv": base64.b64encode(self.spk_priv.private_bytes_raw()).decode('utf-8'),
            "spk_pub": serialize_key(self.spk_pub),
            "spk_sig": base64.b64encode(self.spk_sig).decode('utf-8'),
            "opk_pairs": [
                {
                    "priv": base64.b64encode(priv.private_bytes_raw()).decode('utf-8'),
                    "pub": serialize_key(pub)
                } for priv, pub in self.opk_pairs
            ],
            "ratchets": {
                peer: {
                    "root_key": base64.b64encode(r.root_key).decode('utf-8'),
                    "chain_key": base64.b64encode(r.chain_key).decode('utf-8'),
                    "message_num": r.message_num
                } for peer, r in self.ratchets.items()
            }
        }
        with open(self.key_file, 'w') as f:
            json.dump(data, f, indent=2)
        # logging.debug(f"{self.name} saved keys to {self.key_file}")

    def load_keys(self):
        try:
            with open(self.key_file, 'r') as f:
                data = json.load(f)
            self.ik_priv = deserialize_x25519_privkey(data["ik_priv"])
            self.ik_pub = deserialize_x25519_pubkey(data["ik_pub"])
            self.ik_sign_priv = deserialize_ed25519_privkey(data["ik_sign_priv"])
            self.ik_sign_pub = deserialize_ed25519_pubkey(data["ik_sign_pub"])
            self.spk_priv = deserialize_x25519_privkey(data["spk_priv"])
            self.spk_pub = deserialize_x25519_pubkey(data["spk_pub"])
            self.spk_sig = base64.b64decode(data["spk_sig"])
            self.opk_pairs = [
                (
                    deserialize_x25519_privkey(opk["priv"]),
                    deserialize_x25519_pubkey(opk["pub"])
                ) for opk in data["opk_pairs"]
            ]
            self.ratchets = {
                peer: SymmetricRatchet(
                    root_key=base64.b64decode(r["root_key"]),
                    chain_key=base64.b64decode(r["chain_key"])
                ) for peer, r in data.get("ratchets", {}).items()
            }
            for peer, r in data.get("ratchets", {}).items():
                self.ratchets[peer].message_num = r["message_num"]
            logging.debug(f"{self.name} loaded keys from {self.key_file}")
        except Exception as e:
            logging.error(f"Failed to load keys for {self.name}: {e}")
            self.ik_priv, self.ik_pub = generate_dh_keypair()
            self.ik_sign_priv, self.ik_sign_pub = generate_signing_keypair()
            self.spk_priv, self.spk_pub = generate_dh_keypair()
            self.spk_sig = self.ik_sign_priv.sign(self.spk_pub.public_bytes_raw())
            self.opk_pairs = [generate_dh_keypair() for _ in range(10)]
            self.ratchets = {}

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
        self.save_keys()
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
        self.save_keys()
        logging.debug(f"{self.name} initialized ratchet for {peer_name}")
        return ek_pub, self.ik_pub, self.ik_sign_pub, ik_signature, bundle.one_time_prekeys[0] if bundle.one_time_prekeys else None

    def establish_session_as_responder(self, peer_name: str, peer_ik_pub, peer_ek_pub, used_opk_pub):
        if peer_name in self.ratchets:
            return  # Session already exists
        logging.debug(f"Available OPKs: {[opk_pub.public_bytes_raw() for _, opk_pub in self.opk_pairs]}")
        opk_priv = None
        opk_index = -1
        if used_opk_pub:
            for i, (priv, pub) in enumerate(self.opk_pairs):
                if pub.public_bytes_raw() == used_opk_pub.public_bytes_raw():
                    opk_priv = priv
                    opk_index = i
                    break
            if opk_priv is None:
                logging.warning(f"No matching OPK for {peer_name}, using IK and SPK only")
        else:
            logging.debug(f"No OPK provided for {peer_name}, using IK and SPK only")
        root_key, chain_key = compute_x3dh_responder(
            self.ik_priv, self.spk_priv, opk_priv, peer_ik_pub, peer_ek_pub
        )
        self.ratchets[peer_name] = SymmetricRatchet(root_key, chain_key)
        if opk_index != -1:
            self.opk_pairs.pop(opk_index)  # Remove used one-time prekey
            logging.debug(f"{self.name} removed OPK at index {opk_index}")
        self.save_keys()
        logging.debug(f"{self.name} initialized ratchet for {peer_name}")
        logging.debug(f"Session for {peer_name}: {peer_name in self.ratchets}")

    def update_session(self, peer_name: str, peer_bundle: dict):
        bundle = PreKeyBundle.deserialize(peer_bundle)
        ek_priv, ek_pub = generate_dh_keypair()
        root_key, chain_key, ik_signature = compute_x3dh_initiator(
            self.ik_priv, self.ik_sign_priv, ek_priv, bundle
        )
        self.ratchets[peer_name].update_chain_key(chain_key)
        self.save_keys()
        logging.debug(f"{self.name} updated ratchet for {peer_name}")
        return ek_pub, self.ik_pub, self.ik_sign_pub, ik_signature, bundle.one_time_prekeys[0] if bundle.one_time_prekeys else None

    def send_message(self, peer_name: str, plaintext: str) -> RatchetMessage:
        if peer_name not in self.ratchets:
            raise ValueError(f"No session with {peer_name}")
        msg = self.ratchets[peer_name].encrypt(plaintext.encode('utf-8'))
        self.save_keys()
        return msg

    def receive_message(self, peer_name: str, message: dict) -> str:
        if peer_name not in self.ratchets:
            raise ValueError(f"No session with {peer_name}")
        msg = self.ratchets[peer_name].decrypt(RatchetMessage.deserialize(message))
        self.save_keys()
        return msg.decode('utf-8')