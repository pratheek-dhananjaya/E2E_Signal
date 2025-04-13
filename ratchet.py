import base64
import logging
from crypto_utils import generate_dh_keypair, dh_exchange, hkdf, encrypt_message, decrypt_message, serialize_key, deserialize_x25519_pubkey
import hmac
import hashlib
from collections import defaultdict

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class RatchetMessage:
    def __init__(self, ciphertext: bytes, nonce: bytes, dh_pub: str, pn: int, n: int):
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.dh_pub = dh_pub
        self.pn = pn
        self.n = n

    def serialize(self):
        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(self.nonce).decode('utf-8'),
            "dh_pub": self.dh_pub,
            "pn": self.pn,
            "n": self.n
        }

    @staticmethod
    def deserialize(data):
        return RatchetMessage(
            ciphertext=base64.b64decode(data["ciphertext"]),
            nonce=base64.b64decode(data["nonce"]),
            dh_pub=data["dh_pub"],
            pn=data["pn"],
            n=data["n"]
        )

class DoubleRatchet:
    def __init__(self, root_key: bytes, dh_pair: tuple, remote_dh_pub, chain_key: bytes):
        self.root_key = root_key
        self.dh_pair = dh_pair
        self.remote_dh_pub = remote_dh_pub
        self.send_chain_key = chain_key
        self.recv_chain_key = chain_key
        self.send_message_num = 0
        self.recv_message_num = 0
        self.previous_chain_length = 0
        self.skipped_keys = defaultdict(dict)
        self.initialized = False  # Track if first message has been processed
        logging.debug(f"Initialized ratchet: root_key={base64.b64encode(root_key).decode('utf-8')}, chain_key={base64.b64encode(chain_key).decode('utf-8')}, remote_dh_pub={serialize_key(remote_dh_pub)}")

    def _dh_ratchet(self):
        self.previous_chain_length = self.send_message_num
        self.send_message_num = 0
        self.recv_message_num = 0

        shared_secret = dh_exchange(self.dh_pair[0], self.remote_dh_pub)
        self.root_key, self.recv_chain_key = self._kdf_rk(self.root_key, shared_secret)

        self.dh_pair = generate_dh_keypair()
        shared_secret = dh_exchange(self.dh_pair[0], self.remote_dh_pub)
        self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, shared_secret)
        logging.debug(f"DH ratchet: new send_chain_key={base64.b64encode(self.send_chain_key).decode('utf-8')}")

    def _kdf_rk(self, root_key: bytes, dh_output: bytes) -> tuple[bytes, bytes]:
        hkdf_out = hkdf(dh_output, salt=root_key, info=b"WhisperRatchet", length=64)
        return hkdf_out[:32], hkdf_out[32:]

    def _kdf_ck(self, chain_key: bytes) -> tuple[bytes, bytes]:
        chain_key_hmac = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
        message_key_hmac = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
        logging.debug(f"Derived message_key={base64.b64encode(message_key_hmac).decode('utf-8')}")
        return chain_key_hmac, message_key_hmac

    def encrypt(self, plaintext: bytes) -> RatchetMessage:
        if self.send_chain_key is None:
            raise ValueError("Sending chain key not initialized")

        self.send_chain_key, message_key = self._kdf_ck(self.send_chain_key)
        associated_data = f"{self.send_message_num}:{self.dh_pair[1].public_bytes_raw().hex()}".encode('utf-8')
        ciphertext, nonce = encrypt_message(message_key, plaintext, associated_data)
        message = RatchetMessage(
            ciphertext=ciphertext,
            nonce=nonce,
            dh_pub=serialize_key(self.dh_pair[1]),
            pn=self.previous_chain_length,
            n=self.send_message_num
        )
        self.send_message_num += 1
        logging.debug(f"Encrypted: n={self.send_message_num-1}, associated_data={associated_data}")
        return message

    def decrypt(self, message: RatchetMessage) -> bytes:
        remote_dh_pub = deserialize_x25519_pubkey(message.dh_pub)

        # Skip DH ratchet for first received message to use initial chain key
        if not self.initialized:
            logging.debug(f"First message received, updating remote_dh_pub to {message.dh_pub}")
            self.remote_dh_pub = remote_dh_pub
            self.initialized = True
        elif remote_dh_pub.public_bytes_raw() != self.remote_dh_pub.public_bytes_raw():
            logging.debug(f"Performing DH ratchet: old_dh_pub={serialize_key(self.remote_dh_pub)}, new_dh_pub={message.dh_pub}")
            self._skip_messages(self.remote_dh_pub, message.pn)
            self.remote_dh_pub = remote_dh_pub
            self._dh_ratchet()

        plaintext = self._try_skipped_keys(message)
        if plaintext is not None:
            return plaintext

        if self.recv_chain_key is None:
            raise ValueError("Receiving chain key not initialized")

        self._skip_messages(self.remote_dh_pub, message.n)
        self.recv_chain_key, message_key = self._kdf_ck(self.recv_chain_key)
        associated_data = f"{message.n}:{remote_dh_pub.public_bytes_raw().hex()}".encode('utf-8')
        plaintext = decrypt_message(message_key, message.ciphertext, message.nonce, associated_data)
        self.recv_message_num = message.n + 1
        logging.debug(f"Decrypted: n={message.n}, associated_data={associated_data}")
        return plaintext

    def _skip_messages(self, dh_pub, until: int):
        if self.recv_chain_key is None:
            return

        dh_pub_str = serialize_key(dh_pub)
        while self.recv_message_num < until:
            self.recv_chain_key, message_key = self._kdf_ck(self.recv_chain_key)
            self.skipped_keys[dh_pub_str][self.recv_message_num] = message_key
            self.recv_message_num += 1

    def _try_skipped_keys(self, message: RatchetMessage) -> bytes | None:
        dh_pub_str = message.dh_pub
        if dh_pub_str in self.skipped_keys and message.n in self.skipped_keys[dh_pub_str]:
            message_key = self.skipped_keys[dh_pub_str][message.n]
            associated_data = f"{message.n}:{message.dh_pub}".encode('utf-8')
            try:
                plaintext = decrypt_message(message_key, message.ciphertext, message.nonce, associated_data)
                del self.skipped_keys[dh_pub_str][message.n]
                if not self.skipped_keys[dh_pub_str]:
                    del self.skipped_keys[dh_pub_str]
                return plaintext
            except:
                pass
        return None