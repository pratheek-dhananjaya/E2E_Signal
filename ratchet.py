import base64
import hmac
import hashlib
import threading
import logging
from crypto_utils import encrypt_message, decrypt_message

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class RatchetMessage:
    def __init__(self, ciphertext: bytes, nonce: bytes, n: int):
        self.ciphertext = ciphertext
        self.nonce = nonce
        self.n = n

    def serialize(self):
        return {
            "ciphertext": base64.b64encode(self.ciphertext).decode('utf-8'),
            "nonce": base64.b64encode(self.nonce).decode('utf-8'),
            "n": self.n
        }

    @staticmethod
    def deserialize(data):
        return RatchetMessage(
            ciphertext=base64.b64decode(data["ciphertext"]),
            nonce=base64.b64decode(data["nonce"]),
            n=data["n"]
        )

class SymmetricRatchet:
    def __init__(self, root_key: bytes, chain_key: bytes):
        self.root_key = root_key
        self.chain_key = chain_key
        self.message_num = 0
        self.lock = threading.Lock()
        # logging.debug(f"Initialized ratchet: root_key={base64.b64encode(root_key).decode('utf-8')[:32]}..., chain_key={base64.b64encode(chain_key).decode('utf-8')}")

    def _kdf_ck(self, chain_key: bytes) -> tuple[bytes, bytes]:
        chain_key_hmac = hmac.new(chain_key, b"\x01", hashlib.sha256).digest()
        message_key_hmac = hmac.new(chain_key, b"\x02", hashlib.sha256).digest()
        # logging.debug(f"Derived message_key={base64.b64encode(message_key_hmac).decode('utf-8')}")
        return chain_key_hmac, message_key_hmac

    def update_chain_key(self, new_chain_key: bytes):
        with self.lock:
            self.chain_key = new_chain_key
            self.message_num = 0
            # logging.debug(f"Updated chain_key={base64.b64encode(self.chain_key).decode('utf-8')}")

    def encrypt(self, plaintext: bytes) -> RatchetMessage:
        with self.lock:
            self.chain_key, message_key = self._kdf_ck(self.chain_key)
            associated_data = f"{self.message_num}".encode('utf-8')
            ciphertext, nonce = encrypt_message(message_key, plaintext, associated_data)
            message = RatchetMessage(
                ciphertext=ciphertext,
                nonce=nonce,
                n=self.message_num
            )
            self.message_num += 1
            # logging.debug(f"Encrypted: n={self.message_num-1}, associated_data={associated_data}")
            return message

    def decrypt(self, message: RatchetMessage) -> bytes:
        with self.lock:
            self.chain_key, message_key = self._kdf_ck(self.chain_key)
            associated_data = f"{message.n}".encode('utf-8')
            plaintext = decrypt_message(message_key, message.ciphertext, message.nonce, associated_data)
            self.message_num = message.n + 1
            # logging.debug(f"Decrypted: n={message.n}, associated_data={associated_data}")
            return plaintext