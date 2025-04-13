from cryptography.hazmat.primitives import serialization

from crypto_utils import generate_dh_keypair, dh_exchange, hkdf
import hashlib
import os

class DoubleRatchet:
    def __init__(self, root_key, dh_pair, remote_dh_pub):
        self.root_key = root_key
        self.dh_pair = dh_pair  # (priv, pub)
        self.remote_dh_pub = remote_dh_pub

        self.send_chain_key = None
        self.recv_chain_key = None
        self.send_message_number = 0
        self.recv_message_number = 0

        self._dh_ratchet()

    def _dh_ratchet(self):
        # DH: DHs (priv) x DHr (pub)
        shared_secret = dh_exchange(self.dh_pair[0], self.remote_dh_pub)
        self.root_key, self.recv_chain_key = self._kdf_rk(self.root_key, shared_secret)

        # Generate new DH key pair for sending and perform DH again
        self.dh_pair = generate_dh_keypair()
        shared_secret_send = dh_exchange(self.dh_pair[0], self.remote_dh_pub)
        self.root_key, self.send_chain_key = self._kdf_rk(self.root_key, shared_secret_send)

    def encrypt(self, plaintext):
        if self.send_chain_key is None:
            raise ValueError("Send chain key not initialized")

        self.send_chain_key, message_key = self._kdf_ck(self.send_chain_key)
        ciphertext = self._encrypt_message(message_key, plaintext)
        self.send_message_number += 1
        return ciphertext, self.dh_pair[1]

    def decrypt(self, sender_dh_pub, ciphertext):
        # Ensure both public keys are in raw format for comparison
        if sender_dh_pub.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
        ) != self.remote_dh_pub.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ):
            # If the public keys do not match, update the remote public key and perform DH ratchet
            self.remote_dh_pub = sender_dh_pub
            self._dh_ratchet()

        # Proceed with decrypting the message using the chain key and the message key
        self.recv_chain_key, message_key = self._kdf_ck(self.recv_chain_key)
        self.recv_message_number += 1

        # Decrypt the message and return the plaintext
        return self._decrypt_message(message_key, ciphertext)

        if self.recv_chain_key is None:
            raise ValueError("Receive chain key not initialized")

        self.recv_chain_key, message_key = self._kdf_ck(self.recv_chain_key)
        self.recv_message_number += 1
        return self._decrypt_message(message_key, ciphertext)

    def _kdf_rk(self, rk, dh_output):
        hkdf_out = hkdf(dh_output, salt=rk, info=b"ratchet-rk", length=64)
        return hkdf_out[:32], hkdf_out[32:]  # root_key, chain_key

    def _kdf_ck(self, ck):
        if ck is None:
            raise ValueError("Chain key is None.")
        return self._hash(ck), self._hash(ck + b"MSG")

    def _encrypt_message(self, key, plaintext):
        return bytes([a ^ b for a, b in zip(plaintext, key[:len(plaintext)])])

    def _decrypt_message(self, key, ciphertext):
        return bytes([a ^ b for a, b in zip(ciphertext, key[:len(ciphertext)])])

    def _hash(self, data):
        return hashlib.sha256(data).digest()
