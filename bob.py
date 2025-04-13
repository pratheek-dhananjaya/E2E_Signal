import socket
import pickle

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from user import User

HOST = 'localhost'
PORT = 65432

bob = User("Bob")
bundle = bob.publish_prekey_bundle()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("[Bob] Waiting for connection...")
    conn, addr = s.accept()
    with conn:
        print(f"[Bob] Connected by {addr}")

        # Step 1: Send Bob's prekey bundle
        conn.sendall(pickle.dumps(bundle))

        # Step 2: Receive Alice's IK and EPK
        init = conn.recv(4096)
        alice_ik_bytes, alice_epk_bytes = pickle.loads(init)
        alice_ik = X25519PublicKey.from_public_bytes(alice_ik_bytes)
        alice_epk = X25519PublicKey.from_public_bytes(alice_epk_bytes)
        print("[Bob] Received Alice's keys. Establishing session...")
        bob.establish_session_as_responder(alice_ik, alice_epk)

        # Step 3: Chat loop
        while True:
            enc_msg = conn.recv(4096)
            if not enc_msg:
                break
            ciphertext, sender_dh_bytes = pickle.loads(enc_msg)

            # Convert the sender's dh_pub from bytes back to X25519PublicKey
            sender_dh = X25519PublicKey.from_public_bytes(sender_dh_bytes)

            # Decrypt the message
            plaintext = bob.receive_message(sender_dh, ciphertext)
            if isinstance(plaintext, bytes):
                print(f"[Bob → Alice]: Received non-UTF-8 message. Treating as binary.")
                print(f"Non-text message: {plaintext}")
            else:
                # Try to decode it as a UTF-8 string
                try:
                    print(f"[Bob → Alice]: {plaintext.decode('utf-8')}")
                except UnicodeDecodeError:
                    print(f"[Bob → Alice]: Failed to decode as UTF-8, treating as binary.")

            reply = input("[Bob → Alice]: ")
            reply_ciphertext = bob.send_message(reply)

            # Serialize the sender's public key before sending
            reply_sender_dh_bytes = reply_ciphertext[1].public_bytes(
                encoding=serialization.Encoding.Raw,  # To get raw bytes
                format=serialization.PublicFormat.Raw  # To get the raw public key format
            )

            # Send the ciphertext and serialized sender's public key
            conn.sendall(pickle.dumps((reply_ciphertext[0], reply_sender_dh_bytes)))
