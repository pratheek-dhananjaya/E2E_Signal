import socket
import pickle
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives import serialization
from user import User

HOST = 'localhost'
PORT = 65432

alice = User("Alice")

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    print("[Alice] Connected to Bob.")

    # Step 1: Receive Bob's prekey bundle
    bundle = pickle.loads(s.recv(4096))
    bob_ik = X25519PublicKey.from_public_bytes(bundle["identity_key"])
    print("[Alice] Received Bob's bundle. Establishing session...")

    # Step 2: Establish session and get EPK
    epk_pub = alice.establish_session_as_initiator(bundle, bob_ik)

    # Step 3: Send Alice's identity and ephemeral public key (as bytes)
    alice_ik_bytes = alice.ik_pub_bytes  # Assuming this is already in bytes
    alice_epk_bytes = alice.ephemeral_pub_bytes  # Assuming this is already in bytes
    s.sendall(pickle.dumps((alice_ik_bytes, alice_epk_bytes)))

    # Step 4: Start chatting
    while True:
        msg = input("[Alice → Bob]: ")
        encoded_msg = msg.encode("utf-8")
        ciphertext = alice.send_message(encoded_msg)

        # If `ciphertext` contains any cryptographic objects (like X25519PublicKey), ensure they are serialized
        if isinstance(ciphertext, tuple):
            # Assuming ciphertext contains (message, sender_dh), where sender_dh is X25519PublicKey
            sender_dh = ciphertext[1]
            sender_dh_bytes = sender_dh.public_bytes(
                encoding=serialization.Encoding.Raw,  # To get raw bytes
                format=serialization.PublicFormat.Raw  # To get the raw public key format
            )

            # Now we send the serialized data
            s.sendall(pickle.dumps((ciphertext[0], sender_dh_bytes)))
        else:
            # If ciphertext is already ready to send (no complex objects), just send it
            s.sendall(pickle.dumps(ciphertext))

        enc_msg = s.recv(4096)
        if not enc_msg:
            break
        ciphertext, sender_dh_bytes = pickle.loads(enc_msg)

        # Deserialize the sender's DH public key
        sender_dh = X25519PublicKey.from_public_bytes(sender_dh_bytes)

        # Decrypt the message
        plaintext = alice.receive_message(sender_dh, ciphertext)
        print(f"\n[Bob → Alice]: {plaintext}")
