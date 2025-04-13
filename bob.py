import socket
import json
import base64
import logging
from user import User
from crypto_utils import serialize_key, deserialize_x25519_pubkey, verify_signature, deserialize_ed25519_pubkey

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

HOST = 'localhost'
PORT = 65432

def handle_client(conn, addr, bob):
    """Handle a single client connection."""
    try:
        with conn:
            print(f"[Bob] Connected by {addr}")
            logging.debug(f"Connected by {addr}")

            # Send prekey bundle
            bundle = bob.publish_prekey_bundle()
            logging.debug(f"Sending bundle: {bundle}")
            conn.sendall(json.dumps(bundle).encode('utf-8'))

            # Receive Alice’s IK, EPK, signing public key, and IK signature
            data = conn.recv(4096).decode('utf-8')
            if not data:
                print("[Bob] No data received from Alice")
                logging.debug("No data received from Alice")
                return

            try:
                init_data = json.loads(data)
                logging.debug(f"Received init_data: {init_data}")
            except json.JSONDecodeError as e:
                print(f"[Bob] Error decoding init data: {e}")
                logging.error(f"Error decoding init data: {e}")
                return

            alice_ik_pub = deserialize_x25519_pubkey(init_data["ik_pub"])
            alice_epk_pub = deserialize_x25519_pubkey(init_data["epk_pub"])
            alice_ik_sign_pub = deserialize_ed25519_pubkey(init_data["ik_sign_pub"])
            alice_ik_sig = base64.b64decode(init_data["ik_signature"])

            # Verify Alice’s IK signature using her Ed25519 signing key
            if not verify_signature(alice_ik_sign_pub, alice_ik_pub.public_bytes_raw(), alice_ik_sig):
                print("[Bob] Invalid Alice IK signature")
                logging.debug("Invalid Alice IK signature")
                return

            print("[Bob] Received Alice’s keys. Establishing session...")
            logging.debug("Establishing session")
            bob.establish_session_as_responder(alice_ik_pub, alice_epk_pub)

            # Chat loop
            while True:
                data = conn.recv(4096)
                if not data:
                    print("[Bob] Connection closed by Alice")
                    logging.debug("Connection closed by Alice")
                    break
                try:
                    msg = bob.receive_message(json.loads(data.decode('utf-8')))
                    print(f"[Bob ← Alice]: {msg}")
                    logging.debug(f"Received message: {msg}")
                except json.JSONDecodeError as e:
                    print(f"[Bob] Error decoding message: {e}")
                    logging.error(f"Error decoding message: {e}")
                    continue

                reply = input("[Bob → Alice]: ")
                enc_msg = bob.send_message(reply)
                logging.debug(f"Sending message: {enc_msg.serialize()}")
                conn.sendall(json.dumps(enc_msg.serialize()).encode('utf-8'))
    except ConnectionError as e:
        print(f"[Bob] Connection error: {e}")
        logging.error(f"Connection error: {e}")
    except Exception as e:
        print(f"[Bob] Unexpected error: {str(e)}")
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)

def main():
    bob = User("Bob")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((HOST, PORT))
            s.listen()
            print("[Bob] Waiting for connection...")
            logging.debug("Waiting for connection")
            conn, addr = s.accept()
            handle_client(conn, addr, bob)
    except ConnectionError as e:
        print(f"[Bob] Connection error: {e}")
        logging.error(f"Connection error: {e}")
    except Exception as e:
        print(f"[Bob] Unexpected error: {str(e)}")
        logging.error(f"Unexpected error: {str(e)}", exc_info=True)

if __name__ == "__main__":
    main()