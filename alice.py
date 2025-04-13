import socket
import json
import base64
import logging
from user import User
from crypto_utils import serialize_key
import sys

# Set up logging
logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

HOST = 'localhost'
PORT = 65432

alice = User("Alice")

try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[Alice] Connected to Bob.")
        logging.debug("Connected to Bob")

        # Receive Bob’s prekey bundle
        data = s.recv(4096).decode('utf-8')
        if not data:
            raise ValueError("No data received from Bob")
        logging.debug(f"Received bundle data: {data}")
        try:
            bundle = json.loads(data)
        except json.JSONDecodeError as e:
            print(f"[Alice] Error decoding bundle: {e}")
            logging.error(f"Error decoding bundle: {e}")
            sys.exit(1)
        print("[Alice] Received Bob’s bundle. Establishing session...")
        logging.debug("Establishing session")

        # Establish session
        epk_pub, ik_pub, ik_sign_pub, ik_signature = alice.establish_session_as_initiator(bundle)

        # Send Alice’s IK, EPK, signing public key, and IK signature
        init_data = {
            "ik_pub": serialize_key(ik_pub),
            "epk_pub": serialize_key(epk_pub),
            "ik_sign_pub": serialize_key(ik_sign_pub),
            "ik_signature": base64.b64encode(ik_signature).decode('utf-8')
        }
        logging.debug(f"Sending init_data: {init_data}")
        s.sendall(json.dumps(init_data).encode('utf-8'))

        # Chat loop
        while True:
            msg = input("[Alice → Bob]: ")
            enc_msg = alice.send_message(msg)
            logging.debug(f"Sending message: {enc_msg.serialize()}")
            s.sendall(json.dumps(enc_msg.serialize()).encode('utf-8'))

            data = s.recv(4096)
            if not data:
                print("[Alice] Connection closed by Bob")
                logging.debug("Connection closed by Bob")
                break
            try:
                reply = alice.receive_message(json.loads(data.decode('utf-8')))
                print(f"[Alice ← Bob]: {reply}")
                logging.debug(f"Received message: {reply}")
            except json.JSONDecodeError as e:
                print(f"[Alice] Error decoding message: {e}")
                logging.error(f"Error decoding message: {e}")
except ConnectionError as e:
    print(f"[Alice] Connection error: {e}")
    logging.error(f"Connection error: {e}")
except Exception as e:
    print(f"[Alice] Unexpected error: {str(e)}")
    logging.error(f"Unexpected error: {str(e)}", exc_info=True)