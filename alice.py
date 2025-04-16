import socket
import json
import base64
import threading
import logging
import time
from user import User
from crypto_utils import deserialize_x25519_pubkey, serialize_key
from cryptography.exceptions import InvalidKey, InvalidTag

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def receive_messages(sock, alice, peer_name):
    sock.settimeout(1.0)
    while True:
        try:
            data = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    logging.debug("Receive socket closed")
                    break
                data += chunk
                if len(chunk) < 1024:
                    break
            if not data:
                continue
            msg = json.loads(data.decode('utf-8'))
            sender = msg['sender']
            if sender != peer_name:
                continue
            logging.debug(f"Received x3dh_data: {msg['x3dh_data']}")
            logging.debug(f"Received message: {msg['message']}")
            logging.debug(f"Ratchet state: {alice.ratchets.get(peer_name)}")
            if 'x3dh_data' in msg and msg['x3dh_data'] and all(k in msg['x3dh_data'] for k in ['epk_pub', 'ik_pub', 'used_opk']):
                epk_pub = deserialize_x25519_pubkey(msg['x3dh_data']['epk_pub'])
                ik_pub = deserialize_x25519_pubkey(msg['x3dh_data']['ik_pub'])
                used_opk = deserialize_x25519_pubkey(msg['x3dh_data']['used_opk'])
                alice.establish_session_as_responder(peer_name, ik_pub, epk_pub, used_opk)
                logging.debug(f"New session established for {peer_name}")
            try:
                plaintext = alice.receive_message(peer_name, msg['message'])
            except InvalidTag as e:
                logging.error(f"Authentication error: {e}", exc_info=True)
                continue
            print(f"\n[Alice ← {peer_name}]: {plaintext}")
            logging.debug(f"Received message: {plaintext}")
            if peer_name in alice.ratchets:
                logging.debug(f"Receive chain_key: {alice.ratchets[peer_name].chain_key}")
                logging.debug(f"Session key: {alice.ratchets[peer_name].root_key}")
            print(f"[Alice → {peer_name}]: ", end="", flush=True)
        except socket.timeout:
            continue
        except ValueError as e:
            logging.error(f"Key deserialization error: {e}", exc_info=True)
            continue
        except InvalidKey as e:
            logging.error(f"Decryption error: {e}", exc_info=True)
            continue
        except Exception as e:
            logging.error(f"Receive error: {str(e)}", exc_info=True)
            continue

def send_messages(sock, alice, peer_name):
    sock.settimeout(15.0)  # Longer timeout for registration
    # Register bundle
    for attempt in range(3):
        try:
            logging.debug("Attempting to register bundle")
            bundle_data = json.dumps({
                "type": "register",
                "user": alice.name,
                "bundle": alice.publish_prekey_bundle()
            }).encode('utf-8')
            sock.sendall(bundle_data)
            logging.debug(f"Sent bundle data length: {len(bundle_data)}")
            data = sock.recv(1024)
            resp = json.loads(data.decode('utf-8'))
            logging.debug(f"Register response: {resp}")
            if resp.get("status") == "OK":
                print("[Alice] Successfully registered bundle")
                break
            else:
                print(f"[Alice] Registration failed: {resp.get('message', 'Unknown error')}")
        except socket.timeout:
            logging.warning(f"Register attempt {attempt+1} timed out")
            if attempt == 2:
                print("[Alice] Warning: Failed to register bundle, continuing...")
        except Exception as e:
            logging.error(f"Register error: {e}")
            if attempt == 2:
                print("[Alice] Warning: Failed to register bundle, continuing...")
        time.sleep(3)
    sock.settimeout(1.0)  # Reset for messaging
    time.sleep(1)  # Brief delay to ensure server readiness

    while True:
        try:
            message = input(f"[Alice → {peer_name}]: ")
            if message.lower() == "quit":
                break
            if message.lower() == "newkey":
                alice.generate_new_keys()
                for attempt in range(3):
                    try:
                        sock.sendall(json.dumps({
                            "type": "newkey",
                            "user": alice.name,
                            "bundle": alice.publish_prekey_bundle()
                        }).encode('utf-8'))
                        data = sock.recv(1024)
                        resp = json.loads(data.decode('utf-8'))
                        logging.debug(f"Newkey response: {resp}")
                        if resp.get("status") == "OK":
                            print("[Alice] New keys registered")
                            break
                    except socket.timeout:
                        logging.warning(f"Newkey attempt {attempt+1} timed out")
                    except Exception as e:
                        logging.error(f"Newkey error: {e}")
                continue
            # Get peer's bundle
            sock.sendall(json.dumps({
                "type": "get_bundle",
                "target": peer_name
            }).encode('utf-8'))
            data = sock.recv(1024)
            resp = json.loads(data.decode('utf-8'))
            if not resp['bundle']:
                print(f"[Alice] Message not sent: {peer_name} not registered")
                time.sleep(2)
                continue
            # Establish or reuse session
            x3dh_data = None
            if peer_name not in alice.ratchets:
                x3dh_data = alice.establish_session_as_initiator(peer_name, resp['bundle'])
                logging.debug(f"New session established for {peer_name}")
            # Encrypt message
            msg = alice.send_message(peer_name, message)
            msg_data = {
                "type": "message",
                "sender": alice.name,
                "recipient": peer_name,
                "message": msg.serialize(),
            }
            if x3dh_data:
                epk, ik, ik_sign, ik_sig, used_opk = x3dh_data
                logging.debug(f"Sending x3dh_data: {epk.public_bytes_raw(), ik.public_bytes_raw(), used_opk.public_bytes_raw()}")
                msg_data["x3dh_data"] = {
                    "epk_pub": base64.b64encode(epk.public_bytes_raw()).decode('utf-8'),
                    "ik_pub": base64.b64encode(ik.public_bytes_raw()).decode('utf-8'),
                    "ik_sign_pub": base64.b64encode(ik_sign.public_bytes_raw()).decode('utf-8'),
                    "ik_signature": base64.b64encode(ik_sig).decode('utf-8'),
                    "used_opk": serialize_key(used_opk)
                }
            sock.sendall(json.dumps(msg_data).encode('utf-8'))
            print(f"[Alice → {peer_name}]: {message}")
            logging.debug(f"Sent message: {message}")
            if peer_name in alice.ratchets:
                logging.debug(f"Send chain_key: {alice.ratchets[peer_name].chain_key}")
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Send error: {e}")
            print(f"[Alice] Send error: {e}")

def main():
    alice = User("Alice")
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receive_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_name = "Bob"

    try:
        send_sock.connect(('127.0.0.1', 65432))
        receive_sock.connect(('127.0.0.1', 65433))
        logging.debug("Connected to server")

        # Register receive socket
        receive_sock.sendall(json.dumps({
            "type": "register_receive",
            "user": alice.name
        }).encode('utf-8'))
        logging.debug("Sent register_receive")

        # Start threads
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(receive_sock, alice, peer_name),
            daemon=True
        )
        send_thread = threading.Thread(
            target=send_messages,
            args=(send_sock, alice, peer_name),
            daemon=True
        )
        receive_thread.start()
        send_thread.start()
        send_thread.join()

    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"[Alice] Error: {e}")
    finally:
        send_sock.close()
        receive_sock.close()
        logging.debug("Connections closed")

if __name__ == "__main__":
    main()