import socket
import json
import base64
import threading
import logging
import time
from user import User
from crypto_utils import deserialize_x25519_pubkey, serialize_key

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def receive_messages(sock, bob, peer_name):
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
            if 'x3dh_data' in msg:
                epk_pub = deserialize_x25519_pubkey(msg['x3dh_data']['epk_pub'])
                ik_pub = deserialize_x25519_pubkey(msg['x3dh_data']['ik_pub'])
                used_opk = deserialize_x25519_pubkey(msg['x3dh_data']['used_opk'])
                bob.establish_session_as_responder(peer_name, ik_pub, epk_pub, used_opk)
            plaintext = bob.receive_message(peer_name, msg['message'])
            print(f"\n[Bob ← {peer_name}]: {plaintext}")
            logging.debug(f"Received message: {plaintext}")
            print(f"[Bob → {peer_name}]: ", end="", flush=True)
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Receive error: {e}")
            break

def send_messages(sock, bob, peer_name):
    sock.settimeout(15.0)  # Longer timeout for registration
    # Register bundle
    for attempt in range(3):
        try:
            logging.debug("Attempting to register bundle")
            bundle_data = json.dumps({
                "type": "register",
                "user": bob.name,
                "bundle": bob.publish_prekey_bundle()
            }).encode('utf-8')
            sock.sendall(bundle_data)
            logging.debug(f"Sent bundle data length: {len(bundle_data)}")
            data = sock.recv(1024)
            resp = json.loads(data.decode('utf-8'))
            logging.debug(f"Register response: {resp}")
            if resp.get("status") == "OK":
                print("[Bob] Successfully registered bundle")
                break
            else:
                print(f"[Bob] Registration failed: {resp.get('message', 'Unknown error')}")
        except socket.timeout:
            logging.warning(f"Register attempt {attempt+1} timed out")
            if attempt == 2:
                print("[Bob] Warning: Failed to register bundle, continuing...")
        except Exception as e:
            logging.error(f"Register error: {e}")
            if attempt == 2:
                print("[Bob] Warning: Failed to register bundle, continuing...")
        time.sleep(3)
    sock.settimeout(1.0)  # Reset for messaging
    time.sleep(1)  # Brief delay to ensure server readiness

    while True:
        try:
            message = input(f"[Bob → {peer_name}]: ")
            if message.lower() == "quit":
                break
            if message.lower() == "newkey":
                bob.generate_new_keys()
                for attempt in range(3):
                    try:
                        sock.sendall(json.dumps({
                            "type": "newkey",
                            "user": bob.name,
                            "bundle": bob.publish_prekey_bundle()
                        }).encode('utf-8'))
                        data = sock.recv(1024)
                        resp = json.loads(data.decode('utf-8'))
                        logging.debug(f"Newkey response: {resp}")
                        if resp.get("status") == "OK":
                            print("[Bob] New keys registered")
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
                print(f"[Bob] Message not sent: {peer_name} not registered")
                time.sleep(2)
                continue
            # Establish or update session
            if peer_name not in bob.ratchets:
                x3dh_data = bob.establish_session_as_initiator(peer_name, resp['bundle'])
            else:
                x3dh_data = bob.update_session(peer_name, resp['bundle'])
            if x3dh_data:
                epk, ik, ik_sign, ik_sig, used_opk = x3dh_data
                # Encrypt message
                msg = bob.send_message(peer_name, message)
                sock.sendall(json.dumps({
                    "type": "message",
                    "sender": bob.name,
                    "recipient": peer_name,
                    "message": msg.serialize(),
                    "x3dh_data": {
                        "epk_pub": base64.b64encode(epk.public_bytes_raw()).decode('utf-8'),
                        "ik_pub": base64.b64encode(ik.public_bytes_raw()).decode('utf-8'),
                        "ik_sign_pub": base64.b64encode(ik_sign.public_bytes_raw()).decode('utf-8'),
                        "ik_signature": base64.b64encode(ik_sig).decode('utf-8'),
                        "used_opk": serialize_key(used_opk)
                    }
                }).encode('utf-8'))
                print(f"[Bob → {peer_name}]: {message}")
                logging.debug(f"Sent message: {message}")
        except socket.timeout:
            continue
        except Exception as e:
            logging.error(f"Send error: {e}")
            print(f"[Bob] Send error: {e}")

def main():
    bob = User("Bob")
    send_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    receive_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    peer_name = "Alice"

    try:
        send_sock.connect(('127.0.0.1', 65432))
        receive_sock.connect(('127.0.0.1', 65433))
        logging.debug("Connected to server")

        # Register receive socket
        receive_sock.sendall(json.dumps({
            "type": "register_receive",
            "user": bob.name
        }).encode('utf-8'))
        logging.debug("Sent register_receive")

        # Start threads
        receive_thread = threading.Thread(
            target=receive_messages,
            args=(receive_sock, bob, peer_name),
            daemon=True
        )
        send_thread = threading.Thread(
            target=send_messages,
            args=(send_sock, bob, peer_name),
            daemon=True
        )
        receive_thread.start()
        send_thread.start()
        send_thread.join()

    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"[Bob] Error: {e}")
    finally:
        send_sock.close()
        receive_sock.close()
        logging.debug("Connections closed")

if __name__ == "__main__":
    main()