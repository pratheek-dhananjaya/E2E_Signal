import socket
import json
import base64
import sys
import threading
import logging
import time
import os
from user import User
from crypto_utils import deserialize_x25519_pubkey, serialize_key
from cryptography.exceptions import InvalidKey, InvalidTag

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

def parse_multiple_json(data):
    decoder = json.JSONDecoder()
    messages = []
    pos = 0
    while pos < len(data):
        try:
            msg, idx = decoder.raw_decode(data, pos)
            messages.append(msg)
            pos += idx
        except json.JSONDecodeError:
            break
    return messages

def receive_messages(sock, alice, peer_name):
    sock.settimeout(1.0)
    while True:
        try:
            data = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    logging.debug("Receive socket closed")
                    return  # Exit the function when socket is closed
                data += chunk
                if len(chunk) < 1024:
                    break
            if not data:
                continue
            data_str = data.decode('utf-8')
            messages = parse_multiple_json(data_str)
            for msg in messages:
                if msg.get('type') == 'reconnection_notification':
                    logging.debug("Received reconnection notification")
                    if peer_name in alice.ratchets:
                        del alice.ratchets[peer_name]
                        logging.debug(f"Cleared session for {peer_name} due to reconnection")
                    continue
                sender = msg['sender']
                if sender != peer_name:
                    continue
                if peer_name not in alice.ratchets and not msg.get('x3dh_data'):
                    logging.debug(f"No session with {peer_name}, skipping until session established")
                    continue
                if 'x3dh_data' in msg and msg['x3dh_data'] and all(k in msg['x3dh_data'] for k in ['epk_pub', 'ik_pub', 'used_opk']):
                    try:
                        epk_pub = deserialize_x25519_pubkey(msg['x3dh_data']['epk_pub'])
                        ik_pub = deserialize_x25519_pubkey(msg['x3dh_data']['ik_pub'])
                        used_opk = deserialize_x25519_pubkey(msg['x3dh_data']['used_opk'])
                        alice.establish_session_as_responder(peer_name, ik_pub, epk_pub, used_opk)
                        logging.debug(f"New session established for {peer_name}")
                    except ValueError as e:
                        logging.error(f"Session setup error: {e}", exc_info=True)
                        continue
                if peer_name not in alice.ratchets:
                    logging.warning(f"No session with {peer_name}, skipping message")
                    continue
                try:
                    message_n = msg['message']['n']
                    expected_n = alice.ratchets[peer_name].message_num
                    if message_n < expected_n:
                        logging.debug(f"Message n={message_n} already processed (expected n>={expected_n}), skipping")
                        continue
                    if message_n > expected_n:
                        logging.warning(f"Message n={message_n} too far ahead (expected n={expected_n}), skipping")
                        continue
                    sys.stdout.write('\r\033[K')
                    sys.stdout.flush()
                    plaintext = alice.receive_message(peer_name, msg['message'])
                    print(f"[You ← {peer_name}]: {plaintext}")
                    print(f"[You → {peer_name}]: ", end="", flush=True)
                except InvalidTag as e:
                    logging.error(f"Authentication error: {e}", exc_info=True)
                    temp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        temp_sock.connect(('127.0.0.1', 65432))
                        temp_sock.sendall(json.dumps({"type": "get_bundle", "target": peer_name}).encode('utf-8') + b'\n')
                        resp_data = temp_sock.recv(1024)
                        resp = json.loads(resp_data.decode('utf-8'))
                        if resp['bundle']:
                            del alice.ratchets[peer_name]
                            alice.establish_session_as_initiator(peer_name, resp['bundle'])
                            logging.debug(f"Re-established session for {peer_name} due to decryption failure")
                    except Exception as e:
                        logging.error(f"Session re-establishment failed: {e}")
                    finally:
                        temp_sock.close()
                    continue
                except Exception as e:
                    logging.error(f"Receive error: {str(e)}", exc_info=True)
                    continue
        except socket.timeout:
            continue
        except OSError as e:
            logging.error(f"Socket error: {e}", exc_info=True)
            return  # Exit on socket errors like Bad file descriptor
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
    sock.settimeout(15.0)
    for attempt in range(3):
        try:
            logging.debug("Attempting to register bundle")
            bundle_data = json.dumps({
                "type": "register",
                "user": alice.name,
                "bundle": alice.publish_prekey_bundle()
            }).encode('utf-8')
            sock.sendall(bundle_data + b'\n')
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
    sock.settimeout(1.0)
    time.sleep(1)

    while True:
        try:
            message = input(f"[You → {peer_name}]: ")
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
                        }).encode('utf-8') + b'\n')
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
            sock.sendall(json.dumps({
                "type": "get_bundle",
                "target": peer_name
            }).encode('utf-8') + b'\n')
            data = sock.recv(1024)
            resp = json.loads(data.decode('utf-8'))
            if not resp['bundle']:
                print(f"[Alice] Message not sent: {peer_name} not registered")
                time.sleep(2)
                continue
            x3dh_data = None
            if peer_name not in alice.ratchets:
                x3dh_data = alice.establish_session_as_initiator(peer_name, resp['bundle'])
            msg = alice.send_message(peer_name, message)
            msg_data = {
                "type": "message",
                "sender": alice.name,
                "recipient": peer_name,
                "message": msg.serialize(),
            }
            if x3dh_data:
                epk, ik, ik_sign, ik_sig, used_opk = x3dh_data
                msg_data["x3dh_data"] = {
                    "epk_pub": base64.b64encode(epk.public_bytes_raw()).decode('utf-8'),
                    "ik_pub": base64.b64encode(ik.public_bytes_raw()).decode('utf-8'),
                    "ik_sign_pub": base64.b64encode(ik_sign.public_bytes_raw()).decode('utf-8'),
                    "ik_signature": base64.b64encode(ik_sig).decode('utf-8'),
                    "used_opk": serialize_key(used_opk)
                }
            sock.sendall(json.dumps(msg_data).encode('utf-8') + b'\n')
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

        receive_sock.sendall(json.dumps({
            "type": "register_receive",
            "user": alice.name
        }).encode('utf-8') + b'\n')
        logging.debug("Sent register_receive")

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
        try:
            receive_sock.close()
        except:
            pass
        logging.debug("Connections closed")

if __name__ == "__main__":
    main()