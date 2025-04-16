import socket
import json
import threading
import logging
import os
from collections import defaultdict
from queue import Queue

logging.basicConfig(level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s")

class Server:
    def __init__(self):
        self.bundles = {}  # user -> prekey bundle
        self.messages = defaultdict(list)  # recipient -> list of messages
        self.receive_sockets = {}  # user -> receive socket
        self.lock = threading.Lock()
        self.key_file = "keys.txt"
        self.save_queue = Queue()
        self._start_save_thread()

    def _start_save_thread(self):
        def save_worker():
            while True:
                bundles = self.save_queue.get()
                try:
                    with open(self.key_file, 'w') as f:
                        json.dump(bundles, f, indent=2)
                    logging.debug(f"Saved keys to {self.key_file}")
                except Exception as e:
                    logging.error(f"Failed to save keys: {e}")
                self.save_queue.task_done()

        threading.Thread(target=save_worker, daemon=True).start()

    def save_keys(self):
        self.save_queue.put(self.bundles.copy())
        logging.debug("Queued key save")

    def delete_keys(self, user):
        with self.lock:
            if user in self.bundles:
                del self.bundles[user]
                self.save_keys()
                logging.debug(f"Deleted keys for {user}")

    def handle_send(self, sock, addr):
        sock.settimeout(1.0)
        while True:
            try:
                # Read full message
                data = b""
                while True:
                    chunk = sock.recv(1024)
                    if not chunk:
                        logging.debug(f"Send socket closed by {addr}")
                        sock.close()
                        return
                    data += chunk
                    if len(chunk) < 1024:
                        break
                logging.debug(f"Raw data length: {len(data)}")
                msg = json.loads(data.decode('utf-8'))
                logging.debug(f"Received send request: {msg['type']} from {addr}")

                if msg['type'] == 'register':
                    user = msg['user']
                    with self.lock:
                        self.bundles[user] = msg['bundle']
                    logging.debug(f"Stored bundle for {user}")
                    sock.sendall(json.dumps({"status": "OK"}).encode('utf-8'))
                    logging.debug(f"Sent OK response to {user}")
                    self.save_keys()
                elif msg['type'] == 'newkey':
                    user = msg['user']
                    self.delete_keys(user)
                    with self.lock:
                        self.bundles[user] = msg['bundle']
                    sock.sendall(json.dumps({"status": "OK"}).encode('utf-8'))
                    logging.debug(f"Sent OK response for newkey to {user}")
                    self.save_keys()
                elif msg['type'] == 'get_bundle':
                    user = msg['target']
                    with self.lock:
                        bundle = self.bundles.get(user, {})
                    sock.sendall(json.dumps({"bundle": bundle}).encode('utf-8'))
                    logging.debug(f"Sent bundle for {user}")
                elif msg['type'] == 'message':
                    recipient = msg['recipient']
                    if "x3dh_data" in msg and not all(k in msg["x3dh_data"] for k in ["epk_pub", "ik_pub", "used_opk"]):
                        logging.error(f"Invalid x3dh_data from {msg['sender']}")
                        continue
                    logging.debug(f"Received message from {msg['sender']} with x3dh_data: {'x3dh_data' in msg}")
                    logging.debug(f"Message content: {msg['message']}")
                    with self.lock:
                        self.messages[recipient].append(msg)
                        logging.debug(f"Stored message for {recipient}")
                        if recipient in self.receive_sockets:
                            self.receive_sockets[recipient].sendall(
                                json.dumps({
                                    "sender": msg["sender"],
                                    "message": msg["message"],
                                    "x3dh_data": msg.get("x3dh_data", {})
                                }).encode('utf-8')
                            )
                            logging.debug(f"Delivered message to {recipient}")
            except socket.timeout:
                continue
            except json.JSONDecodeError as e:
                logging.error(f"JSON error: {e}")
                sock.sendall(json.dumps({"status": "ERROR", "message": "Invalid JSON"}).encode('utf-8'))
            except Exception as e:
                logging.error(f"Send error: {e}")
                sock.sendall(json.dumps({"status": "ERROR", "message": str(e)}).encode('utf-8'))
        sock.close()

    def handle_receive(self, sock, addr):
        sock.settimeout(1.0)
        try:
            # Read full message
            data = b""
            while True:
                chunk = sock.recv(1024)
                if not chunk:
                    logging.debug(f"Receive socket closed by {addr}")
                    return
                data += chunk
                if len(chunk) < 1024:
                    break
            logging.debug(f"Raw receive data length: {len(data)}")
            msg = json.loads(data.decode('utf-8'))
            logging.debug(f"Received receive request: {msg['type']} from {addr}")
            if msg['type'] == 'register_receive':
                user = msg['user']
                with self.lock:
                    self.receive_sockets[user] = sock
                    logging.debug(f"Registered receive socket for {user}")
                # Send queued messages
                with self.lock:
                    for m in self.messages.get(user, []):
                        sock.sendall(
                            json.dumps({
                                "sender": m["sender"],
                                "message": m["message"],
                                "x3dh_data": m.get("x3dh_data", {})
                            }).encode('utf-8')
                        )
                        logging.debug(f"Sent queued message to {user}")
                    self.messages[user].clear()
        except socket.timeout:
            pass
        except json.JSONDecodeError as e:
            logging.error(f"Receive JSON error: {e}")
        except Exception as e:
            logging.error(f"Receive error: {e}")
        # Keep socket open

    def run(self):
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        send_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        send_socket.bind(('127.0.0.1', 65432))
        send_socket.listen()
        receive_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        receive_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        receive_socket.bind(('127.0.0.1', 65433))
        receive_socket.listen()
        logging.debug("Server started on ports 65432 (send), 65433 (receive)")

        def accept_send():
            while True:
                try:
                    sock, addr = send_socket.accept()
                    logging.debug(f"Accepted send connection from {addr}")
                    threading.Thread(target=self.handle_send, args=(sock, addr), daemon=True).start()
                except Exception as e:
                    logging.error(f"Accept send error: {e}")

        def accept_receive():
            while True:
                try:
                    sock, addr = receive_socket.accept()
                    logging.debug(f"Accepted receive connection from {addr}")
                    threading.Thread(target=self.handle_receive, args=(sock, addr), daemon=True).start()
                except Exception as e:
                    logging.error(f"Accept receive error: {e}")

        threading.Thread(target=accept_send, daemon=True).start()
        threading.Thread(target=accept_receive, daemon=True).start()

        try:
            while True:
                pass
        except KeyboardInterrupt:
            logging.info("Shutting down server")
            send_socket.close()
            receive_socket.close()

if __name__ == "__main__":
    server = Server()
    server.run()