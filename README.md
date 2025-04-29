# End-to-End Encrypted Messaging Application using Signal Protocol

A Python-based chat app using the Signal Protocol for secure, end-to-end encrypted messaging between Alice and Bob.

## Signal Protocol

The Signal Protocol enables secure messaging with end-to-end encryption, used in apps like Signal and WhatsApp. It ensures messages are only readable by the recipient, with forward and backward secrecy.

**X3DH**: Establishes a shared session key using identity keys, signed prekeys, and one-time prekeys (OPKs) via multiple Diffie-Hellman exchanges.

**Double Ratchet**: Encrypts messages with evolving keys. The Symmetric Ratchet derives unique message keys, and the Diffie-Hellman Ratchet updates session keys for forward/backward secrecy.

## Overview

This app allows Alice and Bob to chat securely via a server. It uses X3DH for session setup and Symmetric Ratchet for message encryption.

## Files

**server.py**: Manages prekey bundles and message relaying.

**alice.py, bob.py**: Client scripts for Alice and Bob.

**user.py**: Handles keys, X3DH, and ratchet logic.

**x3dh.py, ratchet.py, crypto_utils.py**: Implement X3DH, ratchet, and crypto utilities.

## How It Works

* Users generate keys (identity, signed prekey, OPKs) and register bundles with the server.

* Alice initiates a session with Bob using X3DH, consuming an OPK.

* Messages are encrypted/decrypted with the Symmetric Ratchet.

* OPKs are replenished on reconnection.