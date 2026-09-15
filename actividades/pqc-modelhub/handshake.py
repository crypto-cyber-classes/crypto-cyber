import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

# Primitiva actual del handshake. Migrar a "ml-kem-768" es el objetivo del ejercicio.
HANDSHAKE_PRIMITIVE = "x25519"
HANDSHAKE_PUBKEY_LEN = 32   # X25519. Con ML-KEM-768 pasa a 1184.
HANDSHAKE_AUTH_SIG_LEN = 64  # Ed25519.

HKDF_INFO = b"modelhub handshake v1"


def generate_keypair():
    sk = X25519PrivateKey.generate()
    return sk, sk.public_key()


def public_bytes(public_key):
    return public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)


def derive_session_key(private_key, peer_public_bytes, info=HKDF_INFO):
    peer = X25519PublicKey.from_public_bytes(peer_public_bytes)
    shared = private_key.exchange(peer)
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(shared)


def encrypt(key, plaintext, aad=b""):
    """AES-256-GCM. Devuelve nonce(12) || ciphertext || tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key, blob, aad=b""):
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)


def sign_handshake(auth_private_key, transcript):
    """El dispositivo autentica su parte del handshake con Ed25519."""
    return auth_private_key.sign(transcript)


def verify_handshake(auth_public_bytes, signature, transcript):
    Ed25519PublicKey.from_public_bytes(auth_public_bytes).verify(signature, transcript)


def do_handshake():
    """Handshake completo, en memoria. Devuelve (clave_dispositivo, clave_servidor, pubkey_dispositivo).

    Las dos claves derivadas tienen que ser idénticas: es el secreto compartido.
    """
    dev_sk, dev_pk = generate_keypair()
    srv_sk, srv_pk = generate_keypair()

    dev_pk_bytes = public_bytes(dev_pk)
    srv_pk_bytes = public_bytes(srv_pk)

    k_dev = derive_session_key(dev_sk, srv_pk_bytes)
    k_srv = derive_session_key(srv_sk, dev_pk_bytes)
    return k_dev, k_srv, dev_pk_bytes
