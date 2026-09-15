import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# La primitiva por default de telemetría también está declarada en config.yaml.
TELEMETRY_PRIMITIVE = "aes-256-gcm"
KEY_BYTES = 32  # 256 bits


def new_key():
    return AESGCM.generate_key(bit_length=256)


def encrypt_at_rest(key, plaintext, aad=b"modelhub-telemetry"):
    """Cifra telemetría para guardarla. Devuelve nonce(12) || ciphertext || tag."""
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt_at_rest(key, blob, aad=b"modelhub-telemetry"):
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(key).decrypt(nonce, ct, aad)
