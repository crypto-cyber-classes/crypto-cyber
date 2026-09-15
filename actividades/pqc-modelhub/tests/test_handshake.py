import pytest

import handshake
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def test_ambos_lados_derivan_la_misma_clave():
    k_dev, k_srv, dev_pub = handshake.do_handshake()
    assert k_dev == k_srv
    assert len(k_dev) == 32
    assert len(dev_pub) == handshake.HANDSHAKE_PUBKEY_LEN


def test_aes_gcm_ida_y_vuelta():
    k_dev, k_srv, _ = handshake.do_handshake()
    blob = handshake.encrypt(k_dev, b"telemetria: bateria 87%")
    assert handshake.decrypt(k_srv, blob) == b"telemetria: bateria 87%"


def test_ciphertext_alterado_falla():
    k_dev, _, _ = handshake.do_handshake()
    blob = bytearray(handshake.encrypt(k_dev, b"payload"))
    blob[-1] ^= 0x01  # alteramos el tag
    with pytest.raises(Exception):
        handshake.decrypt(k_dev, bytes(blob))


def test_autenticacion_ed25519():
    auth = Ed25519PrivateKey.generate()
    transcript = b"handshake-transcript"
    sig = handshake.sign_handshake(auth, transcript)
    assert len(sig) == handshake.HANDSHAKE_AUTH_SIG_LEN
    handshake.verify_handshake(
        auth.public_key().public_bytes_raw(), sig, transcript
    )
    with pytest.raises(InvalidSignature):
        handshake.verify_handshake(
            auth.public_key().public_bytes_raw(), sig, b"otro-transcript"
        )
