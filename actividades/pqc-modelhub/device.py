from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import handshake
from server import RELEASE_PUBLIC_KEY, release_message

# Clave pública del servidor, confiada de fábrica por el dispositivo.
TRUSTED_RELEASE_KEY = RELEASE_PUBLIC_KEY


class ModeloNoAutorizado(Exception):
    pass


def verify_release(version, model_bytes, signature, trusted_key=TRUSTED_RELEASE_KEY):
    """Devuelve True si la firma del release valida. Lanza ModeloNoAutorizado si no."""
    try:
        trusted_key.verify(
            signature, release_message(version, model_bytes), ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        raise ModeloNoAutorizado(
            "firma inválida para el release {}: el dispositivo NO lo carga".format(version)
        )
    return True


def load_model(version, model_bytes, signature, trusted_key=TRUSTED_RELEASE_KEY):
    """Verifica la firma y 'carga' el modelo. Devuelve un resumen de lo cargado."""
    verify_release(version, model_bytes, signature, trusted_key)
    return {
        "version": version,
        "bytes": len(model_bytes),
        "estado": "cargado",
    }


def run_handshake():
    """Corre un handshake y devuelve la clave de sesión derivada por el dispositivo."""
    k_dev, k_srv, _ = handshake.do_handshake()
    assert k_dev == k_srv, "las claves derivadas no coinciden"
    return k_dev
