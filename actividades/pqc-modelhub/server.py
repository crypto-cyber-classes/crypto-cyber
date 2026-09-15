import hashlib
import json
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

# Orden del grupo de P-256 (parámetro público de la curva).
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


def _load_release_key():
    # La clave de firma de releases. En producción viviría en un HSM; acá se deriva
    # de una semilla fija para que el servicio pueda firmar de forma reproducible.
    seed = b"modelhub/release-signing/v1"
    d = int.from_bytes(hashlib.sha256(seed).digest(), "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


_release_key = _load_release_key()
RELEASE_PUBLIC_KEY = _release_key.public_key()


def release_message(version, model_bytes):
    """Mensaje canónico que se firma para un release. Formato estable y determinístico."""
    digest = hashlib.sha256(model_bytes).hexdigest()
    return "modelhub-release::{}::sha256:{}".format(version, digest).encode()


def sign_release(version, model_bytes):
    """Firma un release con ECDSA P-256. Devuelve la firma DER."""
    return _release_key.sign(release_message(version, model_bytes), ec.ECDSA(hashes.SHA256()))


SESSION_TTL_SECONDS = 3600  # 1 hora

_session_key = ec.generate_private_key(ec.SECP256R1())
SESSION_PUBLIC_KEY = _session_key.public_key()


def issue_session_token(device_id, ttl=SESSION_TTL_SECONDS, now=None):
    """Emite un token de sesión firmado con vencimiento."""
    now = int(time.time()) if now is None else int(now)
    payload = {"device_id": device_id, "iat": now, "exp": now + int(ttl)}
    payload_bytes = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    signature = _session_key.sign(payload_bytes, ec.ECDSA(hashes.SHA256()))
    return {"payload": payload_bytes, "sig": signature}


def verify_session_token(token, now=None):
    """Valida firma y vencimiento. Devuelve el payload dict o levanta ValueError."""
    now = int(time.time()) if now is None else int(now)
    try:
        SESSION_PUBLIC_KEY.verify(
            token["sig"], token["payload"], ec.ECDSA(hashes.SHA256())
        )
    except InvalidSignature:
        raise ValueError("token con firma inválida")
    payload = json.loads(token["payload"].decode())
    if now >= payload["exp"]:
        raise ValueError(
            "token vencido (exp={}, ahora={})".format(payload["exp"], now)
        )
    return payload
