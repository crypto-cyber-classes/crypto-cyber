"""Genera dos firmas ECDSA P-256 de dos releases de ModelHub REUSANDO el mismo nonce.

Esto reproduce un error de implementación clásico: firmar dos mensajes distintos con
el mismo valor de `k` (nonce). Cuando eso pasa, las dos firmas comparten el mismo `r`,
y de ahí se puede recuperar la clave privada con aritmética modular.

El script es reproducible y ya dejó su salida en `signatures.json`. NO hace falta
correrlo para la actividad; está para que se vea que las firmas son reales y salen de
la misma clave con la que el servidor firma releases.

Uso:  python forensics/generate_signatures.py
"""

import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from server import _release_key, release_message  # noqa: E402

# --- Parámetros de la curva NIST P-256 (secp256r1) --------------------------------
P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
A = P - 3
B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
GX = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
GY = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551

# Nonce FIJO que se reusa en las dos firmas. Este es el bug.
REUSED_K = 0x7A1F9C3E5D2B8A46C0E1F3D5B7A9C8E60F2D4B6A8C0E2F4D6B8A0C2E4F6A8B0D


def _inv(x, m):
    return pow(x, -1, m)


def _point_add(p, q):
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    if p == q:
        lam = (3 * x1 * x1 + A) * _inv(2 * y1, P) % P
    else:
        lam = (y2 - y1) * _inv(x2 - x1, P) % P
    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P
    return (x3, y3)


def _scalar_mult(k, point):
    result = None
    addend = point
    while k:
        if k & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        k >>= 1
    return result


def _z(message_bytes):
    return int.from_bytes(hashlib.sha256(message_bytes).digest(), "big") % N


def ecdsa_sign_fixed_k(d, message_bytes, k):
    z = _z(message_bytes)
    x1, _y1 = _scalar_mult(k, (GX, GY))
    r = x1 % N
    s = (_inv(k, N) * (z + r * d)) % N
    if r == 0 or s == 0:
        raise ValueError("r o s dieron 0: elegí otro k")
    return r, s


def main():
    d = _release_key.private_numbers().private_value
    qx, qy = _scalar_mult(d, (GX, GY))

    releases = [
        {"version": "v2.1", "model": b"modelhub-weights-v2.1:detector-int8"},
        {"version": "v2.2", "model": b"modelhub-weights-v2.2:detector-int8+hotfix"},
    ]

    firmas = []
    for rel in releases:
        msg = release_message(rel["version"], rel["model"])
        r, s = ecdsa_sign_fixed_k(d, msg, REUSED_K)
        firmas.append(
            {
                "version": rel["version"],
                "message_hex": msg.hex(),
                "r": hex(r),
                "s": hex(s),
            }
        )

    out = {
        "_nota": (
            "Dos firmas ECDSA P-256 de releases de ModelHub. Mirá el valor 'r' de las "
            "dos antes de escribir una sola línea de código."
        ),
        "curva": "secp256r1 (NIST P-256)",
        "n": hex(N),
        "pubkey": {"x": hex(qx), "y": hex(qy)},
        "firmas": firmas,
    }

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signatures.json")
    with open(path, "w") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("Escrito:", path)
    print("r[v2.1] =", firmas[0]["r"])
    print("r[v2.2] =", firmas[1]["r"])
    print("¿Notás algo?")


if __name__ == "__main__":
    main()
