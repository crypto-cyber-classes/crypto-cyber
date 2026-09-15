"""Cierra el ataque: con la clave privada recuperada, firma un modelo con backdoor y
se lo pasa a un dispositivo. El dispositivo lo carga como si fuera legítimo.

Este script NO recupera la clave: esa parte la escriben ustedes (son ~6 líneas de
aritmética modular a partir de forensics/signatures.json). Este script toma la clave
que ya recuperaste y demuestra la consecuencia.

Uso:
    python forensics/verify_backdoor.py --key clave.txt
    echo 0x<d_en_hex> | python forensics/verify_backdoor.py
    python forensics/verify_backdoor.py --key <d_en_hex>

`clave.txt` (o el argumento) debe contener el escalar privado d en hex (0x...) o en
decimal.
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import hashes  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import device  # noqa: E402
from server import RELEASE_PUBLIC_KEY, release_message  # noqa: E402


def _parse_scalar(text):
    text = text.strip()
    if not text:
        raise ValueError("no recibí ninguna clave")
    return int(text, 16) if text.lower().startswith("0x") else int(text, 0)


def _read_key(args):
    if args.key:
        # Puede ser un path a un archivo o el escalar directo.
        if os.path.isfile(args.key):
            with open(args.key) as f:
                return _parse_scalar(f.read())
        return _parse_scalar(args.key)
    data = sys.stdin.read()
    return _parse_scalar(data)


def main():
    parser = argparse.ArgumentParser(description="Firma un modelo con backdoor usando la clave recuperada.")
    parser.add_argument("--key", help="Archivo con la clave d recuperada, o el escalar d directo (hex/dec).")
    args = parser.parse_args()

    d = _read_key(args)
    recovered_key = ec.derive_private_key(d, ec.SECP256R1())

    # ¿La clave recuperada es realmente la del servidor?
    recovered_pub = recovered_key.public_key().public_numbers()
    trusted_pub = RELEASE_PUBLIC_KEY.public_numbers()
    if (recovered_pub.x, recovered_pub.y) != (trusted_pub.x, trusted_pub.y):
        print("La clave recuperada NO coincide con la clave pública del servidor.")
        print("Revisá la aritmética de recuperación (z, k, d).")
        return 1
    print("OK: la clave recuperada coincide con la clave de firma de releases de ModelHub.")

    # Firmamos un modelo con backdoor como si fuéramos el servidor.
    backdoor_version = "v2.3-backdoor"
    backdoor_model = b"modelhub-weights-v2.3:detector + puerta-trasera"
    forged_sig = recovered_key.sign(
        release_message(backdoor_version, backdoor_model), ec.ECDSA(hashes.SHA256())
    )

    # Se lo pasamos al dispositivo, que confía en la clave pública del servidor.
    resultado = device.load_model(backdoor_version, backdoor_model, forged_sig)

    print()
    print("⚠ dispositivo cargó modelo NO autorizado — firma válida con clave comprometida")
    print("   release:", resultado["version"], "| bytes:", resultado["bytes"], "| estado:", resultado["estado"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
