import time

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

RUNS = 200
MAX_FRAME = 1500  # ver protocol.py


def _hkdf(shared):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"bench").derive(shared)


def bench_x25519():
    # Handshake completo, con las claves efímeras que se generan en CADA handshake.
    t0 = time.perf_counter()
    for _ in range(RUNS):
        dev = X25519PrivateKey.generate()
        srv = X25519PrivateKey.generate()
        dev_pub = dev.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        srv_pub = srv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
        _hkdf(dev.exchange(X25519PublicKey.from_public_bytes(srv_pub)))
        _hkdf(srv.exchange(X25519PublicKey.from_public_bytes(dev_pub)))
    elapsed = (time.perf_counter() - t0) / RUNS

    # En el cable: dispositivo manda su pubkey, servidor manda la suya.
    wire = len(dev_pub) + len(srv_pub)
    return elapsed, wire


def bench_mlkem768():
    # Handshake completo: el dispositivo genera su par efímero, el servidor encapsula.
    t0 = time.perf_counter()
    for _ in range(RUNS):
        dev_sk = mlkem.MLKEM768PrivateKey.generate()
        dev_pub = dev_sk.public_key().public_bytes_raw()
        ss_srv, ct = mlkem.MLKEM768PublicKey.from_public_bytes(dev_pub).encapsulate()
        ss_dev = dev_sk.decapsulate(ct)
        _hkdf(ss_srv)
        _hkdf(ss_dev)
    elapsed = (time.perf_counter() - t0) / RUNS

    # En el cable: dispositivo manda su pubkey, servidor manda el ciphertext.
    wire = len(dev_pub) + len(ct)
    return elapsed, wire


def _entra(wire):
    return "entra" if wire <= MAX_FRAME else "NO entra"


def main():
    print("ModelHub - benchmark de handshake ({} corridas)".format(RUNS))
    print("=" * 64)
    x_lat, x_wire = bench_x25519()
    q_lat, q_wire = bench_mlkem768()

    fmt = "{:<18} {:>13} {:>15} {:>10}"
    print(fmt.format("Primitiva", "Latencia (ms)", "Bytes en cable", "Frame 1500"))
    print("-" * 64)
    print(fmt.format("X25519 (clásico)", "{:.3f}".format(x_lat * 1e3), str(x_wire), _entra(x_wire)))
    print(fmt.format("ML-KEM-768 (PQ)", "{:.3f}".format(q_lat * 1e3), str(q_wire), _entra(q_wire)))
    print("-" * 64)
    print()
    print("El costo de migrar está en el TAMAÑO: PQ pesa x{:.0f} en el cable ({} -> {} B).".format(
        q_wire / x_wire if x_wire else float("nan"), x_wire, q_wire
    ))
    if q_wire > MAX_FRAME:
        print("Y {} B no entran en un frame de {} B: por eso el handshake PQ rompe el transporte.".format(
            q_wire, MAX_FRAME
        ))


if __name__ == "__main__":
    main()
