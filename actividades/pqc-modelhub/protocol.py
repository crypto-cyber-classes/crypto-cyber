import struct

# magic(4) | version(1) | tipo(1) | payload_len(2) | pubkey[32] | sig[64]
HEADER_FMT = "!4sBBH32s64s"
HEADER_SIZE = struct.calcsize(HEADER_FMT)  # 104 bytes
MAX_FRAME = 1500

MAGIC = b"MHUB"
PUBKEY_FIELD = 32
SIG_FIELD = 64

# Tipos de frame
TYPE_HANDSHAKE = 1
TYPE_FIRMWARE = 2
TYPE_TELEMETRY = 3


class FrameFieldError(ValueError):
    """Un campo no entra en el frame de tamaño fijo. El mensaje dice cuál y por qué."""


def frame_size(pubkey_len, sig_len, payload_len):
    
    overflow = max(0, pubkey_len - PUBKEY_FIELD) + max(0, sig_len - SIG_FIELD)
    return HEADER_SIZE + overflow + payload_len


def pack_frame(version, tipo, payload, pubkey, sig, magic=MAGIC):
    
    if len(pubkey) > PUBKEY_FIELD:
        raise FrameFieldError(
            "pubkey de {} B no entra en el campo de {} B del frame "
            "(X25519=32, ML-KEM-768=1184). El frame de tamaño fijo no soporta la "
            "clave post-cuántica: hay que fragmentar el handshake o cambiar el "
            "transporte.".format(len(pubkey), PUBKEY_FIELD)
        )
    if len(sig) > SIG_FIELD:
        raise FrameFieldError(
            "sig de {} B no entra en el campo de {} B del frame "
            "(Ed25519=64, ML-DSA-65=3309). La firma post-cuántica no entra en un "
            "solo frame.".format(len(sig), SIG_FIELD)
        )
    if len(payload) > 0xFFFF:
        raise FrameFieldError(
            "payload de {} B excede el máximo de {} B que puede declarar el header "
            "(campo de 2 bytes).".format(len(payload), 0xFFFF)
        )

    frame = struct.pack(
        HEADER_FMT,
        magic,
        version,
        tipo,
        len(payload),
        pubkey.ljust(PUBKEY_FIELD, b"\x00"),
        sig.ljust(SIG_FIELD, b"\x00"),
    ) + payload

    if len(frame) > MAX_FRAME:
        raise FrameFieldError(
            "frame de {} B excede MAX_FRAME={} B. En este transporte no entra en un "
            "solo paquete.".format(len(frame), MAX_FRAME)
        )
    return frame


def unpack_frame(frame):
    """Devuelve (version, tipo, pubkey, sig, payload). pubkey/sig sin el padding de ceros."""
    if len(frame) < HEADER_SIZE:
        raise FrameFieldError(
            "frame de {} B es más corto que el header ({} B).".format(len(frame), HEADER_SIZE)
        )
    magic, version, tipo, payload_len, pubkey, sig = struct.unpack(
        HEADER_FMT, frame[:HEADER_SIZE]
    )
    if magic != MAGIC:
        raise FrameFieldError("magic inválido: {!r}".format(magic))
    payload = frame[HEADER_SIZE:HEADER_SIZE + payload_len]
    return version, tipo, pubkey.rstrip(b"\x00"), sig.rstrip(b"\x00"), payload
