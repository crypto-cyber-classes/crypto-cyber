import pytest

import handshake
from protocol import (
    HEADER_SIZE,
    MAX_FRAME,
    TYPE_FIRMWARE,
    FrameFieldError,
    frame_size,
    pack_frame,
    unpack_frame,
)

# Un chunk de firmware realista para mandar junto al handshake.
FIRMWARE_CHUNK = b"\x00" * 1024


def test_pack_unpack_roundtrip():
    pubkey = b"\x11" * 32
    sig = b"\x22" * 64
    payload = b"hola dispositivo"
    frame = pack_frame(version=1, tipo=TYPE_FIRMWARE, payload=payload, pubkey=pubkey, sig=sig)
    version, tipo, out_pubkey, out_sig, out_payload = unpack_frame(frame)
    assert version == 1
    assert tipo == TYPE_FIRMWARE
    assert out_pubkey == pubkey
    assert out_sig == sig
    assert out_payload == payload


def test_pack_frame_rechaza_pubkey_gigante_con_mensaje_claro():
    # Una pubkey post-cuántica (ML-KEM-768 = 1184 B) no entra en el campo de 32 B.
    with pytest.raises(FrameFieldError) as exc:
        pack_frame(version=1, tipo=TYPE_FIRMWARE, payload=b"", pubkey=b"\x00" * 1184, sig=b"\x00" * 64)
    msg = str(exc.value)
    assert "1184" in msg and "32" in msg  # el mensaje muestra los tamaños del choque


def test_firmware_update_fits_in_one_frame():
    # Un frame de actualización de firmware = header + pubkey del handshake + firma + chunk.
    # Con X25519 (32 B) entra. Cuando se migre el handshake a ML-KEM-768 (1184 B), NO entra
    # y este test falla mostrando los números: hay que decidir (fragmentar, cambiar
    # transporte, o postergar esta migración).
    total = frame_size(
        pubkey_len=handshake.HANDSHAKE_PUBKEY_LEN,
        sig_len=handshake.HANDSHAKE_AUTH_SIG_LEN,
        payload_len=len(FIRMWARE_CHUNK),
    )
    assert total <= MAX_FRAME, (
        "Un frame de actualización de firmware necesita {total} B "
        "(header {header} + pubkey {pk} + firma {sig} + firmware {fw}) "
        "pero MAX_FRAME es {maxf} B. La pubkey del handshake mide {pk} B "
        "(X25519=32, ML-KEM-768=1184): al migrar deja de entrar en un solo frame. "
        "Decidí: fragmentar el handshake, cambiar el transporte, o postergar esta migración."
    ).format(
        total=total,
        header=HEADER_SIZE,
        pk=handshake.HANDSHAKE_PUBKEY_LEN,
        sig=handshake.HANDSHAKE_AUTH_SIG_LEN,
        fw=len(FIRMWARE_CHUNK),
        maxf=MAX_FRAME,
    )
