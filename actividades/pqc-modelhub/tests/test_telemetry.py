import pytest

import telemetry


def test_cifrado_ida_y_vuelta():
    key = telemetry.new_key()
    dato = b"telemetria operativa: temp=41C, uptime=12d"
    blob = telemetry.encrypt_at_rest(key, dato)
    assert telemetry.decrypt_at_rest(key, blob) == dato


def test_tag_alterado_falla():
    key = telemetry.new_key()
    blob = bytearray(telemetry.encrypt_at_rest(key, b"dato"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        telemetry.decrypt_at_rest(key, bytes(blob))


def test_clave_de_256_bits():
    assert telemetry.KEY_BYTES == 32
    assert len(telemetry.new_key()) == 32
