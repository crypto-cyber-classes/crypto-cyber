import time

import pytest

import server


def test_token_valido_verifica():
    token = server.issue_session_token("cam-001")
    payload = server.verify_session_token(token)
    assert payload["device_id"] == "cam-001"


def test_token_vencido_se_rechaza():
    # Emitido hace 2 horas con TTL de 1 hora -> vencido.
    hace_dos_horas = int(time.time()) - 7200
    token = server.issue_session_token("cam-001", now=hace_dos_horas)
    with pytest.raises(ValueError):
        server.verify_session_token(token)


def test_ttl_es_una_hora():
    assert server.SESSION_TTL_SECONDS == 3600
    now = 1_000_000
    token = server.issue_session_token("cam-001", now=now)
    # Válido justo antes de vencer, inválido justo después.
    assert server.verify_session_token(token, now=now + 3599)["device_id"] == "cam-001"
    with pytest.raises(ValueError):
        server.verify_session_token(token, now=now + 3600)


def test_token_manipulado_se_rechaza():
    token = server.issue_session_token("cam-001")
    token["payload"] = token["payload"].replace(b"cam-001", b"cam-999")
    with pytest.raises(ValueError):
        server.verify_session_token(token)
