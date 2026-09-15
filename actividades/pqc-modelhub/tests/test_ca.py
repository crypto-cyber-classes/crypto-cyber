import pytest

import ca
from cryptography.exceptions import InvalidSignature


def test_cert_emitido_por_ca_externa_verifica():
    cert, _api_key = ca.issue_api_certificate("api.modelhub.example")
    assert ca.verify_api_certificate(cert) is True


def test_cert_de_otra_ca_no_verifica():
    # Un cert emitido por una CA distinta no valida contra nuestra CA externa.
    _otra_key, otra_ca = ca._build_external_ca()
    cert, _ = ca.issue_api_certificate("api.modelhub.example")
    with pytest.raises(InvalidSignature):
        ca.verify_api_certificate(cert, ca_cert=otra_ca)
