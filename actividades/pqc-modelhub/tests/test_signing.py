import pytest

import server
from device import ModeloNoAutorizado, load_model, verify_release


def test_release_firmado_se_carga():
    model = b"pesos-del-modelo-v1.0"
    sig = server.sign_release("v1.0", model)
    assert verify_release("v1.0", model, sig) is True
    resultado = load_model("v1.0", model, sig)
    assert resultado["estado"] == "cargado"
    assert resultado["version"] == "v1.0"


def test_release_con_firma_invalida_se_rechaza():
    model = b"pesos-del-modelo-v1.0"
    sig = server.sign_release("v1.0", model)
    # Alteramos el modelo: la firma ya no corresponde.
    with pytest.raises(ModeloNoAutorizado):
        verify_release("v1.0", model + b"-alterado", sig)


def test_firma_de_otra_version_no_sirve():
    model = b"pesos"
    sig = server.sign_release("v1.0", model)
    with pytest.raises(ModeloNoAutorizado):
        verify_release("v2.0", model, sig)
