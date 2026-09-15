import datetime

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def _build_external_ca():
    """Crea la CA externa mockeada. En la realidad esto es Let's Encrypt / DigiCert / etc."""
    ca_key = ec.generate_private_key(ec.SECP256R1())
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "CA-Externa-Mock R3"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Autoridad Certificante Externa"),
        ]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_cert


# La CA se instancia una vez. ModelHub NO tiene la clave privada ca_key: solo recibe
# el certificado firmado. Acá la retenemos únicamente para poder mockear la emisión.
_CA_KEY, CA_CERT = _build_external_ca()


def issue_api_certificate(common_name="api.modelhub.example"):
    """La CA externa emite el cert TLS de la API. Devuelve (cert, clave_privada_api).

    La clave del servidor la genera ModelHub, pero la FIRMA del cert la pone la CA.
    Sin la CA, este cert no vale: por eso migrarlo no depende solo de ModelHub.
    """
    api_key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(CA_CERT.subject)
        .public_key(api_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]), critical=False
        )
        .sign(_CA_KEY, hashes.SHA256())  # <-- firma la CA externa, no ModelHub
    )
    return cert, api_key


def verify_api_certificate(cert, ca_cert=CA_CERT):
    """Verifica que el cert de la API haya sido emitido por la CA externa."""
    ca_cert.public_key().verify(
        cert.signature,
        cert.tbs_certificate_bytes,
        ec.ECDSA(cert.signature_hash_algorithm),
    )
    return True
