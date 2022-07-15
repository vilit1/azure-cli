# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------

import datetime
from os.path import exists, join
import base64
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa


def create_self_signed_certificate(device_id, valid_days, cert_output_dir):
    cert_file = device_id + '-cert.pem'
    key_file = device_id + '-key.pem'

    # create a key pair
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    # create a self-signed cert
    subject_name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, device_id),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject_name)
        .issuer_name(subject_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=valid_days)
        )
        .sign(key, hashes.SHA256())
    )

    key_dump = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    cert_dump = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    thumbprint = cert.fingerprint(hashes.SHA1()).hex().upper()

    if cert_output_dir is not None and exists(cert_output_dir):
        open(join(cert_output_dir, cert_file), "wt").write(cert_dump)
        open(join(cert_output_dir, key_file), "wt").write(key_dump)
    return {
        'certificate': cert_dump,
        'privateKey': key_dump,
        'thumbprint': thumbprint
    }


def open_certificate(certificate_path):
    certificate = ""
    if certificate_path.endswith('.pem') or certificate_path.endswith('.cer'):
        with open(certificate_path, "rb") as cert_file:
            certificate = cert_file.read()
        try:
            certificate = certificate.decode("utf-8")
        except UnicodeError:
            certificate = base64.b64encode(certificate).decode("utf-8")
    else:
        raise ValueError("Certificate file type must be either '.pem' or '.cer'.")
    # Remove trailing white space from the certificate content
    return certificate.rstrip()


def generate_key(byte_length=32):
    """
    Generate cryptographically secure device key.
    """
    import secrets

    token_bytes = secrets.token_bytes(byte_length)
    return base64.b64encode(token_bytes).decode("utf8")


def _dps_certificate_response_transform(certificate_response):
    from azure.mgmt.iothubprovisioningservices.models import (CertificateListDescription,
                                                              CertificateResponse,
                                                              VerificationCodeResponse)
    if isinstance(certificate_response, CertificateListDescription) and certificate_response.value:
        for cert in certificate_response.value:
            cert = _replace_certificate_bytes(cert)
    if isinstance(certificate_response, (CertificateResponse, VerificationCodeResponse)):
        certificate_response = _replace_certificate_bytes(certificate_response)
    return certificate_response


def _replace_certificate_bytes(cert_object):
    properties = getattr(cert_object, 'properties', {})
    body = getattr(properties, 'certificate', None)
    if body:
        cert_bytes = _safe_decode(body)
        if not cert_bytes:
            from knack.log import get_logger
            logger = get_logger(__name__)
            logger.warning('Certificate `%s` contains invalid unicode characters; its body was omitted from output.',
                           cert_object.name)
        cert_object.properties.certificate = cert_bytes
    return cert_object


def _safe_decode(cert_bytes):
    if isinstance(cert_bytes, str):
        return cert_bytes
    if isinstance(cert_bytes, (bytearray, bytes)):
        try:
            return cert_bytes.decode('utf-8')
        except UnicodeDecodeError:
            return None
    return None


def parse_cosmos_db_connection_string(cs):
    validate = ["AccountEndpoint", "AccountKey"]
    return _parse_connection_string(cs, validate, "Cosmos DB Collection")


def _parse_connection_string(cs, validate=None, cstring_type="entity"):
    decomposed = _validate_key_value_pairs(cs)
    decomposed_lower = dict((k.lower(), v) for k, v in decomposed.items())
    if validate:
        for k in validate:
            if not any([decomposed.get(k), decomposed_lower.get(k.lower())]):
                raise ValueError(
                    "{} connection string has missing property: {}".format(
                        cstring_type, k
                    )
                )
    return decomposed


def _validate_key_value_pairs(string):
    """
    Funtion to validate key-value pairs in the format: a=b;c=d

    Args:
        string (str): semicolon delimited string of key/value pairs.

    Returns (dict, None): a dictionary of key value pairs.
    """
    result = None
    if string:
        kv_list = [x for x in string.split(";") if "=" in x]  # key-value pairs
        result = dict(x.split("=", 1) for x in kv_list)
    return result