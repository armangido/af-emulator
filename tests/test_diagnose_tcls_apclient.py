from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "patches" / "diagnose_tcls_apclient.py"
spec = spec_from_file_location("diagnose_tcls_apclient", MODULE_PATH)
mod = module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def test_known_tcls_hashes_are_classified():
    assert mod.classify_tcls_hash(mod.VALIDATED_TCLS_SHA256) == "validated-raw-pem-patched"
    assert mod.classify_tcls_hash(mod.ORIGINAL_TCLS_SHA256.upper()) == "original-needs-raw-pem-patch"
    assert mod.classify_tcls_hash("00" * 32) == "unknown"


def test_matching_private_and_apclient_are_detected(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    private_path = tmp_path / "PRIVATE.PEM"
    apclient_path = tmp_path / "APClient.dat"
    private_path.write_bytes(private_pem)
    apclient_path.write_bytes(public_pem)

    result = mod.check_key_pair(private_path, apclient_path)
    assert result.same_rsa_key is True
    assert result.exact_bytes_match is True
    assert result.apclient_length == 272


def test_mismatched_key_pair_is_detected(tmp_path):
    key_a = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    key_b = rsa.generate_private_key(public_exponent=65537, key_size=1024)

    private_path = tmp_path / "PRIVATE.PEM"
    apclient_path = tmp_path / "APClient.dat"
    private_path.write_bytes(
        key_a.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    apclient_path.write_bytes(
        key_b.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    result = mod.check_key_pair(private_path, apclient_path)
    assert result.same_rsa_key is False
    assert result.exact_bytes_match is False
