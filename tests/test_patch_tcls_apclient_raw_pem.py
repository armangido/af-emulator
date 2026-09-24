from importlib.util import module_from_spec, spec_from_file_location
from pathlib import Path
import sys

MODULE_PATH = Path(__file__).resolve().parents[1] / "tools" / "patches" / "patch_tcls_apclient_raw_pem.py"
spec = spec_from_file_location("patch_tcls_apclient_raw_pem", MODULE_PATH)
mod = module_from_spec(spec)
assert spec and spec.loader
sys.modules[spec.name] = mod
spec.loader.exec_module(mod)


def test_hash_classification():
    assert mod.classify_hash(mod.SOURCE_SHA256.upper()) == "original-needs-raw-pem-patch"
    assert mod.classify_hash(mod.PATCHED_SHA256) == "already-patched"
    assert mod.classify_hash("00" * 32) == "unknown"


def test_verified_patch_sites_are_exact():
    assert mod.PATCHES == (
        (0x000E07EA, bytes.fromhex("FF 52 28"), bytes.fromhex("90 90 90")),
        (0x000E07F6, bytes.fromhex("B4"), bytes.fromhex("B8")),
    )


def test_verify_sites_rejects_wrong_signature():
    size = max(offset + len(original) for offset, original, _ in mod.PATCHES)
    data = bytearray(size)
    for offset, original, _ in mod.PATCHES:
        data[offset:offset + len(original)] = original
    mod.verify_sites(bytes(data), expect_patched=False)

    data[0x000E07EA] ^= 0xFF
    try:
        mod.verify_sites(bytes(data), expect_patched=False)
    except RuntimeError as exc:
        assert "signature mismatch" in str(exc)
    else:
        raise AssertionError("verify_sites accepted a modified signature")
