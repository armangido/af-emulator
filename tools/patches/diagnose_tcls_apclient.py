#!/usr/bin/env python3
"""
Assault Fire PH - TCLS/APClient compatibility diagnostic.

Read-only helper: hashes TCLS.dll and verifies that server/PRIVATE.PEM and
TCLS/config/APClient.dat contain the same RSA public key. It also identifies
the verified original/pre-patch TCLS build and the exact raw-PEM-compatible
patched form used by the working preservation setup.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization

VALIDATED_TCLS_SHA256 = "3ff351e0adb594d7544e28db2e966a6d6eb548e9df70daaf4daf58f2ee438d56"
ORIGINAL_TCLS_SHA256 = "13ead403452e0f25cf00658369bf4bf5ff34ed1b16027f7833fb27d398386cd1"
ISSUE7_URL = "https://github.com/armangido/af-emulator/issues/7"


@dataclass(frozen=True)
class KeyCheck:
    apclient_sha256: str
    derived_public_sha256: str
    exact_bytes_match: bool
    same_rsa_key: bool
    apclient_length: int


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_tcls_hash(sha256_hex: str) -> str:
    value = sha256_hex.lower()
    if value == VALIDATED_TCLS_SHA256:
        return "validated-raw-pem-patched"
    if value == ORIGINAL_TCLS_SHA256:
        return "original-needs-raw-pem-patch"
    return "unknown"


def derive_public_pem(private_key_path: Path) -> bytes:
    private_key = serialization.load_pem_private_key(
        private_key_path.read_bytes(), password=None
    )
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def public_key_numbers(pem: bytes):
    key = serialization.load_pem_public_key(pem)
    public_numbers = getattr(key, "public_numbers", None)
    if public_numbers is None:
        raise ValueError("PEM does not contain a supported public key")
    nums = public_numbers()
    return (getattr(nums, "n", None), getattr(nums, "e", None))


def check_key_pair(private_key_path: Path, apclient_path: Path) -> KeyCheck:
    apclient = apclient_path.read_bytes()
    derived = derive_public_pem(private_key_path)
    try:
        same_rsa_key = public_key_numbers(apclient) == public_key_numbers(derived)
    except (ValueError, TypeError):
        same_rsa_key = False
    return KeyCheck(
        apclient_sha256=hashlib.sha256(apclient).hexdigest(),
        derived_public_sha256=hashlib.sha256(derived).hexdigest(),
        exact_bytes_match=(apclient == derived),
        same_rsa_key=same_rsa_key,
        apclient_length=len(apclient),
    )


def resolve_paths(args):
    root = args.client_root.expanduser().resolve() if args.client_root else None
    tcls = args.tcls or (root / "TCLS" / "Tenio" / "TCLS.dll" if root else None)
    apclient = args.apclient or (root / "TCLS" / "config" / "APClient.dat" if root else None)
    if tcls is None or apclient is None:
        raise SystemExit("Provide --client-root, or provide both --tcls and --apclient.")
    return (
        tcls.expanduser().resolve(),
        apclient.expanduser().resolve(),
        args.private_key.expanduser().resolve(),
    )


def require_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise SystemExit(f"{label} not found: {path}")


def print_tcls_result(tcls_path: Path, tcls_sha: str) -> str:
    classification = classify_tcls_hash(tcls_sha)
    print("[TCLS]")
    print(f"  path   : {tcls_path}")
    print(f"  SHA256 : {tcls_sha.upper()}")
    if classification == "validated-raw-pem-patched":
        print("  class  : validated raw-PEM-compatible PH TCLS build")
        print("  note   : exact patched form used by the working RSA/DH setup")
    elif classification == "original-needs-raw-pem-patch":
        print("  class  : verified original/pre-patch TCLS build from Issue #7")
        print("  note   : differs from the validated build only at the recovered")
        print("           raw-PEM loader compatibility edit sites")
        print("  fix    : tools/patches/patch_tcls_apclient_raw_pem.py")
        print(f"  issue  : {ISSUE7_URL}")
    else:
        print("  class  : unknown/unvalidated TCLS build")
        print("  note   : do not apply offsets or patch bytes from another build")
    return classification


def print_key_result(check: KeyCheck, apclient_path: Path, private_key_path: Path) -> None:
    print("\n[RSA / APClient.dat]")
    print(f"  private key        : {private_key_path}")
    print(f"  APClient.dat       : {apclient_path}")
    print(f"  APClient length    : {check.apclient_length} bytes")
    print(f"  APClient SHA256    : {check.apclient_sha256.upper()}")
    print(f"  derived pub SHA256 : {check.derived_public_sha256.upper()}")
    print(f"  exact byte match   : {'YES' if check.exact_bytes_match else 'NO'}")
    print(f"  same RSA key       : {'YES' if check.same_rsa_key else 'NO'}")
    if check.apclient_length == 272:
        print("  format hint        : expected 272-byte RSA-1024 SPKI PEM length")
    else:
        print("  format hint        : length differs from the known 272-byte PH PEM")


def print_diagnosis(classification: str, check: KeyCheck) -> None:
    print("\n[DIAGNOSIS]")
    if not check.same_rsa_key:
        print("  PRIVATE.PEM and APClient.dat do not represent the same RSA public key.")
        print("  Fix the key pair before debugging the AUTH protocol.")
        return
    if classification == "original-needs-raw-pem-patch":
        print("  The RSA pair matches. Regenerating the keys is not the fix.")
        print("  This is the verified original/pre-patch TCLS build.")
        print("  Close client.exe/TCLS and apply the recovered raw-PEM compatibility patch:")
        print("    python tools/patches/patch_tcls_apclient_raw_pem.py <TCLS.dll> --apply")
        return
    if classification == "validated-raw-pem-patched":
        print("  TCLS is the verified raw-PEM-compatible build and the RSA pair matches.")
        print("  If VERSION works but AUTH never connects, verify the launcher loaded")
        print("  this exact DLL copy and then inspect the local AP/TCLS initialization.")
        return
    print("  The RSA pair matches, but this TCLS hash is unvalidated.")
    print("  Capture the network sequence and loaded TCLS path before patching anything.")


def parse_args():
    repo_root = Path(__file__).resolve().parents[2]
    ap = argparse.ArgumentParser(description="Read-only TCLS/APClient compatibility diagnostic")
    ap.add_argument("--client-root", type=Path, help=r'Assault Fire root, e.g. "D:\\AssaultFirePH"')
    ap.add_argument("--tcls", type=Path, help="explicit path to TCLS.dll")
    ap.add_argument("--apclient", type=Path, help="explicit path to APClient.dat")
    ap.add_argument(
        "--private-key", type=Path, default=repo_root / "server" / "PRIVATE.PEM",
        help="server private PEM (default: repository server/PRIVATE.PEM)",
    )
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    tcls_path, apclient_path, private_key_path = resolve_paths(args)
    require_file(tcls_path, "TCLS.dll")
    require_file(apclient_path, "APClient.dat")
    require_file(private_key_path, "PRIVATE.PEM")

    print("Assault Fire PH - TCLS/APClient diagnostic")
    print("Read-only: no client or server file will be modified.\n")
    classification = print_tcls_result(tcls_path, sha256_file(tcls_path))
    try:
        check = check_key_pair(private_key_path, apclient_path)
    except Exception as exc:
        print(f"\nERROR: could not parse/compare RSA material: {exc}")
        return 2
    print_key_result(check, apclient_path, private_key_path)
    print_diagnosis(classification, check)
    return 0 if check.same_rsa_key else 2


if __name__ == "__main__":
    sys.exit(main())
