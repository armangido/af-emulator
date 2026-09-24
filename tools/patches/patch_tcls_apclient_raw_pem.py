#!/usr/bin/env python3
"""
Assault Fire PH - verified raw-PEM TCLS compatibility patcher.

This helper patches one exact original TCLS.dll build so CAPAccount::LoadPublicKey
uses the raw APClient.dat PEM path used by the validated local preservation setup.

Verified source SHA-256:
  13ead403452e0f25cf00658369bf4bf5ff34ed1b16027f7833fb27d398386cd1

Verified patched SHA-256:
  3ff351e0adb594d7544e28db2e966a6d6eb548e9df70daaf4daf58f2ee438d56

The patch is two edit sites / four changed bytes:
  RVA/file offset 0x000E07EA: FF 52 28 -> 90 90 90
  RVA/file offset 0x000E07F6: B4       -> B8

The .text section for this DLL has matching RVA/file offsets at these locations.
The first edit skips a virtual call in CAPAccount::LoadPublicKey; the second
changes the final copy source from [ebp-0x44C] to [ebp-0x448], selecting the
raw APClient.dat buffer used by the verified working setup.

Safety:
* Only the exact source hash is accepted for --apply.
* Expected original bytes are checked before writing.
* The fully patched output hash must match the verified target hash.
* A .bak copy is created before replacement unless the exact source backup
  already exists.
* Unknown DLLs are never modified.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import sys
import tempfile
from pathlib import Path

SOURCE_SHA256 = "13ead403452e0f25cf00658369bf4bf5ff34ed1b16027f7833fb27d398386cd1"
PATCHED_SHA256 = "3ff351e0adb594d7544e28db2e966a6d6eb548e9df70daaf4daf58f2ee438d56"

PATCHES = (
    (0x000E07EA, bytes.fromhex("FF 52 28"), bytes.fromhex("90 90 90")),
    (0x000E07F6, bytes.fromhex("B4"), bytes.fromhex("B8")),
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def classify_hash(value: str) -> str:
    value = value.lower()
    if value == SOURCE_SHA256:
        return "original-needs-raw-pem-patch"
    if value == PATCHED_SHA256:
        return "already-patched"
    return "unknown"


def verify_sites(data: bytes, expect_patched: bool = False) -> None:
    for offset, original, patched in PATCHES:
        expected = patched if expect_patched else original
        actual = data[offset:offset + len(expected)]
        if actual != expected:
            raise RuntimeError(
                f"signature mismatch at 0x{offset:08X}: "
                f"expected {expected.hex(' ').upper()}, "
                f"found {actual.hex(' ').upper()}"
            )


def patched_bytes(source: bytes) -> bytes:
    if sha256_bytes(source) != SOURCE_SHA256:
        raise RuntimeError("source hash is not the verified original TCLS build")
    verify_sites(source, expect_patched=False)
    out = bytearray(source)
    for offset, original, patched in PATCHES:
        out[offset:offset + len(original)] = patched
    result = bytes(out)
    verify_sites(result, expect_patched=True)
    actual = sha256_bytes(result)
    if actual != PATCHED_SHA256:
        raise RuntimeError(
            "patched result hash mismatch: "
            f"expected {PATCHED_SHA256}, got {actual}"
        )
    return result


def default_backup(path: Path) -> Path:
    return path.with_name(path.name + ".bak")


def ensure_backup(path: Path, source_data: bytes) -> Path:
    backup = default_backup(path)
    if backup.exists():
        backup_hash = sha256_file(backup)
        if backup_hash == SOURCE_SHA256:
            print(f"[BACKUP] Existing verified source backup kept: {backup}")
            return backup
        raise RuntimeError(
            f"backup already exists but is not the verified source build: {backup}\n"
            f"backup SHA256: {backup_hash.upper()}\n"
            "Move/rename that file before applying the patch."
        )
    shutil.copy2(path, backup)
    if sha256_file(backup) != SOURCE_SHA256:
        raise RuntimeError("backup verification failed")
    print(f"[BACKUP] {path}")
    print(f"      -> {backup}")
    return backup


def atomic_replace(path: Path, data: bytes) -> None:
    fd, temp_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
    )
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        temp = Path(temp_name)
        if sha256_file(temp) != PATCHED_SHA256:
            raise RuntimeError("temporary patched file failed SHA-256 verification")
        os.replace(temp, path)
    finally:
        temp = Path(temp_name)
        if temp.exists():
            temp.unlink()


def check(path: Path) -> int:
    if not path.is_file():
        print(f"ERROR: TCLS.dll not found: {path}")
        return 2
    digest = sha256_file(path)
    state = classify_hash(digest)
    print(f"[TCLS] {path}")
    print(f"[SHA256] {digest.upper()}")
    if state == "original-needs-raw-pem-patch":
        print("[STATE] Verified original Issue #7 / pre-raw-PEM build")
        verify_sites(path.read_bytes(), expect_patched=False)
        print("[SITES] Original patch signatures match.")
        print("[NEXT] Close client.exe/TCLS, then rerun with --apply.")
        return 1
    if state == "already-patched":
        print("[STATE] Already patched for raw APClient.dat PEM compatibility")
        verify_sites(path.read_bytes(), expect_patched=True)
        print("[SITES] Patched signatures match.")
        return 0
    print("[STATE] Unknown/unvalidated TCLS build")
    print("[SAFE] Nothing will be patched.")
    return 2


def apply(path: Path) -> int:
    if not path.is_file():
        raise RuntimeError(f"TCLS.dll not found: {path}")
    source = path.read_bytes()
    digest = sha256_bytes(source)
    if digest == PATCHED_SHA256:
        print("[OK] TCLS.dll is already the verified patched build.")
        return 0
    if digest != SOURCE_SHA256:
        raise RuntimeError(
            "refusing to modify an unknown TCLS.dll\n"
            f"found SHA256   : {digest.upper()}\n"
            f"expected source: {SOURCE_SHA256.upper()}"
        )
    result = patched_bytes(source)
    ensure_backup(path, source)
    atomic_replace(path, result)
    final_hash = sha256_file(path)
    if final_hash != PATCHED_SHA256:
        raise RuntimeError("post-write verification failed")
    print("[OK] Applied verified raw-PEM TCLS compatibility patch.")
    print(f"[SHA256] {final_hash.upper()}")
    print("[PATCH] 0x000E07EA: FF 52 28 -> 90 90 90")
    print("[PATCH] 0x000E07F6: B4       -> B8")
    return 0


def restore(path: Path) -> int:
    backup = default_backup(path)
    if not backup.is_file():
        raise RuntimeError(f"verified backup not found: {backup}")
    backup_data = backup.read_bytes()
    backup_hash = sha256_bytes(backup_data)
    if backup_hash != SOURCE_SHA256:
        raise RuntimeError(
            "refusing restore because backup hash is not the verified source build\n"
            f"backup SHA256: {backup_hash.upper()}"
        )
    current_hash = sha256_file(path) if path.exists() else None
    if current_hash not in (PATCHED_SHA256, SOURCE_SHA256):
        raise RuntimeError(
            "refusing to overwrite an unknown current TCLS.dll during restore"
        )
    shutil.copy2(backup, path)
    if sha256_file(path) != SOURCE_SHA256:
        raise RuntimeError("restore verification failed")
    print("[OK] Restored verified original TCLS.dll from backup.")
    print(f"[SHA256] {SOURCE_SHA256.upper()}")
    return 0


def parse_args():
    ap = argparse.ArgumentParser(
        description="Patch the verified Assault Fire PH TCLS raw-PEM loader build"
    )
    ap.add_argument(
        "tcls",
        type=Path,
        help=r'path to TCLS.dll, e.g. "D:\AssaultFirePH\TCLS\Tenio\TCLS.dll"',
    )
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true", help="apply the verified patch")
    mode.add_argument("--restore", action="store_true", help="restore from TCLS.dll.bak")
    return ap.parse_args()


def main() -> int:
    args = parse_args()
    path = args.tcls.expanduser().resolve()
    try:
        if args.apply:
            return apply(path)
        if args.restore:
            return restore(path)
        return check(path)
    except Exception as exc:
        print(f"ERROR: {exc}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
