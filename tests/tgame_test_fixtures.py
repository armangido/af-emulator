"""Minimal sparse PE fixtures for the TGame patch-site tests."""

from __future__ import annotations

import struct
import sys
from pathlib import Path

PATCH_TOOLS = Path(__file__).resolve().parents[1] / "tools" / "patches"
if str(PATCH_TOOLS) not in sys.path:
    sys.path.insert(0, str(PATCH_TOOLS))

import tgame_binary  # noqa: E402
import tgame_servermove_v4  # noqa: E402


IMAGE_BASE = 0x00400000
SECTION_RVA = 0x1000
RAW_POINTER = 0x200


def write_tgame_fixture(
    path: Path,
    state: str = "unpatched",
    *,
    dynamic_base: bool = False,
    servermove_compatible: bool = False,
) -> Path:
    path = Path(path)
    trampoline_rva = tgame_binary.TARGET_RVA - 0x200
    if state == "pic-patched":
        patched_stub = tgame_binary.build_static_trampoline(
            tgame_binary.TARGET_RVA, trampoline_rva
        )
    else:
        patched_stub = tgame_binary.build_trampoline(
            IMAGE_BASE + tgame_binary.TARGET_RVA + len(tgame_binary.EXPECTED_ORIGINAL)
        )
    last_rva = max(
        tgame_binary.TARGET_RVA + tgame_binary.PATCHED_ENTRY_SIZE,
        trampoline_rva + len(patched_stub),
    )
    if servermove_compatible:
        last_rva = max(
            last_rva,
            max(
                (
                    vtable - IMAGE_BASE + 0x52C
                    for vtable, _move_impl, _pwsm_impl
                    in tgame_servermove_v4.KNOWN_VTABLES.values()
                ),
                default=0,
            ),
            tgame_servermove_v4.PZ_DIRECT_BASE_CALL - IMAGE_BASE + 5,
        )
    virtual_size = ((last_rva - SECTION_RVA + 0xFFF) // 0x1000) * 0x1000
    raw_size = (
        0x1000
        if state == "virtual-only"
        else 0x3000
        if state in {"relocated", "relocated-patched", "relocated-ambiguous"}
        else virtual_size
    )

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("wb") as stream:
        stream.truncate(RAW_POINTER + raw_size)

    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    optional = bytearray(0xE0)
    struct.pack_into("<H", optional, 0, 0x010B)
    struct.pack_into("<I", optional, 4, raw_size)  # SizeOfCode
    struct.pack_into("<I", optional, 28, IMAGE_BASE)
    struct.pack_into("<I", optional, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", optional, 36, 0x200)  # FileAlignment
    struct.pack_into("<I", optional, 56, SECTION_RVA + virtual_size)  # SizeOfImage
    struct.pack_into("<I", optional, 60, 0x200)
    dll_characteristics = 0x0040 if dynamic_base else 0
    struct.pack_into("<H", optional, 70, dll_characteristics)

    coff = struct.pack("<HHIIIHH", 0x014C, 1, 0, 0, 0, len(optional), 0x010F)
    section = bytearray(40)
    section[:8] = b".text\0\0\0"
    struct.pack_into(
        "<IIII", section, 8, virtual_size, SECTION_RVA, raw_size, RAW_POINTER
    )
    struct.pack_into("<I", section, 36, 0x60000020)  # code + execute + read

    with path.open("r+b") as stream:
        stream.seek(0)
        stream.write(dos)
        stream.seek(0x80)
        stream.write(b"PE\0\0" + coff + optional + section)

        target_offset = RAW_POINTER + tgame_binary.TARGET_RVA - SECTION_RVA
        if state == "unpatched":
            entry = tgame_binary.EXPECTED_ORIGINAL
        elif state in {"patched", "pic-patched"}:
            displacement = trampoline_rva - (tgame_binary.TARGET_RVA + 5)
            entry = b"\xE9" + struct.pack("<i", displacement) + b"\x90\x90\x90"
            trampoline_offset = RAW_POINTER + trampoline_rva - SECTION_RVA
            stream.seek(trampoline_offset)
            stream.write(patched_stub)
        elif state == "bad-trampoline":
            displacement = trampoline_rva - (tgame_binary.TARGET_RVA + 5)
            entry = b"\xE9" + struct.pack("<i", displacement) + b"\x90\x90\x90"
            trampoline_offset = RAW_POINTER + trampoline_rva - SECTION_RVA
            stream.seek(trampoline_offset)
            stream.write(b"\xCC" * len(patched_stub))
        elif state == "unknown":
            entry = b"\xCC" * tgame_binary.PATCHED_ENTRY_SIZE
        elif state in {
            "virtual-only", "relocated", "relocated-patched", "relocated-ambiguous"
        }:
            entry = None
        else:
            raise ValueError(f"unknown fixture state: {state}")

        if entry is not None:
            stream.seek(target_offset)
            stream.write(entry)
        if state == "relocated":
            alternate_rva = 0x2000
            stream.seek(RAW_POINTER + alternate_rva - SECTION_RVA)
            stream.write(tgame_binary.EXPECTED_ORIGINAL)
        elif state == "relocated-ambiguous":
            for alternate_rva in (0x2000, 0x2800):
                stream.seek(RAW_POINTER + alternate_rva - SECTION_RVA)
                stream.write(tgame_binary.EXPECTED_ORIGINAL)
        elif state == "relocated-patched":
            alternate_rva = 0x2000
            alternate_trampoline_rva = 0x1E00
            displacement = alternate_trampoline_rva - (alternate_rva + 5)
            entry = (
                b"\xE9"
                + struct.pack("<i", displacement)
                + tgame_binary.PATCHED_ENTRY_SUFFIX
            )
            trampoline = tgame_binary.build_trampoline(
                IMAGE_BASE + alternate_rva + len(tgame_binary.EXPECTED_ORIGINAL)
            )
            stream.seek(RAW_POINTER + alternate_rva - SECTION_RVA)
            stream.write(entry)
            stream.seek(RAW_POINTER + alternate_trampoline_rva - SECTION_RVA)
            stream.write(trampoline)
        if servermove_compatible:
            def write_va(va: int, data: bytes) -> None:
                rva = int(va) - IMAGE_BASE
                stream.seek(RAW_POINTER + rva - SECTION_RVA)
                stream.write(data)

            def call_rel32(site_va: int, target_va: int) -> bytes:
                return b"\xE8" + struct.pack("<i", int(target_va) - (int(site_va) + 5))

            # Minimal exact native anchors required by tgame_servermove_v4.py.
            write_va(
                tgame_servermove_v4.SERVERMOVE_STUB,
                tgame_servermove_v4.STOCK_STUB,
            )
            for va, expected in {
                0x008EF060: bytes.fromhex("83 EC 14 83 3D A4 E9 05"),
                0x00DA3980: bytes.fromhex("6A 00"),
                0x00D9C1A0: bytes.fromhex("6A FF 68"),
                0x015E0AD0: bytes.fromhex("83 EC 10 8B 44 24"),
                0x00934DA0: bytes.fromhex("83 EC 0C 56"),
                0x00BE82E0: bytes.fromhex("83 EC 5C"),
                0x004EA100: bytes.fromhex("6A FF 68 10 CE 8B 01"),
                0x009564ED: bytes.fromhex(
                    "89 0D 38 3F 06 02 89 15 3C 3F 06 02"
                ),
            }.items():
                write_va(va, expected)

            write_va(
                0x00A7C918,
                call_rel32(0x00A7C918, 0x00D9C1A0)
                + bytes.fromhex("83 B8 AC 03 00 00 00"),
            )
            write_va(
                0x00934DFD,
                call_rel32(0x00934DFD, 0x00BE82E0),
            )

            for _label, (vtable, move_impl, pwsm_impl) in (
                tgame_servermove_v4.KNOWN_VTABLES.items()
            ):
                write_va(vtable + 0x4C8, struct.pack("<I", tgame_servermove_v4.SERVERMOVE_STUB))
                write_va(vtable + 0x4CC, struct.pack("<I", tgame_servermove_v4.CORRECTION_IMPL))
                write_va(vtable + 0x4D0, struct.pack("<I", move_impl))
                write_va(vtable + 0x528, struct.pack("<I", pwsm_impl))

            write_va(
                tgame_servermove_v4.PZ_DIRECT_BASE_CALL,
                call_rel32(
                    tgame_servermove_v4.PZ_DIRECT_BASE_CALL,
                    tgame_servermove_v4.SERVERMOVE_STUB,
                ),
            )

            # The supported image contains exactly 33 literal references to the
            # shared stripped ServerMove entry. Build the remaining references
            # into an otherwise unused low-RVA fixture range.
            stream.flush()
            stream.seek(0)
            ref = struct.pack("<I", tgame_servermove_v4.SERVERMOVE_STUB)
            existing_refs = stream.read().count(ref)
            if existing_refs > 33:
                raise AssertionError(
                    f"fixture unexpectedly contains {existing_refs} ServerMove refs"
                )
            filler_refs = 33 - existing_refs
            if filler_refs:
                write_va(IMAGE_BASE + 0x4000, ref * filler_refs)

    return path
