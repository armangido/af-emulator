#!/usr/bin/env python3
r"""
AFDevLoader v48.2 - generic Assault Fire PH PvE dedicated-server loader.

Starts the validated local TGame_AFDEV runtime, enters true server mode, opens
the room-selected installed PvE map on the game thread, applies captured room
settings, verifies movement/correction and the live zero DS key, then publishes
SESSION_READY for the v9 bridge.

The repository never distributes TGame_AFDEV.exe. The one-click launcher builds
that private copy from the user's own verified TGame.exe and installs the
verified .afm4 ServerMove-v4 patch into the AFDEV copy only. Native ServerMove
v4 is now mandatory for the supported PH v1.0.0.24 AFDEV path: this loader
validates the live JMP/body and refuses to start gameplay if the local AFDEV
copy still contains the stripped stock stub. The older in-memory movement
bridge has been removed. Runtime addresses remain build-specific and every
required patch site is validated before execution resumes.
"""

import argparse
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import threading
import time
import uuid
import json


def _configure_utf8_stdio():
    """Prevent Windows legacy code pages from crashing diagnostic output."""
    for name in ("stdout", "stderr"):
        stream = getattr(sys, name, None)
        if stream is None or not hasattr(stream, "reconfigure"):
            continue
        try:
            stream.reconfigure(encoding="utf-8", errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


_configure_utf8_stdio()


DEFAULT_GAME_DIR = os.environ.get("AF_GAME_DIR", "")
DEFAULT_MAP = os.environ.get("AF_DS_DEFAULT_MAP", "")

# ---------------------------------------------------------------------------
# Validated addresses - clean PH TGame build
# ---------------------------------------------------------------------------

# Mandatory TCLS/GetLoginInfo failure path -> continue engine init.
LOGININFO_FAIL_VA = 0x014972F1
LOGININFO_EXPECT = bytes.fromhex("A1 20 D4 F9 01")
LOGININFO_PATCH  = bytes.fromhex("E9 17 01 00 00")  # jmp 0x0149740D

# TGTenio::DevLogin.
# Make it FAIL immediately instead of starting any Tencent/Tenio connection.
# Original function uses ret 14h.
DEVLOGIN_VA = 0x01494FF0
DEVLOGIN_EXPECT = bytes.fromhex("81 EC C8 01 00 00 A1 A0")
DEVLOGIN_OFFLINE_FAIL = bytes.fromhex(
    "31 C0"          # xor eax,eax
    "C2 14 00"      # ret 14h
    "90 90 90"      # padding
)

# v32 diagnostic: this exact PH build unconditionally does:
#   0x0134945C  mov [GIsClient], esi      ; esi == 1
#   0x01349462  mov [GIsServer], esi      ; temporary 1
#   ...
#   0x013494D8  mov [GIsClient], esi      ; 1
#   0x013494DE  mov [GIsServer], ebx      ; ebx == 0  <-- final reset
#
# The later UTGOnlineSubsystem DS registration gate tests GIsServer and skips
# TGDsDsmNetHandler/TGDsDsaNetHandler when it is zero.
#
# DIAGNOSTIC ONLY: NOP only that final 6-byte GIsServer reset so the engine's
# own earlier write of 1 survives into subsystem initialization.
GIS_CLIENT_VA = 0x01FD69C8
GIS_SERVER_VA = 0x01FD69CC
GIS_EDITOR_VA = 0x01FD69AC

GIS_SERVER_FINAL_RESET_VA = 0x013494DE
GIS_SERVER_FINAL_RESET_EXPECT = bytes.fromhex(
    "89 1D CC 69 FD 01"
)
GIS_SERVER_FINAL_RESET_PATCH = b"\x90" * 6

# v32 diagnostic: finish startup in a true dedicated-server mode pair:
#     GIsClient = 0
#     GIsServer = 1
#
# Exact original at 0x013494D8:
#     89 35 C8 69 FD 01    mov [0x01FD69C8], esi   ; esi == 1
#
# Replace only the source register:
#     89 1D C8 69 FD 01    mov [0x01FD69C8], ebx   ; ebx == 0
GIS_CLIENT_FINAL_WRITE_VA = 0x013494D8
GIS_CLIENT_FINAL_WRITE_EXPECT = bytes.fromhex(
    "89 35 C8 69 FD 01"
)
GIS_CLIENT_FINAL_WRITE_PATCH = bytes.fromhex(
    "89 1D C8 69 FD 01"
)

DSM_VTABLE_VA = 0x01D8EE60
DSM_CDO_NAME_INDEX = 0x00002BF5

# Real UGameEngine::Exec-like handler.
# We statically verified this function parses the UTF-16 command "OPEN".
# UTGameEngine::Exec override. It falls through to UGameEngine::Exec.
TGAMEENGINE_EXEC_VA = 0x015B8980

# Global pointers.
GENGINE_PTR_VA = 0x02063820
GLOG_PTR_VA    = 0x01F9D420

# Live UE3 world pointer used directly by LoadMap/Tick in this build.
GWORLD_PTR_VA  = 0x02066BF8

# ---------------------------------------------------------------------------
# v72 TRUE-DS zero-DSKey live socket rekey
# ---------------------------------------------------------------------------
# Retail A11A currently advertises a 16-byte all-zero DSKey.  In true-DS mode
# the PH socket constructor instead selects the built-in dedicated-server key.
# v72 fixes ONLY the live encrypted UDP socket AES context by calling AFDEV's
# own AES SetKey routine.  The static key constant and executable on disk are
# never modified.
V72_OFF_WORLD_NETDRIVER = 0xD8
V72_OFF_NETDRIVER_SOCKET = 0x1A8
V72_SOCKET_CRYPTO_ENABLED = 0x18
V72_SOCKET_AES_CONTEXT = 0x1C
V72_AES_SETKEY = 0x004039C0
V72_ZERO_DSKEY = b"\x00" * 16
V72_HARDCODED_DS_KEY_VA = 0x01DC0DA4
V72_EXPECTED_HARDCODED_DS_KEY = bytes.fromhex(
    "7467616d651fe92c9a971a0cd1f610fb"
)

# OPEN's vtable target stores the requested travel URL here.
# FString layout: Data*, Num, Max (12 bytes), then a separate byte/state flag.
PENDING_URL_OFFSET = 0x674
PENDING_FLAG_OFFSET = 0x680

# Fullscreen/loading movie stop wrapper used by TGame's LoadMap path.
#
# 0095B1C0:
#   if (arg != 0)
#       GFullScreenMovie->vfunc_38();
#   else
#       GFullScreenMovie->vfunc_1C(...);
#
# LoadMap calls this wrapper with arg=1 when stopping the loading movie.
STOP_LOADING_MOVIE_VA = 0x0095B1C0

# Assault Fire's separate LoadingMovie UI routine.
#
# Static reverse engineering:
#   0x01257FB0(... five stack args ...)
#
# Its first argument controls Show/Hide. With arg1=0 and arg5=0 it enters
# the LoadingMovie hide path at 0x01258099. Passing all five arguments as 0
# requests an immediate hide without the PostLoadPause/StreamByURL path.
AF_SHOW_LOADING_MOVIE_VA = 0x01257FB0

# UGameEngine layout confirmed by the same routine.
#
#   GEngine+0x47C = TArray<ULocalPlayer*>::Data
#   GEngine+0x480 = Count
#   GEngine+0x484 = Max
#
# It then checks:
#   LocalPlayer+0x40
# which is the player's PlayerController/Actor pointer in this build.
GAMEPLAYERS_OFFSET = 0x47C
LOCALPLAYER_PC_OFFSET = 0x40

# ---------------------------------------------------------------------------
# v24 PVE synthetic-listen-host fix
#
# TGSV3/PVE StartGame installs TimerCheckStartGame.  That timer fires on the
# FIRST PVEPlayerController for which:
#     !PC.bWaitingLoadingProcessComplete
#     PRI != None
#     !PRI.bAlwaysObserver
#
# AFDevLoader necessarily creates a synthetic GamePlayers[0] local controller
# inside TGame_AFDEV.exe.  In the broken runs that synthetic host was becoming
# the first eligible PVE player and consuming the one-shot GameStart event
# before the real network client finished loading.
#
# Neutralize ONLY GamePlayers[0]'s PRI by setting bAlwaysObserver.  The remote
# network client's PRI is never touched.
PVE_PC_VTABLE_V24 = 0x01E24C28
PVE_PC_PRI_OFFSET_V24 = 0x1DC
PVE_PRI_FLAGS_OFFSET_V24 = 0x3C0
PVE_PRI_ALWAYS_OBSERVER_MASK_V24 = 0x00000004

# Same-era UE3 controller layout. UPlayer+0x40 was already live-validated
# against Assault Fire in v0.12, so these are now used as READ-ONLY probes.
#
# AController:
#   +0x190 Pawn
#
# APlayerController:
#   +0x66C Player (UPlayer/ULocalPlayer)
#   +0x670 PlayerCamera
#   +0x688 AcknowledgedPawn
#
CONTROLLER_PAWN_OFFSET = 0x190
PC_PLAYER_OFFSET = 0x66C
PC_CAMERA_OFFSET = 0x670
PC_ACK_PAWN_OFFSET = 0x688

# ---------------------------------------------------------------------------
# Correct PH native class map + decoded tutorial defaults
# ---------------------------------------------------------------------------
#
# These were recovered from THIS exact clean TGame.exe:
#
#   TGGame:
#       ctor   0x013F9980
#       vtable 0x01D61948
#
#   TGTeamGame:
#       ctor   0x013F9A10
#       vtable 0x01D62530
#
#   TGPlayerController:
#       ctor   0x013F9BA0
#       vtable 0x01D64720
#       native size 0x9E0
#
#   TGPVPPlayerController:
#       ctor   0x013F9C00
#       vtable 0x01D651D8
#
#   TGTeamPlayerController:
#       ctor   0x013F9C30
#       vtable 0x01D65728
#       native size 0x9F8
#
#   TGPawn:
#       ctor   0x013EF8C0
#       vtable 0x01D5A830
#
#   TGTeamPawn:
#       ctor   0x013EF920
#       vtable 0x01D5B350
#       native size 0x1110
#
# The decoded PH UTGame.u package proves the intended tutorial classes:
#
#   TGTeamMatch_Tutorial extends TGTeamMatch
#
#   Default__TGTeamMatch_Tutorial.DefaultPawnClass
#       = TGTMPawn_Tutorial
#
#   Default__TGTeamMatch_Tutorial.PlayerControllerClass
#       = TGTMPlayerController_Tutorial
#
# TGTMPawn_Tutorial is a script subclass of TGTMPawn -> TGTeamPawn,
# therefore the expected native runtime vtable is TGTeamPawn's 0x01D5B350.
#
# TGTMPlayerController_Tutorial is a script subclass of
# TGTMPlayerController -> TGTeamPlayerController,
# therefore the expected native runtime vtable is 0x01D65728.
#
UTPLAYERCONTROLLER_VTABLE = 0x01D61428

TGGAME_VTABLE = 0x01D61948
TGTEAMGAME_VTABLE = 0x01D62530

TGPLAYERCONTROLLER_VTABLE = 0x01D64720
TGPVPPLAYERCONTROLLER_VTABLE = 0x01D651D8
TGTEAMPLAYERCONTROLLER_VTABLE = 0x01D65728

TGPLAYERCONTROLLER_SIZE = 0x9E0
TGTEAMPLAYERCONTROLLER_SIZE = 0x9F8

TGPAWN_VTABLE = 0x01D5A830
TGTEAMPAWN_VTABLE = 0x01D5B350
TGTEAMPAWN_NATIVE_SIZE = 0x1110

DEFAULT_GAME_CLASS = "PVEGame.TGSVGame"


# ---------------------------------------------------------------------------
# Native ServerMove v4
# ---------------------------------------------------------------------------
#
# The supported PH v1.0.0.24 AFDEV runtime must use the disk-restored
# ServerMove v4 body installed into the user's local TGame_AFDEV.exe.
# The loader validates the shared stripped-stub redirection before gameplay and
# never installs or patches controller vtables for movement at runtime.
#
PVE_SERVERMOVE_STUB_V48 = 0x013A88D0

SERVERMOVE_V4_HEAD = bytes.fromhex(
    "55 8B EC 53 56 57 83 EC 30 8B F1 8B 9E D8 01 00 "
    "00 85 DB 0F 84 56 02 00 00 F3 0F 10 45 08 F3 0F"
)
SERVERMOVE_V4_STOCK_STUB = bytes.fromhex("C2 28 00 CC CC")
STEEL_FORTRESS_MODE_ID_V4 = 0x00002002

# Mutation keeps its own settings path below. Its controller also reaches the
# shared ServerMove entry, so no movement-specific vtable patch is required.
BIO_MODE_ID_V49 = 0x00000204


# v45 established the legacy TGSV PvE round family with stock
# movement/ServerMove code untouched. v48 preserves that round flow and
# restores native MoveAutonomous plus the stock PH correction stage.
#
# Shipped PvE package analysis and PVEGame.u show that the ResetRound path uses
# TGSVGame with TGSVGameReplicationInfo. The generic PvE loader therefore uses
# PVEGame.TGSVGame rather than TGSVGame.TGSV3Game.
# v21: isolate the AFDEV listen-server process from TGame's normal
# single-instance named mutex. Static call site in the validated PH image:
#   0x01349D75 -> push 0x01D12F98
#   CreateMutexW(...)
#   GetLastError()==183 -> "multiple running instances" popup.
# Change only the final GUID nibble for this suspended AFDEV process.
SINGLE_INSTANCE_MUTEX_VA = 0x01D12F98
SINGLE_INSTANCE_MUTEX_ORIGINAL = (
    "TGAME_{D21F20CD-996C-4ae2-8BF8-F2A7B4CD20D5}\0".encode("utf-16le")
)
SINGLE_INSTANCE_MUTEX_SERVER = (
    "TGAME_{D21F20CD-996C-4ae2-8BF8-F2A7B4CD20D6}\0".encode("utf-16le")
)

# Exact UE3 world helpers recovered from this clean PH TGame.exe.
#
# UWorld::GetWorldInfo-like helper:
#     ecx = UWorld*
#     push 0
#     call 0x00D9C1A0
#     ret 4
#
# UWorld::SetGameInfo (called by LoadMap):
#     0x00DA2760
#
# Inside SetGameInfo the returned WorldInfo is stored locally and the spawned
# authoritative GameInfo actor is written to:
#
#     WorldInfo + 0x414
#
UWORLD_GETWORLDINFO_VA = 0x00D9C1A0
WORLDINFO_GAME_OFFSET = 0x414

# TGame image and its .idata region. Most UE3 object vtables for this build
# live in .idata; this is only used as a READ-ONLY heuristic.
TGAME_IMAGE_MIN = 0x00400000
TGAME_IMAGE_MAX = 0x025BE000
TGAME_IDATA_MIN = 0x019F6000
TGAME_IDATA_MAX = 0x01F9C21F

# ---------------------------------------------------------------------------
# LoadMap milestone instrumentation
# ---------------------------------------------------------------------------
#
# These are existing 5-byte "push <timing-log-string>" instructions inside
# the real UE3 LoadMap routine. v0.11 replaces each push with a JMP to a tiny
# trampoline which:
#
#   1) writes the stage number to a private marker
#   2) executes the ORIGINAL push instruction
#   3) jumps straight back to address+5
#
# So the actual LoadMap logic is preserved.
#
LOADMAP_STAGES = [
    (
        1,
        "Before Load level",
        0x009C8A0C,
        bytes.fromhex("68 E0 BB B4 01"),
    ),
    (
        2,
        "After World Init",
        0x009C8B37,
        bytes.fromhex("68 88 BC B4 01"),
    ),
    (
        3,
        "Before Handle pending level",
        0x009C91D1,
        bytes.fromhex("68 28 C0 B4 01"),
    ),
    (
        4,
        "After SetGameInfo",
        0x009C966D,
        bytes.fromhex("68 D8 C1 B4 01"),
    ),
    (
        5,
        "After BeginPlay",
        0x009C99AA,
        bytes.fromhex("68 88 C2 B4 01"),
    ),
    (
        6,
        "After Client init",
        0x009C9E44,
        bytes.fromhex("68 70 C3 B4 01"),
    ),
    (
        7,
        "Finished loading level",
        0x009CAAAF,
        bytes.fromhex("68 F0 C6 B4 01"),
    ),
]

IS_BOOT_FROM_TCLS_VA = 0x020D4B80

# Win32 constants.
CREATE_SUSPENDED = 0x00000004
CREATE_UNICODE_ENVIRONMENT = 0x00000400

PAGE_READWRITE = 0x04
PAGE_EXECUTE_READWRITE = 0x40

MEM_RESERVE = 0x2000
MEM_RELEASE = 0x8000

MEM_COMMIT = 0x1000
MEM_PRIVATE = 0x20000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100

# Commands we will try after the correct Tutorial controller exists.
# We stop as soon as a real TGTeamPawn-family object appears.
SPAWN_TRIGGER_COMMANDS = [
    "RESTARTPLAYER",
    "STARTMATCH",
    "QUICKRESTARTGAME",
    "RESTARTGAME",
    "STARTGAME",
    "SUMMON UTGame.TGTMPawn_Tutorial",
    "RESTARTLEVEL",
]

INFINITE = 0xFFFFFFFF
STILL_ACTIVE = 259
WAIT_OBJECT_0 = 0x00000000
WAIT_TIMEOUT = 0x00000102

WOW64_CONTEXT_i386 = 0x00010000
WOW64_CONTEXT_CONTROL = WOW64_CONTEXT_i386 | 0x00000001
WOW64_CONTEXT_INTEGER = WOW64_CONTEXT_i386 | 0x00000002
WOW64_CONTEXT_SEGMENTS = WOW64_CONTEXT_i386 | 0x00000004
WOW64_CONTEXT_FULL = (
    WOW64_CONTEXT_CONTROL |
    WOW64_CONTEXT_INTEGER |
    WOW64_CONTEXT_SEGMENTS
)


kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
shell32 = ctypes.WinDLL("shell32", use_last_error=True)


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.POINTER(ctypes.c_ubyte)),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]



class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress", ctypes.c_void_p),
        ("AllocationBase", ctypes.c_void_p),
        ("AllocationProtect", wintypes.DWORD),
        ("RegionSize", ctypes.c_size_t),
        ("State", wintypes.DWORD),
        ("Protect", wintypes.DWORD),
        ("Type", wintypes.DWORD),
    ]


class WOW64_FLOATING_SAVE_AREA(ctypes.Structure):
    _fields_ = [
        ("ControlWord", wintypes.DWORD),
        ("StatusWord", wintypes.DWORD),
        ("TagWord", wintypes.DWORD),
        ("ErrorOffset", wintypes.DWORD),
        ("ErrorSelector", wintypes.DWORD),
        ("DataOffset", wintypes.DWORD),
        ("DataSelector", wintypes.DWORD),
        ("RegisterArea", ctypes.c_ubyte * 80),
        ("Cr0NpxState", wintypes.DWORD),
    ]


class WOW64_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ContextFlags", wintypes.DWORD),

        ("Dr0", wintypes.DWORD),
        ("Dr1", wintypes.DWORD),
        ("Dr2", wintypes.DWORD),
        ("Dr3", wintypes.DWORD),
        ("Dr6", wintypes.DWORD),
        ("Dr7", wintypes.DWORD),

        ("FloatSave", WOW64_FLOATING_SAVE_AREA),

        ("SegGs", wintypes.DWORD),
        ("SegFs", wintypes.DWORD),
        ("SegEs", wintypes.DWORD),
        ("SegDs", wintypes.DWORD),

        ("Edi", wintypes.DWORD),
        ("Esi", wintypes.DWORD),
        ("Ebx", wintypes.DWORD),
        ("Edx", wintypes.DWORD),
        ("Ecx", wintypes.DWORD),
        ("Eax", wintypes.DWORD),

        ("Ebp", wintypes.DWORD),
        ("Eip", wintypes.DWORD),
        ("SegCs", wintypes.DWORD),
        ("EFlags", wintypes.DWORD),
        ("Esp", wintypes.DWORD),
        ("SegSs", wintypes.DWORD),

        ("ExtendedRegisters", ctypes.c_ubyte * 512),
    ]


# ---------------------------------------------------------------------------
# Win32 prototypes
# ---------------------------------------------------------------------------

kernel32.CreateProcessW.argtypes = [
    wintypes.LPCWSTR,
    wintypes.LPWSTR,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.BOOL,
    wintypes.DWORD,
    ctypes.c_void_p,
    wintypes.LPCWSTR,
    ctypes.POINTER(STARTUPINFOW),
    ctypes.POINTER(PROCESS_INFORMATION),
]
kernel32.CreateProcessW.restype = wintypes.BOOL

kernel32.ReadProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.ReadProcessMemory.restype = wintypes.BOOL

kernel32.WriteProcessMemory.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.POINTER(ctypes.c_size_t),
]
kernel32.WriteProcessMemory.restype = wintypes.BOOL

kernel32.VirtualProtectEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.VirtualProtectEx.restype = wintypes.BOOL

kernel32.VirtualAllocEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
    wintypes.DWORD,
]
kernel32.VirtualAllocEx.restype = ctypes.c_void_p

kernel32.VirtualQueryEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.POINTER(MEMORY_BASIC_INFORMATION),
    ctypes.c_size_t,
]
kernel32.VirtualQueryEx.restype = ctypes.c_size_t

kernel32.VirtualFreeEx.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    wintypes.DWORD,
]
kernel32.VirtualFreeEx.restype = wintypes.BOOL

kernel32.FlushInstructionCache.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
]
kernel32.FlushInstructionCache.restype = wintypes.BOOL

kernel32.ResumeThread.argtypes = [wintypes.HANDLE]
kernel32.ResumeThread.restype = wintypes.DWORD

kernel32.SuspendThread.argtypes = [wintypes.HANDLE]
kernel32.SuspendThread.restype = wintypes.DWORD

kernel32.Wow64GetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(WOW64_CONTEXT),
]
kernel32.Wow64GetThreadContext.restype = wintypes.BOOL

kernel32.Wow64SetThreadContext.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(WOW64_CONTEXT),
]
kernel32.Wow64SetThreadContext.restype = wintypes.BOOL

kernel32.GetExitCodeProcess.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.GetExitCodeProcess.restype = wintypes.BOOL

kernel32.CreateRemoteThread.argtypes = [
    wintypes.HANDLE,
    ctypes.c_void_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    ctypes.c_void_p,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.CreateRemoteThread.restype = wintypes.HANDLE

kernel32.GetExitCodeThread.argtypes = [
    wintypes.HANDLE,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.GetExitCodeThread.restype = wintypes.BOOL

kernel32.TerminateProcess.argtypes = [
    wintypes.HANDLE,
    wintypes.UINT,
]
kernel32.TerminateProcess.restype = wintypes.BOOL

kernel32.WaitForSingleObject.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
]
kernel32.WaitForSingleObject.restype = wintypes.DWORD

kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

shell32.IsUserAnAdmin.argtypes = []
shell32.IsUserAnAdmin.restype = wintypes.BOOL

shell32.ShellExecuteW.argtypes = [
    wintypes.HWND,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    ctypes.c_int,
]
shell32.ShellExecuteW.restype = ctypes.c_void_p


def winerr(prefix):
    e = ctypes.get_last_error()
    raise OSError(e, f"{prefix}: Win32 error {e}")


def ensure_admin():
    if shell32.IsUserAnAdmin():
        return

    params = subprocess.list2cmdline(
        [str(Path(__file__).resolve())] + sys.argv[1:]
    )

    print("[AFDEV] Requesting Administrator rights...")

    rc = shell32.ShellExecuteW(
        None,
        "runas",
        sys.executable,
        params,
        str(Path(__file__).resolve().parent),
        1,
    )

    value = int(ctypes.cast(rc, ctypes.c_void_p).value or 0)

    if value <= 32:
        raise SystemExit(
            f"UAC elevation failed/cancelled (ShellExecuteW={value})."
        )

    raise SystemExit(0)


def process_alive(hproc):
    code = wintypes.DWORD()

    if not kernel32.GetExitCodeProcess(
        hproc,
        ctypes.byref(code),
    ):
        return False

    return code.value == STILL_ACTIVE


def read_remote(hproc, address, size):
    buf = (ctypes.c_ubyte * size)()
    done = ctypes.c_size_t()

    if not kernel32.ReadProcessMemory(
        hproc,
        ctypes.c_void_p(address),
        ctypes.byref(buf),
        size,
        ctypes.byref(done),
    ):
        winerr(f"ReadProcessMemory(0x{address:08X})")

    if done.value != size:
        raise RuntimeError(
            f"short ReadProcessMemory at 0x{address:08X}: "
            f"{done.value}/{size}"
        )

    return bytes(buf)


def read_u32(hproc, address):
    return struct.unpack(
        "<I",
        read_remote(hproc, address, 4),
    )[0]


def write_remote(hproc, address, data):
    old = wintypes.DWORD()

    if not kernel32.VirtualProtectEx(
        hproc,
        ctypes.c_void_p(address),
        len(data),
        PAGE_EXECUTE_READWRITE,
        ctypes.byref(old),
    ):
        winerr(f"VirtualProtectEx(0x{address:08X})")

    try:
        src = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
        done = ctypes.c_size_t()

        if not kernel32.WriteProcessMemory(
            hproc,
            ctypes.c_void_p(address),
            ctypes.byref(src),
            len(data),
            ctypes.byref(done),
        ):
            winerr(f"WriteProcessMemory(0x{address:08X})")

        if done.value != len(data):
            raise RuntimeError(
                f"short WriteProcessMemory at 0x{address:08X}: "
                f"{done.value}/{len(data)}"
            )

        kernel32.FlushInstructionCache(
            hproc,
            ctypes.c_void_p(address),
            len(data),
        )

    finally:
        dummy = wintypes.DWORD()

        kernel32.VirtualProtectEx(
            hproc,
            ctypes.c_void_p(address),
            len(data),
            old.value,
            ctypes.byref(dummy),
        )


def verify_and_patch(hproc, address, expected, replacement, label):
    current = read_remote(
        hproc,
        address,
        len(expected),
    )

    print(
        f"[AFDEV] {label} @0x{address:08X}\n"
        f"        current : {current.hex(' ').upper()}\n"
        f"        expected: {expected.hex(' ').upper()}"
    )

    if current != expected:
        raise RuntimeError(
            f"{label}: bytes do not match validated build."
        )

    write_remote(
        hproc,
        address,
        replacement,
    )

    after = read_remote(
        hproc,
        address,
        len(replacement),
    )

    if after != replacement:
        raise RuntimeError(
            f"{label}: patch verification failed."
        )

    print(
        f"        patched : {after.hex(' ').upper()}"
    )


def wait_for_engine(hproc, timeout):
    # Some machines need considerably longer than 20 seconds to publish
    # GEngine even though UE3 is still making forward progress (GLog is
    # commonly live first). Keep the dead-process fast fail, but use a
    # configurable healthy-process deadline and report progress.
    started = time.monotonic()
    deadline = started + max(5.0, float(timeout))
    next_progress = started + 10.0
    last_engine = 0
    last_log = 0

    while True:
        if not process_alive(hproc):
            elapsed = time.monotonic() - started
            raise RuntimeError(
                "TGame exited before GEngine became ready "
                f"(elapsed={elapsed:.1f}s, "
                f"GEngine=0x{last_engine:08X}, "
                f"GLog=0x{last_log:08X})."
            )

        try:
            last_engine = read_u32(
                hproc,
                GENGINE_PTR_VA,
            )
            last_log = read_u32(
                hproc,
                GLOG_PTR_VA,
            )
        except OSError:
            pass

        if last_engine and last_log:
            return last_engine, last_log

        now = time.monotonic()
        if now >= deadline:
            elapsed = now - started
            raise RuntimeError(
                "Timed out waiting for UE3 globals. "
                f"elapsed={elapsed:.1f}s "
                f"GEngine=0x{last_engine:08X} "
                f"GLog=0x{last_log:08X}"
            )

        if now >= next_progress:
            elapsed = now - started
            print(
                f"[AFDEV] UE3 still starting: elapsed={elapsed:.1f}s "
                f"GEngine=0x{last_engine:08X} "
                f"GLog=0x{last_log:08X}",
                flush=True,
            )
            next_progress = now + 10.0

        time.sleep(0.10)



def safe_read_u32(hproc, address):
    try:
        return read_u32(hproc, address)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# v72 live encrypted-socket zero-DSKey rekey (integrated per AFDEV instance)
# ---------------------------------------------------------------------------

def v72_resolve_encrypted_socket(hproc):
    world = safe_read_u32(hproc, GWORLD_PTR_VA) or 0
    if not world:
        return 0, 0, 0
    driver = safe_read_u32(hproc, world + V72_OFF_WORLD_NETDRIVER) or 0
    if not driver:
        return world, 0, 0
    sock = safe_read_u32(hproc, driver + V72_OFF_NETDRIVER_SOCKET) or 0
    return world, driver, sock


def v72_make_rekey_stub(ctx_addr, key_addr):
    # cdecl: AES_SetKey(ctx, key, 128)
    return (
        b"\x68\x80\x00\x00\x00"
        + b"\x68" + struct.pack("<I", key_addr)
        + b"\x68" + struct.pack("<I", ctx_addr)
        + b"\xB8" + struct.pack("<I", V72_AES_SETKEY)
        + b"\xFF\xD0"
        + b"\x83\xC4\x0C"
        + b"\x33\xC0"
        + b"\xC3"
    )


def v72_run_remote_stub(hproc, stub_addr):
    tid = wintypes.DWORD()
    ht = kernel32.CreateRemoteThread(
        hproc,
        None,
        0,
        ctypes.c_void_p(stub_addr),
        None,
        0,
        ctypes.byref(tid),
    )
    if not ht:
        winerr("CreateRemoteThread(v72 AES SetKey)")
    try:
        wr = kernel32.WaitForSingleObject(ht, 5000)
        if wr == WAIT_TIMEOUT:
            raise RuntimeError("v72 remote AES SetKey thread timed out")
        if wr != WAIT_OBJECT_0:
            raise RuntimeError(f"v72 WaitForSingleObject returned 0x{wr:08X}")
        code = wintypes.DWORD()
        if kernel32.GetExitCodeThread(ht, ctypes.byref(code)):
            return code.value
        return None
    finally:
        kernel32.CloseHandle(ht)


def v72_rekey_socket(hproc, sock, remote_base):
    enabled = safe_read_u32(hproc, sock + V72_SOCKET_CRYPTO_ENABLED)
    if enabled != 1:
        raise RuntimeError(
            f"v72 socket 0x{sock:08X} crypto flag +0x18 is {enabled!r}, expected 1"
        )

    ctx = sock + V72_SOCKET_AES_CONTEXT
    key_addr = remote_base + 0x100
    stub_addr = remote_base + 0x200

    write_remote(hproc, key_addr, V72_ZERO_DSKEY)
    write_remote(hproc, stub_addr, v72_make_rekey_stub(ctx, key_addr))

    before_head = read_remote(hproc, ctx, 16)
    before_dec = read_remote(hproc, ctx + 0x100, 16)
    before_rounds = safe_read_u32(hproc, ctx + 0x200)

    v72_run_remote_stub(hproc, stub_addr)

    after_head = read_remote(hproc, ctx, 16)
    after_dec = read_remote(hproc, ctx + 0x100, 16)
    after_rounds = safe_read_u32(hproc, ctx + 0x200)
    ok = after_head == V72_ZERO_DSKEY and after_rounds == 10

    return {
        "ctx": ctx,
        "enabled": enabled,
        "before_head": before_head,
        "before_dec": before_dec,
        "before_rounds": before_rounds,
        "after_head": after_head,
        "after_dec": after_dec,
        "after_rounds": after_rounds,
        "ok": ok,
    }


def arm_zero_dskey_guard_v72(hproc, timeout=15.0):
    """
    Apply the validated v72 live-socket fix before SESSION_READY, then keep a
    daemon guard alive so NetDriver/socket recreation is rekeyed automatically.
    This operates only on the AFDEV process handle owned by this loader.
    """
    hardcoded = read_remote(
        hproc,
        V72_HARDCODED_DS_KEY_VA,
        len(V72_EXPECTED_HARDCODED_DS_KEY),
    )
    print(
        f"[AFDEV-ZERO-DSKEY-v72] static server key @0x{V72_HARDCODED_DS_KEY_VA:08X}="
        f"{hardcoded.hex()}"
    )
    if hardcoded != V72_EXPECTED_HARDCODED_DS_KEY:
        raise RuntimeError(
            "v72 hardcoded server AES key bytes do not match the validated build"
        )

    rp = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not rp:
        winerr("VirtualAllocEx(v72 rekey page)")
    remote_base = int(ctypes.cast(rp, ctypes.c_void_p).value or 0)

    state = {
        "remote": remote_base,
        "socket": 0,
        "rekey_count": 0,
        "last_world": 0,
        "last_driver": 0,
        "verified": False,
    }

    deadline = time.time() + max(1.0, float(timeout))
    last_error = None
    while time.time() < deadline:
        if not process_alive(hproc):
            raise RuntimeError("AFDEV exited while waiting for v72 encrypted UDP socket")
        world, driver, sock = v72_resolve_encrypted_socket(hproc)
        if not sock:
            time.sleep(0.05)
            continue
        try:
            result = v72_rekey_socket(hproc, sock, remote_base)
            if not result["ok"]:
                raise RuntimeError("v72 AES zero-key schedule verification failed")
            state.update({
                "socket": sock,
                "rekey_count": 1,
                "last_world": world,
                "last_driver": driver,
                "verified": True,
            })
            print(
                f"[AFDEV-ZERO-DSKEY-v72] VERIFIED GWorld=0x{world:08X} "
                f"NetDriver=0x{driver:08X} Socket=0x{sock:08X} "
                f"CryptoEnabled={result['enabled']} before={result['before_head'].hex()} "
                f"after={result['after_head'].hex()} rounds={result['after_rounds']}"
            )
            break
        except Exception as exc:
            last_error = exc
            time.sleep(0.10)
    else:
        raise RuntimeError(
            "Timed out waiting for a verifiable v72 encrypted UDP socket"
            + (f": {last_error}" if last_error else "")
        )

    def worker():
        last_socket = state["socket"]
        while process_alive(hproc):
            try:
                world, driver, sock = v72_resolve_encrypted_socket(hproc)
                if not sock:
                    time.sleep(0.10)
                    continue
                ctx = sock + V72_SOCKET_AES_CONTEXT
                head = read_remote(hproc, ctx, 16)
                rounds = safe_read_u32(hproc, ctx + 0x200)
                if sock != last_socket or head != V72_ZERO_DSKEY or rounds != 10:
                    result = v72_rekey_socket(hproc, sock, remote_base)
                    if not result["ok"]:
                        raise RuntimeError("v72 guard rekey verification failed")
                    state["socket"] = sock
                    state["last_world"] = world
                    state["last_driver"] = driver
                    state["rekey_count"] += 1
                    state["verified"] = True
                    last_socket = sock
                    print(
                        f"[AFDEV-ZERO-DSKEY-v72] REKEYED recreated/reset socket=0x{sock:08X} "
                        f"count={state['rekey_count']} rounds={result['after_rounds']}"
                    )
                time.sleep(0.10)
            except Exception as exc:
                print(f"[AFDEV-ZERO-DSKEY-v72] guard retry after: {exc}")
                time.sleep(0.20)

    t = threading.Thread(
        target=worker,
        name="AFDEV-ZERO-DSKEY-v72",
        daemon=True,
    )
    t.start()
    return state, t



def arm_pve_synthetic_host_observer_v24(hproc, engine_ptr):
    """
    Background guard for AFDEV's synthetic GamePlayers[0] PVE controller.

    It polls the actual UGameEngine GamePlayers[0] pointer.  Only when that
    local PlayerController has the exact verified PVE PC vtable does it touch
    memory.  It then sets ONLY PRI.bAlwaysObserver (+0x3C0 mask 0x4).

    This is intentionally not a spawn/load/UI hack.  It prevents AFDEV's fake
    local frontend player from satisfying PVEGame.TimerCheckStartGame before
    the real remote player is ready.
    """
    state = {
        "first_patch": False,
        "patch_count": 0,
        "last_pc": 0,
        "last_pri": 0,
    }

    print(
        "[AFDEV-v24] Armed synthetic-host observer guard "
        "(GamePlayers[0] only)."
    )

    def worker():
        while process_alive(hproc):
            try:
                raw = read_remote(
                    hproc,
                    engine_ptr + GAMEPLAYERS_OFFSET,
                    12,
                )
                data_ptr, count, max_count = struct.unpack("<III", raw)

                if not (
                    data_ptr
                    and 1 <= count <= 32
                    and count <= max_count
                ):
                    time.sleep(0.005)
                    continue

                local_player = read_u32(hproc, data_ptr)
                if not local_player:
                    time.sleep(0.005)
                    continue

                pc = read_u32(
                    hproc,
                    local_player + LOCALPLAYER_PC_OFFSET,
                )
                if not pc:
                    time.sleep(0.005)
                    continue

                vt = read_u32(hproc, pc)
                if vt != PVE_PC_VTABLE_V24:
                    time.sleep(0.005)
                    continue

                pri = read_u32(
                    hproc,
                    pc + PVE_PC_PRI_OFFSET_V24,
                )
                if not pri:
                    time.sleep(0.005)
                    continue

                flags_addr = pri + PVE_PRI_FLAGS_OFFSET_V24
                old_flags = read_u32(hproc, flags_addr)
                new_flags = (
                    old_flags | PVE_PRI_ALWAYS_OBSERVER_MASK_V24
                )

                if new_flags != old_flags:
                    write_remote(
                        hproc,
                        flags_addr,
                        struct.pack("<I", new_flags),
                    )
                    verify = read_u32(hproc, flags_addr)
                    if not (
                        verify & PVE_PRI_ALWAYS_OBSERVER_MASK_V24
                    ):
                        raise RuntimeError(
                            "bAlwaysObserver verification failed"
                        )

                    state["patch_count"] += 1
                    state["last_pc"] = pc
                    state["last_pri"] = pri

                    if not state["first_patch"]:
                        state["first_patch"] = True
                        print(
                            "[AFDEV-v24] >>> PVE synthetic host neutralized "
                            f"BEFORE GameStart eligibility: "
                            f"PC=0x{pc:08X} PRI=0x{pri:08X} "
                            f"PRI+0x3C0 0x{old_flags:08X}"
                            f" -> 0x{verify:08X} "
                            "(bAlwaysObserver=TRUE)"
                        )
                    else:
                        print(
                            "[AFDEV-v24] Re-applied host bAlwaysObserver "
                            f"PC=0x{pc:08X} PRI=0x{pri:08X}"
                        )

                # Keep guarding.  Some lifecycle code can rewrite packed
                # PRI flag DWORDs; if bit 2 is ever cleared, restore it.
                time.sleep(0.010)

            except Exception:
                # Map/world swaps are expected while OPEN is travelling.
                time.sleep(0.010)

    t = threading.Thread(
        target=worker,
        name="AF-PVE-SyntheticHostObserver-v24",
        daemon=True,
    )
    t.start()
    return state, t


def read_remote_fstring(hproc, address, max_chars=512):
    """
    Read a UE3 FString/TArray<TCHAR>:
      +0 Data*
      +4 Num
      +8 Max
    """
    try:
        raw = read_remote(hproc, address, 12)
        ptr, num, cap = struct.unpack("<III", raw)

        if ptr == 0:
            return "", ptr, num, cap

        if num == 0:
            return "", ptr, num, cap

        # FString Num usually includes trailing NUL.
        if num > max_chars or cap > 0x100000 or num > cap:
            return f"<invalid FString ptr=0x{ptr:08X} num={num} max={cap}>", ptr, num, cap

        chars = read_remote(hproc, ptr, num * 2)
        text = chars.decode("utf-16le", errors="replace").rstrip("\x00")
        return text, ptr, num, cap

    except Exception as e:
        return f"<read error: {e}>", 0, 0, 0


def find_recent_log_files(game_root):
    """
    Assault Fire/UE3 builds vary in where -log writes.
    Probe likely locations and return existing .log files newest-first.
    """
    roots = [
        game_root / "TGame" / "Logs",
        game_root / "TGame" / "Log",
        game_root / "Binaries" / "Win32",
        game_root,
    ]

    found = []
    seen = set()

    for root in roots:
        if not root.is_dir():
            continue

        try:
            for p in root.glob("*.log"):
                rp = str(p.resolve()).lower()
                if rp in seen:
                    continue
                seen.add(rp)

                try:
                    found.append((p.stat().st_mtime, p))
                except OSError:
                    pass
        except OSError:
            pass

    found.sort(reverse=True)
    return [p for _, p in found]


def print_log_tail(path, max_lines=30):
    try:
        data = path.read_bytes()

        # UE3 logs can be ANSI or UTF-16.
        if data.startswith(b"\xff\xfe"):
            text = data.decode("utf-16le", errors="replace")
        else:
            # Detect likely UTF-16LE by NUL density.
            sample = data[:4096]
            nul_ratio = (sample.count(0) / max(1, len(sample)))
            if nul_ratio > 0.20:
                text = data.decode("utf-16le", errors="replace")
            else:
                text = data.decode("utf-8", errors="replace")

        lines = text.splitlines()
        print(f"[AFDEV] LOG TAIL: {path}")
        for line in lines[-max_lines:]:
            print(f"[TGLOG] {line}")

    except Exception as e:
        print(f"[AFDEV] Could not read log {path}: {e}")




def rel32(from_after_instruction, target):
    """
    x86 signed rel32 displacement encoded modulo 2^32.
    """
    return (target - from_after_instruction) & 0xFFFFFFFF


def install_loadmap_stage_hooks(hproc):
    """
    Install seven one-shot/non-destructive-in-behavior LoadMap milestone hooks.

    Returns:
        marker_ptr, instrumentation_base
    """
    # One page is enough for marker + 7 trampolines.
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(LoadMap instrumentation)")

    base = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    marker_ptr = base
    tramp_base = base + 0x100

    write_remote(
        hproc,
        marker_ptr,
        struct.pack("<I", 0),
    )

    print(
        f"[AFDEV] LoadMap stage marker @0x{marker_ptr:08X}"
    )

    for index, (stage, name, address, expected) in enumerate(
        LOADMAP_STAGES
    ):
        current = read_remote(
            hproc,
            address,
            5,
        )

        print(
            f"[AFDEV] Stage {stage} hook: {name}\n"
            f"        VA       : 0x{address:08X}\n"
            f"        current  : {current.hex(' ').upper()}\n"
            f"        expected : {expected.hex(' ').upper()}"
        )

        if current != expected:
            raise RuntimeError(
                f"LoadMap stage {stage} bytes do not match."
            )

        trampoline = tramp_base + index * 0x40

        # Original instruction is:
        #   push <imm32>
        original_imm = expected[1:5]

        code = bytearray()

        # mov dword ptr [marker_ptr], stage
        code += b"\xC7\x05"
        code += struct.pack("<I", marker_ptr)
        code += struct.pack("<I", stage)

        # Execute the exact original PUSH imm32.
        code += b"\x68" + original_imm

        # jmp address+5
        jump_back_from = trampoline + len(code) + 5
        code += b"\xE9" + struct.pack(
            "<I",
            rel32(
                jump_back_from,
                address + 5,
            ),
        )

        write_remote(
            hproc,
            trampoline,
            bytes(code),
        )

        # Replace original 5-byte PUSH with JMP trampoline.
        patch = (
            b"\xE9"
            + struct.pack(
                "<I",
                rel32(
                    address + 5,
                    trampoline,
                ),
            )
        )

        write_remote(
            hproc,
            address,
            patch,
        )

        after = read_remote(
            hproc,
            address,
            5,
        )

        if after != patch:
            raise RuntimeError(
                f"LoadMap stage {stage} hook verification failed."
            )

        print(
            f"        trampoline: 0x{trampoline:08X}"
        )

    print(
        "[AFDEV] All LoadMap milestone hooks installed."
    )

    return marker_ptr, base


def stage_name(stage):
    for number, name, _, _ in LOADMAP_STAGES:
        if number == stage:
            return name

    if stage == 0:
        return "LoadMap not entered"

    return "unknown"


def monitor_loadmap_stage(
    hproc,
    marker_ptr,
    seconds=30,
):
    print()
    print(
        "[AFDEV] ===== LOADMAP MILESTONE MONITOR ====="
    )

    previous = None
    highest = 0

    for i in range(seconds + 1):
        if not process_alive(hproc):
            print(
                "[AFDEV] TGame exited during LoadMap stage monitor."
            )
            return highest

        try:
            stage = read_u32(
                hproc,
                marker_ptr,
            )
        except Exception as e:
            print(
                f"[AFDEV] Stage marker read failed: {e}"
            )
            return highest

        if stage > highest:
            highest = stage

        if stage != previous:
            print(
                f"[MILESTONE +{i:02d}s] "
                f"stage={stage} -> {stage_name(stage)}"
            )
            previous = stage

        if stage >= 7:
            print(
                "[AFDEV] >>> LoadMap reached FINAL milestone 7."
            )
            break

        if i != seconds:
            time.sleep(1.0)

    print(
        f"[AFDEV] Highest LoadMap stage: "
        f"{highest} ({stage_name(highest)})"
    )
    print(
        "[AFDEV] ===== END MILESTONE MONITOR ====="
    )
    print()

    return highest


def sample_primary_thread(
    hproc,
    hthread,
    samples=12,
    interval=0.25,
):
    """
    If LoadMap does not reach stage 7, sample the primary/game thread EIP
    and a few stack dwords. This often exposes the exact wait/call where it
    is blocked.
    """
    print(
        "[AFDEV] ===== PRIMARY THREAD SAMPLES ====="
    )

    for i in range(samples):
        if not process_alive(hproc):
            break

        prev = kernel32.SuspendThread(
            hthread
        )

        if prev == 0xFFFFFFFF:
            print(
                "[AFDEV] SuspendThread failed during sampler."
            )
            break

        try:
            ctx = WOW64_CONTEXT()
            ctx.ContextFlags = WOW64_CONTEXT_FULL

            if not kernel32.Wow64GetThreadContext(
                hthread,
                ctypes.byref(ctx),
            ):
                print(
                    "[AFDEV] Wow64GetThreadContext failed during sampler."
                )
                break

            stack_words = []

            try:
                raw = read_remote(
                    hproc,
                    ctx.Esp,
                    8 * 4,
                )
                stack_words = list(
                    struct.unpack(
                        "<8I",
                        raw,
                    )
                )
            except Exception:
                stack_words = []

            stack_text = " ".join(
                f"{x:08X}"
                for x in stack_words
            )

            print(
                f"[THREAD {i:02d}] "
                f"EIP=0x{ctx.Eip:08X} "
                f"ESP=0x{ctx.Esp:08X} "
                f"stack={stack_text}"
            )

        finally:
            kernel32.ResumeThread(
                hthread
            )

        time.sleep(interval)

    print(
        "[AFDEV] ===== END THREAD SAMPLES ====="
    )
    print()




def scan_gameinfo_config(game_root, map_name):
    r"""
    Search the installed TGame\Config INI files for map-prefix/GameInfo clues.
    This is local/offline and avoids guessing the correct Tutorial GameInfo.
    """
    config_root = game_root / "TGame" / "Config"

    print()
    print("[AFDEV] ===== CONFIG / GAMETYPE SCAN =====")
    print(f"[AFDEV] Config root: {config_root}")

    if not config_root.is_dir():
        print("[AFDEV] Config directory not found.")
        print("[AFDEV] ===== END CONFIG SCAN =====")
        print()
        return

    prefix = map_name.split("-", 1)[0].strip().lower()
    needles = (
        "gamemapprefix",
        "defaultgametype",
        "gameinfo",
        "tutorial",
        f"{prefix}-",
        f"prefix={prefix}",
        f"prefix={prefix.upper()}",
    )

    hits = []

    for path in sorted(config_root.rglob("*.ini")):
        try:
            raw = path.read_bytes()

            # Most UE3 INIs here are ANSI/UTF-8; tolerate UTF-16 as well.
            if raw.startswith(b"\xff\xfe"):
                text = raw.decode("utf-16le", errors="replace")
            elif raw.startswith(b"\xfe\xff"):
                text = raw.decode("utf-16be", errors="replace")
            else:
                text = raw.decode("utf-8", errors="replace")

            for lineno, line in enumerate(text.splitlines(), 1):
                low = line.lower()

                if any(n.lower() in low for n in needles):
                    hits.append(
                        (path, lineno, line.strip())
                    )
        except Exception:
            continue

    if not hits:
        print(
            "[AFDEV] No matching GameInfo/map-prefix lines found "
            "in Config INIs."
        )
    else:
        # Avoid flooding: prefer lines containing tutorial/TR/game mapping.
        print(
            f"[AFDEV] Found {len(hits)} matching config lines "
            "(showing up to 80):"
        )

        for path, lineno, line in hits[:80]:
            try:
                rel = path.relative_to(config_root)
            except Exception:
                rel = path

            print(
                f"[CFG] {rel}:{lineno}: {line}"
            )

    print("[AFDEV] ===== END CONFIG SCAN =====")
    print()


def wait_for_player_controller(
    hproc,
    engine_ptr,
    timeout=15.0,
):
    """
    Wait for GamePlayers[0].Actor/PlayerController to become non-null.
    """
    deadline = time.time() + timeout
    last_lp = 0
    last_pc = 0

    while time.time() < deadline:
        try:
            raw = read_remote(
                hproc,
                engine_ptr + GAMEPLAYERS_OFFSET,
                12,
            )
            data_ptr, count, max_count = struct.unpack(
                "<III",
                raw,
            )

            if (
                data_ptr
                and 1 <= count <= 32
                and count <= max_count
            ):
                last_lp = read_u32(
                    hproc,
                    data_ptr,
                )

                if last_lp:
                    last_pc = read_u32(
                        hproc,
                        last_lp + LOCALPLAYER_PC_OFFSET,
                    )

                    if last_pc:
                        return last_lp, last_pc
        except Exception:
            pass

        time.sleep(0.25)

    return last_lp, last_pc



def wait_for_nonnull_gworld(hproc, timeout=15.0):
    """
    PendingURL can clear slightly before GWorld is swapped to the new world.
    v0.13 observed exactly that race. Wait for the final non-null pointer.
    """
    deadline = time.time() + timeout
    last = 0

    while time.time() < deadline:
        last = safe_read_u32(
            hproc,
            GWORLD_PTR_VA,
        ) or 0

        if last:
            return last

        time.sleep(0.10)

    return last


def is_probable_object_pointer(hproc, ptr):
    """
    Conservative read-only UE3 UObject heuristic:
      - pointer must be aligned and in plausible user address space
      - target must be readable
      - target's first DWORD (vtable) must land inside TGame .idata
    """
    if not ptr or (ptr & 3):
        return None

    if ptr < 0x00010000 or ptr >= 0x70000000:
        return None

    try:
        vtbl = read_u32(
            hproc,
            ptr,
        )
    except Exception:
        return None

    if TGAME_IDATA_MIN <= vtbl < TGAME_IDATA_MAX:
        return vtbl

    return None



def find_exact_vtable_targets_in_blob(
    hproc,
    object_base,
    object_size,
    target_vtable,
    target_name,
):
    """
    Scan an object's DWORD fields for pointers whose target begins with the
    exact requested native vtable.
    """
    hits = []

    try:
        blob = read_remote(
            hproc,
            object_base,
            object_size,
        )
    except Exception:
        return hits

    for off in range(
        0,
        object_size - 3,
        4,
    ):
        ptr = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if (
            not ptr
            or (ptr & 3)
            or ptr < 0x00010000
            or ptr >= 0x70000000
        ):
            continue

        try:
            vtbl = read_u32(
                hproc,
                ptr,
            )
        except Exception:
            continue

        if vtbl == target_vtable:
            hits.append(
                (off, ptr)
            )

    if hits:
        print(
            f"[AFDEV] >>> Exact {target_name} pointer(s) found:"
        )
        for off, ptr in hits:
            print(
                f"[AFDEV]     object+0x{off:X} -> "
                f"0x{ptr:08X} "
                f"(vtable=0x{target_vtable:08X})"
            )
    else:
        print(
            f"[AFDEV] >>> No direct {target_name} pointer found "
            f"in object 0x{object_base:08X} size 0x{object_size:X}."
        )

    return hits



def scan_private_memory_for_vtable(
    hproc,
    target_vtable,
    label,
    max_hits=64,
):
    """
    Scan committed MEM_PRIVATE regions below 0x70000000 for allocations whose
    first DWORD at a 4-byte aligned address equals target_vtable.

    This is read-only. UObject instances live in private process memory, so
    this is much more decisive than only walking one or two UWorld pointers.
    """
    pattern = struct.pack("<I", target_vtable)
    hits = []

    address = 0x00010000
    max_address = 0x70000000
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while address < max_address and len(hits) < max_hits:
        got = kernel32.VirtualQueryEx(
            hproc,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            mbi_size,
        )

        if not got:
            # Move by one allocation granularity rather than getting stuck.
            address += 0x10000
            continue

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)

        if size <= 0:
            address += 0x10000
            continue

        next_address = base + size

        readable = (
            mbi.State == MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and not (mbi.Protect & PAGE_NOACCESS)
            and not (mbi.Protect & PAGE_GUARD)
        )

        if readable:
            # Read in bounded chunks so a huge heap region does not require
            # one enormous temporary allocation.
            chunk_size = 1024 * 1024
            pos = base
            end = min(next_address, max_address)

            while pos < end and len(hits) < max_hits:
                want = min(chunk_size, end - pos)

                try:
                    blob = read_remote(
                        hproc,
                        pos,
                        want,
                    )
                except Exception:
                    pos += want
                    continue

                start = 0

                while len(hits) < max_hits:
                    idx = blob.find(pattern, start)

                    if idx < 0:
                        break

                    candidate = pos + idx

                    # UObject allocations are at least DWORD aligned.
                    if (candidate & 3) == 0:
                        # Basic sanity: inspect a few common object-header
                        # positions. We do NOT assume exact UE3 header layout;
                        # this simply filters obviously empty/random hits.
                        try:
                            head = read_remote(
                                hproc,
                                candidate,
                                0x40,
                            )
                            hdr28 = struct.unpack_from(
                                "<I",
                                head,
                                0x28,
                            )[0]
                            hdr2c = struct.unpack_from(
                                "<I",
                                head,
                                0x2C,
                            )[0]
                        except Exception:
                            hdr28 = hdr2c = 0

                        hits.append(
                            (
                                candidate,
                                hdr28,
                                hdr2c,
                            )
                        )

                    start = idx + 4

                pos += want

        if next_address <= address:
            address += 0x10000
        else:
            address = next_address

    print(
        f"[AFDEV] Global {label} exact-vtable hits: {len(hits)}"
    )

    for candidate, hdr28, hdr2c in hits[:20]:
        print(
            f"[GLOBAL] {label:26} "
            f"obj=0x{candidate:08X} "
            f"vtbl=0x{target_vtable:08X} "
            f"hdr28=0x{hdr28:08X} "
            f"hdr2C=0x{hdr2c:08X}"
        )

    return hits


def v28_dsm_census(hproc, label):
    """
    Diagnostic census for TGDsDsmNetHandler after preserving GIsServer.
    """
    print()
    print(
        f"[AFDEV-v32] ===== DSM CENSUS: {label} ====="
    )

    hits = scan_private_memory_for_vtable(
        hproc,
        DSM_VTABLE_VA,
        "TGDsDsmNetHandler",
        max_hits=32,
    )

    cdo_count = 0
    non_cdo = []

    for obj, hdr28, name_index in hits:
        kind = (
            "CDO"
            if name_index == DSM_CDO_NAME_INDEX
            else "RUNTIME/OTHER"
        )

        if kind == "CDO":
            cdo_count += 1
        else:
            non_cdo.append(obj)

        host = "<unreadable>"
        port = 0

        try:
            raw = read_remote(hproc, obj + 0x74, 12)
            ptr, num, cap = struct.unpack("<Iii", raw)

            if ptr and 0 < num <= cap <= 0x1000:
                sw = read_remote(
                    hproc,
                    ptr,
                    min(num * 2, 0x800),
                )
                host = (
                    sw.decode("utf-16le", "replace")
                    .split("\0", 1)[0]
                )
            elif num == 0:
                host = ""
        except Exception:
            pass

        try:
            port = read_u32(hproc, obj + 0x80)
        except Exception:
            port = 0

        print(
            f"[AFDEV-v32] DSM {kind:13s} "
            f"obj=0x{obj:08X} "
            f"NameIndex=0x{name_index:08X} "
            f"Host={host!r} Port={port}"
        )

    print(
        f"[AFDEV-v32] DSM summary: total={len(hits)} "
        f"CDO={cdo_count} non-CDO={len(non_cdo)}"
    )

    if non_cdo:
        print(
            "[AFDEV-v32] >>> SUCCESS: a non-CDO DSM object exists. "
            "DS-side registration is now active."
        )
    else:
        print(
            "[AFDEV-v32] >>> No non-CDO DSM object yet."
        )

    print(
        "[AFDEV-v32] ===== END DSM CENSUS ====="
    )
    print()

    return hits, non_cdo


def scan_tutorial_runtime_globally(hproc):
    """
    Return global exact-vtable hits for the tutorial native bases.
    """
    print()
    print(
        "[AFDEV] ===== GLOBAL TUTORIAL OBJECT SCAN ====="
    )

    game_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMGAME_VTABLE,
        "TGTeamGame-family",
    )

    controller_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMPLAYERCONTROLLER_VTABLE,
        "TGTeamPlayerController-family",
    )

    pawn_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn-family",
    )

    print(
        "[AFDEV] ===== END GLOBAL TUTORIAL OBJECT SCAN ====="
    )
    print()

    return game_hits, controller_hits, pawn_hits



def profile_pawn_candidate(
    hproc,
    pawn,
    live_pc,
    local_player,
    gworld,
):
    """
    Read-only relationship probe for one TGTeamPawn-family candidate.

    We deliberately do NOT assume pawn/controller offsets. Instead we look
    for exact live-object pointers inside the candidate allocation.
    """
    result = {
        "pawn": pawn,
        "pc_offsets": [],
        "lp_offsets": [],
        "world_offsets": [],
    }

    try:
        blob = read_remote(
            hproc,
            pawn,
            0x1800,
        )
    except Exception as e:
        print(
            f"[PAWNREL] 0x{pawn:08X}: read failed: {e}"
        )
        return result

    for off in range(0, len(blob) - 3, 4):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if live_pc and value == live_pc:
            result["pc_offsets"].append(off)

        if local_player and value == local_player:
            result["lp_offsets"].append(off)

        if gworld and value == gworld:
            result["world_offsets"].append(off)

    rels = []

    if result["pc_offsets"]:
        rels.append(
            "PC@" + ",".join(
                f"+0x{x:X}"
                for x in result["pc_offsets"]
            )
        )

    if result["lp_offsets"]:
        rels.append(
            "LP@" + ",".join(
                f"+0x{x:X}"
                for x in result["lp_offsets"]
            )
        )

    if result["world_offsets"]:
        rels.append(
            "WORLD@" + ",".join(
                f"+0x{x:X}"
                for x in result["world_offsets"]
            )
        )

    relation_text = (
        " ; ".join(rels)
        if rels
        else "no direct live PC/LP/GWorld refs"
    )

    print(
        f"[PAWNREL] pawn=0x{pawn:08X}: {relation_text}"
    )

    return result


def controller_pawn_pointer_hits(
    hproc,
    pc,
    pawn_addresses,
):
    """
    Scan a generous controller window for exact pointers to known
    TGTeamPawn-family candidates. This does not rely on a guessed Pawn offset.
    """
    hits = []

    if not pc or not pawn_addresses:
        return hits

    try:
        blob = read_remote(
            hproc,
            pc,
            0x1800,
        )
    except Exception as e:
        print(
            f"[AFDEV] Could not scan controller for pawn pointers: {e}"
        )
        return hits

    pawns = set(pawn_addresses)

    for off in range(0, len(blob) - 3, 4):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if value in pawns:
            hits.append(
                (off, value)
            )

    if hits:
        print(
            "[AFDEV] >>> Live controller contains TGTeamPawn-family "
            "pointer(s):"
        )
        for off, pawn in hits:
            print(
                f"[REL] PC+0x{off:X} -> pawn 0x{pawn:08X}"
            )
    else:
        print(
            "[AFDEV] Live controller contains NO direct pointer to any "
            "known TGTeamPawn-family candidate."
        )

    return hits


def classify_pawn_set(
    hproc,
    pawn_hits,
    live_pc,
    local_player,
    gworld,
    label,
):
    """
    Profile a complete set of exact-vtable pawn candidates.
    """
    addresses = [
        x[0]
        for x in pawn_hits
    ]

    print()
    print(
        f"[AFDEV] ===== PAWN RELATIONSHIP PROFILE: {label} ====="
    )
    print(
        f"[AFDEV] Candidate count: {len(addresses)}"
    )

    profiles = []

    for pawn in addresses:
        profiles.append(
            profile_pawn_candidate(
                hproc,
                pawn,
                live_pc,
                local_player,
                gworld,
            )
        )

    controller_hits = controller_pawn_pointer_hits(
        hproc,
        live_pc,
        addresses,
    )

    strongly_related = [
        p
        for p in profiles
        if p["pc_offsets"]
    ]

    print(
        f"[AFDEV] Pawns with exact live-PC backref: "
        f"{len(strongly_related)}"
    )
    print(
        f"[AFDEV] Controller->pawn pointer hits: "
        f"{len(controller_hits)}"
    )
    print(
        f"[AFDEV] ===== END PAWN RELATIONSHIP PROFILE: {label} ====="
    )
    print()

    return {
        "addresses": set(addresses),
        "profiles": profiles,
        "controller_hits": controller_hits,
        "strongly_related": strongly_related,
    }



def inject_exec_on_localplayer_thread(
    hproc,
    hthread,
    local_player,
    log_ptr,
    command,
):
    """
    Execute a gameplay/player console command through the SAME FExec path
    that TGame itself uses for GamePlayers[0].

    Static proof from this exact TGame.exe, around 0x009B9936:

        mov eax,[GEngine+0x47C]  ; GamePlayers.Data
        mov edi,[eax]            ; ULocalPlayer*
        add edi,0x3C             ; embedded FExec subobject

        ...
        mov ebp,[edi]            ; FExec vtable
        push GLog
        push Cmd
        mov ecx,edi
        mov edx,[ebp+0]
        call edx                 ; FExec::Exec(Cmd, Ar)

    So:
        Exec this = ULocalPlayer + 0x3C
        function  = [ [ULocalPlayer+0x3C] + 0 ]
        args      = (TCHAR* Cmd, FOutputDevice* Ar)

    This is a much better route for gameplay commands than calling
    UTGameEngine::Exec directly.
    """
    command_bytes = (
        command.encode("utf-16le")
        + b"\x00\x00"
    )

    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(LocalPlayer Exec)")

    remote = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    command_ptr = remote + 0x000
    result_ptr = remote + 0x400
    code_ptr = remote + 0x500

    write_remote(
        hproc,
        command_ptr,
        command_bytes,
    )

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(
        hthread
    )

    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(LocalPlayer Exec)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64GetThreadContext(LocalPlayer Exec)"
            )

        original_eip = ctx.Eip

        print(
            f"[AFDEV] LocalPlayer Exec: game thread paused "
            f"at EIP=0x{original_eip:08X}"
        )

        exec_this = (
            local_player + 0x3C
        ) & 0xFFFFFFFF

        try:
            sub_vtable = read_u32(
                hproc,
                exec_this,
            )
            exec_fn = read_u32(
                hproc,
                sub_vtable,
            )
        except Exception as e:
            raise RuntimeError(
                f"Could not resolve LocalPlayer FExec vtable: {e}"
            )

        print(
            f"[AFDEV] LocalPlayer      = 0x{local_player:08X}"
        )
        print(
            f"[AFDEV] LocalPlayer FExec= 0x{exec_this:08X}"
        )
        print(
            f"[AFDEV] FExec vtable     = 0x{sub_vtable:08X}"
        )
        print(
            f"[AFDEV] FExec::Exec      = 0x{exec_fn:08X}"
        )
        print(
            f"[AFDEV] Player command   = {command}"
        )

        sc = bytearray()

        # Preserve exact interrupted CPU state.
        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # ecx = LocalPlayer + 0x3C
        sc += b"\xB9" + struct.pack(
            "<I",
            exec_this,
        )

        # eax = [ecx]  (FExec sub-vtable)
        sc += b"\x8B\x01"

        # edx = [eax]  (slot 0 = Exec)
        sc += b"\x8B\x10"

        # push Ar = *GLog
        sc += b"\xA1" + struct.pack(
            "<I",
            GLOG_PTR_VA,
        )
        sc += b"\x50"

        # push Cmd
        sc += b"\x68" + struct.pack(
            "<I",
            command_ptr,
        )

        # call edx
        sc += b"\xFF\xD2"

        # Save returned UBOOL/EAX.
        sc += b"\xA3" + struct.pack(
            "<I",
            result_ptr,
        )

        sc += b"\x61"  # popad
        sc += b"\x9D"  # popfd

        # Return to exact interrupted EIP without clobbering regs.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64SetThreadContext(LocalPlayer Exec)"
            )

        resumed = kernel32.ResumeThread(
            hthread
        )

        if resumed == 0xFFFFFFFF:
            winerr(
                "ResumeThread(LocalPlayer Exec)"
            )

        suspended = False

        deadline = time.time() + 15.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited during LocalPlayer Exec."
                )

            result = read_u32(
                hproc,
                result_ptr,
            )

            if result != 0xDEADC0DE:
                print(
                    f"[AFDEV] LocalPlayer FExec::Exec returned: "
                    f"0x{result:08X}"
                )
                return result

            time.sleep(0.05)

        raise RuntimeError(
            "LocalPlayer Exec trampoline did not finish."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(
                hthread
            )


def run_localplayer_exec_sanity_probe(
    hproc,
    hthread,
    local_player,
    log_ptr,
):
    """
    CAUSEEVENT is known to be sent through exactly this LocalPlayer FExec
    path by TGame's own engine tick code. Using a nonexistent event name
    is safe and tells us whether the command interface itself accepts the
    command.
    """
    print()
    print(
        "[AFDEV] ===== LOCALPLAYER FEXEC SANITY PROBE ====="
    )

    command = "CAUSEEVENT AFDEV_NONEXISTENT_EVENT"

    try:
        result = inject_exec_on_localplayer_thread(
            hproc,
            hthread,
            local_player,
            log_ptr,
            command,
        )
    except Exception as e:
        print(
            f"[AFDEV] LocalPlayer FExec sanity probe failed: {e}"
        )
        print(
            "[AFDEV] ===== END LOCALPLAYER FEXEC SANITY PROBE ====="
        )
        print()
        return None

    print(
        f"[AFDEV] Sanity command result: 0x{result:08X}"
    )

    if result:
        print(
            "[AFDEV] >>> LocalPlayer FExec path is LIVE and "
            "recognized CAUSEEVENT."
        )
    else:
        print(
            "[AFDEV] CAUSEEVENT returned 0. The FExec call itself "
            "completed, but this build did not report the command handled."
        )

    print(
        "[AFDEV] ===== END LOCALPLAYER FEXEC SANITY PROBE ====="
    )
    print()

    return result


def run_spawn_trigger_probes(
    hproc,
    hthread,
    engine_ptr,
    log_ptr,
    live_pc,
    local_player,
    gworld,
):
    """
    v0.18 behavior:
      - ALWAYS run the trigger probes, even if TGTeamPawn-family objects
        already exist globally.
      - Snapshot the exact pawn-object set before each command.
      - Diff the set afterward.
      - Check direct pawn->live-PC and live-PC->pawn relationships.
      - Stop only when we get strong evidence of a newly spawned/possessed
        pawn, not merely because class-default/archetype pawn objects exist.
    """
    print()
    print(
        "[AFDEV] ===== PAWN-SPAWN TRIGGER PROBES v0.19 / LOCALPLAYER FEXEC ====="
    )

    baseline_hits = scan_private_memory_for_vtable(
        hproc,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn-family BASELINE",
        max_hits=128,
    )

    baseline_profile = classify_pawn_set(
        hproc,
        baseline_hits,
        live_pc,
        local_player,
        gworld,
        "BASELINE",
    )

    previous_set = set(
        baseline_profile["addresses"]
    )

    if (
        baseline_profile["strongly_related"]
        or baseline_profile["controller_hits"]
    ):
        print(
            "[AFDEV] >>> A baseline TGTeamPawn-family object is already "
            "strongly related to the live controller."
        )
        print(
            "[AFDEV] We will still run commands to see if possession/state "
            "changes further."
        )

    for command in SPAWN_TRIGGER_COMMANDS:
        print()
        print(
            "=" * 72
        )
        print(
            f"[AFDEV] >>> Trying runtime command: {command}"
        )

        try:
            result = inject_exec_on_localplayer_thread(
                hproc,
                hthread,
                local_player,
                log_ptr,
                command,
            )
        except Exception as e:
            print(
                f"[AFDEV] Command injection failed: {e}"
            )
            continue

        print(
            f"[AFDEV] LocalPlayer Exec return: 0x{result:08X}"
        )

        # Let script/native game state tick.
        time.sleep(2.0)

        after_hits = scan_private_memory_for_vtable(
            hproc,
            TGTEAMPAWN_VTABLE,
            f"TGTeamPawn-family AFTER {command}",
            max_hits=128,
        )

        after_profile = classify_pawn_set(
            hproc,
            after_hits,
            live_pc,
            local_player,
            gworld,
            f"AFTER {command}",
        )

        after_set = set(
            after_profile["addresses"]
        )

        new_pawns = sorted(
            after_set - previous_set
        )

        vanished = sorted(
            previous_set - after_set
        )

        if new_pawns:
            print(
                f"[AFDEV] >>> NEW TGTeamPawn-family object(s) after "
                f"{command!r}:"
            )
            for pawn in new_pawns:
                print(
                    f"[NEWPAWN] 0x{pawn:08X}"
                )
        else:
            print(
                f"[AFDEV] No new TGTeamPawn-family allocation after "
                f"{command!r}."
            )

        if vanished:
            print(
                f"[AFDEV] Pawn candidate(s) disappeared after "
                f"{command!r}:"
            )
            for pawn in vanished:
                print(
                    f"[OLDPAWN-GONE] 0x{pawn:08X}"
                )

        # Re-read live LocalPlayer->PC in case a restart replaced controller.
        lp_now, pc_now = wait_for_player_controller(
            hproc,
            engine_ptr,
            timeout=2.0,
        )

        if pc_now and pc_now != live_pc:
            print(
                f"[AFDEV] >>> PlayerController changed: "
                f"0x{live_pc:08X} -> 0x{pc_now:08X}"
            )
            live_pc = pc_now
            local_player = lp_now

            # Re-classify current pawns against the new controller.
            after_profile = classify_pawn_set(
                hproc,
                after_hits,
                live_pc,
                local_player,
                gworld,
                f"AFTER {command} WITH NEW PC",
            )

        strong_relation = bool(
            after_profile["strongly_related"]
            or after_profile["controller_hits"]
        )

        # Strong success: actual possession/ownership-like pointer relation.
        if strong_relation:
            print()
            print(
                f"[AFDEV] >>> STRONG SUCCESS after {command!r}: "
                "a TGTeamPawn-family object is now directly related to "
                "the live PlayerController."
            )
            print(
                "[AFDEV] ===== END PAWN-SPAWN TRIGGER PROBES v0.19 / LOCALPLAYER FEXEC ====="
            )
            print()
            return {
                "command": command,
                "new_pawns": new_pawns,
                "pawn_hits": after_hits,
                "profile": after_profile,
                "live_pc": live_pc,
                "local_player": local_player,
                "strong": True,
            }

        # We still report allocation success even if not possessed.
        if new_pawns:
            print(
                f"[AFDEV] {command!r} created new pawn-family object(s), "
                "but no direct possession/controller relationship was "
                "detected yet."
            )

        previous_set = after_set

    print()
    print(
        "[AFDEV] All trigger probes finished without a strong "
        "controller<->pawn relationship."
    )
    print(
        "[AFDEV] ===== END PAWN-SPAWN TRIGGER PROBES v0.19 / LOCALPLAYER FEXEC ====="
    )
    print()

    return {
        "command": None,
        "new_pawns": [],
        "pawn_hits": after_hits if "after_hits" in locals() else baseline_hits,
        "profile": after_profile if "after_profile" in locals() else baseline_profile,
        "live_pc": live_pc,
        "local_player": local_player,
        "strong": False,
    }




def get_worldinfo_on_game_thread(
    hproc,
    hthread,
    gworld,
):
    """
    Call the exact UWorld::GetWorldInfo helper from this TGame build.

        ECX = GWorld
        push 0
        call 0x00D9C1A0

    Returns the live AWorldInfo*.
    """
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(GetWorldInfo)")

    remote = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    result_ptr = remote + 0x100
    code_ptr = remote + 0x200

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(
        hthread
    )

    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(GetWorldInfo)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64GetThreadContext(GetWorldInfo)"
            )

        original_eip = ctx.Eip

        sc = bytearray()

        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # ECX = GWorld
        sc += b"\xB9" + struct.pack(
            "<I",
            gworld,
        )

        # helper's single stack argument = 0
        sc += b"\x6A\x00"

        # EAX = UWorld::GetWorldInfo helper
        sc += b"\xB8" + struct.pack(
            "<I",
            UWORLD_GETWORLDINFO_VA,
        )

        # call eax
        sc += b"\xFF\xD0"

        # helper returns WorldInfo* in EAX
        sc += b"\xA3" + struct.pack(
            "<I",
            result_ptr,
        )

        sc += b"\x61"  # popad
        sc += b"\x9D"  # popfd

        # exact interrupted EIP
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64SetThreadContext(GetWorldInfo)"
            )

        resumed = kernel32.ResumeThread(
            hthread
        )

        if resumed == 0xFFFFFFFF:
            winerr(
                "ResumeThread(GetWorldInfo)"
            )

        suspended = False

        deadline = time.time() + 10.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while calling GetWorldInfo."
                )

            result = read_u32(
                hproc,
                result_ptr,
            )

            if result != 0xDEADC0DE:
                return result

            time.sleep(0.05)

        raise RuntimeError(
            "GetWorldInfo trampoline timed out."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(
                hthread
            )


def inspect_authority_world(
    hproc,
    hthread,
    gworld,
):
    """
    Definitive authority/GameInfo probe.

    If WorldInfo+0x414 is NULL, there is no live authoritative GameInfo actor.
    If it is non-NULL, print its vtable and core UObject header words.
    """
    print()
    print(
        "[AFDEV] ===== AUTHORITY / WORLDINFO / GAMEINFO PROBE ====="
    )
    print(
        f"[AFDEV] GWorld = 0x{gworld:08X}"
    )

    try:
        world_info = get_worldinfo_on_game_thread(
            hproc,
            hthread,
            gworld,
        )
    except Exception as e:
        print(
            f"[AFDEV] GetWorldInfo failed: {e}"
        )
        print(
            "[AFDEV] ===== END AUTHORITY PROBE ====="
        )
        print()
        return {
            "world_info": 0,
            "game_info": 0,
        }

    print(
        f"[AFDEV] WorldInfo = 0x{world_info:08X}"
    )

    game_info = 0

    if world_info:
        try:
            game_info = read_u32(
                hproc,
                world_info + WORLDINFO_GAME_OFFSET,
            )
        except Exception as e:
            print(
                f"[AFDEV] Could not read WorldInfo+0x414: {e}"
            )

    print(
        f"[AFDEV] WorldInfo+0x414 (Game) = "
        f"0x{game_info:08X}"
    )

    if not game_info:
        print(
            "[AFDEV] >>> NO LIVE GameInfo actor exists in this world."
        )
        print(
            "[AFDEV] >>> That is the exact condition expected on a "
            "client/non-authority world."
        )
    else:
        try:
            vtbl = read_u32(
                hproc,
                game_info,
            )
            head = read_remote(
                hproc,
                game_info,
                0x40,
            )

            dwords = [
                struct.unpack_from("<I", head, x)[0]
                for x in range(0, 0x40, 4)
            ]

            print(
                f"[AFDEV] GameInfo vtable = 0x{vtbl:08X}"
            )
            print(
                "[AFDEV] GameInfo UObject header DWORDs:"
            )

            for off in range(0, 0x40, 0x10):
                vals = " ".join(
                    f"{dwords[(off // 4) + i]:08X}"
                    for i in range(4)
                )
                print(
                    f"[GI +0x{off:02X}] {vals}"
                )

            if vtbl == TGTEAMGAME_VTABLE:
                print(
                    "[AFDEV] >>> LIVE GameInfo matches the "
                    "TGTeamGame native family."
                )
            else:
                print(
                    "[AFDEV] >>> LIVE GameInfo exists, but its native "
                    "vtable is not the mapped TGTeamGame value."
                )

        except Exception as e:
            print(
                f"[AFDEV] Could not inspect GameInfo: {e}"
            )

    print(
        "[AFDEV] ===== END AUTHORITY PROBE ====="
    )
    print()

    return {
        "world_info": world_info,
        "game_info": game_info,
    }


def scan_world_for_tggame_and_tgpawn(
    hproc,
    gworld,
):
    """
    Targeted v0.16 scan for the tutorial's expected native bases.

    Expected:
      TGTeamMatch_Tutorial -> TGTeamGame native vtable 0x01D62530
      TGTMPawn_Tutorial    -> TGTeamPawn native vtable 0x01D5B350
    """
    print()
    print(
        "[AFDEV] ===== TUTORIAL GAMEINFO / PAWN EXACT-VTABLE SCAN ====="
    )

    if not gworld:
        print("[AFDEV] GWorld is NULL.")
        print(
            "[AFDEV] ===== END TUTORIAL EXACT-VTABLE SCAN ====="
        )
        print()
        return

    print(f"[AFDEV] GWorld                 = 0x{gworld:08X}")
    print(
        f"[AFDEV] Expected GameInfo VT   = "
        f"0x{TGTEAMGAME_VTABLE:08X} (TGTeamGame family)"
    )
    print(
        f"[AFDEV] Expected Pawn VT       = "
        f"0x{TGTEAMPAWN_VTABLE:08X} (TGTeamPawn family)"
    )

    # Direct fields in UWorld first.
    direct_game = find_exact_vtable_targets_in_blob(
        hproc,
        gworld,
        0x1400,
        TGTEAMGAME_VTABLE,
        "TGTeamGame/TGTeamMatch_Tutorial",
    )

    direct_pawn = find_exact_vtable_targets_in_blob(
        hproc,
        gworld,
        0x1400,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn/TGTMPawn_Tutorial",
    )

    try:
        world_blob = read_remote(
            hproc,
            gworld,
            0x1400,
        )
    except Exception as e:
        print(f"[AFDEV] Could not read UWorld: {e}")
        print(
            "[AFDEV] ===== END TUTORIAL EXACT-VTABLE SCAN ====="
        )
        print()
        return

    child_objects = []
    seen = set()

    for off in range(0, 0x1400 - 3, 4):
        ptr = struct.unpack_from("<I", world_blob, off)[0]

        if ptr in seen:
            continue

        vtbl = is_probable_object_pointer(
            hproc,
            ptr,
        )

        if vtbl is None:
            continue

        seen.add(ptr)
        child_objects.append(
            (off, ptr, vtbl)
        )

    print(
        f"[AFDEV] UWorld direct UObject-like children: "
        f"{len(child_objects)}"
    )

    game_hits = []
    pawn_hits = []

    # Follow one UObject level. This is enough to catch WorldInfo/GameInfo
    # style ownership without relying on version-specific UWorld offsets.
    for parent_off, child, child_vtbl in child_objects[:192]:
        try:
            blob = read_remote(
                hproc,
                child,
                0x1400,
            )
        except Exception:
            continue

        for off in range(0, 0x1400 - 3, 4):
            ptr = struct.unpack_from(
                "<I",
                blob,
                off,
            )[0]

            if (
                not ptr
                or (ptr & 3)
                or ptr < 0x00010000
                or ptr >= 0x70000000
            ):
                continue

            try:
                vtbl = read_u32(
                    hproc,
                    ptr,
                )
            except Exception:
                continue

            rec = (
                parent_off,
                child,
                child_vtbl,
                off,
                ptr,
            )

            if vtbl == TGTEAMGAME_VTABLE:
                game_hits.append(rec)

            if vtbl == TGTEAMPAWN_VTABLE:
                pawn_hits.append(rec)

    if direct_game or game_hits:
        print(
            "[AFDEV] >>> SUCCESS: tutorial TGTeamGame-family "
            "GameInfo object is present."
        )

        for poff, child, cvtbl, off, ptr in game_hits[:12]:
            print(
                f"[GAME] GWorld+0x{poff:X} -> "
                f"0x{child:08X}(vtbl=0x{cvtbl:08X}) "
                f"+0x{off:X} -> "
                f"0x{ptr:08X}(vtbl=0x{TGTEAMGAME_VTABLE:08X})"
            )
    else:
        print(
            "[AFDEV] >>> Tutorial TGTeamGame-family GameInfo "
            "was NOT found in the scanned graph."
        )

    if direct_pawn or pawn_hits:
        print(
            "[AFDEV] >>> SUCCESS: tutorial TGTeamPawn-family "
            "Pawn object is present."
        )

        for poff, child, cvtbl, off, ptr in pawn_hits[:12]:
            print(
                f"[PAWN] GWorld+0x{poff:X} -> "
                f"0x{child:08X}(vtbl=0x{cvtbl:08X}) "
                f"+0x{off:X} -> "
                f"0x{ptr:08X}(vtbl=0x{TGTEAMPAWN_VTABLE:08X})"
            )
    else:
        print(
            "[AFDEV] >>> Tutorial TGTeamPawn-family Pawn "
            "was NOT found in the scanned graph."
        )

    print(
        "[AFDEV] ===== END TUTORIAL EXACT-VTABLE SCAN ====="
    )
    print()



def scan_exact_tgplayercontroller(
    hproc,
    local_player,
    pc,
    gworld,
):
    """
    Targeted tutorial controller probe.

    Expected for TGTMPlayerController_Tutorial:
        native base TGTeamPlayerController
        vtable 0x01D65728

    We scan the inherited/native portion of the controller for a direct
    pointer to the expected TGTeamPawn-family pawn.
    """
    print()
    print(
        "[AFDEV] ===== EXACT TUTORIAL PLAYERCONTROLLER RUNTIME SCAN ====="
    )

    if not pc:
        print("[AFDEV] PlayerController is NULL.")
        print(
            "[AFDEV] ===== END TUTORIAL CONTROLLER SCAN ====="
        )
        print()
        return

    try:
        pc_vtbl = read_u32(
            hproc,
            pc,
        )
    except Exception:
        pc_vtbl = 0

    print(f"[AFDEV] PC              = 0x{pc:08X}")
    print(f"[AFDEV] PC VTable       = 0x{pc_vtbl:08X}")
    print(
        f"[AFDEV] Expected VT      = "
        f"0x{TGTEAMPLAYERCONTROLLER_VTABLE:08X}"
    )
    print(
        f"[AFDEV] LocalPlayer      = 0x{local_player:08X}"
    )
    print(f"[AFDEV] GWorld           = 0x{gworld:08X}")

    if pc_vtbl == TGTEAMPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] >>> SUCCESS: controller matches "
            "TGTeamPlayerController family."
        )
        print(
            "[AFDEV] >>> This is the expected native base for "
            "TGTMPlayerController_Tutorial."
        )
    elif pc_vtbl == TGPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] Controller is TGPlayerController family, "
            "not the tutorial team-controller family."
        )
    elif pc_vtbl == TGPVPPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] Controller is TGPVPPlayerController family."
        )
    elif pc_vtbl == UTPLAYERCONTROLLER_VTABLE:
        print(
            "[AFDEV] Controller fell back to the lower/base "
            "UT PlayerController family."
        )
    else:
        print(
            "[AFDEV] Controller vtable is not one of the mapped "
            "TG controller families."
        )

    try:
        blob = read_remote(
            hproc,
            pc,
            TGTEAMPLAYERCONTROLLER_SIZE,
        )
    except Exception as e:
        print(
            f"[AFDEV] Could not read controller object: {e}"
        )
        print(
            "[AFDEV] ===== END TUTORIAL CONTROLLER SCAN ====="
        )
        print()
        return

    # Known reverse direction:
    # ULocalPlayer+0x40 -> PlayerController.
    try:
        lp_actor = read_u32(
            hproc,
            local_player + LOCALPLAYER_PC_OFFSET,
        )
        print(
            f"[AFDEV] ULocalPlayer+0x40 = 0x{lp_actor:08X} "
            f"({'MATCH' if lp_actor == pc else 'MISMATCH'})"
        )
    except Exception as e:
        print(
            f"[AFDEV] ULocalPlayer+0x40 validation failed: {e}"
        )

    # Find the LocalPlayer pointer in the controller itself.
    lp_hits = []

    for off in range(
        0,
        TGTEAMPLAYERCONTROLLER_SIZE - 3,
        4,
    ):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if value == local_player:
            lp_hits.append(off)

    if lp_hits:
        print(
            "[AFDEV] LocalPlayer pointer inside controller at: "
            + ", ".join(
                f"+0x{x:X}"
                for x in lp_hits
            )
        )

    # Exact tutorial pawn target.
    tutorial_pawn_hits = find_exact_vtable_targets_in_blob(
        hproc,
        pc,
        TGTEAMPLAYERCONTROLLER_SIZE,
        TGTEAMPAWN_VTABLE,
        "TGTeamPawn/TGTMPawn_Tutorial",
    )

    # Also show base-pawn hits as a fallback diagnostic.
    base_pawn_hits = find_exact_vtable_targets_in_blob(
        hproc,
        pc,
        TGTEAMPLAYERCONTROLLER_SIZE,
        TGPAWN_VTABLE,
        "base TGPawn",
    )

    if tutorial_pawn_hits:
        print(
            "[AFDEV] >>> SUCCESS: controller has a direct pointer "
            "to the expected tutorial pawn family."
        )
    elif base_pawn_hits:
        print(
            "[AFDEV] Controller has a base-TGPawn pointer, but not "
            "the expected tutorial team-pawn family."
        )
    else:
        print(
            "[AFDEV] >>> Controller has NO direct Pawn pointer "
            "matching either mapped TG pawn family."
        )

    # Print only high-value object pointers in the controller:
    # mapped pawn/controller families and LocalPlayer.
    print(
        "[AFDEV] High-value mapped object pointers in controller:"
    )

    mapped_vtables = {
        TGPAWN_VTABLE: "TGPawn-family",
        TGTEAMPAWN_VTABLE: "TGTeamPawn-family",
        TGPLAYERCONTROLLER_VTABLE: "TGPlayerController-family",
        TGPVPPLAYERCONTROLLER_VTABLE: "TGPVPPlayerController-family",
        TGTEAMPLAYERCONTROLLER_VTABLE: "TGTeamPlayerController-family",
    }

    printed = 0

    for off in range(
        0,
        TGTEAMPLAYERCONTROLLER_SIZE - 3,
        4,
    ):
        value = struct.unpack_from(
            "<I",
            blob,
            off,
        )[0]

        if value == local_player:
            print(
                f"[MAP] PC+0x{off:03X} = "
                f"0x{value:08X} LOCALPLAYER"
            )
            printed += 1
            continue

        if (
            not value
            or (value & 3)
            or value < 0x00010000
            or value >= 0x70000000
        ):
            continue

        try:
            vtbl = read_u32(
                hproc,
                value,
            )
        except Exception:
            continue

        label = mapped_vtables.get(vtbl)

        if label:
            print(
                f"[MAP] PC+0x{off:03X} = "
                f"0x{value:08X} "
                f"vtbl=0x{vtbl:08X} {label}"
            )
            printed += 1

    if printed == 0:
        print("[AFDEV]   <none>")

    print(
        "[AFDEV] ===== END TUTORIAL CONTROLLER SCAN ====="
    )
    print()



def inspect_player_controller_core(
    hproc,
    local_player,
    pc,
    label="",
):
    """
    Read-only probe of core same-era UE3 PlayerController fields.
    """
    print()
    print(
        f"[AFDEV] ===== PLAYERCONTROLLER CORE{label} ====="
    )

    if not pc:
        print("[AFDEV] PlayerController is NULL.")
        print("[AFDEV] ===== END PLAYERCONTROLLER CORE =====")
        print()
        return {}

    fields = {}

    probes = [
        ("Pawn", CONTROLLER_PAWN_OFFSET),
        ("Player", PC_PLAYER_OFFSET),
        ("PlayerCamera", PC_CAMERA_OFFSET),
        ("AcknowledgedPawn", PC_ACK_PAWN_OFFSET),
    ]

    for name, offset in probes:
        try:
            value = read_u32(
                hproc,
                pc + offset,
            )
        except Exception:
            value = 0

        fields[name] = value

        print(
            f"[AFDEV] PC+0x{offset:03X} "
            f"{name:16} = 0x{value:08X}"
        )

    player_ptr = fields.get("Player", 0)
    pawn = fields.get("Pawn", 0)
    ack = fields.get("AcknowledgedPawn", 0)
    camera = fields.get("PlayerCamera", 0)

    if player_ptr:
        relation = (
            "MATCHES LocalPlayer"
            if player_ptr == local_player
            else "DIFFERS from LocalPlayer"
        )
        print(
            f"[AFDEV] Player relation: {relation} "
            f"(LocalPlayer=0x{local_player:08X})"
        )

    if pawn:
        try:
            pawn_vtbl = read_u32(hproc, pawn)
        except Exception:
            pawn_vtbl = 0

        print(
            f"[AFDEV] >>> Controller already possesses a Pawn: "
            f"0x{pawn:08X} (VTable=0x{pawn_vtbl:08X})"
        )
    else:
        print(
            "[AFDEV] >>> Controller Pawn is NULL."
        )

    if ack:
        print(
            f"[AFDEV] >>> AcknowledgedPawn is 0x{ack:08X}"
        )
    else:
        print(
            "[AFDEV] >>> AcknowledgedPawn is NULL."
        )

    if camera:
        try:
            camera_vtbl = read_u32(
                hproc,
                camera,
            )
        except Exception:
            camera_vtbl = 0

        print(
            f"[AFDEV] >>> PlayerCamera exists: "
            f"0x{camera:08X} (VTable=0x{camera_vtbl:08X})"
        )
    else:
        print(
            "[AFDEV] >>> PlayerCamera is NULL."
        )

    print(
        "[AFDEV] ===== END PLAYERCONTROLLER CORE ====="
    )
    print()

    return fields


def inspect_local_players(hproc, engine_ptr, label=""):
    """
    Inspect the UGameEngine GamePlayers TArray and each LocalPlayer's
    PlayerController pointer.
    """
    try:
        raw = read_remote(
            hproc,
            engine_ptr + GAMEPLAYERS_OFFSET,
            12,
        )
        data_ptr, count, max_count = struct.unpack(
            "<III",
            raw,
        )
    except Exception as e:
        print(
            f"[AFDEV] GamePlayers{label}: read failed: {e}"
        )
        return {
            "data": 0,
            "count": 0,
            "max": 0,
            "players": [],
        }

    print()
    print(
        f"[AFDEV] GamePlayers{label}: "
        f"Data=0x{data_ptr:08X} Count={count} Max={max_count}"
    )

    result = {
        "data": data_ptr,
        "count": count,
        "max": max_count,
        "players": [],
    }

    # Sanity bounds.
    if count > 32 or max_count > 1024 or count > max_count:
        print(
            "[AFDEV] WARNING: GamePlayers TArray values look invalid."
        )
        return result

    for i in range(count):
        try:
            lp = read_u32(
                hproc,
                data_ptr + i * 4,
            ) if data_ptr else 0

            pc = (
                read_u32(
                    hproc,
                    lp + LOCALPLAYER_PC_OFFSET,
                )
                if lp
                else 0
            )

            lp_vtbl = (
                read_u32(hproc, lp)
                if lp
                else 0
            )

            pc_vtbl = (
                read_u32(hproc, pc)
                if pc
                else 0
            )

            print(
                f"[AFDEV]   Player[{i}] "
                f"ULocalPlayer=0x{lp:08X} "
                f"VTable=0x{lp_vtbl:08X} "
                f"PlayerController=0x{pc:08X} "
                f"PCVTable=0x{pc_vtbl:08X}"
            )

            result["players"].append(
                {
                    "local_player": lp,
                    "local_player_vtable": lp_vtbl,
                    "player_controller": pc,
                    "player_controller_vtable": pc_vtbl,
                }
            )

        except Exception as e:
            print(
                f"[AFDEV]   Player[{i}] read failed: {e}"
            )

    if count == 0:
        print(
            "[AFDEV] >>> No LocalPlayer exists."
        )
    elif not any(
        p.get("player_controller")
        for p in result["players"]
    ):
        print(
            "[AFDEV] >>> LocalPlayer exists, but no PlayerController is attached."
        )
    else:
        print(
            "[AFDEV] >>> At least one LocalPlayer + PlayerController exists."
        )

    print()

    return result


def hide_af_loading_ui_on_game_thread(hproc, hthread):
    """
    Call Assault Fire's own LoadingMovie hide routine:

        0x01257FB0(0, 0, 0.0f, 0.0f, 0)

    on the primary/game thread.

    The function uses stdcall-like stack cleanup:
        ret 0x14

    so it consumes all five arguments itself.
    """
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(AF LoadingMovie hide)")

    remote = int(
        ctypes.cast(
            remote,
            ctypes.c_void_p,
        ).value
    )

    result_ptr = remote + 0x100
    code_ptr = remote + 0x200

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(hthread)
    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(AF LoadingMovie hide)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64GetThreadContext(AF LoadingMovie hide)"
            )

        original_eip = ctx.Eip

        print(
            f"[AFDEV] AF LoadingMovie hide: "
            f"game thread paused at EIP=0x{original_eip:08X}"
        )

        sc = bytearray()

        # Preserve exact interrupted CPU state.
        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # Five arguments, right-to-left.
        # arg5 = 0
        # arg4 = 0.0f
        # arg3 = 0.0f
        # arg2 = 0
        # arg1 = 0  -> SHOW=FALSE
        sc += b"\x6A\x00" * 5

        # mov eax, AF_SHOW_LOADING_MOVIE_VA
        sc += b"\xB8" + struct.pack(
            "<I",
            AF_SHOW_LOADING_MOVIE_VA,
        )

        # call eax
        sc += b"\xFF\xD0"

        # Function returns with RET 14h, so ESP is back at pushad frame.

        # marker = 1
        sc += b"\xC7\x05"
        sc += struct.pack(
            "<I",
            result_ptr,
        )
        sc += struct.pack(
            "<I",
            1,
        )

        sc += b"\x61"  # popad
        sc += b"\x9D"  # popfd

        # Return to the exact interrupted instruction.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        print(
            f"[AFDEV] AF LoadingMovie hide trampoline "
            f"@0x{code_ptr:08X}"
        )
        print(
            "[AFDEV] Calling "
            f"0x{AF_SHOW_LOADING_MOVIE_VA:08X}"
            "(Show=0, arg2=0, fade=0, pause=0, arg5=0)"
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr(
                "Wow64SetThreadContext(AF LoadingMovie hide)"
            )

        resumed = kernel32.ResumeThread(hthread)

        if resumed == 0xFFFFFFFF:
            winerr("ResumeThread(AF LoadingMovie hide)")

        suspended = False

        deadline = time.time() + 10.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while hiding AF LoadingMovie UI."
                )

            done = read_u32(
                hproc,
                result_ptr,
            )

            if done == 1:
                print(
                    "[AFDEV] Assault Fire LoadingMovie hide "
                    "routine returned successfully."
                )
                return True

            time.sleep(0.05)

        raise RuntimeError(
            "AF LoadingMovie hide trampoline did not finish."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(hthread)


def stop_loading_movie_on_game_thread(hproc, hthread):
    """
    Execute TGame's own loading-movie stop wrapper (0x0095B1C0, arg=1)
    on the primary/game thread.

    This uses the same one-shot thread-hijack method as the OPEN command:
      - suspend primary thread
      - preserve flags + registers
      - call wrapper with push 1
      - set completion sentinel
      - restore state
      - jump back to exact interrupted EIP
    """
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx(stop movie)")

    remote = int(ctypes.cast(remote, ctypes.c_void_p).value)

    result_ptr = remote + 0x100
    code_ptr = remote + 0x200

    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(hthread)
    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(stop movie)")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64GetThreadContext(stop movie)")

        original_eip = ctx.Eip

        print(
            f"[AFDEV] StopMovie: game thread paused at "
            f"EIP=0x{original_eip:08X}"
        )

        sc = bytearray()

        sc += b"\x9C"  # pushfd
        sc += b"\x60"  # pushad

        # push 1
        sc += b"\x6A\x01"

        # mov eax, STOP_LOADING_MOVIE_VA
        sc += b"\xB8" + struct.pack(
            "<I",
            STOP_LOADING_MOVIE_VA,
        )

        # call eax
        # 0x95B1C0 returns with ret 4, cleaning the argument.
        sc += b"\xFF\xD0"

        # completion sentinel = 1
        sc += b"\xC7\x05" + struct.pack(
            "<I",
            result_ptr,
        ) + struct.pack(
            "<I",
            1,
        )

        sc += b"\x61"      # popad
        sc += b"\x9D"      # popfd

        # Return to exact interrupted EIP without clobbering registers.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        print(
            f"[AFDEV] StopMovie trampoline @0x{code_ptr:08X}"
        )
        print(
            f"[AFDEV] Calling 0x{STOP_LOADING_MOVIE_VA:08X}(1)"
        )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64SetThreadContext(stop movie)")

        resumed = kernel32.ResumeThread(hthread)
        if resumed == 0xFFFFFFFF:
            winerr("ResumeThread(stop movie)")

        suspended = False

        deadline = time.time() + 10.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while stopping loading movie."
                )

            done = read_u32(
                hproc,
                result_ptr,
            )

            if done == 1:
                print(
                    "[AFDEV] StopMovie wrapper executed successfully."
                )
                return True

            time.sleep(0.05)

        raise RuntimeError(
            "StopMovie game-thread trampoline did not finish."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(hthread)


def wait_for_pending_url_clear(
    hproc,
    engine_ptr,
    timeout=20.0,
):
    """
    Wait until the OPEN request has been consumed.
    Returns True when PendingURL Num becomes zero.
    """
    deadline = time.time() + timeout

    while time.time() < deadline:
        if not process_alive(hproc):
            return False

        text, ptr, num, cap = read_remote_fstring(
            hproc,
            engine_ptr + PENDING_URL_OFFSET,
        )

        print(
            f"[AFDEV] Travel wait: PendingURL={text!r} "
            f"(Num={num} Max={cap})"
        )

        if num == 0:
            return True

        time.sleep(0.5)

    return False


def monitor_travel_state(hproc, engine_ptr, game_root, seconds=30):
    print()
    print("[AFDEV] ===== LIVE TRAVEL / LOADMAP STATE =====")
    print(
        f"[AFDEV] Monitoring for {seconds}s: "
        "GWorld, PendingURL, PendingFlag"
    )

    previous = None
    world_first_seen = None

    for i in range(seconds + 1):
        if not process_alive(hproc):
            print("[AFDEV] TGame exited during state monitor.")
            return

        gworld = safe_read_u32(hproc, GWORLD_PTR_VA)
        pending, pptr, pnum, pmax = read_remote_fstring(
            hproc,
            engine_ptr + PENDING_URL_OFFSET,
        )

        try:
            pflag = read_remote(
                hproc,
                engine_ptr + PENDING_FLAG_OFFSET,
                1,
            )[0]
        except Exception:
            pflag = None

        state = (gworld, pending, pflag, pnum, pmax)

        # Print every 2 sec, plus immediately when state changes.
        if state != previous or i % 2 == 0:
            gworld_text = (
                f"0x{gworld:08X}"
                if gworld is not None
                else "<read-fail>"
            )
            flag_text = (
                f"0x{pflag:02X}"
                if pflag is not None
                else "<read-fail>"
            )

            print(
                f"[STATE +{i:02d}s] "
                f"GWorld={gworld_text} "
                f"PendingFlag={flag_text} "
                f"PendingURL={pending!r} "
                f"(Num={pnum} Max={pmax})"
            )

        if gworld and world_first_seen is None:
            world_first_seen = i
            print(
                f"[AFDEV] >>> GWorld became non-null at +{i}s: "
                f"0x{gworld:08X}"
            )

        previous = state

        if i != seconds:
            time.sleep(1.0)

    print("[AFDEV] ===== END LIVE STATE =====")
    print()

    logs = find_recent_log_files(game_root)
    if logs:
        print_log_tail(logs[0], max_lines=40)
    else:
        print("[AFDEV] No .log file found in common game log locations.")


def inject_exec_on_game_thread(
    hproc,
    hthread,
    engine_ptr,
    log_ptr,
    command,
):
    """
    Run UTGameEngine::Exec(command, *GLog) on the primary TGame thread.

    The trampoline:
      pushfd
      pushad
      mov eax,[GEngine]
      lea ecx,[eax+3Ch]   ; FExec/Exec adjusted this
      mov eax,[GLog]
      push eax             ; second arg: FOutputDevice*
      push command_ptr     ; first arg: TCHAR*
      mov eax,UTGameEngine::Exec
      call eax             ; callee RET 8
      mov [result_ptr],eax
      popad
      popfd
      jmp original_EIP

    Registers/flags and the interrupted EIP are restored afterward.
    """

    command_bytes = (
        command.encode("utf-16le")
        + b"\x00\x00"
    )

    # 4 KB is plenty for command + result + trampoline.
    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )

    if not remote:
        winerr("VirtualAllocEx")

    remote = int(ctypes.cast(
        remote,
        ctypes.c_void_p,
    ).value)

    command_ptr = remote + 0x000
    result_ptr  = remote + 0x400
    code_ptr    = remote + 0x500

    write_remote(
        hproc,
        command_ptr,
        command_bytes,
    )

    # Sentinel = not executed yet.
    write_remote(
        hproc,
        result_ptr,
        struct.pack("<I", 0xDEADC0DE),
    )

    prev = kernel32.SuspendThread(hthread)

    if prev == 0xFFFFFFFF:
        winerr("SuspendThread")

    suspended = True

    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL

        if not kernel32.Wow64GetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64GetThreadContext")

        original_eip = ctx.Eip

        print(
            f"[AFDEV] Primary/game thread paused at "
            f"EIP=0x{original_eip:08X}"
        )

        # x86 trampoline.
        sc = bytearray()

        sc += b"\x9C"              # pushfd
        sc += b"\x60"              # pushad

        # mov eax,[GENGINE_PTR_VA]
        sc += b"\xA1" + struct.pack(
            "<I",
            GENGINE_PTR_VA,
        )

        # test eax,eax
        sc += b"\x85\xC0"

        # jz -> restore (patched below)
        jz_pos = len(sc)
        sc += b"\x74\x00"

        # IMPORTANT:
        # UEngine/UTGameEngine's Exec implementation is reached through the
        # FExec multiple-inheritance subobject. Static code proves the Exec
        # body dereferences [this-0x3C] to get the real engine/vtable.
        #
        # Therefore:
        #     Exec this = GEngine + 0x3C
        #
        # v0.7 incorrectly used GEngine directly, causing the crash at
        # 0x009C0FF9 after:
        #     mov eax,[esi-3C]
        #
        # lea ecx,[eax+3Ch]
        sc += b"\x8D\x48\x3C"

        # mov eax,[GLOG_PTR_VA]
        sc += b"\xA1" + struct.pack(
            "<I",
            GLOG_PTR_VA,
        )

        # push eax (FOutputDevice*)
        sc += b"\x50"

        # push command_ptr
        sc += b"\x68" + struct.pack(
            "<I",
            command_ptr,
        )

        # mov eax, TGAMEENGINE_EXEC_VA
        # Call the Assault Fire UTGameEngine::Exec override. Unknown/base
        # commands such as OPEN fall through to UGameEngine::Exec.
        sc += b"\xB8" + struct.pack(
            "<I",
            TGAMEENGINE_EXEC_VA,
        )

        # call eax
        sc += b"\xFF\xD0"

        # mov [result_ptr],eax
        sc += b"\xA3" + struct.pack(
            "<I",
            result_ptr,
        )

        restore_pos = len(sc)

        # popad / popfd
        sc += b"\x61\x9D"

        # mov eax,original_eip ; jmp eax
        # EAX was restored by popad, so use push original; ret
        # to avoid clobbering any register.
        sc += b"\x68" + struct.pack(
            "<I",
            original_eip,
        )
        sc += b"\xC3"

        # Fix short JZ displacement.
        disp = restore_pos - (jz_pos + 2)

        if not -128 <= disp <= 127:
            raise RuntimeError(
                "internal trampoline branch out of range"
            )

        sc[jz_pos + 1] = disp & 0xFF

        write_remote(
            hproc,
            code_ptr,
            bytes(sc),
        )

        print(
            f"[AFDEV] Trampoline @0x{code_ptr:08X}"
        )
        print(
            f"[AFDEV] Command    @0x{command_ptr:08X}: "
            f"{command}"
        )
        exec_this = (engine_ptr + 0x3C) & 0xFFFFFFFF

        print(
            f"[AFDEV] GEngine=0x{engine_ptr:08X} "
            f"GLog=0x{log_ptr:08X}"
        )
        print(
            f"[AFDEV] Exec this = GEngine+0x3C = "
            f"0x{exec_this:08X}"
        )

        # Useful structural diagnostic. In this build the Exec implementation
        # uses [this-0x3C], which must resolve back to the actual GEngine.
        try:
            main_vtable = read_u32(hproc, engine_ptr)
            subobject_word = read_u32(hproc, exec_this)
            print(
                f"[AFDEV] [GEngine]      = 0x{main_vtable:08X}"
            )
            print(
                f"[AFDEV] [GEngine+3C]   = 0x{subobject_word:08X}"
            )
        except Exception as e:
            print(
                f"[AFDEV] Exec-layout diagnostic skipped: {e}"
            )

        ctx.Eip = code_ptr

        if not kernel32.Wow64SetThreadContext(
            hthread,
            ctypes.byref(ctx),
        ):
            winerr("Wow64SetThreadContext")

        resumed = kernel32.ResumeThread(hthread)

        if resumed == 0xFFFFFFFF:
            winerr("ResumeThread(trampoline)")

        suspended = False

        # Wait for trampoline to write the UTGameEngine::Exec result.
        deadline = time.time() + 60.0

        while time.time() < deadline:
            if not process_alive(hproc):
                raise RuntimeError(
                    "TGame exited while executing UE3 OPEN."
                )

            result = read_u32(
                hproc,
                result_ptr,
            )

            if result != 0xDEADC0DE:
                print(
                    f"[AFDEV] UTGameEngine::Exec returned: "
                    f"0x{result:08X}"
                )

                # Keep the allocation alive. It is harmless and avoids any
                # tiny race with the trampoline's final instruction.
                return result

            time.sleep(0.05)

        raise RuntimeError(
            "The game-thread Exec trampoline did not finish within 60 sec."
        )

    finally:
        if suspended:
            kernel32.ResumeThread(hthread)



# ---------------------------------------------------------------------------
# v39 - exact TGSV3Game SpawnActor return + rejection branch tracer
#
# No guessed class-loader repair.  v38 proved the class passed by SetGameInfo
# is non-NULL and has the TGSV3Game FName index (0x1076E).
#
# We instrument ONLY SetGameInfo's SpawnActor call:
#   0x00DA2D7F call 0x00A649E0
#
# The call wrapper swaps the return address, then tail-jumps to SpawnActor.
# This preserves every original argument and SpawnActor's native "ret 2Ch".
# When SpawnActor returns, our after-return stub records EAX and jumps to the
# original SetGameInfo return address.
#
# We also wrap the stock SpawnActor failure-log callsites.  When the tracked
# SetGameInfo spawn is active, they record an exact reason code but still call
# the original logger unchanged.
# ---------------------------------------------------------------------------

V40_SETGAMEINFO_SPAWN_CALL = 0x00DA2D7F
V40_SETGAMEINFO_SPAWN_EXPECT = bytes.fromhex("E8 5C 1C CC FF")
V40_SPAWNACTOR = 0x00A649E0

# (callsite, expected call bytes, original logger target, reason code)
V40_REASON_SITES = (
    # "no class was specified"
    (0x00A64CB8, bytes.fromhex("E8 33 47 A6 FF"), 0x004C93F0, 1),
    # common logger for deprecated / abstract / not-an-actor-class
    (0x00A64D04, bytes.fromhex("E8 E7 46 A6 FF"), 0x004C93F0, 2),
    # bStatic / bNoDelete
    (0x00A64E02, bytes.fromhex("E8 E9 45 A6 FF"), 0x004C93F0, 3),
    # template class mismatch
    (0x00A64E93, bytes.fromhex("E8 68 88 7B 00"), 0x0121D700, 4),
    # collision failure path A
    (0x00A650CB, bytes.fromhex("E8 30 86 7B 00"), 0x0121D700, 5),
    # collision failure path B
    (0x00A65161, bytes.fromhex("E8 9A 85 7B 00"), 0x0121D700, 6),
    # spawned then destroyed because encroaching
    (0x00A658C9, bytes.fromhex("E8 22 3B A6 FF"), 0x004C93F0, 7),
)

V40_REASON_TEXT = {
    0: "none of the instrumented stock failure branches",
    1: "no class specified",
    2: "deprecated / abstract / not-an-actor-class (format pointer disambiguates)",
    3: "class has bStatic or bNoDelete",
    4: "template class mismatch",
    5: "collision at spawn location (path A)",
    6: "collision at spawn location (path B)",
    7: "spawned then destroyed because it encroached on another Actor",
}


def install_spawnactor_trace_v40(hproc):
    cur = read_remote(
        hproc,
        V40_SETGAMEINFO_SPAWN_CALL,
        5,
    )
    if cur != V40_SETGAMEINFO_SPAWN_EXPECT:
        raise RuntimeError(
            "v39 SetGameInfo SpawnActor call mismatch: "
            f"expected={V40_SETGAMEINFO_SPAWN_EXPECT.hex(' ')} "
            f"got={cur.hex(' ')}"
        )

    for callsite, expected, _target, _reason in V40_REASON_SITES:
        got = read_remote(hproc, callsite, 5)
        if got != expected:
            raise RuntimeError(
                f"v39 reason-site mismatch @0x{callsite:08X}: "
                f"expected={expected.hex(' ')} got={got.hex(' ')}"
            )

    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x3000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not remote:
        winerr("VirtualAllocEx(v39 SpawnActor trace)")

    remote = int(ctypes.cast(remote, ctypes.c_void_p).value)

    scratch = remote
    entry = remote + 0x400
    after = remote + 0x600
    reason_code_base = remote + 0x800

    S_TRACKING = scratch + 0x00
    S_ORIG_RET = scratch + 0x04
    S_CLASS = scratch + 0x08
    S_THIS = scratch + 0x0C
    S_RETURN = scratch + 0x10
    S_DONE = scratch + 0x14
    S_REASON = scratch + 0x18
    S_FORMAT = scratch + 0x1C
    S_REASON_SITE = scratch + 0x20

    # v40 immediate snapshot fields (captured before the spawned actor can be
    # destroyed/reused by a subsequent world handoff).
    S_WORLDINFO_AT_RETURN = scratch + 0x24
    S_GWORLD_AT_RETURN = scratch + 0x28
    S_ACTOR_VT_AT_RETURN = scratch + 0x2C
    S_ACTOR_CLASS_AT_RETURN = scratch + 0x30
    S_ACTOR_NAMEIDX_AT_RETURN = scratch + 0x34
    S_ACTOR_NAMENUM_AT_RETURN = scratch + 0x38

    write_remote(hproc, scratch, b"\x00" * 0x100)

    # Entry wrapper:
    # Preserve all registers. Replace only the return address on the original
    # SpawnActor stack, then tail-jump to stock SpawnActor.
    sc = bytearray()

    sc += b"\x50"                              # push eax
    sc += b"\x8B\x44\x24\x04"                 # mov eax,[esp+4] original return
    sc += b"\xA3" + struct.pack("<I", S_ORIG_RET)
    sc += b"\x8B\x44\x24\x08"                 # mov eax,[esp+8] original Class arg
    sc += b"\xA3" + struct.pack("<I", S_CLASS)
    sc += b"\x89\x0D" + struct.pack("<I", S_THIS)   # mov [abs],ecx
    sc += b"\x58"                              # pop eax

    sc += b"\xC7\x05" + struct.pack("<I", S_TRACKING) + struct.pack("<I", 1)
    sc += b"\xC7\x05" + struct.pack("<I", S_DONE) + struct.pack("<I", 0)
    sc += b"\xC7\x05" + struct.pack("<I", S_REASON) + struct.pack("<I", 0)
    sc += b"\xC7\x05" + struct.pack("<I", S_FORMAT) + struct.pack("<I", 0)
    sc += b"\xC7\x05" + struct.pack("<I", S_REASON_SITE) + struct.pack("<I", 0)

    # Replace SetGameInfo return address with after-return stub.
    sc += b"\xC7\x04\x24" + struct.pack("<I", after)

    # Tail jump preserves the exact original stack / 11 arguments.
    sc += b"\xB8" + struct.pack("<I", V40_SPAWNACTOR)
    sc += b"\xFF\xE0"

    write_remote(hproc, entry, bytes(sc))

    # After SpawnActor's native ret 2Ch:
    # EAX is the exact return actor pointer.
    ar = bytearray()

    # EAX is the exact SpawnActor return pointer.
    ar += b"\xA3" + struct.pack("<I", S_RETURN)

    # At the original 0x00DA2D84, SetGameInfo does:
    #     mov edx,[esp+0x24]
    #     mov [edx+0x414],eax
    # Capture that exact WorldInfo* before anything else can change.
    ar += b"\x8B\x54\x24\x24"                      # mov edx,[esp+24]
    ar += b"\x89\x15" + struct.pack("<I", S_WORLDINFO_AT_RETURN)

    # Snapshot global GWorld at the same instant.
    ar += b"\x8B\x0D" + struct.pack("<I", GWORLD_PTR_VA)
    ar += b"\x89\x0D" + struct.pack("<I", S_GWORLD_AT_RETURN)

    # Snapshot the actor header immediately, before a later world destruction
    # can free/reuse this memory.
    ar += b"\x85\xC0"                                # test eax,eax
    jz_pos = len(ar)
    ar += b"\x0F\x84\x00\x00\x00\x00"          # jz no_actor

    ar += b"\x8B\x08"                                # mov ecx,[eax]
    ar += b"\x89\x0D" + struct.pack("<I", S_ACTOR_VT_AT_RETURN)
    ar += b"\x8B\x48\x34"                          # mov ecx,[eax+34]
    ar += b"\x89\x0D" + struct.pack("<I", S_ACTOR_CLASS_AT_RETURN)
    ar += b"\x8B\x48\x2C"                          # mov ecx,[eax+2C]
    ar += b"\x89\x0D" + struct.pack("<I", S_ACTOR_NAMEIDX_AT_RETURN)
    ar += b"\x8B\x48\x30"                          # mov ecx,[eax+30]
    ar += b"\x89\x0D" + struct.pack("<I", S_ACTOR_NAMENUM_AT_RETURN)

    no_actor = len(ar)
    struct.pack_into("<i", ar, jz_pos + 2, no_actor - (jz_pos + 6))

    ar += b"\xC7\x05" + struct.pack("<I", S_DONE) + struct.pack("<I", 1)
    ar += b"\xC7\x05" + struct.pack("<I", S_TRACKING) + struct.pack("<I", 0)

    # push original SetGameInfo return address; ret
    ar += b"\xFF\x35" + struct.pack("<I", S_ORIG_RET)
    ar += b"\xC3"

    write_remote(hproc, after, bytes(ar))

    def make_call_patch(callsite, target):
        rel = target - (callsite + 5)
        if not (-0x80000000 <= rel <= 0x7FFFFFFF):
            raise RuntimeError("v39 rel32 target out of range")
        return b"\xE8" + struct.pack("<i", rel)

    main_patch = make_call_patch(
        V40_SETGAMEINFO_SPAWN_CALL,
        entry,
    )
    write_remote(
        hproc,
        V40_SETGAMEINFO_SPAWN_CALL,
        main_patch,
    )

    # Small wrappers for each failure logger callsite.
    reason_wrappers = []

    for idx, (callsite, _expected, logger_target, reason) in enumerate(
        V40_REASON_SITES
    ):
        wrapper = reason_code_base + idx * 0x80
        rw = bytearray()

        # Save eax because it may be live across the logger call setup.
        rw += b"\x50"  # push eax
        rw += b"\xA1" + struct.pack("<I", S_TRACKING)
        rw += b"\x85\xC0"  # test eax,eax

        # je skip_record
        je_pos = len(rw)
        rw += b"\x0F\x84\x00\x00\x00\x00"

        rw += b"\xC7\x05" + struct.pack("<I", S_REASON) + struct.pack("<I", reason)
        rw += b"\xC7\x05" + struct.pack("<I", S_REASON_SITE) + struct.pack("<I", callsite)

        # With our push eax, the original logger call's format pointer that
        # was [esp+0x0C] is now [esp+0x10]. This is meaningful for the common
        # deprecated/abstract/not-actor logger and harmless elsewhere.
        rw += b"\x8B\x44\x24\x10"
        rw += b"\xA3" + struct.pack("<I", S_FORMAT)

        skip_record = len(rw)
        rel = skip_record - (je_pos + 6)
        struct.pack_into("<i", rw, je_pos + 2, rel)

        rw += b"\x58"  # pop eax
        rw += b"\xB8" + struct.pack("<I", logger_target)
        rw += b"\xFF\xE0"  # tail-jump logger, original stack untouched

        write_remote(hproc, wrapper, bytes(rw))

        patch = make_call_patch(callsite, wrapper)
        write_remote(hproc, callsite, patch)
        reason_wrappers.append((callsite, wrapper, reason))

    if read_remote(hproc, V40_SETGAMEINFO_SPAWN_CALL, 5) != main_patch:
        raise RuntimeError("v39 main SpawnActor hook verification failed")

    print()
    print("[AFDEV-v40] Exact SetGameInfo->SpawnActor tracer installed.")
    print(
        f"[AFDEV-v40] Spawn callsite=0x{V40_SETGAMEINFO_SPAWN_CALL:08X} "
        f"entry=0x{entry:08X} after=0x{after:08X}"
    )
    print(
        f"[AFDEV-v40] Failure branches instrumented: {len(reason_wrappers)}"
    )

    return {
        "remote": remote,
        "tracking": S_TRACKING,
        "orig_ret": S_ORIG_RET,
        "class": S_CLASS,
        "this": S_THIS,
        "return": S_RETURN,
        "done": S_DONE,
        "reason": S_REASON,
        "format": S_FORMAT,
        "reason_site": S_REASON_SITE,
        "worldinfo_at_return": S_WORLDINFO_AT_RETURN,
        "gworld_at_return": S_GWORLD_AT_RETURN,
        "actor_vt_at_return": S_ACTOR_VT_AT_RETURN,
        "actor_class_at_return": S_ACTOR_CLASS_AT_RETURN,
        "actor_nameidx_at_return": S_ACTOR_NAMEIDX_AT_RETURN,
        "actor_namenum_at_return": S_ACTOR_NAMENUM_AT_RETURN,
    }


def report_spawnactor_trace_v40(hproc, state):
    done = read_u32(hproc, state["done"])
    cls = read_u32(hproc, state["class"])
    thisp = read_u32(hproc, state["this"])
    ret = read_u32(hproc, state["return"])
    reason = read_u32(hproc, state["reason"])
    fmt = read_u32(hproc, state["format"])
    site = read_u32(hproc, state["reason_site"])

    wi_at_ret = read_u32(hproc, state["worldinfo_at_return"])
    gw_at_ret = read_u32(hproc, state["gworld_at_return"])
    av_at_ret = read_u32(hproc, state["actor_vt_at_return"])
    ac_at_ret = read_u32(hproc, state["actor_class_at_return"])
    ani_at_ret = read_u32(hproc, state["actor_nameidx_at_return"])
    ann_at_ret = read_u32(hproc, state["actor_namenum_at_return"])

    print()
    print("[AFDEV-v40] ===== SETGAMEINFO SPAWNACTOR RESULT =====")
    print(
        f"[AFDEV-v40] completed={bool(done)} "
        f"this=0x{thisp:08X} Class=0x{cls:08X}"
    )
    print(
        f"[AFDEV-v40] SpawnActor return EAX=0x{ret:08X}"
    )
    print(
        f"[AFDEV-v40] IMMEDIATE snapshot: "
        f"GWorld=0x{gw_at_ret:08X} WorldInfo=0x{wi_at_ret:08X}"
    )
    print(
        f"[AFDEV-v40] IMMEDIATE actor header: "
        f"vt=0x{av_at_ret:08X} Class=0x{ac_at_ret:08X} "
        f"FName=(0x{ani_at_ret:08X},{ann_at_ret})"
    )
    print(
        f"[AFDEV-v40] failure_reason={reason} "
        f"({V40_REASON_TEXT.get(reason, 'unknown')})"
    )
    print(
        f"[AFDEV-v40] failure_callsite=0x{site:08X} "
        f"format_ptr=0x{fmt:08X}"
    )

    if cls:
        try:
            ni = read_u32(hproc, cls + 0x2C)
            nn = read_u32(hproc, cls + 0x30)
            flags = read_u32(hproc, cls + 0xF4)
            superp = read_u32(hproc, cls + 0x48)
            print(
                f"[AFDEV-v40] Class FName=(0x{ni:08X},{nn}) "
                f"ClassFlags=0x{flags:08X} Super=0x{superp:08X}"
            )
        except Exception:
            pass

    if ret:
        try:
            vt = read_u32(hproc, ret)
            ni = read_u32(hproc, ret + 0x2C)
            nn = read_u32(hproc, ret + 0x30)
            objcls = read_u32(hproc, ret + 0x34)
            print(
                f"[AFDEV-v40] returned actor: vt=0x{vt:08X} "
                f"FName=(0x{ni:08X},{nn}) Class=0x{objcls:08X}"
            )
        except Exception:
            pass

    if not done:
        print(
            "[AFDEV-v40] WARNING: tracked SetGameInfo SpawnActor call "
            "did not return through the after stub."
        )
    elif ret == 0:
        if reason:
            print(
                "[AFDEV-v40] >>> SpawnActor itself rejected TGSV3Game "
                "on the recorded stock failure branch."
            )
        else:
            print(
                "[AFDEV-v40] >>> SpawnActor returned NULL, but none of the "
                "instrumented early rejection logs fired. The failure is later "
                "in actor allocation/initialization."
            )
    else:
        print(
            "[AFDEV-v40] >>> SpawnActor CREATED the GameInfo actor. "
            "If final WorldInfo.Game is NULL, something clears it later "
            "during LoadMap."
        )

    print("[AFDEV-v40] ===== END SETGAMEINFO SPAWNACTOR RESULT =====")
    print()


# ---------------------------------------------------------------------------
# v40 local read-only GWorld transition watcher
# ---------------------------------------------------------------------------

def start_gworld_transition_watcher_v40(hproc):
    state = {
        "stop": False,
        "events": [],
        "start": time.time(),
    }

    def worker():
        last = None
        while not state["stop"]:
            try:
                cur = safe_read_u32(hproc, GWORLD_PTR_VA) or 0
            except Exception:
                cur = 0

            if cur != last:
                now = time.time() - state["start"]

                netdriver = 0
                level = 0
                if cur:
                    try:
                        netdriver = safe_read_u32(hproc, cur + 0xD8) or 0
                    except Exception:
                        netdriver = 0
                    try:
                        level = safe_read_u32(hproc, cur + 0x50) or 0
                    except Exception:
                        level = 0

                rec = (now, last or 0, cur, netdriver, level)
                state["events"].append(rec)

                print(
                    f"[AFDEV-v40][GWORLD +{now:07.3f}s] "
                    f"{('NULL' if not last else f'0x{last:08X}')} -> "
                    f"{('NULL' if not cur else f'0x{cur:08X}')} "
                    f"NetDriver=0x{netdriver:08X} PersistentLevel=0x{level:08X}",
                    flush=True,
                )

                last = cur

            time.sleep(0.002)

    t = threading.Thread(
        target=worker,
        name="afdev-v40-gworld-watch",
        daemon=True,
    )
    t.start()
    return state, t


def report_gworld_transitions_v40(state):
    print()
    print("[AFDEV-v40] ===== GWORLD TRANSITION SUMMARY =====")
    for i, (ts, old, new, nd, level) in enumerate(state["events"]):
        print(
            f"[GW {i:02d}] +{ts:07.3f}s "
            f"{('NULL' if not old else f'0x{old:08X}')} -> "
            f"{('NULL' if not new else f'0x{new:08X}')} "
            f"NetDriver=0x{nd:08X} PersistentLevel=0x{level:08X}"
        )
    print("[AFDEV-v40] ===== END GWORLD TRANSITION SUMMARY =====")
    print()


# ---------------------------------------------------------------------------
# v41 - isolate ONLY the late OPEN / selected PvE map LoadMap.
#
# v40 proved that its captured TGSV3Game spawn belonged to the PRE-OPEN
# frontend world (the world already existed before OPEN).  v41 therefore:
#
#   * hooks the exact LoadMap -> UWorld::SetGameInfo callsite;
#   * clears the hook counters immediately BEFORE OPEN;
#   * clears the SpawnActor trace immediately BEFORE OPEN;
#   * resets the LoadMap stage marker to zero immediately BEFORE OPEN.
#
# This makes every reported SetGameInfo/SpawnActor/stage event unambiguously
# belong to the selected PvE map travel rather than frontend startup.
# ---------------------------------------------------------------------------

V41_SETGAMEINFO_CALLSITE = 0x009C9627
V41_SETGAMEINFO_EXPECT = bytes.fromhex("E8 34 91 3D 00")
V41_SETGAMEINFO_TARGET = 0x00DA2760


def install_setgameinfo_call_trace_v41(hproc):
    current = read_remote(
        hproc,
        V41_SETGAMEINFO_CALLSITE,
        5,
    )
    if current != V41_SETGAMEINFO_EXPECT:
        raise RuntimeError(
            "v41 SetGameInfo callsite mismatch: "
            f"expected={V41_SETGAMEINFO_EXPECT.hex(' ')} "
            f"got={current.hex(' ')}"
        )

    remote = kernel32.VirtualAllocEx(
        hproc,
        None,
        0x1000,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE,
    )
    if not remote:
        winerr("VirtualAllocEx(v41 SetGameInfo trace)")

    remote = int(ctypes.cast(remote, ctypes.c_void_p).value)

    scratch = remote
    code = remote + 0x100

    S_COUNT = scratch + 0x00
    S_THIS = scratch + 0x04
    S_URL = scratch + 0x08

    write_remote(hproc, scratch, b"\x00" * 0x40)

    sc = bytearray()
    sc += b"\x89\x0D" + struct.pack("<I", S_THIS)   # mov [abs],ecx
    sc += b"\x8B\x44\x24\x04"                      # mov eax,[esp+4]
    sc += b"\xA3" + struct.pack("<I", S_URL)        # mov [abs],eax
    sc += b"\xFF\x05" + struct.pack("<I", S_COUNT)  # inc dword [abs]
    sc += b"\xB8" + struct.pack("<I", V41_SETGAMEINFO_TARGET)
    sc += b"\xFF\xE0"                               # jmp eax

    write_remote(hproc, code, bytes(sc))

    rel = code - (V41_SETGAMEINFO_CALLSITE + 5)
    if not (-0x80000000 <= rel <= 0x7FFFFFFF):
        raise RuntimeError("v41 SetGameInfo wrapper out of rel32 range")

    patch = b"\xE8" + struct.pack("<i", rel)
    write_remote(hproc, V41_SETGAMEINFO_CALLSITE, patch)

    if read_remote(hproc, V41_SETGAMEINFO_CALLSITE, 5) != patch:
        raise RuntimeError("v41 SetGameInfo hook verification failed")

    print()
    print("[AFDEV-v41] Fresh-travel SetGameInfo call tracer installed.")
    print(
        f"[AFDEV-v41] callsite=0x{V41_SETGAMEINFO_CALLSITE:08X} "
        f"target=0x{V41_SETGAMEINFO_TARGET:08X} wrapper=0x{code:08X}"
    )

    return {
        "remote": remote,
        "count": S_COUNT,
        "this": S_THIS,
        "url": S_URL,
    }


def reset_post_open_trace_v41(
    hproc,
    stage_marker_ptr,
    spawn_state,
    setgameinfo_state,
):
    # Fresh LoadMap marker.
    write_remote(
        hproc,
        stage_marker_ptr,
        struct.pack("<I", 0),
    )

    # Clear every v40 SpawnActor result field so a frontend startup call cannot
    # be mistaken for an selected PvE map call.
    zero_spawn_keys = (
        "tracking",
        "orig_ret",
        "class",
        "this",
        "return",
        "done",
        "reason",
        "format",
        "reason_site",
        "worldinfo_at_return",
        "gworld_at_return",
        "actor_vt_at_return",
        "actor_class_at_return",
        "actor_nameidx_at_return",
        "actor_namenum_at_return",
    )

    for key in zero_spawn_keys:
        write_remote(
            hproc,
            spawn_state[key],
            b"\x00\x00\x00\x00",
        )

    # Clear direct SetGameInfo-call trace.
    for key in ("count", "this", "url"):
        write_remote(
            hproc,
            setgameinfo_state[key],
            b"\x00\x00\x00\x00",
        )

    print()
    print("[AFDEV-v41] ===== POST-OPEN TRACE RESET =====")
    print("[AFDEV-v41] LoadMap stage marker reset to 0.")
    print("[AFDEV-v41] SetGameInfo call count reset to 0.")
    print("[AFDEV-v41] SpawnActor trace reset to 0.")
    print(
        "[AFDEV-v41] From this point onward every captured event belongs "
        "to the selected PvE map OPEN travel."
    )
    print("[AFDEV-v41] ===== END TRACE RESET =====")
    print()


def report_setgameinfo_call_trace_v41(hproc, state):
    count = read_u32(hproc, state["count"])
    thisp = read_u32(hproc, state["this"])
    urlp = read_u32(hproc, state["url"])

    print()
    print("[AFDEV-v41] ===== POST-OPEN SETGAMEINFO CALL TRACE =====")
    print(
        f"[AFDEV-v41] calls={count} last_this=0x{thisp:08X} "
        f"last_FURL_ptr=0x{urlp:08X}"
    )

    if count == 0:
        print(
            "[AFDEV-v41] >>> selected PvE map LoadMap NEVER called UWorld::SetGameInfo."
        )
    else:
        print(
            "[AFDEV-v41] >>> selected PvE map LoadMap DID call UWorld::SetGameInfo."
        )

    print("[AFDEV-v41] ===== END SETGAMEINFO CALL TRACE =====")
    print()


# ---------------------------------------------------------------------------
# r12 PvE GameSpecificSettings propagation
# ---------------------------------------------------------------------------
# Stock shipped UnrealScript proves:
#   TGGame.UpdateGameSpecificSettings(Settings)
#       GameSettings = Settings
#       WorldInfo.GameSettingFlags = GameSettings.Flags
#   PVEGame.UpdateGameSpecificSettings(Settings)
#       Super.UpdateGameSpecificSettings(Settings)
#       InitGameReplicationInfo()
#   PVEGame.GetDifficulty()
#       0x1001 -> Easy(0), 0x1002 -> Normal(1), 0x1003 -> Hard(2)
#
# The old DS backend never delivered the Settings struct to AFDEV, so PvE
# always retained defaults.  Resolve the live fields by reflection and write
# only the stock final state before SESSION_READY / before the retail client is
# allowed through the UDP latch.  No Kismet output is forced or patched.

PVE_FNAME_FROM_TCHAR_VA = 0x004D78D0
PVE_UOBJECT_NAME_INDEX = 0x2C
PVE_UOBJECT_NAME_NUMBER = 0x30
PVE_UOBJECT_CLASS = 0x34
PVE_UFIELD_NEXT = 0x3C
PVE_USTRUCT_SUPER = 0x48
PVE_USTRUCT_CHILDREN = 0x4C
PVE_UPROPERTY_ARRAYDIM = 0x40
PVE_UPROPERTY_ELEMENTSIZE = 0x44
PVE_UPROPERTY_OFFSET = 0x60
PVE_UFUNCTION_PARMS_SIZE = 0xBE

# Compatibility aliases for the older r24 Maya/Steel settings path.
# r24 used MAYA_* names for this same validated PH v1.0.0.24 UE3 layout.
# Keep these aliases defined so older Maya/Steel code cannot crash with
# NameError while sharing the generic reflection implementation.
MAYA_FNAME_FROM_TCHAR_VA = PVE_FNAME_FROM_TCHAR_VA
MAYA_UOBJECT_NAME_INDEX = PVE_UOBJECT_NAME_INDEX
MAYA_UOBJECT_NAME_NUMBER = PVE_UOBJECT_NAME_NUMBER
MAYA_UOBJECT_CLASS = PVE_UOBJECT_CLASS
MAYA_UFIELD_NEXT = PVE_UFIELD_NEXT
MAYA_USTRUCT_SUPER = PVE_USTRUCT_SUPER
MAYA_USTRUCT_CHILDREN = PVE_USTRUCT_CHILDREN
MAYA_UPROPERTY_ARRAYDIM = PVE_UPROPERTY_ARRAYDIM
MAYA_UPROPERTY_ELEMENTSIZE = PVE_UPROPERTY_ELEMENTSIZE
MAYA_UPROPERTY_OFFSET = PVE_UPROPERTY_OFFSET
MAYA_UFUNCTION_PARMS_SIZE = PVE_UFUNCTION_PARMS_SIZE
# r20 profile -> authoritative UE3 PRI name synchronization.
R20_PVE_PC_VTABLE = 0x01E24C28
R20_ULOCALPLAYER_VTABLE = 0x01D59830
R20_PC_PRI_OFFSET = 0x1DC
R20_PC_PLAYER_OFFSET = 0x370


def _pve_ptr(v):
    return isinstance(v, int) and 0x00010000 <= v < 0x7FFF0000 and (v & 3) == 0


def _pve_object_header(hproc, obj):
    if not _pve_ptr(obj):
        return None
    try:
        raw = read_remote(hproc, obj, 0x38)
    except Exception:
        return None
    return {
        "name_index": struct.unpack_from("<I", raw, PVE_UOBJECT_NAME_INDEX)[0],
        "name_number": struct.unpack_from("<I", raw, PVE_UOBJECT_NAME_NUMBER)[0],
        "class": struct.unpack_from("<I", raw, PVE_UOBJECT_CLASS)[0],
    }


def _pve_construct_fname(hproc, hthread, text_value):
    text_bytes = text_value.encode("utf-16le") + b"\x00\x00"
    remote = kernel32.VirtualAllocEx(
        hproc, None, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if not remote:
        winerr("VirtualAllocEx(PvE FName)")
    remote = int(ctypes.cast(remote, ctypes.c_void_p).value)
    string_ptr = remote + 0x000
    fname_ptr = remote + 0x400
    done_ptr = remote + 0x420
    code_ptr = remote + 0x500
    write_remote(hproc, string_ptr, text_bytes)
    write_remote(hproc, fname_ptr, b"\x00" * 8)
    write_remote(hproc, done_ptr, struct.pack("<I", 0))

    prev = kernel32.SuspendThread(hthread)
    if prev == 0xFFFFFFFF:
        winerr("SuspendThread(PvE FName)")
    suspended = True
    try:
        ctx = WOW64_CONTEXT()
        ctx.ContextFlags = WOW64_CONTEXT_FULL
        if not kernel32.Wow64GetThreadContext(hthread, ctypes.byref(ctx)):
            winerr("Wow64GetThreadContext(PvE FName)")
        original_eip = ctx.Eip
        sc = bytearray()
        sc += b"\x9C\x60"  # pushfd; pushad
        sc += b"\xB9" + struct.pack("<I", fname_ptr)  # ecx=this
        sc += b"\x6A\x01\x6A\x01"
        sc += b"\x68" + struct.pack("<I", string_ptr)
        sc += b"\xB8" + struct.pack("<I", PVE_FNAME_FROM_TCHAR_VA)
        sc += b"\xFF\xD0"
        sc += b"\xC7\x05" + struct.pack("<I", done_ptr) + struct.pack("<I", 1)
        sc += b"\x61\x9D"
        sc += b"\x68" + struct.pack("<I", original_eip) + b"\xC3"
        write_remote(hproc, code_ptr, bytes(sc))
        ctx.Eip = code_ptr
        if not kernel32.Wow64SetThreadContext(hthread, ctypes.byref(ctx)):
            winerr("Wow64SetThreadContext(PvE FName)")
        if kernel32.ResumeThread(hthread) == 0xFFFFFFFF:
            winerr("ResumeThread(PvE FName)")
        suspended = False
        deadline = time.time() + 5.0
        while time.time() < deadline:
            if read_u32(hproc, done_ptr) == 1:
                idx, num = struct.unpack("<II", read_remote(hproc, fname_ptr, 8))
                print(f"[AFDEV-PVE-SETTINGS] FName {text_value!r}=0x{idx:08X}:{num}")
                return idx, num
            time.sleep(0.01)
        raise RuntimeError(f"FName({text_value!r}) timed out")
    finally:
        if suspended:
            kernel32.ResumeThread(hthread)


def _pve_find_field(hproc, start_struct, fname_pair):
    idx, num = fname_pair
    cur = start_struct
    seen_structs = set()
    while _pve_ptr(cur) and cur not in seen_structs:
        seen_structs.add(cur)
        try:
            fld = read_u32(hproc, cur + PVE_USTRUCT_CHILDREN)
        except Exception:
            break
        seen_fields = set()
        while _pve_ptr(fld) and fld not in seen_fields:
            seen_fields.add(fld)
            hdr = _pve_object_header(hproc, fld)
            if not hdr:
                break
            if hdr["name_index"] == idx and hdr["name_number"] == num:
                raw = read_remote(hproc, fld, 0x68)
                return {
                    "field": fld,
                    "offset": struct.unpack_from("<I", raw, PVE_UPROPERTY_OFFSET)[0],
                    "array_dim": struct.unpack_from("<I", raw, PVE_UPROPERTY_ARRAYDIM)[0],
                    "element_size": struct.unpack_from("<I", raw, PVE_UPROPERTY_ELEMENTSIZE)[0],
                }
            try:
                fld = read_u32(hproc, fld + PVE_UFIELD_NEXT)
            except Exception:
                break
        try:
            cur = read_u32(hproc, cur + PVE_USTRUCT_SUPER)
        except Exception:
            break
    return None


def _pve_struct_descriptor(hproc, struct_property, target_fname):
    # UStructProperty stores a pointer to its UScriptStruct after the UProperty
    # base. Scan only the small subclass tail and accept only a UObject whose
    # FName is exactly GameSpecificSettings.
    raw = read_remote(hproc, struct_property, 0xA0)
    idx, num = target_fname
    hits = []
    for off in range(0x64, 0xA0 - 3, 4):
        cand = struct.unpack_from("<I", raw, off)[0]
        hdr = _pve_object_header(hproc, cand)
        if hdr and hdr["name_index"] == idx and hdr["name_number"] == num:
            hits.append((off, cand))
    if len(hits) != 1:
        raise RuntimeError(
            f"GameSettings StructProperty descriptor not unique: {[(hex(o), hex(p)) for o,p in hits]}"
        )
    return hits[0][1]


def _pve_write_int(hproc, address, value, element_size, label):
    if element_size == 1:
        data = struct.pack("<B", int(value) & 0xFF)
    elif element_size == 2:
        data = struct.pack("<H", int(value) & 0xFFFF)
    elif element_size == 4:
        data = struct.pack("<I", int(value) & 0xFFFFFFFF)
    else:
        raise RuntimeError(f"{label}: unsupported ElementSize={element_size}")
    old = read_remote(hproc, address, element_size)
    write_remote(hproc, address, data)
    verify = read_remote(hproc, address, element_size)
    if verify != data:
        raise RuntimeError(f"{label}: write verification failed")
    print(
        f"[AFDEV-PVE-SETTINGS] {label} @0x{address:08X} "
        f"{int.from_bytes(old, 'little')} -> {int(value)}"
    )



def _r20_probable_uobject(hproc, obj):
    if not _pve_ptr(obj):
        return False
    try:
        vt = read_u32(hproc, obj)
        hdr = _pve_object_header(hproc, obj)
    except Exception:
        return False
    return bool(
        hdr
        and 0x00400000 <= int(vt) < 0x03000000
        and _pve_ptr(int(hdr.get("class") or 0))
    )


def _r20_scan_exact_vtable_quiet(hproc, target_vtable, max_hits=64):
    pattern = struct.pack("<I", int(target_vtable))
    hits = []
    address = 0x00010000
    max_address = 0x70000000
    mbi = MEMORY_BASIC_INFORMATION()
    mbi_size = ctypes.sizeof(mbi)

    while address < max_address and len(hits) < max_hits:
        got = kernel32.VirtualQueryEx(
            hproc,
            ctypes.c_void_p(address),
            ctypes.byref(mbi),
            mbi_size,
        )
        if not got:
            address += 0x10000
            continue

        base = int(mbi.BaseAddress or 0)
        size = int(mbi.RegionSize or 0)
        if size <= 0:
            address += 0x10000
            continue
        nxt = base + size

        readable = (
            mbi.State == MEM_COMMIT
            and mbi.Type == MEM_PRIVATE
            and not (mbi.Protect & PAGE_NOACCESS)
            and not (mbi.Protect & PAGE_GUARD)
        )

        if readable:
            pos = base
            end = min(nxt, max_address)
            while pos < end and len(hits) < max_hits:
                want = min(1024 * 1024, end - pos)
                try:
                    blob = read_remote(hproc, pos, want)
                except Exception:
                    pos += want
                    continue

                start = 0
                while len(hits) < max_hits:
                    off = blob.find(pattern, start)
                    if off < 0:
                        break
                    cand = pos + off
                    if (cand & 3) == 0 and _r20_probable_uobject(hproc, cand):
                        hits.append(cand)
                    start = off + 4
                pos += want

        address = nxt if nxt > address else address + 0x10000

    return sorted(set(hits))


def _r20_find_remote_pve_pc(hproc):
    remotes = []
    for pc in _r20_scan_exact_vtable_quiet(
        hproc, R20_PVE_PC_VTABLE, 64
    ):
        try:
            player = read_u32(hproc, pc + R20_PC_PLAYER_OFFSET)
            pri = read_u32(hproc, pc + R20_PC_PRI_OFFSET)
        except Exception:
            continue

        if not _r20_probable_uobject(hproc, player):
            continue
        if not _r20_probable_uobject(hproc, pri):
            continue

        try:
            player_vt = read_u32(hproc, player)
        except Exception:
            player_vt = 0

        if player_vt == R20_ULOCALPLAYER_VTABLE:
            continue

        remotes.append((pc, player, pri))

    return remotes


def _r20_read_fstring(hproc, address):
    try:
        data, num, cap = struct.unpack(
            "<III", read_remote(hproc, address, 12)
        )
    except Exception:
        return "<unreadable>"

    if num <= 0:
        return ""
    if not _pve_ptr(data) or num > 128 or cap < num or cap > 256:
        return f"<invalid data=0x{data:08X} num={num} max={cap}>"

    try:
        return (
            read_remote(hproc, data, num * 2)
            .decode("utf-16le", errors="replace")
            .rstrip("\x00")
        )
    except Exception:
        return "<payload-unreadable>"


def r20_sync_remote_pri_name(hproc, hthread, nickname, timeout=45.0):
    """Wait for retail client PC/PRI and set authoritative PRI.PlayerName."""
    nickname = str(nickname or "").strip()
    if not nickname or nickname in ("LocalPlayer", "Player1"):
        print(
            f"[AFDEV-PROFILE-r20] skip PRI rename: unresolved nickname={nickname!r}"
        )
        return False

    if len(nickname) > 31:
        print("[AFDEV-PROFILE-r20] skip nickname >31 chars")
        return False

    encoded = nickname.encode("utf-16le") + b"\x00\x00"
    deadline = time.time() + float(timeout)
    last_count = None

    while time.time() < deadline and process_alive(hproc):
        remotes = _r20_find_remote_pve_pc(hproc)

        if len(remotes) == 1:
            pc, player, pri = remotes[0]
            ph = _pve_object_header(hproc, pri)
            if not ph:
                time.sleep(0.10)
                continue

            pair = _pve_construct_fname(
                hproc, hthread, "PlayerName"
            )
            prop = _pve_find_field(
                hproc, ph["class"], pair
            )
            if (
                not prop
                or prop["array_dim"] != 1
                or prop["element_size"] != 12
            ):
                raise RuntimeError(
                    f"PRI.PlayerName reflected field invalid: {prop}"
                )

            remote_buf = kernel32.VirtualAllocEx(
                hproc,
                None,
                max(0x1000, len(encoded)),
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            )
            if not remote_buf:
                winerr("VirtualAllocEx(r20 PlayerName)")

            remote_buf = int(
                ctypes.cast(remote_buf, ctypes.c_void_p).value
            )
            write_remote(hproc, remote_buf, encoded)

            addr = pri + int(prop["offset"])
            old_name = _r20_read_fstring(hproc, addr)
            num = len(nickname) + 1
            fstr = struct.pack("<III", remote_buf, num, num)

            prev = kernel32.SuspendThread(hthread)
            if prev == 0xFFFFFFFF:
                winerr("SuspendThread(r20 PlayerName)")
            try:
                write_remote(hproc, addr, fstr)
            finally:
                kernel32.ResumeThread(hthread)

            if read_remote(hproc, addr, 12) != fstr:
                raise RuntimeError(
                    "PRI.PlayerName write verification failed"
                )

            print(
                f"[AFDEV-PROFILE-r20] remote PC=0x{pc:08X} "
                f"PRI=0x{pri:08X} PlayerName {old_name!r} -> {nickname!r}"
            )
            return True

        if last_count != len(remotes):
            print(
                "[AFDEV-PROFILE-r20] waiting for unique remote PVE PC "
                f"(candidates={len(remotes)})"
            )
            last_count = len(remotes)

        time.sleep(0.20)

    print(
        f"[AFDEV-PROFILE-r20] remote PRI name sync timed out after {timeout:.1f}s"
    )
    return False

def apply_pve_game_settings(hproc, hthread, authority, mode_id, map_id, sub_mode_id, room_flags):
    mode_id = int(mode_id) & 0xFFFFFFFF
    map_id = int(map_id) & 0xFFFFFFFF
    sub_mode_id = int(sub_mode_id) & 0xFFFFFFFF
    room_flags = int(room_flags) & 0xFFFFFFFF

    # The v48 loader is shared by the verified AFDEV PvE families.  Earlier
    # revisions accidentally hard-coded Survival (0x2001) here even though the
    # spawner already routes Defense / Steel Forest as ModeId 0x2002 with
    # PVEGame.TGIFGame.  That made the map finish loading, then killed the
    # loader immediately before SESSION_READY.
    supported_modes = {
        0x00002001: "Survival",
        0x00002002: "Defense",
    }
    mode_name = supported_modes.get(mode_id)
    if mode_name is None:
        raise RuntimeError(
            f"unsupported AFDEV ModeId 0x{mode_id:08X}; "
            "verified modes are 0x00002001 (Survival) and 0x00002002 (Defense)"
        )
    if sub_mode_id not in (0x00001001, 0x00001002, 0x00001003):
        raise RuntimeError(f"unsupported PvE SubModeId 0x{sub_mode_id:08X}")

    difficulty = sub_mode_id - 0x00001001
    diff_name = ("Easy", "Normal", "Hard")[difficulty]
    advanced_hero = bool(room_flags & 0x00040000)
    print(
        f"[AFDEV-PVE-SETTINGS] APPLY family={mode_name} "
        f"mode=0x{mode_id:08X} map=0x{map_id:04X} "
        f"submode=0x{sub_mode_id:08X} flags=0x{room_flags:08X} "
        f"difficulty={diff_name}({difficulty}) advanced_hero={advanced_hero}"
    )

    world_info = int((authority or {}).get("world_info") or 0)
    game_info = int((authority or {}).get("game_info") or 0)
    if not _pve_ptr(world_info) or not _pve_ptr(game_info):
        raise RuntimeError("PvE settings: live WorldInfo/GameInfo missing")
    gi_hdr = _pve_object_header(hproc, game_info)
    wi_hdr = _pve_object_header(hproc, world_info)
    if not gi_hdr or not wi_hdr:
        raise RuntimeError("PvE settings: invalid WorldInfo/GameInfo UObject header")

    wanted = {}
    for name in (
        "GameSettings", "GameSpecificSettings", "ModeId", "SubModeId", "MapId", "Flags",
        "GameSettingFlags", "GameReplicationInfo", "Difficulty",
    ):
        wanted[name] = _pve_construct_fname(hproc, hthread, name)

    game_settings_prop = _pve_find_field(hproc, gi_hdr["class"], wanted["GameSettings"])
    if not game_settings_prop or game_settings_prop["array_dim"] != 1:
        raise RuntimeError("PvE settings: reflected GameSettings property not found")
    if not (0x20 <= game_settings_prop["element_size"] <= 0x80):
        raise RuntimeError(
            f"PvE settings: unexpected GameSettings ElementSize=0x{game_settings_prop['element_size']:X}"
        )
    settings_struct = _pve_struct_descriptor(
        hproc, game_settings_prop["field"], wanted["GameSpecificSettings"]
    )

    members = {}
    for name in ("ModeId", "SubModeId", "MapId", "Flags"):
        m = _pve_find_field(hproc, settings_struct, wanted[name])
        if not m or m["array_dim"] != 1 or m["element_size"] != 4:
            raise RuntimeError(f"PvE settings: reflected {name} member invalid: {m}")
        if m["offset"] + 4 > game_settings_prop["element_size"]:
            raise RuntimeError(f"PvE settings: {name} offset outside GameSettings struct")
        members[name] = m

    base = game_info + game_settings_prop["offset"]
    _pve_write_int(hproc, base + members["ModeId"]["offset"], mode_id, 4, "GameSettings.ModeId")
    _pve_write_int(hproc, base + members["SubModeId"]["offset"], sub_mode_id, 4, "GameSettings.SubModeId")
    _pve_write_int(hproc, base + members["MapId"]["offset"], map_id, 4, "GameSettings.MapId")
    _pve_write_int(hproc, base + members["Flags"]["offset"], room_flags, 4, "GameSettings.Flags")

    world_flags_prop = _pve_find_field(hproc, wi_hdr["class"], wanted["GameSettingFlags"])
    if not world_flags_prop or world_flags_prop["array_dim"] != 1 or world_flags_prop["element_size"] != 4:
        raise RuntimeError(f"PvE settings: WorldInfo.GameSettingFlags invalid: {world_flags_prop}")
    _pve_write_int(
        hproc, world_info + world_flags_prop["offset"], room_flags, 4, "WorldInfo.GameSettingFlags"
    )

    # Survival has a verified PVEGameReplicationInfo.Difficulty field and
    # depends on it for the stock GetDifficulty() path. Defense/TGIFGame is a
    # different GameInfo family: keep the authoritative GameSettings/SubModeId
    # write mandatory, but do not kill a valid Defense DS merely because its
    # live GRI does not expose the Survival-specific Difficulty property.
    difficulty_applied = False
    gri_prop = _pve_find_field(hproc, gi_hdr["class"], wanted["GameReplicationInfo"])
    if not gri_prop or gri_prop["element_size"] != 4:
        if mode_id == 0x00002001:
            raise RuntimeError(f"PvE settings: GameReplicationInfo property invalid: {gri_prop}")
        print(
            "[AFDEV-PVE-SETTINGS] Defense GRI difficulty write skipped: "
            f"GameReplicationInfo property invalid: {gri_prop}"
        )
    else:
        gri = read_u32(hproc, game_info + gri_prop["offset"])
        gri_hdr = _pve_object_header(hproc, gri)
        if not gri_hdr:
            if mode_id == 0x00002001:
                raise RuntimeError("PvE settings: live GameReplicationInfo missing")
            print(
                "[AFDEV-PVE-SETTINGS] Defense GRI difficulty write skipped: "
                "live GameReplicationInfo not ready/exposed"
            )
        else:
            diff_prop = _pve_find_field(hproc, gri_hdr["class"], wanted["Difficulty"])
            if (
                not diff_prop
                or diff_prop["array_dim"] != 1
                or diff_prop["element_size"] not in (1, 2, 4)
            ):
                if mode_id == 0x00002001:
                    raise RuntimeError(f"PvE settings: PVE GRI Difficulty invalid: {diff_prop}")
                print(
                    "[AFDEV-PVE-SETTINGS] Defense GRI difficulty write skipped: "
                    f"Difficulty property invalid: {diff_prop}"
                )
            else:
                _pve_write_int(
                    hproc,
                    gri + diff_prop["offset"],
                    difficulty,
                    diff_prop["element_size"],
                    "PVEGameReplicationInfo.Difficulty",
                )
                difficulty_applied = True

    print(
        "[AFDEV-PVE-SETTINGS] VERIFIED stock final state; "
        f"family={mode_name} difficulty_write="
        f"{'GRI+SubModeId' if difficulty_applied else 'SubModeId-only'}."
    )
    return {
        "difficulty": difficulty,
        "difficulty_name": diff_name,
        "difficulty_applied": difficulty_applied,
        "advanced_hero": advanced_hero,
        "mode_name": mode_name,
        "mode_id": mode_id,
        "map_id": map_id,
        "sub_mode_id": sub_mode_id,
        "room_flags": room_flags,
    }

def main():
    if os.name != "nt":
        raise SystemExit("Windows only.")

    ap = argparse.ArgumentParser(
        description=(
            "Assault Fire PH offline UE3 game-thread map loader"
        )
    )

    ap.add_argument(
        "--game-dir",
        default=str(DEFAULT_GAME_DIR),
    )
    ap.add_argument(
        "--map",
        default=DEFAULT_MAP,
    )
    ap.add_argument(
        "--game",
        default=DEFAULT_GAME_CLASS,
        help=(
            "GameInfo class forced into the UE3 travel URL "
            f"(default: {DEFAULT_GAME_CLASS})"
        ),
    )
    ap.add_argument(
        "--max-players",
        type=int,
        default=4,
        help=(
            "MaxPlayers URL option for the listen server "
            "(default: 4; AFDEV itself already occupies one local slot)"
        ),
    )
    ap.add_argument(
        "--mode-id", type=lambda x: int(x, 0), default=0x00002001,
        help="TGGame GameSpecificSettings.ModeId captured from A10A.",
    )
    ap.add_argument(
        "--map-id", type=lambda x: int(x, 0), default=0x002F,
        help="TGGame GameSpecificSettings.MapId captured from A10A.",
    )
    ap.add_argument(
        "--sub-mode-id", type=lambda x: int(x, 0), default=0x00001001,
        help="TGGame GameSpecificSettings.SubModeId (PvE: 0x1001 Easy, 0x1002 Normal, 0x1003 Hard).",
    )
    ap.add_argument(
        "--room-flags", type=lambda x: int(x, 0), default=0x00003008,
        help="TGGame GameSpecificSettings.Flags captured from A10A; 0x40000 is Advanced Hero modifier.",
    )

    ap.add_argument(
        "--delay",
        type=float,
        default=3.0,
        help=(
            "extra seconds to wait after GEngine/GLog become valid "
            "(default 3)"
        ),
    )
    ap.add_argument(
        "--engine-timeout",
        type=float,
        default=max(
            5.0,
            float(os.environ.get("AF_DS_ENGINE_TIMEOUT", "60")),
        ),
        help=(
            "seconds to wait for live TGame to publish GEngine/GLog "
            "(default 60; env AF_DS_ENGINE_TIMEOUT)"
        ),
    )
    ap.add_argument(
        "--resx",
        type=int,
        default=1280,
    )
    ap.add_argument(
        "--resy",
        type=int,
        default=720,
    )
    ap.add_argument(
        "--port",
        type=int,
        default=7777,
        help="Per-instance UE3 UDP listen port (default 7777).",
    )
    ap.add_argument(
        "--instance-id",
        default="default",
        help="Stable per-instance identity used to derive a unique TGame mutex.",
    )
    ap.add_argument(
        "--pid-file",
        default="",
        help="Optional file receiving the spawned TGame_AFDEV.exe PID.",
    )
    ap.add_argument(
        "--ready-file",
        default="",
        help="Optional JSON SESSION_READY marker written after the v48 authoritative world is live.",
    )
    ap.add_argument(
        "--no-uac",
        action="store_true",
        help="Do not self-elevate; fail if parent/backend is not already elevated.",
    )

    args = ap.parse_args()

    if not str(args.game_dir or "").strip():
        raise SystemExit(
            "Missing --game-dir / AF_GAME_DIR. Point it at your Assault Fire PH Binaries\\Win32 directory."
        )
    if not str(args.map or "").strip():
        raise SystemExit(
            "Missing --map. Use the room-selected PvE MapString or set AF_DS_DEFAULT_MAP explicitly."
        )

    if args.no_uac:
        if not shell32.IsUserAnAdmin():
            raise SystemExit(
                "AFDEV spawner mode requires the parent/backend to run as Administrator."
            )
    else:
        ensure_admin()

    print("[AFDEV] Running elevated: YES")

    game_dir = Path(args.game_dir).resolve()
    game_root = game_dir.parent.parent
    exe = game_dir / "TGame_AFDEV.exe"
    source_exe = game_dir / "TGame.exe"

    # Server-hosting fallback: TGame_AFDEV.exe is only a private local working
    # copy.  If it does not exist, build it from the user's own TGame.exe.
    # Never modify the original TGame.exe.
    if not exe.is_file():
        if not source_exe.is_file():
            raise SystemExit(
                f"Missing:\n  {exe}\n\n"
                f"Cannot create it because TGame.exe is also missing:\n  {source_exe}"
            )
        print(
            "[AFDEV] TGame_AFDEV.exe is missing; creating a local private copy "
            "from TGame.exe."
        )
        shutil.copy2(source_exe, exe)

    print(
        "[AFDEV] Assault Fire PH PVE MAP LOADER"
    )
    print(
        f"[AFDEV] GAME DIR : {game_dir}"
    )
    print(
        f"[AFDEV] DEV EXE  : {exe}"
    )
    print(
        "[AFDEV] BUILD    : using TGame_AFDEV.exe without whole-file hash gating; "
        "runtime patch-site signatures will still be validated"
    )

    # Confirm map exists before launching.
    map_name = Path(args.map).stem
    maps_root = (
        game_root
        / "TGame"
        / "CookedPC"
        / "Maps"
    )

    map_path = None

    if maps_root.is_dir():
        for p in maps_root.rglob("*.udk"):
            if p.stem.lower() == map_name.lower():
                map_path = p
                break

    if not map_path:
        raise SystemExit(
            f"Map not found:\n  {map_name}\n"
            f"under:\n  {maps_root}"
        )

    print(
        f"[AFDEV] MAP FOUND: {map_path}"
    )

    scan_gameinfo_config(
        game_root,
        map_name,
    )

    # Do NOT pass a map, EXEC=, or -q on the command line.
    # v0.7 will issue OPEN itself after the UE3 engine is live.
    port = int(args.port)
    if not (1024 <= port <= 65535):
        raise SystemExit(f"Invalid --port {port}; expected 1024..65535")

    cmd = [
        str(exe),
        "-log",
        "-windowed",
        f"-port={port}",
        f"ResX={args.resx}",
        f"ResY={args.resy}",
    ]

    cmdline = subprocess.list2cmdline(cmd)

    print(
        "[AFDEV-v32] TRUE DS-MODE diagnostic build: GIsClient=0 / GIsServer=1"
    )
    print(
        f"[AFDEV] CMD      : {cmdline}"
    )
    print(
        "[AFDEV] Creating TGame suspended..."
    )

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)

    pi = PROCESS_INFORMATION()
    mutable = ctypes.create_unicode_buffer(
        cmdline
    )

    if not kernel32.CreateProcessW(
        str(exe),
        mutable,
        None,
        None,
        False,
        CREATE_SUSPENDED |
        CREATE_UNICODE_ENVIRONMENT,
        None,
        str(game_dir),
        ctypes.byref(si),
        ctypes.byref(pi),
    ):
        winerr("CreateProcessW")

    try:
        print(
            f"[AFDEV] PID={pi.dwProcessId} "
            f"Thread={pi.dwThreadId} port={port} instance={args.instance_id!r}"
        )

        pid_file = Path(args.pid_file).resolve() if args.pid_file else None
        ready_file = Path(args.ready_file).resolve() if args.ready_file else None
        if pid_file:
            pid_file.parent.mkdir(parents=True, exist_ok=True)
            pid_file.write_text(str(int(pi.dwProcessId)), encoding="utf-8")
        if ready_file:
            ready_file.parent.mkdir(parents=True, exist_ok=True)
            try:
                ready_file.unlink()
            except FileNotFoundError:
                pass

        server_mutex_text = (
            "TGAME_{"
            + str(uuid.uuid5(
                uuid.NAMESPACE_URL,
                "assaultfire-afdev-v48:" + str(args.instance_id),
            )).upper()
            + "}\0"
        )
        server_mutex_bytes = server_mutex_text.encode("utf-16le")
        if len(server_mutex_bytes) != len(SINGLE_INSTANCE_MUTEX_ORIGINAL):
            raise RuntimeError("derived v48 server mutex length does not match validated image")

        try:
            verify_and_patch(
                pi.hProcess,
                LOGININFO_FAIL_VA,
                LOGININFO_EXPECT,
                LOGININFO_PATCH,
                "TCLS LoginInfo bypass",
            )

            verify_and_patch(
                pi.hProcess,
                DEVLOGIN_VA,
                DEVLOGIN_EXPECT,
                DEVLOGIN_OFFLINE_FAIL,
                "TGTenio::DevLogin offline FAIL stub",
            )

            print(
                "[AFDEV-v28] DIAGNOSTIC: preserving the engine's own "
                "GIsServer=1 write."
            )
            verify_and_patch(
                pi.hProcess,
                GIS_SERVER_FINAL_RESET_VA,
                GIS_SERVER_FINAL_RESET_EXPECT,
                GIS_SERVER_FINAL_RESET_PATCH,
                "NOP final GIsServer reset @0x013494DE",
            )

            print(
                "[AFDEV-v32] DIAGNOSTIC: forcing final GIsClient write "
                "to use EBX=0 instead of ESI=1."
            )
            verify_and_patch(
                pi.hProcess,
                GIS_CLIENT_FINAL_WRITE_VA,
                GIS_CLIENT_FINAL_WRITE_EXPECT,
                GIS_CLIENT_FINAL_WRITE_PATCH,
                "Final GIsClient write -> 0 @0x013494D8",
            )

            # v21: give only this listen-server process a different named
            # mutex, so a normal TCLS-launched TGame can run beside it.
            mutex_now = read_remote(
                pi.hProcess,
                SINGLE_INSTANCE_MUTEX_VA,
                len(SINGLE_INSTANCE_MUTEX_ORIGINAL),
            )
            print(
                f"[AFDEV] Single-instance mutex @0x{SINGLE_INSTANCE_MUTEX_VA:08X}"
            )
            if mutex_now != SINGLE_INSTANCE_MUTEX_ORIGINAL:
                raise RuntimeError(
                    "single-instance mutex bytes do not match validated image"
                )

            print(
                "[AFDEV]   original: "
                + mutex_now.decode("utf-16le").rstrip("\0")
            )

            write_remote(
                pi.hProcess,
                SINGLE_INSTANCE_MUTEX_VA,
                server_mutex_bytes,
            )

            mutex_verify = read_remote(
                pi.hProcess,
                SINGLE_INSTANCE_MUTEX_VA,
                len(server_mutex_bytes),
            )
            if mutex_verify != server_mutex_bytes:
                raise RuntimeError("v48 server mutex isolation verification failed")

            print(
                "[AFDEV]   server  : "
                + mutex_verify.decode("utf-16le").rstrip("\0")
            )
            print(
                "[AFDEV]   result  : normal TGame mutex remains free"
            )

            servermove_v4_state = None
            steel_v4_deferred = False
            steel_v4_saved_stub = b""

            live_servermove_stub = read_remote(
                pi.hProcess,
                PVE_SERVERMOVE_STUB_V48,
                5,
            )

            if live_servermove_stub == SERVERMOVE_V4_STOCK_STUB:
                raise RuntimeError(
                    "native ServerMove v4 is required, but TGame_AFDEV.exe still "
                    "contains the stripped stock ServerMove stub; rerun "
                    "START_ASSAULT_FIRE.ps1 or apply "
                    "tools/patches/tgame_servermove_v4.py to the local AFDEV copy"
                )
            if len(live_servermove_stub) != 5 or live_servermove_stub[0] != 0xE9:
                raise RuntimeError(
                    "shared ServerMove stub does not match the required "
                    "ServerMove-v4 JMP"
                )

            rel = struct.unpack("<i", live_servermove_stub[1:5])[0]
            disk_servermove_v4_target = (
                PVE_SERVERMOVE_STUB_V48 + 5 + rel
            ) & 0xFFFFFFFF
            candidate_head = read_remote(
                pi.hProcess,
                disk_servermove_v4_target,
                len(SERVERMOVE_V4_HEAD),
            )
            if candidate_head != SERVERMOVE_V4_HEAD:
                raise RuntimeError(
                    "shared ServerMove stub JMP target does not match the "
                    "verified ServerMove-v4 body"
                )

            # Steel/TGIF touches the shared movement entry during map OPEN.
            # Historical stock-stub runs load the same map successfully, so
            # defer v4 only during that startup window. The client is not
            # released until SESSION_READY, and v4 is restored immediately
            # after LoadMap stage 7.
            if int(args.mode_id) == STEEL_FORTRESS_MODE_ID_V4:
                steel_v4_saved_stub = bytes(live_servermove_stub)
                write_remote(
                    pi.hProcess,
                    PVE_SERVERMOVE_STUB_V48,
                    SERVERMOVE_V4_STOCK_STUB,
                )
                verify = read_remote(
                    pi.hProcess,
                    PVE_SERVERMOVE_STUB_V48,
                    5,
                )
                if verify != SERVERMOVE_V4_STOCK_STUB:
                    raise RuntimeError(
                        "Steel ServerMove-v4 startup defer verification failed"
                    )
                steel_v4_deferred = True
                print(
                    "[AFDEV-SERVERMOVE-v4-STEEL] DEFERRED during TGIF OPEN: "
                    "shared stub restored to stock ret 0x28"
                )

            servermove_v4_state = {
                "remote": disk_servermove_v4_target,
                "disk_patch": True,
                "targets": [
                    {"label": "shared ServerMove/PWSM disk patch v4"}
                ],
            }
            print(
                "[AFDEV-SERVERMOVE-v4] REQUIRED native disk patch verified: "
                f"0x{PVE_SERVERMOVE_STUB_V48:08X} -> "
                f"0x{disk_servermove_v4_target:08X}"
            )
            if steel_v4_deferred:
                print(
                    "[AFDEV-SERVERMOVE-v4] native v4 deferred only for Steel OPEN; "
                    "it will be restored after LoadMap stage 7."
                )
            else:
                print(
                    "[AFDEV-SERVERMOVE-v4] native v4 owns authoritative movement; "
                    "no runtime movement bridge is installed."
                )

            stage_marker_ptr, stage_instrumentation_base = (
                install_loadmap_stage_hooks(
                    pi.hProcess,
                )
            )

            v40_spawn_state = install_spawnactor_trace_v40(
                pi.hProcess,
            )

            v41_setgameinfo_state = install_setgameinfo_call_trace_v41(
                pi.hProcess,
            )

            boot = read_u32(
                pi.hProcess,
                IS_BOOT_FROM_TCLS_VA,
            )

            print(
                f"[AFDEV] IsBootFromTCLS="
                f"0x{boot:08X}"
            )

            # Keep true direct/dev state.
            if boot != 0:
                write_remote(
                    pi.hProcess,
                    IS_BOOT_FROM_TCLS_VA,
                    b"\x00\x00\x00\x00",
                )

        except Exception:
            kernel32.TerminateProcess(
                pi.hProcess,
                0xAF07,
            )
            raise

        prev = kernel32.ResumeThread(
            pi.hThread
        )

        if prev == 0xFFFFFFFF:
            winerr("ResumeThread")

        print(
            "[AFDEV] TGame resumed; waiting for UE3..."
        )

        engine_ptr, log_ptr = wait_for_engine(
            pi.hProcess,
            timeout=max(5.0, float(args.engine_timeout)),
        )

        print(
            f"[AFDEV] UE3 ready: "
            f"GEngine=0x{engine_ptr:08X}, "
            f"GLog=0x{log_ptr:08X}"
        )

        v40_gworld_state, v40_gworld_thread = (
            start_gworld_transition_watcher_v40(
                pi.hProcess,
            )
        )

        # v28: decisive verification BEFORE OPEN/PVE injection.
        v28_client = read_u32(
            pi.hProcess,
            GIS_CLIENT_VA,
        )
        v28_server = read_u32(
            pi.hProcess,
            GIS_SERVER_VA,
        )
        v28_editor = read_u32(
            pi.hProcess,
            GIS_EDITOR_VA,
        )

        print(
            f"[AFDEV-v41] MODE after UE3 init: "
            f"GIsClient={v28_client} "
            f"GIsServer={v28_server} "
            f"GIsEditor={v28_editor}"
        )

        time.sleep(1.0)
        v28_dsm_census(
            pi.hProcess,
            "AFTER UE3 INIT / BEFORE OPEN",
        )

        print()
        print(
            "[AFDEV-v45] PVE LEGACY-SV TEST: PVEGame.TGSVGame selected from actual map Kismet."
        )
        print(
            "[AFDEV-v45] Required mode: GIsClient=0 GIsServer=1 GIsEditor=0"
        )
        if not (v28_client == 0 and v28_server == 1 and v28_editor == 0):
            raise RuntimeError(
                f"true DS mode not reached: client={v28_client} "
                f"server={v28_server} editor={v28_editor}"
            )

        if args.delay > 0:
            print(
                f"[AFDEV] Waiting {args.delay:.1f}s "
                "for frontend/render initialization..."
            )
            time.sleep(args.delay)

        if not process_alive(pi.hProcess):
            raise RuntimeError(
                "TGame exited before OPEN injection."
            )

        game_class = args.game.strip()

        # v26: production target is Survival / the selected PvE map.  The previous v25
        # test accidentally inherited tutorial defaults, which caused the
        # real client to reach that listen server and receive
        # Engine.GameMessage.MaxedOutMessage.  Keep an explicit banner here.
        print(
            f"[AFDEV-v48] PVE target: map={map_name!r} "
            f"game={game_class!r}"
        )

        max_players = max(2, int(args.max_players))

        if game_class:
            travel_target = (
                f"{map_name}?game={game_class}?listen"
                f"?MaxPlayers={max_players}"
            )
        else:
            travel_target = (
                f"{map_name}?listen?MaxPlayers={max_players}"
            )

        command = f"OPEN {travel_target}"

        print(
            f"[AFDEV] Forced GameInfo travel target: "
            f"{travel_target}"
        )

        # v24: start the GamePlayers[0] observer guard BEFORE OPEN.
        # It remains inert in the frontend because the PC vtable is not the
        # verified PVE vtable.  As soon as TGSV3's local synthetic PC exists,
        # its PRI is marked bAlwaysObserver so it cannot consume GameStart.
        pve_host_guard_state, pve_host_guard_thread = (
            arm_pve_synthetic_host_observer_v24(
                pi.hProcess,
                engine_ptr,
            )
        )

        # v41: discard ALL frontend-startup trace state immediately before
        # issuing OPEN.  This is the critical difference from v39/v40.
        reset_post_open_trace_v41(
            pi.hProcess,
            stage_marker_ptr,
            v40_spawn_state,
            v41_setgameinfo_state,
        )

        result = inject_exec_on_game_thread(
            pi.hProcess,
            pi.hThread,
            engine_ptr,
            log_ptr,
            command,
        )

        print()
        print(
            "[AFDEV] Game-thread UTGameEngine::Exec completed."
        )
        print(
            f"[AFDEV] Command: {command}"
        )
        print(
            f"[AFDEV] Exec return: {result}"
        )
        print()

        highest_stage = monitor_loadmap_stage(
            pi.hProcess,
            stage_marker_ptr,
            seconds=30,
        )

        if highest_stage < 7:
            print(
                "[AFDEV] LoadMap did NOT reach the final milestone."
            )
            sample_primary_thread(
                pi.hProcess,
                pi.hThread,
                samples=16,
                interval=0.25,
            )
        else:
            print(
                "[AFDEV] LoadMap completed all seven instrumented stages."
            )

        if steel_v4_deferred:
            if highest_stage < 7:
                raise RuntimeError(
                    "Steel LoadMap did not reach stage 7; refusing to enable "
                    "ServerMove v4 into an incomplete world"
                )
            write_remote(
                pi.hProcess,
                PVE_SERVERMOVE_STUB_V48,
                steel_v4_saved_stub,
            )
            restored = read_remote(
                pi.hProcess,
                PVE_SERVERMOVE_STUB_V48,
                5,
            )
            if restored != steel_v4_saved_stub or restored[0] != 0xE9:
                raise RuntimeError(
                    "Steel ServerMove-v4 post-LoadMap restore verification failed"
                )
            rel = struct.unpack("<i", restored[1:5])[0]
            restored_target = (
                PVE_SERVERMOVE_STUB_V48 + 5 + rel
            ) & 0xFFFFFFFF
            restored_head = read_remote(
                pi.hProcess,
                restored_target,
                len(SERVERMOVE_V4_HEAD),
            )
            if (
                restored_target != disk_servermove_v4_target
                or restored_head != SERVERMOVE_V4_HEAD
            ):
                raise RuntimeError(
                    "Steel ServerMove-v4 restored target/body verification failed"
                )
            print(
                "[AFDEV-SERVERMOVE-v4-STEEL] RESTORED after LoadMap stage 7: "
                f"0x{PVE_SERVERMOVE_STUB_V48:08X} -> "
                f"0x{restored_target:08X} PASS"
            )
            steel_v4_deferred = False

        print()
        print(
            "[AFDEV] Waiting for OPEN travel request to be consumed..."
        )

        cleared = wait_for_pending_url_clear(
            pi.hProcess,
            engine_ptr,
            timeout=20.0,
        )

        if cleared:
            gworld_now = safe_read_u32(
                pi.hProcess,
                GWORLD_PTR_VA,
            )

            print(
                "[AFDEV] PendingURL cleared."
            )
            print(
                f"[AFDEV] Current GWorld = "
                f"{('0x%08X' % gworld_now) if gworld_now else 'NULL'}"
            )

            # v33 true-DS path: with GIsClient=0 there should be no local
            # frontend player/loading-movie completion dependency.  The normal
            # retail PH client is the network player.  Do not wait for or
            # manipulate ULocalPlayer/HUD/loading UI in AFDEV.
            if v28_client == 0 and v28_server == 1:
                final_gworld = wait_for_nonnull_gworld(
                    pi.hProcess,
                    timeout=15.0,
                )
                print(
                    f"[AFDEV-v41] TRUE-DS GWorld=0x{final_gworld:08X}"
                )

                report_gworld_transitions_v40(
                    v40_gworld_state,
                )

                report_setgameinfo_call_trace_v41(
                    pi.hProcess,
                    v41_setgameinfo_state,
                )

                report_spawnactor_trace_v40(
                    pi.hProcess,
                    v40_spawn_state,
                )

                authority = inspect_authority_world(
                    pi.hProcess,
                    pi.hThread,
                    final_gworld,
                )
                print(
                    "[AFDEV-v41] Skipping AFDEV local-player and loading-UI "
                    "logic because GIsClient=0."
                )
                if not servermove_v4_state:
                    raise RuntimeError(
                        "ServerMove-v4 readiness state missing after validated startup"
                    )
                print(
                    "[AFDEV-SERVERMOVE-v4] Native movement ACTIVE: "
                    f"0x{PVE_SERVERMOVE_STUB_V48:08X} -> "
                    f"0x{servermove_v4_state['remote']:08X}"
                )
                print(
                    "[AFDEV-SERVERMOVE-v4] Runtime movement bridge: REMOVED; "
                    "authoritative movement stays inside the restored native ServerMove path."
                )
                print(
                    "[AFDEV-v41] the selected PvE map server world is left running for "
                    "the normal PH client / bridge connection."
                )
                v28_dsm_census(
                    pi.hProcess,
                    "AFTER OPEN / TRUE DS",
                )
                print(
                    "[AFDEV-v41] Verify with probe_afdev_process_mode_v58.py; "
                    "expected GIsClient=0 GIsServer=1."
                )

                if int(args.mode_id) in (0x00002001, 0x00002002):
                    # r12: apply the room's real PvE settings before the client
                    # handshake is released.  This is early enough that PVE GameStart
                    # / difficulty Kismet consumes the captured SubModeId instead of
                    # AFDEV's Easy default.
                    # r16: UE3 finishes constructing GameInfo/GRI/reflection data on
                    # slightly different frames from run to run.  r12-r15 treated a
                    # transient reflection miss as fatal, which made lazy AFDEV startup
                    # intermittently exit rc=1.  Retry the idempotent stock-field apply
                    # for a bounded window; permanent room-setting errors still fail
                    # immediately.
                    pve_settings_deadline = time.time() + 12.0
                    pve_settings_attempt = 0
                    pve_settings_last_error = None
                    while True:
                        pve_settings_attempt += 1
                        try:
                            pve_settings_state = apply_pve_game_settings(
                                pi.hProcess,
                                pi.hThread,
                                authority,
                                args.mode_id,
                                args.map_id,
                                args.sub_mode_id,
                                args.room_flags,
                            )
                            if pve_settings_attempt > 1:
                                print(
                                    f"[AFDEV-PVE-SETTINGS] READY after retry attempts={pve_settings_attempt}"
                                )
                            break
                        except Exception as exc:
                            pve_settings_last_error = exc
                            msg = str(exc)
                            permanent = (
                                "unsupported AFDEV ModeId" in msg
                                or "unsupported PvE SubModeId" in msg
                            )
                            if permanent or not process_alive(pi.hProcess):
                                raise
                            if time.time() >= pve_settings_deadline:
                                raise RuntimeError(
                                    "PvE settings did not become writable within 12.0s; "
                                    f"attempts={pve_settings_attempt}; last={msg}"
                                ) from exc
                            print(
                                f"[AFDEV-PVE-SETTINGS] WAIT attempt={pve_settings_attempt} "
                                f"transient={type(exc).__name__}: {msg}"
                            )
                            time.sleep(0.25)
                            # Refresh authority because GameInfo/GRI can be replaced
                            # during the last phase of map travel.
                            try:
                                authority = inspect_authority_world(
                                    pi.hProcess, pi.hThread, final_gworld
                                )
                            except Exception as refresh_exc:
                                print(
                                    f"[AFDEV-PVE-SETTINGS] authority refresh pending: {refresh_exc}"
                                )
                elif int(args.mode_id) == BIO_MODE_ID_V49:
                    # Mutation owns its game settings in TGBioGame. Do not
                    # reinterpret its room flags/submode as PvE difficulty.
                    pve_settings_state = {
                        "difficulty": 0,
                        "difficulty_name": "Native",
                        "difficulty_applied": False,
                        "mode_name": "Mutation",
                        "advanced_hero": False,
                    }
                    print(
                        "[AFDEV-MUTATION] Native TGBioGame.TGBioMatch startup; "
                        "skipped PvE-specific GameSettings writes."
                    )
                else:
                    raise RuntimeError(
                        f"unsupported AFDEV ModeId 0x{int(args.mode_id) & 0xFFFFFFFF:08X}"
                    )

                # r8: A11A advertises a zero DSKey.  Do not publish
                # SESSION_READY until this exact AFDEV instance's live encrypted
                # UDP socket has been rekeyed with the validated v72 routine.
                zero_dskey_state, zero_dskey_thread = arm_zero_dskey_guard_v72(
                    pi.hProcess,
                    timeout=15.0,
                )
                print(
                    f"[AFDEV-v48.2] ZERO-DSKEY READY socket=0x{zero_dskey_state['socket']:08X} "
                    f"rekeys={zero_dskey_state['rekey_count']} verified={zero_dskey_state['verified']}"
                )

                if ready_file:
                    ready_payload = {
                        "ready": True,
                        "pid": int(pi.dwProcessId),
                        "port": port,
                        "instance_id": str(args.instance_id),
                        "map": map_name,
                        "game": game_class,
                        "max_players": max_players,
                        "mode_id": int(args.mode_id),
                        "map_id": int(args.map_id),
                        "sub_mode_id": int(args.sub_mode_id),
                        "room_flags": int(args.room_flags),
                        "pve_difficulty": int(pve_settings_state["difficulty"]),
                        "pve_difficulty_name": str(pve_settings_state["difficulty_name"]),
                        "pve_difficulty_applied": bool(
                            pve_settings_state.get("difficulty_applied")
                        ),
                        "mode_name": str(pve_settings_state.get("mode_name") or ""),
                        "advanced_hero": bool(pve_settings_state["advanced_hero"]),
                        "gworld": int(final_gworld or 0),
                        "loadmap_stage": int(highest_stage),
                        "native_movement": bool(servermove_v4_state),
                        "servermove_v4": bool(servermove_v4_state),
                        "zero_dskey": bool(zero_dskey_state.get("verified")),
                        "zero_dskey_socket": int(zero_dskey_state.get("socket") or 0),
                        "zero_dskey_rekeys": int(zero_dskey_state.get("rekey_count") or 0),
                        "timestamp": time.time(),
                    }
                    tmp_ready = ready_file.with_suffix(ready_file.suffix + ".tmp")
                    tmp_ready.write_text(
                        json.dumps(ready_payload, indent=2, sort_keys=True),
                        encoding="utf-8",
                    )
                    os.replace(tmp_ready, ready_file)
                    print(
                        f"[AFDEV-v48-SPAWNER] SESSION_READY file={ready_file} "
                        f"pid={pi.dwProcessId} udp={port} servermove_v4={bool(servermove_v4_state)} "
                        f"difficulty={pve_settings_state['difficulty_name']} "
                        f"submode=0x{int(args.sub_mode_id):08x} flags=0x{int(args.room_flags):08x} "
                        f"zero_dskey={bool(zero_dskey_state.get('verified'))}"
                    )

                try:
                    r20_sync_remote_pri_name(
                        pi.hProcess,
                        pi.hThread,
                        os.environ.get("AF_PLAYER_NICKNAME", ""),
                        timeout=45.0,
                    )
                except Exception as exc:
                    print(
                        f"[AFDEV-PROFILE-r20] nonfatal PRI sync error: {exc}"
                    )

                print(
                    "[AFDEV-v41] Press Ctrl+C in this loader only when you "
                    "want to stop monitoring; AFDEV is not modified on disk."
                )
                while process_alive(pi.hProcess):
                    time.sleep(1.0)
                return

            players_before = inspect_local_players(
                pi.hProcess,
                engine_ptr,
                label=" BEFORE UI hide",
            )

            print(
                "[AFDEV] Natural loading-completion mode: "
                "NOT forcing UE3 fullscreen-movie stop."
            )
            print(
                "[AFDEV] Natural loading-completion mode: "
                "NOT forcing Assault Fire LoadingMovie hide."
            )
            print(
                "[AFDEV] Leaving the stock movie/streaming completion path "
                "intact so the PlayerController load-complete callback can fire."
            )

            # IMPORTANT:
            # Earlier loader versions manually called:
            #   stop_loading_movie_on_game_thread(...)
            #   hide_af_loading_ui_on_game_thread(...)
            #
            # Current live UnrealScript analysis shows the stock completion path
            # enters an externally-triggered function containing "UT_loadmovie",
            # which sets bInitialProcessingComplete=TRUE and calls the
            # "Load Complete Player:" handler.  Forcing the movie/UI closed here
            # can bypass that native/delegate callback.  Do not short-circuit it.
            time.sleep(2.0)

            players_after = inspect_local_players(
                pi.hProcess,
                engine_ptr,
                label=" AFTER UI hide",
            )

            lp0, pc0 = wait_for_player_controller(
                pi.hProcess,
                engine_ptr,
                timeout=10.0,
            )

            print(
                f"[AFDEV] Controller wait result: "
                f"ULocalPlayer=0x{lp0:08X} "
                f"PlayerController=0x{pc0:08X}"
            )

            final_gworld = wait_for_nonnull_gworld(
                pi.hProcess,
                timeout=10.0,
            )

            print(
                f"[AFDEV] Final GWorld after transition wait: "
                f"0x{final_gworld:08X}"
            )

            authority = inspect_authority_world(
                pi.hProcess,
                pi.hThread,
                final_gworld,
            )

            # v23: TGTeamMatch_Tutorial still returns
            # Engine.GameMessage.MaxedOutMessage even when the OPEN URL
            # contains ?MaxPlayers=4.  Test the live GameInfo object directly
            # through UE3's native SET/GETALL console support after LoadMap,
            # when WorldInfo.Game definitely exists.
            print()
            print("[AFDEV] ===== RUNTIME GAMEINFO CAPACITY OVERRIDE =====")

            capacity_commands = [
                "GETALL GameInfo MaxPlayers",
                f"SET GameInfo MaxPlayers {max_players}",
                f"SET GameInfo MaxSpectators {max_players}",
                "GETALL GameInfo MaxPlayers",
                "GETALL GameInfo MaxSpectators",
            ]

            for cap_cmd in capacity_commands:
                try:
                    cap_result = inject_exec_on_game_thread(
                        pi.hProcess,
                        pi.hThread,
                        engine_ptr,
                        log_ptr,
                        cap_cmd,
                    )
                    print(
                        f"[AFDEV] CAPACITY CMD result=0x{cap_result:08X}: "
                        f"{cap_cmd}"
                    )
                except Exception as e:
                    print(
                        f"[AFDEV] CAPACITY CMD failed: {cap_cmd}: {e}"
                    )

            print("[AFDEV] ===== END RUNTIME CAPACITY OVERRIDE =====")
            print()

            scan_world_for_tggame_and_tgpawn(
                pi.hProcess,
                final_gworld,
            )

            scan_exact_tgplayercontroller(
                pi.hProcess,
                lp0,
                pc0,
                final_gworld,
            )

            global_game_hits, global_pc_hits, global_pawn_hits = (
                scan_tutorial_runtime_globally(
                    pi.hProcess,
                )
            )

            print(
                "[AFDEV] v23 is intentionally NOT running the old "
                "console-command pawn probes. This run is focused on "
                "whether ?listen creates a real authoritative GameInfo."
            )

            print(
                "[AFDEV] NOTE: v0.13's borrowed +0x66C/+0x670/+0x688 "
                "controller offsets were invalid for Assault Fire and "
                "are intentionally NOT used by v0.14."
            )

            print(
                "[AFDEV] Both loading-screen paths have now been "
                "explicitly stopped/hidden."
            )
        else:
            print(
                "[AFDEV] PendingURL did not clear within 20 seconds; "
                "not forcing StopMovie yet."
            )

        monitor_travel_state(
            pi.hProcess,
            engine_ptr,
            game_root,
            seconds=8,
        )

        print()
        print(
            "[AFDEV-v24] Synthetic-host observer guard status: "
            f"first_patch={pve_host_guard_state['first_patch']} "
            f"patch_count={pve_host_guard_state['patch_count']} "
            f"last_pc=0x{pve_host_guard_state['last_pc']:08X} "
            f"last_pri=0x{pve_host_guard_state['last_pri']:08X}"
        )
        if not pve_host_guard_state["first_patch"]:
            print(
                "[AFDEV-v24] WARNING: the guard never saw the verified "
                "PVE GamePlayers[0] controller. Do NOT interpret this run "
                "as a test of the host-observer hypothesis."
            )

        print(
            "Send the console output and a screenshot of what is visible "
            "after the StopMovie call."
        )

        kernel32.WaitForSingleObject(
            pi.hProcess,
            INFINITE,
        )

    finally:
        if pi.hThread:
            kernel32.CloseHandle(
                pi.hThread
            )

        if pi.hProcess:
            kernel32.CloseHandle(
                pi.hProcess
            )


if __name__ == "__main__":
    main()
