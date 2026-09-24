# Assault Fire Emulator

[![Python](https://img.shields.io/badge/Python-3.12+-blue)](https://www.python.org/)
[![Engine](https://img.shields.io/badge/Engine-Unreal%20Engine%203-lightgrey)](#)
[![Status](https://img.shields.io/badge/status-preservation%20research-orange)](docs/STATUS.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An unofficial, community-driven **Assault Fire PH** preservation and server-emulation project.

The goal is simple: make the retired PH client usable in a local/isolated environment for preservation, interoperability, research, and nostalgia.

> This project is not affiliated with, endorsed by, or sponsored by Tencent, Level Up! Games, or any original rights holder.

## What works today

The current public baseline is **v143b**.

- VERSION / AUTH / DIR / ROLE / ZONE local backend flow
- existing/local profile login path
- dynamic room and dedicated-server lifecycle used by The Altar
- lazy AFDEV startup instead of spawning a server when a lobby is merely created
- v48 AFDEV loader + v9 multi-peer UDP bridge
- zero-DSKey readiness gate before the UE3 session is released
- The Altar / Maya difficulty selection:
  - Easy — `0x00001001`
  - Normal — `0x00001002`
  - Hard — `0x00001003`

The first-time nickname/new-account flow and several social/progression features are still separate work. See **[Project Status](docs/STATUS.md)** for the detailed matrix.

## Important: legacy kernel anti-cheat

Before troubleshooting the emulator, make sure the original PH client's **legacy kernel anti-cheat / security driver is not blocking the client from starting correctly**.

This component was built for an older Windows environment and can cause crashes, driver initialization failures, or startup problems on modern systems before the emulator is ever contacted.

This project does **not** provide bypass, disabling, kernel-modification, or security-circumvention instructions.

**Diagnostic hint:** if the client fails before you see normal VERSION / AUTH traffic in the emulator logs, or Windows/client messages point to a driver/security initialization problem, you are still dealing with the **client/OS compatibility layer**, not a server-protocol bug. Resolve that environment compatibility independently in an isolated preservation setup before debugging the emulator.

See **[Vital Setup Notes](docs/VITAL_SETUP_NOTES.md)** and **[Issue #4](https://github.com/armangido/af-emulator/issues/4)** for the known symptoms and project scope.

## Quick start

### 1. Clone and install

```powershell
git clone https://github.com/armangido/af-emulator.git
cd af-emulator

py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 2. Generate the local RSA key

Point the helper at your own Assault Fire PH `TCLS\config` directory:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\YourAssaultFireFolder\TCLS\config"
```

This creates the local server key and matching `APClient.dat`.

**Never commit or upload `server\PRIVATE.PEM`.**

### 3. Redirect the retired PH services to localhost

Run from **Administrator PowerShell**:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup\setup_assaultfire_hosts.ps1
```

### 4. Start the emulator

```powershell
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

For **The Altar / PvE**, also point the DS spawner at your local AFDEV game directory before starting the server:

```powershell
$env:AF_GAME_DIR = "D:\YourAssaultFireFolder\Binaries\Win32"
$env:AF_DS_SPAWNER_ENABLED = "1"
```

The repository does **not** provide `TGame_AFDEV.exe`, maps, packages, or other original game files.

### 5. Launch the PH client

For the validated PH build, use **one** compatibility path:

**Normal TCLS launch**

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tgame_datetime.py
```

Then launch normally through `client.exe / TCLS`.

**Suspended TCLS handoff**

Log in through TCLS and stop at the normal **START** screen, then run:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py
```

The suspended-launch helper already applies the datetime compatibility patch, so **do not run both helpers for the same launch**.

For the full walkthrough, use **[Getting Started](docs/GETTING_STARTED.md)**.

## The Altar

The stable Altar path is integrated on `main`.

```text
Create room
   ↓
reserve DS capacity only
   ↓
Start Match
   ↓
arm per-room bridge + return DS assignment
   ↓
first valid client DS UDP packet
   ↓
lazy-start v48 AFDEV
   ↓
verify world / movement / zero DS key
   ↓
SESSION_READY
   ↓
release latched packet through v9 bridge
   ↓
UE3 gameplay session
```

Room settings sent through A11E are applied before the lazy AFDEV spawn, so the selected Easy / Normal / Hard difficulty reaches the server runtime.

A PH-client HUD label can still display the wrong text in some cases; that is tracked separately from the authoritative server/AFDEV difficulty state.

See **[The Altar Runtime](docs/ALTAR_RUNTIME.md)** for implementation details.

## If something fails

Start with the symptom instead of changing random files:

- **`AP client initialization failed.`** → run `tools/patches/diagnose_tcls_apclient.py`. If it detects the verified original `13EAD403...` TCLS build, use `tools/patches/patch_tcls_apclient_raw_pem.py`; see [Launcher / AP / TGame errors](docs/LAUNCHER_ERRORS.md) and [Issue #7](https://github.com/armangido/af-emulator/issues/7).
- **TCLS launches but TGame does not hand off correctly** → [Vital Launch Requirements](docs/LAUNCH_REQUIREMENTS.md)
- **TGame crashes around datetime/startup** → use one of the compatibility helpers above
- **legacy security-driver / modern Windows startup problems** → [Vital Setup Notes](docs/VITAL_SETUP_NOTES.md) and [Issue #4](https://github.com/armangido/af-emulator/issues/4)
- **not sure whether a feature is implemented** → [Project Status](docs/STATUS.md)

When reporting a problem, include the exact error text and the last server/client log lines before the failure.

## Documentation

You do not need to read everything before trying the project.

| Guide | Use it for |
| --- | --- |
| [Getting Started](docs/GETTING_STARTED.md) | first setup and local launch |
| [Project Status](docs/STATUS.md) | what works, what is partial, what is still planned |
| [The Altar Runtime](docs/ALTAR_RUNTIME.md) | current v143b / v48 / v9 PvE path |
| [Launch Requirements](docs/LAUNCH_REQUIREMENTS.md) | TCLS → TGame handoff and compatibility |
| [Launcher Errors](docs/LAUNCHER_ERRORS.md) | known launcher/AP/TGame messages |
| [Architecture](docs/ARCHITECTURE.md) | ports, components, and data flow |
| [FAQ](docs/FAQ.md) | common questions |
| [Contributing](CONTRIBUTING.md) | submitting fixes, tests, and research |

## Repository layout

```text
server/      emulator/backend and DS lifecycle
tools/       setup, compatibility, bridge, loader, and research utilities
docs/        setup, protocol, architecture, and troubleshooting
tests/       reproducible regression tests
.github/     issue and contribution templates
```

Legacy files such as the older v94 server, v26 loader, and v5 bridge are kept for rollback/history. They are **not** the recommended Altar path.

## Project scope

This repository contains original emulator code, documentation, and research tooling.

Please do **not** commit:

- original game executables or DLLs
- `.upk`, `.udk`, maps, audio, textures, or other proprietary assets
- private keys, credentials, or account data
- raw memory dumps containing proprietary or personal data
- files you do not have permission to redistribute

Users must obtain any required original game files independently and lawfully.

The project does not provide tooling or instructions for defeating active anti-cheat or operating-system security protections.

## Contributing

Contributions are welcome, especially:

- reproducible protocol findings
- packet parsers/encoders
- client-launch compatibility fixes
- dedicated-server improvements
- regression tests
- documentation corrections

Please read **[CONTRIBUTING.md](CONTRIBUTING.md)** before opening a PR.

For protocol reports, include the client build, opcode/direction, sanitized packet or decoded fields, expected behavior, observed behavior, and relevant logs.

## License

Original code and documentation in this repository are licensed under the [MIT License](LICENSE).

The license does **not** grant rights to Assault Fire, the original client, executables, DLLs, maps, packages, artwork, audio, trademarks, or other third-party material.
