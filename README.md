# Assault Fire Emulator

[![Python](https://img.shields.io/badge/Python-3.12+-blue)](https://www.python.org/)
[![Engine](https://img.shields.io/badge/Engine-Unreal%20Engine%203-lightgrey)](#)
[![Status](https://img.shields.io/badge/status-preservation%20research-orange)](docs/STATUS.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An unofficial, community-driven preservation and server-emulation project for **Assault Fire PH**.

> This project is not affiliated with, endorsed by, or sponsored by Tencent, Level Up! Games, or any original rights holder.

## Current The Altar state — video preview

> **The Altar currently loads and the player can spawn, but the normal PvE round/enemy lifecycle does not start correctly.**

<a href="https://github.com/armangido/af-emulator/issues/1">
  

  https://github.com/user-attachments/assets/da20eced-5792-47d8-a360-1262e2fe8e8b


</a>

**What this sample demonstrates:** room creation → The Altar loading → map entry/player spawn works, while the post-load PvE round progression is still incomplete.

➡️ **[Open the full non-working The Altar sample / investigation — Issue #1](https://github.com/armangido/af-emulator/issues/1)**

## Vital launch information

Getting the emulator listeners online is only half of the launch path. The stock PH launcher still has to hand the authenticated session from **TCLS → TGame.exe** correctly.

The validated launch path includes:

- matching `server\PRIVATE.PEM` + `TCLS\config\APClient.dat`;
- localhost hosts redirects;
- normal `client.exe / TCLS` login;
- TCLS `GetLoginInfo` + selected-server lookup;
- TCLS creation of `TCLS_SHAREDMEMEMORY<child PID>`;
- optional **runtime-only TCLS suspended-launch compatibility patch** at `TCLS.dll+0x584E0` after verifying `8B 55 18 52`;
- required TGame datetime runtime compatibility patch for the validated PH build;
- successful `TGame.exe` ROLE/ZONE connections.

The known TCLS suspended-launch patch temporarily changes:

```text
TCLS.dll + 0x584E0
original: 8B 55 18 52
runtime : 6A 04 90 90   ; push CREATE_SUSPENDED, nop, nop
```

It must be restored immediately after the child TGame is created. **Do not patch a different build unless the original signature matches. Do not distribute a modified TCLS.dll.**

The repository now includes a debugger-free helper that automates this safely:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py
```

Run it after `client.exe / TCLS` is logged in and sitting at the normal **START** screen. It verifies the TCLS signature, temporarily enables `CREATE_SUSPENDED`, detects the new child `TGame.exe`, restores TCLS immediately, applies the existing TGame datetime patch while the child is suspended, and then resumes TGame.

**When using this combined helper, do not also run `patch_tgame_datetime.py` separately.**

➡️ **[Read the full TCLS → TGame launch and compatibility guide](docs/LAUNCH_REQUIREMENTS.md)**

### Legacy kernel anti-cheat / security-driver compatibility

The original PH client includes an old kernel-level security / anti-cheat component. On modern Windows this legacy component can cause startup failures, crashes, driver initialization errors, or other instability **even when the emulator itself is working correctly**.

For preservation testing, this may require using a local test environment where the obsolete security-driver path is not active or is otherwise avoided. The project does **not** provide instructions or tooling for defeating active anti-cheat/security systems.

Any system, driver, boot-policy, virtualization, or security configuration changes a user independently chooses to make are performed at their own risk. The maintainers/contributors are not responsible for damage, instability, data loss, security problems, driver failures, or other consequences caused by third-party tools, original game drivers, or user-performed system changes.

See **[Issue #4](https://github.com/armangido/af-emulator/issues/4)**, **[Vital Setup Notes](docs/VITAL_SETUP_NOTES.md)**, and **[DISCLAIMER.md](DISCLAIMER.md)**.

## Easy setup

For a first local test:

```powershell
git clone https://github.com/armangido/af-emulator.git
cd af-emulator

py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Generate the matching local RSA key pair and install the public key into your Assault Fire `TCLS\config` folder:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\YourAssaultFireFolder\TCLS\config"
```

Then, from **Administrator PowerShell**, redirect the retired PH services to localhost:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup\setup_assaultfire_hosts.ps1
```

Start the stable server:

```powershell
.\.venv\Scripts\python.exe .\server\assaultfire_server_v94.py
```

The RSA helper creates `server\PRIVATE.PEM` automatically. **Never upload or commit that file.**

For the validated PH build, choose **one** client compatibility path:

- **Normal TCLS launch:** run `tools\patches\patch_tgame_datetime.py` before clicking START.
- **Suspended TCLS handoff:** log in to the launcher, stop at START, then run `tools\patches\patch_tcls_suspended_launch.py`. The combined helper includes the datetime patch automatically.

Do not run both patchers for the same launch. See [Issue #3](https://github.com/armangido/af-emulator/issues/3) and [Vital Launch Requirements](docs/LAUNCH_REQUIREMENTS.md).

➡️ **[Read the very easy step-by-step tutorial](docs/GETTING_STARTED.md)**

## Start here

New to the project?

- **[Friendly setup tutorial](docs/GETTING_STARTED.md)** — clone, install, configure the local key, run v94, test the client, and prepare a useful bug report.
- **[Working / broken / planned status](docs/STATUS.md)** — shows what currently works, what is only partial, what is broken/unavailable, and what contributors can help implement.
- **[Project milestones](docs/MILESTONES.md)** — roadmap from the stable v94 baseline through The Altar, dedicated-server lifecycle, and a preservation-quality release.
- **[Contributing guide](CONTRIBUTING.md)** — rules for safe protocol research, pull requests, and sanitized evidence.
- **[Stable PvE bridge + server spawner](docs/PVE_BRIDGE_AND_SPAWNER.md)** — known-good v5 UDP bridge and v26 AFDEV listen-server launcher used for The Altar research.
- **[Local hosts redirect](config/hosts.txt)** — ready-to-copy mappings for the retired PH service hostnames → `127.0.0.1`.
- **[FAQ](docs/FAQ.md)** — common crashes, RSA/APClient questions, ports, The Altar status, and troubleshooting.
- **[Launcher / AP / TGame error reference](docs/LAUNCHER_ERRORS.md)** — known AP/AUTH errors, TCLS launcher logs, TGame popups, security warning codes, crash codes, and what each one usually means.
- **[Architecture + port map](docs/ARCHITECTURE.md)** — quick diagram of how TCLS, TGame, the emulator, bridge, and AFDEV fit together.
- **[Registration website + SQLite accounts](docs/REGISTRATION_WEBSITE.md)** — local account registration, UIN allocation, password hashing, and the planned v94 AUTH integration boundary.
- **[Vital launch requirements](docs/LAUNCH_REQUIREMENTS.md)** — TCLS → TGame handoff, shared memory, validated TCLS runtime patch, TGame compatibility patch, and failure diagnosis.
- **[Vital setup notes](docs/VITAL_SETUP_NOTES.md)** — key, hosts, datetime, legacy security-driver compatibility, and isolation warnings.
- **[Disclaimer](DISCLAIMER.md)** — project scope, legacy driver compatibility, and responsibility for user-performed system changes.

## Current public baseline

The current public baseline is **v94**.

This is intentionally the last known stable branch before the experimental first-login / new-account creation work. Those experimental account-creation changes are **not included in this repository at this time**.

The stable baseline currently contains the project's working/reproducible implementation for:

- VERSION service
- AUTH handshake
- DIR/server discovery
- existing local profile / zone login path
- player information and inventory/property handling used by the stable branch
- shop/backend work from the stable branch
- lobby/room foundation
- friends/chat foundation
- clan foundation and persisted ClanID work

The server source is currently kept as a versioned baseline:

```text
server/assaultfire_server_v94.py
```

Later experimental branches are being kept out of `main` until their behavior is verified.

## Goal

The goal is to document and reimplement the network/backend behavior required to run the original Assault Fire PH client in an isolated/local environment for preservation, research, and interoperability.

This repository contains **original project code and documentation only**. It must not contain copyrighted game binaries, proprietary game assets, leaked source code, private keys, credentials, or personal player data.

## Running the stable baseline

Python 3.12 is recommended.

Install the Python dependency:

```bash
pip install -r requirements.txt
```

The server expects a locally supplied RSA private key. The key itself must **never** be committed.

By default the stable server looks for:

```text
server/PRIVATE.PEM
```

You can instead set:

```text
AF_PRIVATE_KEY=<path to your local PRIVATE.PEM>
AF_LOG_PATH=<optional server log path>
AF_X32DBG_LOG=<optional x32dbg crypto log path>
```

Then run:

```bash
python server/assaultfire_server_v94.py
```

The current baseline is designed around local/isolated preservation testing.

## Repository policy

### Allowed

- Clean-room server/emulator code written by contributors
- Protocol descriptions derived from observation/research
- Packet parsers/encoders
- Debugging and diagnostic tools written for this project
- Documentation
- Sanitized test fixtures containing no proprietary content or secrets

### Do not commit

- `TGame.exe`, `TCLS.dll`, or other original game binaries
- Original `.upk`, `.udk`, audio, textures, maps, or other game assets
- Private keys or certificates
- Account credentials
- Raw player-state files containing personal information
- Full memory dumps
- Decompiled/disassembled proprietary code copied verbatim
- Files you do not have permission to redistribute

Users must obtain any required original game client files independently and lawfully.

## Project structure

```text
server/      Stable emulator/server implementation
tools/       Original debugging, packet, and research utilities
docs/        Protocol and architecture documentation
tests/       Reproducible tests and sanitized fixtures
.github/     Contributor and issue templates
```

For now, only verified/stable material is being promoted into the public baseline.

## Contributing

Contributions are welcome. Good contributions include protocol documentation, packet parsing, reproducible bug reports, tests, and fixes against the stable baseline.

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting code or research.

When reporting protocol behavior, include reproducible evidence where possible:

- client version
- packet direction
- command/opcode
- packet length
- sanitized hex or decoded fields
- expected behavior
- observed behavior
- relevant logs with secrets/private data removed

Please do not submit speculative account-creation/new-account changes to `main` until that flow is reproducibly verified.

## Preservation and interoperability

This project is intended for preservation, interoperability, education, and research around discontinued software. It does not provide the original game client or copyrighted game content.

## License

The original code and documentation in this repository are licensed under the [MIT License](LICENSE).

This license applies only to material created for the `af-emulator` project. It does **not** grant rights to Assault Fire, the original game client, executables, DLLs, maps, packages, artwork, audio, trademarks, or any other third-party material. Those remain the property of their respective rights holders.
