# Vital Launch Requirements and TCLS → TGame Handoff

This page documents the **client-side compatibility and launch steps** that are easy to miss when testing the Assault Fire PH emulator.

The emulator can have VERSION/AUTH/DIR/ROLE working correctly and the game can still fail to launch because the legacy PH launcher and `TGame.exe` have separate compatibility requirements.

> These notes are for the validated **Assault Fire PH v1.0.0.24** preservation setup only. They are build-specific. Do not blindly apply RVAs or patch bytes to another client build.

## What a successful launch actually looks like

The expected local path is:

```text
client.exe / TCLS
  |
  +-- VERSION :9060
  |
  +-- AUTH :8000
  |
  +-- DIR :9010
  |
  +-- initial ROLE/TACC :65005
  |
  +-- TCLS obtains LoginInfo + selected game-server information
  |
  +-- TCLS creates TGame.exe -q <uin>
  |
  +-- TCLS writes TCLS_SHAREDMEMEMORY<decimal child PID>
  |
  +-- TGame.exe reads the TCLS handoff
  |
  +-- TGame connects to ROLE :65005
  |
  +-- TGame connects to ZONE :65006
```

For the current local profile used by the public research baseline, the observed launch command is equivalent to:

```text
TGame.exe -q 10001
```

The UIN is not something contributors should hard-code into unrelated client builds; it comes from the local login/profile flow.

## Before blaming the backend

Confirm these in order:

| Stage | Good signal |
|---|---|
| Hosts | retired PH hostnames resolve to `127.0.0.1` |
| VERSION | emulator receives the 65-byte request |
| AUTH | AP login completes and the client sends the final acknowledgement |
| DIR | the local server entry is accepted |
| ROLE/TACC | the launcher reaches the local ROLE service |
| launch transition | a later VERSION request contains the logged-in UIN |
| TCLS launch | child `TGame.exe` appears |
| shared memory | `TCLS_SHAREDMEMEMORY<child PID>` is created/written |
| game transport | a new ROLE connection is owned by `TGame.exe` |
| ZONE | `TGame.exe` reaches the local zone endpoint |

A failure after AUTH is therefore not automatically an AUTH failure.

## Verified TCLS launch internals

The following offsets were verified on the known PH `TCLS.dll`:

```text
TCLS.dll + 0x5C150   CLaunchUI::GetLoginInfo
TCLS.dll + 0x5C230   selected game-server information request
TCLS.dll + 0x5C236   zero-result check; can log "Get Game Server Info fail!"
TCLS.dll + 0x5E7B3   CreateFileMappingW on the shared-memory path
TCLS.dll + 0x584F4   CreateProcessW call area
```

The validated TCLS SHA-256 from the research notes is:

```text
3ff351e0adb594d7544e28db2e966a6d6eb548e9df70daaf4daf58f2ee438d56
```

Treat the hash as a compatibility identifier, not as permission to redistribute the DLL. **Do not commit TCLS.dll to this repository.**

## TCLS suspended-launch compatibility patch

One known-good clean-launch workflow temporarily makes TCLS create `TGame.exe` in a suspended state. This gives a local helper enough time to let TCLS finish the shared-memory handoff and apply required TGame compatibility work before TGame starts normal initialization.

Patch site:

```text
TCLS.dll + 0x000584E0
```

Expected original bytes:

```text
8B 55 18 52
```

Decoded:

```asm
mov edx, [ebp+18h]     ; dwCreationFlags
push edx
```

Temporary runtime bytes:

```text
6A 04 90 90
```

Decoded:

```asm
push 4                 ; CREATE_SUSPENDED
nop
nop
```

### Important rules

1. **Verify the four original bytes first.** If they are not exactly `8B 55 18 52`, stop.
2. Apply this **in memory only**. Do not publish or distribute a modified `TCLS.dll`.
3. Apply it only when the launcher is already at the normal START stage.
4. Let TCLS create the child and finish its shared-memory handoff.
5. Restore the original TCLS bytes immediately after the child `TGame.exe` is observed.
6. Apply any required TGame compatibility patch while the child is still suspended.
7. Resume TGame.
8. Do not leave a debugger attached to TGame during normal protected initialization.

If your existing local setup already launches TGame reliably, **do not add this patch just because it is documented here**. It is a compatibility/diagnostic method, not a protocol requirement.

### Automated helper — recommended when this path is needed

The repository includes:

```text
tools/patches/patch_tcls_suspended_launch.py
```

Run the normal launcher first, log in, and stop at the **START** screen. Close/detach x32dbg, then run from the repository root:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py
```

When it prints:

```text
TCLS ARMED
Click START in the Assault Fire launcher now.
```

click START.

The helper performs the complete debugger-free sequence:

```text
verify TCLS+0x584E0
        |
        v
8B 55 18 52 -> 6A 04 90 90
        |
        v
TCLS creates a NEW TGame.exe suspended
        |
        v
restore TCLS immediately
        |
        v
find suspended TGame image
        |
        v
apply patch_tgame_datetime.py
        |
        v
resume TGame primary thread
```

It snapshots existing TGame PIDs before arming TCLS, so an older TGame process is not mistaken for the newly created child. It also prefers a new `TGame.exe` whose parent PID is the active `client.exe`.

The TCLS restore runs from a `finally` path. On timeout, Ctrl+C, or an ordinary Python error, the helper attempts to put the four original TCLS bytes back before exiting.

If the TGame datetime signature does not match, the helper **does not resume the child**. It leaves TGame suspended so a mismatched build does not continue through a known compatibility failure path.

For manual inspection after both patches:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py --leave-suspended
```

When using this combined helper, **do not run `patch_tgame_datetime.py` separately for the same launch**.

## Why the shared-memory handoff matters

TCLS and TGame do not simply communicate by command-line arguments.

The verified launcher creates a mapping named:

```text
TCLS_SHAREDMEMEMORY<decimal child PID>
```

The spelling really contains `SHAREDMEMEMORY`.

Observed mapping size:

```text
0x80000
```

TCLS writes login/game-server handoff information into this mapping after creating the child. Starting `TGame.exe` manually can therefore produce a different state from launching through TCLS.

This is why a contributor should preserve the normal:

```text
client.exe -> TCLS -> TGame.exe
```

launch path whenever possible.

## Required TGame datetime compatibility patch

The known PH `TGame.exe` can crash in a legacy datetime conversion path.

The repository includes the standalone patcher:

```text
tools/patches/patch_tgame_datetime.py
```

The combined `patch_tcls_suspended_launch.py` helper imports and applies this same verified datetime patch while TGame is suspended, so users of the combined path do not need to run it separately.

Validated patch point:

```text
TGame.exe + 0x010B9510
VA 0x014B9510 when image base = 0x00400000
```

Expected bytes:

```text
83 EC 24 53 8B 5C 24 2C
```

The helper verifies the signature and patches process memory only.

See [Issue #3](https://github.com/armangido/af-emulator/issues/3) for the current implementation and limitations.

## RSA / APClient.dat requirement

The local server private key and the client's public key must be a matching RSA-1024 pair:

```text
server\PRIVATE.PEM  <---- matching pair ---->  TCLS\config\APClient.dat
```

Use:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\AssaultFirePH\TCLS\config"
```

The known local PH setup loads `APClient.dat` as a raw PEM public key after a verified TCLS compatibility patch.

Verified original/pre-patch TCLS SHA-256:

```text
13ead403452e0f25cf00658369bf4bf5ff34ed1b16027f7833fb27d398386cd1
```

Verified working patched SHA-256:

```text
3ff351e0adb594d7544e28db2e966a6d6eb548e9df70daaf4daf58f2ee438d56
```

Recovered edit sites:

```text
TCLS.dll + 0x000E07EA
FF 52 28  ->  90 90 90

TCLS.dll + 0x000E07F6
B4        ->  B8
```

Use the repository helper rather than editing bytes manually:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_apclient_raw_pem.py "D:\AssaultFirePH\TCLS\Tenio\TCLS.dll" --apply
```

The helper accepts only the verified source hash, checks the original signatures, creates a backup, and requires the final hash to match the verified working DLL exactly.

This is separate from the `+0x584E0` CREATE_SUSPENDED handoff patch.

## Windows / TenProtect compatibility note

Earlier clean-launch research also reproduced a legacy Windows/TenProtect failure where `TGame.exe` exited very early with:

```text
0xC000071C  STATUS_INVALID_THREAD
```

That was a **client/OS compatibility failure**, not a server protocol failure.

Research found working runtime approaches around the affected thread-termination path, but system DLL RVAs can differ between Windows builds. Do **not** hard-code an `ntdll.dll` RVA from somebody else's PC.

If you hit this exact exit code, record:

- Windows version/build;
- TGame exit code;
- TGame/TCLS hashes;
- whether the child was launched through TCLS;
- whether the shared-memory mapping was created;
- the exact validated instruction signature before any runtime modification.

This area should eventually have a signature-based compatibility helper rather than a fixed system-DLL RVA.

## Recommended launch order

For the stable public backend:

```text
1. Generate/install the matching RSA pair.
2. Redirect the retired PH hostnames to localhost.
3. Start server/assaultfire_server_v143b.py.
4. Start client.exe / TCLS normally.
5. Log in and reach the normal START stage.
6. Choose ONE launch compatibility path:

   A) Normal TCLS launch:
      start tools/patches/patch_tgame_datetime.py
      click START

   B) Suspended TCLS handoff:
      start tools/patches/patch_tcls_suspended_launch.py
      wait for "TCLS ARMED"
      click START
      helper restores TCLS + patches datetime + resumes TGame

7. Confirm TCLS_SHAREDMEMEMORY<PID> is created/written.
8. Confirm the server sees OWNER=TGame.exe on ROLE, then ZONE.
```

Do not run Path A and Path B simultaneously.

## Useful failure split

```text
No VERSION
  -> hosts/DNS/server listener problem

VERSION works, AUTH fails
  -> RSA pair / APClient / AUTH framing problem

AUTH works, no server list
  -> DIR tree / attributes problem

DIR works, START does nothing
  -> TCLS selected-server / GetLoginInfo / process-launch path

TGame appears then instantly exits
  -> client compatibility/TenProtect/datetime path; inspect exit code

TGame stays alive but never reaches ROLE
  -> TCLS shared-memory handoff / TGame login transport

ROLE works but gameplay UI is incomplete
  -> ZONE/gameplay protocol; not a launcher problem
```

## Repository rule

Do not commit or upload:

- `TCLS.dll`
- `TGame.exe`
- patched copies of those binaries
- `PRIVATE.PEM`
- original maps/packages/assets
- memory dumps containing third-party code or personal data

Document **signatures, offsets, behavior, and original clean-room helpers** instead.
