# Assault Fire Server Emulator

**Language:** **English** | [Tagalog](README-TL.md) | [Cebuano](README-CEB.md) | [简体中文](README-ZH-CN.md) | [More languages](README-LANGUAGES.md)

[![Python](https://img.shields.io/badge/Python-3.10+-blue)](https://www.python.org/)
[![CI](https://github.com/armangido/af-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/armangido/af-emulator/actions/workflows/ci.yml)
[![Engine](https://img.shields.io/badge/Engine-Unreal%20Engine%203-lightgrey)](#)
[![Status](https://img.shields.io/badge/status-preservation%20research-orange)](docs/STATUS.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An unofficial **Assault Fire PH** preservation/server-emulation project.

> [!WARNING]
> **Anti-scam notice — this emulator is free**
>
> The official source for this project is this GitHub repository. The maintainers do **not** sell official builds, licenses, activation keys, required downloads, private access, or paid unlocks for the emulator.
>
> If someone claims that you **must pay** to obtain an "official" copy, activate the emulator, unlock required features, receive a required key, or gain access on behalf of this project, **do not pay**. That claim is not authorized by the maintainers and may be an attempt to scam you.
>
> This repository uses the MIT License, which permits third parties to redistribute or sell copies or related services under its terms. Paying a third party does **not** make their copy, server, support, or service official, endorsed, or affiliated with this project. The emulator itself is available here for free.
>
> When in doubt, verify downloads and instructions against this repository before running files or sending money to anyone.

> [!IMPORTANT]
> **Server independence disclaimer**
>
> This repository provides emulator software and preservation/research tooling only.
>
> Any private, public, community, hosted, or third-party server that uses, modifies, or is based on this repository is **independently operated** and is **not affiliated with, endorsed by, sponsored by, controlled by, or officially operated by this repository or its maintainers**.
>
> The repository maintainers are not responsible for third-party server operators, accounts, rules, moderation, content, security, availability, conduct, or services.

> [!IMPORTANT]
> This project is currently made for **Assault Fire PH v1.0.0.24 only**.
>
> If your game is a different version, stop. Do not force the patches.

> [!WARNING]
> This repository does **not** include the original game client.
>
> You must already have your own Assault Fire PH files.

---

# 🟢 I just want to play. What do I do?

## Easiest way — use the one-click script

Put the **whole `af-emulator` folder inside your Assault Fire PH game folder**.

Example:
<img width="1113" height="682" alt="image" src="https://github.com/user-attachments/assets/e12bf7a5-6a12-462a-b695-082e51bdabf4" />

```text
AssaultFirePH
├─ Binaries
│  └─ Win32
│     └─ TGame.exe
├─ TCLS
│  ├─ client.exe
│  └─ Tenio
│     └─ TCLS.dll
├─ TGame
└─ af-emulator
   └─ START_ASSAULT_FIRE.ps1
```

Then right-click:

```text
START_ASSAULT_FIRE.ps1
```

and choose:

```text
Run with PowerShell
```

That is now the normal setup/launch path.

The script handles the annoying parts for you:

- asks Windows for Administrator permission;
- finds the game automatically;
- checks that the client is the supported **Assault Fire PH v1.0.0.24** build;
- reuses any working Python 3.10+ installation; if none is found, Windows Package Manager installs Python Install Manager, which supplies the current stable Python 3 release;
- creates a persistent runtime at `GAME_ROOT\.af-emulator-runtime\venv`; older `venv-py312` runtimes are detected and reused automatically;
- asks whether you want the verified **permanent TCLS.dll compatibility patch**;
- creates/verifies the local RSA key pair and installs the matching `APClient.dat`;
- repairs the three Windows hosts entries;
- applies the verified datetime patch permanently to **your own `TGame.exe`**, first saving an exact `TGame.exe.bak` backup;
- creates `TGame_AFDEV.exe` locally from that verified patched `TGame.exe`, then installs the verified native **ServerMove v4** patch into the AFDEV copy only, so PvE does not require a separately distributed AFDEV executable;
- starts the emulator server;
- waits for preflight to reach **UNLOCKED**;
- starts the runtime launch helper automatically;
- launches `TCLS\client.exe` automatically.

### Create a local account the first time you play

When you run the launcher, it starts the development account website on your
PC and opens the registration page in your browser. Register there the first
time you use this local server. The usual address is:

```text
http://127.0.0.1:8080/register
```

If port `8080` is already in use, the server selects another local port and
prints the exact **Registration** address in its window. `127.0.0.1` means
`localhost`: this page is reachable only from the same PC running the emulator.

Choose a username with 3–24 letters, numbers, dots, underscores, or hyphens,
and a password with 8–72 characters. Then use that same username and password
to log in through the Assault Fire launcher. Register only once for this local
server database. On later launches, close the registration page and use your
existing credentials. Keep the emulator server window open while you play.

If the browser did not open automatically, copy the `[WEB] Registration` URL
from the server window into your browser. The local website is part of the
development setup; it is not a public registration service.

After your account is registered, the normal player interaction is:

```text
log in with your registered username and password
↓
wait for the START button
↓
click START
```

You do **not** need to manually start the server, set `AF_CLIENT_ROOT`, set `AF_GAME_DIR`, run the hosts helper, run the TCLS launch helper, or create `TGame_AFDEV.exe`.

### Run it again without repeating setup answers

The launcher saves your normal **Y/N choices** in a local `launcher.config.json` file beside `START_ASSAULT_FIRE.ps1`. It uses those choices the next time you run the script. Answers are not case-sensitive, and pressing Enter uses the shown default.

The config is created automatically after your first saved choice. If you want to set the common defaults before the first run, copy `launcher.config.example.json` to `launcher.config.json` in the same folder. You can edit the Y/N values in that file. Delete `launcher.config.json` to answer the prompts again from scratch.

For safety, the launcher still asks before replacing a mismatched `PRIVATE.PEM`. Before launch, it validates the TGame PE and exact datetime patch signature. If the known patch RVA has no file bytes, it searches executable sections and accepts only one exact match; an already-patched image must also have the complete known trampoline. A clean supported image uses an aligned `0x00`/`0xCC` code cave in a mapped executable section when one is available. If no cave is available, the patcher adds a small `.afdt` executable section only when the PE headers contain an unused section-header slot. It saves an exact `TGame.exe.bak` before replacing the file. If validation, backup verification, or post-write checks fail, the game is not accepted for launch and the original file is left in place. The suspended-launch helper then checks the selected RVA and trampoline again in the loaded TGame process before resuming it. This verifies the patch site, not every byte of the executable, so use the same PH v1.0.0.24 game build. The launcher does not accept a file just because you confirm it. The config stores preferences, **not the contents of your private key**, and Git ignores the local config file.

> [!IMPORTANT]
> The one-click script does **not** download or redistribute Assault Fire files.
> It only works with the game files you already have. It permanently patches a
> verified local `TGame.exe` and keeps the original as `TGame.exe.bak`. The local
> `TGame_AFDEV.exe` copy is created from that verified patched file and receives
> the verified native ServerMove-v4 patch locally. The normal client `TGame.exe`
> is not replaced by the ServerMove tool. If the
> signature is at a different RVA, it must be the only matching executable-
> section signature. The patcher uses a safe code cave or adds a dedicated
> executable section when the PE headers have an unused section-header slot.

> [!CAUTION]
> If the script cannot verify the `TGame.exe` patch-site signature or reports an
> unknown `TCLS.dll` hash, stop. Do not force a patch onto another game version.

---

## Manual setup / troubleshooting path

The steps below are kept for developers, troubleshooting, and machines where the one-click script cannot be used.

---

# Part 1 — FIRST TIME SETUP

You normally do this part only once.

## Step 1 — Install the things you need

You need:

```text
Python 3.10 or newer
Git
your own Assault Fire PH v1.0.0.24
```

If you do not know where to download Python or Git, use the official websites below.

---

### 1A — Install Python 3.10 or newer

Open this website in your browser:

**Python official website:**

https://www.python.org/downloads/windows/

Scroll down to the **Files** section.

Under **Windows**, click:

```text
Windows installer (64-bit)
```

For most normal Windows 10/11 computers, this is the correct one.

After the file downloads:

1. Double-click the Python installer.
2. On the first installer screen, look near the bottom.
3. If you see:

```text
Add python.exe to PATH
```

turn that checkbox **ON**.
4. Click:

```text
Install Now
```

5. Wait for it to finish.
6. Close the installer.

> [!IMPORTANT]
> Install a current **64-bit Python 3.10 or newer** release.
>
> The one-click launcher is no longer locked to one exact Python minor version.

### Check that Python installed correctly

Open a **new** PowerShell window and run:

```powershell
py --version
```

GOOD:

```text
Python 3.10.x or newer
```

BAD:

```text
py is not recognized
```

If you get the BAD message:

1. close PowerShell,
2. reopen PowerShell,
3. try again.

If it still does not work, reinstall Python and make sure the Python launcher/PATH option is enabled.

---

### 1B — Install Git

Open this website:

**Git official website:**

https://git-scm.com/install/windows

Click the big Windows download link for:

```text
64-bit Git for Windows
```

After it downloads:

1. Double-click the installer.
2. Keep the default options.
3. Keep clicking **Next**.
4. Click **Install**.
5. When it finishes, click **Finish**.

You do not need to understand the Git installer options for this project. The normal/default choices are fine.

### Check that Git installed correctly

Open a **new** PowerShell window and run:

```powershell
git --version
```

GOOD:

```text
git version ...
```

BAD:

```text
git is not recognized
```

If you get the BAD message, close PowerShell, reopen it, and try again.

---

### 1C — You still need the game itself

This repository does **not** download Assault Fire for you.

You must already have your own:

```text
Assault Fire PH v1.0.0.24
```

The emulator repository does not include the original game client or proprietary game files.

---

# ✅ Step 1 checkpoint

Before continuing, these two commands should work:

```powershell
py -3 --version
git --version
```

If both commands print a version number, continue to Step 2.

If either command says **not recognized**, fix that first.

---

## Step 2 — Get this emulator

### Easy way: Git

Open **PowerShell** and paste:

```powershell
git clone https://github.com/armangido/af-emulator.git
cd af-emulator
```

### If you downloaded the ZIP instead

1. Extract the ZIP.
2. Open the extracted `af-emulator` folder.
3. Click the Windows Explorer address bar.
4. Type:

```text
powershell
```

5. Press **Enter**.

A PowerShell window should open inside the emulator folder.

### How do I know I am in the right folder?

You should see files/folders like:

```text
README.md
server
tools
docs
tests
```

Your PowerShell line should end with something similar to:

```text
...\af-emulator>
```

> [!CAUTION]
> Do **not** run setup commands from inside `server\`.
>
> Stay in the main `af-emulator` folder.

---

## Step 3 — Create the Python environment

Copy and paste these two commands:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Wait for them to finish.

### GOOD

This file should now exist:

```text
af-emulator\.venv\Scripts\python.exe
```

### BAD

If PowerShell says:

```text
.\.venv\Scripts\python.exe is not recognized
```

you are probably in the wrong folder.

Go back to the folder containing `README.md`, `server`, and `tools`, then try again.

---

# Step 4 — Find your Assault Fire folder

This is very important.

Open your Assault Fire PH folder in Windows Explorer.

A correct game folder should contain something like:

```text
Your Assault Fire Folder
│
├─ TCLS
│  ├─ Tenio
│  │  └─ TCLS.dll
│  └─ config
│     └─ APClient.dat
│
└─ Binaries
   └─ Win32
      └─ TGame.exe
```

Example:

```text
D:\AssaultFirePH
```

Another computer might use:

```text
C:\Program Files (x86)\Level Up Games\Assault Fire PH
```

Both are fine.

## Copy your game-folder path

In Windows Explorer:

1. Open the Assault Fire folder.
2. Click the address bar.
3. Copy the full path.

You will use that path below.

> [!IMPORTANT]
> Whenever this README says:
>
> ```text
> YOUR_GAME_FOLDER
> ```
>
> replace it with the real folder you copied.
>
> Do **not** literally type `YOUR_GAME_FOLDER`.

---

# Step 5 — Generate your local server key

Go back to the PowerShell window inside `af-emulator`.

Example if your game is in `D:\AssaultFirePH`:

```powershell
.\.venv\Scripts\python.exe .\tools\setup\generate_local_rsa_keypair.py --client-config-dir "D:\AssaultFirePH\TCLS\config"
```

If your game is somewhere else, change only the path inside the quotes.

This creates:

```text
af-emulator\server\PRIVATE.PEM

and

YOUR_GAME_FOLDER\TCLS\config\APClient.dat
```

> [!CAUTION]
> Never upload `PRIVATE.PEM`.
>
> Never send it to another person.
>
> Never commit it to GitHub.

---

# Step 6 — Check TCLS and APClient.dat

Example:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\diagnose_tcls_apclient.py --client-root "D:\AssaultFirePH"
```

Replace `D:\AssaultFirePH` with your real game folder.

## GOOD — continue only if you get this

You want:

```text
class              : validated raw-PEM-compatible PH TCLS build
exact byte match   : YES
same RSA key       : YES
```

If those are already correct, go to **Step 7**.

## If TCLS needs the known compatibility patch

If the diagnostic shows this original TCLS SHA-256:

```text
13EAD403452E0F25CF00658369BF4BF5FF34ED1B16027F7833FB27D398386CD1
```

fully close Assault Fire and `client.exe`.

Then run:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_apclient_raw_pem.py "YOUR_GAME_FOLDER\TCLS\Tenio\TCLS.dll" --apply
```

Example:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_apclient_raw_pem.py "D:\AssaultFirePH\TCLS\Tenio\TCLS.dll" --apply
```

The known working patched SHA-256 is:

```text
3FF351E0ADB594D7544E28DB2E966A6D6EB548E9DF70DAAF4DAF58F2EE438D56
```

The tool also creates:

```text
TCLS.dll.bak
```

Now run the diagnostic from the beginning of Step 6 again.

> [!CAUTION]
> If the tool says the DLL/hash is unknown, **STOP**.
>
> Do not force the patch.

---

# Step 7 — Point the old Assault Fire servers to your own PC

Open **PowerShell as Administrator**.

How:

```text
Start menu
→ search "PowerShell"
→ right-click PowerShell
→ Run as administrator
```

Go to your `af-emulator` folder.

Then run:

```powershell
powershell -ExecutionPolicy Bypass -File .\tools\setup\setup_assaultfire_hosts.ps1
```

The helper configures these names:

```text
tversion.levelupgames.ph
tauthproxy.levelupgames.ph
tdir.levelupgames.ph
```

to use:

```text
127.0.0.1
```

That means:

```text
"connect to my own PC"
```

You normally do **not** need to edit the Windows hosts file yourself.

---

# ✅ First-time setup finished

You can now use the shorter steps below every time you want to play.

---

# Part 2 — EVERY TIME YOU WANT TO PLAY

This is the important part.

You need **two PowerShell windows**.

Think of them like this:

```text
WINDOW 1 = SERVER
WINDOW 2 = GAME LAUNCH HELPER
```

Do not close Window 1 while playing.

---

# Step A — Open PowerShell in af-emulator

Open the `af-emulator` folder in Windows Explorer.

Click the address bar and type:

```text
powershell
```

Press **Enter**.

This is **Window 1**.

---

# Step B — Tell the server where your game is

Example game folder:

```text
D:\AssaultFirePH
```

Paste:

```powershell
$env:AF_CLIENT_ROOT = "D:\AssaultFirePH"
$env:AF_GAME_DIR = "D:\AssaultFirePH\Binaries\Win32"
```

Use your own real game path.

> [!IMPORTANT]
> These variables belong to this PowerShell window.
>
> If you close the window and open a new one, set them again.

---

# Step C — Start the server

In the same PowerShell window:

```powershell
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

### Developer: host only, without a local Assault Fire client

If this machine is only hosting the emulator/backend, start it with:

```powershell
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py --server-only
```

You can also set `AF_SERVER_ONLY=1`.

Server-only mode skips the **local** client/TCLS/`APClient.dat`/hosts preflight, so
`AF_CLIENT_ROOT` and `AF_GAME_DIR` are not required on the host. It does **not**
unlock the local game-launch helpers.

AUTH still requires your private server RSA key. The server checks, in order, an
explicit `--private-key <path>`, `AF_PRIVATE_KEY` / `AF_PRIVATE_KEY_PATH`,
`PRIVATE.PEM` beside the server script, and common repository `server\PRIVATE.PEM`
locations. This means a developer copy such as `af\TEST\assaultfire_server_v143b.py`
can automatically find `af\server\PRIVATE.PEM` when it exists.

Never commit or share `PRIVATE.PEM`.

Now wait.

Do **not** open the game yet.

The server checks your setup first.

---

# Step D — Wait for the green/good server result

At first you may see:

```text
[PREFLIGHT] game launch gate         : LOCKED
```

That can be normal for a moment.

The server is still opening its ports.

## GOOD — this is what you are waiting for

```text
[PREFLIGHT] game launch gate         : UNLOCKED
[MAIN] All listeners running.
```

You should also have:

```text
[PREFLIGHT] TCLS validated build    : YES
[PREFLIGHT] APClient exact bytes    : YES
[PREFLIGHT] same RSA key            : YES
```

If everything is good, leave **Window 1 open**.

## BAD — stop here

If you see:

```text
[PREFLIGHT] client root             : None
[PREFLIGHT] TCLS validated build    : NO
[PREFLIGHT] APClient exact bytes    : NO
[PREFLIGHT] same RSA key            : NO
[PREFLIGHT] game launch gate         : LOCKED
```

do **not** continue.

Do **not** click START.

The game-launch helper will intentionally block you.

Common fixes:

| What you see | What it usually means |
| --- | --- |
| `client root : None` | You forgot `AF_CLIENT_ROOT` |
| `TCLS validated build : NO` | Wrong/unpatched TCLS |
| `APClient exact bytes : NO` | Wrong `APClient.dat` |
| `same RSA key : NO` | `PRIVATE.PEM` and `APClient.dat` do not belong together |
| hosts check = `NO` | Run Step 7 again as Administrator |
| port/bind error | Another emulator/server is probably already running |

The full log is saved in:

```text
af-emulator\server\af_server_live.log
```

Send that log when reporting an emulator bug.

Do **not** send `PRIVATE.PEM`.

---

# Step E — Open Assault Fire launcher

Now open:

```text
YOUR_GAME_FOLDER\TCLS\client.exe
```

Log in normally.

Wait until you reach the launcher screen with the **START** button.

## DO NOT CLICK START YET

Stop at the START button.

Leave the launcher open.

---

# Step F — Open Window 2

Go back to the `af-emulator` folder in Windows Explorer.

Click the address bar.

Type:

```text
powershell
```

Press **Enter**.

This is **Window 2**.

---

# Step G — Run the safe launch helper

In **Window 2**, paste:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py
```

Wait.

## DO NOT click START until Window 2 says this

```text
TCLS ARMED
Click START in the Assault Fire launcher now.
```

When you see those lines:

# 👉 NOW CLICK START

The helper will automatically:

```text
create TGame.exe safely
        ↓
finish TCLS handoff
        ↓
apply the required TGame compatibility patch
        ↓
resume TGame.exe
```

You do not need to do those steps yourself.

> [!IMPORTANT]
> When using `patch_tcls_suspended_launch.py`, do **not** also run `patch_tgame_datetime.py`.
>
> Use one launch method, not both.

---

# 🎮 Normal start order

If you forget everything else, remember this:

```text
1. Open PowerShell in af-emulator
2. Set AF_CLIENT_ROOT
3. Set AF_GAME_DIR
4. Start assaultfire_server_v143b.py
5. WAIT for UNLOCKED
6. Open client.exe
7. Log in
8. STOP at START
9. Open second PowerShell in af-emulator
10. Run patch_tcls_suspended_launch.py
11. WAIT for TCLS ARMED
12. Click START
```

---

# Copy/paste example

This example assumes the game is installed here:

```text
D:\AssaultFirePH
```

## Window 1

```powershell
$env:AF_CLIENT_ROOT = "D:\AssaultFirePH"
$env:AF_GAME_DIR = "D:\AssaultFirePH\Binaries\Win32"
.\.venv\Scripts\python.exe .\server\assaultfire_server_v143b.py
```

Wait for:

```text
[PREFLIGHT] game launch gate         : UNLOCKED
[MAIN] All listeners running.
```

Then open:

```text
D:\AssaultFirePH\TCLS\client.exe
```

Log in.

Stop at **START**.

## Window 2

```powershell
.\.venv\Scripts\python.exe .\tools\patches\patch_tcls_suspended_launch.py
```

Wait for:

```text
TCLS ARMED
Click START in the Assault Fire launcher now.
```

Then click **START**.

---

# Logging — you normally do not need to touch this

The default console level is:

```text
INFO
```

That is fine for normal players.

The full file log still saves **DEBUG + INFO + WARNING + ERROR**, even when DEBUG is hidden from the console.

Full log:

```text
server\af_server_live.log
```

So if something breaks, the detailed information should still be there.

At startup you may see:

```text
[LOGGING] console=INFO file=DEBUG+ path=...\server\af_server_live.log
```

That is good.

## I want every message on the console too

Before starting the server:

```powershell
$env:AF_LOG_LEVEL = "DEBUG"
```

Other choices:

```text
INFO
WARNING
ERROR
```

Changing this affects the **console only**.

The file still keeps DEBUG records.

## Sensitive AUTH debugging

Raw AUTH plaintext/ciphertext can contain authentication information.

It is therefore **off by default**, even though normal DEBUG logging is always saved.

Only enable it for a controlled local diagnostic:

```powershell
$env:AF_DEBUG_AUTH_HEX = "1"
```

Turn it off again after testing:

```powershell
Remove-Item Env:AF_DEBUG_AUTH_HEX -ErrorAction SilentlyContinue
```

Do not post raw sensitive AUTH logs publicly.

---

# PvE / creating a room

The dedicated-server spawner is enabled by default.

The important setting is:

```powershell
$env:AF_GAME_DIR = "YOUR_GAME_FOLDER\Binaries\Win32"
```

If this points to the wrong place, the launcher/login may work but starting a PvE match can fail later.

Example:

```powershell
$env:AF_GAME_DIR = "D:\AssaultFirePH\Binaries\Win32"
```

When a PvE room starts, the emulator handles the dedicated-server lifecycle automatically.

The local AFDEV copy also receives the verified native ServerMove-v4 patch automatically. The loader validates the live restored body and now refuses to start gameplay if the local AFDEV copy still has the stripped stock stub; the old runtime movement fallback has been removed. Steel/TGIF startup temporarily keeps the stock stripped ServerMove stub during map `OPEN`, then restores v4 after LoadMap stage 7 before the client is released.

You do not normally start AFDEV or run the ServerMove patcher manually.

More details for developers: [PvE Runtime](docs/PVE_RUNTIME.md).

---

# The most common mistakes

## 1. You typed YOUR_GAME_FOLDER literally

Wrong:

```powershell
$env:AF_CLIENT_ROOT = "YOUR_GAME_FOLDER"
```

Correct example:

```powershell
$env:AF_CLIENT_ROOT = "D:\AssaultFirePH"
```

---

## 2. You are inside the wrong folder

Wrong PowerShell location:

```text
...\af-emulator\server>
```

Better:

```text
...\af-emulator>
```

You should be able to see:

```text
README.md
server
tools
docs
```

---

## 3. You clicked START too early

Correct order:

```text
launcher reaches START
        ↓
DO NOT CLICK IT
        ↓
run patch_tcls_suspended_launch.py
        ↓
wait for TCLS ARMED
        ↓
click START
```

---

## 4. Server says LOCKED

Do not click START.

Wait first.

If it changes to:

```text
UNLOCKED
```

you are good.

If it stays LOCKED and shows a `NO` or `FAILED`, fix that problem first.

---

## 5. "AP client initialization failed."

Run:

```powershell
.\.venv\Scripts\python.exe .\tools\patches\diagnose_tcls_apclient.py --client-root "YOUR_GAME_FOLDER"
```

You need:

```text
validated TCLS
exact byte match = YES
same RSA key = YES
```

If not, go back to **First-time Step 6**.

More details: [Launcher Errors](docs/LAUNCHER_ERRORS.md).

---

## 6. TGame opens and crashes immediately

Use the recommended suspended launch helper.

Do not just click START by itself.

If the helper reports:

```text
TGame build/signature mismatch
```

stop.

Do not force the patch.

Your TGame may not be the supported PH v1.0.0.24 build.

---

## 7. "Port already in use" / bind failed

You may already have another emulator running.

Close the old server window and try again.

Do not run two copies of the emulator on the same ports unless you intentionally configured different ports.

---

# What should I send when asking for help?

Send:

```text
1. A screenshot of the error
2. What step you were doing
3. The exact command you ran
4. server\af_server_live.log
5. Your Assault Fire version
```

Do **not** send:

```text
PRIVATE.PEM
passwords
account credentials
tokens
original proprietary game binaries
```

---

# Important client note

The original PH client contains an old kernel-level security/anti-cheat component made for an older Windows environment.

On modern Windows it can cause problems before the emulator is contacted.

This repository does **not** provide instructions for bypassing, disabling, or modifying that kernel security component.

See [Vital Setup Notes](docs/VITAL_SETUP_NOTES.md).

---

# What currently works?

The public stable baseline is **v143b**.

Working/integrated areas include VERSION, AUTH, DIR, ROLE, ZONE, existing/local profile login, shared rooms, dynamic room work, PvE dedicated-server allocation/lifecycle, stock-selected PvE map/settings propagation, lazy AFDEV startup, the live-verified native ServerMove-v4 AFDEV path, inventory/shop/profile preservation work, and the live-verified native A50E AP/TP refresh path.

Local username/password registration is available through the development
website described above. First-time in-game nickname creation and parts of the
social/progression systems are still incomplete or being validated.

> [!IMPORTANT]
> PH v1.0.0.24 native AP refresh is live-verified. The stock AP reload button sends A50E; the emulator reloads the authoritative persisted wallet and publishes wallet values through the recovered A00A UpdatePlayerProperty schema.
>
> The same refresh boundary now republishes AP, GP, and MP with the recovered bitmask flags: AP/TP `0x01`, GP `0x02`, and MP `0x10`. AP is live-verified; the GP/MP extension is implemented from the same recovered schema and should be live-checked with distinctive admin values.
>
> A50E is a read/synchronization operation only. Website/admin wallet changes are the write side; repeated in-game refresh clicks do not grant or increment currency.
>
> The protocol finding is not AP-specific: UpdatePlayerProperty uses bitmask flags and a schema-sensitive A00A route. See [Research Findings](docs/RESEARCH_FINDINGS.md) and Issue #57 before adding new GP/MP/EXP/property producers.

For the detailed matrix, read [Project Status](docs/STATUS.md).

---

# Advanced / developer documentation

Normal players do not need to read these first.

| Document | What it is for |
| --- | --- |
| [Getting Started](docs/GETTING_STARTED.md) | longer setup guide |
| [Project Status](docs/STATUS.md) | what works / what is partial |
| [PvE Runtime](docs/PVE_RUNTIME.md) | dedicated-server lifecycle |
| [Launch Requirements](docs/LAUNCH_REQUIREMENTS.md) | TCLS → TGame technical details |
| [Launcher Errors](docs/LAUNCHER_ERRORS.md) | launcher/TGame troubleshooting |
| [Architecture](docs/ARCHITECTURE.md) | ports and services |
| [Research Findings](docs/RESEARCH_FINDINGS.md) | verified protocol/runtime research |
| [RE Tooling](docs/RE_TOOLING.md) | reverse-engineering helpers/workflow |
| [FAQ](docs/FAQ.md) | common questions |
| [Contributing](CONTRIBUTING.md) | contributing code/research |

---

# Repository safety rules

Do not commit or upload:

```text
original TGame.exe / TCLS.dll
maps / UPK / UDK files
original game assets
PRIVATE.PEM
passwords
tokens
cookies
personal account information
memory dumps containing third-party code or private data
```

Users must obtain original game files independently and lawfully.

---

# License

Original emulator code and documentation in this repository are licensed under the [MIT License](LICENSE).

This license does not grant rights to Assault Fire, the original client, executables, DLLs, maps, packages, artwork, audio, trademarks, or other third-party material.

This project is not affiliated with, endorsed by, or sponsored by Tencent, Level Up! Games, or any original rights holder.
