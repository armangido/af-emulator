# Assault Fire Server Emulator

**Language:** **English** | [Tagalog](README-TL.md) | [Cebuano](README-CEB.md) | [简体中文](README-ZH-CN.md) | [More languages](README-LANGUAGES.md)

[![Python](https://img.shields.io/badge/Python-3.12+-blue)](https://www.python.org/)
[![CI](https://github.com/armangido/af-emulator/actions/workflows/ci.yml/badge.svg)](https://github.com/armangido/af-emulator/actions/workflows/ci.yml)
[![Engine](https://img.shields.io/badge/Engine-Unreal%20Engine%203-lightgrey)](#)
[![Status](https://img.shields.io/badge/status-preservation%20research-orange)](docs/STATUS.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

An unofficial **Assault Fire PH** preservation/server-emulation project.


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
- installs Python 3.12 with Windows Package Manager when it is missing;
- creates a persistent Python 3.12 runtime at `GAME_ROOT\.af-emulator-runtime\venv-py312` and reuses it across ZIP/repo updates;
- asks whether you want the verified **permanent TCLS.dll compatibility patch**;
- creates/verifies the local RSA key pair and installs the matching `APClient.dat`;
- repairs the three Windows hosts entries;
- creates `TGame_AFDEV.exe` locally from **your own verified `TGame.exe`** so PvE does not require a separately distributed AFDEV executable;
- starts the emulator server;
- waits for preflight to reach **UNLOCKED**;
- starts the runtime launch helper automatically;
- launches `TCLS\client.exe` automatically.

After that, the only normal player interaction is:

```text
log in
↓
wait for the START button
↓
click START
```

You do **not** need to manually start the server, set `AF_CLIENT_ROOT`, set `AF_GAME_DIR`, run the hosts helper, run the TCLS launch helper, or create `TGame_AFDEV.exe`.

> [!IMPORTANT]
> The one-click script does **not** download or redistribute Assault Fire files.
> It only works with the game files you already have. The local `TGame_AFDEV.exe`
> copy is created only when your `TGame.exe` matches the exact supported build.

> [!CAUTION]
> If the script says the `TGame.exe` or `TCLS.dll` hash is unknown, stop.
> Do not force a patch onto another game version.

---

## Manual setup / troubleshooting path

The steps below are kept for developers, troubleshooting, and machines where the one-click script cannot be used.

---

# Part 1 — FIRST TIME SETUP

You normally do this part only once.

## Step 1 — Install the things you need

You need:

```text
Python 3.12
Git
your own Assault Fire PH v1.0.0.24
```

If you do not know where to download Python or Git, use the official websites below.

---

### 1A — Install Python 3.12

Open this website in your browser:

**Python official website:**

https://www.python.org/downloads/release/python-3123/

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
> Install **Python 3.12**.
>
> Do not assume Python 3.13 or 3.14 will behave exactly the same with this project.

### Check that Python installed correctly

Open a **new** PowerShell window and run:

```powershell
py -3.12 --version
```

GOOD:

```text
Python 3.12.x
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
py -3.12 --version
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
py -3.12 -m venv .venv
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

You do not normally start AFDEV manually.

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

Working/integrated areas include VERSION, AUTH, DIR, ROLE, ZONE, existing/local profile login, shared rooms, dynamic room work, PvE dedicated-server allocation/lifecycle, stock-selected PvE map/settings propagation, lazy AFDEV startup, inventory/shop/profile preservation work, and the current local AP synchronization path.

Some features are still incomplete or still being validated, including first-time nickname/account creation and parts of the social/progression systems.

> [!IMPORTANT]
> AP initialization currently uses a temporary local-only workaround on PH v1.0.0.24.
>
> The server wallet and normal AP purchases remain authoritative, but the stock client's native initial AP/GamePoint population is not yet fully recovered.
>
> The emulator currently copies the persisted AP balance into the verified local player field once per `TGame.exe` process. Disable this with `AF_LOCAL_AP_SYNC=0` only if you know why you are doing it.

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
