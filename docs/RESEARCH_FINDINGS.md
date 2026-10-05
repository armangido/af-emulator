# Verified Research Findings

This page collects reverse-engineering findings that are useful to preservation work but are too detailed for the project status page.

## Evidence labels

- **Verified** — observed in the validated PH build, recovered from shipped package/schema data, or exercised by the current working runtime.
- **Observed capture** — recorded from one accepted stock-client exchange; useful evidence, but not necessarily a universal constant.
- **Research lead** — a strong clue that still lacks enough protocol/runtime validation to be called implemented.

Unless stated otherwise, addresses and runtime details on this page are specific to the validated Assault Fire PH preservation build used by this repository.

## 1. Legacy PvE round-family finding: `PVEGame.TGSVGame`

**Status: Verified**

Static package/map analysis used by the current v48 loader found that a shipped PvE scripting package contains:

```text
PVEGame.TGSVSeqAct_ResetRound
```

and does not contain the investigated TGSV3 round-start/prepare/clear sequence-action instances.

The recovered `PVEGame.u` relationship for that reset path points to:

```text
PVEGame.TGSVGame
PVEGame.TGSVGameReplicationInfo
```

This established `PVEGame.TGSVGame` rather than `TGSVGame.TGSV3Game` as the validated game class used by the current generic PvE runtime.

This finding removed the need for the earlier experimental idea of reclassifying the live GRI or changing the spawned game type after map load.

Source implementation: `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## 2. The working AFDEV process is a true server process

**Status: Verified**

The current v48 loader validates the process-level Unreal globals before declaring the AFDEV runtime usable:

```text
GIsClient = 0
GIsServer = 1
GIsEditor = 0
```

If the process does not enter this state, the loader treats that as a startup failure instead of continuing with a client/listen-hybrid configuration.

This matters because earlier experiments could load farther while still being in the wrong process mode, producing misleading PvE loading and movement behavior.

Source implementation: `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## 3. Multiple AFDEV instances need unique TGame mutex identities

**Status: Verified**

The validated PH image has a normal single-instance path around `CreateMutexW`.

Recovered static details:

```text
call-site area : 0x01349D75
mutex string   : 0x01D12F98
GetLastError() : 183 -> multiple-running-instances path
```

The original mutex name is:

```text
TGAME_{D21F20CD-996C-4ae2-8BF8-F2A7B4CD20D5}
```

For AFDEV server processes, the v48 loader derives a deterministic per-instance `TGAME_{...}` mutex name using UUID5 and the DS `instance_id`. This lets multiple local AFDEV server processes coexist while preserving separate process identities.

Source implementation: `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## 4. GEO protocol commands used before the ZONE handoff

**Status: Verified**

The recovered C2GEO/GEO2C command family used by the local TGame path is:

| Direction | Command | ID |
|---|---|---:|
| C2GEO | `REQ_ZONELIST` | `0x1000` |
| GEO2C | `RES_ZONELIST` | `0x2000` |
| C2GEO | `REQ_PINGLIST` | `0x1001` |
| GEO2C | `RES_PINGLIST` | `0x2001` |

The GEO packet magic is `0x8202`.

The recovered `C2GEOPkgHead` is four big-endian `u16` fields:

```text
Magic
Cmd
HeadLen
BodyLen
```

These messages sit in the TGame login path immediately before or around selection of the local ZONE endpoint.

Source implementation: `server/assaultfire_server_v143b.py`.

## 5. One accepted stock A10A room-creation capture

**Status: Observed capture**

An accepted PH client room-creation capture recorded on 2026-09-19 contained:

```text
ModeId    = 0x00002001
MapId     = 0x002F
SubModeId = 0x00001001
Flags     = 0x00003008
MapString = empty in this particular A10A request
```

These values are a known accepted reference, not universal constants for every room or map.

The current implementation preserves the stock room fields and allows the later A11E `SetGameSettings` update to replace the map/settings snapshot before lazy AFDEV startup. A later stock `MapString` can therefore become the actual map launched by v48.

Source implementation/comments: `server/assaultfire_server_v143b.py` and `server/assaultfire_ds_spawner.py`.

## 6. Tutorial completion has a recovered client request entry, but rewards are not solved

**Status: Research lead**

The recovered `UTGame.u` online-request catalog contains:

```text
TGOnlineClient.OnlineRequest_NotifyFinishNewGuidTask(Byte nTaskMode)
export index: 43269
```

This is a strong lead for the tutorial/basic-controls completion path and may explain why simply finishing the playable tutorial is not sufficient for rewards in the current emulator.

What is **not** yet verified:

- the numeric network command used by this request;
- the exact request/response wire structure;
- whether it gates starter rewards, progression, or another tutorial state;
- the stock client's expected completion acknowledgement.

Tutorial rewards therefore remain **unsolved** in the public baseline. This entry is a research target, not an implemented feature.

Source catalog: `V139_UTGAME_REQUEST_CATALOG` in `server/assaultfire_server_v143b.py`.

## 7. PH UpdatePlayerProperty uses schema-sensitive A00A routing and bitmask flags

**Status: Verified**

Live PH 1.0.0.24 validation on 2026-10-04 recovered the stock wallet/property update path strongly enough to replace the earlier AP-specific command/layout guesses.

The important result is broader than AP:

- `A00A` is accepted for the **36-byte UpdatePlayerProperty** notification body used by the wallet/progression path.
- The same client also uses `A00A` for the existing **19-byte PropOperation** notification path.
- Therefore a numeric command ID by itself is not sufficient to identify the semantic consumer in this family. The body/TDR schema and the live handler/listener path must be considered together.
- `EUPDATEPROPERTYFLAG_*` values are **bitmasks**, not ordinal selectors:

  | Property | Flag |
  |---|---:|
  | TP / PH AP | `0x01` |
  | GP | `0x02` |
  | EXP | `0x04` |
  | PROP | `0x08` |
  | MP | `0x10` |

The verified fixed UpdatePlayerProperty body is 36 bytes:

```text
u32 UpdateFlag
u16 Reason
i32 TGamePoint
i32 HappyPoint
i32 GoldPoint
i32 MonthPoint
i32 Experience
i32 EvolutionPoint
i32 CardPoint
u16 Count
```

For the stock `OnlineRequest_UpdateTPValue()` flow specifically:

```text
C2ZN A50E ReqTPBalance
        ↓
reload authoritative persisted wallet
        ↓
ZN2C A00A / 36-byte UpdatePlayerProperty
UpdateFlag = 0x01
Reason     = 0x2A  (TPBALANCE)
TGamePoint = absolute current AP
Count      = 0
```

A50E is a **read/synchronization request**, not a top-up operation. Website/admin changes mutate the authoritative persisted balance; pressing the in-game refresh button reloads that balance and publishes the current absolute value. Repeating A50E must therefore be idempotent.

The `TPBALANCE` reason value is `42 / 0x2A`. This was recovered from the shipped enum ordering (`USECARD`, `TPBALANCE`, `EXCHANGE_PROP`) and then live-validated by the working AP refresh path.

### General protocol lesson

Do not assign semantics from adjacent command IDs, stale symbolic ordering, or macro-name string order alone. In this PH client, the same top-level numeric ID can participate in different schema-specific paths. Promotion to stable code should require both:

1. a structure/body recovered from shipped schema/client evidence; and
2. a live consumer/callback result showing that the intended stock path executed.

This finding should be reused when validating GP, MP, EXP, property notifications, purchase-side wallet changes, and other UpdatePlayerProperty producers. Reason values other than the now-verified TP-balance case remain subject to separate validation; see Issue #57.

Source implementation: `server/assaultfire_server_v143b.py`.

## 8. Shared native ServerMove was stripped, and the reconstructed v4 path is live-verified

**Status: Verified**

In the validated PH v1.0.0.24 image, the shared native ServerMove target at:

```text
0x013A88D0
```

is a stripped `ret 0x28` stub. Static analysis found 33 literal references to that shared target across the normal TG/PvP/PvE/Mecha/AI/Bio movement families. The controller vtables retain the surviving correction and MoveAutonomous dispatch slots.

The public `tools/patches/tgame_servermove_v4.py` tool validates the exact native anchors and installs a small local `.afm4` section into the user's own `TGame_AFDEV.exe`. It redirects only the shared stripped stub. Existing controller vtable entries are deliberately preserved.

The reconstructed path uses surviving PH native implementations including:

```text
CheckSpeedHack        0x008EF060
AActor::SetRotation   0x00BE82E0
FaceRotation thunk    0x015E0AD0
World TimeSeconds     0x00DA3980
UWorld::GetWorldInfo  0x00D9C1A0
virtual correction    +0x4CC
virtual MoveAutonomous +0x4D0
```

It also restores the AcknowledgedPawn/GivePawn gate, timestamp/server-time bookkeeping, CustomTimeDilation handling, controller/pawn rotation handling, and the WorldInfo.Pauser movement gate. ClientLoc remains input to the surviving correction path and is not copied directly into Pawn.Location.

### Live validation

On 2026-10-05 a read-only hardware-breakpoint trace observed the exact reconstructed body executing at the live `.afm4` entry **686 times** during Survival. All 686 hits carried the expected authoritative server PlayerController in ECX.

Measured movement during that run:

```text
client_max_move = 1351.9
server_max_move = 1355.4
max_delta       = 24.6
```

A later Steel Fortress run observed:

```text
ServerMove-v4       = 4327 hits
generic MoveAutonomous = 4316 hits
PZ selector         = 0 hits
JockeyControlMoveAutonomous = 0 hits
```

The mech's forward/backward/steering behavior was visually confirmed correct in that run. Therefore the working Steel result must **not** be described as proof that the PZ/Jockey-specific functions executed; the observed working path was the generic virtual MoveAutonomous route.

Steel/TGIF additionally requires a startup guard: the AFDEV loader temporarily restores the stock stripped ServerMove stub during map `OPEN`, then restores and verifies the disk ServerMove-v4 JMP after LoadMap stage 7 and before `SESSION_READY`.

With that live validation complete, the older AFDEV in-memory movement bridge is no longer part of the supported runtime. The loader now requires the verified disk-restored ServerMove-v4 body and fails closed when only the stripped stock stub is present. The v9 DS UDP bridge remains separate network/session transport and does not implement movement.

The one remaining explicit fidelity gap is the exact PH `Pawn.MaxPitchLimit` memory offset used for swimming/flying pitch clamping. The public implementation intentionally does not guess that offset.

Source implementation: `tools/patches/tgame_servermove_v4.py` and `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`.

## Publication rule

Future additions should preserve the distinction between verified behavior, single captures, and research leads. A promising symbol or export name by itself is not enough to mark a feature as working.
