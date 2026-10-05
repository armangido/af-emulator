# PvE runtime and stock-selected map flow

The repository carries the integrated local Assault Fire PH PvE runtime used by the stable v143b path. The stock room's selected installed PvE map is propagated into the lazy v48 AFDEV launch, so the dedicated-server lifecycle is not tied to a single map.

## Lifecycle

1. A10A creates/reserves the room only. It does not start AFDEV.
2. A3A0 or A113 arms the lightweight DS bridge and returns the DS assignment path.
3. The first valid client DS UDP packet is latched.
4. The v48 AFDEV loader starts the room's selected installed map with the resolved game class.
5. The local `TGame_AFDEV.exe` must contain the verified disk-restored ServerMove v4. The loader validates it and fails closed if the stock stripped stub is still present; there is no in-memory movement fallback.
6. Steel/TGIF startup temporarily restores the stock stripped ServerMove stub during `OPEN`, then restores and verifies ServerMove v4 immediately after LoadMap stage 7, before `SESSION_READY`.
7. The loader applies the live zero DS key.
8. `SESSION_READY.json` is written only after the AFDEV world, native ServerMove-v4 path and DS key are ready.
9. The bridge releases the latched first packet and normal UE3 traffic continues.
10. Match cleanup is player-scoped; a shared DS survives until the last in-match player leaves.

## Map and difficulty selection

A10A seeds the reserved DS allocation from the stock room's `MapString`, ModeId, MapId, SubModeId and flags. The room owner's live A11E `SetGameSettings` packet is authoritative for the next lazy AFDEV spawn and can replace the selected map/settings before A113/AFDEV startup.

`AF_DS_USE_CLIENT_MAP=1` is the default. Set it to `0` only when intentionally forcing `AF_DS_DEFAULT_MAP`. The v48 loader resolves the requested filename under the local `TGame\CookedPC\Maps` tree before launch, so the emulator does not need a hard-coded map-ID-to-filename table.

Known stock PvE difficulty submode values:

- `0x00001001` — Easy
- `0x00001002` — Normal
- `0x00001003` — Hard

The v48 loader receives the selected `SubModeId` and applies it to the live PvE `GameSettings` / difficulty state before `SESSION_READY`.

A client HUD difficulty label mismatch is tracked separately from the authoritative server/AFDEV difficulty state.

## Native ServerMove v4

The public launcher patches only the locally-created `TGame_AFDEV.exe`; the normal client `TGame.exe` keeps its existing verified datetime patch and is not replaced by the ServerMove tool.

`tools/patches/tgame_servermove_v4.py` validates the PH v1.0.0.24 native anchors, keeps all controller vtable dispatch entries intact, appends a small executable `.afm4` section, and redirects the shared stripped ServerMove stub at `0x013A88D0` into the reconstructed body. The AFDEV loader requires that live body. The older runtime movement bridge has been removed, so movement is owned only by the native `TGame_AFDEV.exe` ServerMove path.

The restored path keeps the surviving PH implementations for CheckSpeedHack, SetRotation, FaceRotation, virtual MoveAutonomous and the correction stage. The authoritative `ClientLoc` is not copied directly into `Pawn.Location`.

Live validation on 2026-10-05 observed the exact reconstructed body executing 686 times in Survival with all hits on the expected server PlayerController. Client/server movement distance was 1351.9 / 1355.4 units with a maximum sampled separation of 24.6 units. A later Steel Fortress run observed 4327 ServerMove-v4 calls and 4316 generic MoveAutonomous calls; forward/backward/steering mech controls were visually confirmed correct.

The exact PH `Pawn.MaxPitchLimit` offset for swimming/flying remains intentionally unguessed. Walking/falling uses the validated stock-style pitch path.

The separate **DS UDP bridge v9 remains required** for first-packet latching, per-peer UDP forwarding and AFDEV/session handoff. It is transport/lifecycle plumbing only; it no longer implements player movement.

## Runtime files

- `server/assaultfire_server_v143b.py`
- `server/assaultfire_ds_spawner.py`
- `tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py`
- `tools/bridge/af_ds_udp_bridge_v9_multi_peer_latch.py`

The repository does not redistribute `TGame_AFDEV.exe`, cooked maps, private keys, player state, or runtime DS state.
