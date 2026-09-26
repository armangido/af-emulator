# Project Status

This page tracks the **public stable baseline only**.

Current public baseline: **v143b**

Experimental or unverified work is excluded from `main` until it is reproducibly verified with the Assault Fire PH client.

## Status legend

| Mark | Meaning |
|---|---|
| ✅ Working | Reproducible in the current public baseline |
| 🟡 Partial | Implemented enough for testing/research, but not complete or not fully live-verified |
| 🔴 Broken / unavailable | Known not to work, intentionally excluded, or missing required protocol behavior |
| 🛠 Wanted | A feature we want contributors to help implement or verify |

## What currently works

| Area | Status | Notes |
|---|---:|---|
| VERSION service | ✅ | Local version-service response path is implemented. |
| AUTH handshake | ✅ | RSA/DH/AES authentication path used by the local client is implemented. |
| DIR/server discovery | ✅ | Local directory response and server endpoint discovery are implemented. |
| ROLE/ZONE connection foundation | ✅ | The public v143b baseline can bring the existing local profile through the established login path. |
| Existing local player/profile state | ✅ | v143b has a known local player/profile path and persisted player state. |
| PlayerInfo / property delivery | ✅ | Stable player information and property/inventory messages used by v143b are implemented. |
| Shop foundation | ✅ | Stable shop/balance/purchase work from the pre-v95 branch is present. |
| Clan ID persistence | ✅ | v143b persists clan membership/ClanID and reflects it in PlayerInfo. |
| Clan name verification/create request shapes | ✅ | Known v143b request/response shapes are implemented on `main`. |
| DS UDP bridge v9 | ✅ | Multi-peer first-packet latch bridge used by the integrated v143b PvE handoff. |
| AFDEV PvE loader v48 | ✅ | Lazy multi-instance AFDEV loader started on the first valid DS UDP packet; launches the room-selected installed PvE map with `PVEGame.TGSVGame`. |
| PvE dedicated-server/gameplay handoff + map selection | ✅ | v143b integrates the lazy v48 AFDEV + v9 bridge path, zero-DSKey readiness gate, stock A10A/A11E map/settings propagation, and player-scoped DS cleanup. |
| Dedicated-server reservation and UE3 handoff | ✅ | A10A reserves capacity, A3A0/A113 arm the DS path, A11A assigns the endpoint, and AFDEV starts lazily on the first valid DS UDP packet. |

## Partial or research-grade features

| Area | Status | Current limitation |
|---|---:|---|
| Lobby browser | ✅ | Live two-stock-client PH validation covers automatic A100/A102 first paint, enterable room rows, and shared room visibility. A102 now uses verified FIRST|LAST page flags, so the stock list paints without a manual filter toggle. |
| Room create/list behavior | ✅ | Core two-client create/list/join/leave/ready/camp-switch behavior is live-verified. Stock A103 room entry, shared A105/A106 state, cleanup/owner transfer, and the With32 sparse camp-seat layout are integrated. Larger-scale production policy remains separate. |
| Friends | 🟡 | v143b includes A303-A30A foundation and a local test friend path; real two-client persisted social behavior belongs to later experimental work and is not part of the public baseline. |
| Private chat | 🟡 | v143b uses a LocalFriend echo/test path. Real friend-to-friend online/offline delivery is not part of this stable baseline. |
| Clans | 🟡 | Basic create/name/persistence behavior exists. Large nested clan detail/member responses were deliberately not guessed and still require verification. |
| Inventory/equipment | 🟡 | The stable profile/property path works, but not every item/equipment/UI edge case is verified. |
| Match allocation / capacity policy | 🟡 | The stock A10A/A11A handoff and lazy per-room DS path are integrated, but production-grade pooling, capacity policy, abuse limits, and large-scale multi-host orchestration still need work. |
| Legacy kernel security-driver compatibility | 🟡 | The original client security driver can cause startup/crash problems on modern Windows independently of the emulator. Track separately in Issue #4; system-level changes are outside the supported emulator implementation. |
| TDR/protocol documentation | 🟡 | Many structures/opcodes are known, but documentation and exact field verification are incomplete. |
| Initial AP/GamePoint population | 🟡 | **Temporary local-only workaround.** On PH v1.0.0.24 the persisted server AP is copied into the verified live `LocalPlayerData.GamePoint + 0x84` field once per local `TGame.exe` PID. Normal purchase deduction/persistence remains server-authoritative. The proper native login/A50E TP-balance initialization still needs to be recovered. Disable the workaround with `AF_LOCAL_AP_SYNC=0`. |

## Broken, unavailable, or intentionally excluded

| Area | Status | Why |
|---|---:|---|
| First-time account creation | 🔴 | Experimental v95+ work is intentionally excluded because it is not considered stable. |
| First-login nickname UI | 🔴 | Not part of v143b and not yet reproducibly verified for the public baseline. |
| New-account starter inventory/profile lifecycle | 🔴 | Depends on the experimental account-creation work and is intentionally excluded. |
| Real multi-account login lifecycle | 🟡 | Concurrent local stock clients now receive distinct process-local UINs and identity-safe wire GIDs for multiplayer validation. Persistent real-account login/inventory isolation still belongs to the SQLite account work. |
| Real two-client friends/private chat | 🔴 | Not included in v143b; later work still needs proper stock-client validation before promotion. |
| Full clan UI/detail/member rendering | 🔴 | Nested ClanDetailedInfo/MemberInfo wire layouts are not fully verified. |
| Survival enemy/round backend lifecycle | 🔴 | Not implemented as a complete public stable backend. |
| Full match start → gameplay → result lifecycle | 🔴 | Not complete in v143b. |
| Match history / ranking / player-card stock UI | 🔴 | Later backend experiments exist, but exact retail-client wire/UI integration is not part of v143b. |
| Party/squad/team matchmaking | 🔴 | Not implemented in the stable public baseline. |
| Quick-match queue | 🔴 | Not implemented in v143b. |
| Mail/inbox | 🔴 | Not implemented in the stable public baseline. |
| Achievements/missions full stock UI integration | 🔴 | Not implemented in v143b. |
| Calendar/daily-login UI | 🔴 | Not part of v143b. |

## What we want to implement

These are good contribution targets:

1. **Protocol documentation** — turn recovered command IDs and packet layouts into readable, reproducible documentation.
2. **Tests** — add unit tests and sanitized packet fixtures for VERSION, AUTH, DIR, ROLE, and ZONE behavior.
3. **PvE result/reward lifecycle** — recover authoritative completion plus the stock results/rewards presentation for every supported stock-selected PvE map, then award/persist EXP/AP exactly once.
4. **Two-client social verification** — implement and verify friends, presence, friend requests, private chat, and reconnect behavior without depending on the broken first-login work.
5. **Clan completion** — recover and verify the nested clan detail/member structures used by the stock PH client.
6. **Existing-account persistence cleanup** — make stable existing-profile persistence easier to configure and test.
7. **PvE lifecycle follow-up** — current priority: authoritative round completion, reward calculation/persistence, and stock client result/reward UI now that the lobby/room and generic DS handoff paths are integrated.
8. **Dedicated-server scaling and capacity controls** — harden DS pooling, capacity rejection, one-lobby-per-player rules, rate limits, idempotency, and multi-host orchestration.
9. **Match lifecycle** — room start, loading, gameplay session, match completion, rewards/results, and clean teardown.
10. **Developer tooling** — packet decoders, protocol inspectors, sanitized logging, automated smoke tests, and reproducible test harnesses.

## Promotion rule

A feature should not move into the stable public baseline just because a backend implementation exists.

Before promotion to `main`, we want evidence that:

- the expected stock Assault Fire PH client request is observed;
- the response schema is based on verified protocol evidence rather than guessed nested structures;
- the feature does not regress the existing v143b login/profile path or solved PvE runtime;
- secrets, copyrighted assets, and personal data are not included;
- reproduction steps are documented.

If you are researching an incomplete feature, opening an issue with logs, packet IDs, sanitized hex, or static-analysis findings is already a useful contribution.

## Solved PvE handoff and map selection

The v143b server, lazy DS spawner, v48 AFDEV loader and v9 multi-peer latch bridge are integrated. A10A is reserve-only and seeds the selected room map/settings; A11E can replace them before start; A3A0/A113 arm the match path; AFDEV starts on the first valid DS UDP packet; SESSION_READY is gated by the verified runtime state. See [PVE_RUNTIME.md](PVE_RUNTIME.md).
