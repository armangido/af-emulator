# Project Milestones

This roadmap describes the path from the current stable public baseline to a more complete Assault Fire PH local revival.

The rule for every milestone is simple:

> **Verified behavior moves forward. Guessed behavior stays experimental.**

## Milestone 0 — Public stable baseline ✅

**Status: complete**

Goal: publish a clean, reproducible starting point without unverified first-login/new-account work.

Completed:

- [x] Stable v143b backend published
- [x] VERSION service
- [x] AUTH handshake
- [x] DIR/server discovery
- [x] Existing local profile/login path
- [x] Stable shop/inventory/profile foundation
- [x] Stable clan persistence foundation
- [x] Stable v9 multi-peer DS UDP bridge
- [x] Stable v48 lazy multi-instance AFDEV PvE loader
- [x] Local hosts redirect template/helper
- [x] RSA-1024 key generation helper
- [x] Beginner setup tutorial
- [x] TGame datetime runtime compatibility patch
- [x] MIT license
- [x] Working / partial / broken status documentation
- [x] Generic PvE lifecycle and map-selection regression tests

## Milestone 1 — Reproducible local setup 🟡

**Status: active**

Goal: a new contributor can clone the repository and reproduce the known stable path with minimal manual reverse-engineering knowledge.

Tasks:

- [x] One-command RSA key generation
- [x] Automatic APClient.dat backup/install helper
- [x] Portable server key/log paths
- [x] Hosts setup helper
- [ ] Add a startup self-check for missing/incorrect files
- [ ] Integrate/automate the required TGame datetime compatibility patch
- [ ] Add a port-conflict diagnostic
- [ ] Add a simple smoke-test script for VERSION/AUTH/DIR listeners
- [ ] Document the required client-side raw-PEM APClient/TCLS compatibility step more completely
- [ ] Validate the tutorial from a clean Windows install/folder

**Exit condition:** a clean setup can reach the existing local profile path by following only the repository documentation.

## Milestone 2 — Stable lobby, rooms, social, and clans 🟡

**Status: partial**

Goal: promote only live-verified multiplayer frontend/backend behavior into the public `main` baseline.

Tasks:

- [x] Replace the synthetic single-room path with the shared dynamic room registry used by the stock lobby flow
- [x] Verify room create / list / enter / leave / ready behavior with two stock clients
- [x] Verify automatic A100/A102 first paint with FIRST|LAST page flags (no filter-toggle workaround)
- [x] Verify live A103 EnterRoomByRoomId and shared A105/A106 room state
- [x] Verify owner transfer / disconnect cleanup for the shared room
- [x] Verify PH With32 sparse camp switching (left 0/1 ↔ right 16/17) without the player row disappearing
- [ ] Verify two-client friend request / accept / remove flow
- [ ] Verify two-client private chat
- [ ] Verify reconnect/offline-delivery behavior
- [ ] Complete stock clan detail/member structures
- [ ] Verify clan UI rendering and member updates
- [ ] Add protocol tests for verified commands

**Exit condition:** two local clients can use the normal stock lobby/social/clan flows without experimental account creation.

## Milestone 3 — PvE dedicated-server handoff and map selection ✅

**Status: integrated on `main`**

The stable v143b path now carries the stock room's PvE selection into the lazy dedicated-server lifecycle instead of forcing a fixed map.

Completed:

- [x] A10A reserves DS capacity without starting AFDEV
- [x] A10A seeds ModeId / MapId / SubModeId / flags into the reservation
- [x] stock `MapString` is used by default for the room's AFDEV map
- [x] A11E can replace the reserved map/settings before A113
- [x] v9 bridge latches the first DS UDP packet and starts v48 lazily
- [x] v48 resolves the selected installed `.udk` map and opens it with `PVEGame.TGSVGame`
- [x] zero-DSKey/runtime verification gates `SESSION_READY`
- [x] player-scoped shared-DS cleanup/rejoin behavior is retained
- [x] PvE maps use the same generic stock-selected map and lazy dedicated-server path

The broader enemy/objective/round-completion/result/reward lifecycle remains separate follow-up work under the full match lifecycle milestone.

## Milestone 4 — Dedicated-server scaling and full match lifecycle 🟡

**Status: partial**

Goal: build on the now-integrated stock PvE reservation/handoff path and finish production-style capacity controls plus the full gameplay → result → lobby lifecycle.

### Current next target — PvE results and rewards

The lobby/room flow is complete enough for now. The active target is the post-match path for **every supported stock-selected PvE map**:

- [ ] Detect authoritative successful PvE completion from AFDEV/DS instead of trusting the client
- [ ] Recover the stock result/reward command and payload consumed by the retail PH client
- [ ] Show earned rewards in the stock results/rewards UI
- [ ] Award EXP and AP with difficulty-aware server rules
- [ ] Persist rewards and match history exactly once (idempotent settlement)
- [ ] Log a concise server-side reward summary for debugging/auditing
- [ ] Verify solo and two-client settlement, including reconnect/duplicate-packet safety

Tasks:

- [x] Verify the stock A10A reservation / A11A assignment path used by the current client
- [x] Integrate lazy per-room v9 bridge + v48 AFDEV startup
- [x] Gate client release on verified `SESSION_READY`
- [x] Preserve player-scoped cleanup for shared PvE sessions
- [ ] Enforce and regression-test DS-pool capacity rejection
- [ ] Enforce one active owned lobby per player plus account/IP cooldowns and idempotent create handling
- [ ] Complete authoritative round/match completion
- [ ] Complete results, rewards, EXP/AP and match-history persistence
- [ ] Verify clean result → lobby return with multiple stock clients
- [ ] Add multi-client lifecycle/capacity regression tests

**Exit condition:** stock clients can move from lobby → reserved DS → gameplay → authoritative result/rewards → lobby with capacity and abuse controls behaving predictably.

## Milestone 5 — Preservation-quality release 🔴

**Status: planned**

Goal: make the emulator useful to other preservation researchers without requiring knowledge of this project's history.

Tasks:

- [ ] Split the monolithic v143b server into readable modules without changing behavior
- [ ] Add automated protocol/unit tests
- [ ] Add sanitized packet fixtures
- [ ] Add architecture and protocol reference docs
- [ ] Add configuration files instead of source-code constants
- [ ] Improve error messages and startup diagnostics
- [ ] Add contributor issue templates for protocol research
- [ ] Document reproducible client compatibility requirements
- [ ] Replace the **temporary local AP/GamePoint process-memory initializer** with the verified native PH login/TP-balance path, then remove the `LocalPlayerData.GamePoint + 0x84` workaround
- [ ] Tag a stable release after regression testing

**Exit condition:** the stable project can be installed, understood, tested, and extended from the public repository alone.

## Not a milestone yet — first-time/new-account creation

The experimental first-time account/nickname work remains intentionally outside the public stable baseline.

It should not become a milestone until the stock PH client flow is reproducibly understood and can be implemented without destabilizing the existing working profile/login path.

## PvE runtime integration

- [x] Solved lazy PvE DS handoff
- [x] Stock room MapString reaches the DS allocation
- [x] A11E map/difficulty settings update before lazy spawn
- [x] v48 native movement/correction loader
- [x] zero-DSKey verification before SESSION_READY
- [x] v9 multi-peer first-packet latch bridge
- [x] player-scoped shared-DS cleanup
