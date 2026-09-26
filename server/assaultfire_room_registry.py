"""Thread-safe ephemeral match-room registry for the stable v143b backend.

The game protocol keeps room state in memory; account/progression data belongs
elsewhere. This module intentionally has no network or persistence side effects.
"""
from __future__ import annotations

import copy
import threading
import time

PLAYER_STATE_UNREADY = 8
PLAYER_STATE_READY = 9
PLAYER_FLAG_ROOM_OWNER = 4


class RoomRegistryError(ValueError):
    """Raised when a room operation cannot be completed safely."""


class RoomRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._rooms: dict[int, dict] = {}
        self._player_room: dict[int, int] = {}

    @staticmethod
    def _member(uin: int, nickname: str, seat_index: int, *, owner=False, observer=False) -> dict:
        return {
            "uin": int(uin),
            "nickname": str(nickname or f"Player{int(uin)}")[:31],
            "seat_index": int(seat_index),
            "state": PLAYER_STATE_UNREADY,
            "ready": False,
            "flags": PLAYER_FLAG_ROOM_OWNER if owner else 0,
            "spec_equip_flags": 0,
            "camp": 1,
            "observer": bool(observer),
            "joined_at": time.time(),
        }

    @staticmethod
    def _snapshot(room: dict | None) -> dict | None:
        if room is None:
            return None
        members = [copy.deepcopy(m) for m in room["members"].values()]
        members.sort(key=lambda m: (int(m["seat_index"]), int(m["uin"])))
        fighter_count = sum(1 for m in members if not m.get("observer"))
        observer_count = sum(1 for m in members if m.get("observer"))
        owner = room["members"].get(int(room["owner_uin"]))
        out = {k: copy.deepcopy(v) for k, v in room.items() if k != "members"}
        out.update(
            {
                "room_id": int(room["room_id"]),
                "display_id": int(room.get("display_id", int(room["room_id"]) & 0xFFFF or 1)),
                "qqtalk_room_id": int(room.get("qqtalk_room_id", 0)),
                "sub_channel_id": int(room.get("sub_channel_id", 1)),
                "name": str(room.get("name") or f"Room {int(room['room_id'])}"),
                "owner_uin": int(room["owner_uin"]),
                "owner_name": str(owner["nickname"] if owner else room.get("owner_name", "")),
                "match_settings_wire": bytes(room.get("match_settings_wire", b"")),
                "mode_id": int(room.get("mode_id", 0)),
                "map_id": int(room.get("map_id", 0)),
                "sub_mode_id": int(room.get("sub_mode_id", 0)),
                "flags": int(room.get("flags", 0)),
                "fighter_capacity": int(room.get("fighter_capacity", 4)),
                "observer_capacity": int(room.get("observer_capacity", 0)),
                "fighter_count": fighter_count,
                "observer_count": observer_count,
                "password": str(room.get("password", "")),
                "members": members,
                "started": bool(room.get("started", False)),
                "created_at": float(room.get("created_at", 0.0)),
            }
        )
        return out

    @staticmethod
    def _seat_ranges(room: dict, *, observer: bool):
        fighters = max(1, int(room.get("fighter_capacity", 4) or 4))
        observers = max(0, int(room.get("observer_capacity", 0) or 0))
        return range(fighters, fighters + observers) if observer else range(0, fighters)

    def _next_free_seat_locked(self, room: dict, *, observer: bool) -> int | None:
        used = {int(m["seat_index"]) for m in room["members"].values()}
        for seat in self._seat_ranges(room, observer=observer):
            if seat not in used:
                return seat
        return None

    def get_room(self, room_id: int) -> dict | None:
        with self._lock:
            return self._snapshot(self._rooms.get(int(room_id)))

    def room_for_player(self, uin: int) -> dict | None:
        with self._lock:
            room_id = self._player_room.get(int(uin))
            return self._snapshot(self._rooms.get(room_id)) if room_id is not None else None

    def require_owner(self, room_id: int, uin: int) -> dict:
        room_id, uin = int(room_id), int(uin)
        with self._lock:
            room = self._rooms.get(room_id)
            if room is None:
                raise RoomRegistryError("room-not-found")
            if uin not in room["members"]:
                raise RoomRegistryError("not-in-room")
            if int(room["owner_uin"]) != uin:
                raise RoomRegistryError(
                    f"not-room-owner:owner={int(room['owner_uin'])}:requester={uin}"
                )
            return self._snapshot(room)

    def list_rooms(self, include_started: bool = False) -> list[dict]:
        with self._lock:
            rooms = [
                self._snapshot(room)
                for room in self._rooms.values()
                if include_started or not room.get("started")
            ]
        rooms.sort(key=lambda r: (int(r.get("display_id", 0)), int(r["room_id"])))
        return rooms

    def create_room(self, room_data: dict, *, owner_uin: int, owner_name: str) -> dict:
        owner_uin = int(owner_uin)
        room_id = int(room_data["room_id"])
        with self._lock:
            if room_id in self._rooms:
                raise RoomRegistryError(f"room-already-exists:{room_id}")
            if owner_uin in self._player_room:
                raise RoomRegistryError(f"player-already-in-room:{owner_uin}")
            room = copy.deepcopy(dict(room_data))
            room["room_id"] = room_id
            room["display_id"] = int(room.get("display_id", room_id & 0xFFFF or 1))
            room["owner_uin"] = owner_uin
            room["owner_name"] = str(owner_name or f"Player{owner_uin}")[:31]
            room["fighter_capacity"] = max(1, int(room.get("fighter_capacity", 4) or 4))
            room["observer_capacity"] = max(0, int(room.get("observer_capacity", 0) or 0))
            room["password"] = str(room.get("password") or "")[:7]
            room["started"] = False
            room["created_at"] = float(room.get("created_at") or time.time())
            room["members"] = {}
            room["members"][owner_uin] = self._member(
                owner_uin, owner_name, 0, owner=True, observer=False
            )
            self._rooms[room_id] = room
            self._player_room[owner_uin] = room_id
            return self._snapshot(room)

    def join_room(self, *, uin: int, nickname: str, room_id: int, password="", observer=False):
        uin, room_id = int(uin), int(room_id)
        observer = bool(observer)
        with self._lock:
            current = self._player_room.get(uin)
            if current == room_id:
                room = self._rooms.get(room_id)
                if room is None or uin not in room["members"]:
                    raise RoomRegistryError("room-membership-corrupt")
                member = copy.deepcopy(room["members"][uin])
                existing = sorted(int(x) for x in room["members"] if int(x) != uin)
                return self._snapshot(room), member, existing
            if current is not None:
                raise RoomRegistryError(f"player-already-in-room:{current}")
            room = self._rooms.get(room_id)
            if room is None:
                raise RoomRegistryError("room-not-found")
            if room.get("started"):
                raise RoomRegistryError("room-already-started")
            expected = str(room.get("password") or "")
            if expected and str(password or "") != expected:
                raise RoomRegistryError("bad-room-password")
            seat = self._next_free_seat_locked(room, observer=observer)
            if seat is None:
                raise RoomRegistryError("room-full")
            existing = sorted(int(x) for x in room["members"])
            member = self._member(uin, nickname, seat, owner=False, observer=observer)
            room["members"][uin] = member
            self._player_room[uin] = room_id
            return self._snapshot(room), copy.deepcopy(member), existing

    def rollback_join(self, uin: int, room_id: int) -> bool:
        """Undo only a newly inserted non-owner join after downstream failure."""
        uin, room_id = int(uin), int(room_id)
        with self._lock:
            if self._player_room.get(uin) != room_id:
                return False
            room = self._rooms.get(room_id)
            if room is None:
                self._player_room.pop(uin, None)
                return False
            if int(room.get("owner_uin", 0)) == uin:
                raise RoomRegistryError("refusing-to-rollback-room-owner")
            if uin not in room["members"]:
                self._player_room.pop(uin, None)
                return False
            room["members"].pop(uin, None)
            self._player_room.pop(uin, None)
            return True

    def leave_room(self, uin: int) -> dict | None:
        uin = int(uin)
        with self._lock:
            room_id = self._player_room.pop(uin, None)
            if room_id is None:
                return None
            room = self._rooms.get(room_id)
            if room is None:
                return None
            removed = room["members"].pop(uin, None)
            if removed is None:
                return None
            old_owner = int(room["owner_uin"])
            deleted = not room["members"]
            new_owner = None
            snapshot = None
            if deleted:
                self._rooms.pop(room_id, None)
            else:
                if old_owner == uin:
                    new_owner_member = min(
                        room["members"].values(),
                        key=lambda m: (int(m["seat_index"]), int(m["uin"])),
                    )
                    new_owner = int(new_owner_member["uin"])
                    room["owner_uin"] = new_owner
                    for member in room["members"].values():
                        member["flags"] = int(member.get("flags", 0)) & ~PLAYER_FLAG_ROOM_OWNER
                    new_owner_member["flags"] |= PLAYER_FLAG_ROOM_OWNER
                snapshot = self._snapshot(room)
            return {
                "room_id": int(room_id),
                "removed": copy.deepcopy(removed),
                "old_owner_uin": old_owner,
                "new_owner_uin": new_owner,
                "deleted": deleted,
                "room": snapshot,
            }

    def set_ready(self, uin: int, ready: bool) -> dict:
        uin = int(uin)
        with self._lock:
            room_id = self._player_room.get(uin)
            room = self._rooms.get(room_id) if room_id is not None else None
            if room is None or uin not in room["members"]:
                raise RoomRegistryError("not-in-room")
            member = room["members"][uin]
            member["ready"] = bool(ready)
            member["state"] = PLAYER_STATE_READY if ready else PLAYER_STATE_UNREADY
            return self._snapshot(room)

    def reset_round_state(self, room_id: int) -> dict:
        """Return a surviving logical room to the stock pre-round state.

        A player can leave UE3 gameplay and return to the same room without
        leaving/rejoining the room itself.  In that path the previous round's
        started/ready flags must not leak into the next Ready/Start cycle.
        """
        room_id = int(room_id)
        with self._lock:
            room = self._rooms.get(room_id)
            if room is None:
                raise RoomRegistryError("room-not-found")
            room["started"] = False
            for member in room["members"].values():
                member["ready"] = False
                member["state"] = PLAYER_STATE_UNREADY
            return self._snapshot(room)

    def move_member(self, uin: int, new_seat: int, camp: int):
        uin, new_seat = int(uin), int(new_seat)
        with self._lock:
            room_id = self._player_room.get(uin)
            room = self._rooms.get(room_id) if room_id is not None else None
            if room is None or uin not in room["members"]:
                raise RoomRegistryError("not-in-room")
            member = room["members"][uin]
            if member.get("observer"):
                allowed = set(self._seat_ranges(room, observer=True))
                if new_seat not in allowed:
                    raise RoomRegistryError(f"seat-out-of-range:{new_seat}")
            elif new_seat < 0 or new_seat >= 32:
                # r20: stock PH fighter seats use sparse 32-entry IDs.
                # FighterCapacity limits population, not numeric seat-id range.
                raise RoomRegistryError(f"seat-out-of-range:{new_seat}")
            for other_uin, other in room["members"].items():
                if int(other_uin) != uin and int(other["seat_index"]) == new_seat:
                    raise RoomRegistryError(f"seat-occupied:{new_seat}")
            old_seat = int(member["seat_index"])
            member["seat_index"] = new_seat
            member["camp"] = int(camp) & 0xFF
            return self._snapshot(room), copy.deepcopy(member), old_seat

    def set_started(self, room_id: int, started: bool) -> dict:
        with self._lock:
            room = self._rooms.get(int(room_id))
            if room is None:
                raise RoomRegistryError("room-not-found")
            room["started"] = bool(started)
            return self._snapshot(room)

    def update_settings(
        self,
        room_id: int,
        *,
        match_settings_wire: bytes,
        mode_id: int,
        map_id: int,
        map_string: str,
        sub_mode_id: int,
        flags: int,
        setting_type: int = 0,
        value: int = 0,
        respawn_time: int = 0,
        recode_type: int = 0,
        live_delay_sec: int = 0,
    ) -> dict:
        """Replace the room's authoritative MatchSettings after A11E."""
        with self._lock:
            room = self._rooms.get(int(room_id))
            if room is None:
                raise RoomRegistryError("room-not-found")
            room.update(
                {
                    "match_settings_wire": bytes(match_settings_wire),
                    "mode_id": int(mode_id) & 0xFFFFFFFF,
                    "map_id": int(map_id) & 0xFFFF,
                    "map_string": str(map_string or ""),
                    "sub_mode_id": int(sub_mode_id) & 0xFFFFFFFF,
                    "flags": int(flags) & 0xFFFFFFFF,
                    "setting_type": int(setting_type) & 0xFFFF,
                    "value": int(value) & 0xFFFF,
                    "respawn_time": int(respawn_time) & 0xFFFF,
                    "recode_type": int(recode_type) & 0xFFFF,
                    "live_delay_sec": int(live_delay_sec) & 0xFFFF,
                }
            )
            return self._snapshot(room)
