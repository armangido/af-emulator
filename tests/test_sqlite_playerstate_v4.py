#!/usr/bin/env python3
from pathlib import Path
import importlib.util
import sqlite3
import tempfile
import py_compile

ROOT = Path(__file__).resolve().parents[1]
SERVER = ROOT / "server" / "assaultfire_server_v143b.py"
SPAWNER = ROOT / "server" / "assaultfire_ds_spawner.py"
DBMOD = ROOT / "server" / "player_db.py"
ACCOUNTDB = ROOT / "server" / "account_db.py"

for p in (SERVER, SPAWNER, DBMOD, ACCOUNTDB):
    py_compile.compile(str(p), doraise=True)

spec = importlib.util.spec_from_file_location("player_db_v4_test", DBMOD)
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)


def prop(gid, item_id, owner=0, loc=12):
    return {
        "gid": gid,
        "item_id": item_id,
        "owner_gid": owner,
        "location": loc,
        "durability": 100,
        "durability_max": 100,
        "avail_hours": 87600,
        "validity": 87600,
        "gain_type": 1,
    }


def state(ap=100000, gp=100000, mp=100000, item=100001):
    return {
        "version": 1,
        "wallet": {"ap": ap, "gp": gp, "mp": mp},
        "current_role_gid": 42953967927297,
        "current_bag_gid": 42953967927298,
        "next_gid": 42953967927310,
        "inventory": [
            prop(42953967927297, item, 1, 10),
            prop(42953967927298, 500001, 1, 12),
        ],
    }


with tempfile.TemporaryDirectory() as td:
    db_path = Path(td) / "assaultfire_accounts.sqlite3"
    db = mod.PlayerDatabase(db_path)

    # Same AP login survives process/repository recreation with the same UIN.
    u1 = db.resolve_identity("asdasdasd")
    assert u1 == 10001
    db2 = mod.PlayerDatabase(db_path)
    assert db2.resolve_identity("ASDASDASD") == u1

    # Different login is isolated.
    u2 = db.resolve_identity("otherplayer")
    assert u2 != u1

    # One-time legacy import belongs only to the first state created.
    legacy = state(ap=77777, gp=66666, mp=55555, item=123456)
    p1, created, imported = db.ensure_player_state(
        u1, state(), legacy_state=legacy, legacy_source="legacy.json"
    )
    assert created and imported
    assert p1["wallet"] == {"ap": 77777, "gp": 66666, "mp": 55555}
    assert any(x["item_id"] == 123456 for x in p1["inventory"])

    p2, created2, imported2 = db.ensure_player_state(
        u2, state(ap=22222), legacy_state=legacy, legacy_source="legacy.json"
    )
    assert created2 and not imported2
    assert p2["wallet"]["ap"] == 22222

    # Nickname is profile-scoped and persistent by stable UIN.
    db.save_nickname(u1, "NickProbe42")
    assert db2.load_nickname(u1) == "NickProbe42"
    assert db2.load_nickname(u2) is None

    # Wallet/inventory/role/bag persist together.
    p1 = db.load_player_state(u1)
    p1["wallet"]["ap"] -= 200
    p1["current_bag_gid"] = 42953967927298
    p1["inventory"].append(prop(42953967927301, 999999))
    db.save_player_state(u1, p1, reason="unit-buy")
    reloaded = db2.load_player_state(u1)
    assert reloaded["wallet"]["ap"] == 77577
    assert any(x["item_id"] == 999999 for x in reloaded["inventory"])

    # A malformed save must roll back profile+wallet+inventory atomically.
    before = db2.load_player_state(u1)
    broken = db2.load_player_state(u1)
    broken["wallet"]["ap"] = 1
    broken["inventory"].append(dict(broken["inventory"][0]))  # duplicate gid
    try:
        db2.save_player_state(u1, broken, reason="must-rollback")
        raise AssertionError("duplicate inventory GID unexpectedly committed")
    except mod.PlayerDBError:
        pass
    after = db2.load_player_state(u1)
    assert after == before

    # Account registration and game identities share one UIN namespace.
    aspec = importlib.util.spec_from_file_location("account_db_v4_test", ACCOUNTDB)
    adb = importlib.util.module_from_spec(aspec)
    aspec.loader.exec_module(adb)
    old_rounds = adb.PBKDF2_ITERATIONS
    adb.PBKDF2_ITERATIONS = 1000
    try:
        # Registering an already-seen AP login adopts the existing game UIN.
        account = adb.create_account(
            "asdasdasd", "a strong test password", db_path=db_path
        )
        assert account["uin"] == u1

        # A fresh registered account must not collide with u2/game identities.
        registered = adb.create_account(
            "registered", "another strong password", db_path=db_path
        )
        assert registered["uin"] not in {u1, u2}
        assert db.resolve_identity("registered") == registered["uin"]
    finally:
        adb.PBKDF2_ITERATIONS = old_rounds

source = SERVER.read_text(encoding="utf-8")
assert 'print("[BOOT] BUILD=v143b-' in source
assert "PLAYER_DB = PlayerDatabase()" in source
assert "auth_login_name, auth_account = authenticate_ap_verify_body(" in source
assert "if auth_account is None:" in source
assert "error_code=1" in source
assert 'auth_uid = int(auth_account["uin"])' in source
assert "resolved_uid = _r12_uid_for_login(_auth_pid, auth_login_name)" in source
assert "_v140_select_player(role_state[\"uin\"])" in source
assert "uin = _V140_PLAYER_STATE.save(" in source
assert "moneyflow_rows=moneyflow_rows" in source
assert "os.replace(tmp, V140_MALL_STATE_PATH)" not in source
assert "PLAYER_DB.claim_nickname(" in source
assert "legacy JSON import" in source

print("SQLITE PLAYERSTATE v4 TEST: PASS")
