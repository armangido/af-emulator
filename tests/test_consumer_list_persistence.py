from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ConsumerListPersistenceTests(unittest.TestCase):
    def test_moneyflow_is_durable_and_wire_replayable(self):
        with tempfile.TemporaryDirectory() as td:
            env = os.environ.copy()
            env.update(
                {
                    "AF_ACCOUNT_DB": str(Path(td) / "accounts.sqlite3"),
                    "AF_RUNTIME_MODE": "production",
                    "AF_DEV_WEB": "0",
                }
            )
            code = r"""
import os
import struct
import time

import assaultfire_server_v143b as s
from player_db import PlayerDatabase

uin = 10001
s._v140_select_player(uin)
wallet = s._v140_wallet()

# These are authoritative POST-purchase balances.
wallet["ap"] = 135413
wallet["gp"] = 18055
wallet["mp"] = 86035

epoch = 1_700_000_000
rows = s._v140_make_purchase_moneyflow_rows(
    session_uin=uin,
    consume_tp=9,
    consume_gp=16500,
    consume_mp=20,
    occurred_at=epoch,
    details="Persistence Test",
    commodity_ids=[200001, 200002],
)
assert [row["money_type"] for row in rows] == [
    s.MONEYTYPE_TP,
    s.MONEYTYPE_GP,
    s.MONEYTYPE_MP,
]
assert [row["number"] for row in rows] == [-9, -16500, -20]
assert [row["current"] for row in rows] == [135413, 18055, 86035]
assert all(row["reason"] == s.MONEYREASON_BUY for row in rows)

# Wallet/inventory state and history rows commit in the same SQLite transaction.
s._v140_save_state(
    "consumer-list-persistence-test",
    moneyflow_rows=rows,
)

persisted = s.PLAYER_DB.load_moneyflow(uin, limit=10)
assert len(persisted) == 3
assert [row["money_type"] for row in persisted] == [1, 2, 3]
assert [row["number"] for row in persisted] == [-9, -16500, -20]
assert [row["current"] for row in persisted] == [135413, 18055, 86035]
assert all(row["occurred_at"] == epoch for row in persisted)
assert all(row["details"] == "Persistence Test" for row in persisted)
assert all(row["commodity_ids"] == [200001, 200002] for row in persisted)

# A completely new DB object sees the same rows: this is restart persistence,
# not an in-memory cache.
db2 = PlayerDatabase(os.environ["AF_ACCOUNT_DB"])
persisted2 = db2.load_moneyflow(uin, limit=10)
assert persisted2 == persisted
assert db2.counts()["player_moneyflow"] == 3

# Verify a persisted timestamp is reproducible as the exact 26-byte wire row.
row = persisted2[0]
wire = s._v140_pack_moneyflow_record(
    uin,
    row["money_type"],
    row["number"],
    row["current"],
    reason=row["reason"],
    when=s._v140_moneyflow_datetime_now(row["occurred_at"]),
)
assert len(wire) == 26
assert struct.unpack_from(">Q", wire, 0)[0] == uin
assert wire[16] == 1
assert struct.unpack_from(">i", wire, 17)[0] == -9
assert struct.unpack_from(">i", wire, 21)[0] == 135413
assert wire[25] == 2

# TDR datetime is a whole 8-byte scalar. Reverse the wire value back to the
# native x86 layout and compare to localtime(epoch).
native_dt = wire[8:16][::-1]
year, month, day, hour, minute, second = struct.unpack("<hBBhBB", native_dt)
tm = time.localtime(epoch)
assert (year, month, day, hour, minute, second) == (
    tm.tm_year,
    tm.tm_mon,
    tm.tm_mday,
    tm.tm_hour,
    tm.tm_min,
    tm.tm_sec,
)
"""
            result = subprocess.run(
                [sys.executable, "-c", code],
                cwd=ROOT / "server",
                env=env,
                text=True,
                capture_output=True,
                timeout=30,
            )

        self.assertEqual(
            result.returncode,
            0,
            msg=(
                "Consumer List persistence probe failed:\n"
                f"{result.stdout}\n{result.stderr}"
            ),
        )


if __name__ == "__main__":
    unittest.main()
