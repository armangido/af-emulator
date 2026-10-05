from pathlib import Path
import tempfile
import unittest

from server.assaultfire_ds_spawner import (
    AFDEV_MODE_IDS,
    DedicatedServerSpawner,
    ROOM_TARGETS,
    SpawnerConfig,
    resolve_room_target,
)

ROOT = Path(__file__).resolve().parents[1]


class MutationRoutingTests(unittest.TestCase):
    OLD_TOWN_TARGETS = {
        0x0048: ("Bio2-Capital_12_Main", "TGBioGame.TGBioMatch"),
        0x0076: ("Bio-Capital_12_Main", "TGBioGame.TGBioMatch"),
    }

    def make_spawner(self, temp_dir):
        return DedicatedServerSpawner(
            SpawnerConfig(
                enabled=True,
                max_instances=1,
                public_port_base=0,
                target_port_base=0,
                runtime_dir=Path(temp_dir) / "runtime",
                create_cooldown=0.0,
            )
        )

    def test_mutation_mode_and_both_old_town_catalog_ids_resolve(self):
        self.assertIn(0x0204, AFDEV_MODE_IDS)
        self.assertEqual(
            ROOM_TARGETS[(0x0204, 0x0027)],
            ("Bio-Capital_4_Main", "TGBioGame.TGBioMatch"),
        )
        for map_id, target in self.OLD_TOWN_TARGETS.items():
            with self.subTest(map_id=map_id):
                self.assertEqual(ROOM_TARGETS[(0x0204, map_id)], target)
                self.assertEqual(
                    resolve_room_target(0x0204, map_id, "", "PVEGame.TGSVGame"),
                    target,
                )

    def test_empty_map_string_uses_verified_mutation_target_for_reserve_and_a11e(self):
        for map_id, target in self.OLD_TOWN_TARGETS.items():
            with self.subTest(map_id=map_id), tempfile.TemporaryDirectory() as td:
                spawner = self.make_spawner(td)
                allocation = spawner.reserve_lobby(
                    owner_id=10000 + map_id,
                    map_name="",
                    mode_id=0x0204,
                    map_id=map_id,
                )
                self.assertEqual((allocation.map_name, allocation.game_class), target)

                updated = spawner.update_lobby_settings(
                    allocation.room_id,
                    mode_id=0x0204,
                    map_id=map_id,
                    sub_mode_id=0,
                    room_flags=0,
                    map_name=None,
                )
                self.assertEqual((updated.map_name, updated.game_class), target)
                spawner.shutdown_all()

    def test_current_server_patch_and_loader_have_mutation_path(self):
        server = (ROOT / "server" / "assaultfire_server_v143b.py").read_text(
            encoding="utf-8"
        )
        loader = (
            ROOT / "tools" / "server_spawner"
            / "AFDevLoader_v48_spawner_multi_instance.py"
        ).read_text(encoding="utf-8")

        # The package includes the latest main commit's A119 quit-match patch.
        self.assertIn("TGAME_ZN_NTF_QUITMATCH = 0xA119", server)
        self.assertIn("TGAME_AFDEV_MODE_IDS = frozenset(AFDEV_MODE_IDS)", server)
        self.assertIn("BIO_MODE_ID_V49 = 0x00000204", loader)
        self.assertIn("elif int(args.mode_id) == BIO_MODE_ID_V49:", loader)
        self.assertIn("Native TGBioGame.TGBioMatch startup", loader)
        self.assertIn("args.mode_id,", loader)
        self.assertIn("servermove_v4_state", loader)
        # Mutation now uses the shared native ServerMove-v4 entry; the retired
        # runtime movement-vtable bridge must not be reintroduced.
        self.assertNotIn("BIO_PC_VTABLE_V49", loader)
        self.assertNotIn("_validate_movement_vtable_v49", loader)


if __name__ == "__main__":
    unittest.main()
