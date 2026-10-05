from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

class PVERuntimeTests(unittest.TestCase):
    def text(self, rel):
        return (ROOT / rel).read_text(encoding="utf-8", errors="replace")

    def test_server_uses_lazy_ds_start_flow(self):
        s = self.text("server/assaultfire_server_v143b.py")
        self.assertIn("A10A reserve only", s)
        self.assertIn("A3A0/A113 arm bridge + A11A", s)
        self.assertIn("0xA11E", s)

    def test_loader_requires_verified_ready_state(self):
        s = self.text("tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py")
        self.assertIn("SESSION_READY", s)
        self.assertIn("zero_dskey", s)
        self.assertIn("native_movement", s)

    def test_loader_builds_private_afdev_copy_and_validates_runtime_signatures(self):
        s = self.text("tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py")
        self.assertIn('source_exe = game_dir / "TGame.exe"', s)
        self.assertIn("shutil.copy2(source_exe, exe)", s)
        self.assertIn("without whole-file hash gating", s)
        self.assertIn("runtime patch-site signatures will still be validated", s)
        self.assertIn("every required patch site is validated before execution resumes", s)
        self.assertIn("verify_and_patch(", s)


    def test_loader_replicates_authoritative_pawn_yaw_to_remote_clients(self):
        s = self.text("tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py")
        self.assertIn("Pawn.Rotation.Yaw <- ViewYaw for remote-facing replication", s)
        self.assertIn(
            'emit(b"\\xC1\\xE8\\x10")                  # eax = ViewYaw',
            s,
        )
        self.assertIn(
            'emit(b"\\x89\\x83" + struct.pack("<I", PVE_ACTOR_ROTATION_OFFSET_V48 + 0x4))',
            s,
        )
        self.assertIn("PVE_MOVEAUTONOMOUS_IMPL_V48 = 0x008F24B0", s)
        self.assertIn("PVE_SERVERMOVE_ERROR_IMPL_V48 = 0x008F2620", s)

    def test_multi_peer_bridge_is_present(self):
        s = self.text("tools/bridge/af_ds_udp_bridge_v9_multi_peer_latch.py")
        self.assertIn("SESSION_READY", s)
        self.assertIn("peer", s.lower())

    def test_player_scoped_cleanup_is_present(self):
        s = self.text("server/assaultfire_ds_spawner.py")
        for marker in ("room_players", "match_players", "ROUND_ENDED"):
            self.assertIn(marker, s)

    def test_active_pve_path_auto_detects_game_dir_without_guessing_maps(self):
        server = self.text("server/assaultfire_server_v143b.py")
        spawner = self.text("server/assaultfire_ds_spawner.py")
        bridge = self.text("tools/bridge/af_ds_udp_bridge_v9_multi_peer_latch.py")
        loader = self.text("tools/server_spawner/AFDevLoader_v48_spawner_multi_instance.py")
        self.assertIn('game_dir: str = ""', spawner)
        self.assertIn('game_dir_source: str = ""', spawner)
        self.assertIn('repo_root.parent / "Binaries" / "Win32"', spawner)
        self.assertIn('game_dir_source = "repo-parent-default"', spawner)
        self.assertIn('game_dir_source = "AF_GAME_DIR"', spawner)
        self.assertIn('default_map: str = ""', spawner)
        self.assertIn('os.environ.get("AF_GAME_DIR", "")', bridge)
        self.assertIn('os.environ.get("AF_DS_DEFAULT_MAP", "")', bridge)
        self.assertIn('os.environ.get("AF_GAME_DIR", "")', loader)
        self.assertIn('os.environ.get("AF_DS_DEFAULT_MAP", "")', loader)
        self.assertIn("AF_GAME_DIR is not set", spawner)
        self.assertIn("automatic default game", spawner)
        self.assertIn("expected <repo-parent>", spawner)
        self.assertIn("game_dir_source={V143B_DS_CONFIG.game_dir_source}", server)
        self.assertIn("no resolved AFDEV map for ", spawner)
        self.assertNotIn("ZN2C_NTF_STARTMATCH legacy-non-PVE", server)
        self.assertIn("stable-v143b duplicate PVE A11A suppressed", server)
        self.assertIn(
            "Do not send the stale fixed 65008 endpoint after allocation failure.",
            server,
        )

if __name__ == "__main__":
    unittest.main()
