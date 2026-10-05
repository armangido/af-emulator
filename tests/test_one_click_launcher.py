from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "START_ASSAULT_FIRE.ps1"
README = ROOT / "README.md"


class OneClickLauncherTests(unittest.TestCase):
    def text(self, path):
        return path.read_text(encoding="utf-8", errors="replace")

    def test_one_click_entrypoint_exists(self):
        self.assertTrue(SCRIPT.is_file())

    def test_script_detects_game_beside_or_around_repo(self):
        s = self.text(SCRIPT)
        self.assertIn('TCLS\\client.exe', s)
        self.assertIn('TCLS\\Tenio\\TCLS.dll', s)
        self.assertIn('Binaries\\Win32\\TGame.exe', s)
        self.assertIn('Find-GameRoot', s)

    def test_script_bootstraps_supported_python_and_requirements(self):
        s = self.text(SCRIPT)
        self.assertIn('9NQ7512CXL7T', s)
        self.assertIn('Python Install Manager', s)
        self.assertIn('install default', s)
        self.assertIn('"requirements.txt"', s)
        self.assertIn('"-m", "venv"', s)
        self.assertIn('"pip", "install"', s)
        self.assertIn('Python 3.10+', s)

    def test_existing_supported_python_is_detected_before_winget(self):
        s = self.text(SCRIPT)
        for marker in (
            '"python.exe"',
            '"python3.exe"',
            '"python312.exe"',
            '"python3.12.exe"',
            '@("py.exe", "py")',
            '"--list-paths"',
            'Resolve-SupportedPython',
        ):
            self.assertIn(marker, s)
        self.assertLess(
            s.index('foreach ($name in @('),
            s.index('Trying Windows Package Manager (winget)'),
        )

    def test_launcher_accepts_python_310_or_newer_instead_of_exact_312(self):
        s = self.text(SCRIPT)
        self.assertIn('function Test-SupportedPythonPath', s)
        self.assertIn("sys.version_info >= (3,10) and sys.version_info < (4,0)", s)
        self.assertIn('Get-ChildItem -LiteralPath $scripts -Filter "python*.exe"', s)
        self.assertIn('Where-Object { $_.Name -notmatch "(?i)^pythonw" }', s)
        self.assertNotIn('function Test-Python312Path', s)
        self.assertNotIn('function Ensure-Python312', s)

    def test_python_install_manager_runtime_is_found_without_path_alias(self):
        s = self.text(SCRIPT)
        self.assertIn('function Find-PythonInstallManager', s)
        self.assertIn('function Find-ManagedPython', s)
        self.assertIn('list --format=exe --one 3', s)
        self.assertIn('Microsoft\\WindowsApps\\pymanager.exe', s)
        self.assertIn('Add-PythonManagerAliasesToPath', s)

    def test_manual_readme_uses_version_agnostic_python_selector(self):
        s = self.text(README)
        self.assertIn('py -3 --version', s)
        self.assertIn('py -3 -m venv .venv', s)
        self.assertNotIn('py -3.12', s)

    def test_launcher_prints_revision_for_stale_zip_diagnosis(self):
        s = self.text(SCRIPT)
        self.assertIn('2026-10-05-oneclick-v36-servermove-v4', s)
        self.assertIn('Launcher revision: $LAUNCHER_REVISION', s)

    def test_launcher_asks_before_replacing_private_key(self):
        s = self.text(SCRIPT)
        self.assertIn('Do you have your own PRIVATE.PEM here and want to keep using it?', s)
        self.assertIn('Do you have your own PRIVATE.PEM key to use?', s)
        self.assertIn('Your PRIVATE.PEM was preserved', s)
        self.assertIn('Prompt "Replace your PRIVATE.PEM and APClient.dat with a new matching pair?"', s)
        self.assertIn('-DefaultYes $false -DoNotRemember', s)
        self.assertIn('Your PRIVATE.PEM was preserved', s)
        self.assertIn('forceNewPair -or', s)

    def test_elevated_launch_helper_saves_failure_diagnostics(self):
        s = self.text(SCRIPT)
        self.assertIn('af_tgame_launch_helper.log', s)
        self.assertIn('Tee-Object -FilePath', s)
        self.assertIn('See helper log: $helperLog', s)

    def test_helper_keeps_native_python_warnings_non_fatal(self):
        s = self.text(SCRIPT)
        self.assertIn('$ErrorActionPreference = "Continue"', s)
        self.assertIn('$helperExitCode = $LASTEXITCODE', s)
        self.assertIn('$ErrorActionPreference = $savedErrorActionPreference', s)

    def test_launcher_self_elevates_before_setup(self):
        s = self.text(SCRIPT)
        self.assertIn("function Test-IsAdministrator", s)
        self.assertIn("if (-not (Test-IsAdministrator))", s)
        self.assertIn("Start-Process -FilePath $currentPowerShellExe -Verb RunAs", s)
        self.assertLess(
            s.index("Start-Process -FilePath $currentPowerShellExe -Verb RunAs"),
            s.index("Initialize-LauncherConfig"),
        )
        for switch in ("SetupOnly", "SkipPythonInstall", "KeepServer"):
            self.assertIn("if ($" + switch + ")", s)

    def test_python_launcher_default_runtime_is_accepted_when_supported(self):
        s = self.text(SCRIPT)
        self.assertIn('Python Launcher default is supported', s)
        self.assertIn('Test-SupportedPythonPath $pyLauncher.Source', s)
        self.assertIn('foreach ($minor in @(14, 13, 12, 11, 10))', s)

    def test_python_fallback_uses_latest_stable_without_minor_version_pin(self):
        s = self.text(SCRIPT)
        self.assertIn('$managerPackageId = "9NQ7512CXL7T"', s)
        self.assertIn('& $manager install default', s)
        self.assertIn('Installing the current stable Python 3 runtime...', s)
        self.assertNotIn('Python.Python.3.12', s)

    def test_manager_self_update_retries_python_runtime_install(self):
        s = self.text(SCRIPT)
        self.assertIn('for ($attempt = 1; $attempt -le 2; $attempt++)', s)
        self.assertIn('$managerUpdatedDuringInstall = $false', s)
        self.assertIn('Python install manager was successfully updated', s)
        self.assertIn(
            'if ($attempt -eq 1 -and $managerUpdatedDuringInstall)',
            s,
        )
        self.assertIn(
            'Python Install Manager updated itself; retrying runtime installation',
            s,
        )
        self.assertIn('$manager = Find-PythonInstallManager', s)

    def test_winget_output_cannot_pollute_bootstrap_python_path(self):
        s = self.text(SCRIPT)
        self.assertIn(
            '& $winget.Source install --exact --id $managerPackageId --accept-package-agreements --accept-source-agreements --disable-interactivity 2>&1 |',
            s,
        )
        self.assertIn(
            'ForEach-Object { Write-Host ([string]$_) }',
            s,
        )
        self.assertRegex(
            s,
            r'& \$winget\.Source install .*?2>&1\s*\|\s*ForEach-Object\s*\{\s*Write-Host',
        )

    def test_root_level_python_install_is_detected_before_winget(self):
        s = self.text(SCRIPT)
        self.assertIn(
            r'Get-ChildItem -LiteralPath ($systemDrive + "\") -Directory -Filter "Python*"',
            s,
        )

    def test_native_command_output_cannot_pollute_return_values(self):
        s = self.text(SCRIPT)
        self.assertIn(
            '& $Exe @Arguments 2>&1 | ForEach-Object',
            s,
        )
        self.assertIn(
            'Write-Host ([string]$_)',
            s,
        )
        self.assertIn('$exitCode = $LASTEXITCODE', s)

    def test_nonstandard_venv_python_filename_is_discovered(self):
        s = self.text(SCRIPT)
        self.assertIn('function Find-VenvPython', s)
        self.assertIn(
            'Get-ChildItem -LiteralPath $scripts -Filter "python*.exe"',
            s,
        )
        self.assertIn(
            'Where-Object { $_.Name -notmatch "(?i)^pythonw" }',
            s,
        )

    def test_existing_venv_is_persistent_across_zip_updates(self):
        s = self.text(SCRIPT)
        self.assertRegex(s, r'\$venvDir\s*=\s*Join-Path\s+\$runtimeRoot\s+"venv"')
        self.assertRegex(
            s,
            r'\$legacyPersistentDir\s*=\s*Join-Path\s+\$runtimeRoot\s+"venv-py312"',
        )
        self.assertIn(
            'Reusing legacy persistent runtime',
            s,
        )
        self.assertIn(
            'Creating persistent Python environment (FIRST TIME ONLY)',
            s,
        )
        self.assertIn(
            'Preserve-BadRuntime',
            s,
        )
        self.assertNotIn(
            'Remove-Item -LiteralPath $venvDir -Recurse -Force',
            s,
        )

    def test_main_uses_game_root_persistent_runtime(self):
        s = self.text(SCRIPT)
        self.assertIn(
            'Ensure-SupportedPython $repoRoot $gameRoot',
            s,
        )
        self.assertIn(
            'Ensure-Venv $repoRoot $gameRoot $bootstrapPython',
            s,
        )

    def test_existing_dependencies_can_skip_pip_reinstall(self):
        s = self.text(SCRIPT)
        self.assertIn(
            'Existing Python dependencies verified; no pip install needed.',
            s,
        )
        self.assertIn(
            '42 <= major < 47',
            s,
        )
        self.assertIn(
            'FIRST TIME OR REQUIREMENTS CHANGED',
            s,
        )

    def test_runtime_components_inherit_the_launcher_admin_token(self):
        s = self.text(SCRIPT)
        self.assertIn(
            "The emulator server inherits this launcher's Administrator token.",
            s,
        )
        self.assertIn(
            "The TGame launch helper inherits this launcher's Administrator token.",
            s,
        )
        self.assertEqual(s.count("-Verb RunAs"), 1)
        self.assertIn("$env:AF_DS_PYTHON=", s)
        self.assertIn("patch_tcls_suspended_launch.py", s)

    def test_launcher_waits_for_flushed_tcls_readiness_before_start(self):
        s = self.text(SCRIPT)
        self.assertIn('" -u " + (Quote-PS $helper)', s)
        self.assertIn('Wait-ForTclsHelperArmed $helperLog $helperWindow 120', s)
        self.assertIn('Remove-Item -LiteralPath $helperLog -Force', s)
        self.assertIn('New-Item -ItemType File -Path $helperLog -Force', s)

    def test_elevated_command_keeps_env_variable_names_literal(self):
        s = self.text(SCRIPT)
        for name in (
            "AF_CLIENT_ROOT",
            "AF_GAME_DIR",
            "AF_DS_SPAWNER_ENABLED",
            "AF_DS_PYTHON",
        ):
            self.assertIn(
                f"'$env:{name}='",
                s,
            )
            self.assertNotIn(
                f'"$env:{name}="',
                s,
            )

    def test_launcher_path_is_initialized_before_console_helper(self):
        s = self.text(SCRIPT)
        self_match = re.search(r'\$self\s*=\s*\$MyInvocation\.MyCommand\.Path', s)
        helper_match = re.search(r'\$consoleHelper\s*=\s*Join-Path\s+\$PSScriptRoot', s)
        self.assertIsNotNone(self_match)
        self.assertIsNotNone(helper_match)
        self.assertLess(
            self_match.start(),
            helper_match.start(),
        )

    def test_console_windows_disable_quickedit_blocking(self):
        s = self.text(SCRIPT)
        helper = self.text(ROOT / "tools" / "setup" / "af_console_nonblocking.ps1")
        self.assertIn('af_console_nonblocking.ps1', s)
        self.assertGreaterEqual(
            s.count('Disable-AFConsoleBlockingSelection'),
            3,
        )
        self.assertIn('ENABLE_QUICK_EDIT_MODE = 0x0040', helper)
        self.assertIn('ENABLE_EXTENDED_FLAGS = 0x0080', helper)
        self.assertIn('mode &= ~ENABLE_QUICK_EDIT_MODE', helper)
        self.assertIn('SetConsoleMode', helper)

    def test_permanent_tcls_patch_is_prompted_and_hash_guarded(self):
        s = self.text(SCRIPT)
        self.assertIn(
            '13EAD403452E0F25CF00658369BF4BF5FF34ED1B16027F7833FB27D398386CD1',
            s,
        )
        self.assertIn(
            '3FF351E0ADB594D7544E28DB2E966A6D6EB548E9DF70DAAF4DAF58F2EE438D56',
            s,
        )
        self.assertIn('patch_tcls_apclient_raw_pem.py', s)
        self.assertIn('Patch TCLS.dll permanently', s)
        self.assertIn('Continue without patching it again?', s)
        self.assertIn('TCLS.dll is already patched. Continue without patching it again?', s)
        self.assertIn('Do you believe this TCLS.dll is already custom-patched?', s)
        self.assertIn('exact verified patched hash', s)

    def test_script_prepares_local_afdev_from_owned_tgame(self):
        s = self.text(SCRIPT)
        expected = 'B4273F2658CA94EEBC559A997FDFCD02D51E77CE75B892250C1DB7FB80C70B51'
        self.assertIn(expected, s)
        self.assertIn('TGame_AFDEV.exe', s)
        self.assertIn(
            'Copy-Item -LiteralPath $tgame -Destination $afdev -Force',
            s,
        )
        self.assertNotIn('Invoke-WebRequest', s)

    def test_script_handles_keys_hosts_server_helper_and_client(self):
        s = self.text(SCRIPT)
        for marker in (
            'generate_local_rsa_keypair.py',
            'diagnose_tcls_apclient.py',
            'setup_assaultfire_hosts.ps1',
            'assaultfire_server_v143b.py',
            'patch_tcls_suspended_launch.py',
            'AF_CLIENT_ROOT',
            'AF_GAME_DIR',
            'AF_DS_SPAWNER_ENABLED',
            'preflight_status.json',
            'Start-Process -FilePath $clientExe',
        ):
            self.assertIn(marker, s)


    def test_launcher_preferences_are_local_and_documented(self):
        s = self.text(SCRIPT)
        config_example = ROOT / "launcher.config.example.json"
        self.assertIn('launcher.config.json', s)
        self.assertIn('function Read-LauncherChoice', s)
        self.assertIn('function Get-TGameBinaryCheck', s)
        self.assertIn('tools\\patches\\tgame_binary.py', s)
        self.assertNotIn('ConfirmTGame_', s)
        self.assertTrue(config_example.is_file())
        self.assertIn('launcher.config.json', self.text(ROOT / ".gitignore"))
        self.assertIn('launcher.config.json', self.text(README))

    def test_readme_promotes_one_click_path(self):
        s = self.text(README)
        self.assertIn('Easiest way — use the one-click script', s)
        self.assertIn('START_ASSAULT_FIRE.ps1', s)
        self.assertIn('TGame_AFDEV.exe', s)
        self.assertIn('TGame.exe.bak', s)
        self.assertIn('.afdt', s)
        self.assertIn('section-header slot', s)
        self.assertNotIn('The original `TGame.exe` is not changed on disk.', s)

    def test_localized_readmes_disclose_permanent_tgame_patch_and_backup(self):
        for path in ROOT.glob("README-*.md"):
            if path.name == "README-LANGUAGES.md":
                continue
            with self.subTest(readme=path.name):
                self.assertIn("TGame.exe.bak", self.text(path))
                self.assertIn(".afdt", self.text(path))


    def test_launcher_waits_for_tcls_armed_before_prompting_for_start(self):
        s = self.text(SCRIPT)
        self.assertIn("function Wait-ForTclsHelperArmed", s)
        self.assertIn("Remove-Item -LiteralPath $helperLog", s)
        self.assertIn("TCLS ARMED", s)
        self.assertIn("if ($HelperProcess.HasExited) {", s)
        self.assertIn("Timed out after $TimeoutSeconds seconds waiting", s)
        self.assertIn("do not click START yet", s)
        self.assertIn(" -u ", s)

        client_launch = s.index("Start-Process -FilePath $clientExe")
        armed_wait = s.index("Wait-ForTclsHelperArmed $helperLog $helperWindow")
        start_instructions = s.index('Write-Title "YOU ARE DONE WITH SETUP"')
        self.assertLess(client_launch, armed_wait)
        self.assertLess(armed_wait, start_instructions)
        self.assertNotIn("Start-Sleep -Milliseconds 700", s)

if __name__ == "__main__":
    unittest.main()
