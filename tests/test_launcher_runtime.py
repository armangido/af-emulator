"""Execute launcher functions with real Windows Python, including paths with spaces."""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent
if str(TESTS_DIR) not in sys.path:
    sys.path.insert(0, str(TESTS_DIR))

from tgame_test_fixtures import write_tgame_fixture
LOAD_FUNCTIONS = r"""
$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0
Import-Module Microsoft.PowerShell.Utility -ErrorAction Stop
# Some hosted PowerShell 5.1 images omit the Utility module from PSModulePath.
# Supply the same SHA-256 result shape used by the launcher when the cmdlet is absent.
if (-not (Get-Command Get-FileHash -ErrorAction SilentlyContinue)) {
    function Get-FileHash {
        param(
            [Parameter(Mandatory=$true)][string]$LiteralPath,
            [string]$Algorithm = "SHA256"
        )
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $stream = [System.IO.File]::OpenRead($LiteralPath)
            try {
                $bytes = $sha.ComputeHash($stream)
            } finally {
                $stream.Dispose()
            }
        } finally {
            $sha.Dispose()
        }
        [pscustomobject]@{
            Algorithm = "SHA256"
            Hash = ([System.BitConverter]::ToString($bytes) -replace "-", "")
            Path = $LiteralPath
        }
    }
}
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    $env:AF_TEST_LAUNCHER, [ref]$tokens, [ref]$parseErrors
)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
foreach ($fn in $ast.FindAll({
    param($node)
    $node -is [System.Management.Automation.Language.FunctionDefinitionAst]
}, $false)) {
    . ([scriptblock]::Create($fn.Extent.Text))
}
$script:LAUNCHER_CONFIG_PATH = Join-Path $env:AF_TEST_ROOT "launcher.config.json"
Initialize-LauncherConfig
"""


@unittest.skipUnless(os.name == "nt", "Windows launcher integration")
class LauncherRuntimeTests(unittest.TestCase):
    def run_launcher(self, shell, body, extra_env=None):
        with tempfile.TemporaryDirectory(prefix="AF runtime with spaces ") as tmp:
            env = dict(os.environ)
            env.update(
                AF_TEST_LAUNCHER=str(ROOT / "START_ASSAULT_FIRE.ps1"),
                AF_TEST_PYTHON=sys.executable,
                AF_TEST_ROOT=str(Path(tmp).resolve()),
                AF_TEST_REPO=str(ROOT),
            )
            if extra_env:
                env.update(extra_env)
            result = subprocess.run(
                [shell, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                 "-Command", LOAD_FUNCTIONS + body],
                env=env, capture_output=True, text=True, errors="replace", timeout=180,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("AF_RUNTIME_TEST_PASS", result.stdout)

    def shells(self):
        shells = [shutil.which(name) for name in ("powershell.exe", "pwsh.exe")]
        self.assertTrue(all(shells), "CI must provide Windows PowerShell 5.1 and PowerShell 7")
        return shells

    def test_created_venv_is_discovered_with_stale_exit_code(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$venv = Join-Path $env:AF_TEST_ROOT "runtime with spaces"
Invoke-Checked -Exe $env:AF_TEST_PYTHON -Arguments @("-m", "venv", $venv) -Description "test venv"
$candidate = Join-Path $venv "Scripts\python.exe"
if (-not (Test-Path -LiteralPath $candidate)) { throw "venv executable missing" }
foreach ($staleCode in @(0, 1)) {
    $global:LASTEXITCODE = $staleCode
    $found = Test-SupportedPythonPath $candidate
    if (-not $found) {
        Write-Host ($Error | Out-String)
        & $candidate -c "import sys; print(sys.version); print(sys.executable)"
        throw "Real supported venv rejected with prior exit code $staleCode"
    }
    if ($found -ne $candidate) { throw "Probe returned wrong path: $found" }
    $global:LASTEXITCODE = $staleCode
    $discovered = Find-VenvPython $venv
    if ($discovered -ne $candidate) { throw "Venv discovery returned wrong path: $discovered" }
}
Write-Host "AF_RUNTIME_TEST_PASS"
""")

    def test_native_warnings_succeed_and_nonzero_exit_fails(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$PSNativeCommandUseErrorActionPreference = $true
$output = Invoke-Checked -Exe $env:AF_TEST_PYTHON -Arguments @(
    "-c", "import sys; print('ordinary warning', file=sys.stderr); print('normal output')"
) -Description "warning with success"
if ($null -ne $output) { throw "Native output leaked into function result" }
$failed = $false
try {
    Invoke-Checked -Exe $env:AF_TEST_PYTHON -Arguments @(
        "-c", "import sys; print('failure', file=sys.stderr); sys.exit(7)"
    ) -Description "expected native failure"
} catch {
    if ($_.Exception.Message -notmatch "failed with exit code 7") { throw }
    $failed = $true
}
if (-not $failed) { throw "Native failure was accepted" }
if ($ErrorActionPreference -ne "Stop") { throw "Error preference was changed" }
if (-not $PSNativeCommandUseErrorActionPreference) { throw "Native preference was changed" }
Write-Host "AF_RUNTIME_TEST_PASS"
""")

    def test_ensure_venv_installs_dependencies_and_reuses_runtime(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$first = Ensure-Venv $env:AF_TEST_REPO $env:AF_TEST_ROOT $env:AF_TEST_PYTHON
foreach ($staleCode in @(0, 1)) {
    $global:LASTEXITCODE = $staleCode
    if (-not (Test-VenvDependencies $first)) {
        throw "Installed dependency rejected with prior exit code $staleCode"
    }
}
if ($first -is [array] -or -not $first) { throw "Bootstrap returned polluted or empty path" }
if (-not (Test-VenvDependencies $first)) { throw "Fresh venv dependencies invalid" }
$stamp = (Get-Item -LiteralPath $first).LastWriteTimeUtc
$second = Ensure-Venv $env:AF_TEST_REPO $env:AF_TEST_ROOT $env:AF_TEST_PYTHON
if ($second -ne $first) { throw "Existing runtime was not reused" }
if ((Get-Item -LiteralPath $second).LastWriteTimeUtc -ne $stamp) {
    throw "Reused runtime executable was replaced"
}
Write-Host "AF_RUNTIME_TEST_PASS"
""")



    def test_ensure_afdev_permanently_patches_verified_clean_tgame_with_backup(self):
        with tempfile.TemporaryDirectory(prefix="AF TGame fixtures ") as fixtures:
            unpatched = write_tgame_fixture(Path(fixtures) / "unpatched.exe", "unpatched")
            patched = write_tgame_fixture(Path(fixtures) / "patched.exe", "patched")
            relocated = write_tgame_fixture(
                Path(fixtures) / "relocated.exe", "relocated"
            )
            for shell in self.shells():
                with self.subTest(shell=shell):
                    self.run_launcher(shell, r"""
$EXPECTED_TGAME_SHA256 = "B4273F2658CA94EEBC559A997FDFCD02D51E77CE75B892250C1DB7FB80C70B51"
function Read-Host([string]$Prompt) { throw "TGame verification must not ask for confirmation: $Prompt" }
function New-TestGame([string]$Name, [string]$Source) {
    $gameRoot = Join-Path $env:AF_TEST_ROOT $Name
    $win32 = Join-Path $gameRoot "Binaries\Win32"
    New-Item -ItemType Directory -Path $win32 -Force | Out-Null
    Copy-Item -LiteralPath $Source -Destination (Join-Path $win32 "TGame.exe")
    return $gameRoot
}
# Keep this integration test focused on Ensure-AFDev's datetime/backup/copy
# control flow. The native ServerMove-v4 reconstruction has dedicated tests.
$script:AF_TEST_SERVERMOVE_PATCHED = @{}
function Get-ServerMoveBinaryCheck(
    [string]$RepoRoot,
    [string]$Path,
    [string]$VenvPython,
    [switch]$Apply
) {
    if ($Apply) {
        $script:AF_TEST_SERVERMOVE_PATCHED[$Path] = $true
        return [pscustomobject]@{
            status = "patched"
            message = "test ServerMove-v4 applied"
        }
    }
    if ($script:AF_TEST_SERVERMOVE_PATCHED.ContainsKey($Path)) {
        return [pscustomobject]@{
            status = "already-patched"
            message = "test ServerMove-v4 present"
        }
    }
    return [pscustomobject]@{
        status = "unpatched-compatible"
        message = "test ServerMove-v4 compatible"
    }
}
foreach ($candidate in @(
    @{ Name = "compatible clean build"; Source = $env:AF_TEST_TGAME_UNPATCHED; Status = "clean" },
    @{ Name = "verified patched build"; Source = $env:AF_TEST_TGAME_PATCHED; Status = "patched" },
    @{ Name = "relocated patch site"; Source = $env:AF_TEST_TGAME_RELOCATED; Status = "relocated" }
)) {
    $gameRoot = New-TestGame $candidate.Name $candidate.Source
    $tgame = Join-Path $gameRoot "Binaries\Win32\TGame.exe"
    $sourceHash = Get-Sha256 $tgame
    if ($sourceHash -eq $EXPECTED_TGAME_SHA256) { throw "Test fixture unexpectedly matches stock hash" }
    Ensure-AFDev $gameRoot $env:AF_TEST_PYTHON $env:AF_TEST_REPO
    $afdev = Join-Path $gameRoot "Binaries\Win32\TGame_AFDEV.exe"
    $finalHash = Get-Sha256 $tgame
    if ((Get-Sha256 $afdev) -ne $finalHash) { throw "$($candidate.Status) AFDEV copy does not match patched source" }
    $finalCheck = Get-TGameBinaryCheck $env:AF_TEST_REPO $tgame $env:AF_TEST_PYTHON
    if ($finalCheck.status -ne "already-patched") { throw "$($candidate.Status) TGame is not verified patched: $($finalCheck.message)" }
    if ($candidate.Status -eq "clean" -or $candidate.Status -eq "relocated") {
        $backup = "$tgame.bak"
        if (-not (Test-Path -LiteralPath $backup -PathType Leaf)) { throw "$($candidate.Status) TGame backup is missing" }
        if ((Get-Sha256 $backup) -ne $sourceHash) { throw "$($candidate.Status) TGame backup does not match its original bytes" }
        if ($finalHash -eq $sourceHash) { throw "$($candidate.Status) TGame was not permanently patched" }
    } elseif ($finalHash -ne $sourceHash) {
        throw "Already-patched TGame was unexpectedly modified"
    }
}

$invalidRoot = Join-Path $env:AF_TEST_ROOT "unknown invalid build"
$invalidWin32 = Join-Path $invalidRoot "Binaries\Win32"
New-Item -ItemType Directory -Path $invalidWin32 -Force | Out-Null
$invalidTGame = Join-Path $invalidWin32 "TGame.exe"
[System.IO.File]::WriteAllBytes($invalidTGame, [byte[]](1, 2, 3, 4, 5))
$invalidAfdev = Join-Path $invalidWin32 "TGame_AFDEV.exe"
$rejected = $false
try {
    Ensure-AFDev $invalidRoot $env:AF_TEST_PYTHON $env:AF_TEST_REPO
} catch {
    if ($_.Exception.Message -notmatch "patch-site signature is not recognized") { throw }
    $rejected = $true
}
if (-not $rejected) { throw "Unknown TGame binary was accepted" }
if (Test-Path -LiteralPath $invalidAfdev) { throw "Unknown TGame caused an AFDEV copy" }
Write-Host "AF_RUNTIME_TEST_PASS"
                    """, {
                        "AF_TEST_TGAME_UNPATCHED": str(unpatched),
                        "AF_TEST_TGAME_PATCHED": str(patched),
                        "AF_TEST_TGAME_RELOCATED": str(relocated),
                    })



    def test_tcls_patch_state_prompts_without_reapplying(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$TCLS_ORIGINAL_SHA256 = "13EAD403452E0F25CF00658369BF4BF5FF34ED1B16027F7833FB27D398386CD1"
$TCLS_PATCHED_SHA256 = "3FF351E0ADB594D7544E28DB2E966A6D6EB548E9DF70DAAF4DAF58F2EE438D56"
$script:AF_TEST_HASH = $TCLS_PATCHED_SHA256
$script:AF_TEST_ANSWER = "NO"
function Get-Sha256([string]$Path) { return $script:AF_TEST_HASH }
function Read-Host([string]$Prompt) { return $script:AF_TEST_ANSWER }
$declined = $false
try {
    Ensure-PermanentTCLS $env:AF_TEST_REPO $env:AF_TEST_ROOT $env:AF_TEST_PYTHON
} catch {
    if ($_.Exception.Message -notmatch "You chose not to continue") { throw }
    $declined = $true
}
if (-not $declined) { throw "Already-patched TCLS was accepted without consent" }
[void]$script:LauncherConfig.Preferences.PSObject.Properties.Remove("ContinueWithPatchedTcls")
$script:AF_TEST_ANSWER = "YES"
Ensure-PermanentTCLS $env:AF_TEST_REPO $env:AF_TEST_ROOT $env:AF_TEST_PYTHON
$script:AF_TEST_HASH = "A" * 64
$unknownDeclined = $false
try {
    Ensure-PermanentTCLS $env:AF_TEST_REPO $env:AF_TEST_ROOT $env:AF_TEST_PYTHON
} catch {
    if ($_.Exception.Message -notmatch "exact verified patched hash") { throw }
    $unknownDeclined = $true
}
if (-not $unknownDeclined) { throw "Unknown TCLS hash was accepted" }
Write-Host "AF_RUNTIME_TEST_PASS"
""")




    def test_launcher_preferences_are_saved_and_reused(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$script:AF_TEST_PROMPTS = 0
function Read-Host([string]$Prompt) {
    $script:AF_TEST_PROMPTS++
    if ($Prompt -like "*saved yes*") { return "y" }
    if ($Prompt -like "*saved no*") { return "n" }
    return ""
}
if (-not (Read-LauncherChoice -Name "SavedYes" -Prompt "saved yes" -DefaultYes $false)) {
    throw "Lowercase y was not accepted"
}
if (Read-LauncherChoice -Name "SavedNo" -Prompt "saved no" -DefaultYes $true) {
    throw "Lowercase n was not accepted"
}
if (-not (Read-LauncherChoice -Name "SavedDefault" -Prompt "saved default" -DefaultYes $true)) {
    throw "Enter did not choose the displayed Y default"
}
function Read-Host([string]$Prompt) { throw "Saved choice unexpectedly prompted again" }
if (-not (Read-LauncherChoice -Name "SavedYes" -Prompt "saved yes" -DefaultYes $false)) {
    throw "Saved Y choice changed"
}
if (Read-LauncherChoice -Name "SavedNo" -Prompt "saved no" -DefaultYes $true) {
    throw "Saved N choice changed"
}
if (-not (Read-LauncherChoice -Name "SavedDefault" -Prompt "saved default" -DefaultYes $true)) {
    throw "Saved default choice changed"
}
if ($script:AF_TEST_PROMPTS -ne 3) { throw "Saved choices prompted again" }
if (-not (Test-Path -LiteralPath $script:LAUNCHER_CONFIG_PATH)) {
    throw "Launcher preferences file was not written"
}
Write-Host "AF_RUNTIME_TEST_PASS"
""")

    def test_native_warning_can_be_tee_logged_without_failing_helper(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$log = Join-Path $env:AF_TEST_ROOT "native helper.log"
$saved = $ErrorActionPreference
$ErrorActionPreference = "Continue"
& $env:AF_TEST_PYTHON -c "import sys; print('harmless warning', file=sys.stderr); print('helper ran')" 2>&1 |
    Tee-Object -FilePath $log
$exitCode = $LASTEXITCODE
$ErrorActionPreference = $saved
if ($exitCode -ne 0) { throw "Warning changed successful native exit code to $exitCode" }
if (-not (Select-String -Path $log -Pattern "harmless warning" -Quiet)) {
    throw "Native stderr was not saved in helper log"
}
Write-Host "AF_RUNTIME_TEST_PASS"
""")

    def test_encoded_helper_child_runs_and_appends_log_with_paths_with_spaces(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
$pythonHelper = Join-Path $env:AF_TEST_ROOT "python helper with spaces.py"
$log = Join-Path $env:AF_TEST_ROOT "TGame helper log with spaces.log"
$logEncoding = if ($PSVersionTable.PSEdition -eq "Core") { "utf8" } else { "Unicode" }
Set-Content -LiteralPath $pythonHelper -Value 'print("AF_RUNTIME_ENCODED_CHILD_OK")' -Encoding UTF8
New-Item -ItemType File -Path $log -Force | Out-Null
$childCommand = (
    '$ErrorActionPreference = "Continue"; ' +
    'Add-Content -LiteralPath ' + (Quote-PS $log) + ' -Value "[AF-HELPER-BOOT] entered" -Encoding ' + $logEncoding + '; ' +
    '& ' + (Quote-PS $env:AF_TEST_PYTHON) + ' -u ' + (Quote-PS $pythonHelper) +
    ' 2>&1 | Tee-Object -FilePath ' + (Quote-PS $log) + ' -Append; ' +
    '$childExitCode = $LASTEXITCODE; ' +
    'Add-Content -LiteralPath ' + (Quote-PS $log) + ' -Value ("[AF-HELPER-BOOT] exit=" + $childExitCode) -Encoding ' + $logEncoding + '; ' +
    'exit $childExitCode'
)
$encoded = ConvertTo-PowerShellEncodedCommand $childCommand
$shellExe = if ($PSVersionTable.PSEdition -eq "Core") {
    Join-Path $PSHOME "pwsh.exe"
} else {
    Join-Path $PSHOME "powershell.exe"
}
$child = Start-Process -FilePath $shellExe -WorkingDirectory $env:AF_TEST_ROOT -PassThru -Wait -ArgumentList @(
    "-NoProfile", "-ExecutionPolicy", "Bypass", "-EncodedCommand", $encoded
)
if ($child.ExitCode -ne 0) { throw "Encoded helper child exited with code $($child.ExitCode)" }
$logText = [System.IO.File]::ReadAllText($log)
foreach ($marker in @("[AF-HELPER-BOOT] entered", "AF_RUNTIME_ENCODED_CHILD_OK", "[AF-HELPER-BOOT] exit=0")) {
    if ($logText -notmatch [regex]::Escape($marker)) { throw "Helper log is missing marker: $marker`n$logText" }
}
Write-Host "AF_RUNTIME_TEST_PASS"
""")



    def test_ensure_keys_asks_and_preserves_existing_or_supplied_private_pem(self):
        for shell in self.shells():
            with self.subTest(shell=shell):
                self.run_launcher(shell, r"""
function New-KeyTestCase([string]$Name, [bool]$WithPrivate) {
    $repo = Join-Path $env:AF_TEST_ROOT ($Name + " repo")
    $game = Join-Path $env:AF_TEST_ROOT ($Name + " game")
    $private = Join-Path $repo "server\PRIVATE.PEM"
    $clientConfig = Join-Path $game "TCLS\config"
    New-Item -ItemType Directory -Path (Split-Path -Parent $private) -Force | Out-Null
    New-Item -ItemType Directory -Path $clientConfig -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $repo "tools\patches") -Force | Out-Null
    Set-Content -LiteralPath (Join-Path $repo "tools\patches\diagnose_tcls_apclient.py") -Value "raise SystemExit(0)" -Encoding Ascii -Force
    Set-Content -LiteralPath (Join-Path $clientConfig "APClient.dat") -Value "matching public key placeholder" -Encoding Ascii -Force
    if ($WithPrivate) {
        Set-Content -LiteralPath $private -Value "user owned private key" -Encoding Ascii -Force
    }
    return [pscustomobject]@{ Repo = $repo; Game = $game; Private = $private }
}
$externalSource = Join-Path $env:AF_TEST_ROOT "my own PRIVATE.PEM"
Set-Content -LiteralPath $externalSource -Value "external private key" -Encoding Ascii -Force
$externalSourceHash = Get-Sha256 $externalSource
$script:AF_TEST_EXTERNAL_PRIVATE = $externalSource
function Read-Host([string]$Prompt) {
    if ($Prompt -like "*full path to your PRIVATE.PEM*") {
        return $script:AF_TEST_EXTERNAL_PRIVATE
    }
    return "YES"
}
$existing = New-KeyTestCase "existing key" $true
$existingBefore = [System.IO.File]::ReadAllText($existing.Private)
Ensure-Keys $existing.Repo $existing.Game $env:AF_TEST_PYTHON
if ([System.IO.File]::ReadAllText($existing.Private) -ne $existingBefore) {
    throw "Existing user-owned PRIVATE.PEM was changed"
}
$external = New-KeyTestCase "external key" $false
Ensure-Keys $external.Repo $external.Game $env:AF_TEST_PYTHON
if ((Get-Sha256 $external.Private) -ne $externalSourceHash) {
    throw "Supplied PRIVATE.PEM was not copied into the server key location"
}
if ((Get-Sha256 $externalSource) -ne $externalSourceHash) {
    throw "Supplied PRIVATE.PEM source was modified"
}
Write-Host "AF_RUNTIME_TEST_PASS"
""")


if __name__ == "__main__":
    unittest.main()
