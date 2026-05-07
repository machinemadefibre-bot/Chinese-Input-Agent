param(
    [string]$AInstallDir = $env:CIA_TEST_A_INSTALL_DIR,
    [string]$BInstallDir = $env:CIA_TEST_B_INSTALL_DIR,
    [switch]$KeepState
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$buildDir = Join-Path $repoRoot "build\tests\ab_crypto_exchange"
$testExe = Join-Path $buildDir "ab_crypto_exchange_test.exe"
$testSource = Join-Path $PSScriptRoot "ab_crypto_exchange_test.c"

$usingDefaultAInstallDir = $false
$usingDefaultBInstallDir = $false
if ([string]::IsNullOrWhiteSpace($AInstallDir)) {
    $AInstallDir = Join-Path $repoRoot "build\ab-installs\ChineseInputAgent-A"
    $usingDefaultAInstallDir = $true
}
if ([string]::IsNullOrWhiteSpace($BInstallDir)) {
    $BInstallDir = Join-Path $repoRoot "build\ab-installs\ChineseInputAgent-B"
    $usingDefaultBInstallDir = $true
}

function Initialize-DefaultInstall {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDir,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
        New-Item -ItemType Directory -Path $InstallDir | Out-Null
    }

    $sourceExe = Join-Path $repoRoot "build\ChineseInputAgent.exe"
    if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
        $sourceExe = Join-Path $repoRoot "dist\ChineseInputAgent\ChineseInputAgent.exe"
    }
    if (-not (Test-Path -LiteralPath $sourceExe -PathType Leaf)) {
        throw "Default $Label install requires build\ChineseInputAgent.exe or dist\ChineseInputAgent\ChineseInputAgent.exe. Run build-mingw.bat first, or pass -${Label}InstallDir."
    }

    Copy-Item -LiteralPath $sourceExe -Destination (Join-Path $InstallDir "ChineseInputAgent-$Label.exe") -Force
}

function Resolve-AppExe {
    param(
        [Parameter(Mandatory = $true)][string]$InstallDir,
        [Parameter(Mandatory = $true)][string]$Label
    )

    if (-not (Test-Path -LiteralPath $InstallDir -PathType Container)) {
        throw "$Label install directory not found: $InstallDir"
    }

    $expected = Join-Path $InstallDir "ChineseInputAgent-$Label.exe"
    if (Test-Path -LiteralPath $expected -PathType Leaf) {
        return (Resolve-Path -LiteralPath $expected).Path
    }

    $candidate = Get-ChildItem -LiteralPath $InstallDir -Filter "ChineseInputAgent*.exe" -File |
        Where-Object { $_.Name -notlike "*Installer*" } |
        Select-Object -First 1
    if (-not $candidate) {
        throw "$Label executable not found under: $InstallDir"
    }
    return $candidate.FullName
}

function Reset-TestStateDir {
    param([Parameter(Mandatory = $true)][string]$DataDir)

    if (-not (Test-Path -LiteralPath $DataDir -PathType Container)) {
        New-Item -ItemType Directory -Path $DataDir | Out-Null
    }

    $testDir = Join-Path $DataDir "ab_exchange_test"
    if (-not $KeepState -and (Test-Path -LiteralPath $testDir)) {
        Remove-Item -LiteralPath $testDir -Recurse -Force
    }
    if (-not (Test-Path -LiteralPath $testDir -PathType Container)) {
        New-Item -ItemType Directory -Path $testDir | Out-Null
    }
    return $testDir
}

function Resolve-CCompiler {
    $preferred = Get-Command "x86_64-w64-mingw32-gcc.exe" -ErrorAction SilentlyContinue
    if ($preferred) { return $preferred.Source }

    $fallback = Get-Command "gcc.exe" -ErrorAction SilentlyContinue
    if ($fallback) { return $fallback.Source }

    throw "No MinGW C compiler found. Install MSYS2 UCRT64 or add x86_64-w64-mingw32-gcc.exe/gcc.exe to PATH."
}

if ($usingDefaultAInstallDir) { Initialize-DefaultInstall -InstallDir $AInstallDir -Label "A" }
if ($usingDefaultBInstallDir) { Initialize-DefaultInstall -InstallDir $BInstallDir -Label "B" }

$aExe = Resolve-AppExe -InstallDir $AInstallDir -Label "A"
$bExe = Resolve-AppExe -InstallDir $BInstallDir -Label "B"
$aDataDir = Join-Path $AInstallDir "data"
$bDataDir = Join-Path $BInstallDir "data"
$aTestDir = Reset-TestStateDir -DataDir $aDataDir
$bTestDir = Reset-TestStateDir -DataDir $bDataDir
$aState = Join-Path $aTestDir "state.dat"
$bState = Join-Path $bTestDir "state.dat"

if (-not (Test-Path -LiteralPath $buildDir -PathType Container)) {
    New-Item -ItemType Directory -Path $buildDir | Out-Null
}

$cc = Resolve-CCompiler
$compileArgs = @(
    "-std=c11",
    "-Wall",
    "-Wextra",
    "-DUNICODE",
    "-D_UNICODE",
    "-DWIN32_LEAN_AND_MEAN",
    "-D_CRT_SECURE_NO_WARNINGS",
    "-DHAVE_SECUREZEROMEMORY=1",
    "-I", (Join-Path $repoRoot "src"),
    "-I", (Join-Path $repoRoot "third_party\curve25519-donna"),
    $testSource,
    (Join-Path $repoRoot "src\crypto_box.c"),
    (Join-Path $repoRoot "src\app_groups.c"),
    (Join-Path $repoRoot "src\app_shared.c"),
    (Join-Path $repoRoot "src\app_storage.c"),
    (Join-Path $repoRoot "third_party\curve25519-donna\curve25519-donna.c"),
    "-o", $testExe,
    "-municode",
    "-lbcrypt",
    "-lcrypt32",
    "-ladvapi32",
    "-lshell32",
    "-luser32"
)

Write-Host "A install: $AInstallDir"
Write-Host "B install: $BInstallDir"
Write-Host "A exe: $aExe"
Write-Host "B exe: $bExe"
Write-Host "A test state: $aState"
Write-Host "B test state: $bState"
Write-Host "Compiler: $cc"
Write-Host "Building AB crypto exchange harness..."

& $cc @compileArgs
if ($LASTEXITCODE -ne 0) {
    throw "Failed to build AB crypto exchange harness."
}

Write-Host "Running AB crypto exchange test..."
& $testExe "--a-exe" $aExe "--b-exe" $bExe "--a-state" $aState "--b-state" $bState
if ($LASTEXITCODE -ne 0) {
    throw "AB crypto exchange test failed."
}
