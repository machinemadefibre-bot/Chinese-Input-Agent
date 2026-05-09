$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$buildDir = Join-Path $Root "build\tests"
$dataDir = Join-Path $buildDir "cia_core_smoke_data"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
if ($dataDir.StartsWith((Join-Path $Root "build"))) {
    Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

function Invoke-SmokeExecutable {
    param([string]$ExePath)

    $oldDataDir = $env:CIA_DATA_DIR
    try {
        $env:CIA_DATA_DIR = $dataDir
        & $ExePath
        if ($LASTEXITCODE -ne 0) {
            throw "cia_core_smoke_test failed"
        }
    } finally {
        $env:CIA_DATA_DIR = $oldDataDir
    }
}

function Try-CMakeSmokeTest {
    $cmake = Get-Command cmake.exe -ErrorAction SilentlyContinue
    if (-not $cmake) {
        return $false
    }

    $cmakeBuildDir = Join-Path $Root "build\cmake-mingw"
    $cachePath = Join-Path $cmakeBuildDir "CMakeCache.txt"
    if (-not (Test-Path $cachePath)) {
        $ninja = Get-Command ninja.exe -ErrorAction SilentlyContinue
        $gcc = Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue
        $windres = Get-Command windres.exe -ErrorAction SilentlyContinue
        $ar = Get-Command x86_64-w64-mingw32-gcc-ar.exe -ErrorAction SilentlyContinue
        $ranlib = Get-Command x86_64-w64-mingw32-gcc-ranlib.exe -ErrorAction SilentlyContinue
        if (-not ($ninja -and $gcc -and $windres -and $ar -and $ranlib)) {
            return $false
        }
        & $cmake.Source -S $Root -B $cmakeBuildDir -G Ninja `
            -DCMAKE_BUILD_TYPE=Release `
            "-DCMAKE_C_COMPILER=$($gcc.Source)" `
            "-DCMAKE_RC_COMPILER=$($windres.Source)" `
            "-DCMAKE_AR=$($ar.Source)" `
            "-DCMAKE_RANLIB=$($ranlib.Source)" `
            "-DCMAKE_C_COMPILER_AR=$($ar.Source)" `
            "-DCMAKE_C_COMPILER_RANLIB=$($ranlib.Source)" `
            -DCMAKE_C_COMPILER_WORKS=TRUE `
            -DCMAKE_C_COMPILER_FORCED=TRUE `
            -DCMAKE_C_ABI_COMPILED=TRUE `
            -DCMAKE_RC_COMPILER_WORKS=TRUE
        if ($LASTEXITCODE -ne 0) {
            throw "cia_core_smoke_test CMake configure failed"
        }
    }

    # Force this small target through a clean rebuild so the smoke test cannot
    # accidentally run a stale object that still initializes profile/Windows Hello.
    & $cmake.Source --build $cmakeBuildDir --target cia_core_smoke_test --config Release --clean-first
    if ($LASTEXITCODE -ne 0) {
        throw "cia_core_smoke_test CMake target build failed"
    }

    $exe = Join-Path $Root "build\cia_core_smoke_test.exe"
    if (-not (Test-Path $exe)) {
        throw "cia_core_smoke_test CMake target did not produce $exe"
    }
    Invoke-SmokeExecutable $exe
    return $true
}

function Invoke-ManualGccFallback {
    $gcc = Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue
    if (-not $gcc) {
        Write-Host "skip cia_core_smoke_test: CMake target unavailable and x86_64-w64-mingw32-gcc.exe not found"
        exit 0
    }

    $coreSources = @(
        "tools\tests\cia_core_smoke_test.c",
        "src\app_shared.c",
        "src\app_storage.c",
        "src\app_profiles.c",
        "src\app_groups.c",
        "src\app_archive.c",
        "src\app_chat_history.c",
        "src\app_llm.c",
        "src\app_flow.c",
        "src\app_carrier_flow.c",
        "src\app_contact_flow.c",
        "src\app_message_flow.c",
        "src\app_tokenizer_prefs.c",
        "src\cia_core.c",
        "src\cia_platform_windows.c",
        "src\crypto_box.c",
        "third_party\curve25519-donna\curve25519-donna.c",
        "third_party\sqlite\sqlite3.c"
    )

    $forbiddenSources = @(
        "src\main.c",
        "src\app_work.c",
        "src\ui_key_transfer.c",
        "src\ui_name_prompt.c",
        "src\ui_overlay.c",
        "src\ui_work_messages.c",
        "src\win_util.c",
        "src\app.rc"
    )

    foreach ($forbidden in $forbiddenSources) {
        if ($coreSources -contains $forbidden) {
            throw "cia_core_smoke_test must not link UI source: $forbidden"
        }
    }

    $exe = Join-Path $buildDir "cia_core_smoke_test.exe"
    $args = @(
        "-std=c11",
        "-DUNICODE",
        "-D_UNICODE",
        "-DWIN32_LEAN_AND_MEAN",
        "-D_CRT_SECURE_NO_WARNINGS",
        "-DSQLITE_OMIT_LOAD_EXTENSION",
        "-DSQLITE_DEFAULT_MEMSTATUS=0",
        "-Isrc",
        "-Ithird_party\curve25519-donna",
        "-Ithird_party\sqlite",
        "-finput-charset=UTF-8",
        "-fexec-charset=UTF-8",
        "-municode",
        "-o", $exe
    ) + $coreSources + @(
        "-lbcrypt",
        "-lcrypt32",
        "-lncrypt"
    )

    & $gcc.Source @args
    if ($LASTEXITCODE -ne 0) {
        throw "cia_core_smoke_test fallback compile failed"
    }
    Invoke-SmokeExecutable $exe
}

Push-Location $Root
try {
    if (-not (Try-CMakeSmokeTest)) {
        Invoke-ManualGccFallback
    }
} finally {
    Pop-Location
}
