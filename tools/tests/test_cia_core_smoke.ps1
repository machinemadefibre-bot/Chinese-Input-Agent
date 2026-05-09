$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$gcc = (Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue)
if (-not $gcc) {
    Write-Host "skip cia_core_smoke_test: x86_64-w64-mingw32-gcc.exe not found"
    exit 0
}

$buildDir = Join-Path $Root "build\tests"
$dataDir = Join-Path $buildDir "cia_core_smoke_data"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
if ($dataDir.StartsWith((Join-Path $Root "build"))) {
    Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

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

Push-Location $Root
$oldDataDir = $env:CIA_DATA_DIR
try {
    & $gcc.Source @args
    if ($LASTEXITCODE -ne 0) {
        throw "cia_core_smoke_test compile failed"
    }
    $env:CIA_DATA_DIR = $dataDir
    & $exe
    if ($LASTEXITCODE -ne 0) {
        throw "cia_core_smoke_test failed"
    }
} finally {
    $env:CIA_DATA_DIR = $oldDataDir
    Pop-Location
}
