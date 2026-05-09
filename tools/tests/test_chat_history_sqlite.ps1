$ErrorActionPreference = "Stop"

$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
$gcc = (Get-Command x86_64-w64-mingw32-gcc.exe -ErrorAction SilentlyContinue)
if (-not $gcc) {
    Write-Host "skip chat_history_sqlite_test: x86_64-w64-mingw32-gcc.exe not found"
    exit 0
}

$buildDir = Join-Path $Root "build\tests"
$dataDir = Join-Path $buildDir "chat_history_sqlite_data"
New-Item -ItemType Directory -Force -Path $buildDir | Out-Null
if ($dataDir.StartsWith((Join-Path $Root "build"))) {
    Remove-Item -LiteralPath $dataDir -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $dataDir | Out-Null

$exe = Join-Path $buildDir "chat_history_sqlite_test.exe"
$args = @(
    "-std=c11",
    "-DUNICODE",
    "-D_UNICODE",
    "-DWIN32_LEAN_AND_MEAN",
    "-D_CRT_SECURE_NO_WARNINGS",
    "-DSQLITE_OMIT_LOAD_EXTENSION",
    "-DSQLITE_DEFAULT_MEMSTATUS=0",
    "-Isrc",
    "-Ithird_party\sqlite",
    "-finput-charset=UTF-8",
    "-fexec-charset=UTF-8",
    "-municode",
    "-o", $exe,
    "tools\tests\chat_history_sqlite_test.c",
    "src\app_chat_history.c",
    "src\app_shared.c",
    "src\app_storage.c",
    "src\cia_platform_windows.c",
    "third_party\sqlite\sqlite3.c",
    "-lbcrypt",
    "-lcrypt32"
)

Push-Location $Root
try {
    & $gcc.Source @args
    if ($LASTEXITCODE -ne 0) {
        throw "chat_history_sqlite_test compile failed"
    }
    & $exe $dataDir
    if ($LASTEXITCODE -ne 0) {
        throw "chat_history_sqlite_test failed"
    }
} finally {
    Pop-Location
}
