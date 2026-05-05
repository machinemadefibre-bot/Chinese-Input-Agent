@echo off
setlocal

where cl.exe >nul 2>nul
if errorlevel 1 (
    echo cl.exe not found. Run this from "x64 Native Tools Command Prompt for VS".
    exit /b 1
)

where rc.exe >nul 2>nul
if errorlevel 1 (
    echo rc.exe not found. Install the Windows SDK or run a Visual Studio developer prompt.
    exit /b 1
)

if not exist build mkdir build

rc.exe /nologo /fo build\app.res src\app.rc
if errorlevel 1 exit /b 1

cl.exe /nologo /W3 /O2 /utf-8 /D_WINDOWS /DHAVE_SECUREZEROMEMORY=1 ^
  /Fe:build\ChineseInputAgent.exe src\main.c src\crypto_box.c third_party\curve25519-donna\curve25519-donna.c build\app.res ^
  user32.lib gdi32.lib comctl32.lib advapi32.lib crypt32.lib bcrypt.lib ncrypt.lib shell32.lib

endlocal
