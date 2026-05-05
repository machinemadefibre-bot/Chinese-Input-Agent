@echo off
setlocal

where x86_64-w64-mingw32-gcc.exe >nul 2>nul
if errorlevel 1 (
    echo x86_64-w64-mingw32-gcc.exe not found. Install MSYS2 UCRT64 MinGW-w64 or use build.bat with MSVC.
    exit /b 1
)

where windres.exe >nul 2>nul
if errorlevel 1 (
    echo windres.exe not found. Install MSYS2 UCRT64 MinGW-w64 or use build.bat with MSVC.
    exit /b 1
)

if not exist build mkdir build

windres.exe src\app.rc -O coff -o build\app_mingw.res
if errorlevel 1 exit /b 1

x86_64-w64-mingw32-gcc.exe -municode -mwindows -O2 -w -static -static-libgcc ^
  -o build\ChineseInputAgent.exe ^
  -D_WINDOWS -DHAVE_SECUREZEROMEMORY=1 ^
  src\main.c src\app_shared.c src\app_storage.c src\app_profiles.c src\app_archive.c src\app_llm.c src\crypto_box.c third_party\curve25519-donna\curve25519-donna.c build\app_mingw.res ^
  -luser32 -lgdi32 -lcomctl32 -ladvapi32 -lcrypt32 -lbcrypt -lncrypt -lshell32

endlocal
