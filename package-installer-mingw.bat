@echo off
setlocal

where x86_64-w64-mingw32-gcc.exe >nul 2>nul
if errorlevel 1 (
    echo x86_64-w64-mingw32-gcc.exe not found. Install MSYS2 UCRT64 MinGW-w64.
    exit /b 1
)

where windres.exe >nul 2>nul
if errorlevel 1 (
    echo windres.exe not found. Install MSYS2 UCRT64 MinGW-w64.
    exit /b 1
)

set PY=%~dp0.venv\Scripts\python.exe
if not exist "%PY%" set PY=python.exe

call "%~dp0package-mingw.bat"
if errorlevel 1 exit /b 1

if not exist build mkdir build

windres.exe src\installer.rc -O coff -o build\installer_mingw.res
if errorlevel 1 exit /b 1

x86_64-w64-mingw32-gcc.exe -municode -mwindows -O2 -w -static -static-libgcc ^
  -o build\ChineseInputAgentInstallerStub.exe ^
  -D_WINDOWS ^
  src\installer.c build\installer_mingw.res ^
  -luser32 -lgdi32 -lcomctl32 -lshell32 -lole32
if errorlevel 1 exit /b 1

"%PY%" tools\packaging\make_installer_archive.py "dist\ChineseInputAgent" "build\ChineseInputAgentPortable.zip"
if errorlevel 1 exit /b 1

"%PY%" tools\packaging\append_installer_payload.py "build\ChineseInputAgentInstallerStub.exe" "build\ChineseInputAgentPortable.zip" "dist\ChineseInputAgentInstaller.exe"
if errorlevel 1 exit /b 1

echo Packaged installer to dist\ChineseInputAgentInstaller.exe
endlocal
