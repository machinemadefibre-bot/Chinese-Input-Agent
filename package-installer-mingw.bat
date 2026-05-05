@echo off
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

where cmake.exe >nul 2>nul
if errorlevel 1 (
    echo cmake.exe not found. Install CMake or add it to PATH.
    exit /b 1
)

set PY=%~dp0.venv\Scripts\python.exe
if not exist "%PY%" set PY=python.exe

call "%~dp0package-mingw.bat"
if errorlevel 1 exit /b 1

cmake.exe --build "%ROOT%\build\cmake-mingw" --target ChineseInputAgentInstallerStub --config Release
if errorlevel 1 exit /b 1

"%PY%" tools\packaging\make_installer_archive.py "dist\ChineseInputAgent" "build\ChineseInputAgentPortable.zip"
if errorlevel 1 exit /b 1

"%PY%" tools\packaging\append_installer_payload.py "build\ChineseInputAgentInstallerStub.exe" "build\ChineseInputAgentPortable.zip" "dist\ChineseInputAgentInstaller.exe"
if errorlevel 1 exit /b 1

echo Packaged installer to dist\ChineseInputAgentInstaller.exe
endlocal
