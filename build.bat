@echo off
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

where cmake.exe >nul 2>nul
if errorlevel 1 (
    echo cmake.exe not found. Install CMake or add it to PATH.
    exit /b 1
)

where ninja.exe >nul 2>nul
if errorlevel 1 (
    echo ninja.exe not found. Install Ninja or add it to PATH.
    exit /b 1
)

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

cmake.exe -S "%ROOT%" -B "%ROOT%\build\cmake-msvc" -G Ninja -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

cmake.exe --build "%ROOT%\build\cmake-msvc" --target ChineseInputAgent --config Release
if errorlevel 1 exit /b 1

endlocal
