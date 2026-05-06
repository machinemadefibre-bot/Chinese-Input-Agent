@echo off
setlocal
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"

rem CMake wrapper: invokes cmake.exe -S through CMAKE_EXE, preferring the Visual Studio bundled copy.
call :load_msvc_env

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

call :find_cmake
if not defined CMAKE_EXE (
    echo cmake.exe not found. Install CMake or add it to PATH.
    exit /b 1
)

call :find_ninja
if not defined NINJA_EXE (
    echo ninja.exe not found. Install Ninja or add it to PATH.
    exit /b 1
)

"%CMAKE_EXE%" -S "%ROOT%" -B "%ROOT%\build\cmake-msvc" -G Ninja -DCMAKE_MAKE_PROGRAM="%NINJA_EXE%" -DCMAKE_BUILD_TYPE=Release
if errorlevel 1 exit /b 1

"%CMAKE_EXE%" --build "%ROOT%\build\cmake-msvc" --target ChineseInputAgent --config Release
if errorlevel 1 exit /b 1

endlocal
exit /b 0

:load_msvc_env
where cl.exe >nul 2>nul
if not errorlevel 1 exit /b 0
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" exit /b 0
for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_ROOT=%%I"
if defined VS_ROOT if exist "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" call "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
exit /b 0

:find_cmake
set "CMAKE_EXE="
if defined VSINSTALLDIR if exist "%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "CMAKE_EXE=%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if defined CMAKE_EXE exit /b 0
for /f "delims=" %%I in ('where cmake.exe 2^>nul') do if not defined CMAKE_EXE set "CMAKE_EXE=%%I"
exit /b 0

:find_ninja
set "NINJA_EXE="
if defined VSINSTALLDIR if exist "%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" set "NINJA_EXE=%VSINSTALLDIR%Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
if defined NINJA_EXE exit /b 0
for /f "delims=" %%I in ('where ninja.exe 2^>nul') do if not defined NINJA_EXE set "NINJA_EXE=%%I"
exit /b 0
