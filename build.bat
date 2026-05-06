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
call :find_vsroot
if defined VS_ROOT if exist "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" call "%VS_ROOT%\Common7\Tools\VsDevCmd.bat" -arch=x64 -host_arch=x64 >nul
exit /b 0

:find_vsroot
set "VS_ROOT="
for /f "delims=" %%I in ('where vswhere.exe 2^>nul') do if not defined VSWHERE_EXE set "VSWHERE_EXE=%%I"
if not defined VSWHERE_EXE call :find_vswhere_from_registry
if defined VSWHERE_EXE for /f "usebackq delims=" %%I in (`"%VSWHERE_EXE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_ROOT=%%I"
if defined VS_ROOT exit /b 0
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\VisualStudio\SxS\VS7" /v 17.0 2^>nul') do if not defined VS_ROOT set "VS_ROOT=%%B"
if defined VS_ROOT exit /b 0
for /f "tokens=2,*" %%A in ('reg query "HKCU\SOFTWARE\Microsoft\VisualStudio\SxS\VS7" /v 17.0 2^>nul') do if not defined VS_ROOT set "VS_ROOT=%%B"
exit /b 0

:find_vswhere_from_registry
set "VS_INSTALLER_DIR="
for /f "delims=" %%K in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Microsoft Visual Studio Installer" /d 2^>nul ^| findstr /B /C:"HKEY"') do (
    if not defined VS_INSTALLER_DIR for /f "tokens=2,*" %%A in ('reg query "%%K" /v InstallLocation 2^>nul') do set "VS_INSTALLER_DIR=%%~B"
)
if defined VS_INSTALLER_DIR if exist "%VS_INSTALLER_DIR%\vswhere.exe" set "VSWHERE_EXE=%VS_INSTALLER_DIR%\vswhere.exe"
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
