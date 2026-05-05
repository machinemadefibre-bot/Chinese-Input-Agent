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

where x86_64-w64-mingw32-gcc-ar.exe >nul 2>nul
if errorlevel 1 (
    echo x86_64-w64-mingw32-gcc-ar.exe not found. Install MSYS2 UCRT64 MinGW-w64.
    exit /b 1
)

where x86_64-w64-mingw32-gcc-ranlib.exe >nul 2>nul
if errorlevel 1 (
    echo x86_64-w64-mingw32-gcc-ranlib.exe not found. Install MSYS2 UCRT64 MinGW-w64.
    exit /b 1
)

for /f "delims=" %%I in ('where x86_64-w64-mingw32-gcc.exe') do if not defined MINGW_CC set "MINGW_CC=%%I"
for /f "delims=" %%I in ('where windres.exe') do if not defined MINGW_RC set "MINGW_RC=%%I"
for /f "delims=" %%I in ('where x86_64-w64-mingw32-gcc-ar.exe') do if not defined MINGW_AR set "MINGW_AR=%%I"
for /f "delims=" %%I in ('where x86_64-w64-mingw32-gcc-ranlib.exe') do if not defined MINGW_RANLIB set "MINGW_RANLIB=%%I"

cmake.exe -S "%ROOT%" -B "%ROOT%\build\cmake-mingw" -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  "-DCMAKE_C_COMPILER=%MINGW_CC%" ^
  "-DCMAKE_RC_COMPILER=%MINGW_RC%" ^
  "-DCMAKE_AR=%MINGW_AR%" ^
  "-DCMAKE_RANLIB=%MINGW_RANLIB%" ^
  -DCMAKE_C_COMPILER_WORKS=TRUE ^
  -DCMAKE_C_COMPILER_FORCED=TRUE ^
  -DCMAKE_C_ABI_COMPILED=TRUE ^
  -DCMAKE_RC_COMPILER_WORKS=TRUE
if errorlevel 1 exit /b 1

cmake.exe --build "%ROOT%\build\cmake-mingw" --target ChineseInputAgent --config Release
if errorlevel 1 exit /b 1

endlocal
