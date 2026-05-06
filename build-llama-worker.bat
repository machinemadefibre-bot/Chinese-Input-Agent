@echo off
setlocal EnableExtensions
set "ROOT=%~dp0"
if "%ROOT:~-1%"=="\" set "ROOT=%ROOT:~0,-1%"
set "SRC=%ROOT%\tools\payload_watermark\llama_worker"
set "FINAL=%ROOT%\build\llama_worker_package"
set "CPU_BUILD=%ROOT%\build\llama_worker_cpu"
set "GPU_BUILD=%ROOT%\build\llama_worker_gpu"
set "VK_BUILD=%ROOT%\build\llama_worker_vulkan"

call :resolve_tool CMAKE cmake.exe
call :resolve_tool NINJA ninja.exe
call :resolve_tool CC x86_64-w64-mingw32-gcc.exe gcc.exe
call :resolve_tool CXX x86_64-w64-mingw32-g++.exe g++.exe

if not defined CMAKE (
  echo cmake.exe not found. Add CMake to PATH.
  exit /b 1
)
if not defined NINJA (
  echo ninja.exe not found. Add Ninja to PATH.
  exit /b 1
)
if not defined CC (
  echo MinGW gcc not found. Add MSYS2 UCRT64 MinGW-w64 to PATH.
  exit /b 1
)
if not defined CXX (
  echo MinGW g++ not found. Add MSYS2 UCRT64 MinGW-w64 to PATH.
  exit /b 1
)

for %%P in ("%CC%") do set "MINGW_BIN=%%~dpP"
if defined MINGW_BIN set "PATH=%MINGW_BIN%;%PATH%"

if exist "%FINAL%" rmdir /s /q "%FINAL%"
mkdir "%FINAL%"

echo Building CPU llama.cpp worker...
"%CMAKE%" -S "%SRC%" -B "%CPU_BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="%CC%" -DCMAKE_CXX_COMPILER="%CXX%" -DCIA_LLAMA_SHARED_BACKENDS=OFF -DGGML_CUDA=OFF -DGGML_VULKAN=OFF
if errorlevel 1 exit /b 1
"%CMAKE%" --build "%CPU_BUILD%" --target cia_llama_worker --config Release -j 1
if errorlevel 1 exit /b 1
copy /y "%CPU_BUILD%\cia_llama_worker.exe" "%FINAL%\cia_llama_worker.exe" >nul

if "%CIA_SKIP_GPU_WORKER%"=="1" goto done

call :detect_cuda
call :detect_vulkan

if not "%CIA_HAVE_CUDA_BUILD%"=="1" goto skip_cuda
echo Building CUDA-preferred dynamic llama.cpp worker...
call :build_msvc_gpu
if not errorlevel 1 goto done
echo CUDA worker build failed; falling back to Vulkan or CPU.

:skip_cuda
if not "%CIA_HAVE_VULKAN_BUILD%"=="1" goto done
echo Building Vulkan dynamic llama.cpp worker...
call :build_mingw_vulkan
if not errorlevel 1 goto done
echo Vulkan worker build failed; keeping CPU worker.

:done
echo Final llama.cpp worker staged in %FINAL%
endlocal
exit /b 0

:resolve_tool
set "%~1="
for %%P in (%*) do (
  if not "%%~P"=="%~1" if not defined %~1 (
    for /f "delims=" %%I in ('where %%~P 2^>nul') do if not defined %~1 set "%~1=%%I"
  )
)
exit /b 0

:detect_cuda
set "CIA_HAVE_CUDA_BUILD=0"
if defined NVCC if not exist "%NVCC%" set "NVCC="
if not defined NVCC call :resolve_tool NVCC nvcc.exe
if not defined NVCC if defined CUDA_PATH if exist "%CUDA_PATH%\bin\nvcc.exe" set "NVCC=%CUDA_PATH%\bin\nvcc.exe"
if not defined NVCC (
  for /f "tokens=1,* delims==" %%A in ('set CUDA_PATH 2^>nul') do if not defined NVCC if exist "%%~B\bin\nvcc.exe" set "NVCC=%%~B\bin\nvcc.exe"
)
if not defined NVCC (
  echo CUDA Toolkit nvcc.exe not found; skipping CUDA worker.
  exit /b 0
)
for %%P in ("%NVCC%") do set "CUDA_BIN=%%~dpP"

call :resolve_tool CL cl.exe
if not defined CL if defined VCVARS if exist "%VCVARS%" set "CIA_HAVE_CUDA_BUILD=1"
if not defined CL if not defined VCVARS call :detect_vcvars
if not defined CL if not defined VCVARS (
  echo MSVC cl.exe not found; skipping CUDA worker because nvcc on Windows needs MSVC host tools.
  exit /b 0
)
set "CIA_HAVE_CUDA_BUILD=1"
exit /b 0

:detect_vcvars
if defined VSINSTALLDIR if exist "%VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSINSTALLDIR%\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if defined VCINSTALLDIR if exist "%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VCINSTALLDIR%\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS if defined VSWHERE if exist "%VSWHERE%" for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
if not defined VCVARS (
  call :resolve_tool VSWHERE vswhere.exe
  if not defined VSWHERE call :resolve_vswhere_from_registry
  if defined VSWHERE for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
)
if not defined VCVARS if defined VSROOT if exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
if not defined VCVARS call :detect_vsroot_from_registry
if not defined VCVARS if defined VSROOT if exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
exit /b 0

:detect_vsroot_from_registry
for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\Microsoft\VisualStudio\SxS\VS7" /v 17.0 2^>nul') do if not defined VSROOT set "VSROOT=%%B"
if defined VSROOT exit /b 0
for /f "tokens=2,*" %%A in ('reg query "HKCU\SOFTWARE\Microsoft\VisualStudio\SxS\VS7" /v 17.0 2^>nul') do if not defined VSROOT set "VSROOT=%%B"
exit /b 0

:resolve_vswhere_from_registry
set "VS_INSTALLER_DIR="
for /f "delims=" %%K in ('reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall" /s /f "Microsoft Visual Studio Installer" /d 2^>nul ^| findstr /B /C:"HKEY"') do (
    if not defined VS_INSTALLER_DIR for /f "tokens=2,*" %%A in ('reg query "%%K" /v InstallLocation 2^>nul') do set "VS_INSTALLER_DIR=%%~B"
)
if defined VS_INSTALLER_DIR if exist "%VS_INSTALLER_DIR%\vswhere.exe" set "VSWHERE=%VS_INSTALLER_DIR%\vswhere.exe"
exit /b 0

:detect_vulkan
set "CIA_HAVE_VULKAN_BUILD=0"
if defined VULKAN_SDK if exist "%VULKAN_SDK%\Bin\glslc.exe" set "CIA_HAVE_VULKAN_BUILD=1"
if "%CIA_HAVE_VULKAN_BUILD%"=="0" (
  call :resolve_tool GLSLC glslc.exe
  if defined GLSLC set "CIA_HAVE_VULKAN_BUILD=1"
)
if "%CIA_HAVE_VULKAN_BUILD%"=="0" echo Vulkan SDK not found; skipping Vulkan worker.
exit /b 0

:build_msvc_gpu
set "GPU_ARGS=-DCIA_LLAMA_SHARED_BACKENDS=ON -DGGML_CUDA=ON -DGGML_CUDA_NCCL=OFF -DGGML_VULKAN=%CIA_HAVE_VULKAN_BUILD% -DCMAKE_CUDA_ARCHITECTURES=86"
if defined VCVARS call "%VCVARS%" >nul
set "VS_CMAKE=%CMAKE%"
set "VS_NINJA=%NINJA%"
"%VS_CMAKE%" -S "%SRC%" -B "%GPU_BUILD%" -G Ninja -DCMAKE_MAKE_PROGRAM="%VS_NINJA%" -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=cl.exe -DCMAKE_CXX_COMPILER=cl.exe %GPU_ARGS%
if errorlevel 1 exit /b 1
"%VS_CMAKE%" --build "%GPU_BUILD%" --target cia_llama_worker --config Release -j 1
if errorlevel 1 exit /b 1
call :stage_dynamic "%GPU_BUILD%"
exit /b %ERRORLEVEL%

:build_mingw_vulkan
"%CMAKE%" -S "%SRC%" -B "%VK_BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="%CC%" -DCMAKE_CXX_COMPILER="%CXX%" -DCIA_LLAMA_SHARED_BACKENDS=ON -DGGML_CUDA=OFF -DGGML_VULKAN=ON
if errorlevel 1 exit /b 1
"%CMAKE%" --build "%VK_BUILD%" --target cia_llama_worker --config Release -j 1
if errorlevel 1 exit /b 1
call :stage_dynamic "%VK_BUILD%"
exit /b %ERRORLEVEL%

:stage_dynamic
set "STAGE_BUILD=%~1"
copy /y "%STAGE_BUILD%\cia_llama_worker.exe" "%FINAL%\cia_llama_worker.exe" >nul
for /r "%STAGE_BUILD%" %%F in (*.dll) do copy /y "%%~fF" "%FINAL%\" >nul
if defined MINGW_BIN (
  for %%F in (libgcc_s_seh-1.dll libstdc++-6.dll libwinpthread-1.dll) do if exist "%MINGW_BIN%%%F" copy /y "%MINGW_BIN%%%F" "%FINAL%\" >nul
)
if defined CUDA_BIN (
  for %%F in ("%CUDA_BIN%cudart64_*.dll" "%CUDA_BIN%cublas64_*.dll" "%CUDA_BIN%cublasLt64_*.dll") do if exist "%%~fF" copy /y "%%~fF" "%FINAL%\" >nul
)
exit /b 0
