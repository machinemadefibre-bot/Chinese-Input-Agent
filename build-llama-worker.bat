@echo off
setlocal EnableExtensions
set ROOT=%~dp0
set SRC=%ROOT%tools\payload_watermark\llama_worker
set FINAL=%ROOT%build\llama_worker_package
set CPU_BUILD=%ROOT%build\llama_worker_cpu
set GPU_BUILD=%ROOT%build\llama_worker_gpu
set VK_BUILD=%ROOT%build\llama_worker_vulkan

set CMAKE=C:\msys64\ucrt64\bin\cmake.exe
set NINJA=C:\msys64\ucrt64\bin\ninja.exe
set CC=C:\msys64\ucrt64\bin\x86_64-w64-mingw32-gcc.exe
set CXX=C:\msys64\ucrt64\bin\x86_64-w64-mingw32-g++.exe
if not exist "%CMAKE%" set CMAKE=cmake.exe
if not exist "%NINJA%" set NINJA=ninja.exe
set PATH=C:\msys64\ucrt64\bin;%PATH%

if exist "%FINAL%" rmdir /s /q "%FINAL%"
mkdir "%FINAL%"

echo Building CPU llama.cpp worker...
"%CMAKE%" -S "%SRC%" -B "%CPU_BUILD%" -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="%CC%" -DCMAKE_CXX_COMPILER="%CXX%" -DCIA_LLAMA_SHARED_BACKENDS=OFF -DGGML_CUDA=OFF -DGGML_VULKAN=OFF
if errorlevel 1 exit /b 1
"%CMAKE%" --build "%CPU_BUILD%" --target cia_llama_worker --config Release -j 1
if errorlevel 1 exit /b 1
copy /y "%CPU_BUILD%\cia_llama_worker.exe" "%FINAL%\cia_llama_worker.exe" >nul

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

:detect_cuda
set CIA_HAVE_CUDA_BUILD=0
set NVCC=
for %%P in (nvcc.exe) do set NVCC=%%~$PATH:P
if not defined NVCC if defined CUDA_PATH if exist "%CUDA_PATH%\bin\nvcc.exe" set NVCC=%CUDA_PATH%\bin\nvcc.exe
if not defined NVCC (
  for /d %%D in ("C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*") do if exist "%%~fD\bin\nvcc.exe" set NVCC=%%~fD\bin\nvcc.exe
)
if not defined NVCC (
  for /d %%D in ("Q:\Program Files\Nvidia CUDA Toolkit") do if exist "%%~fD\bin\nvcc.exe" set NVCC=%%~fD\bin\nvcc.exe
)
if not defined NVCC (
  echo CUDA Toolkit nvcc.exe not found; skipping CUDA worker.
  exit /b 0
)
set CL=
for %%P in (cl.exe) do set CL=%%~$PATH:P
if not defined CL (
  if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  if not defined VCVARS if exist "C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
  if not defined VCVARS (
    set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
    if exist "%VSWHERE%" for /f "usebackq delims=" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VSROOT=%%I"
    if defined VSROOT if exist "%VSROOT%\VC\Auxiliary\Build\vcvars64.bat" set "VCVARS=%VSROOT%\VC\Auxiliary\Build\vcvars64.bat"
  )
)
if not defined CL if not defined VCVARS (
  echo MSVC cl.exe not found; skipping CUDA worker because nvcc on Windows needs MSVC host tools.
  exit /b 0
)
set CIA_HAVE_CUDA_BUILD=1
exit /b 0

:detect_vulkan
set CIA_HAVE_VULKAN_BUILD=0
if defined VULKAN_SDK if exist "%VULKAN_SDK%\Bin\glslc.exe" set CIA_HAVE_VULKAN_BUILD=1
if "%CIA_HAVE_VULKAN_BUILD%"=="0" (
  for /d %%D in ("C:\VulkanSDK\*") do if exist "%%~fD\Bin\glslc.exe" (
    set VULKAN_SDK=%%~fD
    set CIA_HAVE_VULKAN_BUILD=1
  )
)
if "%CIA_HAVE_VULKAN_BUILD%"=="0" echo Vulkan SDK not found; skipping Vulkan worker.
exit /b 0

:build_msvc_gpu
set GPU_ARGS=-DCIA_LLAMA_SHARED_BACKENDS=ON -DGGML_CUDA=ON -DGGML_CUDA_NCCL=OFF -DGGML_VULKAN=%CIA_HAVE_VULKAN_BUILD% -DCMAKE_CUDA_ARCHITECTURES=86
if defined VCVARS (
  call "%VCVARS%" >nul
)
set "VS_CMAKE=cmake.exe"
set "VS_NINJA=ninja.exe"
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe" set "VS_CMAKE=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe"
if exist "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe" set "VS_NINJA=C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe"
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
set STAGE_BUILD=%~1
copy /y "%STAGE_BUILD%\cia_llama_worker.exe" "%FINAL%\cia_llama_worker.exe" >nul
for /r "%STAGE_BUILD%" %%F in (*.dll) do copy /y "%%~fF" "%FINAL%\" >nul
if exist "C:\msys64\ucrt64\bin\libgcc_s_seh-1.dll" copy /y "C:\msys64\ucrt64\bin\libgcc_s_seh-1.dll" "%FINAL%\" >nul
if exist "C:\msys64\ucrt64\bin\libstdc++-6.dll" copy /y "C:\msys64\ucrt64\bin\libstdc++-6.dll" "%FINAL%\" >nul
if exist "C:\msys64\ucrt64\bin\libwinpthread-1.dll" copy /y "C:\msys64\ucrt64\bin\libwinpthread-1.dll" "%FINAL%\" >nul
if defined CUDA_PATH if exist "%CUDA_PATH%\bin" (
  for %%F in ("%CUDA_PATH%\bin\cudart64_*.dll" "%CUDA_PATH%\bin\cublas64_*.dll" "%CUDA_PATH%\bin\cublasLt64_*.dll") do if exist "%%~fF" copy /y "%%~fF" "%FINAL%\" >nul
)
exit /b 0
