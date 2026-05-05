@echo off
setlocal

call "%~dp0build-mingw.bat"
if errorlevel 1 exit /b 1
if not "%CIA_SKIP_LLAMA_BUILD%"=="1" (
  call "%~dp0build-llama-worker.bat"
  if errorlevel 1 exit /b 1
)

set DIST=dist\ChineseInputAgent
if not exist dist mkdir dist
if exist "%DIST%" rmdir /s /q "%DIST%"
mkdir "%DIST%"
mkdir "%DIST%\data"
echo portable data directory marker>"%DIST%\data\.portable"

copy /y build\ChineseInputAgent.exe "%DIST%\ChineseInputAgent.exe" >nul
copy /y README.md "%DIST%\README.md" >nul

mkdir "%DIST%\tools"
mkdir "%DIST%\tools\payload_watermark"
copy /y build\llama_worker_package\*.exe "%DIST%\tools\payload_watermark\" >nul
copy /y build\llama_worker_package\*.dll "%DIST%\tools\payload_watermark\" >nul

mkdir "%DIST%\models"
set MODEL_SRC=models\Qwen3-4B-Instruct-2507-Q4_K_M.gguf
if not exist "%MODEL_SRC%" set MODEL_SRC=models\qwen3-4b-instruct-2507-q4_k_m.gguf
if not exist "%MODEL_SRC%" set MODEL_SRC=models\Qwen_Qwen3.5-4B-Q4_K_M.gguf
if not exist "%MODEL_SRC%" set MODEL_SRC=models\qwen3.5-4b-instruct-Q4_K_M.gguf
if not exist "%MODEL_SRC%" set MODEL_SRC=models\Qwen3.5-4B-Q4_K_M.gguf
if not exist "%MODEL_SRC%" (
  echo Missing Qwen3-4B-Instruct-2507 Q4_K_M GGUF model. Expected models\Qwen3-4B-Instruct-2507-Q4_K_M.gguf.
  exit /b 1
)
copy /y "%MODEL_SRC%" "%DIST%\models\base_model.gguf" >nul

mkdir "%DIST%\licenses"
copy /y third_party\llama.cpp\LICENSE "%DIST%\licenses\llama.cpp-LICENSE.txt" >nul

echo Packaged portable llama.cpp build to %DIST%
endlocal
