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
(
  echo ChineseInputAgentInstaller downloads base_model.gguf during install.
  echo For portable zip-only installs, place a compatible Qwen GGUF model here as base_model.gguf.
) > "%DIST%\models\README.txt"

mkdir "%DIST%\licenses"
copy /y third_party\llama.cpp\LICENSE "%DIST%\licenses\llama.cpp-LICENSE.txt" >nul

echo Packaged portable llama.cpp build to %DIST%
endlocal
