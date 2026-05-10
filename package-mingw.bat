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
mkdir "%DIST%\tools\payload_watermark\prompts"
copy /y tools\payload_watermark\prompts\*.txt "%DIST%\tools\payload_watermark\prompts\" >nul
if exist build\llama_worker_package\tokenizers (
  mkdir "%DIST%\tools\payload_watermark\tokenizers"
  xcopy /y /i /q build\llama_worker_package\tokenizers\* "%DIST%\tools\payload_watermark\tokenizers\" >nul
)
copy /y tools\payload_watermark\worker_config.txt "%DIST%\tools\payload_watermark\worker_config.txt" >nul

mkdir "%DIST%\models"
(
  echo ChineseInputAgentInstaller downloads the selected Qwen GGUF model during install.
  echo For portable zip-only installs, place a compatible GGUF model here and update tools\payload_watermark\worker_config.txt model=...
) > "%DIST%\models\README.txt"

mkdir "%DIST%\licenses"
copy /y third_party\llama.cpp\LICENSE "%DIST%\licenses\llama.cpp-LICENSE.txt" >nul

echo Packaged portable llama.cpp build to %DIST%
endlocal
