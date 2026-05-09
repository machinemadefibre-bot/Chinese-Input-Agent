@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\tests\test_project_invariants.ps1"
if errorlevel 1 exit /b %errorlevel%

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\tests\test_worker_key_carriers.ps1" -FullLength
if errorlevel 1 exit /b %errorlevel%

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\tests\test_chat_history_sqlite.ps1"
if errorlevel 1 exit /b %errorlevel%

endlocal
