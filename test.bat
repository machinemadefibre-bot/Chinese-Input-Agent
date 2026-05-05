@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\tests\test_project_invariants.ps1"

endlocal
