@echo off
setlocal

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0tools\tests\test_ab_installs_crypto_exchange.ps1" %*

endlocal
