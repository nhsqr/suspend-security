@echo off
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0Suspend-Security.ps1" %*
