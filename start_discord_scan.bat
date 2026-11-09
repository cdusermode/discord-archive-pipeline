@echo off
title Sentinel Vault - Ingestion Pipeline & ImGui Dashboard
echo ========================================================
echo  Launching Sentinel Vault...
echo ========================================================

cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% equ 0 (
    python app.py
) else (
    where py >nul 2>nul
    if %errorlevel% equ 0 (
        py app.py
    ) else (
        echo [ERROR] Python not found in system PATH.
        echo Please install Python 3.10+ from python.org and add it to PATH.
        pause
    )
)
if %errorlevel% neq 0 pause
