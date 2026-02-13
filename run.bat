@echo off
:: Terminal window 
title CyberCop AI - Launching System
color 0B

echo ==================================================
echo        CYBERCOP AI: STARTING APPLICATION
echo ==================================================
echo.

:: Step 1: Checking  requirements are installed
echo [STEP 1] Initializing AI Engine...
python -c "import flask, pandas, pefile" >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Modules missing ! please run 'setup.bat' First.
    pause
    exit
)

:: Step 2: Open project in Browser.   
echo [STEP 2] Opening Browser...
::  wait for 2 second 
start ""  http://127.0.0.1:10000

:: Step 3: Start Flask server 
echo [STEP 3] Starting Flask Server on http://127.0.0.1:10000
echo.
echo Press CTRL+C to stop the server.
echo --------------------------------------------------
echo.

:: Main command to run app...
python app.py

echo.
echo [INFO] Server has been closed.
pause