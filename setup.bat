@echo off
:: Title set karna terminal window ke liye
title CyberCop AI - One Click Installer
color 0A

echo ==================================================
echo       CYBERCOP AI: PROJECT SETUP WIZARD
echo ==================================================
echo.

:: Step 1: Python check karna
echo [STEP 1] Checking if Python is installed...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python Not Found! Please install Python.
    pause
    exit
)
echo [OK] Python detected.

echo.

:: Step 2: Pip  update.
echo [STEP 2] Updating Pip to the latest version...
python -m pip install --upgrade pip --user

echo.

:: Step 3: Modules check and install.
echo [STEP 3] Checking and Installing Project Modules...
echoThis process  could take 1-2 minute  (Internet connection needed)...
echo.

::  installation from Requirements file 
pip install -r requirements.txt

echo.
echo ==================================================
echo ✅ SUCCESS: All Modules are successfully Installed!
echo ==================================================
echo.
echo Use 'run.bat' to start the project  .
echo.
pause