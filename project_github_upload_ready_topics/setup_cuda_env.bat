@echo off
setlocal EnableDelayedExpansion

echo ===========================================
echo       PQC CUDA Environment Helper
echo ===========================================

:: Check for Winget
where winget >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] 'winget' not found. Please update Windows or install App Installer from Microsoft Store.
    pause
    exit /b 1
)

echo.
echo This script can help install the required tools using 'winget'.
echo Note: You may need Administrator privileges for these installations.
echo.

:VS_INSTALL
echo [STEP 1] Visual Studio 2022 Community (Desktop C++)
where cl >nul 2>nul
if %errorlevel% equ 0 (
    echo [OK] Visual Studio C++ compiler found.
) else (
    echo Visual Studio 2022 Community is NOT detected in PATH.
    set /p INSTALL_VS="Do you want to run the installer for Visual Studio 2022? (Y/N): "
    if /i "!INSTALL_VS!"=="Y" (
        echo Installing Visual Studio 2022 Community...
        winget install -e --id Microsoft.VisualStudio.2022.Community --scope machine
        echo.
        echo [IMPORTANT] After installation, you MUST open Visual Studio Installer 
        echo and modify the installation to include the "Desktop development with C++" workload.
    )
)

:CUDA_INSTALL
echo.
echo [STEP 2] NVIDIA CUDA Toolkit
where nvcc >nul 2>nul
if %errorlevel% equ 0 (
    echo [OK] CUDA Toolkit found.
) else (
    echo CUDA Toolkit is NOT detected.
    set /p INSTALL_CUDA="Do you want to run the installer for NVIDIA CUDA Toolkit? (Y/N): "
    if /i "!INSTALL_CUDA!"=="Y" (
        echo Installing NVIDIA CUDA Toolkit...
        winget install -e --id Nvidia.CUDA --scope machine
        echo.
        echo [IMPORTANT] You may need to restart your computer after this installation.
    )
)

:CUPQC_CHECK
echo.
echo [STEP 3] NVIDIA cuPQC SDK
if exist "C:\libs\cupqc-sdk" (
    echo [OK] Recommended folder 'C:\libs\cupqc-sdk' exists.
) else (
    echo Creating recommended folder 'C:\libs\cupqc-sdk'...
    mkdir "C:\libs\cupqc-sdk"
)

echo.
echo *** ACTION REQUIRED for cuPQC SDK ***
echo The cuPQC SDK cannot be installed automatically as it requires an NVIDIA Developer account.
echo.
echo 1. Go to: https://developer.nvidia.com/cupqc-sdk
2. Login/Register and download the Windows archive (.zip or .tar.gz).
3. Extract the contents DIRECTLY into: C:\libs\cupqc-sdk
echo    (The folder C:\libs\cupqc-sdk should contain 'include', 'lib', 'cmake' folders directly)
echo.

pause
