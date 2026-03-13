@echo off
setlocal EnableDelayedExpansion

echo ==========================================
echo      PQC CUDA Integration Build Script
echo ==========================================

:: Check for NVCC (CUDA Compiler)
where nvcc >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] CUDA Toolkit not found!
    echo 'nvcc' is not in your PATH.
    echo Please install the NVIDIA CUDA Toolkit (via setup_cuda_env.bat) and restart your terminal.
    pause
    exit /b 1
)

:: Check for CMake
where cmake >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] CMake not found!
    echo Please install CMake or Visual Studio with CMake tools.
    pause
    exit /b 1
)

:: Check recommended path first
set CUPQC_DIR=C:\libs\cupqc-sdk

if not exist "%CUPQC_DIR%\include\cupqc\pk.hpp" (
    echo [WARNING] Recommended path C:\libs\cupqc-sdk does not seem to contain the SDK headers.
    echo We expected to find: C:\libs\cupqc-sdk\include\cupqc\pk.hpp
    echo.
    set /p CUPQC_DIR="Please enter the correct full path to the extracted cuPQC SDK: "
)

if not exist "%CUPQC_DIR%" (
    echo [ERROR] The directory "%CUPQC_DIR%" does not exist.
    pause
    exit /b 1
)

echo.
echo [INFO] Found CUDA Toolkit.
echo [INFO] Using cuPQC SDK at: %CUPQC_DIR%
echo.

:: Create build directory
if not exist "liboqs\build" mkdir "liboqs\build"
cd liboqs\build

:: Configure with CMake
echo [INFO] Configuring CMake with -DOQS_USE_CUPQC=ON...
echo [INFO] This might take a minute...

cmake .. -GNinja ^
    -DOQS_USE_CUPQC=ON ^
    -DCMAKE_PREFIX_PATH="%CUPQC_DIR%" ^
    -DOQS_BUILD_ONLY_LIB=ON ^
    -DCMAKE_BUILD_TYPE=Release 

if %errorlevel% neq 0 (
    echo [ERROR] Ninja generator failed or not found.
    echo Attempting to fall back to Visual Studio generator...
    
    :: Clean cache for retry
    if exist CMakeCache.txt del CMakeCache.txt
    
    cmake .. ^
        -DOQS_USE_CUPQC=ON ^
        -DCMAKE_PREFIX_PATH="%CUPQC_DIR%" ^
        -DOQS_BUILD_ONLY_LIB=ON ^
        -DCMAKE_BUILD_TYPE=Release
    
    if !errorlevel! neq 0 (
        echo [FATAL] CMake configuration failed. 
        echo Please ensure you are running in "x64 Native Tools Command Prompt for VS 2022".
        cd ..\..
        pause
        exit /b 1
    )
)

:: Build
echo.
echo [INFO] Building liboqs (this may take a while)...
cmake --build . --config Release

if %errorlevel% neq 0 (
    echo [FATAL] Build failed.
    cd ..\..
    pause
    exit /b 1
)

:: Copy DLL
echo.
echo [INFO] Build successful! Copying DLL...

:: Find the DLL (location depends on generator)
set FOUND_DLL=0
if exist "bin\oqs.dll" (
    copy /Y "bin\oqs.dll" "..\..\liboqs.dll"
    set FOUND_DLL=1
) else if exist "lib\oqs.dll" (
    copy /Y "lib\oqs.dll" "..\..\liboqs.dll"
    set FOUND_DLL=1
) else if exist "Release\oqs.dll" (
    copy /Y "Release\oqs.dll" "..\..\liboqs.dll"
    set FOUND_DLL=1
)

if !FOUND_DLL! equ 0 (
    echo [WARNING] Could not automatically find 'oqs.dll' in the build directory.
    echo Please look inside liboqs\build for the DLL and copy it manually to %CD%\..\..\liboqs.dll
    cd ..\..
    pause
    exit /b 1
)

echo.
echo ==========================================================
echo [SUCCESS] liboqs.dll has been updated with CUDA support!
echo ==========================================================
cd ..\..
pause
