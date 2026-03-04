# PQC CUDA Integration Guide

This guide explains how to enable GPU acceleration for Post-Quantum Cryptography in your project using NVIDIA CUDA.

## Prerequisites

Before running the build script, you must install the following software on your Windows machine:

1.  **Visual Studio 2022 (Community Edition)**
    -   Download from [visualstudio.microsoft.com](https://visualstudio.microsoft.com/vs/community/)
    -   During installation, select the **"Desktop development with C++"** workload.
    -   Ensure "CMake tools for Windows" is checked (it usually is by default).

2.  **NVIDIA CUDA Toolkit (Latest Version)**
    -   Download from [developer.nvidia.com/cuda-downloads](https://developer.nvidia.com/cuda-downloads)
    -   Install the standard "Express" installation.
    -   **Important**: After installation, restart your computer to ensure environment variables are updated.
    -   Verify the installation by opening a new terminal and running: `nvcc --version`

3.  **NVIDIA cuPQC SDK**
    -   This is the library that implements the GPU-accelerated algorithms.
    -   Download the SDK (x86_64) from the [NVIDIA cuPQC Page](https://developer.nvidia.com/cupqc-sdk).
    -   Extract the `.tar.gz` or `.zip` file to a permanent location (e.g., `C:\libs\cupqc-sdk`).
    -   **Note**: Remember this path, you will need it for the build script.

## Building Liboqs with CUDA Support

Once the prerequisites are installed:

1.  Open the **"x64 Native Tools Command Prompt for VS 2022"** (search for it in the Start Menu).
    -   *Do not use standard PowerShell or CMD, as they might lack the compiler environment variables.*

2.  Navigate to your project directory:
    ```cmd
    cd c:\Users\yksk7\PQC
    ```

3.  Run the provided build script:
    ```cmd
    build_with_cuda.bat
    ```

4.  The script will ask for the location where you extracted the **cuPQC SDK**. Enter the full path (e.g., `C:\libs\cupqc-sdk`).

5.  The script will:
    -   Configure `liboqs` with `-DOQS_USE_CUPQC=ON`.
    -   Compile the library using the CUDA compiler.
    -   Replace your existing `liboqs.dll` with the new GPU-accelerated version.

## Usage

After a successful build, your Python scripts (`pqc_signer.py`, `server/zero_trust.py`) will automatically use the GPU specific algorithms.

-   **Verification**: Run `python list_algos.py`. You should see the same algorithms, but internal execution will now offload to the GPU.
-   **Performance**: Run `python tests/benchmark_pqc.py` to see the throughput improvements (especially with batch sizes > 10).
