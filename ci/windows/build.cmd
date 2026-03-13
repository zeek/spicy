@echo on
:: Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
::
:: Build Spicy on Windows with MSVC and Ninja.

:: Import the MSVC compiler environment. The path is hard-coded to the CI
:: Docker image; adjust if running builds locally.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
if %errorlevel% neq 0 exit /b %errorlevel%

mkdir build
cd build

cmake.exe .. ^
    -G Ninja ^
    -DCMAKE_BUILD_TYPE=Release ^
    -DCMAKE_C_COMPILER=cl.exe ^
    -DCMAKE_CXX_COMPILER=cl.exe ^
    -DVCPKG_TARGET_TRIPLET=x64-windows-static ^
    -DVCPKG_HOST_TRIPLET=x64-windows-static ^
    -DVCPKG_OVERLAY_TRIPLETS=../vcpkg-triplets
if %errorlevel% neq 0 exit /b %errorlevel%

cmake.exe --build .
if %errorlevel% neq 0 exit /b %errorlevel%
