@echo on
:: Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
::
:: Run Spicy unit tests on Windows.

:: Import the MSVC compiler environment.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
if %errorlevel% neq 0 exit /b %errorlevel%

cd build

set FAILED=0

echo === Running hilti-rt-configuration-tests ===
bin\hilti-rt-configuration-tests.exe
if %errorlevel% neq 0 set FAILED=1

echo === Running hilti-rt-tests ===
bin\hilti-rt-tests.exe
if %errorlevel% neq 0 set FAILED=1

echo === Running hilti-toolchain-tests ===
bin\hilti-toolchain-tests.exe
if %errorlevel% neq 0 set FAILED=1

echo === Running spicy-rt-tests ===
bin\spicy-rt-tests.exe
if %errorlevel% neq 0 set FAILED=1

echo === Running spicy-toolchain-tests ===
bin\spicy-toolchain-tests.exe
if %errorlevel% neq 0 set FAILED=1

if %FAILED% neq 0 (
    echo.
    echo === SOME TESTS FAILED ===
    exit /b 1
)

echo.
echo === ALL TESTS PASSED ===
