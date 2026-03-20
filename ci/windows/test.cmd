@echo on
:: Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.
::
:: Run Spicy unit tests on Windows.

:: Import the MSVC compiler environment.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
if %errorlevel% neq 0 exit /b %errorlevel%

cd build

set FAILED=0

echo === Running unit tests via ctest ===
ctest --output-on-failure
if %errorlevel% neq 0 set FAILED=1

:: Run BTest integration tests.
echo.
echo === Running BTest ===
cd ..
"C:\Program Files\Git\bin\bash.exe" -c "export SPICY_BUILD_DIRECTORY=$(cygpath -u '%CD%/build'); export HILTI_CXX_COMPILER_LAUNCHER=; cd tests && btest -j 5 -f diag.log -z 3 2>&1; rc=$?; if [ $rc -ne 0 ]; then echo; echo '=== Begin diagnostics ==='; cat diag.log; echo '=== End diagnostics ==='; fi; exit $rc"
if %errorlevel% neq 0 (
    echo.
    echo === BTEST FAILED ===
    set FAILED=1
)

if %FAILED% neq 0 exit /b 1

echo.
echo === ALL TESTS PASSED ===
