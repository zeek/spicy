@echo on
:: Copyright (c) 2020-now by the Zeek Project. See LICENSE for details.

:: Import the MSVC compiler environment. The path is hard-coded to the CI
:: Docker image; adjust if running builds locally.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvarsall.bat" x86_amd64
if %errorlevel% neq 0 exit /b %errorlevel%

echo === System Information ===
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"Total Physical Memory"
echo.

echo === CPU Information ===
wmic cpu get NumberOfCores,NumberOfLogicalProcessors /Format:List
echo.

echo === Installed Chocolatey Packages ===
choco list
echo.

echo === Compiler Version ===
cl 2>&1 | findstr /C:"Version"
echo.

echo === CMake Version ===
cmake --version
echo.

echo === Ninja Version ===
ninja --version

echo.
echo === Installing BTest ===
python -m venv C:\btest-venv
C:\btest-venv\Scripts\pip install "btest @ git+https://github.com/zeek/btest@master"
if %errorlevel% neq 0 exit /b %errorlevel%

:: Fix CRLF in btest scripts so Git Bash can execute them.
"C:\Program Files\Git\bin\bash.exe" -c "for f in /c/btest-venv/Scripts/btest*; do sed -i 's/\r$//' \"$f\"; done"
