@echo off
setlocal EnableDelayedExpansion
cd /d "%~dp0"

set "POCKET_PYTHON="
for /d %%D in ("%LOCALAPPDATA%\Programs\Python\Python3*") do (
    if not defined POCKET_PYTHON if exist "%%~fD\python.exe" (
        "%%~fD\python.exe" -c "import sys, ida_pro_mcp; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
        if !errorlevel!==0 set "POCKET_PYTHON=%%~fD\python.exe"
    )
)

if not defined POCKET_PYTHON (
    for /f "delims=" %%P in ('where python.exe 2^>nul') do if not defined POCKET_PYTHON (
        "%%P" -c "import sys, ida_pro_mcp; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
        if !errorlevel!==0 set "POCKET_PYTHON=%%P"
    )
)

if defined POCKET_PYTHON (
    if "%~1"=="" (
        "%POCKET_PYTHON%" -m pocket_disasm control
    ) else (
        "%POCKET_PYTHON%" -m pocket_disasm %*
    )
    set "POCKET_EXIT=!errorlevel!"
    if not "!POCKET_EXIT!"=="0" pause
    exit /b !POCKET_EXIT!
)

where py.exe >nul 2>nul
if %errorlevel%==0 (
    py.exe -3.11 -c "import sys, ida_pro_mcp; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)" >nul 2>nul
    if !errorlevel!==0 (
        if "%~1"=="" (
            py.exe -3.11 -m pocket_disasm control
        ) else (
            py.exe -3.11 -m pocket_disasm %*
        )
        set "POCKET_EXIT=!errorlevel!"
        if not "!POCKET_EXIT!"=="0" pause
        exit /b !POCKET_EXIT!
    )
)

echo A compatible Python with ida-pro-mcp 2.0.0 was not found.
echo Run:  "%LOCALAPPDATA%\Programs\Python\Python311\python.exe" -m pip install -e "%~dp0"
echo Then start pocket.cmd again.
pause
exit /b 1
