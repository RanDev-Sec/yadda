@echo off
rem yadda - detection engineering commands. Add this folder to your user PATH once (see README).
set "YADDA_HOME=%~dp0"
set "YADDA_HOME=%YADDA_HOME:~0,-1%"

if /i "%~1"=="go" goto :go

if exist "%YADDA_HOME%\.venv\Scripts\python.exe" goto :run
if /i not "%~1"=="setup" (
  echo yadda: not set up yet - run: yadda setup
  exit /b 1
)

echo Creating Python 3.12 environment ...
rem 1) uv, if installed: downloads its own Python 3.12, separate from the system Python
where uv >nul 2>&1 && (
  uv venv --seed -p 3.12 "%YADDA_HOME%\.venv" && goto :run
)
rem 2) python.org / winget install of 3.12, found via the py launcher
py -3.12 -c "import sys" >nul 2>&1 && (
  py -3.12 -m venv "%YADDA_HOME%\.venv" && goto :run
)
echo.
echo yadda: Python 3.12 is needed (newer versions break the packages Google's Content Manager pins).
echo     Install it, open a NEW terminal, and run "yadda setup" again:
echo.
echo        winget install -e --id Python.Python.3.12
echo     or install uv (it fetches its own Python 3.12):
echo        winget install -e --id astral-sh.uv
echo.
echo     It installs next to your current Python; it does not replace it.
exit /b 1

:run
"%YADDA_HOME%\.venv\Scripts\python.exe" "%YADDA_HOME%\yadda.py" %*
exit /b %ERRORLEVEL%

:go
rem No setlocal on purpose: this changes the directory of the cmd.exe window you typed it in.
if "%~2"=="" (cd /d "%YADDA_HOME%") else (cd /d "%YADDA_HOME%\environments\%~2")
exit /b 0
