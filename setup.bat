@echo off
echo ============================================
echo  Timothy Victor - Cybersecurity Portfolio
echo  Setup Script for Windows
echo ============================================
echo.

cd /d "%~dp0cybersec_portfolio"

echo [1/4] Creating virtual environment...
python3.13 -m venv .venv
if errorlevel 1 (
    echo ERROR: Could not create venv. Trying python...
    python -m venv .venv
)

echo.
echo [2/4] Activating virtual environment...
call .venv\Scripts\activate.bat

echo.
echo [3/4] Installing dependencies...
pip install -r requirements.txt

echo.
echo [4/4] Setting up environment variables...
if not exist .env (
    copy .env.example .env
    echo Created .env file. Please edit it with your real values.
    echo Open: cybersec_portfolio\.env
)

echo.
echo ============================================
echo  Setup complete!
echo  Now run: run.bat
echo ============================================
pause
