@echo off
echo ============================================
echo  Starting Cybersecurity Portfolio...
echo ============================================
echo.

cd /d "%~dp0cybersec_portfolio"

call .venv\Scripts\activate.bat

echo Starting Flask server...
echo Visit: http://127.0.0.1:5000
echo Press Ctrl+C to stop.
echo.

set FLASK_APP=app.py
set FLASK_ENV=development
flask run

pause
