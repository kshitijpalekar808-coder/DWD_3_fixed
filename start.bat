@echo off
echo ============================================
echo   DataWatchDawgs v2 - Starting...
echo ============================================
echo.
pip install -r requirements.txt
echo.
echo Starting server...
python app.py
pause
