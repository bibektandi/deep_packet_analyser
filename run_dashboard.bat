@echo off
title DPI Engine & DNS Firewall Web Dashboard
echo ============================================================
echo   Starting Deep Packet Inspection & DNS Firewall System...
echo   Open in browser: http://localhost:8080
echo ============================================================
echo.

:: Open browser automatically after 2 seconds
timeout /t 2 /nobreak >nul
start http://localhost:8080

:: Start Python Bridge Server
python server.py

pause
