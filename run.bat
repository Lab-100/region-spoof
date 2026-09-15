@echo off
rem Запуск Region Spoof Applet без консоли (фоновый апплет с иконкой в трее).
cd /d "%~dp0"
where pythonw >nul 2>nul
if errorlevel 1 (
    set PY=python
) else (
    set PY=pythonw
)
start "" "%PY%" "%CD%\applet.py"