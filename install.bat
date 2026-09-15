@echo off
rem Установка зависимостей Region Spoof Applet.
cd /d "%~dp0"
where python >nul 2>nul
if errorlevel 1 (
    echo Python не найден. Установите Python 3.10-3.12 с python.org и запустите install.bat снова.
    echo ВАЖНО: при установке отметьте галочку "Add python.exe to PATH".
    pause
    exit /b 1
)
python -m pip install --upgrade pip
python -m pip install proxybroker2 pystray Pillow requests
echo.
echo Зависимости установлены. Запустите run.bat
pause