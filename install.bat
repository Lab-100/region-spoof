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
python -m pip install --disable-pip-version-check --timeout 60 --retries 1 proxybroker2 pystray Pillow requests
echo.
echo Загрузка бинарников (sing-box, mihomo, wintun) из Releases с проверкой SHA256...
python "%~dp0download_binaries.py"
if errorlevel 1 (
    echo.
    echo ВНИМАНИЕ: бинарники не загружены или не прошли проверку SHA256.
    echo Связки singbox/mihomo будут недоступны, но системный прокси
    echo работает и без них. Повторите install.bat или скачайте бинарники
    echo вручную - см. README, раздел "Установка".
)
echo.
echo Зависимости установлены. Запустите run.bat
pause