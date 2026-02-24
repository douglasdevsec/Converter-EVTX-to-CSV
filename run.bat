@echo off
:: EVTX to CSV Converter — Launcher
:: Installs dependencies and opens the GUI
setlocal

echo.
echo  =============================================
echo    EVTX ^-^> CSV Converter
echo  =============================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  ERROR: Python no encontrado.
    echo  Descargalo desde https://python.org
    pause
    exit /b 1
)

:: Install / update dependencies
echo  Instalando dependencias...
python -m pip install -q --upgrade pip
python -m pip install -q -r "%~dp0requirements.txt"
if errorlevel 1 (
    echo.
    echo  ERROR: No se pudieron instalar las dependencias.
    pause
    exit /b 1
)

echo  Dependencias OK.
echo.

:: Launch GUI
python "%~dp0evtx_to_csv.py" %*
endlocal
