@echo off
:: TrailBlazer - Windows Installer
:: Ejecutar como Administrador para mejores resultados

title TrailBlazer Installer
color 04

echo.
echo  ============================================================
echo   TrailBlazer v1.0.0 - Windows Installer
echo   Red Team OPSEC ^& Forensic Footprint Analyzer
echo  ============================================================
echo.

:: Verificar Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python no encontrado. Instala Python 3.8+ desde https://python.org
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PYVER=%%v
echo  [OK] Python %PYVER% detectado

:: Verificar pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] pip no encontrado. Ejecuta: python -m ensurepip
    pause
    exit /b 1
)
echo  [OK] pip disponible

:: Instalar dependencias
echo.
echo  [*] Instalando dependencias...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo  [ERROR] Fallo al instalar dependencias
    pause
    exit /b 1
)
echo  [OK] psutil instalado
echo  [OK] rich instalado

:: Verificar instalacion
echo.
echo  [*] Verificando instalacion...
python -c "import psutil, rich; print('  [OK] Imports correctos')"
if errorlevel 1 (
    echo  [ERROR] Verificacion fallida
    pause
    exit /b 1
)

:: Crear acceso directo opcional
echo.
echo  ============================================================
echo   Instalacion completada exitosamente
echo  ============================================================
echo.
echo  Uso rapido:
echo    python trailblazer.py --full-scan
echo    python trailblazer.py --modules processes,network --verbose
echo    python trailblazer.py --help
echo.
echo  Nota: Ejecutar como Administrador para acceso completo a logs
echo        de eventos y procesos del sistema.
echo.
pause
