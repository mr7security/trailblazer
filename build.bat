@echo off
REM ═══════════════════════════════════════════════════════════════════
REM  TrailBlazer — Build Script (Windows)
REM  Genera TrailBlazer.exe en la carpeta dist/
REM  Requisito: Python 3.9+ en PATH
REM ═══════════════════════════════════════════════════════════════════

echo.
echo  [*] TrailBlazer Build Script
echo  ════════════════════════════════════════
echo.

REM ── Verificar Python ──────────────────────────────────────────────
python --version >nul 2>&1
if errorlevel 1 (
    echo  [!] Python no encontrado. Instala Python 3.9+ y añadelo al PATH.
    pause
    exit /b 1
)

REM ── Instalar dependencias ─────────────────────────────────────────
echo  [*] Instalando dependencias...
pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo  [!] Error al instalar dependencias.
    pause
    exit /b 1
)

REM ── Instalar PyInstaller ──────────────────────────────────────────
echo  [*] Verificando PyInstaller...
pip install pyinstaller --quiet
if errorlevel 1 (
    echo  [!] Error al instalar PyInstaller.
    pause
    exit /b 1
)

REM ── Limpiar builds anteriores ─────────────────────────────────────
echo  [*] Limpiando builds anteriores...
if exist dist\TrailBlazer.exe del /f /q dist\TrailBlazer.exe
if exist build rmdir /s /q build

REM ── Compilar ──────────────────────────────────────────────────────
echo  [*] Compilando TrailBlazer.exe...
echo.
pyinstaller trailblazer.spec --noconfirm

if errorlevel 1 (
    echo.
    echo  [!] Error durante la compilacion.
    pause
    exit /b 1
)

REM ── Resultado ─────────────────────────────────────────────────────
if exist dist\TrailBlazer.exe (
    echo.
    echo  ════════════════════════════════════════
    echo  [OK] TrailBlazer.exe generado en:
    echo       %CD%\dist\TrailBlazer.exe
    echo.
    echo  Para ejecutar:  doble clic en dist\TrailBlazer.exe
    echo  O desde CMD:    dist\TrailBlazer.exe --full-scan
    echo  ════════════════════════════════════════
    echo.
) else (
    echo  [!] El ejecutable no fue generado. Revisa los errores arriba.
)

pause
