#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════
#  TrailBlazer — Build Script (Linux / macOS)
#  Genera el binario TrailBlazer en dist/
#  Requisito: Python 3.9+
# ═══════════════════════════════════════════════════════════════════

set -e

echo ""
echo " [*] TrailBlazer Build Script (Linux/macOS)"
echo " ════════════════════════════════════════"
echo ""

# ── Verificar Python ──────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo " [!] Python3 no encontrado."
    exit 1
fi

# ── Instalar dependencias ─────────────────────────────────────────
echo " [*] Instalando dependencias..."
pip3 install -r requirements.txt --quiet --break-system-packages 2>/dev/null || \
pip3 install -r requirements.txt --quiet

# ── Instalar PyInstaller ──────────────────────────────────────────
echo " [*] Verificando PyInstaller..."
pip3 install pyinstaller --quiet --break-system-packages 2>/dev/null || \
pip3 install pyinstaller --quiet

# ── Limpiar builds anteriores ─────────────────────────────────────
echo " [*] Limpiando builds anteriores..."
rm -rf build dist/TrailBlazer

# ── Compilar ──────────────────────────────────────────────────────
echo " [*] Compilando TrailBlazer..."
echo ""
pyinstaller trailblazer.spec --noconfirm

# ── Resultado ─────────────────────────────────────────────────────
if [ -f "dist/TrailBlazer" ]; then
    chmod +x dist/TrailBlazer
    echo ""
    echo " ════════════════════════════════════════"
    echo " [OK] Binario generado en: $(pwd)/dist/TrailBlazer"
    echo ""
    echo " Para ejecutar:"
    echo "   ./dist/TrailBlazer              # menú interactivo"
    echo "   ./dist/TrailBlazer --full-scan  # scan directo"
    echo " ════════════════════════════════════════"
    echo ""
else
    echo " [!] El binario no fue generado. Revisa los errores."
    exit 1
fi
