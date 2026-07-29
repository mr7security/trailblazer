#!/usr/bin/env bash
# TrailBlazer - Linux/macOS Installer

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo -e "${RED} ============================================================${NC}"
echo -e "${RED}  TrailBlazer v1.0.0 - Linux/macOS Installer${NC}"
echo -e "${RED}  Red Team OPSEC & Forensic Footprint Analyzer${NC}"
echo -e "${RED} ============================================================${NC}"
echo ""

# Verificar Python 3.8+
if ! command -v python3 &>/dev/null; then
    echo -e "${RED}[ERROR]${NC} Python3 no encontrado. Instala Python 3.8+"
    exit 1
fi

PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PYMIN=$(python3 -c "import sys; print(1 if sys.version_info >= (3,8) else 0)")

if [ "$PYMIN" = "0" ]; then
    echo -e "${RED}[ERROR]${NC} Se requiere Python 3.8+. Versión detectada: $PYVER"
    exit 1
fi
echo -e "${GREEN}[OK]${NC} Python $PYVER detectado"

# Verificar pip
if ! command -v pip3 &>/dev/null; then
    echo -e "${YELLOW}[WARN]${NC} pip3 no encontrado, intentando instalar..."
    python3 -m ensurepip --upgrade 2>/dev/null || {
        echo -e "${RED}[ERROR]${NC} No se pudo instalar pip"
        exit 1
    }
fi
echo -e "${GREEN}[OK]${NC} pip disponible"

# Entorno virtual (recomendado)
if [ ! -d "venv" ]; then
    echo ""
    echo -e "${YELLOW}[*]${NC} Creando entorno virtual..."
    python3 -m venv venv
    echo -e "${GREEN}[OK]${NC} Entorno virtual creado en ./venv"
fi

# Activar venv e instalar
source venv/bin/activate 2>/dev/null || true

echo ""
echo -e "${YELLOW}[*]${NC} Instalando dependencias..."
pip3 install -r requirements.txt --quiet
echo -e "${GREEN}[OK]${NC} psutil instalado"
echo -e "${GREEN}[OK]${NC} rich instalado"

# Verificar
echo ""
echo -e "${YELLOW}[*]${NC} Verificando instalación..."
python3 -c "import psutil, rich; print('\033[0;32m[OK]\033[0m Imports correctos')"

# Permisos de ejecución
chmod +x trailblazer.py 2>/dev/null || true

echo ""
echo -e "${GREEN} ============================================================${NC}"
echo -e "${GREEN}  Instalación completada${NC}"
echo -e "${GREEN} ============================================================${NC}"
echo ""
echo "  Uso rápido:"
echo "    python3 trailblazer.py --full-scan"
echo "    python3 trailblazer.py --modules processes,network --verbose"
echo "    python3 trailblazer.py --help"
echo ""
echo -e "${YELLOW}  Nota:${NC} Para acceso completo a logs, ejecuta con sudo:"
echo "    sudo python3 trailblazer.py --full-scan"
echo ""
