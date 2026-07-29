#!/usr/bin/env python3
"""
TrailBlazer Launcher — Menú interactivo para ejecución con doble clic.
Cuando el usuario hace doble clic en TrailBlazer.exe, este launcher
presenta un menú y ejecuta la opción seleccionada.
"""

import sys
import os
import platform
from pathlib import Path

# ── Compatibilidad: añadir el directorio raíz al sys.path ─────────────────────
# Cuando se ejecuta como .exe (PyInstaller), __file__ no existe.
# Usamos sys.executable para obtener la ruta del ejecutable.
if getattr(sys, "frozen", False):
    ROOT = Path(sys.executable).parent
else:
    ROOT = Path(__file__).resolve().parent

sys.path.insert(0, str(ROOT))

# ── Imports ───────────────────────────────────────────────────────────────────
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    from rich.prompt import Prompt, Confirm
    from rich.table import Table
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False

console = Console()

MENU_OPTIONS = [
    ("1", "🔍  Full Scan completo",
         "Ejecuta los 9 módulos + C2 Threat Intel automáticamente",
         ["--full-scan", "--check-c2"]),
    ("2", "⚡  Full Scan rápido (sin Threat Intel)",
         "Análisis completo sin consultas de red",
         ["--full-scan", "--no-report"]),
    ("3", "📊  Full Scan + Informe HTML",
         "Genera informe HTML detallado además de la consola",
         ["--full-scan", "--check-c2"]),
    ("4", "🔬  VirusTotal + C2 (con API key)",
         "Full scan con hasheo VT de ejecutables sospechosos",
         None),   # pide API key
    ("5", "💾  Guardar Baseline",
         "Captura el estado actual del sistema como referencia",
         ["--full-scan", "--baseline", "save"]),
    ("6", "🔀  Comparar con Baseline",
         "Muestra qué cambió respecto al estado base guardado",
         ["--full-scan", "--baseline", "compare"]),
    ("7", "📋  Listar Baselines",
         "Muestra los baselines guardados en este equipo",
         ["--baseline", "list"]),
    ("8", "🧩  Módulos específicos",
         "Elige qué módulos ejecutar",
         None),   # menú secundario
    ("9", "❌  Salir", "", None),
]

MODULES = [
    "processes", "network", "users", "persistence",
    "eventlogs", "filesystem", "credentials", "wmi", "antivirus",
]


# ─────────────────────────────────────────────────────────────────────────────
def print_banner() -> None:
    if not RICH_OK:
        print("\n  TrailBlazer — Red Team OPSEC & Forensic Footprint Analyzer\n")
        return
    banner = Text()
    banner.append("  ████████╗██████╗  █████╗ ██╗██╗     ██████╗ ██╗      █████╗ ███████╗███████╗██████╗ \n", style="bold red")
    banner.append("     ██╔══╝██╔══██╗██╔══██╗██║██║     ██╔══██╗██║     ██╔══██╗╚════██║██╔════╝██╔══██╗\n", style="red")
    banner.append("     ██║   ██████╔╝███████║██║██║     ██████╔╝██║     ███████║    ██╔╝█████╗  ██████╔╝\n", style="yellow")
    banner.append("     ██║   ██╔══██╗██╔══██║██║██║     ██╔══██╗██║     ██╔══██║   ██╔╝ ██╔══╝  ██╔══██╗\n", style="yellow")
    banner.append("     ██║   ██║  ██║██║  ██║██║███████╗██████╔╝███████╗██║  ██║   ██║  ███████╗██║  ██║\n", style="bold yellow")
    banner.append("     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚══════╝╚═╝  ╚═╝\n", style="dim yellow")
    banner.append(f"\n  v1.0.0  ·  Red Team OPSEC & Forensic Footprint Analyzer\n", style="dim")
    banner.append(f"  Sistema: {platform.system()} {platform.release()}  |  Host: {platform.node()}\n", style="dim cyan")
    console.print(Panel(banner, border_style="red", padding=(0, 2)))


def print_menu() -> None:
    if not RICH_OK:
        for opt in MENU_OPTIONS:
            print(f"  [{opt[0]}] {opt[1]}")
        return

    t = Table(box=box.ROUNDED, show_header=False, border_style="dim",
              padding=(0, 1), expand=False)
    t.add_column("N", style="bold cyan",  width=3, justify="center")
    t.add_column("Opción", style="bold",  width=30)
    t.add_column("Descripción", style="dim")

    for opt in MENU_OPTIONS:
        t.add_row(opt[0], opt[1], opt[2])

    console.print()
    console.print(t)
    console.print()


def ask_choice() -> str:
    if RICH_OK:
        return Prompt.ask(
            "  [bold cyan]Selecciona una opción[/]",
            choices=[o[0] for o in MENU_OPTIONS],
            default="1",
        )
    return input("  Opción: ").strip() or "1"


def ask_vt_key() -> str:
    if RICH_OK:
        return Prompt.ask("  [cyan]API Key de VirusTotal[/]").strip()
    return input("  API Key de VirusTotal: ").strip()


def ask_modules() -> list[str]:
    console.print("\n  [dim]Módulos disponibles:[/]")
    for i, m in enumerate(MODULES, 1):
        console.print(f"  [cyan]{i}[/]. {m}")
    console.print()
    raw = Prompt.ask(
        "  Números separados por coma (ej: 1,3,5) o [cyan]all[/] para todos",
        default="all"
    ).strip()
    if raw.lower() == "all":
        return MODULES
    selected = []
    for part in raw.split(","):
        part = part.strip()
        if part.isdigit():
            idx = int(part) - 1
            if 0 <= idx < len(MODULES):
                selected.append(MODULES[idx])
    return selected or MODULES


def wait_exit() -> None:
    console.print("\n  [dim]Presiona [bold]Enter[/] para cerrar...[/]")
    try:
        input()
    except (EOFError, KeyboardInterrupt):
        pass


# ─────────────────────────────────────────────────────────────────────────────
def run_trailblazer(extra_args: list[str]) -> None:
    """Llama a trailblazer.main() con los argumentos dados."""
    sys.argv = ["trailblazer"] + extra_args
    try:
        import trailblazer
        # Recargar para que tome los nuevos sys.argv
        import importlib
        importlib.reload(trailblazer)
        trailblazer.main()
    except SystemExit:
        pass
    except Exception as e:
        console.print(f"\n  [red]Error al ejecutar TrailBlazer:[/] {e}")
        import traceback
        traceback.print_exc()


# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    # Si se pasan argumentos directamente (uso desde CLI), delegar a trailblazer
    if len(sys.argv) > 1:
        sys.argv[0] = "trailblazer"
        import trailblazer
        trailblazer.main()
        return

    # Modo interactivo (doble clic)
    print_banner()
    print_menu()

    choice = ask_choice()

    if choice == "9":
        console.print("\n  [dim]Hasta luego.[/]\n")
        return

    # Buscar la opción seleccionada
    selected = next((o for o in MENU_OPTIONS if o[0] == choice), None)
    if not selected:
        console.print("[red]Opción inválida.[/]")
        wait_exit()
        return

    args = list(selected[3]) if selected[3] else []

    # Opciones que requieren input adicional
    if choice == "4":
        vt_key = ask_vt_key()
        args = ["--full-scan", "--check-c2", "--check-vt", "--vt-key", vt_key]

    elif choice == "8":
        mods = ask_modules()
        args = ["--modules", ",".join(mods)]

    elif choice == "6":
        # Baseline compare — pedir nombre
        name = "default"
        if RICH_OK:
            name = Prompt.ask("  Nombre del baseline", default="default").strip()
        args = ["--full-scan", "--baseline", "compare", "--baseline-name", name]

    elif choice == "5":
        name = "default"
        if RICH_OK:
            name = Prompt.ask("  Nombre para este baseline", default="default").strip()
        args = ["--full-scan", "--baseline", "save", "--baseline-name", name]

    # Opción 3: generar HTML con nombre automático
    if choice == "3":
        import datetime
        ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        args += ["--output", f"TrailBlazer_Report_{ts}.html"]

    console.print(f"\n  [dim]Ejecutando: trailblazer {' '.join(args)}[/]\n")
    run_trailblazer(args)
    wait_exit()


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
