#!/usr/bin/env python3
"""
████████╗██████╗  █████╗ ██╗██╗     ██████╗ ██╗      █████╗ ███████╗███████╗██████╗
   ██╔══╝██╔══██╗██╔══██╗██║██║     ██╔══██╗██║     ██╔══██╗╚════██║██╔════╝██╔══██╗
   ██║   ██████╔╝███████║██║██║     ██████╔╝██║     ███████║    ██╔╝█████╗  ██████╔╝
   ██║   ██╔══██╗██╔══██║██║██║     ██╔══██╗██║     ██╔══██║   ██╔╝ ██╔══╝  ██╔══██╗
   ██║   ██║  ██║██║  ██║██║███████╗██████╔╝███████╗██║  ██║   ██║  ███████╗██║  ██║
   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚══════╝╚═╝  ╚═╝

TrailBlazer v1.0.0 — Red Team OPSEC & Forensic Footprint Analyzer
Autor:   Red Team Portfolio — Miguel R.
Licencia: MIT (uso exclusivo en sistemas autorizados)

USO:
  python trailblazer.py --full-scan
  python trailblazer.py --modules processes,network,users
  python trailblazer.py --full-scan --output reporte.html --timeframe 48h
  python trailblazer.py --modules eventlogs --timeframe 7d --verbose
"""

import sys
import os
import argparse
import json
import platform
from datetime import datetime
from pathlib import Path

# ── Compatibilidad: añadir el directorio raíz al path ────────────────────────
ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# ── Imports de la herramienta ─────────────────────────────────────────────────
from core.config import TOOL_NAME, TOOL_VERSION, TOOL_DESC, TIMEFRAME_SECONDS
from reporters import terminal_reporter as tr
from reporters import html_reporter

# Módulos disponibles
AVAILABLE_MODULES = {
    "processes":   ("collectors.processes",   "processes"),
    "network":     ("collectors.network",     "network"),
    "users":       ("collectors.users",       "users"),
    "persistence": ("collectors.persistence", "persistence"),
    "eventlogs":   ("collectors.eventlogs",   "eventlogs"),
    "filesystem":  ("collectors.filesystem",  "filesystem"),
    "credentials": ("collectors.credentials", "credentials"),
    "wmi":         ("collectors.wmi",         "wmi"),
    "antivirus":   ("collectors.antivirus",   "antivirus"),
}


# ─────────────────────────────────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="trailblazer",
        description=f"{TOOL_NAME} v{TOOL_VERSION} — {TOOL_DESC}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Módulos disponibles:
  processes   — Procesos en ejecución y análisis de comportamiento
  network     — Conexiones activas, puertos en escucha, tráfico sospechoso
  users       — Cuentas locales, sesiones, grupos privilegiados
  persistence — Mecanismos de persistencia (registro, cron, servicios...)
  eventlogs   — Análisis de logs de eventos (Windows EVTX / Linux auth.log)
  filesystem  — Prefetch, executables en rutas temporales, timestomping
  credentials — Claves SSH, AWS, .env, historial PowerShell, tokens Git
  wmi         — WMI Event Subscriptions, COM hijacking, IFEO (Windows)
  antivirus   — Estado Defender, exclusiones, AMSI, detección de EDR/AV

Ejemplos:
  python trailblazer.py --full-scan
  python trailblazer.py --full-scan --output informe.html --timeframe 48h
  python trailblazer.py --modules processes,network --verbose
  python trailblazer.py --modules eventlogs --timeframe 7d
        """,
    )
    p.add_argument(
        "--full-scan", action="store_true",
        help="Ejecutar todos los módulos de análisis",
    )
    p.add_argument(
        "--modules", type=str, default=None,
        metavar="MOD1,MOD2",
        help="Módulos a ejecutar separados por coma",
    )
    p.add_argument(
        "--output", type=str, default=None,
        metavar="FILE.html",
        help="Ruta del informe HTML (por defecto: trailblazer_YYYYMMDD_HHMMSS.html)",
    )
    p.add_argument(
        "--timeframe", type=str, default="24h",
        choices=list(TIMEFRAME_SECONDS.keys()),
        help="Ventana temporal para análisis de logs (default: 24h)",
    )
    p.add_argument(
        "--no-report", action="store_true",
        help="No generar informe HTML",
    )
    p.add_argument(
        "--json", action="store_true",
        help="Exportar resultados en JSON además del HTML",
    )
    p.add_argument(
        "--verbose", "-v", action="store_true",
        help="Salida detallada",
    )
    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
def resolve_modules(args: argparse.Namespace) -> list[str]:
    """Determina qué módulos ejecutar."""
    if args.full_scan:
        return list(AVAILABLE_MODULES.keys())

    if args.modules:
        requested = [m.strip().lower() for m in args.modules.split(",")]
        invalid   = [m for m in requested if m not in AVAILABLE_MODULES]
        if invalid:
            print(f"[!] Módulos no reconocidos: {', '.join(invalid)}")
            print(f"    Disponibles: {', '.join(AVAILABLE_MODULES.keys())}")
            sys.exit(1)
        return requested

    # Si no se especifica nada, mostrar ayuda
    print("[!] Especifica --full-scan o --modules <lista>")
    print("    Ejecuta con -h para ver la ayuda completa.")
    sys.exit(1)


# ─────────────────────────────────────────────────────────────────────────────
def run_module(mod_name: str, args: argparse.Namespace) -> dict:
    """Importa y ejecuta un módulo collector."""
    import importlib
    module_path, _ = AVAILABLE_MODULES[mod_name]
    try:
        mod = importlib.import_module(module_path)
        if mod_name == "eventlogs":
            return mod.collect(timeframe=args.timeframe, verbose=args.verbose)
        else:
            return mod.collect(verbose=args.verbose)
    except Exception as e:
        return {
            "module":     mod_name,
            "error":      str(e),
            "findings":   [],
            "summary":    {},
            "risk_score": 0,
        }


# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args        = parse_args()
    modules     = resolve_modules(args)
    start_time  = datetime.now()

    # Banner
    tr.print_banner(TOOL_VERSION, TOOL_DESC)

    # Info del sistema
    tr.console.print(
        f"\n  [dim]Sistema: [cyan]{platform.system()} {platform.release()}[/]  "
        f"Host: [cyan]{platform.node()}[/]  "
        f"Módulos: [yellow]{', '.join(modules)}[/][/]\n"
    )

    # ── Ejecutar módulos ──────────────────────────────────────────────────────
    module_results = []
    for mod_name in modules:
        tr.print_section(f"▶  {mod_name.upper()}")
        result = run_module(mod_name, args)
        module_results.append(result)

        # Impresión rápida de resumen por módulo
        printer_map = {
            "processes":   tr.print_processes,
            "network":     tr.print_network,
            "users":       tr.print_users,
            "persistence": tr.print_persistence,
            "eventlogs":   tr.print_eventlogs,
            "filesystem":  tr.print_generic,
            "credentials": tr.print_generic,
            "wmi":         tr.print_generic,
            "antivirus":   tr.print_antivirus,
        }
        if mod_name in printer_map:
            printer_map[mod_name](result, args.verbose)

    # ── Resumen global ────────────────────────────────────────────────────────
    total_risk = sum(r.get("risk_score", 0) for r in module_results)
    max_risk   = len(module_results) * 100   # referencia aproximada

    tr.print_section("📊  RESUMEN")
    tr.print_module_summary(module_results)

    tr.print_section("🔎  FINDINGS")
    tr.print_findings(module_results, verbose=args.verbose)

    tr.print_section("🛡  OPSEC SCORE")
    tr.print_opsec_score(total_risk, max_risk)

    # ── Informe HTML ──────────────────────────────────────────────────────────
    if not args.no_report:
        output_path = args.output or (
            f"trailblazer_report_{start_time.strftime('%Y%m%d_%H%M%S')}.html"
        )
        saved = html_reporter.generate(
            module_results, total_risk,
            timeframe=args.timeframe,
            output_path=output_path,
        )
        tr.console.print(f"\n  [green]✓ Informe HTML guardado:[/] [cyan]{saved}[/]")

    # ── Export JSON ───────────────────────────────────────────────────────────
    if args.json:
        json_path = output_path.replace(".html", ".json") if not args.no_report else (
            f"trailblazer_{start_time.strftime('%Y%m%d_%H%M%S')}.json"
        )
        safe_results = []
        for r in module_results:
            # Convertir objetos no serializables
            safe_results.append(json.loads(json.dumps(r, default=str)))
        with open(json_path, "w", encoding="utf-8") as jf:
            json.dump({
                "meta": {
                    "tool":      TOOL_NAME,
                    "version":   TOOL_VERSION,
                    "timestamp": start_time.isoformat(),
                    "timeframe": args.timeframe,
                    "platform":  platform.system(),
                    "hostname":  platform.node(),
                    "risk_score": total_risk,
                },
                "results": safe_results,
            }, jf, indent=2, ensure_ascii=False, default=str)
        tr.console.print(f"  [green]✓ JSON exportado:[/] [cyan]{json_path}[/]")

    # Tiempo de ejecución
    elapsed = (datetime.now() - start_time).total_seconds()
    tr.console.print(f"\n  [dim]Análisis completado en {elapsed:.1f}s[/]\n")


# ─────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
