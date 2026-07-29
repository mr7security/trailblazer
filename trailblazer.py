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
from core import baseline as bl
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

    # ── Baseline / Delta ──────────────────────────────────────────────────────
    # ── Threat Intel / VirusTotal ─────────────────────────────────────────────
    p.add_argument(
        "--vt-key", type=str, default=None,
        metavar="API_KEY",
        help="API key de VirusTotal para hash lookup de archivos sospechosos",
    )
    p.add_argument(
        "--check-vt", action="store_true",
        help="Activar consultas VirusTotal (requiere --vt-key o VIRUSTOTAL_API_KEY)",
    )
    p.add_argument(
        "--check-c2", action="store_true",
        help="Comparar IPs externas contra lista Feodo Tracker C2 (sin API key)",
    )

    # ── Baseline / Delta ──────────────────────────────────────────────────────
    p.add_argument(
        "--baseline", choices=["save", "compare", "list"],
        metavar="ACTION",
        help="Modo baseline: 'save' guarda el estado actual, 'compare' compara con baseline "
             "guardado, 'list' muestra baselines disponibles",
    )
    p.add_argument(
        "--baseline-name", type=str, default="default",
        metavar="NAME",
        help="Nombre del baseline (default: 'default')",
    )

    return p.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
def resolve_modules(args: argparse.Namespace) -> list[str]:
    """Determina qué módulos ejecutar."""
    # --baseline list no necesita módulos
    if getattr(args, "baseline", None) == "list":
        return []

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

    # --baseline compare/save sin --full-scan → todos los módulos
    if getattr(args, "baseline", None) in ("save", "compare"):
        return list(AVAILABLE_MODULES.keys())

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
def _is_local_ip(ip: str) -> bool:
    return ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.",
                          "172.18.", "172.19.", "172.2", "::1", "fe80", ""))


# ─────────────────────────────────────────────────────────────────────────────
def main() -> None:
    args        = parse_args()
    start_time  = datetime.now()

    # ── Baseline list (sin scan) ──────────────────────────────────────────────
    if getattr(args, "baseline", None) == "list":
        tr.print_banner(TOOL_VERSION, TOOL_DESC)
        baselines = bl.list_baselines()
        if not baselines:
            tr.console.print("[yellow]  No hay baselines guardados. "
                             "Usa --baseline save para crear uno.[/]")
        else:
            tr.console.print(f"\n  [bold]Baselines disponibles ({len(baselines)}):[/]\n")
            for b in baselines:
                tr.console.print(
                    f"  [cyan]{b['name']}[/]  "
                    f"[dim]{b.get('created', '?')[:19]}[/]  "
                    f"[yellow]{b.get('count', '?')} findings[/]"
                )
        return

    modules     = resolve_modules(args)

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

    # ── Enrichment: VirusTotal + C2 Threat Intel ──────────────────────────────
    if getattr(args, "check_vt", False) or getattr(args, "check_c2", False):
        import importlib
        enrich_mod = importlib.import_module("collectors.enrichment")

        # Recopilar archivos sospechosos del módulo filesystem
        suspicious_files = []
        for r in module_results:
            if r.get("module") == "filesystem":
                for item in r.get("items", []):
                    if item.get("type") in ("suspicious_exec", "double_extension"):
                        p_path = item.get("path", "")
                        if p_path:
                            suspicious_files.append(p_path)

        # Recopilar IPs externas del módulo network
        external_ips = []
        for r in module_results:
            if r.get("module") == "network":
                for conn in r.get("connections", []):
                    raddr = conn.get("raddr", "")
                    if raddr and not _is_local_ip(raddr.split(":")[0]):
                        ip = raddr.split(":")[0]
                        if ip and ip not in external_ips:
                            external_ips.append(ip)

        tr.print_section("🔍  THREAT INTEL ENRICHMENT")
        enrich_result = enrich_mod.collect(
            vt_key=getattr(args, "vt_key", None),
            check_vt=getattr(args, "check_vt", False),
            check_c2=getattr(args, "check_c2", False),
            suspicious_files=suspicious_files,
            external_ips=external_ips,
            verbose=args.verbose,
        )
        module_results.append(enrich_result)
        s = enrich_result.get("summary", {})
        tr.console.print(
            f"  VT consultados: [cyan]{s.get('vt_checked',0)}[/]  "
            f"C2 matches: [{'red' if s.get('c2_matches',0) else 'green'}]"
            f"{s.get('c2_matches',0)}[/]  "
            f"Findings: [yellow]{s.get('findings_count',0)}[/]"
        )

    # ── Resumen global ────────────────────────────────────────────────────────
    total_risk = sum(r.get("risk_score", 0) for r in module_results)
    max_risk   = len(module_results) * 100   # referencia aproximada

    tr.print_section("📊  RESUMEN")
    tr.print_module_summary(module_results)

    tr.print_section("🔎  FINDINGS")
    tr.print_findings(module_results, verbose=args.verbose)

    tr.print_section("🛡  OPSEC SCORE")
    tr.print_opsec_score(total_risk, max_risk)

    # ── Baseline save / compare ───────────────────────────────────────────────
    baseline_action = getattr(args, "baseline", None)
    baseline_name   = getattr(args, "baseline_name", "default")

    if baseline_action == "save":
        saved_path = bl.save(
            module_results,
            name=baseline_name,
            meta={"platform": platform.system(), "hostname": platform.node()},
        )
        tr.console.print(
            f"\n  [green]✓ Baseline guardado:[/] [cyan]{saved_path}[/]  "
            f"([yellow]{sum(len(r.get('findings',[])) for r in module_results)} findings[/])"
        )

    elif baseline_action == "compare":
        try:
            base = bl.load(baseline_name)
            delta = bl.compare(base, module_results)
            tr.print_section(f"🔀  DELTA vs BASELINE '{baseline_name}'")
            tr.print_delta(delta)
        except FileNotFoundError as e:
            tr.console.print(f"\n  [red]Error:[/] {e}")

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
