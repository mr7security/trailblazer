"""
TrailBlazer :: Reporter - Terminal (Rich)
Renderiza los resultados en consola con formato visual profesional.
"""

from __future__ import annotations
from typing import Any

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text
    from rich.rule import Rule
    from rich.columns import Columns
    from rich import box
    RICH_OK = True
except ImportError:
    RICH_OK = False

SEVERITY_COLORS = {
    "critical": "bold red",
    "high":     "red",
    "medium":   "yellow",
    "low":      "cyan",
    "info":     "dim white",
}

SEVERITY_ICONS = {
    "critical": "💀",
    "high":     "🔴",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}

console = Console()


# ─────────────────────────────────────────────────────────────────────────────
def print_banner(version: str, desc: str) -> None:
    if not RICH_OK:
        print(f"\n  TrailBlazer {version} | {desc}\n")
        return

    banner = Text()
    banner.append("  ████████╗██████╗  █████╗ ██╗██╗     ██████╗ ██╗      █████╗ ███████╗███████╗██████╗ \n", style="bold red")
    banner.append("     ██╔══╝██╔══██╗██╔══██╗██║██║     ██╔══██╗██║     ██╔══██╗╚════██║██╔════╝██╔══██╗\n", style="red")
    banner.append("     ██║   ██████╔╝███████║██║██║     ██████╔╝██║     ███████║    ██╔╝█████╗  ██████╔╝\n", style="yellow")
    banner.append("     ██║   ██╔══██╗██╔══██║██║██║     ██╔══██╗██║     ██╔══██║   ██╔╝ ██╔══╝  ██╔══██╗\n", style="yellow")
    banner.append("     ██║   ██║  ██║██║  ██║██║███████╗██████╔╝███████╗██║  ██║   ██║  ███████╗██║  ██║\n", style="bold yellow")
    banner.append("     ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝╚══════╝╚═════╝ ╚══════╝╚═╝  ╚═╝   ╚═╝  ╚══════╝╚═╝  ╚═╝\n", style="dim yellow")
    banner.append(f"\n  v{version}  ·  {desc}\n", style="dim")

    console.print(Panel(banner, border_style="red", padding=(0, 2)))


def print_section(title: str) -> None:
    if RICH_OK:
        console.print(Rule(f"[bold yellow]{title}[/]", style="yellow"))
    else:
        print(f"\n{'='*60}\n  {title}\n{'='*60}")


def print_opsec_score(total_risk: int, max_risk: int) -> None:
    """Muestra el score OPSEC global."""
    pct   = min(100, int((total_risk / max(max_risk, 1)) * 100))
    score = 100 - pct  # mayor score → mejor OPSEC

    if score >= 80:
        color, label = "green",  "🟢 OPSEC BUENA"
    elif score >= 50:
        color, label = "yellow", "🟡 OPSEC MEDIA"
    elif score >= 20:
        color, label = "red",    "🔴 OPSEC DÉBIL"
    else:
        color, label = "bold red", "💀 OPSEC CRÍTICA"

    if RICH_OK:
        bar_len = 40
        filled  = int(bar_len * score / 100)
        bar     = "█" * filled + "░" * (bar_len - filled)
        console.print(Panel(
            f"[{color}]{bar}[/] [{color}]{score}/100[/]\n"
            f"[bold]{label}[/]  ·  Risk Score: [red]{total_risk}[/]",
            title="[bold]OPSEC Score[/]",
            border_style=color,
            padding=(1, 4),
        ))
    else:
        print(f"\n  OPSEC Score: {score}/100  ({label})")


def print_findings(module_results: list[dict], verbose: bool = False) -> None:
    """Imprime todos los findings ordenados por severidad."""
    all_findings = []
    for r in module_results:
        for f in r.get("findings", []):
            f["_module"] = r.get("module", "?")
            all_findings.append(f)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: order.get(f.get("severity", "info"), 99))

    if not all_findings:
        if RICH_OK:
            console.print("[green]  ✓ Sin findings relevantes detectados.[/]")
        else:
            print("  No findings found.")
        return

    if not RICH_OK:
        for f in all_findings:
            sev = f.get("severity", "?").upper()
            print(f"  [{sev}] {f.get('description', '')}")
        return

    table = Table(
        show_header=True,
        header_style="bold magenta",
        box=box.ROUNDED,
        expand=True,
        show_lines=True,
    )
    table.add_column("Sev",      style="bold", width=9, justify="center")
    table.add_column("Módulo",   style="dim",  width=12)
    table.add_column("Categoría", width=14)
    table.add_column("Descripción", ratio=1)

    for f in all_findings:
        sev   = f.get("severity", "info")
        color = SEVERITY_COLORS.get(sev, "white")
        icon  = SEVERITY_ICONS.get(sev, "")
        table.add_row(
            f"[{color}]{icon} {sev.upper()}[/]",
            f.get("_module", "?"),
            f.get("category", "?"),
            f.get("description", ""),
        )

    console.print(table)


def print_module_summary(results: list[dict]) -> None:
    """Muestra tabla resumen por módulo."""
    if not RICH_OK:
        for r in results:
            print(f"  {r.get('module', '?')}: {r.get('summary', {})}")
        return

    table = Table(
        title="[bold]Resumen por Módulo[/]",
        box=box.SIMPLE_HEAD,
        header_style="bold cyan",
    )
    table.add_column("Módulo",   style="cyan bold", width=14)
    table.add_column("Items",    justify="right", width=8)
    table.add_column("Findings", justify="right", width=10)
    table.add_column("Risk",     justify="right", width=8)
    table.add_column("Estado",   width=14)

    for r in results:
        if "error" in r:
            table.add_row(
                r.get("module", "?"), "-", "-", "-",
                "[red]Error[/]"
            )
            continue
        s      = r.get("summary", {})
        risk   = r.get("risk_score", 0)
        nf     = s.get("findings_count", 0)
        items  = str(
            s.get("total_processes",
            s.get("total_connections",
            s.get("total_items",
            s.get("total_events", "-"))))
        )
        status = "[green]OK[/]" if nf == 0 else (
                 "[red]⚠ Crítico[/]" if risk > 40 else "[yellow]⚠ Revisar[/]")
        table.add_row(
            r.get("module", "?"),
            items,
            str(nf),
            str(risk),
            status,
        )

    console.print(table)


def print_processes(result: dict, verbose: bool) -> None:
    if "error" in result:
        console.print(f"[red]  {result['error']}[/]")
        return
    s = result.get("summary", {})
    console.print(f"  Procesos totales: [cyan]{s.get('total_processes', 0)}[/]  "
                  f"Sospechosos: [red]{s.get('suspicious_count', 0)}[/]")
    if verbose:
        _print_top_procs(result.get("processes", []))


def print_network(result: dict, verbose: bool) -> None:
    if "error" in result:
        console.print(f"[red]  {result['error']}[/]")
        return
    s = result.get("summary", {})
    console.print(
        f"  Conexiones: [cyan]{s.get('total_connections', 0)}[/]  "
        f"Externas: [yellow]{s.get('external_connections', 0)}[/]  "
        f"Escuchando: [green]{s.get('listening_ports', 0)}[/]"
    )


def print_users(result: dict, verbose: bool) -> None:
    s = result.get("summary", {})
    admin_str = "[bold red]SÍ[/]" if s.get("is_admin") else "[green]No[/]"
    console.print(
        f"  Usuario: [cyan]{s.get('current_user', '?')}[/]  "
        f"Admin: {admin_str}  "
        f"Sesiones activas: [yellow]{s.get('active_sessions', 0)}[/]"
    )


def print_persistence(result: dict, verbose: bool) -> None:
    s = result.get("summary", {})
    console.print(
        f"  Mecanismos detectados: [cyan]{s.get('total_items', 0)}[/]  "
        f"Sospechosos: [red]{s.get('suspicious', 0)}[/]"
    )


def print_eventlogs(result: dict, verbose: bool) -> None:
    s = result.get("summary", {})
    console.print(
        f"  Eventos analizados: [cyan]{s.get('total_events', 0)}[/]  "
        f"Timeframe: [dim]{s.get('timeframe', '?')}[/]  "
        f"Críticos: [red]{s.get('critical', 0)}[/]  "
        f"Altos: [yellow]{s.get('high', 0)}[/]"
    )


# ─────────────────────────────────────────────────────────────────────────────
def _print_top_procs(processes: list[dict], n: int = 20) -> None:
    table = Table(box=box.MINIMAL, show_header=True, header_style="dim")
    table.add_column("PID",      width=7,  justify="right")
    table.add_column("Nombre",   width=25)
    table.add_column("Usuario",  width=20)
    table.add_column("Estado",   width=10)
    table.add_column("Conex.",   width=6, justify="right")
    for p in processes[:n]:
        table.add_row(
            str(p.get("pid", "")),
            p.get("name", "")[:24],
            (p.get("username") or "")[:19],
            p.get("status", ""),
            str(len(p.get("connections", []))),
        )
    console.print(table)
