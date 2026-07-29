"""
TrailBlazer :: Collector - Procesos
Analiza procesos en ejecución buscando indicadores de actividad ofensiva.
"""

from __future__ import annotations
import os
import platform
from datetime import datetime
from typing import Any

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

from core.config import SUSPICIOUS_PROC_NAMES, SUSPICIOUS_PATHS, RISK_WEIGHTS


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    """Recolecta y analiza procesos en ejecución."""
    result: dict[str, Any] = {
        "module": "processes",
        "findings": [],
        "summary": {},
        "risk_score": 0,
    }

    if not PSUTIL_OK:
        result["error"] = "psutil no instalado. Ejecuta: pip install psutil"
        return result

    processes = _enumerate_processes(verbose)
    findings  = _analyze_processes(processes)

    result["processes"]  = processes
    result["findings"]   = findings
    result["risk_score"] = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_processes":    len(processes),
        "suspicious_count":   sum(1 for f in findings if f["severity"] in ("critical", "high")),
        "findings_count":     len(findings),
    }
    return result


# ─────────────────────────────────────────────────────────────────────────────
def _enumerate_processes(verbose: bool) -> list[dict]:
    """Enumera procesos con atributos relevantes."""
    procs = []
    attrs = ["pid", "name", "exe", "username", "create_time",
             "status", "ppid", "cmdline"]

    for proc in psutil.process_iter(attrs, ad_value=None):
        try:
            info = proc.info
            # Conexiones de red del proceso
            try:
                conns = proc.net_connections()
                net = [
                    {
                        "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                        "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                        "status": c.status,
                    }
                    for c in conns
                ]
            except (psutil.AccessDenied, AttributeError):
                net = []

            procs.append({
                "pid":         info.get("pid"),
                "name":        info.get("name") or "",
                "exe":         info.get("exe") or "",
                "username":    info.get("username") or "",
                "create_time": datetime.fromtimestamp(info["create_time"]).strftime("%Y-%m-%d %H:%M:%S")
                               if info.get("create_time") else "",
                "status":      info.get("status") or "",
                "ppid":        info.get("ppid"),
                "cmdline":     " ".join(info.get("cmdline") or []),
                "connections": net,
            })
        except (psutil.NoSuchProcess, psutil.ZombieProcess, psutil.AccessDenied):
            continue

    return procs


# ─────────────────────────────────────────────────────────────────────────────
def _analyze_processes(processes: list[dict]) -> list[dict]:
    """Genera findings a partir de la lista de procesos."""
    findings = []

    # Mapa pid → nombre para correlaciones parent-child
    pid_map = {p["pid"]: p["name"] for p in processes}

    for proc in processes:
        name = proc["name"].lower()
        exe  = proc["exe"].lower()
        cmd  = proc["cmdline"].lower()

        # ── Nombre coincide con herramienta ofensiva conocida ──────────────
        if any(s in name for s in SUSPICIOUS_PROC_NAMES):
            findings.append(_finding(
                "critical",
                f"Proceso ofensivo conocido detectado: {proc['name']} (PID {proc['pid']})",
                proc,
                "OPSEC",
            ))

        # ── Proceso ejecutado desde ruta sospechosa ────────────────────────
        for path in SUSPICIOUS_PATHS:
            if path.lower() in exe:
                findings.append(_finding(
                    "high",
                    f"Proceso ejecutando desde ruta sospechosa: {proc['exe']}",
                    proc,
                    "OPSEC",
                ))
                break

        # ── PowerShell con flags de evasión ───────────────────────────────
        if "powershell" in name and any(
            flag in cmd for flag in ["-enc", "-encodedcommand", "-nop", "-windowstyle hidden", "-bypass"]
        ):
            findings.append(_finding(
                "high",
                f"PowerShell con flags de evasión detectado: {proc['cmdline'][:120]}",
                proc,
                "OPSEC",
            ))

        # ── cmd.exe / bash hijo de proceso inusual ────────────────────────
        if name in ("cmd.exe", "bash", "sh", "zsh") and proc.get("ppid"):
            parent_name = pid_map.get(proc["ppid"], "").lower()
            unusual_parents = {"winword.exe", "excel.exe", "outlook.exe", "iexplore.exe",
                               "chrome.exe", "firefox.exe", "acrobat.exe", "wscript.exe", "mshta.exe"}
            if parent_name in unusual_parents:
                findings.append(_finding(
                    "critical",
                    f"Shell ({proc['name']}) lanzada por proceso sospechoso: {parent_name} (PID {proc['ppid']})",
                    proc,
                    "Lateral Movement",
                ))

        # ── Proceso con conexiones de red externas activas ────────────────
        external_conns = [
            c for c in proc.get("connections", [])
            if c["raddr"] and not _is_local(c["raddr"].split(":")[0])
        ]
        if external_conns:
            findings.append(_finding(
                "medium",
                f"Proceso con {len(external_conns)} conexión(es) externa(s): {proc['name']} (PID {proc['pid']})",
                proc,
                "Network",
                extra={"connections": external_conns},
            ))

        # ── Proceso sin exe resuelto (puede indicar process hollowing) ────
        if not proc["exe"] and proc["name"] not in ("System", "Idle", ""):
            findings.append(_finding(
                "medium",
                f"Proceso sin ruta de ejecutable resuelta: {proc['name']} (PID {proc['pid']}) — posible Process Hollowing",
                proc,
                "Evasion",
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
def _is_local(ip: str) -> bool:
    """Devuelve True si la IP es local/loopback."""
    return ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.",
                           "172.18.", "172.19.", "172.2", "::1", "fe80"))


def _finding(severity: str, description: str, proc: dict,
             category: str, extra: dict | None = None) -> dict:
    f = {
        "severity":    severity,
        "description": description,
        "category":    category,
        "process": {
            "pid":      proc.get("pid"),
            "name":     proc.get("name"),
            "exe":      proc.get("exe"),
            "username": proc.get("username"),
            "cmdline":  proc.get("cmdline", "")[:200],
        },
    }
    if extra:
        f.update(extra)
    return f
