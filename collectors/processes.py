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

        # ── cmd.exe / bash hijo de proceso de Office/scripting (no browsers) ──
        # Browsers (chrome, firefox, brave, edge) lanzan cmd.exe legítimamente
        # para abrir archivos/URLs; solo alertamos desde Office/scripting engines.
        if name in ("cmd.exe", "bash", "sh", "zsh") and proc.get("ppid"):
            parent_name = pid_map.get(proc["ppid"], "").lower()
            high_risk_parents = {
                "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
                "acrobat.exe", "acrord32.exe", "wscript.exe", "cscript.exe",
                "mshta.exe", "regsvr32.exe", "rundll32.exe",
            }
            medium_risk_parents = {
                "iexplore.exe",   # IE ya obsoleto — siempre sospechoso
                "chrome.exe", "firefox.exe", "brave.exe", "msedge.exe",
            }
            if parent_name in high_risk_parents:
                findings.append(_finding(
                    "critical",
                    f"Shell ({proc['name']}) lanzada por proceso de Office/scripting: "
                    f"{parent_name} (PID {proc['ppid']}) — ALERTA ALTA",
                    proc, "Lateral Movement",
                ))
            elif parent_name in medium_risk_parents:
                findings.append(_finding(
                    "medium",
                    f"Shell ({proc['name']}) lanzada por browser: {parent_name} "
                    f"(PID {proc['ppid']}) — verificar contexto",
                    proc, "Lateral Movement",
                ))

        # ── Proceso con conexiones externas — excluir PID 0 y apps conocidas ──
        # PID 0 = System Idle Process (Windows) — falso positivo estructural.
        # Apps de escritorio comunes se reportan solo si tienen muchas conexiones.
        KNOWN_DESKTOP_APPS = {
            "chrome.exe", "brave.exe", "firefox.exe", "msedge.exe",
            "teams.exe", "ms-teams.exe", "discord.exe", "slack.exe",
            "onedrive.exe", "onedrive.sync.service.exe", "filesynchelper.exe",
            "steam.exe", "msedgewebview2.exe", "searchhost.exe",
            "explorer.exe", "svchost.exe", "widgets.exe",
            "m365copilot.exe", "copilot.exe",
            # Apps de desarrollo y productividad con conexiones legítimas
            "claude.exe", "code.exe", "cursor.exe", "windsurf.exe",
            "zoom.exe", "webex.exe", "lync.exe", "msteams.exe",
            "dropbox.exe", "box.exe", "googledrivesync.exe",
            # Windows Defender — conexiones legítimas a Microsoft Cloud
            "msmpeng.exe", "nissrv.exe", "msseces.exe", "securityhealthservice.exe",
        }
        EXTERNAL_CONN_THRESHOLD = 10  # solo alertar si supera este umbral para apps conocidas

        if proc["pid"] != 0:
            external_conns = [
                c for c in proc.get("connections", [])
                if c["raddr"] and not _is_local(c["raddr"].split(":")[0])
            ]
            if external_conns:
                is_known = name in KNOWN_DESKTOP_APPS
                count    = len(external_conns)
                # Apps conocidas: solo alertar si conexiones exceden umbral
                if not is_known or count > EXTERNAL_CONN_THRESHOLD:
                    severity = "high" if not is_known and count > 5 else "medium"
                    label    = f"({count} conn. — inusual para esta app)" if is_known else ""
                    findings.append(_finding(
                        severity,
                        f"Proceso con {count} conexión(es) externa(s): "
                        f"{proc['name']} (PID {proc['pid']}) {label}".strip(),
                        proc, "Network",
                        extra={"connections": external_conns[:5]},  # limitar output
                    ))

        # ── Proceso sin exe resuelto — excluir procesos del kernel conocidos ──
        KERNEL_PROCS = {"system idle process", "system", "idle", "registry",
                        "memory compression", "secure system", ""}
        if not proc["exe"] and name not in KERNEL_PROCS and proc["pid"] not in (0, 4):
            findings.append(_finding(
                "medium",
                f"Proceso sin ruta de ejecutable resuelta: {proc['name']} (PID {proc['pid']}) "
                f"— posible Process Hollowing",
                proc, "Evasion",
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
