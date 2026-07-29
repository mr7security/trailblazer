"""
TrailBlazer :: Collector - Logs de Eventos
Windows: Security/System/Application Event Logs vía wevtutil o python-evtx.
Linux: auth.log, secure, syslog, audit.log.
"""

from __future__ import annotations
import os
import re
import platform
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from core.config import WIN_EVENT_IDS, LOG_PATHS, TIMEFRAME_SECONDS, RISK_WEIGHTS

PLATFORM = platform.system()


# ─────────────────────────────────────────────────────────────────────────────
def collect(timeframe: str = "24h", verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "eventlogs",
        "findings": [],
        "summary": {},
        "risk_score": 0,
    }

    seconds   = TIMEFRAME_SECONDS.get(timeframe, 86400)
    since     = datetime.now() - timedelta(seconds=seconds)
    events    = []

    if PLATFORM == "Windows":
        events = _collect_windows_events(since, verbose)
    else:
        events = _collect_linux_logs(since, verbose)

    findings = _analyze(events)

    result["events"]      = events[:200]   # Limitar salida
    result["findings"]    = findings
    result["risk_score"]  = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["timeframe"]   = timeframe
    result["since"]       = since.strftime("%Y-%m-%d %H:%M:%S")
    result["summary"] = {
        "total_events":   len(events),
        "timeframe":      timeframe,
        "findings_count": len(findings),
        "critical":       sum(1 for f in findings if f["severity"] == "critical"),
        "high":           sum(1 for f in findings if f["severity"] == "high"),
    }
    return result


# ════════════════════════════  WINDOWS  ══════════════════════════════════════

def _collect_windows_events(since: datetime, verbose: bool) -> list[dict]:
    events = []
    logs_to_query = [
        ("Security", list(WIN_EVENT_IDS.keys())),
        ("System",   [7045, 7034, 7035, 7036]),
    ]

    for log_name, event_ids in logs_to_query:
        for eid in event_ids:
            try:
                since_str = since.strftime("%Y-%m-%dT%H:%M:%S")
                query = (
                    f"*[System[EventID={eid} and "
                    f"TimeCreated[@SystemTime>='{since_str}']]]"
                )
                cmd = [
                    "wevtutil", "qe", log_name,
                    f"/q:{query}",
                    "/f:text", "/rd:true", "/c:50",
                ]
                out = subprocess.check_output(
                    cmd, stderr=subprocess.DEVNULL
                ).decode(errors="ignore")

                for block in _parse_wevtutil_text(out):
                    block["log"]    = log_name
                    block["eid"]    = eid
                    block["eid_desc"] = WIN_EVENT_IDS.get(eid, f"Event {eid}")
                    events.append(block)

            except (subprocess.CalledProcessError, FileNotFoundError):
                pass

    events.sort(key=lambda e: e.get("time", ""), reverse=True)
    return events


def _parse_wevtutil_text(text: str) -> list[dict]:
    """Parsea la salida en texto de wevtutil."""
    blocks = []
    current: dict[str, str] = {}

    for line in text.splitlines():
        line = line.strip()
        if not line:
            if current:
                blocks.append(current)
                current = {}
            continue
        if line.startswith("Log Name:"):
            pass
        elif line.startswith("Date:"):
            current["time"] = line.split(":", 1)[1].strip()
        elif line.startswith("Source:"):
            current["source"] = line.split(":", 1)[1].strip()
        elif line.startswith("Level:"):
            current["level"] = line.split(":", 1)[1].strip()
        elif line.startswith("User:"):
            current["user"] = line.split(":", 1)[1].strip()
        elif line.startswith("Computer:"):
            current["computer"] = line.split(":", 1)[1].strip()
        elif line.startswith("Description:"):
            current["description"] = line.split(":", 1)[1].strip()
        elif "description" in current:
            current["description"] += " " + line

    if current:
        blocks.append(current)
    return blocks


# ════════════════════════════  LINUX  ════════════════════════════════════════

def _collect_linux_logs(since: datetime, verbose: bool) -> list[dict]:
    events = []
    log_files = LOG_PATHS.get(PLATFORM, LOG_PATHS.get("Linux", []))

    for log_path in log_files:
        p = Path(log_path)
        if not p.exists():
            continue
        try:
            events += _parse_linux_log(p, since)
        except PermissionError:
            events.append({
                "log":         str(p),
                "time":        "",
                "message":     f"[Sin permiso para leer {log_path}]",
                "level":       "info",
                "source":      str(p),
            })

    events.sort(key=lambda e: e.get("time", ""), reverse=True)
    return events


# Patrones comunes en auth.log / secure
_LINUX_PATTERNS = [
    (re.compile(r"Failed password for (\S+) from ([\d.]+)"),  "failed_login"),
    (re.compile(r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)"), "successful_login"),
    (re.compile(r"session opened for user (\S+)"),            "session_open"),
    (re.compile(r"session closed for user (\S+)"),            "session_close"),
    (re.compile(r"sudo:\s+(\S+) : .*COMMAND=(.+)"),          "sudo_command"),
    (re.compile(r"new user: name=(\S+)"),                      "user_created"),
    (re.compile(r"user (\S+) deleted"),                        "user_deleted"),
    (re.compile(r"CRON\[(\d+)\]: \((\S+)\) CMD \((.+)\)"),   "cron_execution"),
    (re.compile(r"su: FAILED SU"),                            "su_failed"),
    (re.compile(r"groupadd.*group '(\S+)'"),                  "group_added"),
]

_MONTH_MAP = {
    "Jan": "01", "Feb": "02", "Mar": "03", "Apr": "04",
    "May": "05", "Jun": "06", "Jul": "07", "Aug": "08",
    "Sep": "09", "Oct": "10", "Nov": "11", "Dec": "12",
}


def _parse_linux_log(path: Path, since: datetime) -> list[dict]:
    events = []
    year = datetime.now().year

    with open(path, errors="ignore") as f:
        for line in f:
            line = line.rstrip()
            # Intentar parsear timestamp: "Jul 28 14:32:01"
            ts = None
            parts = line.split()
            if len(parts) >= 3 and parts[0] in _MONTH_MAP:
                try:
                    ts_str = f"{year}-{_MONTH_MAP[parts[0]]}-{parts[1].zfill(2)} {parts[2]}"
                    ts = datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S")
                    if ts < since:
                        continue
                except ValueError:
                    pass

            event: dict[str, Any] = {
                "log":     str(path),
                "time":    ts.strftime("%Y-%m-%d %H:%M:%S") if ts else "",
                "message": line,
                "level":   "info",
                "type":    "raw",
            }

            # Intentar clasificar con patrones
            for pattern, etype in _LINUX_PATTERNS:
                m = pattern.search(line)
                if m:
                    event["type"]   = etype
                    event["groups"] = list(m.groups())
                    break

            events.append(event)

    return events


# ─────────────────────────────────────────────────────────────────────────────
def _analyze(events: list[dict]) -> list[dict]:
    findings = []

    # Conteos
    failed_logins:   dict[str, int] = {}
    successful_login_ips: list[str] = []
    sudo_users:  list[str] = []
    new_users:   list[str] = []
    log_cleared          = False
    tasks_created: list   = []
    priv_logons:  list    = []

    for e in events:
        eid  = e.get("eid")
        etype = e.get("type", "")
        grps  = e.get("groups", [])

        # ── Windows ──────────────────────────────────────────────────────
        if eid == 4625:  # Logon fallido
            user = e.get("user", "unknown")
            failed_logins[user] = failed_logins.get(user, 0) + 1
        elif eid == 4624:
            successful_login_ips.append(e.get("description", "")[:80])
        elif eid in (4698, 4702):
            tasks_created.append(e.get("description", "")[:100])
        elif eid == 4720:
            new_users.append(e.get("user", "?"))
        elif eid == 1102:
            log_cleared = True
        elif eid == 4672:
            priv_logons.append(e.get("user", "?"))

        # ── Linux ──────────────────────────────────────────────────────
        elif etype == "failed_login" and grps:
            user = grps[0] if grps else "?"
            failed_logins[user] = failed_logins.get(user, 0) + 1
        elif etype == "sudo_command" and grps:
            sudo_users.append(f"{grps[0]} → {grps[1][:60]}" if len(grps) > 1 else grps[0])
        elif etype == "user_created" and grps:
            new_users.append(grps[0])

    # ── Brute force: muchos fallos de login ──────────────────────────────
    for user, count in failed_logins.items():
        if count >= 5:
            findings.append({
                "severity":    "high",
                "description": f"Posible brute force: {count} intentos fallidos para usuario '{user}'",
                "category":    "BruteForce",
                "count":       count,
            })

    # ── Log de auditoría limpiado ──────────────────────────────────────
    if log_cleared:
        findings.append({
            "severity":    "critical",
            "description": "Log de seguridad limpiado (Event 1102) — indicador de anti-forense",
            "category":    "AntiForensics",
        })

    # ── Nuevas cuentas de usuario ──────────────────────────────────────
    for u in new_users:
        findings.append({
            "severity":    "high",
            "description": f"Nueva cuenta de usuario creada: {u}",
            "category":    "Accounts",
        })

    # ── Tareas programadas creadas/modificadas ─────────────────────────
    for t in tasks_created:
        findings.append({
            "severity":    "medium",
            "description": f"Tarea programada creada/modificada: {t[:80]}",
            "category":    "Persistence",
        })

    # ── Comandos sudo ─────────────────────────────────────────────────
    if sudo_users:
        findings.append({
            "severity":    "info",
            "description": f"{len(sudo_users)} ejecución(es) con sudo registradas",
            "category":    "Privilege",
            "detail":      sudo_users[:10],
        })

    # ── Logons con privilegios especiales ──────────────────────────────
    if len(priv_logons) > 3:
        findings.append({
            "severity":    "medium",
            "description": f"{len(priv_logons)} logons con privilegios especiales (Event 4672)",
            "category":    "Privilege",
        })

    return findings
