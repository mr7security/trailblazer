"""
TrailBlazer :: Collector - Persistencia
Detecta mecanismos de persistencia en Windows (registro, tareas, servicios)
y Linux (cron, systemd, scripts de inicio).
"""

from __future__ import annotations
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from core.config import (
    WIN_RUN_KEYS, PERSISTENCE_PATHS_LINUX,
    PERSISTENCE_FILES_LINUX, RISK_WEIGHTS,
)

PLATFORM = platform.system()


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "persistence",
        "findings": [],
        "summary": {},
        "risk_score": 0,
    }

    items    = []
    findings = []

    if PLATFORM == "Windows":
        items += _check_registry()
        items += _check_scheduled_tasks_win()
        items += _check_startup_folder()
        items += _check_services_win()
    else:
        items += _check_cron()
        items += _check_systemd()
        items += _check_init_scripts()
        items += _check_shell_profiles()

    findings = _analyze(items)

    result["persistence_items"] = items
    result["findings"]          = findings
    result["risk_score"]        = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_items":    len(items),
        "suspicious":     sum(1 for f in findings if f["severity"] in ("critical", "high")),
        "findings_count": len(findings),
    }
    return result


# ════════════════════════════  WINDOWS  ══════════════════════════════════════

def _check_registry() -> list[dict]:
    items = []
    try:
        import winreg
        hives = [
            (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
            (winreg.HKEY_CURRENT_USER,  "HKCU"),
        ]
        for hive, hive_name in hives:
            for key_path in WIN_RUN_KEYS:
                if "Services" in key_path:
                    continue  # manejado en _check_services_win
                try:
                    key = winreg.OpenKey(hive, key_path, 0, winreg.KEY_READ)
                    i = 0
                    while True:
                        try:
                            name, data, _ = winreg.EnumValue(key, i)
                            items.append({
                                "type":     "registry_run",
                                "source":   f"{hive_name}\\{key_path}",
                                "name":     name,
                                "value":    str(data)[:300],
                                "platform": "Windows",
                            })
                            i += 1
                        except OSError:
                            break
                    winreg.CloseKey(key)
                except FileNotFoundError:
                    pass
    except ImportError:
        pass
    return items


def _check_scheduled_tasks_win() -> list[dict]:
    items = []
    try:
        out = subprocess.check_output(
            'schtasks /query /fo LIST /v', shell=True,
            stderr=subprocess.DEVNULL).decode(errors="ignore")

        task: dict[str, str] = {}
        for line in out.splitlines():
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k == "TaskName":
                    if task:
                        items.append(task)
                    task = {"type": "scheduled_task", "name": v, "platform": "Windows"}
                elif k == "Task To Run":
                    task["command"] = v
                elif k == "Status":
                    task["status"] = v
                elif k == "Run As User":
                    task["run_as"] = v
                elif k == "Next Run Time":
                    task["next_run"] = v
        if task:
            items.append(task)
    except Exception:
        pass
    return items


def _check_startup_folder() -> list[dict]:
    items = []
    startup_paths = [
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",
    ]
    for sp in startup_paths:
        p = Path(sp)
        if p.exists():
            for f in p.iterdir():
                if f.is_file():
                    items.append({
                        "type":     "startup_folder",
                        "source":   str(sp),
                        "name":     f.name,
                        "path":     str(f),
                        "platform": "Windows",
                    })
    return items


def _check_services_win() -> list[dict]:
    items = []
    try:
        out = subprocess.check_output(
            'sc query type= all state= all', shell=True,
            stderr=subprocess.DEVNULL).decode(errors="ignore")
        svc: dict[str, str] = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("SERVICE_NAME:"):
                if svc:
                    items.append(svc)
                svc = {"type": "service", "name": line.split(":", 1)[1].strip(), "platform": "Windows"}
            elif line.startswith("STATE"):
                svc["state"] = line.split(":", 1)[1].strip()
        if svc:
            items.append(svc)
    except Exception:
        pass
    return items


# ════════════════════════════  LINUX / macOS  ════════════════════════════════

def _check_cron() -> list[dict]:
    items = []
    cron_dirs = PERSISTENCE_PATHS_LINUX[:6]  # /etc/cron.* y /var/spool/cron

    for d in cron_dirs:
        p = Path(d)
        if p.exists():
            if p.is_dir():
                for f in p.iterdir():
                    if f.is_file():
                        try:
                            content = f.read_text(errors="ignore")
                            items.append({
                                "type":    "cron",
                                "source":  str(f),
                                "content": content[:500],
                                "platform": "Linux",
                            })
                        except PermissionError:
                            items.append({"type": "cron", "source": str(f),
                                          "content": "[Sin permiso de lectura]", "platform": "Linux"})
            elif p.is_file():
                try:
                    content = p.read_text(errors="ignore")
                    items.append({"type": "cron", "source": str(p),
                                  "content": content[:500], "platform": "Linux"})
                except PermissionError:
                    items.append({"type": "cron", "source": str(p),
                                  "content": "[Sin permiso de lectura]", "platform": "Linux"})

    # Crontabs de usuario via crontab -l
    try:
        out = subprocess.check_output("crontab -l 2>/dev/null", shell=True).decode(errors="ignore")
        if out.strip():
            items.append({"type": "cron", "source": "crontab -l (usuario actual)",
                          "content": out[:500], "platform": "Linux"})
    except Exception:
        pass

    return items


def _check_systemd() -> list[dict]:
    items = []
    systemd_paths = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
        os.path.expanduser("~/.config/systemd/user"),
    ]
    for sp in systemd_paths:
        p = Path(sp)
        if p.exists() and p.is_dir():
            for f in p.glob("*.service"):
                try:
                    content = f.read_text(errors="ignore")
                    # Solo nos interesan servicios no estándar (con ExecStart)
                    if "ExecStart" in content:
                        items.append({
                            "type":    "systemd_unit",
                            "source":  str(f),
                            "name":    f.name,
                            "content": content[:600],
                            "platform": "Linux",
                        })
                except PermissionError:
                    pass
    return items


def _check_init_scripts() -> list[dict]:
    items = []
    init_files = [
        "/etc/rc.local",
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/environment",
        "/etc/ld.so.preload",
    ]
    for path in init_files:
        p = Path(path)
        if p.exists() and p.is_file():
            try:
                content = p.read_text(errors="ignore")
                items.append({
                    "type":    "init_script",
                    "source":  path,
                    "content": content[:500],
                    "platform": "Linux",
                })
            except PermissionError:
                items.append({"type": "init_script", "source": path,
                              "content": "[Sin permiso de lectura]", "platform": "Linux"})
    return items


def _check_shell_profiles() -> list[dict]:
    items = []
    home = Path.home()
    profile_files = [
        home / ".bashrc",
        home / ".bash_profile",
        home / ".profile",
        home / ".zshrc",
        home / ".zprofile",
        home / ".bash_login",
    ]
    for pf in profile_files:
        if pf.exists():
            try:
                content = pf.read_text(errors="ignore")
                items.append({
                    "type":    "shell_profile",
                    "source":  str(pf),
                    "content": content[:500],
                    "platform": "Linux",
                })
            except PermissionError:
                pass
    return items


# ─────────────────────────────────────────────────────────────────────────────
def _analyze(items: list[dict]) -> list[dict]:
    findings = []
    suspicious_keywords = [
        "curl ", "wget ", "bash -i", "nc ", "ncat ", "/dev/tcp",
        "base64", "python -c", "perl -e", "ruby -e",
        "meterpreter", "cobalt", "empire", "powershell -enc",
        "chmod +x", "/tmp/", "/dev/shm/",
    ]

    for item in items:
        content = (item.get("content") or item.get("command") or
                   item.get("value") or "").lower()
        source  = item.get("source", "")
        itype   = item.get("type", "")

        # ── ld.so.preload no vacío (rootkit indicator) ───────────────────
        if "ld.so.preload" in source and content.strip() and "[sin permiso" not in content:
            findings.append(_finding(
                "critical",
                f"⚠ /etc/ld.so.preload contiene entradas — posible rootkit de librería",
                item,
            ))

        # ── Palabras clave sospechosas en cualquier mecanismo ──────────────
        for kw in suspicious_keywords:
            if kw in content:
                findings.append(_finding(
                    "high",
                    f"Contenido sospechoso ('{kw}') en {itype}: {source}",
                    item,
                ))
                break  # un finding por item

        # ── Tarea programada que corre como SYSTEM/root ───────────────────
        if itype == "scheduled_task" and item.get("run_as", "").upper() in ("SYSTEM", "ROOT"):
            findings.append(_finding(
                "medium",
                f"Tarea programada ejecutándose como SYSTEM: {item.get('name')}",
                item,
            ))

        # ── Servicio systemd en home del usuario ──────────────────────────
        if itype == "systemd_unit" and ".config/systemd/user" in source:
            findings.append(_finding(
                "medium",
                f"Unidad systemd de usuario en directorio home: {source}",
                item,
            ))

    return findings


def _finding(severity: str, description: str, item: dict) -> dict:
    return {
        "severity":    severity,
        "description": description,
        "category":    "Persistence",
        "source":      item.get("source", ""),
        "type":        item.get("type", ""),
    }
