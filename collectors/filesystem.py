"""
TrailBlazer :: Collector - Filesystem
Analiza artefactos del sistema de archivos relevantes para forense:
  - Prefetch de Windows (programas ejecutados recientemente)
  - Executables en rutas sospechosas o con doble extensión
  - Timestomping (manipulación de timestamps)
  - Archivos grandes o recientes en directorios temporales
  - Scripts/binarios en directorios de usuario inusuales
"""

from __future__ import annotations
import os
import platform
import stat
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from core.config import RISK_WEIGHTS

PLATFORM = platform.system()

# ── Extensiones ejecutables que no deberían estar en /tmp o AppData ──────────
EXEC_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta",
    ".scr", ".com", ".pif", ".msi", ".wsf", ".cpl", ".jar",
    # Linux/macOS
    ".sh", ".elf", ".bin", ".run",
}

# Extensiones que, combinadas, forman doble extensión sospechosa
# Ej: invoice.pdf.exe, document.docx.bat
DOUBLE_EXT_DANGER = {".exe", ".bat", ".cmd", ".ps1", ".vbs", ".sh", ".hta", ".scr"}

# Rutas de temp/staging sospechosas
SUSPICIOUS_DIRS_WIN = [
    os.environ.get("TEMP", ""),
    os.environ.get("TMP", ""),
    r"C:\Temp",
    r"C:\Users\Public",
    r"C:\Windows\Temp",
    os.path.join(os.environ.get("APPDATA", ""), ""),
    os.path.join(os.environ.get("LOCALAPPDATA", ""), "Temp"),
]
SUSPICIOUS_DIRS_LINUX = [
    "/tmp", "/var/tmp", "/dev/shm", "/run/shm",
    "/var/www", "/opt",
]

# Archivos legítimos conocidos en AppData (para reducir FP)
KNOWN_APPDATA_EXES = {
    "discord.exe", "slack.exe", "teams.exe", "zoom.exe",
    "code.exe", "cursor.exe", "claude.exe", "brave.exe",
    "spotify.exe", "steam.exe", "1password.exe", "bitwarden.exe",
    "update.exe", "installer.exe", "setup.exe",
}

# Tamaño mínimo de archivo "grande" en temp (bytes) — 10 MB
LARGE_FILE_THRESHOLD = 10 * 1024 * 1024

# Ventana temporal para "reciente" (horas)
RECENT_HOURS = 24


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module":   "filesystem",
        "findings": [],
        "summary":  {},
        "risk_score": 0,
    }

    items: list[dict] = []

    if PLATFORM == "Windows":
        items += _collect_prefetch()
        items += _scan_suspicious_dirs(SUSPICIOUS_DIRS_WIN)
        items += _check_double_extension_win()
    else:
        items += _scan_suspicious_dirs(SUSPICIOUS_DIRS_LINUX)
        items += _check_suid_sgid()

    items += _check_recent_large_files()

    findings = _analyze(items)

    result["items"]      = items[:100]   # limitar output
    result["findings"]   = findings
    result["risk_score"] = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_items":    len(items),
        "findings_count": len(findings),
        "suspicious":     sum(1 for f in findings if f["severity"] in ("critical", "high")),
    }
    return result


# ════════════════════════════  WINDOWS  ══════════════════════════════════════

def _collect_prefetch() -> list[dict]:
    """Lee el directorio Prefetch — lista programas ejecutados recientemente."""
    items = []
    prefetch_dir = Path(r"C:\Windows\Prefetch")
    if not prefetch_dir.exists():
        return items

    now = datetime.now()
    cutoff = now - timedelta(hours=RECENT_HOURS * 7)   # última semana

    try:
        for pf in prefetch_dir.glob("*.pf"):
            try:
                st = pf.stat()
                mtime = datetime.fromtimestamp(st.st_mtime)
                if mtime < cutoff:
                    continue
                # El nombre del .pf es "PROGRAMA-HASH.pf"
                exe_name = pf.stem.rsplit("-", 1)[0].lower()
                items.append({
                    "type":      "prefetch",
                    "name":      pf.name,
                    "exe":       exe_name,
                    "last_run":  mtime.strftime("%Y-%m-%d %H:%M:%S"),
                    "path":      str(pf),
                })
            except (PermissionError, OSError):
                pass
    except PermissionError:
        items.append({
            "type":  "prefetch",
            "error": "Sin acceso a C:\\Windows\\Prefetch — ejecutar como Administrador",
        })

    return items


def _scan_suspicious_dirs(dirs: list[str]) -> list[dict]:
    """Escanea directorios temporales buscando ejecutables."""
    items = []
    seen: set[str] = set()
    now = datetime.now()
    recent_cutoff = now - timedelta(hours=RECENT_HOURS)

    for base_dir in dirs:
        if not base_dir:
            continue
        p = Path(base_dir)
        if not p.exists() or not p.is_dir():
            continue

        try:
            for entry in p.iterdir():
                if not entry.is_file() or str(entry) in seen:
                    continue
                seen.add(str(entry))
                suffix = entry.suffix.lower()
                if suffix not in EXEC_EXTENSIONS:
                    continue

                try:
                    st   = entry.stat()
                    mtime = datetime.fromtimestamp(st.st_mtime)
                    ctime = datetime.fromtimestamp(st.st_ctime)
                    items.append({
                        "type":      "suspicious_exec",
                        "path":      str(entry),
                        "name":      entry.name,
                        "size_kb":   round(st.st_size / 1024, 1),
                        "modified":  mtime.strftime("%Y-%m-%d %H:%M:%S"),
                        "created":   ctime.strftime("%Y-%m-%d %H:%M:%S"),
                        "is_recent": mtime > recent_cutoff,
                        "timestomp": _check_timestomp(st),
                    })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass

    return items


def _check_double_extension_win() -> list[dict]:
    """
    Detecta doble extensión REAL: la penúltima extensión debe ser un tipo de
    documento/imagen, NO un número de versión (ej: .53, .13, .6a son versiones).
    Patrón real malicioso: factura.pdf.exe, foto.jpg.bat, documento.docx.ps1
    """
    items = []
    # Solo estas extensiones "señuelo" indican intención de engaño
    DECOY_EXTENSIONS = {
        ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
        ".txt", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3",
        ".zip", ".rar", ".7z", ".iso", ".img",
    }
    home = Path.home()
    scan_dirs = [home / "Desktop", home / "Downloads", home / "Documents"]

    for d in scan_dirs:
        if not d.exists():
            continue
        try:
            for f in d.rglob("*"):
                if not f.is_file():
                    continue
                suffixes = [s.lower() for s in f.suffixes]
                if len(suffixes) < 2:
                    continue
                final_ext     = suffixes[-1]
                penultimate   = suffixes[-2]
                if final_ext not in DOUBLE_EXT_DANGER:
                    continue
                # El penúltimo debe ser una extensión de documento REAL, no un número de versión
                if penultimate not in DECOY_EXTENSIONS:
                    continue
                try:
                    st = f.stat()
                    items.append({
                        "type":       "double_extension",
                        "path":       str(f),
                        "name":       f.name,
                        "extensions": suffixes,
                        "size_kb":    round(st.st_size / 1024, 1),
                        "modified":   datetime.fromtimestamp(
                                       st.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                    })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass
    return items


# ════════════════════════════  LINUX  ════════════════════════════════════════

def _check_suid_sgid() -> list[dict]:
    """Detecta binarios SUID/SGID inusuales (Linux/macOS)."""
    items = []
    # Binarios SUID legítimos conocidos
    known_suid = {
        "sudo", "su", "passwd", "ping", "mount", "umount",
        "chsh", "chfn", "newgrp", "pkexec", "crontab",
        "ssh-agent", "at", "fusermount", "fusermount3",
        "unix_chkpwd", "staprun", "vmware-user-suid-wrapper",
    }
    scan_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin",
                  "/usr/local/bin", "/usr/local/sbin", "/opt"]

    for base in scan_paths:
        p = Path(base)
        if not p.exists():
            continue
        try:
            for entry in p.iterdir():
                if not entry.is_file():
                    continue
                try:
                    st = entry.stat()
                    is_suid = bool(st.st_mode & stat.S_ISUID)
                    is_sgid = bool(st.st_mode & stat.S_ISGID)
                    if (is_suid or is_sgid) and entry.name not in known_suid:
                        items.append({
                            "type":    "suid_binary",
                            "path":    str(entry),
                            "name":    entry.name,
                            "suid":    is_suid,
                            "sgid":    is_sgid,
                            "owner":   st.st_uid,
                            "mode":    oct(st.st_mode),
                        })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass
    return items


# ════════════════════════════  CROSS-PLATFORM  ═══════════════════════════════

def _check_recent_large_files() -> list[dict]:
    """Archivos grandes creados recientemente en directorios temporales."""
    items = []
    now    = datetime.now()
    cutoff = now - timedelta(hours=RECENT_HOURS)
    dirs   = SUSPICIOUS_DIRS_WIN if PLATFORM == "Windows" else SUSPICIOUS_DIRS_LINUX

    for base_dir in dirs:
        if not base_dir:
            continue
        p = Path(base_dir)
        if not p.exists():
            continue
        try:
            for entry in p.iterdir():
                if not entry.is_file():
                    continue
                try:
                    st    = entry.stat()
                    mtime = datetime.fromtimestamp(st.st_mtime)
                    if st.st_size >= LARGE_FILE_THRESHOLD and mtime > cutoff:
                        items.append({
                            "type":     "large_recent_file",
                            "path":     str(entry),
                            "name":     entry.name,
                            "size_mb":  round(st.st_size / (1024 * 1024), 2),
                            "modified": mtime.strftime("%Y-%m-%d %H:%M:%S"),
                        })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass
    return items


def _check_timestomp(st: os.stat_result) -> bool:
    """Detecta posible timestomping: modificación anterior a creación."""
    try:
        return st.st_mtime < st.st_ctime - 60   # >1 min de diferencia sospechosa
    except Exception:
        return False


# ─────────────────────────────────────────────────────────────────────────────
def _analyze(items: list[dict]) -> list[dict]:
    findings = []

    # Prefetch de herramientas ofensivas conocidas
    offensive_tools = {
        "mimikatz", "meterpreter", "nc", "ncat", "netcat", "wce",
        "pwdump", "fgdump", "procdump", "plink", "psexec",
        "cobaltstrike", "beacon", "rubeus", "sharphound",
        "bloodhound", "crackmapexec", "impacket", "empire",
        "metasploit", "nmap", "masscan", "chisel", "ligolo",
    }
    for item in items:
        if item.get("type") == "prefetch":
            exe = item.get("exe", "").lower()
            if any(t in exe for t in offensive_tools):
                findings.append(_finding(
                    "critical",
                    f"Herramienta ofensiva en Prefetch (ejecutada recientemente): {item['name']}",
                    item, "OPSEC",
                ))

        elif item.get("type") == "suspicious_exec":
            name = item.get("name", "").lower()
            # Ejecutable reciente en ruta temporal
            if item.get("is_recent") and name not in KNOWN_APPDATA_EXES:
                sev = "high" if any(
                    d in item["path"].lower()
                    for d in ["\\temp\\", "\\tmp\\", "/tmp/", "/dev/shm"]
                ) else "medium"
                findings.append(_finding(
                    sev,
                    f"Ejecutable {'reciente ' if item['is_recent'] else ''}en ruta sospechosa: "
                    f"{item['path']} ({item['size_kb']} KB)",
                    item, "OPSEC",
                ))
            # Timestomping
            if item.get("timestomp"):
                findings.append(_finding(
                    "high",
                    f"Posible timestomping detectado en: {item['path']} "
                    f"(modificado antes de ser creado)",
                    item, "AntiForensics",
                ))

        elif item.get("type") == "double_extension":
            findings.append(_finding(
                "high",
                f"Archivo con doble extensión sospechosa: {item['name']} "
                f"({' → '.join(item.get('extensions', []))})",
                item, "Malware",
            ))

        elif item.get("type") == "suid_binary":
            findings.append(_finding(
                "high",
                f"Binario SUID/SGID no estándar: {item['path']} (mode {item.get('mode', '?')})",
                item, "Privilege",
            ))

        elif item.get("type") == "large_recent_file":
            findings.append(_finding(
                "medium",
                f"Archivo grande ({item['size_mb']} MB) creado recientemente en ruta temporal: "
                f"{item['path']}",
                item, "Exfil",
            ))

    return findings


def _finding(severity: str, description: str, item: dict, category: str) -> dict:
    return {
        "severity":    severity,
        "description": description,
        "category":    category,
        "path":        item.get("path", ""),
        "type":        item.get("type", ""),
    }
