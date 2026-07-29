"""
TrailBlazer - Configuración global y constantes
"""

import platform

TOOL_NAME    = "TrailBlazer"
TOOL_VERSION = "1.0.0"
TOOL_AUTHOR  = "Red Team Portfolio"
TOOL_DESC    = "Red Team OPSEC & Forensic Footprint Analyzer"
TOOL_BANNER  = r"""
 _____ ____      _    ___ _     ____  _        _    ____  _____ ____
|_   _|  _ \    / \  |_ _| |   | __ )| |      / \  |_  / | __||  _ \
  | | | |_) |  / _ \  | || |   |  _ \| |     / _ \  / /  |  _| | |_) |
  | | |  _ <  / ___ \ | || |___| |_) | |___ / ___ \/ /__ | |___|  _ <
  |_| |_| \_\/_/   \_\___|_____|____/|_____/_/   \_\____||_____|_| \_\

  v{version}  |  {desc}
"""

PLATFORM = platform.system()  # 'Windows' | 'Linux' | 'Darwin'

# ── Timeframe helpers ─────────────────────────────────────────────────────────
TIMEFRAME_SECONDS = {
    "1h": 3600,
    "6h": 21600,
    "12h": 43200,
    "24h": 86400,
    "48h": 172800,
    "7d": 604800,
    "30d": 2592000,
}

# ── Paths de logs por plataforma ──────────────────────────────────────────────
LOG_PATHS = {
    "Linux": [
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/audit/audit.log",
    ],
    "Darwin": [
        "/var/log/auth.log",
        "/var/log/system.log",
        "/private/var/log/install.log",
    ],
}

# ── Paths de persistencia por plataforma ─────────────────────────────────────
PERSISTENCE_PATHS_LINUX = [
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.monthly",
    "/etc/cron.weekly",
    "/var/spool/cron",
    "/etc/rc.local",
    "/etc/init.d",
    "/etc/profile.d",
    "/etc/ld.so.preload",
]

PERSISTENCE_FILES_LINUX = [
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.bash_login",
    "~/.zshrc",
    "~/.config/autostart",
]

# ── Windows Registry Run Keys ─────────────────────────────────────────────────
WIN_RUN_KEYS = [
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    r"SYSTEM\CurrentControlSet\Services",
]

# ── Windows Event IDs de interés (Security Log) ───────────────────────────────
WIN_EVENT_IDS = {
    4624: "Logon Exitoso",
    4625: "Logon Fallido",
    4648: "Logon con credenciales explícitas",
    4672: "Privilegios especiales asignados",
    4688: "Proceso Creado",
    4698: "Scheduled Task Creada",
    4702: "Scheduled Task Modificada",
    4720: "Cuenta de Usuario Creada",
    4726: "Cuenta de Usuario Eliminada",
    4732: "Miembro añadido al grupo Administradores",
    4756: "Miembro añadido a grupo universal",
    7045: "Nuevo Servicio Instalado",
    1102: "Log de Auditoría Limpiado",
    4719: "Política de Auditoría Modificada",
}

# ── Procesos y rutas considerados sospechosos ─────────────────────────────────
SUSPICIOUS_PROC_NAMES = {
    "mimikatz.exe", "wce.exe", "pwdump.exe", "fgdump.exe",
    "gsecdump.exe", "procdump.exe", "meterpreter",
    "nc.exe", "ncat.exe", "netcat.exe", "plink.exe",
    "cobaltstrike", "beacon.exe",
}

SUSPICIOUS_PATHS = [
    "\\AppData\\Local\\Temp\\",
    "\\AppData\\Roaming\\",
    "\\Windows\\Temp\\",
    "C:\\Temp\\",
    "C:\\Users\\Public\\",
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
]

# ── Puertos considerados sensibles ────────────────────────────────────────────
SENSITIVE_PORTS = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5985: "WinRM HTTP",
    5986: "WinRM HTTPS",
    4444: "Metasploit default",
    1337: "Elite/Backdoor",
    8080: "HTTP Alt",
    9001: "Tor / Meterpreter",
    9002: "Tor",
    6666: "IRC / Backdoor",
    6667: "IRC",
    31337: "Elite Backdoor",
}

# ── Scoring weights ───────────────────────────────────────────────────────────
RISK_WEIGHTS = {
    "critical": 25,
    "high":     15,
    "medium":    8,
    "low":       3,
    "info":      0,
}
