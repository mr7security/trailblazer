"""
TrailBlazer :: Collector - Credentials
Detecta credenciales y secretos expuestos en el sistema:
  - Claves SSH privadas (~/.ssh/)
  - Credenciales AWS (~/.aws/)
  - Archivos .env con secretos
  - Historial de PowerShell (PSReadLine)
  - Tokens Git (.gitconfig, .git-credentials)
  - Configuraciones Docker y Kubernetes con auth
  - Windows Credential Manager (cmdkey)
  - Tokens en archivos de configuración comunes (.npmrc, .pypirc...)

IMPORTANTE: Este módulo solo detecta EXISTENCIA y EXPOSICIÓN de archivos
de credenciales. NUNCA extrae ni muestra el contenido real de los secretos.
"""

from __future__ import annotations
import os
import re
import platform
import subprocess
from pathlib import Path
from typing import Any

from core.config import RISK_WEIGHTS
from core import mitre

PLATFORM = platform.system()
HOME     = Path.home()

# ── Patrones regex para detectar secretos en archivos (sin capturar el valor) ─
SECRET_PATTERNS = [
    (re.compile(r'(?i)(password|passwd|pwd)\s*[=:]\s*\S+'), "Password en texto plano"),
    (re.compile(r'(?i)(api[_-]?key|apikey)\s*[=:]\s*\S+'), "API Key"),
    (re.compile(r'(?i)(secret[_-]?key|secret)\s*[=:]\s*\S+'), "Secret Key"),
    (re.compile(r'(?i)(access[_-]?token|auth[_-]?token)\s*[=:]\s*\S+'), "Token de acceso"),
    (re.compile(r'(?i)aws[_-]?(secret[_-]?access[_-]?key)\s*[=:]\s*\S+'), "AWS Secret Key"),
    (re.compile(r'(?i)(private[_-]?key)\s*[=:]\s*\S+'), "Private Key"),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token"),
    (re.compile(r'glpat-[a-zA-Z0-9\-]{20}'), "GitLab Personal Access Token"),
    (re.compile(r'(?i)-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'), "Clave privada PEM"),
    (re.compile(r'(?i)(db[_-]?password|database[_-]?password)\s*[=:]\s*\S+'), "DB Password"),
    (re.compile(r'(?i)(smtp[_-]?password|mail[_-]?password)\s*[=:]\s*\S+'), "Mail Password"),
    (re.compile(r'AKIA[A-Z0-9]{16}'), "AWS Access Key ID"),
]

# Archivos de historial de comandos
HISTORY_FILES = [
    HOME / ".bash_history",
    HOME / ".zsh_history",
    HOME / ".sh_history",
    HOME / ".python_history",
    HOME / ".mysql_history",
    HOME / ".psql_history",
    # PowerShell (Windows)
    HOME / "AppData" / "Roaming" / "Microsoft" / "Windows" / "PowerShell" /
    "PSReadLine" / "ConsoleHost_history.txt",
]

# Comandos sospechosos en historial
SUSPICIOUS_HISTORY_CMDS = [
    r"net\s+user\s+\w+\s+\S+",          # net user admin Password123
    r"invoke-expression|iex\s*\(",       # IEX (download cradle)
    r"downloadstring|downloadfile",       # PowerShell download
    r"wget\s+.*\|\s*bash",              # wget | bash
    r"curl\s+.*\|\s*(bash|sh)",         # curl | bash
    r"-encodedcommand\s+[A-Za-z0-9+/]", # PS encoded command
    r"mimikatz|sekurlsa|lsadump",        # Mimikatz commands
    r"Add-MpPreference.*ExclusionPath",  # Defender exclusion
    r"Set-MpPreference.*Disable",        # Defender disable
    r"whoami\s*/priv",                   # Privilege check
    r"net\s+localgroup.*administrators", # Admin group modification
    r"schtasks.*/create",               # Scheduled task creation
    r"reg\s+add\s+.*\\run",             # Registry run key
    r"base64\s+-d\s*\|",               # base64 decode pipe
    r"python\s+-c\s+['\"]import",       # Python one-liner
]


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module":   "credentials",
        "findings": [],
        "summary":  {},
        "risk_score": 0,
    }

    items: list[dict] = []

    items += _check_ssh_keys()
    items += _check_aws_credentials()
    items += _check_env_files()
    items += _check_git_credentials()
    items += _check_docker_kubernetes()
    items += _check_history_files()
    items += _check_config_files()

    if PLATFORM == "Windows":
        items += _check_windows_credential_manager()

    findings = _analyze(items)

    result["items"]      = [_sanitize(i) for i in items]
    result["findings"]   = findings
    result["risk_score"] = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_items":    len(items),
        "findings_count": len(findings),
        "critical":       sum(1 for f in findings if f["severity"] == "critical"),
        "high":           sum(1 for f in findings if f["severity"] == "high"),
    }
    return result


# ─────────────────────────────────────────────────────────────────────────────

def _check_ssh_keys() -> list[dict]:
    items = []
    ssh_dir = HOME / ".ssh"
    if not ssh_dir.exists():
        return items

    private_key_names = {
        "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa",
        "id_rsa_old", "identity", "id_ecdsa_sk", "id_ed25519_sk",
    }
    try:
        for f in ssh_dir.iterdir():
            if not f.is_file():
                continue
            name = f.name.lower()
            # Clave privada (sin extensión .pub)
            is_private = (name in private_key_names or
                          (not name.endswith(".pub") and
                           _file_contains_pattern(f, r"-----BEGIN .* PRIVATE KEY-----")))
            # Permisos demasiado abiertos (solo Linux)
            perm_issue = False
            if PLATFORM != "Windows":
                try:
                    mode = f.stat().st_mode & 0o777
                    perm_issue = mode not in (0o600, 0o400)
                except OSError:
                    pass

            items.append({
                "type":        "ssh_key",
                "path":        str(f),
                "name":        f.name,
                "is_private":  is_private,
                "perm_issue":  perm_issue,
                "exists":      True,
            })
    except PermissionError:
        pass

    # known_hosts — revela hosts a los que se ha conectado
    known = ssh_dir / "known_hosts"
    if known.exists():
        try:
            line_count = sum(1 for _ in known.open(errors="ignore"))
            items.append({
                "type":       "ssh_known_hosts",
                "path":       str(known),
                "host_count": line_count,
            })
        except (PermissionError, OSError):
            pass

    return items


def _check_aws_credentials() -> list[dict]:
    items = []
    aws_dir = HOME / ".aws"
    for fname in ("credentials", "config"):
        f = aws_dir / fname
        if f.exists():
            has_secret = _file_contains_pattern(f, r"aws_secret_access_key|aws_access_key_id")
            items.append({
                "type":       "aws_credentials",
                "path":       str(f),
                "name":       f.name,
                "has_secret": has_secret,
                "size_bytes": f.stat().st_size if f.exists() else 0,
            })
    return items


def _check_env_files() -> list[dict]:
    items = []
    search_dirs = [HOME, HOME / "Documents", HOME / "Desktop",
                   Path(os.getcwd())]
    env_patterns = [".env", ".env.local", ".env.production",
                    ".env.development", ".env.backup"]

    for d in search_dirs:
        if not d.exists():
            continue
        try:
            for pat in env_patterns:
                f = d / pat
                if f.exists() and f.is_file():
                    secrets_found = _scan_for_secrets(f)
                    items.append({
                        "type":          "env_file",
                        "path":          str(f),
                        "name":          f.name,
                        "secrets_found": secrets_found,
                        "size_bytes":    f.stat().st_size,
                    })
        except (PermissionError, OSError):
            pass

    return items


def _check_git_credentials() -> list[dict]:
    items = []
    git_cred = HOME / ".git-credentials"
    gitconfig = HOME / ".gitconfig"

    if git_cred.exists():
        line_count = 0
        try:
            line_count = sum(1 for l in git_cred.open(errors="ignore") if l.strip())
        except (PermissionError, OSError):
            pass
        items.append({
            "type":          "git_credentials",
            "path":          str(git_cred),
            "stored_tokens": line_count,
            "critical":      line_count > 0,
        })

    if gitconfig.exists():
        has_email = _file_contains_pattern(gitconfig, r"email\s*=")
        items.append({
            "type":      "gitconfig",
            "path":      str(gitconfig),
            "has_email": has_email,
        })

    return items


def _check_docker_kubernetes() -> list[dict]:
    items = []
    docker_cfg = HOME / ".docker" / "config.json"
    kube_cfg   = HOME / ".kube" / "config"

    if docker_cfg.exists():
        has_auth = _file_contains_pattern(docker_cfg, r'"auth"\s*:\s*"[^"]{8,}"')
        items.append({
            "type":     "docker_config",
            "path":     str(docker_cfg),
            "has_auth": has_auth,
        })

    if kube_cfg.exists():
        has_token = _file_contains_pattern(kube_cfg, r"token:|client-certificate-data:")
        items.append({
            "type":      "kube_config",
            "path":      str(kube_cfg),
            "has_token": has_token,
        })

    return items


def _check_history_files() -> list[dict]:
    items = []
    compiled = [re.compile(p, re.IGNORECASE) for p in SUSPICIOUS_HISTORY_CMDS]

    for hist_file in HISTORY_FILES:
        if not hist_file.exists():
            continue
        try:
            suspicious_lines: list[str] = []
            with open(hist_file, errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if any(pat.search(line) for pat in compiled):
                        suspicious_lines.append(line[:150])

            items.append({
                "type":             "command_history",
                "path":             str(hist_file),
                "name":             hist_file.name,
                "suspicious_count": len(suspicious_lines),
                "suspicious_cmds":  suspicious_lines[:10],   # máx 10
            })
        except (PermissionError, OSError):
            pass

    return items


def _check_config_files() -> list[dict]:
    """Escanea archivos de configuración de herramientas comunes."""
    items = []
    config_files = [
        HOME / ".npmrc",
        HOME / ".pypirc",
        HOME / ".netrc",
        HOME / ".pgpass",
        HOME / ".my.cnf",
        HOME / ".boto",
        HOME / "AppData" / "Roaming" / "pip" / "pip.ini",
    ]
    for cf in config_files:
        if cf.exists() and cf.is_file():
            secrets = _scan_for_secrets(cf)
            if secrets:
                items.append({
                    "type":          "config_file",
                    "path":          str(cf),
                    "name":          cf.name,
                    "secrets_found": secrets,
                })
    return items


def _check_windows_credential_manager() -> list[dict]:
    items = []
    try:
        out = subprocess.check_output(
            "cmdkey /list", shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore")

        entries = []
        current: dict[str, str] = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Target:"):
                if current:
                    entries.append(current)
                current = {"target": line.split(":", 1)[1].strip()}
            elif line.startswith("Type:") and current:
                current["type"] = line.split(":", 1)[1].strip()
            elif line.startswith("User:") and current:
                current["user"] = line.split(":", 1)[1].strip()
        if current:
            entries.append(current)

        if entries:
            items.append({
                "type":    "credential_manager",
                "entries": entries,
                "count":   len(entries),
            })
    except Exception:
        pass
    return items


# ─────────────────────────────────────────────────────────────────────────────

def _file_contains_pattern(path: Path, pattern: str) -> bool:
    try:
        content = path.read_text(errors="ignore")
        return bool(re.search(pattern, content, re.IGNORECASE))
    except (PermissionError, OSError):
        return False


def _scan_for_secrets(path: Path) -> list[str]:
    """Devuelve lista de tipos de secretos encontrados (sin el valor)."""
    found = []
    try:
        content = path.read_text(errors="ignore")
        for pattern, label in SECRET_PATTERNS:
            if pattern.search(content) and label not in found:
                found.append(label)
    except (PermissionError, OSError):
        pass
    return found


def _sanitize(item: dict) -> dict:
    """Elimina valores sensibles del item antes de incluirlo en el output."""
    safe = dict(item)
    for key in ("token", "password", "secret", "key", "auth"):
        if key in safe:
            safe[key] = "[REDACTED]"
    return safe


# ─────────────────────────────────────────────────────────────────────────────

def _analyze(items: list[dict]) -> list[dict]:
    findings = []

    for item in items:
        itype = item.get("type", "")

        # ── SSH ──────────────────────────────────────────────────────────
        if itype == "ssh_key" and item.get("is_private"):
            sev = "high"
            msg = f"Clave SSH privada expuesta: {item['path']}"
            if item.get("perm_issue"):
                sev = "critical"
                msg += " (permisos incorrectos — legible por otros usuarios)"
            findings.append(_finding(sev, msg, item, "CredentialExposure", technique="T1552.004"))

        # ── AWS ──────────────────────────────────────────────────────────
        elif itype == "aws_credentials" and item.get("has_secret"):
            findings.append(_finding(
                "critical",
                f"Credenciales AWS con secret key en texto plano: {item['path']}",
                item, "CredentialExposure", technique="T1552.001",
            ))

        # ── .env ─────────────────────────────────────────────────────────
        elif itype == "env_file" and item.get("secrets_found"):
            types = ", ".join(item["secrets_found"])
            findings.append(_finding(
                "high",
                f"Archivo .env con secretos detectados ({types}): {item['path']}",
                item, "CredentialExposure", technique="T1552.001",
            ))

        # ── Git credentials ───────────────────────────────────────────────
        elif itype == "git_credentials" and item.get("critical"):
            findings.append(_finding(
                "high",
                f"Tokens Git almacenados en texto plano: {item['path']} "
                f"({item['stored_tokens']} entrada(s))",
                item, "CredentialExposure", technique="T1552.001",
            ))

        # ── Docker auth ───────────────────────────────────────────────────
        elif itype == "docker_config" and item.get("has_auth"):
            findings.append(_finding(
                "high",
                f"Docker config con credenciales de registro almacenadas: {item['path']}",
                item, "CredentialExposure", technique="T1552.001",
            ))

        # ── Kubernetes token ──────────────────────────────────────────────
        elif itype == "kube_config" and item.get("has_token"):
            findings.append(_finding(
                "high",
                f"Kubeconfig con tokens de autenticación: {item['path']}",
                item, "CredentialExposure", technique="T1552.001",
            ))

        # ── Historial de comandos ─────────────────────────────────────────
        elif itype == "command_history" and item.get("suspicious_count", 0) > 0:
            n = item["suspicious_count"]
            findings.append(_finding(
                "medium",
                f"Historial de comandos con {n} línea(s) sospechosa(s): {item['path']}",
                item, "OPSEC", technique="T1552.004",
            ))

        # ── Config files con secretos ─────────────────────────────────────
        elif itype == "config_file" and item.get("secrets_found"):
            types = ", ".join(item["secrets_found"])
            findings.append(_finding(
                "high",
                f"Archivo de configuración con secretos ({types}): {item['path']}",
                item, "CredentialExposure", technique="T1552.001",
            ))

        # ── Windows Credential Manager ────────────────────────────────────
        elif itype == "credential_manager" and item.get("count", 0) > 0:
            findings.append(_finding(
                "medium",
                f"Windows Credential Manager con {item['count']} credencial(es) almacenada(s)",
                item, "CredentialExposure", technique="T1555.004",
            ))

    return findings


def _finding(severity: str, description: str, item: dict,
             category: str, technique: str = "") -> dict:
    f = {
        "severity":    severity,
        "description": description,
        "category":    category,
        "path":        item.get("path", ""),
        "type":        item.get("type", ""),
    }
    if technique:
        f.update(mitre.get(technique))
    return f
