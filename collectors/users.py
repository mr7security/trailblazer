"""
TrailBlazer :: Collector - Usuarios y Sesiones
Enumera cuentas locales, sesiones activas y privilegios.
"""

from __future__ import annotations
import os
import platform
import subprocess
from typing import Any

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

from core.config import RISK_WEIGHTS

PLATFORM = platform.system()


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "users",
        "findings": [],
        "summary": {},
        "risk_score": 0,
    }

    current_user = _get_current_user()
    sessions     = _get_sessions()
    local_users  = _get_local_users()
    sudo_groups  = _get_privileged_groups()
    findings     = _analyze(current_user, sessions, local_users, sudo_groups)

    result["current_user"]    = current_user
    result["sessions"]        = sessions
    result["local_users"]     = local_users
    result["privileged_groups"] = sudo_groups
    result["findings"]        = findings
    result["risk_score"]      = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "current_user":    current_user.get("username"),
        "is_admin":        current_user.get("is_admin", False),
        "active_sessions": len(sessions),
        "local_users":     len(local_users),
        "findings_count":  len(findings),
    }
    return result


# ─────────────────────────────────────────────────────────────────────────────
def _get_current_user() -> dict:
    info: dict[str, Any] = {
        "username": os.environ.get("USERNAME") or os.environ.get("USER") or "unknown",
        "uid":      None,
        "gid":      None,
        "is_admin": False,
        "groups":   [],
    }

    if PLATFORM == "Windows":
        try:
            import ctypes
            info["is_admin"] = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
        try:
            out = subprocess.check_output("whoami /groups /fo csv", shell=True,
                                          stderr=subprocess.DEVNULL).decode(errors="ignore")
            info["groups"] = [line.split(",")[0].strip('"') for line in out.splitlines()[1:] if line]
        except Exception:
            pass
    else:
        try:
            import pwd, grp
            pw = pwd.getpwuid(os.getuid())
            info["uid"]  = pw.pw_uid
            info["gid"]  = pw.pw_gid
            info["is_admin"] = pw.pw_uid == 0
            info["groups"] = [g.gr_name for g in grp.getgrall() if pw.pw_name in g.gr_mem]
        except Exception:
            pass

    return info


def _get_sessions() -> list[dict]:
    sessions = []
    if not PSUTIL_OK:
        return sessions
    try:
        for u in psutil.users():
            sessions.append({
                "name":     u.name,
                "terminal": u.terminal or "",
                "host":     u.host or "local",
                "started":  u.started,
                "pid":      u.pid if hasattr(u, "pid") else None,
            })
    except Exception:
        pass
    return sessions


def _get_local_users() -> list[dict]:
    users = []

    if PLATFORM == "Windows":
        try:
            out = subprocess.check_output("net user", shell=True,
                                          stderr=subprocess.DEVNULL).decode(errors="ignore")
            for line in out.splitlines():
                line = line.strip()
                if line and not line.startswith(("-", "Cuentas", "The command", "User accounts", "Alias")):
                    for u in line.split():
                        if u:
                            users.append({"name": u, "details": {}})
        except Exception:
            pass

    else:
        try:
            with open("/etc/passwd") as f:
                for line in f:
                    parts = line.strip().split(":")
                    if len(parts) >= 4:
                        uid = int(parts[2]) if parts[2].isdigit() else -1
                        users.append({
                            "name":    parts[0],
                            "uid":     uid,
                            "gid":     parts[3],
                            "home":    parts[5] if len(parts) > 5 else "",
                            "shell":   parts[6] if len(parts) > 6 else "",
                            "is_human": uid >= 1000 or uid == 0,
                        })
        except Exception:
            pass

    return users


def _get_privileged_groups() -> list[dict]:
    groups = []

    if PLATFORM == "Windows":
        try:
            out = subprocess.check_output(
                'net localgroup "Administrators"', shell=True,
                stderr=subprocess.DEVNULL).decode(errors="ignore")
            members = []
            capture = False
            for line in out.splitlines():
                if "---" in line:
                    capture = not capture
                    continue
                if capture and line.strip():
                    members.append(line.strip())
            groups.append({"group": "Administrators", "members": members})
        except Exception:
            pass

    else:
        privileged = ["root", "sudo", "wheel", "admin", "docker", "lxd", "disk", "shadow"]
        try:
            import grp
            for gname in privileged:
                try:
                    g = grp.getgrnam(gname)
                    groups.append({"group": gname, "members": g.gr_mem})
                except KeyError:
                    pass
        except ImportError:
            pass

    return groups


# ─────────────────────────────────────────────────────────────────────────────
def _analyze(current_user: dict, sessions: list, local_users: list,
             priv_groups: list) -> list[dict]:
    findings = []

    # ── Usuario actual con privilegios de admin ───────────────────────────
    if current_user.get("is_admin"):
        findings.append({
            "severity":    "high",
            "description": f"Ejecutando como administrador/root: {current_user['username']}",
            "category":    "Privilege",
        })

    # ── Múltiples sesiones activas ────────────────────────────────────────
    if len(sessions) > 1:
        findings.append({
            "severity":    "medium",
            "description": f"{len(sessions)} sesiones activas detectadas: "
                           + ", ".join(s["name"] for s in sessions),
            "category":    "Sessions",
        })

    # ── Sesiones remotas ──────────────────────────────────────────────────
    remote = [s for s in sessions if s.get("host") and s["host"] not in ("local", "", ":0", "localhost")]
    if remote:
        findings.append({
            "severity":    "high",
            "description": f"Sesión(es) remota(s) activa(s): "
                           + ", ".join(f"{s['name']}@{s['host']}" for s in remote),
            "category":    "Sessions",
        })

    # ── Usuarios con shell interactiva en Linux ────────────────────────────
    if PLATFORM != "Windows":
        interactive = [u for u in local_users
                       if u.get("shell") and u["shell"] not in ("/usr/sbin/nologin", "/bin/false", "")
                       and u.get("is_human")]
        if len(interactive) > 2:
            findings.append({
                "severity":    "low",
                "description": f"{len(interactive)} cuentas de usuario con shell interactiva",
                "category":    "Accounts",
            })

    # ── Grupos privilegiados no vacíos ────────────────────────────────────
    for g in priv_groups:
        members = [m for m in g.get("members", []) if m]
        if members:
            findings.append({
                "severity":    "info",
                "description": f"Grupo privilegiado '{g['group']}' tiene {len(members)} miembro(s): "
                               + ", ".join(members[:5]),
                "category":    "Privilege",
            })

    return findings
