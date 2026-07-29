"""
TrailBlazer :: Collector - WMI & Advanced Persistence
Detecta mecanismos de persistencia avanzados:

Windows:
  - WMI Event Subscriptions (__EventFilter, __EventConsumer, __FilterToConsumerBinding)
    → MITRE T1546.003 — técnica silenciosa, difícil de detectar sin herramientas
  - Archivos MOF sospechosos (compilados automáticamente por WMI)
  - COM Object hijacking (HKCU\\Software\\Classes\\CLSID)
  - AppInit_DLLs (inyección de DLL en todos los procesos)
  - Image File Execution Options (IFEO) — debugger hijacking

Linux / macOS:
  - Reglas udev sospechosas (/etc/udev/rules.d/)
  - Trabajos at (/var/spool/at/)
  - Módulos del kernel cargados inusuales (lsmod)
  - Hooks en PAM (/etc/pam.d/)
  - LD_PRELOAD en entorno del sistema
"""

from __future__ import annotations
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from core.config import RISK_WEIGHTS
from core import mitre

PLATFORM = platform.system()


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module":   "wmi",
        "findings": [],
        "summary":  {},
        "risk_score": 0,
    }

    items: list[dict] = []

    if PLATFORM == "Windows":
        items += _check_wmi_subscriptions()
        items += _check_mof_files()
        items += _check_com_hijacking()
        items += _check_appinit_dlls()
        items += _check_ifeo()
    else:
        items += _check_udev_rules()
        items += _check_at_jobs()
        items += _check_kernel_modules()
        items += _check_pam_hooks()
        items += _check_ld_preload_env()

    findings = _analyze(items)

    result["items"]      = items
    result["findings"]   = findings
    result["risk_score"] = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_items":    len(items),
        "findings_count": len(findings),
        "critical":       sum(1 for f in findings if f["severity"] == "critical"),
        "high":           sum(1 for f in findings if f["severity"] == "high"),
    }
    return result


# ════════════════════════════  WINDOWS  ══════════════════════════════════════

def _check_wmi_subscriptions() -> list[dict]:
    """
    Consulta WMI Event Subscriptions — técnica MITRE T1546.003.
    Las suscripciones legítimas son raras; casi cualquier hallazgo es sospechoso.
    """
    items = []

    queries = {
        "EventFilter":          "SELECT * FROM __EventFilter",
        "EventConsumer":        "SELECT * FROM __EventConsumer",
        "FilterToConsumerBinding": "SELECT * FROM __FilterToConsumerBinding",
    }

    for class_name, query in queries.items():
        try:
            # Usar PowerShell para consultar WMI (más fiable que wmic)
            cmd = (
                f'powershell -NoProfile -NonInteractive -Command "'
                f'Get-WmiObject -Namespace root\\subscription -Query \\\"{query}\\\" '
                f'| Select-Object -Property Name, Query, CommandLineTemplate, '
                f'ScriptText, EventNamespace | ConvertTo-Json -Compress"'
            )
            out = subprocess.check_output(
                cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15
            ).decode(errors="ignore").strip()

            if out and out not in ("null", "[]", ""):
                # Intentar parsear; si falla, guardar raw
                try:
                    import json
                    data = json.loads(out)
                    if not isinstance(data, list):
                        data = [data]
                    for entry in data:
                        items.append({
                            "type":       "wmi_subscription",
                            "class":      class_name,
                            "name":       str(entry.get("Name", "?")),
                            "query":      str(entry.get("Query", ""))[:200],
                            "command":    str(entry.get("CommandLineTemplate", ""))[:200],
                            "script":     str(entry.get("ScriptText", ""))[:200],
                            "namespace":  str(entry.get("EventNamespace", "")),
                        })
                except Exception:
                    items.append({
                        "type":  "wmi_subscription",
                        "class": class_name,
                        "raw":   out[:300],
                    })

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError,
                FileNotFoundError):
            pass

    return items


def _check_mof_files() -> list[dict]:
    """Busca archivos .mof fuera de rutas estándar (posible persistencia WMI)."""
    items = []
    standard_mof_dirs = {
        r"c:\windows\system32\wbem",
        r"c:\windows\syswow64\wbem",
    }
    search_paths = [
        Path(r"C:\Windows\Temp"),
        Path(r"C:\Temp"),
        Path(os.environ.get("TEMP", "")),
        Path(os.environ.get("APPDATA", "")),
    ]
    for base in search_paths:
        if not base.exists():
            continue
        try:
            for mof in base.rglob("*.mof"):
                if str(mof.parent).lower() not in standard_mof_dirs:
                    items.append({
                        "type": "mof_file",
                        "path": str(mof),
                        "name": mof.name,
                    })
        except (PermissionError, OSError):
            pass
    return items


def _check_com_hijacking() -> list[dict]:
    """
    Detecta COM Object Hijacking en HKCU (T1546.015).
    HKCU\\Software\\Classes\\CLSID anula entradas en HKLM — no requiere admin.
    """
    items = []
    try:
        import winreg
        key_path = r"Software\Classes\CLSID"
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path,
                                 0, winreg.KEY_READ)
            i = 0
            while True:
                try:
                    clsid = winreg.EnumKey(key, i)
                    # Intentar leer InprocServer32
                    try:
                        sub = winreg.OpenKey(key, f"{clsid}\\InprocServer32")
                        val, _ = winreg.QueryValueEx(sub, "")
                        items.append({
                            "type":   "com_hijack",
                            "clsid":  clsid,
                            "server": str(val)[:200],
                        })
                        winreg.CloseKey(sub)
                    except FileNotFoundError:
                        pass
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except FileNotFoundError:
            pass
    except ImportError:
        pass
    return items


def _check_appinit_dlls() -> list[dict]:
    """
    AppInit_DLLs — inyecta DLLs en todos los procesos que cargan user32.dll (T1546.010).
    Valor vacío es normal; cualquier DLL listada es sospechosa.
    """
    items = []
    try:
        import winreg
        paths = [
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows"),
            (winreg.HKEY_LOCAL_MACHINE,
             r"SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows"),
        ]
        for hive, path in paths:
            try:
                key = winreg.OpenKey(hive, path, 0, winreg.KEY_READ)
                try:
                    val, _ = winreg.QueryValueEx(key, "AppInit_DLLs")
                    if val and val.strip():
                        items.append({
                            "type":  "appinit_dlls",
                            "path":  path,
                            "value": str(val)[:300],
                        })
                except FileNotFoundError:
                    pass
                winreg.CloseKey(key)
            except FileNotFoundError:
                pass
    except ImportError:
        pass
    return items


def _check_ifeo() -> list[dict]:
    """
    Image File Execution Options — redirige la ejecución de un binario a otro (T1546.012).
    Técnica usada para persistencia: reemplazar sethc.exe, utilman.exe, etc.
    """
    items = []
    high_value_targets = {
        "sethc.exe", "utilman.exe", "osk.exe", "magnify.exe",
        "narrator.exe", "displayswitch.exe", "atbroker.exe",
        "cmd.exe", "powershell.exe", "taskmgr.exe",
    }
    try:
        import winreg
        base = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        key  = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base, 0, winreg.KEY_READ)
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                try:
                    sub = winreg.OpenKey(key, subkey_name)
                    try:
                        debugger, _ = winreg.QueryValueEx(sub, "Debugger")
                        items.append({
                            "type":        "ifeo_debugger",
                            "target":      subkey_name,
                            "debugger":    str(debugger)[:200],
                            "is_critical": subkey_name.lower() in high_value_targets,
                        })
                    except FileNotFoundError:
                        pass
                    winreg.CloseKey(sub)
                except Exception:
                    pass
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except (ImportError, FileNotFoundError):
        pass
    return items


# ════════════════════════════  LINUX / macOS  ════════════════════════════════

def _check_udev_rules() -> list[dict]:
    """Busca reglas udev que ejecuten comandos (posible persistencia)."""
    items = []
    udev_dirs = ["/etc/udev/rules.d", "/lib/udev/rules.d", "/run/udev/rules.d"]
    for d in udev_dirs:
        p = Path(d)
        if not p.exists():
            continue
        try:
            for rule in p.glob("*.rules"):
                try:
                    content = rule.read_text(errors="ignore")
                    # Reglas que ejecutan comandos son sospechosas
                    if "RUN" in content or "PROGRAM" in content:
                        items.append({
                            "type":    "udev_rule",
                            "path":    str(rule),
                            "name":    rule.name,
                            "content": content[:400],
                        })
                except (PermissionError, OSError):
                    pass
        except (PermissionError, OSError):
            pass
    return items


def _check_at_jobs() -> list[dict]:
    """Lista trabajos programados con `at`."""
    items = []
    at_dirs = ["/var/spool/at", "/var/spool/cron/atjobs"]
    for d in at_dirs:
        p = Path(d)
        if not p.exists():
            continue
        try:
            jobs = list(p.iterdir())
            if jobs:
                items.append({
                    "type":      "at_jobs",
                    "directory": d,
                    "count":     len(jobs),
                    "jobs":      [j.name for j in jobs[:10]],
                })
        except (PermissionError, OSError):
            pass

    # También via comando `at -l`
    try:
        out = subprocess.check_output(
            "at -l 2>/dev/null", shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        if out:
            items.append({
                "type":    "at_jobs_cmd",
                "content": out[:300],
                "count":   len(out.splitlines()),
            })
    except Exception:
        pass
    return items


def _check_kernel_modules() -> list[dict]:
    """Detecta módulos del kernel no firmados o inusuales (posibles rootkits)."""
    items = []
    try:
        out = subprocess.check_output(
            "lsmod", shell=True, stderr=subprocess.DEVNULL
        ).decode(errors="ignore")
        modules = []
        for line in out.splitlines()[1:]:   # saltar cabecera
            parts = line.split()
            if parts:
                modules.append(parts[0])

        # Comparar contra lista negra básica de rootkits conocidos
        rootkit_names = {
            "reptile", "diamorphine", "azazel", "necurs", "jynx",
            "vlany", "subversive", "sutekh", "rooty",
        }
        suspicious = [m for m in modules if m.lower() in rootkit_names]
        items.append({
            "type":        "kernel_modules",
            "total":       len(modules),
            "suspicious":  suspicious,
            "module_list": modules[:50],
        })
    except Exception:
        pass
    return items


def _check_pam_hooks() -> list[dict]:
    """Detecta módulos PAM inusuales que podrían interceptar autenticación."""
    items = []
    pam_dir = Path("/etc/pam.d")
    if not pam_dir.exists():
        return items

    standard_pam_modules = {
        "pam_unix.so", "pam_deny.so", "pam_permit.so", "pam_env.so",
        "pam_nologin.so", "pam_selinux.so", "pam_loginuid.so",
        "pam_keyinit.so", "pam_limits.so", "pam_systemd.so",
        "pam_motd.so", "pam_lastlog.so", "pam_tally2.so",
        "pam_faillock.so", "pam_pwquality.so", "pam_cracklib.so",
        "pam_securetty.so", "pam_succeed_if.so", "pam_google_authenticator.so",
        "pam_sss.so", "pam_ldap.so", "pam_krb5.so",
    }

    try:
        for pam_file in pam_dir.iterdir():
            if not pam_file.is_file():
                continue
            try:
                content = pam_file.read_text(errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if line.startswith("#") or not line:
                        continue
                    parts = line.split()
                    # El módulo suele ser el último campo con .so
                    for part in parts:
                        if part.endswith(".so") and part not in standard_pam_modules:
                            items.append({
                                "type":   "pam_module",
                                "file":   str(pam_file),
                                "module": part,
                                "line":   line[:150],
                            })
            except (PermissionError, OSError):
                pass
    except (PermissionError, OSError):
        pass
    return items


def _check_ld_preload_env() -> list[dict]:
    """Detecta LD_PRELOAD en el entorno actual."""
    items = []
    ld = os.environ.get("LD_PRELOAD", "")
    if ld:
        items.append({
            "type":  "ld_preload_env",
            "value": ld[:300],
        })
    return items


# ─────────────────────────────────────────────────────────────────────────────

def _analyze(items: list[dict]) -> list[dict]:
    findings = []

    for item in items:
        itype = item.get("type", "")

        if itype == "wmi_subscription":
            # Filtrar subscripciones built-in legítimas de Windows
            name  = (item.get("name") or "").lower()
            klass = (item.get("class") or "").lower()
            BUILTIN_WMI = {
                "scm event log filter", "scm event log consumer",
                "ntlm log filter", "ntlm log consumer",
                "ucmrt filter", "ucmrt consumer",
                "bvtfilter", "bvtconsumer",
            }
            # FilterToConsumerBinding sin nombre = binding del SCM built-in
            is_builtin_binding = (
                "filtertoconsumerbinding" in klass and name in ("none", "", "null")
            )
            if any(b in name for b in BUILTIN_WMI) or is_builtin_binding:
                continue  # Subscripción nativa de Windows, no maliciosa
            findings.append(_finding(
                "critical",
                f"WMI Event Subscription detectada — T1546.003: "
                f"{item.get('class', '?')} / {item.get('name', '?')}",
                item, "Persistence", technique="T1546.003",
            ))

        elif itype == "mof_file":
            findings.append(_finding(
                "high",
                f"Archivo MOF fuera de ruta estándar: {item['path']}",
                item, "Persistence", technique="T1546.003",
            ))

        elif itype == "com_hijack":
            server = item.get("server", "").lower()
            LEGIT_COM_SERVERS = {
                "shell32.dll", "mscoree.dll", "ole32.dll", "oleaut32.dll",
                "comctl32.dll", "shlwapi.dll", "urlmon.dll", "mshtml.dll",
                "ieframe.dll", "msxml6.dll", "wbem", "system32",
            }
            LEGIT_COM_PATHS = {
                "\\windows\\system32\\", "\\windows\\syswow64\\",
                "\\program files\\microsoft", "\\program files (x86)\\microsoft",
                "teamsmeeting",
            }
            server_lower = server.lower()
            if (any(s in server_lower for s in LEGIT_COM_SERVERS) or
                    any(p in server_lower for p in LEGIT_COM_PATHS)):
                continue
            findings.append(_finding(
                "high",
                f"COM Object Hijacking (HKCU) — T1546.015: "
                f"CLSID {item.get('clsid')} → {item.get('server', '?')[:80]}",
                item, "Persistence", technique="T1546.015",
            ))

        elif itype == "appinit_dlls":
            findings.append(_finding(
                "critical",
                f"AppInit_DLLs configurado — T1546.010 (inyección global): "
                f"{item.get('value', '')[:80]}",
                item, "Persistence", technique="T1546.010",
            ))

        elif itype == "ifeo_debugger":
            sev = "critical" if item.get("is_critical") else "high"
            findings.append(_finding(
                sev,
                f"IFEO Debugger Hijacking — T1546.012: "
                f"{item.get('target')} → {item.get('debugger', '')[:80]}",
                item, "Persistence", technique="T1546.012",
            ))

        elif itype == "udev_rule":
            findings.append(_finding(
                "medium",
                f"Regla udev con ejecución de comando: {item['path']}",
                item, "Persistence", technique="T1053.003",
            ))

        elif itype in ("at_jobs", "at_jobs_cmd") and item.get("count", 0) > 0:
            findings.append(_finding(
                "medium",
                f"Trabajos `at` programados detectados: {item.get('count', '?')} trabajo(s)",
                item, "Persistence", technique="T1053.003",
            ))

        elif itype == "kernel_modules" and item.get("suspicious"):
            for mod in item["suspicious"]:
                findings.append(_finding(
                    "critical",
                    f"Módulo del kernel con nombre de rootkit conocido: {mod}",
                    item, "Rootkit", technique="T1574.002",
                ))

        elif itype == "pam_module":
            findings.append(_finding(
                "high",
                f"Módulo PAM no estándar — posible interceptor de autenticación: "
                f"{item.get('module')} en {item.get('file')}",
                item, "Persistence", technique="T1547.001",
            ))

        elif itype == "ld_preload_env":
            findings.append(_finding(
                "critical",
                f"LD_PRELOAD activo en entorno — posible rootkit de librería: "
                f"{item.get('value', '')[:80]}",
                item, "Rootkit", technique="T1574.002",
            ))

    return findings


def _finding(severity: str, description: str, item: dict,
             category: str, technique: str = "") -> dict:
    f = {
        "severity":    severity,
        "description": description,
        "category":    category,
        "type":        item.get("type", ""),
        "path":        item.get("path", item.get("target", "")),
    }
    if technique:
        f.update(mitre.get(technique))
    return f
