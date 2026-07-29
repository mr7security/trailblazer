"""
TrailBlazer :: Collector - Antivirus / EDR
Evalúa el estado del ecosistema de seguridad del endpoint:

Windows:
  - Windows Defender: estado, protección en tiempo real, cloud protection
  - Tamper Protection (si está desactivada, el AV puede ser manipulado)
  - AMSI (Antimalware Scan Interface): activo / patched / bypass detectado
  - Exclusiones de Defender: rutas, extensiones y procesos excluidos
    → Desde perspectiva Red Team: las exclusiones son zonas de aterrizaje seguras
  - EDR/AV de terceros instalados (CrowdStrike, SentinelOne, Carbon Black...)
  - Estado del servicio WdFilter (minifilter de Defender)

Linux / macOS:
  - ClamAV: instalado y activo
  - auditd: sistema de auditoría activo
  - SELinux / AppArmor: modo (enforcing / permissive / disabled)
  - Otros AV conocidos (Sophos, ESET, Trend Micro...)

Perspectiva OPSEC:
  Las exclusiones configuradas son el hallazgo más valioso desde el punto de
  vista ofensivo: indican rutas donde se pueden depositar herramientas sin
  que Defender las analice.
"""

from __future__ import annotations
import os
import platform
import subprocess
from pathlib import Path
from typing import Any

from core.config import RISK_WEIGHTS

PLATFORM = platform.system()

# ── EDR / AV conocidos (proceso o servicio) ───────────────────────────────────
KNOWN_EDR_AV = {
    # EDR corporativos
    "csagent.exe":       "CrowdStrike Falcon",
    "csfalconservice":   "CrowdStrike Falcon",
    "sentinelagent.exe": "SentinelOne",
    "sentinelone":       "SentinelOne",
    "cb.exe":            "VMware Carbon Black",
    "cbdaemon":          "VMware Carbon Black",
    "carbonblack":       "VMware Carbon Black",
    "cyserver.exe":      "Cybereason",
    "cybereason":        "Cybereason",
    "xagt.exe":          "FireEye/Trellix HX",
    "xagtnotif.exe":     "FireEye/Trellix HX",
    "mfeelamk.exe":      "Trellix (McAfee) ENS",
    "mcshield.exe":      "McAfee/Trellix",
    "masvc.exe":         "McAfee/Trellix",
    "bdagent.exe":       "Bitdefender GravityZone",
    "bdntwrk.exe":       "Bitdefender",
    "eguiproxy.exe":     "ESET Endpoint Security",
    "ekrn.exe":          "ESET Kernel Service",
    "sophosav.exe":      "Sophos",
    "sophosfsav":        "Sophos",
    "savscan":           "Sophos",
    "tmlisten.exe":      "Trend Micro",
    "tmbmsrv.exe":       "Trend Micro",
    "coreserviceshell":  "Trend Micro",
    "cylancesvc.exe":    "Cylance (Blackberry)",
    "cyoptics.exe":      "Cylance",
    "pccntmon.exe":      "Trend Micro OfficeScan",
    "repux.exe":         "Secureworks Taegis",
    "amagent.exe":       "Automox",
    "wdboot.sys":        "Windows Defender (driver)",
    "msmpeng.exe":       "Windows Defender",
    "nissrv.exe":        "Windows Defender NIS",
    # Linux / macOS
    "clamd":             "ClamAV",
    "freshclam":         "ClamAV (updater)",
    "sophosd":           "Sophos (Linux)",
    "ds_agent":          "Trend Micro Deep Security",
}


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module":   "antivirus",
        "findings": [],
        "summary":  {},
        "risk_score": 0,
    }

    data: dict[str, Any] = {}

    if PLATFORM == "Windows":
        data["defender"]    = _check_windows_defender()
        data["amsi"]        = _check_amsi()
        data["exclusions"]  = _check_defender_exclusions()
        data["edr_av"]      = _detect_edr_av_windows()
    else:
        data["clamav"]      = _check_clamav()
        data["selinux"]     = _check_selinux_apparmor()
        data["auditd"]      = _check_auditd()
        data["edr_av"]      = _detect_edr_av_linux()

    findings = _analyze(data)

    result["data"]       = data
    result["findings"]   = findings
    result["risk_score"] = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"]    = _build_summary(data, findings)
    return result


# ════════════════════════════  WINDOWS  ══════════════════════════════════════

def _check_windows_defender() -> dict:
    """Estado completo de Windows Defender vía PowerShell Get-MpComputerStatus."""
    info: dict[str, Any] = {
        "available": False,
        "error":     None,
    }
    try:
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            'Get-MpComputerStatus | Select-Object '
            'AntivirusEnabled, RealTimeProtectionEnabled, '
            'BehaviorMonitorEnabled, IoavProtectionEnabled, '
            'NISEnabled, OnAccessProtectionEnabled, '
            'AntispywareEnabled, TamperProtectionSource, '
            'AMServiceEnabled, AntispywareSignatureLastUpdated, '
            'AntivirusSignatureLastUpdated, DefenderSignaturesOutOfDate, '
            'FullScanAge, QuickScanAge '
            '| ConvertTo-Json -Compress"'
        )
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15
        ).decode(errors="ignore").strip()

        if out and out != "null":
            import json
            raw = json.loads(out)
            info = {
                "available":              True,
                "antivirus_enabled":      raw.get("AntivirusEnabled", False),
                "realtime_protection":    raw.get("RealTimeProtectionEnabled", False),
                "behavior_monitor":       raw.get("BehaviorMonitorEnabled", False),
                "ioav_protection":        raw.get("IoavProtectionEnabled", False),
                "nis_enabled":            raw.get("NISEnabled", False),
                "on_access":              raw.get("OnAccessProtectionEnabled", False),
                "antispyware":            raw.get("AntispywareEnabled", False),
                "am_service":             raw.get("AMServiceEnabled", False),
                "tamper_protection":      raw.get("TamperProtectionSource", "?"),
                "signatures_out_of_date": raw.get("DefenderSignaturesOutOfDate", False),
                "full_scan_age_days":     raw.get("FullScanAge", -1),
                "quick_scan_age_days":    raw.get("QuickScanAge", -1),
            }
    except subprocess.TimeoutExpired:
        info["error"] = "Timeout al consultar Defender"
    except Exception as e:
        info["error"] = str(e)[:100]

    return info


def _check_amsi() -> dict:
    """
    Verifica si AMSI está operativo.
    Un AMSI 'patched' o bypassado indica actividad ofensiva previa.
    """
    info: dict[str, Any] = {"status": "unknown", "details": ""}
    try:
        # Test básico: intentar invocar AmsiScanString vía PowerShell
        # Si devuelve AMSI_RESULT_CLEAN (1) está activo
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            'try {'
            '  $amsi = [Ref].Assembly.GetType(\'System.Management.Automation.AmsiUtils\');'
            '  $field = $amsi.GetField(\'amsiInitFailed\', \'NonPublic,Static\');'
            '  $val = $field.GetValue($null);'
            '  Write-Output \"amsiInitFailed:$val\"'
            '} catch { Write-Output \"error:$_\" }"'
        )
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=10
        ).decode(errors="ignore").strip()

        if "amsiInitFailed:True" in out:
            info["status"]  = "bypassed"
            info["details"] = "amsiInitFailed = True — AMSI desactivado en la sesión actual"
        elif "amsiInitFailed:False" in out:
            info["status"]  = "active"
            info["details"] = "AMSI activo y operativo"
        elif "error:" in out:
            info["status"]  = "unknown"
            info["details"] = "No se pudo verificar el estado de AMSI"
        else:
            info["status"]  = "unknown"
            info["details"] = out[:100]

    except Exception as e:
        info["status"]  = "error"
        info["details"] = str(e)[:80]

    return info


def _check_defender_exclusions() -> dict:
    """
    Lee las exclusiones configuradas en Windows Defender.
    Desde perspectiva Red Team: estas rutas son zonas 'ciegas' del AV.
    """
    exclusions: dict[str, list] = {
        "paths":      [],
        "extensions": [],
        "processes":  [],
        "iparanges":  [],
    }
    try:
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            '$p = Get-MpPreference; '
            '$out = @{'
            '  paths      = @($p.ExclusionPath);'
            '  extensions = @($p.ExclusionExtension);'
            '  processes  = @($p.ExclusionProcess);'
            '  iparanges  = @($p.ExclusionIpAddress)'
            '}; '
            'ConvertTo-Json $out -Compress"'
        )
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15
        ).decode(errors="ignore").strip()

        if out and out != "null":
            import json
            raw = json.loads(out)

            def _valid_excl(val: str) -> bool:
                """Filtra valores de error devueltos cuando no hay privilegios admin."""
                if not val:
                    return False
                v = str(val).lower()
                return not (
                    v.startswith("n/a") or
                    "administrator" in v or
                    "must be" in v or
                    "access denied" in v
                )

            exclusions["paths"]      = [x for x in (raw.get("paths") or []) if _valid_excl(x)]
            exclusions["extensions"] = [x for x in (raw.get("extensions") or []) if _valid_excl(x)]
            exclusions["processes"]  = [x for x in (raw.get("processes") or []) if _valid_excl(x)]
            exclusions["iparanges"]  = [x for x in (raw.get("iparanges") or []) if _valid_excl(x)]

    except Exception:
        pass

    exclusions["total"] = (
        len(exclusions["paths"]) +
        len(exclusions["extensions"]) +
        len(exclusions["processes"])
    )
    return exclusions


def _detect_edr_av_windows() -> list[dict]:
    """Detecta productos AV/EDR instalados vía WMI y procesos en ejecución."""
    detected = []

    # Método 1: WMI AntiVirusProduct
    try:
        cmd = (
            'powershell -NoProfile -NonInteractive -Command "'
            'Get-WmiObject -Namespace root\\SecurityCenter2 -Class AntiVirusProduct '
            '| Select-Object displayName, productState '
            '| ConvertTo-Json -Compress"'
        )
        out = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=15
        ).decode(errors="ignore").strip()

        if out and out not in ("null", "[]", ""):
            import json
            products = json.loads(out)
            if not isinstance(products, list):
                products = [products]
            for p in products:
                name  = p.get("displayName", "?")
                state = p.get("productState", 0)
                # productState: hex. bit 12 = real-time on, bit 4 = definitions up to date
                rt_on = bool((int(state) >> 12) & 0xF != 0) if isinstance(state, int) else None
                detected.append({
                    "source":      "WMI",
                    "name":        name,
                    "state":       state,
                    "realtime_on": rt_on,
                })
    except Exception:
        pass

    # Método 2: Procesos en ejecución
    try:
        import psutil
        running = {p.name().lower() for p in psutil.process_iter(["name"], ad_value="?")}
        for proc_name, product in KNOWN_EDR_AV.items():
            if proc_name.lower() in running and "Windows Defender" not in product:
                if not any(d["name"] == product for d in detected):
                    detected.append({
                        "source":  "process",
                        "name":    product,
                        "process": proc_name,
                    })
    except Exception:
        pass

    return detected


# ════════════════════════════  LINUX / macOS  ════════════════════════════════

def _check_clamav() -> dict:
    info: dict[str, Any] = {"installed": False, "daemon_running": False}
    try:
        out = subprocess.check_output(
            "clamscan --version 2>/dev/null", shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        if out:
            info["installed"] = True
            info["version"]   = out.split("\n")[0][:80]
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            "systemctl is-active clamav-daemon 2>/dev/null || "
            "service clamav-daemon status 2>/dev/null | grep -c running",
            shell=True, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        info["daemon_running"] = "active" in out or out == "1"
    except Exception:
        pass

    return info


def _check_selinux_apparmor() -> dict:
    info: dict[str, Any] = {"selinux": "unknown", "apparmor": "unknown"}

    # SELinux
    try:
        out = subprocess.check_output(
            "getenforce 2>/dev/null", shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        if out:
            info["selinux"] = out.lower()   # Enforcing / Permissive / Disabled
    except Exception:
        info["selinux"] = "not_installed"

    # AppArmor
    try:
        out = subprocess.check_output(
            "aa-status --json 2>/dev/null || apparmor_status 2>/dev/null | head -3",
            shell=True, stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        if "profiles are in enforce mode" in out or '"enforce"' in out:
            info["apparmor"] = "enforcing"
        elif "profiles are in complain mode" in out:
            info["apparmor"] = "complain"
        elif out:
            info["apparmor"] = "installed"
        else:
            info["apparmor"] = "not_installed"
    except Exception:
        info["apparmor"] = "not_installed"

    return info


def _check_auditd() -> dict:
    info: dict[str, Any] = {"running": False, "rules_count": 0}
    try:
        out = subprocess.check_output(
            "systemctl is-active auditd 2>/dev/null", shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        info["running"] = out == "active"
    except Exception:
        pass

    try:
        out = subprocess.check_output(
            "auditctl -l 2>/dev/null | wc -l", shell=True,
            stderr=subprocess.DEVNULL
        ).decode(errors="ignore").strip()
        info["rules_count"] = int(out) if out.isdigit() else 0
    except Exception:
        pass

    return info


def _detect_edr_av_linux() -> list[dict]:
    detected = []
    try:
        import psutil
        running = {p.name().lower() for p in psutil.process_iter(["name"], ad_value="?")}
        for proc_name, product in KNOWN_EDR_AV.items():
            if proc_name.lower() in running:
                detected.append({"name": product, "process": proc_name})
    except Exception:
        pass
    return detected


# ─────────────────────────────────────────────────────────────────────────────

def _analyze(data: dict) -> list[dict]:
    findings = []

    if PLATFORM == "Windows":
        defender = data.get("defender", {})
        amsi     = data.get("amsi", {})
        excl     = data.get("exclusions", {})
        edr_av   = data.get("edr_av", [])

        # ── Defender desactivado ────────────────────────────────────────────
        if defender.get("available") and not defender.get("antivirus_enabled"):
            findings.append(_finding(
                "critical",
                "Windows Defender DESACTIVADO — el sistema no tiene protección AV activa",
                "DefenseEvasion",
            ))

        # ── Protección en tiempo real desactivada ──────────────────────────
        if defender.get("available") and not defender.get("realtime_protection"):
            findings.append(_finding(
                "critical",
                "Protección en tiempo real de Defender DESACTIVADA (RealTimeProtection=False)",
                "DefenseEvasion",
            ))

        # ── Tamper Protection desactivada ──────────────────────────────────
        tp = str(defender.get("tamper_protection", "")).lower()
        if defender.get("available") and tp in ("0", "false", "disabled", "not configured"):
            findings.append(_finding(
                "high",
                "Tamper Protection DESACTIVADA — Defender puede ser modificado sin restricciones",
                "DefenseEvasion",
            ))

        # ── Firmas desactualizadas ─────────────────────────────────────────
        if defender.get("signatures_out_of_date"):
            findings.append(_finding(
                "medium",
                "Firmas de Defender DESACTUALIZADAS — capacidad de detección reducida",
                "DefenseEvasion",
            ))

        # ── Scan antiguo ───────────────────────────────────────────────────
        quick_age = defender.get("quick_scan_age_days", -1)
        if isinstance(quick_age, int) and quick_age > 7:
            findings.append(_finding(
                "low",
                f"Último quick scan hace {quick_age} días — recomendado cada 7 días",
                "Hygiene",
            ))

        # ── AMSI bypassed ──────────────────────────────────────────────────
        if amsi.get("status") == "bypassed":
            findings.append(_finding(
                "critical",
                f"AMSI BYPASSED en la sesión actual — {amsi.get('details', '')}",
                "DefenseEvasion",
            ))

        # ── Exclusiones de Defender ────────────────────────────────────────
        # Esto es informativo Y crítico desde OPSEC: son zonas ciegas del AV
        for path in excl.get("paths", []):
            findings.append(_finding(
                "high",
                f"[OPSEC] Ruta excluida de Defender (zona ciega): {path}",
                "DefenderExclusion",
            ))
        for ext in excl.get("extensions", []):
            findings.append(_finding(
                "medium",
                f"[OPSEC] Extensión excluida de Defender: {ext}",
                "DefenderExclusion",
            ))
        for proc in excl.get("processes", []):
            findings.append(_finding(
                "medium",
                f"[OPSEC] Proceso excluido de escaneo de Defender: {proc}",
                "DefenderExclusion",
            ))

        # ── Sin EDR/AV de terceros ─────────────────────────────────────────
        non_defender = [e for e in edr_av
                        if "Defender" not in e.get("name", "")]
        if not non_defender:
            findings.append(_finding(
                "info",
                "Sin EDR/AV de terceros detectado — solo Windows Defender",
                "Coverage",
            ))
        else:
            for e in non_defender:
                findings.append(_finding(
                    "info",
                    f"EDR/AV detectado: {e.get('name', '?')} "
                    f"({'vía WMI' if e.get('source') == 'WMI' else 'proceso activo'})",
                    "Coverage",
                ))

    else:
        # ── Linux: ClamAV no instalado ────────────────────────────────────
        clamav = data.get("clamav", {})
        if not clamav.get("installed"):
            findings.append(_finding(
                "medium",
                "ClamAV no instalado — sin AV de código abierto en el sistema",
                "Coverage",
            ))

        # ── SELinux/AppArmor en modo permissive o disabled ─────────────────
        sel = data.get("selinux", {})
        aa  = data.get("apparmor", {})
        selinux_mode  = sel.get("selinux", "unknown")  if isinstance(sel, dict) else sel
        apparmor_mode = aa.get("apparmor", "unknown")   if isinstance(aa, dict) else aa

        if selinux_mode == "permissive":
            findings.append(_finding(
                "medium",
                "SELinux en modo PERMISSIVE — registra violaciones pero no las bloquea",
                "DefenseEvasion",
            ))
        elif selinux_mode in ("disabled", "unknown"):
            findings.append(_finding(
                "low",
                f"SELinux {selinux_mode} — sin MAC enforcement de SELinux",
                "Coverage",
            ))

        if apparmor_mode in ("complain", "not_installed"):
            findings.append(_finding(
                "low",
                f"AppArmor en modo {apparmor_mode} — protección MAC reducida",
                "Coverage",
            ))

        # ── auditd no activo ───────────────────────────────────────────────
        auditd = data.get("auditd", {})
        if not auditd.get("running"):
            findings.append(_finding(
                "medium",
                "auditd NO está en ejecución — sin registro de auditoría del kernel",
                "Coverage",
            ))

    return findings


def _build_summary(data: dict, findings: list) -> dict:
    s: dict[str, Any] = {
        "findings_count": len(findings),
        "critical":       sum(1 for f in findings if f["severity"] == "critical"),
        "high":           sum(1 for f in findings if f["severity"] == "high"),
    }
    if PLATFORM == "Windows":
        defender = data.get("defender", {})
        excl     = data.get("exclusions", {})
        s["defender_enabled"]    = defender.get("antivirus_enabled", "?")
        s["realtime_protection"] = defender.get("realtime_protection", "?")
        s["amsi_status"]         = data.get("amsi", {}).get("status", "unknown")
        s["exclusions_total"]    = excl.get("total", 0)
        s["edr_av_count"]        = len(data.get("edr_av", []))
    else:
        s["clamav_installed"] = data.get("clamav", {}).get("installed", False)
        s["selinux_mode"]     = data.get("selinux", {}).get("selinux", "unknown")
        s["apparmor_mode"]    = data.get("apparmor", {}).get("apparmor", "unknown")
        s["auditd_running"]   = data.get("auditd", {}).get("running", False)
    return s


def _finding(severity: str, description: str, category: str) -> dict:
    return {
        "severity":    severity,
        "description": description,
        "category":    category,
        "type":        "antivirus",
    }
