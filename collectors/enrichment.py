"""
TrailBlazer :: Collector - Threat Intelligence Enrichment
Enriquece hallazgos del sistema con información de threat intel:

  1. VirusTotal — Hash SHA256 de ejecutables sospechosos
     Requiere: --vt-key <API_KEY> o variable VIRUSTOTAL_API_KEY
     Límite gratuito: 4 req/min, 500/día

  2. Threat Intel IPs — Compara conexiones externas contra:
     - Feodo Tracker (abuse.ch) — C2 de Emotet, Dridex, TrickBot...
     - Lista local cacheable en data/c2_ips.txt

  Las consultas son opcionales y no bloquean el scan si fallan.
"""

from __future__ import annotations
import hashlib
import json
import os
import platform
import time
import urllib.request
import urllib.error
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from core.config import RISK_WEIGHTS
from core import mitre

PLATFORM = platform.system()

# Ruta de datos: junto al .exe en modo frozen, junto al proyecto en modo script
if getattr(sys, "frozen", False):
    DATA_DIR = Path(sys.executable).parent / "data"
else:
    DATA_DIR = Path(__file__).resolve().parent.parent / "data"
C2_CACHE     = DATA_DIR / "c2_ips.txt"
C2_CACHE_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist.txt"
C2_CACHE_TTL = timedelta(hours=6)   # refrescar cada 6 horas

VT_API_URL   = "https://www.virustotal.com/api/v3/files/{}"
VT_REQ_DELAY = 15.1   # segundos entre requests (4/min en free tier)


# ─────────────────────────────────────────────────────────────────────────────
def collect(
    vt_key:          str | None  = None,
    check_vt:        bool        = False,
    check_c2:        bool        = True,
    suspicious_files: list[str]  = None,
    external_ips:    list[str]   = None,
    verbose:         bool        = False,
) -> dict[str, Any]:
    """
    Collector de enriquecimiento. Recibe datos ya recopilados por otros módulos.

    Args:
        vt_key:          API key de VirusTotal (opcional).
        check_vt:        Si True, consulta VT para cada archivo sospechoso.
        check_c2:        Si True, compara IPs externas contra lista C2.
        suspicious_files: Lista de rutas de archivos a hashear y consultar.
        external_ips:    Lista de IPs externas detectadas por el módulo network.
    """
    result: dict[str, Any] = {
        "module":   "enrichment",
        "findings": [],
        "summary":  {},
        "risk_score": 0,
    }

    items    = []
    findings = []

    # ── VirusTotal ────────────────────────────────────────────────────────────
    vt_results: list[dict] = []
    if check_vt and (suspicious_files or []):
        api_key = vt_key or os.environ.get("VIRUSTOTAL_API_KEY", "")
        if not api_key:
            items.append({"type": "vt_error",
                           "error": "API key de VirusTotal no configurada. "
                                    "Usa --vt-key o la variable VIRUSTOTAL_API_KEY."})
        else:
            for fpath in (suspicious_files or [])[:10]:  # máx 10 en free tier
                vtr = _check_virustotal(fpath, api_key, verbose)
                if vtr:
                    vt_results.append(vtr)
                    items.append(vtr)
                time.sleep(VT_REQ_DELAY)

    # ── C2 / Threat Intel IPs ─────────────────────────────────────────────────
    c2_matches: list[dict] = []
    if check_c2 and (external_ips or []):
        c2_list = _load_c2_list(verbose)
        if c2_list:
            for ip in (external_ips or []):
                clean_ip = ip.split(":")[0] if ":" in ip else ip
                if clean_ip in c2_list:
                    entry = c2_list[clean_ip]
                    c2_matches.append({
                        "type":     "c2_match",
                        "ip":       clean_ip,
                        "malware":  entry.get("malware", "?"),
                        "country":  entry.get("country", "?"),
                        "source":   "Feodo Tracker (abuse.ch)",
                    })
                    items.append(c2_matches[-1])

    findings = _analyze(vt_results, c2_matches)

    result["items"]      = items
    result["findings"]   = findings
    result["risk_score"] = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_items":    len(items),
        "findings_count": len(findings),
        "vt_checked":     len(vt_results),
        "c2_matches":     len(c2_matches),
        "critical":       sum(1 for f in findings if f["severity"] == "critical"),
        "high":           sum(1 for f in findings if f["severity"] == "high"),
    }
    return result


# ─────────────────────────────────────────────────────────────────────────────
def _check_virustotal(filepath: str, api_key: str, verbose: bool) -> dict | None:
    """Calcula SHA256 y consulta VirusTotal."""
    p = Path(filepath)
    if not p.exists() or not p.is_file():
        return None

    # Hash SHA256
    try:
        sha256 = hashlib.sha256(p.read_bytes()).hexdigest()
    except (PermissionError, OSError) as e:
        return {"type": "vt_error", "path": filepath, "error": str(e)[:80]}

    url = VT_API_URL.format(sha256)
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data     = json.loads(resp.read().decode())
            attrs    = data.get("data", {}).get("attributes", {})
            stats    = attrs.get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            total     = sum(stats.values()) or 1
            names     = list(attrs.get("popular_threat_classification", {})
                             .get("suggested_threat_label", ""))[:60] or []
            return {
                "type":      "virustotal",
                "path":      filepath,
                "sha256":    sha256,
                "malicious": malicious,
                "total":     total,
                "ratio":     f"{malicious}/{total}",
                "threat":    attrs.get("popular_threat_classification", {})
                                  .get("suggested_threat_label", ""),
                "vt_url":    f"https://www.virustotal.com/gui/file/{sha256}",
            }
    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Hash no encontrado en VT — archivo desconocido o legítimo nuevo
            return {
                "type":      "virustotal",
                "path":      filepath,
                "sha256":    sha256,
                "malicious": 0,
                "total":     0,
                "ratio":     "0/0",
                "threat":    "Sin datos en VirusTotal",
                "vt_url":    f"https://www.virustotal.com/gui/file/{sha256}",
            }
        return {"type": "vt_error", "path": filepath, "error": f"HTTP {e.code}"}
    except Exception as e:
        return {"type": "vt_error", "path": filepath, "error": str(e)[:80]}


# ─────────────────────────────────────────────────────────────────────────────
def _load_c2_list(verbose: bool) -> dict[str, dict]:
    """
    Carga la lista de IPs C2 de Feodo Tracker.
    Usa caché local (TTL 6h). Si no hay conexión, usa la caché existente.
    """
    DATA_DIR.mkdir(exist_ok=True)

    # ¿Caché válida?
    use_cache = (
        C2_CACHE.exists() and
        datetime.fromtimestamp(C2_CACHE.stat().st_mtime) > datetime.now() - C2_CACHE_TTL
    )

    if not use_cache:
        try:
            req = urllib.request.Request(
                C2_CACHE_URL,
                headers={"User-Agent": "TrailBlazer/1.0 (security-research)"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                content = resp.read().decode(errors="ignore")
            C2_CACHE.write_text(content, encoding="utf-8")
            if verbose:
                print(f"  [enrichment] C2 list actualizada: {len(content.splitlines())} líneas")
        except Exception as e:
            if verbose:
                print(f"  [enrichment] No se pudo descargar C2 list: {e}")
            if not C2_CACHE.exists():
                return {}

    # Parsear formato Feodo Tracker:
    # # Feodo Tracker Botnet C&C List
    # # Format: IP address|Port|Date added|Malware|Country
    # 1.2.3.4|443|2024-01-01|Emotet|US
    c2_dict: dict[str, dict] = {}
    try:
        for line in C2_CACHE.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            if len(parts) >= 4:
                ip = parts[0].strip()
                c2_dict[ip] = {
                    "port":    parts[1].strip() if len(parts) > 1 else "?",
                    "malware": parts[3].strip() if len(parts) > 3 else "?",
                    "country": parts[4].strip() if len(parts) > 4 else "?",
                }
    except Exception:
        pass

    return c2_dict


# ─────────────────────────────────────────────────────────────────────────────
def _analyze(vt_results: list[dict], c2_matches: list[dict]) -> list[dict]:
    findings = []

    for vtr in vt_results:
        if vtr.get("type") == "vt_error":
            continue
        mal = vtr.get("malicious", 0)
        tot = vtr.get("total", 0)
        if mal == 0:
            continue  # limpio o sin datos

        sev = "critical" if mal >= 5 else "high" if mal >= 2 else "medium"
        findings.append({
            "severity":    sev,
            "description": f"[VirusTotal] {vtr['ratio']} engines detectan: "
                           f"{Path(vtr['path']).name} — SHA256: {vtr['sha256'][:16]}...  "
                           f"→ {vtr.get('vt_url', '')}",
            "category":    "Malware",
            "path":        vtr.get("path", ""),
            "type":        "virustotal",
            **mitre.get("T1204.002"),
        })

    for c2 in c2_matches:
        findings.append({
            "severity":    "critical",
            "description": f"[C2 Intel] Conexión activa a infraestructura C2 conocida: "
                           f"{c2['ip']} — {c2['malware']} ({c2['country']}) "
                           f"[Fuente: {c2['source']}]",
            "category":    "C2",
            "ip":          c2["ip"],
            "type":        "c2_match",
            **mitre.get("T1071"),
        })

    return findings
