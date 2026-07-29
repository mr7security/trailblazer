"""
TrailBlazer :: Baseline / Delta Engine
Permite capturar un snapshot del estado del sistema y compararlo
con un scan posterior para detectar cambios forenses.

Uso:
  trailblazer.py --baseline save [--baseline-name clean]
  trailblazer.py --baseline compare [--baseline-name clean]
"""

from __future__ import annotations
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

# Cuando se ejecuta como .exe (PyInstaller frozen), los archivos de datos
# deben escribirse junto al ejecutable, no dentro del bundle temporal.
if getattr(sys, "frozen", False):
    _BASE = Path(sys.executable).parent
else:
    _BASE = Path(__file__).resolve().parent.parent

BASELINE_DIR = _BASE / "baselines"


# ─────────────────────────────────────────────────────────────────────────────
def save(module_results: list[dict], name: str = "default",
         meta: dict | None = None) -> Path:
    """Guarda un snapshot de los resultados como baseline JSON."""
    BASELINE_DIR.mkdir(exist_ok=True)

    snapshot = {
        "meta": {
            "name":      name,
            "created":   datetime.now().isoformat(),
            "tool":      "TrailBlazer",
            **(meta or {}),
        },
        "findings":  _extract_findings(module_results),
        "summaries": {r["module"]: r.get("summary", {}) for r in module_results},
    }

    path = BASELINE_DIR / f"{name}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snapshot, f, indent=2, ensure_ascii=False, default=str)

    return path


def load(name: str = "default") -> dict:
    """Carga un baseline guardado previamente."""
    path = BASELINE_DIR / f"{name}.json"
    if not path.exists():
        raise FileNotFoundError(
            f"No se encontró el baseline '{name}' en {BASELINE_DIR}.\n"
            f"  Créalo con: python trailblazer.py --full-scan --baseline save --baseline-name {name}"
        )
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def list_baselines() -> list[dict]:
    """Lista los baselines disponibles."""
    if not BASELINE_DIR.exists():
        return []
    result = []
    for p in sorted(BASELINE_DIR.glob("*.json")):
        try:
            with open(p, encoding="utf-8") as f:
                data = json.load(f)
            meta = data.get("meta", {})
            result.append({
                "name":    p.stem,
                "created": meta.get("created", "?"),
                "path":    str(p),
                "count":   len(data.get("findings", [])),
            })
        except Exception:
            result.append({"name": p.stem, "path": str(p)})
    return result


# ─────────────────────────────────────────────────────────────────────────────
def compare(baseline: dict, current_results: list[dict]) -> dict:
    """
    Compara el baseline con el scan actual.
    Devuelve: {new, resolved, persisting, delta_score}
    """
    base_findings = {_fingerprint(f): f for f in baseline.get("findings", [])}
    curr_findings = {_fingerprint(f): f for f in _extract_findings(current_results)}

    base_keys = set(base_findings.keys())
    curr_keys = set(curr_findings.keys())

    new_keys       = curr_keys - base_keys
    resolved_keys  = base_keys - curr_keys
    persisting_keys = base_keys & curr_keys

    return {
        "baseline_name": baseline.get("meta", {}).get("name", "?"),
        "baseline_date": baseline.get("meta", {}).get("created", "?"),
        "new":           [curr_findings[k] for k in new_keys],
        "resolved":      [base_findings[k] for k in resolved_keys],
        "persisting":    [base_findings[k] for k in persisting_keys],
        "stats": {
            "new_count":       len(new_keys),
            "resolved_count":  len(resolved_keys),
            "persisting_count": len(persisting_keys),
            "baseline_total":  len(base_keys),
            "current_total":   len(curr_keys),
        },
    }


# ─────────────────────────────────────────────────────────────────────────────
def _extract_findings(module_results: list[dict]) -> list[dict]:
    """Extrae todos los findings de una lista de resultados de módulos."""
    findings = []
    for r in module_results:
        for f in r.get("findings", []):
            f2 = dict(f)
            f2["_module"] = r.get("module", "?")
            findings.append(f2)
    return findings


def _fingerprint(finding: dict) -> str:
    """
    Genera una huella única para un finding basada en:
    severity + module + description (primeros 80 chars) + category.
    No incluimos datos dinámicos (timestamps, PIDs) para que
    findings equivalentes en distinto momento sean iguales.
    """
    parts = [
        finding.get("severity", ""),
        finding.get("_module", ""),
        finding.get("category", ""),
        finding.get("description", "")[:80],
    ]
    return "|".join(parts)
