"""
TrailBlazer :: Reporter - HTML
Genera un informe HTML profesional con todos los resultados del análisis.
"""

from __future__ import annotations
import json
from datetime import datetime
from typing import Any

SEVERITY_BADGE = {
    "critical": '<span class="badge critical">💀 CRITICAL</span>',
    "high":     '<span class="badge high">🔴 HIGH</span>',
    "medium":   '<span class="badge medium">🟡 MEDIUM</span>',
    "low":      '<span class="badge low">🔵 LOW</span>',
    "info":     '<span class="badge info">⚪ INFO</span>',
}


# ─────────────────────────────────────────────────────────────────────────────
def generate(module_results: list[dict], total_risk: int,
             timeframe: str = "24h", output_path: str = "") -> str:
    """Genera el HTML completo y lo escribe en output_path. Devuelve la ruta."""

    all_findings = []
    for r in module_results:
        for f in r.get("findings", []):
            f2 = dict(f)
            f2["_module"] = r.get("module", "?")
            all_findings.append(f2)

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    all_findings.sort(key=lambda f: order.get(f.get("severity", "info"), 99))

    score     = max(0, 100 - min(100, total_risk))
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not output_path:
        output_path = f"trailblazer_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"

    html = _build_html(all_findings, module_results, score, total_risk, timestamp, timeframe)

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)

    return output_path


# ─────────────────────────────────────────────────────────────────────────────
def _build_html(findings, module_results, score, risk, timestamp, timeframe) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1

    score_color = ("#2ecc71" if score >= 80 else
                   "#f39c12" if score >= 50 else
                   "#e74c3c" if score >= 20 else "#8e44ad")
    score_label = ("BUENA" if score >= 80 else "MEDIA" if score >= 50 else
                   "DÉBIL" if score >= 20 else "CRÍTICA")

    findings_rows = "\n".join(_finding_row(f) for f in findings)
    module_cards  = "\n".join(_module_card(r) for r in module_results)

    return f"""<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>TrailBlazer Report — {timestamp}</title>
<style>
  :root {{
    --bg:       #0d1117;
    --bg2:      #161b22;
    --bg3:      #21262d;
    --border:   #30363d;
    --text:     #c9d1d9;
    --accent:   #ff4757;
    --green:    #2ecc71;
    --yellow:   #f39c12;
    --blue:     #3498db;
    --purple:   #9b59b6;
    --red:      #e74c3c;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', monospace; line-height: 1.6; }}
  a {{ color: var(--blue); text-decoration: none; }}

  /* Header */
  .header {{ background: linear-gradient(135deg, #0d1117 0%, #1a0a0a 100%);
             border-bottom: 2px solid var(--accent); padding: 2rem 3rem; }}
  .header h1 {{ color: var(--accent); font-size: 2rem; letter-spacing: 4px; }}
  .header .sub {{ color: #666; font-size: 0.85rem; margin-top: 0.3rem; }}
  .meta {{ display: flex; gap: 2rem; margin-top: 1rem; flex-wrap: wrap; }}
  .meta span {{ background: var(--bg3); padding: 0.2rem 0.8rem;
                border-radius: 12px; font-size: 0.8rem; color: #aaa; }}

  /* Container */
  .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem 1.5rem; }}

  /* Score card */
  .score-card {{ background: var(--bg2); border: 1px solid var(--border);
                 border-radius: 12px; padding: 2rem; margin-bottom: 2rem;
                 display: flex; align-items: center; gap: 3rem; flex-wrap: wrap; }}
  .score-circle {{ width: 120px; height: 120px; border-radius: 50%;
                   border: 6px solid {score_color}; display: flex;
                   flex-direction: column; align-items: center; justify-content: center;
                   flex-shrink: 0; }}
  .score-num {{ font-size: 2.2rem; font-weight: 900; color: {score_color}; }}
  .score-lbl {{ font-size: 0.65rem; color: #aaa; letter-spacing: 1px; }}
  .score-info h2 {{ color: {score_color}; font-size: 1.4rem; margin-bottom: 0.5rem; }}
  .score-bar-wrap {{ background: var(--bg3); border-radius: 6px; height: 10px;
                     width: 320px; max-width: 100%; overflow: hidden; margin-top: 0.8rem; }}
  .score-bar {{ height: 100%; border-radius: 6px;
                background: {score_color}; width: {score}%; transition: width 1s; }}

  /* Stat badges */
  .stats {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 10px;
           padding: 1rem 1.5rem; text-align: center; flex: 1; min-width: 110px; }}
  .stat .num {{ font-size: 2rem; font-weight: 700; }}
  .stat .lbl {{ font-size: 0.75rem; color: #888; text-transform: uppercase; letter-spacing: 1px; }}
  .stat.critical .num {{ color: #8e44ad; }}
  .stat.high .num     {{ color: var(--red); }}
  .stat.medium .num   {{ color: var(--yellow); }}
  .stat.low .num      {{ color: var(--blue); }}
  .stat.info .num     {{ color: #666; }}

  /* Section */
  .section-title {{ font-size: 1rem; font-weight: 700; color: var(--yellow);
                    letter-spacing: 2px; text-transform: uppercase;
                    border-left: 3px solid var(--yellow); padding-left: 0.8rem;
                    margin: 2rem 0 1rem; }}

  /* Findings table */
  .table-wrap {{ overflow-x: auto; border-radius: 10px; border: 1px solid var(--border); }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.88rem; }}
  thead tr {{ background: var(--bg3); }}
  th {{ padding: 0.8rem 1rem; text-align: left; color: #8b949e;
        font-weight: 600; border-bottom: 1px solid var(--border); }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background .15s; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: var(--bg3); }}
  td {{ padding: 0.75rem 1rem; vertical-align: top; }}
  td.desc {{ max-width: 500px; word-break: break-word; }}

  /* Badges */
  .badge {{ display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px;
            font-size: 0.75rem; font-weight: 700; white-space: nowrap; }}
  .badge.critical {{ background: rgba(142,68,173,0.25); color: #d8b4fe; border: 1px solid #9b59b6; }}
  .badge.high     {{ background: rgba(231,76,60,0.2);   color: #fca5a5; border: 1px solid #e74c3c; }}
  .badge.medium   {{ background: rgba(243,156,18,0.2);  color: #fcd34d; border: 1px solid #f39c12; }}
  .badge.low      {{ background: rgba(52,152,219,0.2);  color: #93c5fd; border: 1px solid #3498db; }}
  .badge.info     {{ background: rgba(107,114,128,0.2); color: #9ca3af; border: 1px solid #6b7280; }}

  /* Module cards */
  .modules {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
              gap: 1rem; margin-bottom: 2rem; }}
  .mod-card {{ background: var(--bg2); border: 1px solid var(--border);
               border-radius: 10px; padding: 1.2rem; }}
  .mod-card h3 {{ color: var(--blue); font-size: 0.95rem; margin-bottom: 0.6rem;
                  text-transform: uppercase; letter-spacing: 1px; }}
  .mod-stat {{ display: flex; justify-content: space-between;
               font-size: 0.82rem; color: #8b949e; margin: 0.2rem 0; }}
  .mod-stat span {{ color: var(--text); }}

  /* Footer */
  footer {{ text-align: center; color: #444; font-size: 0.75rem;
            padding: 2rem; border-top: 1px solid var(--border); margin-top: 3rem; }}

  /* Filter buttons */
  .filters {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem; }}
  .filter-btn {{ background: var(--bg3); border: 1px solid var(--border);
                 color: #aaa; padding: 0.3rem 0.9rem; border-radius: 6px;
                 cursor: pointer; font-size: 0.8rem; transition: all .2s; }}
  .filter-btn:hover, .filter-btn.active {{
    background: var(--accent); border-color: var(--accent); color: white; }}
  .hidden {{ display: none; }}
</style>
</head>
<body>

<div class="header">
  <h1>⚡ TRAILBLAZER</h1>
  <div class="sub">Red Team OPSEC &amp; Forensic Footprint Analyzer</div>
  <div class="meta">
    <span>📅 {timestamp}</span>
    <span>⏱ Timeframe: {timeframe}</span>
    <span>🔍 Findings: {len(findings)}</span>
    <span>⚠ Risk Score: {risk}</span>
  </div>
</div>

<div class="container">

  <!-- Score -->
  <div class="score-card">
    <div class="score-circle">
      <div class="score-num">{score}</div>
      <div class="score-lbl">OPSEC</div>
    </div>
    <div class="score-info">
      <h2>OPSEC {score_label}</h2>
      <p style="color:#888; font-size:0.85rem;">
        Un score mayor indica menor huella forense detectada.<br>
        Reduce hallazgos críticos y altos para mejorar el score.
      </p>
      <div class="score-bar-wrap"><div class="score-bar"></div></div>
    </div>
  </div>

  <!-- Stats -->
  <div class="stats">
    <div class="stat critical"><div class="num">{counts['critical']}</div><div class="lbl">Critical</div></div>
    <div class="stat high">   <div class="num">{counts['high']}</div>   <div class="lbl">High</div></div>
    <div class="stat medium"> <div class="num">{counts['medium']}</div> <div class="lbl">Medium</div></div>
    <div class="stat low">    <div class="num">{counts['low']}</div>    <div class="lbl">Low</div></div>
    <div class="stat info">   <div class="num">{counts['info']}</div>   <div class="lbl">Info</div></div>
  </div>

  <!-- Módulos -->
  <div class="section-title">📦 Módulos Ejecutados</div>
  <div class="modules">
    {module_cards}
  </div>

  <!-- Findings -->
  <div class="section-title">🔎 Findings Detallados</div>

  <div class="filters">
    <button class="filter-btn active" onclick="filterFindings('all')">Todos ({len(findings)})</button>
    <button class="filter-btn" onclick="filterFindings('critical')">💀 Critical ({counts['critical']})</button>
    <button class="filter-btn" onclick="filterFindings('high')">🔴 High ({counts['high']})</button>
    <button class="filter-btn" onclick="filterFindings('medium')">🟡 Medium ({counts['medium']})</button>
    <button class="filter-btn" onclick="filterFindings('low')">🔵 Low ({counts['low']})</button>
    <button class="filter-btn" onclick="filterFindings('info')">⚪ Info ({counts['info']})</button>
  </div>

  <div class="table-wrap">
    <table id="findings-table">
      <thead>
        <tr>
          <th>Severidad</th>
          <th>Módulo</th>
          <th>Categoría</th>
          <th>Descripción</th>
        </tr>
      </thead>
      <tbody>
        {findings_rows}
      </tbody>
    </table>
  </div>

</div>

<footer>
  TrailBlazer v1.0.0 — Herramienta educativa para profesionales de seguridad —
  Uso exclusivo en entornos autorizados
</footer>

<script>
function filterFindings(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('#findings-table tbody tr').forEach(row => {{
    row.classList.toggle('hidden', sev !== 'all' && row.dataset.sev !== sev);
  }});
}}
</script>
</body>
</html>"""


def _finding_row(f: dict) -> str:
    sev   = f.get("severity", "info")
    badge = SEVERITY_BADGE.get(sev, sev)
    return (
        f'<tr data-sev="{sev}">'
        f'<td>{badge}</td>'
        f'<td><code>{f.get("_module", "?")}</code></td>'
        f'<td>{f.get("category", "?")}</td>'
        f'<td class="desc">{_esc(f.get("description", ""))}</td>'
        f'</tr>'
    )


def _module_card(r: dict) -> str:
    mod  = r.get("module", "?")
    s    = r.get("summary", {})
    risk = r.get("risk_score", 0)
    nf   = s.get("findings_count", 0)

    if "error" in r:
        return (
            f'<div class="mod-card">'
            f'<h3>{mod}</h3>'
            f'<div style="color:#e74c3c; font-size:0.82rem;">{r["error"]}</div>'
            f'</div>'
        )

    # Items key varía por módulo
    items_key = next((k for k in ["total_processes", "total_connections",
                                   "total_items", "total_events"] if k in s), None)
    items_val = s.get(items_key, "?") if items_key else "?"

    stat_color = "var(--red)" if risk > 30 else ("var(--yellow)" if risk > 10 else "var(--green)")

    return (
        f'<div class="mod-card">'
        f'<h3>📂 {mod}</h3>'
        f'<div class="mod-stat">Items analizados <span>{items_val}</span></div>'
        f'<div class="mod-stat">Findings <span style="color:{stat_color}">{nf}</span></div>'
        f'<div class="mod-stat">Risk Score <span style="color:{stat_color}">{risk}</span></div>'
        f'</div>'
    )


def _esc(s: str) -> str:
    return (s.replace("&", "&amp;").replace("<", "&lt;")
             .replace(">", "&gt;").replace('"', "&quot;"))
