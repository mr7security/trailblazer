"""
TrailBlazer :: Collector - Red
Analiza conexiones de red activas, puertos en escucha y tráfico sospechoso.
"""

from __future__ import annotations
import socket
from typing import Any

try:
    import psutil
    PSUTIL_OK = True
except ImportError:
    PSUTIL_OK = False

from core.config import SENSITIVE_PORTS, RISK_WEIGHTS


# ─────────────────────────────────────────────────────────────────────────────
def collect(verbose: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {
        "module": "network",
        "findings": [],
        "summary": {},
        "risk_score": 0,
    }

    if not PSUTIL_OK:
        result["error"] = "psutil no instalado."
        return result

    connections  = _get_connections()
    interfaces   = _get_interfaces()
    findings     = _analyze(connections)

    result["connections"]  = connections
    result["interfaces"]   = interfaces
    result["findings"]     = findings
    result["risk_score"]   = sum(RISK_WEIGHTS.get(f["severity"], 0) for f in findings)
    result["summary"] = {
        "total_connections":    len(connections),
        "listening_ports":      sum(1 for c in connections if c["status"] == "LISTEN"),
        "established":          sum(1 for c in connections if c["status"] == "ESTABLISHED"),
        "external_connections": sum(1 for c in connections if c["is_external"]),
        "findings_count":       len(findings),
    }
    return result


# ─────────────────────────────────────────────────────────────────────────────
def _get_connections() -> list[dict]:
    """Obtiene todas las conexiones de red del sistema."""
    conns = []
    pid_map = {p.pid: p.name() for p in psutil.process_iter(["pid", "name"], ad_value="?")}

    try:
        raw_conns = psutil.net_connections(kind="inet")
    except psutil.AccessDenied:
        raw_conns = []

    for c in raw_conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        rip   = c.raddr.ip if c.raddr else ""

        conns.append({
            "pid":         c.pid,
            "process":     pid_map.get(c.pid, "?"),
            "family":      "IPv6" if c.family.name == "AF_INET6" else "IPv4",
            "type":        "UDP" if c.type.name == "SOCK_DGRAM" else "TCP",
            "laddr":       laddr,
            "raddr":       raddr,
            "status":      c.status if c.status else "",
            "is_external": bool(rip) and not _is_local(rip),
            "rport":       c.raddr.port if c.raddr else None,
            "lport":       c.laddr.port if c.laddr else None,
        })

    return conns


def _get_interfaces() -> list[dict]:
    """Obtiene información de interfaces de red."""
    interfaces = []
    stats  = psutil.net_if_stats()
    addrs  = psutil.net_if_addrs()

    for name, addr_list in addrs.items():
        ips = []
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ips.append({"ip": addr.address, "netmask": addr.netmask})
        st = stats.get(name)
        interfaces.append({
            "name":  name,
            "ips":   ips,
            "up":    st.isup if st else False,
            "speed": st.speed if st else 0,
        })
    return interfaces


# ─────────────────────────────────────────────────────────────────────────────
def _analyze(connections: list[dict]) -> list[dict]:
    findings = []
    seen_suspicious_ports: set[int] = set()

    for c in connections:
        rport = c.get("rport")
        lport = c.get("lport")

        # ── Puerto remoto sensible ──────────────────────────────────────────
        if rport and rport in SENSITIVE_PORTS and rport not in seen_suspicious_ports:
            seen_suspicious_ports.add(rport)
            svc = SENSITIVE_PORTS[rport]
            findings.append(_finding(
                "high",
                f"Conexión a puerto sensible {rport} ({svc}) → {c['raddr']} [{c['process']}]",
                c, "Network"
            ))

        # ── Puerto local sospechoso en escucha ────────────────────────────
        if lport and lport in SENSITIVE_PORTS and c["status"] == "LISTEN":
            if lport not in seen_suspicious_ports:
                seen_suspicious_ports.add(lport)
                svc = SENSITIVE_PORTS[lport]
                findings.append(_finding(
                    "medium",
                    f"Puerto sensible {lport} ({svc}) escuchando localmente [{c['process']}]",
                    c, "Network"
                ))

        # ── Conexiones externas de procesos inusuales ─────────────────────
        if c["is_external"] and c["status"] == "ESTABLISHED":
            unusual = {"cmd.exe", "powershell.exe", "wscript.exe",
                       "cscript.exe", "mshta.exe", "rundll32.exe",
                       "regsvr32.exe", "bash", "sh"}
            if c["process"].lower() in unusual:
                findings.append(_finding(
                    "critical",
                    f"Proceso inusual con conexión externa: {c['process']} → {c['raddr']}",
                    c, "C2/Exfil"
                ))

        # ── Altas puertos locales (>49000) en LISTEN sin proceso conocido ──
        if lport and lport > 49000 and c["status"] == "LISTEN" and c["process"] in ("?", ""):
            findings.append(_finding(
                "medium",
                f"Puerto alto {lport} en escucha sin proceso identificado",
                c, "Backdoor"
            ))

    return findings


# ─────────────────────────────────────────────────────────────────────────────
def _is_local(ip: str) -> bool:
    return ip.startswith(("127.", "10.", "192.168.", "172.16.", "172.17.",
                           "172.18.", "172.19.", "172.2", "::1", "fe80", "0.0.0.0"))


def _finding(severity: str, description: str, conn: dict, category: str) -> dict:
    return {
        "severity":    severity,
        "description": description,
        "category":    category,
        "connection": {
            "process": conn.get("process"),
            "pid":     conn.get("pid"),
            "laddr":   conn.get("laddr"),
            "raddr":   conn.get("raddr"),
            "status":  conn.get("status"),
        },
    }
