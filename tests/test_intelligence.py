from datetime import datetime
from types import SimpleNamespace

from app.intelligence import analyze_value, build_workbench, root_domain


def test_root_domain_preserves_ip_hosts():
    assert root_domain("185.199.108.153") == "185.199.108.153"


def test_analyze_value_scores_matching_raw_ip_url():
    indicator = SimpleNamespace(
        id=1,
        value="http://185.199.108.153/update/login/verify.exe",
        type="url",
        source="urlhaus",
        tags="malware,payload,stealer",
        first_seen=datetime(2026, 5, 21, 10, 0, 0),
        last_seen=datetime(2026, 5, 21, 11, 0, 0),
    )

    result = analyze_value(indicator.value, [indicator])

    assert result["type"] == "url"
    assert result["root_domain"] == "185.199.108.153"
    assert result["risk_label"] == "critical"
    assert result["matches"][0]["root_domain"] == "185.199.108.153"


def test_build_workbench_groups_campaigns_and_priority_counts():
    indicators = [
        SimpleNamespace(
            id=1,
            value="45.142.122.90",
            type="ip",
            source="feodo",
            tags="botnet,c2,emotet",
            first_seen=datetime(2026, 5, 21, 10, 0, 0),
            last_seen=datetime(2026, 5, 21, 11, 0, 0),
        ),
        SimpleNamespace(
            id=2,
            value="http://secure-billing-check.example.com/payment/login",
            type="url",
            source="phishtank",
            tags="phishing,banking,login",
            first_seen=datetime(2026, 5, 21, 10, 0, 0),
            last_seen=datetime(2026, 5, 21, 11, 0, 0),
        ),
    ]
    sources = [
        SimpleNamespace(name="feodo", last_fetch=datetime(2026, 5, 21, 11, 0, 0)),
        SimpleNamespace(name="phishtank", last_fetch=datetime(2026, 5, 21, 11, 0, 0)),
    ]

    result = build_workbench(indicators, sources)

    assert result["summary"]["total_indicators"] == 2
    assert result["summary"]["critical_or_high"] == 2
    assert {campaign["name"] for campaign in result["campaigns"]} == {
        "Botnet C2",
        "Credential phishing",
    }
