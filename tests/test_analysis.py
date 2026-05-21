from datetime import datetime, timedelta
from types import SimpleNamespace

from app.analysis import (
    analyze_indicator,
    campaign_key,
    parse_search_intent,
    risk_level_matches,
)


def test_parse_search_intent_extracts_filters_and_time_window():
    now = datetime(2026, 5, 21, 12, 0, 0)

    intent = parse_search_intent(
        "show high risk botnet IPs from Feodo last 7 days",
        now=now,
    )

    assert intent.types == ["ip"]
    assert intent.sources == ["feodo"]
    assert intent.tags == ["botnet"]
    assert intent.risk_levels == ["high"]
    assert intent.since == now - timedelta(days=7)
    assert intent.since_label == "last 7 days"
    assert intent.text_terms == []


def test_analyze_indicator_marks_recent_c2_ip_as_high_risk():
    indicator = SimpleNamespace(
        value="45.142.122.90",
        type="ip",
        source="feodo",
        tags="botnet,c2,emotet",
        first_seen=datetime(2026, 5, 20, 12, 0, 0),
        last_seen=datetime(2026, 5, 21, 10, 0, 0),
    )

    analysis = analyze_indicator(indicator, now=datetime(2026, 5, 21, 12, 0, 0))

    assert analysis.risk_level in {"high", "critical"}
    assert analysis.risk_score >= 65
    assert analysis.campaign_key == "c2:45.142.122.0/24"
    assert any("Feodo" in reason for reason in analysis.risk_reasons)


def test_campaign_key_groups_urls_by_base_host_and_primary_tag():
    key = campaign_key(
        "http://secure.login.example.com/payment/verify",
        "url",
        ["phishing", "banking"],
    )

    assert key == "phishing:example.com"


def test_high_risk_query_keeps_high_and_critical_only():
    assert risk_level_matches("critical", ["high"])
    assert risk_level_matches("high", ["high"])
    assert not risk_level_matches("medium", ["high"])


def test_parse_search_intent_extracts_country_and_status():
    intent = parse_search_intent("active russian and american indicators country:cn status:mitigated")
    assert "ru" in intent.countries
    assert "us" in intent.countries
    assert "cn" in intent.countries
    assert "active" in intent.statuses
    assert "mitigated" in intent.statuses

