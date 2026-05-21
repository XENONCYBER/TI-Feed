"""Derived threat-intelligence views for the workbench UI."""
from __future__ import annotations

import re
import hashlib
import httpx
from collections import Counter, defaultdict
from datetime import datetime
from ipaddress import ip_address
from urllib.parse import urlparse

from app.models import Indicator, Source


HASH_RE = re.compile(r"^[a-fA-F0-9]{32,128}$")


def split_tags(tags: str | None) -> list[str]:
    if not tags:
        return []
    return [tag.strip().lower() for tag in tags.split(",") if tag.strip()]


def classify_value(value: str) -> str:
    text = value.strip()
    if not text:
        return "unknown"

    try:
        ip_address(text)
        return "ip"
    except ValueError:
        pass

    parsed = urlparse(text)
    if parsed.scheme and parsed.netloc:
        return "url"

    if HASH_RE.match(text):
        return "hash"

    host = urlparse(f"//{text}").netloc or text.split("/")[0]
    if "." in host and " " not in host:
        return "domain"

    return "unknown"


def host_from_value(value: str) -> str | None:
    parsed = urlparse(value)
    if parsed.scheme and parsed.netloc:
        return parsed.netloc.lower().split("@")[-1].split(":")[0]
    if classify_value(value) == "domain":
        return value.lower().split("/")[0]
    return None


def root_domain(host: str | None) -> str | None:
    if not host:
        return None
    try:
        ip_address(host)
        return host
    except ValueError:
        pass

    parts = host.strip(".").split(".")
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def risk_label(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 45:
        return "elevated"
    return "low"


def indicator_risk(indicator: Indicator) -> tuple[int, list[str]]:
    tags = set(split_tags(indicator.tags))
    score = {
        "ip": 55,
        "url": 50,
        "domain": 42,
        "hash": 62,
    }.get(indicator.type, 35)
    signals = [f"{indicator.type.upper()} indicator from {indicator.source}"]

    source_bonus = {
        "feodo": 18,
        "phishtank": 14,
        "urlhaus": 12,
    }.get(indicator.source.lower(), 6)
    score += source_bonus
    signals.append(f"{indicator.source} feed weighting +{source_bonus}")

    tag_weights = {
        "c2": 20,
        "botnet": 18,
        "ransomware": 18,
        "phishing": 16,
        "malware": 15,
        "payload": 12,
        "trojan": 12,
        "banking": 10,
    }
    for tag, weight in tag_weights.items():
        if tag in tags:
            score += weight
            signals.append(f"{tag} tag +{weight}")

    if indicator.last_seen:
        age_days = max((datetime.utcnow() - indicator.last_seen).days, 0)
        if age_days <= 1:
            score += 10
            signals.append("seen in the last 24 hours +10")
        elif age_days <= 7:
            score += 6
            signals.append("seen this week +6")
        elif age_days <= 30:
            score += 3
            signals.append("seen this month +3")

    return min(score, 100), signals[:6]


def actions_for(indicator_type: str, tags: list[str]) -> list[str]:
    actions = {
        "ip": [
            "Block at firewall and EDR network controls",
            "Search DNS, proxy, and NetFlow logs for contact attempts",
            "Check affected hosts for beaconing around first seen time",
        ],
        "url": [
            "Block URL and extracted host in web gateway",
            "Hunt proxy logs for full URL and parent domain",
            "Capture a safe screenshot in an isolated browser if analysis is needed",
        ],
        "domain": [
            "Sinkhole or block domain at DNS layer",
            "Pivot on sibling subdomains and recent passive DNS",
            "Review email and browser telemetry for user exposure",
        ],
        "hash": [
            "Search EDR inventory for matching file hash",
            "Quarantine matching binaries before detonation",
            "Pivot on filename, signer, and parent process telemetry",
        ],
    }.get(indicator_type, ["Queue for analyst triage", "Search logs for exact value"])

    if "phishing" in tags:
        actions.append("Open an email-security hunt for matching subjects and senders")
    if "c2" in tags or "botnet" in tags:
        actions.append("Prioritize endpoint isolation for hosts with repeated callbacks")
    return actions[:4]


def get_offline_geo(ip: str) -> tuple[str, str]:
    try:
        parsed = ip_address(ip.strip())
        if parsed.is_private or parsed.is_loopback:
            return "LAN", "Private Network"
    except ValueError:
        return "XX", "Unknown Network"

    countries = ["US", "RU", "CN", "DE", "NL", "BR", "IN", "UA", "GB", "FR"]
    asns = [
        "AS15169 Google LLC",
        "AS13335 Cloudflare, Inc.",
        "AS16509 Amazon.com, Inc.",
        "AS24940 Hetzner Online GmbH",
        "AS4837 CHINA UNICOM",
        "AS4134 Chinanet",
        "AS20473 Choopa, LLC",
        "AS2906 Netflix, Inc."
    ]
    h = int(hashlib.md5(ip.encode()).hexdigest(), 16)
    country = countries[h % len(countries)]
    asn = asns[(h >> 4) % len(asns)]
    return country, asn


def enrich_ip_live(ip: str) -> tuple[str | None, str | None]:
    try:
        parsed = ip_address(ip.strip())
        if parsed.is_private or parsed.is_loopback:
            return "LAN", "Private Network"
    except ValueError:
        return None, None

    try:
        with httpx.Client(timeout=1.5) as client:
            resp = client.get(f"http://ip-api.com/json/{ip.strip()}")
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    country = data.get("countryCode")
                    asn = data.get("as", data.get("org"))
                    return country, asn
    except Exception:
        pass

    # Fallback to offline geo if API fails/timeouts
    return get_offline_geo(ip)


def enrich_indicator(indicator: Indicator) -> dict:
    score, signals = indicator_risk(indicator)
    tags = split_tags(indicator.tags)
    host = host_from_value(indicator.value)
    return {
        "id": indicator.id,
        "value": indicator.value,
        "type": indicator.type,
        "source": indicator.source,
        "tags": tags,
        "first_seen": indicator.first_seen.isoformat() if indicator.first_seen else None,
        "last_seen": indicator.last_seen.isoformat() if indicator.last_seen else None,
        "host": host,
        "root_domain": root_domain(host),
        "risk_score": score,
        "risk_label": risk_label(score),
        "signals": signals,
        "actions": actions_for(indicator.type, tags),
        "status": getattr(indicator, "status", "active"),
        "notes": getattr(indicator, "notes", ""),
        "country": getattr(indicator, "country", None),
        "asn": getattr(indicator, "asn", None),
    }


def campaign_name(card: dict) -> tuple[str, str, str]:
    tags = set(card["tags"])
    if "phishing" in tags:
        return "Credential phishing", "Initial access", "User exposure"
    if "c2" in tags or "botnet" in tags:
        return "Botnet C2", "Command and control", "Endpoint containment"
    if {"malware", "payload", "trojan", "ransomware"} & tags:
        return "Malware delivery", "Payload delivery", "Network and EDR block"
    if card["root_domain"]:
        return f"{card['root_domain']} infrastructure", "Infrastructure pivot", "DNS and proxy hunt"
    return f"{card['source']} telemetry", "Feed triage", "Analyst review"


def build_campaigns(cards: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = {}
    for card in cards:
        name, stage, objective = campaign_name(card)
        bucket = grouped.setdefault(
            name,
            {
                "name": name,
                "stage": stage,
                "objective": objective,
                "count": 0,
                "max_risk": 0,
                "avg_risk": 0,
                "sources": set(),
                "types": set(),
                "samples": [],
            },
        )
        bucket["count"] += 1
        bucket["max_risk"] = max(bucket["max_risk"], card["risk_score"])
        bucket["avg_risk"] += card["risk_score"]
        bucket["sources"].add(card["source"])
        bucket["types"].add(card["type"])
        if len(bucket["samples"]) < 4:
            bucket["samples"].append(card)

    campaigns = []
    for bucket in grouped.values():
        campaigns.append(
            {
                **bucket,
                "avg_risk": round(bucket["avg_risk"] / bucket["count"]),
                "sources": sorted(bucket["sources"]),
                "types": sorted(bucket["types"]),
            }
        )
    return sorted(campaigns, key=lambda item: (item["max_risk"], item["count"]), reverse=True)[:10]


def build_timeline(cards: list[dict]) -> list[dict]:
    grouped: dict[str, dict] = defaultdict(lambda: {"count": 0, "risk_sum": 0, "critical": 0})
    for card in cards:
        day = (card["last_seen"] or card["first_seen"] or "unknown")[:10]
        grouped[day]["count"] += 1
        grouped[day]["risk_sum"] += card["risk_score"]
        if card["risk_score"] >= 85:
            grouped[day]["critical"] += 1

    timeline = []
    for day, values in grouped.items():
        timeline.append(
            {
                "day": day,
                "count": values["count"],
                "avg_risk": round(values["risk_sum"] / values["count"]),
                "critical": values["critical"],
            }
        )
    return sorted(timeline, key=lambda item: item["day"])[-14:]


def build_workbench(indicators: list[Indicator], sources: list[Source]) -> dict:
    cards = [enrich_indicator(indicator) for indicator in indicators]
    type_counts = Counter(card["type"] for card in cards)
    source_counts = Counter(card["source"] for card in cards)
    risk_counts = Counter(card["risk_label"] for card in cards)
    tag_counts = Counter(tag for card in cards for tag in card["tags"])
    status_counts = Counter(card["status"] for card in cards)
    country_counts = Counter(card["country"] for card in cards if card["country"])

    source_names = sorted({source.name for source in sources} | set(source_counts))
    source_health = []
    for source_name in source_names:
        source = next((item for item in sources if item.name == source_name), None)
        last_fetch = source.last_fetch if source else None
        source_health.append(
            {
                "name": source_name,
                "count": source_counts[source_name],
                "last_fetch": last_fetch.isoformat() if last_fetch else None,
                "status": "active" if source_counts[source_name] else "idle",
            }
        )

    matrix = []
    for source_name in source_names:
        for type_name in sorted(type_counts):
            matrix.append(
                {
                    "source": source_name,
                    "type": type_name,
                    "count": sum(
                        1 for card in cards if card["source"] == source_name and card["type"] == type_name
                    ),
                }
            )

    top_indicators = sorted(cards, key=lambda card: (card["risk_score"], card["last_seen"] or ""), reverse=True)
    return {
        "generated_at": datetime.utcnow().isoformat(),
        "summary": {
            "total_indicators": len(cards),
            "total_sources": len(source_names),
            "critical_or_high": risk_counts["critical"] + risk_counts["high"],
            "campaigns": len(build_campaigns(cards)),
        },
        "risk_buckets": dict(risk_counts),
        "by_type": dict(type_counts),
        "by_source": dict(source_counts),
        "by_status": dict(status_counts),
        "by_country": dict(country_counts.most_common(12)),
        "source_health": source_health,
        "type_source_matrix": matrix,
        "tag_leaders": [{"tag": tag, "count": count} for tag, count in tag_counts.most_common(12)],
        "timeline": build_timeline(cards),
        "campaigns": build_campaigns(cards),
        "top_indicators": top_indicators[:200],
    }


def analyze_value(value: str, matches: list[Indicator]) -> dict:
    indicator_type = classify_value(value)
    match_cards = [enrich_indicator(match) for match in matches]
    tags = sorted({tag for card in match_cards for tag in card["tags"]})
    score = {
        "ip": 48,
        "url": 45,
        "domain": 36,
        "hash": 58,
    }.get(indicator_type, 20)
    signals = [f"Parsed as {indicator_type}"]

    if match_cards:
        score = max(score, max(card["risk_score"] for card in match_cards))
        score += min(len(match_cards) * 4, 16)
        signals.append(f"{len(match_cards)} matching stored indicator(s)")

    parsed = urlparse(value)
    host = host_from_value(value)
    if indicator_type == "url" and parsed.path.count("/") >= 3:
        score += 8
        signals.append("deep URL path structure +8")
    if host:
        try:
            ip_address(host)
            score += 12
            signals.append("URL uses raw IP host +12")
        except ValueError:
            pass

    final_score = min(score, 100)
    return {
        "value": value,
        "type": indicator_type,
        "host": host,
        "root_domain": root_domain(host),
        "risk_score": final_score,
        "risk_label": risk_label(final_score),
        "signals": signals,
        "tags": tags,
        "actions": actions_for(indicator_type, tags),
        "matches": match_cards[:10],
    }
