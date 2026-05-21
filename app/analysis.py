"""Local NLP and explainable threat analysis helpers."""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta
from ipaddress import ip_address
from urllib.parse import urlparse


TYPE_ALIASES = {
    "ip": {"ip", "ips", "address", "addresses", "c2", "botnet"},
    "url": {"url", "urls", "link", "links", "website", "websites"},
    "domain": {"domain", "domains", "host", "hosts", "hostname"},
    "hash": {"hash", "hashes", "sha256", "md5", "file"},
}

SOURCE_ALIASES = {
    "urlhaus": {"urlhaus", "urlhausfeed"},
    "phishtank": {"phishtank", "phish", "phishing"},
    "feodo": {"feodo", "feodotracker"},
}

TAG_ALIASES = {
    "phishing": {"phishing", "phish", "credential", "credentials", "login"},
    "botnet": {"botnet", "botnets", "zombie"},
    "c2": {"c2", "command", "control", "cnc"},
    "malware": {"malware", "payload", "trojan", "stealer", "ransomware"},
    "banking": {"banking", "bank", "payment", "invoice"},
}

RISK_ALIASES = {
    "critical": {"critical", "severe", "worst"},
    "high": {"high", "dangerous", "urgent", "risky"},
    "medium": {"medium", "moderate", "suspicious"},
    "low": {"low", "minor"},
}

COUNTRY_ALIASES = {
    "us": {"us", "usa", "united states", "america", "american"},
    "ru": {"ru", "russia", "russian"},
    "cn": {"cn", "china", "chinese"},
    "de": {"de", "germany", "german"},
    "nl": {"nl", "netherlands", "dutch"},
    "gb": {"gb", "uk", "united kingdom", "britain", "british"},
    "ua": {"ua", "ukraine", "ukrainian"},
    "br": {"br", "brazil", "brazilian"},
    "in": {"in", "india", "indian"},
    "fr": {"fr", "france", "french"},
}

STATUS_ALIASES = {
    "active": {"active", "live", "running", "online"},
    "mitigated": {"mitigated", "resolved", "blocked", "offline", "cleared"},
    "false_positive": {"false_positive", "fp", "whitelist", "whitelisted", "safe"},
}

RISK_LEVEL_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

STOPWORDS = {
    "a",
    "all",
    "and",
    "are",
    "by",
    "find",
    "for",
    "from",
    "give",
    "i",
    "in",
    "last",
    "latest",
    "day",
    "days",
    "hour",
    "hours",
    "me",
    "of",
    "on",
    "past",
    "recent",
    "risk",
    "show",
    "that",
    "the",
    "this",
    "threat",
    "threats",
    "to",
    "with",
}

TAG_WEIGHTS = {
    "ransomware": 40,
    "stealer": 35,
    "c2": 30,
    "botnet": 30,
    "malware": 28,
    "trojan": 25,
    "phishing": 24,
    "payload": 20,
    "banking": 12,
}


@dataclass(frozen=True)
class SearchIntent:
    raw_query: str
    text_terms: list[str]
    types: list[str]
    sources: list[str]
    tags: list[str]
    risk_levels: list[str]
    since: datetime | None
    since_label: str | None
    countries: list[str]
    statuses: list[str]

    def as_dict(self) -> dict[str, object]:
        return {
            "raw_query": self.raw_query,
            "text_terms": self.text_terms,
            "types": self.types,
            "sources": self.sources,
            "tags": self.tags,
            "risk_levels": self.risk_levels,
            "since": self.since,
            "since_label": self.since_label,
            "countries": self.countries,
            "statuses": self.statuses,
        }


@dataclass(frozen=True)
class ThreatAnalysis:
    risk_score: int
    risk_level: str
    risk_reasons: list[str]
    campaign_key: str


def parse_search_intent(query: str, now: datetime | None = None) -> SearchIntent:
    """Convert a plain-English threat hunting query into structured filters."""
    current_time = now or datetime.utcnow()
    normalized = query.strip().lower()
    tokens = re.findall(r"[a-z0-9_.:/-]+", normalized)
    token_set = set(tokens)

    types = _collect_alias_matches(token_set, TYPE_ALIASES)
    sources = _collect_alias_matches(token_set, SOURCE_ALIASES)
    tags = _collect_alias_matches(token_set, TAG_ALIASES)
    risk_levels = _parse_risk_levels(token_set)
    countries = _collect_alias_matches(token_set, COUNTRY_ALIASES)
    statuses = _collect_alias_matches(token_set, STATUS_ALIASES)
    
    # Parse explicit key-value filters like country:us, status:active
    for token in tokens:
        if token.startswith("country:"):
            c = token.split(":", 1)[1]
            if c and c not in countries:
                countries.append(c)
        elif token.startswith("status:"):
            s = token.split(":", 1)[1]
            if s and s not in statuses:
                statuses.append(s)

    since, since_label = _parse_time_window(normalized, current_time)

    filter_words = _all_alias_words() | STOPWORDS
    text_terms = [
        token
        for token in tokens
        if token not in filter_words and not token.isdigit() and len(token) > 1 and not (token.startswith("country:") or token.startswith("status:"))
    ]

    return SearchIntent(
        raw_query=query,
        text_terms=_dedupe(text_terms),
        types=types,
        sources=sources,
        tags=tags,
        risk_levels=risk_levels,
        since=since,
        since_label=since_label,
        countries=countries,
        statuses=statuses,
    )


def analyze_indicator(indicator, now: datetime | None = None) -> ThreatAnalysis:
    """Score an indicator with explainable local features."""
    current_time = now or datetime.utcnow()
    tags = _split_tags(indicator.tags)
    value = str(indicator.value or "")
    indicator_type = str(indicator.type or "").lower()
    source = str(indicator.source or "").lower()
    score = 10
    reasons: list[str] = []

    if indicator_type == "url":
        score += 14
        reasons.append("URL indicators can deliver payloads or credential pages.")
    elif indicator_type == "ip":
        score += 12
        reasons.append("IP indicators can represent reachable infrastructure.")
    elif indicator_type == "hash":
        score += 18
        reasons.append("File hash indicator suggests known malicious content.")

    if source in {"urlhaus", "phishtank"}:
        score += 12
        reasons.append(f"Source feed {source} specializes in active malicious URLs.")
    elif source == "feodo":
        score += 16
        reasons.append("Feodo feed tracks botnet command-and-control infrastructure.")

    for tag in tags:
        weight = TAG_WEIGHTS.get(tag)
        if weight:
            score += weight
            reasons.append(f"Tag '{tag}' raises risk.")

    url_features = _url_risk_features(value)
    score += sum(points for points, _ in url_features)
    reasons.extend(reason for _, reason in url_features)

    if indicator.last_seen:
        age_days = max((current_time - indicator.last_seen).days, 0)
        if age_days <= 2:
            score += 16
            reasons.append("Seen in the last 48 hours.")
        elif age_days <= 14:
            score += 8
            reasons.append("Seen within the last 14 days.")

    risk_score = min(score, 100)
    return ThreatAnalysis(
        risk_score=risk_score,
        risk_level=_risk_level(risk_score),
        risk_reasons=reasons[:5] or ["No strong risk feature matched."],
        campaign_key=campaign_key(value, indicator_type, tags),
    )


def explain_intent_match(indicator, intent: SearchIntent) -> list[str]:
    """Explain why a result matched the natural-language query."""
    tags = set(_split_tags(indicator.tags))
    value = str(indicator.value or "").lower()
    source = str(indicator.source or "").lower()
    indicator_type = str(indicator.type or "").lower()
    country = str(getattr(indicator, "country", "") or "").lower()
    status = str(getattr(indicator, "status", "") or "").lower()
    reasons: list[str] = []

    if indicator_type in intent.types:
        reasons.append(f"type matched '{indicator_type}'")
    if source in intent.sources:
        reasons.append(f"source matched '{source}'")
    if country in intent.countries:
        reasons.append(f"country matched '{country}'")
    if status in intent.statuses:
        reasons.append(f"status matched '{status}'")

    matched_tags = sorted(tags.intersection(intent.tags))
    if matched_tags:
        reasons.append("tag matched " + ", ".join(matched_tags))

    matched_terms = [
        term
        for term in intent.text_terms
        if term in value or any(term in tag for tag in tags)
    ]
    if matched_terms:
        reasons.append("text matched " + ", ".join(matched_terms[:3]))

    return reasons or ["ranked by recency and risk"]


def semantic_score(indicator, intent: SearchIntent) -> int:
    tags = set(_split_tags(indicator.tags))
    country = str(getattr(indicator, "country", "") or "").lower()
    status = str(getattr(indicator, "status", "") or "").lower()
    haystack = f"{indicator.value} {indicator.source} {indicator.type} {' '.join(tags)} {country} {status}".lower()
    score = 0

    if str(indicator.type).lower() in intent.types:
        score += 25
    if str(indicator.source).lower() in intent.sources:
        score += 20
    if country in intent.countries:
        score += 15
    if status in intent.statuses:
        score += 15
    score += 10 * len(tags.intersection(intent.tags))
    score += 4 * sum(1 for term in intent.text_terms if term in haystack)
    return score


def campaign_key(value: str, indicator_type: str, tags: list[str]) -> str:
    primary_tag = _primary_tag(tags) or indicator_type or "indicator"
    entity = _campaign_entity(value, indicator_type)
    return f"{primary_tag}:{entity}"


def risk_level_matches(level: str, requested: list[str]) -> bool:
    if not requested:
        return True

    level_rank = RISK_LEVEL_ORDER.get(level, 0)
    requested_rank = min(RISK_LEVEL_ORDER[item] for item in requested)
    return level_rank >= requested_rank


def _collect_alias_matches(token_set: set[str], aliases: dict[str, set[str]]) -> list[str]:
    return [
        canonical
        for canonical, words in aliases.items()
        if token_set.intersection(words)
    ]


def _parse_risk_levels(token_set: set[str]) -> list[str]:
    levels = [
        canonical
        for canonical, words in RISK_ALIASES.items()
        if token_set.intersection(words)
    ]
    return sorted(levels, key=lambda item: RISK_LEVEL_ORDER[item])


def _parse_time_window(query: str, now: datetime) -> tuple[datetime | None, str | None]:
    day_match = re.search(r"(?:last|past)\s+(\d+)\s+days?", query)
    if day_match:
        days = max(int(day_match.group(1)), 1)
        return now - timedelta(days=days), f"last {days} days"

    hour_match = re.search(r"(?:last|past)\s+(\d+)\s+hours?", query)
    if hour_match:
        hours = max(int(hour_match.group(1)), 1)
        return now - timedelta(hours=hours), f"last {hours} hours"

    if "today" in query or "last 24 hours" in query:
        return now - timedelta(days=1), "last 24 hours"
    if "this week" in query or "last week" in query:
        return now - timedelta(days=7), "last 7 days"
    if "recent" in query:
        return now - timedelta(days=30), "last 30 days"

    return None, None


def _split_tags(tags: str | None) -> list[str]:
    if not tags:
        return []
    return [tag.strip().lower() for tag in tags.split(",") if tag.strip()]


def _url_risk_features(value: str) -> list[tuple[int, str]]:
    parsed = urlparse(value)
    host = parsed.hostname or ""
    path = parsed.path.lower()
    features: list[tuple[int, str]] = []

    if not parsed.scheme:
        return features

    if host and _is_ip(host):
        features.append((14, "URL uses a raw IP host."))
    if len(value) > 120:
        features.append((8, "URL is unusually long."))
    if parsed.query:
        features.append((5, "URL contains query parameters."))
    if any(path.endswith(ext) for ext in (".exe", ".dll", ".scr", ".zip", ".js")):
        features.append((14, "URL path points to a risky file type."))
    if any(word in path for word in ("login", "verify", "invoice", "payment")):
        features.append((8, "URL path contains credential or payment wording."))

    return features


def _campaign_entity(value: str, indicator_type: str) -> str:
    if indicator_type == "url":
        host = urlparse(value).hostname or value
        return _registrable_host_or_ip(host)
    if indicator_type == "domain":
        return _registrable_host_or_ip(value)
    if indicator_type == "ip":
        return _ip_subnet(value)
    return value[:24]


def _registrable_host_or_ip(host: str) -> str:
    cleaned = host.strip().lower()
    if _is_ip(cleaned):
        return cleaned

    labels = [label for label in cleaned.split(".") if label]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return cleaned or "unknown"


def _ip_subnet(value: str) -> str:
    try:
        parsed = ip_address(value)
    except ValueError:
        return value

    if parsed.version == 4:
        parts = value.split(".")
        return ".".join(parts[:3]) + ".0/24"
    return str(parsed)


def _primary_tag(tags: list[str]) -> str | None:
    for preferred in ("ransomware", "stealer", "c2", "botnet", "malware", "phishing"):
        if preferred in tags:
            return preferred
    return tags[0] if tags else None


def _risk_level(score: int) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def _all_alias_words() -> set[str]:
    words: set[str] = set()
    for aliases in (TYPE_ALIASES, SOURCE_ALIASES, TAG_ALIASES, RISK_ALIASES, COUNTRY_ALIASES, STATUS_ALIASES):
        for values in aliases.values():
            words.update(values)
    return words


def _dedupe(items: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for item in items:
        if item not in seen:
            seen.add(item)
            result.append(item)
    return result


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
    except ValueError:
        return False
    return True
