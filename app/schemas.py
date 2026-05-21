from datetime import datetime
from pydantic import BaseModel


class IndicatorResponse(BaseModel):
    id: int
    value: str
    type: str
    source: str
    tags: str | None
    first_seen: datetime | None
    last_seen: datetime | None
    status: str
    notes: str
    country: str | None
    asn: str | None

    class Config:
        from_attributes = True


class IndicatorCreateRequest(BaseModel):
    value: str
    type: str  # ip, url, domain, hash
    source: str = "custom"
    tags: str | None = None
    status: str = "active"
    notes: str = ""


class IndicatorTriageRequest(BaseModel):
    status: str | None = None
    notes: str | None = None
    tags: str | None = None
    source: str | None = None


class StatsResponse(BaseModel):
    total_indicators: int
    total_sources: int
    by_type: dict[str, int]
    by_source: dict[str, int]


class SearchIntentResponse(BaseModel):
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


class AnalyzedIndicatorResponse(IndicatorResponse):
    risk_score: int
    risk_level: str
    risk_reasons: list[str]
    matched_intent: list[str]
    campaign_key: str
    campaign_size: int
    semantic_score: int


class NaturalLanguageSearchResponse(BaseModel):
    intent: SearchIntentResponse
    results: list[AnalyzedIndicatorResponse]
