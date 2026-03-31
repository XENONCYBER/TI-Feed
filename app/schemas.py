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

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_indicators: int
    total_sources: int
    by_type: dict[str, int]
    by_source: dict[str, int]
