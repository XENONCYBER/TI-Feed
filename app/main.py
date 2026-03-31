from fastapi import FastAPI, Depends, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func

from app.database import get_db, init_db
from app.models import Indicator, Source
from app.schemas import IndicatorResponse, StatsResponse

app = FastAPI(title="CyShield", description="Threat Intelligence Platform")

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def startup():
    init_db()


@app.get("/")
def dashboard():
    return FileResponse("static/index.html")


@app.get("/api/search", response_model=list[IndicatorResponse])
def search(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """Search for indicators by value."""
    results = (
        db.query(Indicator)
        .filter(Indicator.value.contains(q))
        .order_by(Indicator.last_seen.desc())
        .limit(limit)
        .all()
    )
    return results


@app.get("/api/indicators", response_model=list[IndicatorResponse])
def list_indicators(
    type: str | None = None,
    source: str | None = None,
    limit: int = Query(50, le=200),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    """List indicators with optional filters."""
    query = db.query(Indicator)

    if type:
        query = query.filter(Indicator.type == type)
    if source:
        query = query.filter(Indicator.source == source)

    results = (
        query.order_by(Indicator.last_seen.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return results


@app.get("/api/stats", response_model=StatsResponse)
def get_stats(db: Session = Depends(get_db)):
    """Get statistics."""
    total = db.query(func.count(Indicator.id)).scalar() or 0
    sources_count = db.query(func.count(Source.id)).scalar() or 0

    # Count by type
    by_type_rows = (
        db.query(Indicator.type, func.count(Indicator.id))
        .group_by(Indicator.type)
        .all()
    )
    by_type = {row[0]: row[1] for row in by_type_rows}

    # Count by source
    by_source_rows = (
        db.query(Indicator.source, func.count(Indicator.id))
        .group_by(Indicator.source)
        .all()
    )
    by_source = {row[0]: row[1] for row in by_source_rows}

    return StatsResponse(
        total_indicators=total,
        total_sources=sources_count,
        by_type=by_type,
        by_source=by_source,
    )


@app.get("/api/sources")
def list_sources(db: Session = Depends(get_db)):
    """List feed sources."""
    return db.query(Source).all()
