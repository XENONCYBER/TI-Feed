from datetime import datetime

from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from sqlalchemy import func, or_

from app.analysis import (
    analyze_indicator,
    explain_intent_match,
    parse_search_intent,
    risk_level_matches,
    semantic_score,
)
from app.database import get_db, init_db
from app.intelligence import analyze_value, build_workbench, get_offline_geo, enrich_ip_live
from app.models import Indicator, Source
from app.schemas import (
    AnalyzedIndicatorResponse,
    IndicatorResponse,
    NaturalLanguageSearchResponse,
    StatsResponse,
    IndicatorCreateRequest,
    IndicatorTriageRequest,
)


app = FastAPI(title="CyShield", description="Threat Intelligence Platform")

# Serve static files
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.on_event("startup")
def startup():
    init_db()
    # Check if empty, and if so seed demo data
    db = SessionLocal()
    try:
        if db.query(Indicator).count() == 0:
            from app.cli import seed_demo
            seed_demo()
    except Exception as e:
        print(f"Startup seeding error: {e}")
    finally:
        db.close()
    
    # Start the background sync worker
    schedule_periodic_sync()


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


@app.get("/api/nl-search", response_model=NaturalLanguageSearchResponse)
def natural_language_search(
    q: str = Query(..., min_length=1),
    limit: int = Query(50, le=200),
    db: Session = Depends(get_db),
):
    """Search indicators with local natural-language intent parsing."""
    intent = parse_search_intent(q)
    query = db.query(Indicator)

    if intent.types:
        query = query.filter(Indicator.type.in_(intent.types))
    if intent.sources:
        query = query.filter(Indicator.source.in_(intent.sources))
    if intent.tags:
        query = query.filter(
            or_(*[Indicator.tags.contains(tag) for tag in intent.tags])
        )
    if intent.countries:
        countries_expanded = []
        for c in intent.countries:
            countries_expanded.extend([c.lower(), c.upper()])
        query = query.filter(Indicator.country.in_(countries_expanded))
    if intent.statuses:
        statuses_expanded = []
        for s in intent.statuses:
            statuses_expanded.extend([s.lower(), s.upper(), s.capitalize()])
        query = query.filter(Indicator.status.in_(statuses_expanded))
    if intent.text_terms:
        query = query.filter(
            or_(
                *[
                    or_(
                        Indicator.value.contains(term),
                        Indicator.tags.contains(term),
                    )
                    for term in intent.text_terms
                ]
            )
        )
    if intent.since:
        query = query.filter(Indicator.last_seen >= intent.since)

    candidate_limit = min(max(limit * 4, 200), 1000)
    candidates = (
        query.order_by(Indicator.last_seen.desc())
        .limit(candidate_limit)
        .all()
    )

    analyzed_rows = []
    for indicator in candidates:
        analysis = analyze_indicator(indicator)
        if not risk_level_matches(analysis.risk_level, intent.risk_levels):
            continue
        analyzed_rows.append((indicator, analysis, semantic_score(indicator, intent)))

    campaign_counts: dict[str, int] = {}
    for _, analysis, _ in analyzed_rows:
        campaign_counts[analysis.campaign_key] = (
            campaign_counts.get(analysis.campaign_key, 0) + 1
        )

    analyzed_rows.sort(
        key=lambda row: (
            row[2],
            row[1].risk_score,
            row[0].last_seen or row[0].first_seen or datetime.min,
        ),
        reverse=True,
    )

    results = [
        _analyzed_response(indicator, analysis, score, campaign_counts, intent)
        for indicator, analysis, score in analyzed_rows[:limit]
    ]
    return NaturalLanguageSearchResponse(intent=intent.as_dict(), results=results)


@app.get("/api/indicators", response_model=list[IndicatorResponse])
def list_indicators(
    type: str | None = None,
    source: str | None = None,
    status: str | None = None,
    country: str | None = None,
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
    if status:
        query = query.filter(Indicator.status == status)
    if country:
        query = query.filter(Indicator.country == country)

    results = (
        query.order_by(Indicator.last_seen.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return results


@app.post("/api/indicators", response_model=IndicatorResponse)
def create_indicator(payload: IndicatorCreateRequest, db: Session = Depends(get_db)):
    """Create a new custom indicator."""
    existing = db.query(Indicator).filter(
        Indicator.value == payload.value,
        Indicator.type == payload.type
    ).first()
    if existing:
        raise HTTPException(status_code=400, detail="Indicator already exists")
    
    country, asn = None, None
    if payload.type == "ip":
        country, asn = get_offline_geo(payload.value)
        
    indicator = Indicator(
        value=payload.value,
        type=payload.type,
        source=payload.source,
        tags=payload.tags,
        status=payload.status,
        notes=payload.notes,
        country=country,
        asn=asn,
        first_seen=datetime.utcnow(),
        last_seen=datetime.utcnow()
    )
    db.add(indicator)
    db.commit()
    db.refresh(indicator)
    return indicator


@app.patch("/api/indicators/{indicator_id}", response_model=IndicatorResponse)
def triage_indicator(indicator_id: int, payload: IndicatorTriageRequest, db: Session = Depends(get_db)):
    """Update triage details of an indicator."""
    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
        
    if payload.status is not None:
        indicator.status = payload.status
    if payload.notes is not None:
        indicator.notes = payload.notes
    if payload.tags is not None:
        indicator.tags = payload.tags
    if payload.source is not None:
        indicator.source = payload.source
        
    db.commit()
    db.refresh(indicator)
    return indicator


@app.delete("/api/indicators/{indicator_id}")
def delete_indicator(indicator_id: int, db: Session = Depends(get_db)):
    """Delete an indicator."""
    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
        
    db.delete(indicator)
    db.commit()
    return {"status": "success", "message": f"Indicator {indicator_id} deleted"}


@app.post("/api/indicators/{indicator_id}/enrich", response_model=IndicatorResponse)
def force_enrich_indicator(indicator_id: int, db: Session = Depends(get_db)):
    """Force run dynamic IP country/ASN lookup."""
    indicator = db.query(Indicator).filter(Indicator.id == indicator_id).first()
    if not indicator:
        raise HTTPException(status_code=404, detail="Indicator not found")
        
    if indicator.type == "ip":
        country, asn = enrich_ip_live(indicator.value)
        if country:
            indicator.country = country
        if asn:
            indicator.asn = asn
        db.commit()
        db.refresh(indicator)
        
    return indicator


@app.get("/api/workbench")
def get_workbench(
    limit: int = Query(300, le=1000),
    db: Session = Depends(get_db),
):
    """Return derived intelligence for the interactive workbench."""
    indicators = (
        db.query(Indicator)
        .order_by(Indicator.last_seen.desc())
        .limit(limit)
        .all()
    )
    sources = db.query(Source).all()
    return build_workbench(indicators, sources)


@app.get("/api/analyze")
def analyze_ioc(
    q: str = Query(..., min_length=1),
    db: Session = Depends(get_db),
):
    """Analyze a pasted indicator and correlate it with stored feed data."""
    value = q.strip()
    if not value:
        raise HTTPException(status_code=400, detail="q cannot be blank")

    matches = (
        db.query(Indicator)
        .filter(Indicator.value.contains(value))
        .order_by(Indicator.last_seen.desc())
        .limit(10)
        .all()
    )
    return analyze_value(value, matches)


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


@app.get("/api/insights")
def get_insights(db: Session = Depends(get_db), limit: int = Query(5, le=20)):
    """Return explainable risk and campaign summaries for the dashboard."""
    indicators = (
        db.query(Indicator)
        .order_by(Indicator.last_seen.desc())
        .limit(1000)
        .all()
    )
    risk_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    campaign_counts: dict[str, int] = {}

    for indicator in indicators:
        analysis = analyze_indicator(indicator)
        risk_counts[analysis.risk_level] += 1
        campaign_counts[analysis.campaign_key] = (
            campaign_counts.get(analysis.campaign_key, 0) + 1
        )

    top_campaigns = sorted(
        campaign_counts.items(),
        key=lambda item: item[1],
        reverse=True,
    )[:limit]

    return {
        "risk_counts": risk_counts,
        "top_campaigns": [
            {"campaign_key": key, "count": count}
            for key, count in top_campaigns
        ],
    }


def _analyzed_response(
    indicator: Indicator,
    analysis,
    score: int,
    campaign_counts: dict[str, int],
    intent,
) -> AnalyzedIndicatorResponse:
    return AnalyzedIndicatorResponse(
        id=indicator.id,
        value=indicator.value,
        type=indicator.type,
        source=indicator.source,
        tags=indicator.tags,
        first_seen=indicator.first_seen,
        last_seen=indicator.last_seen,
        status=indicator.status or "active",
        notes=indicator.notes or "",
        country=indicator.country,
        asn=indicator.asn,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        risk_reasons=analysis.risk_reasons,
        matched_intent=explain_intent_match(indicator, intent),
        campaign_key=analysis.campaign_key,
        campaign_size=campaign_counts.get(analysis.campaign_key, 1),
        semantic_score=score,
    )


# Feeds background sync implementation
from fastapi import BackgroundTasks
import threading
import time
from app.database import SessionLocal

sync_lock = threading.Lock()
sync_status = {
    "in_progress": False,
    "last_sync": None,
    "result": None
}

def run_sync_in_background():
    global sync_status
    if not sync_lock.acquire(blocking=False):
        return
    sync_status["in_progress"] = True
    try:
        from app.cli import ingest_all
        import asyncio
        asyncio.run(ingest_all())
        sync_status["result"] = "Success"
    except Exception as e:
        sync_status["result"] = f"Error: {str(e)}"
    finally:
        sync_status["in_progress"] = False
        sync_status["last_sync"] = datetime.utcnow().isoformat()
        sync_lock.release()

def schedule_periodic_sync():
    """Run feed sync every 30 minutes in the background."""
    def loop():
        while True:
            # Sleep 30 minutes first, feeds already ingested or seeded on start
            time.sleep(1800)
            try:
                run_sync_in_background()
            except Exception as e:
                print(f"Periodic sync error: {e}")
            
    thread = threading.Thread(target=loop, daemon=True)
    thread.start()


@app.post("/api/feeds/sync")
def trigger_feed_sync(background_tasks: BackgroundTasks):
    """Trigger feed synchronization in the background."""
    if sync_status["in_progress"]:
        return {"status": "already_running", "message": "Feed synchronization is already in progress"}
    
    background_tasks.add_task(run_sync_in_background)
    return {"status": "started", "message": "Feed synchronization started in the background"}


@app.get("/api/feeds/status")
def get_sync_status(db: Session = Depends(get_db)):
    """Get current feed status and sync metadata."""
    sources = db.query(Source).all()
    source_details = []
    for s in sources:
        source_details.append({
            "name": s.name,
            "url": s.url,
            "last_fetch": s.last_fetch.isoformat() if s.last_fetch else None
        })
    return {
        "sync_in_progress": sync_status["in_progress"],
        "last_sync": sync_status["last_sync"],
        "result": sync_status["result"],
        "sources": source_details
    }

