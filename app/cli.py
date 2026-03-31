"""CLI for feed ingestion."""
import asyncio
import sys
from datetime import datetime

from app.database import SessionLocal, init_db
from app.models import Indicator, Source
from app.feeds.urlhaus import URLHausFeed
from app.feeds.phishtank import PhishTankFeed
from app.feeds.feodo import FeodoFeed


FEEDS = [
    URLHausFeed(),
    PhishTankFeed(),
    FeodoFeed(),
]


async def ingest_feed(feed, db):
    """Ingest a single feed."""
    print(f"  Fetching {feed.name}...")

    try:
        raw_indicators = await feed.fetch()
        print(f"  Got {len(raw_indicators)} indicators")

        # Update source
        source = db.query(Source).filter(Source.name == feed.name).first()
        if not source:
            source = Source(name=feed.name, url=feed.url)
            db.add(source)
        source.last_fetch = datetime.utcnow()

        added = 0
        updated = 0

        for raw in raw_indicators:
            existing = db.query(Indicator).filter(
                Indicator.value == raw.value,
                Indicator.type == raw.type,
            ).first()

            if existing:
                existing.last_seen = datetime.utcnow()
                if raw.tags:
                    existing.tags = ",".join(raw.tags)
                updated += 1
            else:
                indicator = Indicator(
                    value=raw.value,
                    type=raw.type,
                    source=feed.name,
                    tags=",".join(raw.tags) if raw.tags else None,
                )
                db.add(indicator)
                added += 1

        db.commit()
        print(f"  Done: {added} added, {updated} updated")
        return added, updated

    except Exception as e:
        print(f"  Error: {e}")
        return 0, 0


async def ingest_all():
    """Ingest all feeds."""
    init_db()
    db = SessionLocal()

    print("Starting feed ingestion...\n")

    total_added = 0
    total_updated = 0

    for feed in FEEDS:
        added, updated = await ingest_feed(feed, db)
        total_added += added
        total_updated += updated
        print()

    db.close()
    print(f"Complete: {total_added} total added, {total_updated} total updated")


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m app.cli <command>")
        print("Commands:")
        print("  ingest  - Fetch all feeds and store indicators")
        sys.exit(1)

    command = sys.argv[1]

    if command == "ingest":
        asyncio.run(ingest_all())
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
