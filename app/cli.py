"""CLI for feed ingestion."""
"""CLI for feed ingestion."""
import asyncio
import sys
from datetime import datetime

from app.database import SessionLocal, init_db
from app.models import Indicator, Source
from app.feeds.urlhaus import URLHausFeed
from app.feeds.phishtank import PhishTankFeed
from app.feeds.feodo import FeodoFeed
from app.feeds.sslbl import SSLBLFeed


FEEDS = [
    URLHausFeed(),
    PhishTankFeed(),
    FeodoFeed(),
    SSLBLFeed(),
]

DEMO_INDICATORS = [
    {
        "value": "http://185.199.108.153/update/login/verify.exe",
        "type": "url",
        "source": "urlhaus",
        "tags": "malware,payload,stealer",
    },
    {
        "value": "http://secure-billing-check.example.com/payment/login",
        "type": "url",
        "source": "phishtank",
        "tags": "phishing,banking,login",
    },
    {
        "value": "45.142.122.90",
        "type": "ip",
        "source": "feodo",
        "tags": "botnet,c2,emotet",
        "country": "BR",
        "asn": "AS265555",
    },
    {
        "value": "45.142.122.91",
        "type": "ip",
        "source": "feodo",
        "tags": "botnet,c2,emotet",
        "country": "GB",
        "asn": "AS28555",
    },
    {
        "value": "222.186.190.15",
        "type": "ip",
        "source": "feodo",
        "tags": "botnet,c2",
        "country": "CN",
        "asn": "AS4134 Chinanet",
    },
    {
        "value": "95.213.255.1",
        "type": "ip",
        "source": "feodo",
        "tags": "botnet,c2",
        "country": "RU",
        "asn": "AS49505 Selectel",
    },
    {
        "value": "185.220.101.5",
        "type": "ip",
        "source": "sslbl",
        "tags": "botnet,c2,ssl",
        "country": "DE",
        "asn": "AS206349",
    },
    {
        "value": "signin-wallet-alert.example.net",
        "type": "domain",
        "source": "phishtank",
        "tags": "phishing,credential",
    },
    {
        "value": "http://cdn-files.example.org/invoice/update.zip",
        "type": "url",
        "source": "urlhaus",
        "tags": "malware,payload",
    },
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
                if raw.type == "ip" and (not existing.country or not existing.asn):
                    from app.intelligence import get_offline_geo
                    c, a = get_offline_geo(raw.value)
                    existing.country = c
                    existing.asn = a
                updated += 1
            else:
                country, asn = None, None
                if raw.type == "ip":
                    from app.intelligence import get_offline_geo
                    country, asn = get_offline_geo(raw.value)
                indicator = Indicator(
                    value=raw.value,
                    type=raw.type,
                    source=feed.name,
                    tags=",".join(raw.tags) if raw.tags else None,
                    country=country,
                    asn=asn,
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


def seed_demo():
    """Seed local indicators for demos without live feed access."""
    init_db()
    db = SessionLocal()
    now = datetime.utcnow()

    for sample in DEMO_INDICATORS:
        source = db.query(Source).filter(Source.name == sample["source"]).first()
        if not source:
            source = Source(name=sample["source"])
            db.add(source)
        source.last_fetch = now

        existing = db.query(Indicator).filter(
            Indicator.value == sample["value"],
            Indicator.type == sample["type"],
        ).first()
        if existing:
            existing.tags = sample["tags"]
            existing.source = sample["source"]
            existing.last_seen = now
            if "country" in sample:
                existing.country = sample["country"]
            if "asn" in sample:
                existing.asn = sample["asn"]
            elif sample["type"] == "ip" and (not existing.country or not existing.asn):
                from app.intelligence import get_offline_geo
                c, a = get_offline_geo(sample["value"])
                existing.country = c
                existing.asn = a
        else:
            country = sample.get("country")
            asn = sample.get("asn")
            if sample["type"] == "ip" and (not country or not asn):
                from app.intelligence import get_offline_geo
                c, a = get_offline_geo(sample["value"])
                country = country or c
                asn = asn or a
            clean_sample = {k: v for k, v in sample.items() if k not in ("country", "asn")}
            db.add(Indicator(**clean_sample, first_seen=now, last_seen=now, country=country, asn=asn))

    db.commit()
    db.close()
    print(f"Seeded {len(DEMO_INDICATORS)} demo indicators")


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m app.cli <command>")
        print("Commands:")
        print("  ingest  - Fetch all feeds and store indicators")
        print("  seed-demo  - Add local demo indicators")
        sys.exit(1)

    command = sys.argv[1]

    if command == "ingest":
        asyncio.run(ingest_all())
    elif command == "seed-demo":
        seed_demo()
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()
