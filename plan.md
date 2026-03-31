# CyShield - Threat Intelligence Platform

A lightweight threat intelligence feed aggregator.

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Python 3.11+ / FastAPI |
| Database | SQLite (single file) |
| Frontend | HTML + TailwindCSS (CDN) + Vanilla JS |
| Feeds | URLHaus, PhishTank, Feodo Tracker |

No Docker. No Redis. No complex setup.

## Project Structure

```
cyshield/
├── app/
│   ├── main.py           # FastAPI app + routes
│   ├── models.py         # SQLAlchemy models
│   ├── database.py       # SQLite setup
│   ├── schemas.py        # Pydantic schemas
│   ├── feeds/
│   │   ├── base.py
│   │   ├── urlhaus.py
│   │   ├── phishtank.py
│   │   └── feodo.py
│   └── cli.py            # CLI for ingestion
├── static/
│   └── index.html        # Dashboard
├── cyshield.db           # SQLite (auto-created)
├── requirements.txt
└── README.md
```

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Dashboard |
| GET | `/api/search?q=` | Search indicators |
| GET | `/api/indicators` | List indicators |
| GET | `/api/stats` | Basic statistics |

## Database Schema

```sql
CREATE TABLE indicators (
    id INTEGER PRIMARY KEY,
    value TEXT NOT NULL,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    tags TEXT,
    first_seen DATETIME,
    last_seen DATETIME,
    UNIQUE(value, type)
);

CREATE TABLE sources (
    id INTEGER PRIMARY KEY,
    name TEXT UNIQUE NOT NULL,
    last_fetch DATETIME
);
```

## How to Run

```bash
# Install
pip install -r requirements.txt

# Ingest feeds
python -m app.cli ingest

# Start server
uvicorn app.main:app --reload

# Open http://localhost:8000
```

## Tasks

- [x] Create project structure
- [ ] Set up SQLite database and models
- [ ] Build feed connectors (URLHaus, PhishTank, Feodo)
- [ ] Create CLI for ingestion
- [ ] Build API endpoints
- [ ] Create dashboard HTML
