# CyShield

A lightweight threat intelligence feed aggregator with local NLP search and explainable risk scoring.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Ingest threat feeds
python -m app.cli ingest

# Optional: seed local demo data if live feeds are unavailable
python -m app.cli seed-demo

# Start the server
uvicorn app.main:app --reload
```

Open http://localhost:8000 to view the dashboard.

## Features

- **Feed Ingestion**: URLHaus, PhishTank, Feodo Tracker
- **NLP Search**: Search with prompts like "high risk botnet IPs from Feodo"
- **Explainable Risk**: Score indicators with visible evidence
- **Workbench Intelligence**: Derived risk buckets, campaign graph, source matrix, and response actions
- **Campaign Clustering**: Group related indicators by host, subnet, and threat tag
- **Dashboard**: Interactive analyst workbench with filters, drilldowns, and IOC intake
- **API**: REST endpoints for integration

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/search?q=` | Search indicators |
| `GET /api/nl-search?q=` | Natural-language search with risk analysis |
| `GET /api/workbench` | Workbench summary, campaigns, matrix, timeline, and top indicators |
| `GET /api/analyze?q=` | Analyze and correlate a pasted indicator |
| `GET /api/indicators` | List all indicators |
| `GET /api/stats` | Get statistics |
| `GET /api/insights` | Risk and campaign summaries |
| `GET /api/sources` | List feed sources |

## Project Structure

```text
cyshield/
app/
  main.py          # FastAPI app and routes
  analysis.py      # NLP intent parsing and explainable risk scoring
  intelligence.py  # Workbench rollups and IOC analysis
  models.py        # Database models
  schemas.py       # API response schemas
  database.py      # SQLite setup
  cli.py           # Ingestion and demo seed commands
  feeds/           # Feed connectors
static/
  index.html       # Analyst workbench dashboard
cyshield.db        # SQLite database, auto-created
```
