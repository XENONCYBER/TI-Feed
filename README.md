# CyShield

A lightweight threat intelligence feed aggregator.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Ingest threat feeds
python -m app.cli ingest

# Start the server
uvicorn app.main:app --reload
```

Open http://localhost:8000 to view the dashboard.

## Features

- **Feed Ingestion**: URLHaus, PhishTank, Feodo Tracker
- **Search**: Find indicators by IP, URL, or domain
- **Dashboard**: Simple web UI for searching
- **API**: REST endpoints for integration

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /api/search?q=` | Search indicators |
| `GET /api/indicators` | List all indicators |
| `GET /api/stats` | Get statistics |
| `GET /api/sources` | List feed sources |

## Project Structure

```
cyshield/
├── app/
│   ├── main.py        # FastAPI app
│   ├── models.py      # Database models
│   ├── database.py    # SQLite setup
│   ├── cli.py         # CLI commands
│   └── feeds/         # Feed connectors
├── static/
│   └── index.html     # Dashboard
└── cyshield.db        # SQLite database
```
