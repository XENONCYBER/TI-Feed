import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app, get_db
from app.database import Base, init_db
from app.models import Indicator

# Setup a test SQLite database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_cyshield.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def override_get_db():
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()

app.dependency_overrides[get_db] = override_get_db

@pytest.fixture(autouse=True)
def setup_database():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    # Add dummy indicator
    indicator = Indicator(
        value="185.220.101.5",
        type="ip",
        source="feodo",
        tags="botnet,c2",
        status="active",
        notes="Known Tor exit node active botnet",
        country="de",
        asn="AS206349"
    )
    db.add(indicator)
    db.commit()
    yield
    Base.metadata.drop_all(bind=engine)

def test_natural_language_search_api():
    client = TestClient(app)
    response = client.get("/api/nl-search?q=active+german+botnet+IPs")
    assert response.status_code == 200
    data = response.json()
    assert "intent" in data
    assert "results" in data
    assert len(data["results"]) > 0
    first = data["results"][0]
    assert first["value"] == "185.220.101.5"
    assert first["status"] == "active"
    assert first["country"] == "de"
    assert first["asn"] == "AS206349"

    # Test case insensitivity (matching uppercase 'DE' in db if we insert it)
    db = TestingSessionLocal()
    indicator_cn = Indicator(
        value="222.186.190.15",
        type="ip",
        source="feodo",
        tags="botnet,c2",
        status="active",
        notes="Active Chinese Botnet",
        country="CN", # Uppercase
        asn="AS4134 Chinanet"
    )
    db.add(indicator_cn)
    db.commit()

    response_cn = client.get("/api/nl-search?q=china")
    assert response_cn.status_code == 200
    data_cn = response_cn.json()
    assert len(data_cn["results"]) > 0
    assert data_cn["results"][0]["value"] == "222.186.190.15"


def test_feeds_sync_endpoints():
    client = TestClient(app)
    # Check status endpoint
    response = client.get("/api/feeds/status")
    assert response.status_code == 200
    data = response.json()
    assert "sync_in_progress" in data
    assert "sources" in data

    # Trigger sync endpoint
    response_sync = client.post("/api/feeds/sync")
    assert response_sync.status_code == 200
    data_sync = response_sync.json()
    assert data_sync["status"] in ("started", "already_running")
