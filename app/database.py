from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker, declarative_base

DATABASE_URL = "sqlite:///./cyshield.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    
    # Auto-migration for new indicator fields
    inspector = inspect(engine)
    if "indicators" in inspector.get_table_names():
        existing_cols = {col["name"] for col in inspector.get_columns("indicators")}
        with engine.begin() as conn:
            if "status" not in existing_cols:
                conn.execute(text("ALTER TABLE indicators ADD COLUMN status VARCHAR NOT NULL DEFAULT 'active'"))
            if "notes" not in existing_cols:
                conn.execute(text("ALTER TABLE indicators ADD COLUMN notes TEXT NOT NULL DEFAULT ''"))
            if "country" not in existing_cols:
                conn.execute(text("ALTER TABLE indicators ADD COLUMN country VARCHAR"))
            if "asn" not in existing_cols:
                conn.execute(text("ALTER TABLE indicators ADD COLUMN asn VARCHAR"))

