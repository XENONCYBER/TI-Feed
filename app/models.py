from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text
from app.database import Base


class Indicator(Base):
    __tablename__ = "indicators"

    id = Column(Integer, primary_key=True, index=True)
    value = Column(String, nullable=False, index=True)
    type = Column(String, nullable=False)  # ip, url, domain, hash
    source = Column(String, nullable=False)
    tags = Column(Text, nullable=True)  # comma-separated
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)

    class Config:
        orm_mode = True


class Source(Base):
    __tablename__ = "sources"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, nullable=False)
    url = Column(String, nullable=True)
    last_fetch = Column(DateTime, nullable=True)
