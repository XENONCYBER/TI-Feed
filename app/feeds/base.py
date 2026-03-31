"""Base class for feed connectors."""
from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RawIndicator:
    value: str
    type: str  # ip, url, domain, hash
    tags: list[str] | None = None


class BaseFeed(ABC):
    name: str = "base"
    url: str = ""

    @abstractmethod
    async def fetch(self) -> list[RawIndicator]:
        pass
