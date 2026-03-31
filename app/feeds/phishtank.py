"""PhishTank feed - phishing URLs."""
import gzip
import json
import httpx
from app.feeds.base import BaseFeed, RawIndicator


class PhishTankFeed(BaseFeed):
    name = "phishtank"
    url = "http://data.phishtank.com/data/online-valid.json.gz"

    async def fetch(self, limit: int = 5000) -> list[RawIndicator]:
        indicators = []

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.get(self.url)
            response.raise_for_status()

            try:
                content = gzip.decompress(response.content)
                data = json.loads(content.decode("utf-8"))
            except gzip.BadGzipFile:
                data = response.json()

            entries = data[:limit] if isinstance(data, list) else []

            for entry in entries:
                url = entry.get("url", "").strip()
                if not url:
                    continue

                tags = ["phishing"]
                target = entry.get("target")
                if target:
                    tags.append(target)

                indicators.append(RawIndicator(
                    value=url,
                    type="url",
                    tags=tags,
                ))

        return indicators
