"""URLHaus feed - malicious URLs."""
import csv
import io
import httpx
from app.feeds.base import BaseFeed, RawIndicator


class URLHausFeed(BaseFeed):
    name = "urlhaus"
    url = "https://urlhaus.abuse.ch/downloads/csv_recent/"

    async def fetch(self) -> list[RawIndicator]:
        indicators = []

        async with httpx.AsyncClient(timeout=60.0) as client:
            response = await client.get(self.url)
            response.raise_for_status()

            lines = [
                line for line in response.text.split("\n")
                if line and not line.startswith("#")
            ]

            reader = csv.reader(io.StringIO("\n".join(lines)))

            for row in reader:
                if len(row) < 7:
                    continue

                url = row[2].strip().strip('"')
                threat = row[5].strip().strip('"')
                tags_str = row[6].strip().strip('"')

                if not url:
                    continue

                tags = [t.strip() for t in tags_str.split(",") if t.strip()]
                if threat:
                    tags.insert(0, threat)

                indicators.append(RawIndicator(
                    value=url,
                    type="url",
                    tags=tags[:5] if tags else None,
                ))

        return indicators
