"""Feodo Tracker feed - botnet C2 IPs."""
import csv
import io
import httpx
from app.feeds.base import BaseFeed, RawIndicator


class FeodoFeed(BaseFeed):
    name = "feodo"
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

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
                if len(row) < 4:
                    continue

                ip = row[1].strip().strip('"') if len(row) > 1 else ""
                malware = row[4].strip().strip('"') if len(row) > 4 else ""

                if not ip:
                    continue

                tags = ["botnet", "c2"]
                if malware:
                    tags.append(malware.lower())

                indicators.append(RawIndicator(
                    value=ip,
                    type="ip",
                    tags=tags,
                ))

        return indicators
