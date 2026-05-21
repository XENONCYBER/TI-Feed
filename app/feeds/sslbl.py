"""SSLBL feed - malicious TLS/SSL C2 IPs."""
import csv
import io
import httpx
from app.feeds.base import BaseFeed, RawIndicator


class SSLBLFeed(BaseFeed):
    name = "sslbl"
    url = "https://sslbl.abuse.ch/blacklist/sslipblacklist.csv"

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
                if len(row) < 3:
                    continue

                ip = row[0].strip().strip('"')
                malware = row[2].strip().strip('"')

                if not ip:
                    continue

                tags = ["c2", "malware", "sslbl"]
                if malware:
                    tags.append(malware.lower())

                indicators.append(RawIndicator(
                    value=ip,
                    type="ip",
                    tags=tags,
                ))

        return indicators
