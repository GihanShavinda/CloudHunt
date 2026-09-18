from __future__ import annotations
import json
from pathlib import Path
from cloudhunt.ingest.base import RawRecord
from cloudhunt.models.events import Source
from cloudhunt.normalise.enrich import Enricher, StaticGeoAsnResolver
from cloudhunt.normalise.pipeline import normalise

class FixtureReplay:
    def __init__(self, repo_root: Path):
        self.repo_root = Path(repo_root)
        geo = self.repo_root / 'sample_data' / 'enrichment' / 'geoip.json'
        self.enricher = Enricher(geo_resolver=StaticGeoAsnResolver.from_file(geo))

    def load(self, path: str | Path) -> list[dict]:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        return data.get('Records', data) if isinstance(data, dict) else data

    def replay(self, path: str | Path):
        records = self.load(path)
        events = []
        seen = set()
        for idx, rec in enumerate(records):
            raw = RawRecord(record=rec, raw_ref=f'{Path(path).name}:{idx}', source=Source.cloudtrail)
            event = self.enricher.enrich(normalise(raw))
            if event.dedup_key() not in seen:
                seen.add(event.dedup_key())
                events.append(event)
        return sorted(events, key=lambda e: e.ts)
