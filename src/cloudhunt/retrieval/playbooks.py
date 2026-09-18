"""Versioned local playbook store and deterministic corpus-only retrieval."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable
import yaml

@dataclass(frozen=True)
class Playbook:
    playbook_id: str
    version: str
    title: str
    detection_types: tuple[str, ...]
    attack_ids: tuple[str, ...]
    action_names: tuple[str, ...]
    steps: tuple[str, ...]
    source_path: str

    @property
    def provenance(self) -> dict:
        return {"type": "playbook", "ref": self.playbook_id, "version": self.version}

    def as_context(self) -> dict:
        return {
            "playbook_id": self.playbook_id, "version": self.version, "title": self.title,
            "detection_types": list(self.detection_types), "attack_ids": list(self.attack_ids),
            "action_names": list(self.action_names), "steps": list(self.steps),
            "provenance": self.provenance,
        }

class PlaybookStore:
    def __init__(self, root: Path | None = None):
        self.root = root or Path(__file__).resolve().parents[1] / "playbooks"
        self._items = self._load()

    def _load(self) -> list[Playbook]:
        items: list[Playbook] = []
        for p in sorted(self.root.glob("*.yml")) + sorted(self.root.glob("*.yaml")):
            doc = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            items.append(Playbook(
                playbook_id=str(doc["id"]), version=str(doc["version"]), title=str(doc["title"]),
                detection_types=tuple(doc.get("detection_types", [])),
                attack_ids=tuple(doc.get("attack_ids", [])),
                action_names=tuple(doc.get("action_names", [])),
                steps=tuple(doc.get("steps", [])), source_path=str(p),
            ))
        return items

    def all(self) -> list[Playbook]:
        return list(self._items)

    def retrieve(self, *, detection_types: Iterable[str] = (), attack_ids: Iterable[str] = (), action_names: Iterable[str] = ()) -> list[Playbook]:
        d, a, n = set(detection_types), set(attack_ids), set(action_names)
        scored = []
        for pb in self._items:
            score = len(d & set(pb.detection_types)) * 3 + len(a & set(pb.attack_ids)) * 2 + len(n & set(pb.action_names))
            if score:
                scored.append((score, pb.playbook_id, pb))
        return [pb for _, _, pb in sorted(scored, key=lambda x: (-x[0], x[1]))]
