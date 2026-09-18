"""Mobile approval primitives: device registry, push dispatch and one-time tokens.

M11 deliberately does not decide whether an action needs a human. It accepts only
pending actions already classified by the Milestone 6 response engine.
"""
from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Protocol


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Device:
    device_id: str
    owner: str
    push_token: str
    platform: str
    revoked: bool = False
    registered_at: str = field(default_factory=lambda: _now().isoformat())


class DeviceRegistry:
    def __init__(self) -> None:
        self._devices: dict[str, Device] = {}

    def register(self, owner: str, push_token: str, platform: str) -> Device:
        device = Device(secrets.token_hex(12), owner, push_token, platform)
        self._devices[device.device_id] = device
        return device

    def revoke(self, device_id: str, owner: str) -> bool:
        d = self._devices.get(device_id)
        if not d or d.owner != owner:
            return False
        d.revoked = True
        return True

    def active_for(self, owner: str | None = None) -> list[Device]:
        return [d for d in self._devices.values() if not d.revoked and (owner is None or d.owner == owner)]


class PushGateway(Protocol):
    def send(self, device: Device, payload: dict) -> None: ...


class InMemoryPushGateway:
    """Test/dev gateway. Payloads intentionally carry only a case reference."""
    def __init__(self) -> None:
        self.sent: list[tuple[str, dict]] = []

    def send(self, device: Device, payload: dict) -> None:
        self.sent.append((device.device_id, dict(payload)))


class PushService:
    def __init__(self, registry: DeviceRegistry | None = None, gateway: PushGateway | None = None):
        self.registry = registry or DeviceRegistry()
        self.gateway = gateway or InMemoryPushGateway()

    def notify_human_required(self, case_id: str) -> None:
        payload = {"type": "approval_required", "case_id": case_id}
        for device in self.registry.active_for():
            self.gateway.send(device, payload)


@dataclass
class ApprovalTokenRecord:
    digest: str
    case_id: str
    action_id: str
    action_key: str
    expires_at: datetime
    used: bool = False


class ApprovalTokenError(ValueError):
    pass


class ApprovalTokenStore:
    def __init__(self, ttl_seconds: int = 300) -> None:
        self.ttl_seconds = ttl_seconds
        self._records: dict[str, ApprovalTokenRecord] = {}

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def issue(self, case_id: str, action_id: str, action_key: str) -> tuple[str, ApprovalTokenRecord]:
        token = secrets.token_urlsafe(32)
        rec = ApprovalTokenRecord(
            digest=self._digest(token), case_id=case_id, action_id=action_id,
            action_key=action_key, expires_at=_now() + timedelta(seconds=self.ttl_seconds),
        )
        self._records[rec.digest] = rec
        return token, rec

    def consume(self, token: str, case_id: str, action_id: str, action_key: str) -> ApprovalTokenRecord:
        rec = self._records.get(self._digest(token))
        if rec is None:
            raise ApprovalTokenError("invalid approval token")
        if rec.used:
            raise ApprovalTokenError("approval token already used")
        if _now() >= rec.expires_at:
            raise ApprovalTokenError("approval token expired")
        if (rec.case_id, rec.action_id, rec.action_key) != (case_id, action_id, action_key):
            raise ApprovalTokenError("approval token scope mismatch")
        rec.used = True
        return rec

class RedisApprovalTokenStore:
    """Redis-backed one-time token store for multi-process production deployments.

    Tokens are stored under their SHA-256 digest with Redis TTL. ``GETDEL`` makes
    consumption atomic, so a token cannot be replayed across API workers.
    """
    def __init__(self, redis_url: str, ttl_seconds: int = 300) -> None:
        import json
        import redis
        self._json = json
        self.redis = redis.Redis.from_url(redis_url, decode_responses=True)
        self.ttl_seconds = ttl_seconds

    def issue(self, case_id: str, action_id: str, action_key: str) -> tuple[str, ApprovalTokenRecord]:
        token = secrets.token_urlsafe(32)
        digest = self._digest(token)
        rec = ApprovalTokenRecord(
            digest=digest, case_id=case_id, action_id=action_id, action_key=action_key,
            expires_at=_now() + timedelta(seconds=self.ttl_seconds),
        )
        payload = self._json.dumps({
            "digest": rec.digest, "case_id": rec.case_id, "action_id": rec.action_id,
            "action_key": rec.action_key, "expires_at": rec.expires_at.isoformat(),
        })
        self.redis.setex(f"cloudhunt:approval:{digest}", self.ttl_seconds, payload)
        return token, rec

    @staticmethod
    def _digest(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def consume(self, token: str, case_id: str, action_id: str, action_key: str) -> ApprovalTokenRecord:
        digest = self._digest(token)
        key = f"cloudhunt:approval:{digest}"
        raw = self.redis.getdel(key)
        if raw is None:
            raise ApprovalTokenError("invalid, expired, or already used approval token")
        data = self._json.loads(raw)
        rec = ApprovalTokenRecord(
            digest=data["digest"], case_id=data["case_id"], action_id=data["action_id"],
            action_key=data["action_key"], expires_at=datetime.fromisoformat(data["expires_at"]), used=True,
        )
        if (rec.case_id, rec.action_id, rec.action_key) != (case_id, action_id, action_key):
            raise ApprovalTokenError("approval token scope mismatch")
        if _now() >= rec.expires_at:
            raise ApprovalTokenError("approval token expired")
        return rec
