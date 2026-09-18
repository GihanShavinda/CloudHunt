"""The scoped executor — the *only* place that touches AWS.

Actions never call boto3 directly; they call the narrow, semantic methods on an
:class:`ActionExecutor`. That indirection does three things:

* **Scope.** The surface is a fixed, minimal set of containment operations — the
  cross-account role this runs under is least-privileged to exactly these calls.
* **Reversibility.** Every mutating method has a companion read (status/getters)
  so an action can capture before/after and build an ``undo_ref``.
* **Testability / LocalStack.** :class:`Boto3ActionExecutor` targets real AWS or
  LocalStack (endpoint override); :class:`FakeActionExecutor` implements the same
  surface over in-memory state for offline tests.

No ``shell=True`` anywhere, no credentials in code — boto3 resolves them from the
environment / instance role as usual.
"""

from __future__ import annotations

import uuid
from typing import Optional, Protocol


class ActionExecutor(Protocol):
    # --- IAM: access keys ---
    def list_access_keys(self, user_name: str) -> list[dict]: ...
    def update_access_key(self, user_name: str, key_id: str, status: str) -> None: ...
    # --- IAM: inline policies (quarantine / revoke sessions) ---
    def put_user_policy(self, user_name: str, name: str, document: dict) -> None: ...
    def delete_user_policy(self, user_name: str, name: str) -> None: ...
    def list_user_policies(self, user_name: str) -> list[str]: ...
    def put_role_policy(self, role_name: str, name: str, document: dict) -> None: ...
    def delete_role_policy(self, role_name: str, name: str) -> None: ...
    def list_role_policies(self, role_name: str) -> list[str]: ...
    # --- EC2 ---
    def instance_security_groups(self, instance_id: str) -> list[str]: ...
    def set_instance_security_groups(self, instance_id: str, groups: list[str]) -> None: ...
    def create_snapshot(self, volume_id: str, description: str) -> str: ...
    def delete_snapshot(self, snapshot_id: str) -> None: ...
    # --- CloudTrail ---
    def trail_is_logging(self, trail_name: str) -> bool: ...
    def start_logging(self, trail_name: str) -> None: ...
    def stop_logging(self, trail_name: str) -> None: ...


class Boto3ActionExecutor:
    """Real executor. Set ``endpoint_url`` to a LocalStack URL for cost-free dev."""

    def __init__(self, region: Optional[str] = None, endpoint_url: Optional[str] = None,
                 session=None):
        import boto3  # local import so the package imports without boto3 present
        session = session or boto3.session.Session()
        kw = {"region_name": region} if region else {}
        if endpoint_url:
            kw["endpoint_url"] = endpoint_url
        self._iam = session.client("iam", **kw)
        self._ec2 = session.client("ec2", **kw)
        self._ct = session.client("cloudtrail", **kw)

    def list_access_keys(self, user_name: str) -> list[dict]:
        md = self._iam.list_access_keys(UserName=user_name).get("AccessKeyMetadata", [])
        return [{"AccessKeyId": k["AccessKeyId"], "Status": k["Status"]} for k in md]

    def update_access_key(self, user_name: str, key_id: str, status: str) -> None:
        self._iam.update_access_key(UserName=user_name, AccessKeyId=key_id, Status=status)

    def put_user_policy(self, user_name, name, document):
        import json
        self._iam.put_user_policy(UserName=user_name, PolicyName=name,
                                  PolicyDocument=json.dumps(document))

    def delete_user_policy(self, user_name, name):
        self._iam.delete_user_policy(UserName=user_name, PolicyName=name)

    def list_user_policies(self, user_name):
        return self._iam.list_user_policies(UserName=user_name).get("PolicyNames", [])

    def put_role_policy(self, role_name, name, document):
        import json
        self._iam.put_role_policy(RoleName=role_name, PolicyName=name,
                                  PolicyDocument=json.dumps(document))

    def delete_role_policy(self, role_name, name):
        self._iam.delete_role_policy(RoleName=role_name, PolicyName=name)

    def list_role_policies(self, role_name):
        return self._iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])

    def instance_security_groups(self, instance_id):
        r = self._ec2.describe_instances(InstanceIds=[instance_id])
        inst = r["Reservations"][0]["Instances"][0]
        return [g["GroupId"] for g in inst.get("SecurityGroups", [])]

    def set_instance_security_groups(self, instance_id, groups):
        self._ec2.modify_instance_attribute(InstanceId=instance_id, Groups=groups)

    def create_snapshot(self, volume_id, description):
        return self._ec2.create_snapshot(VolumeId=volume_id,
                                          Description=description)["SnapshotId"]

    def delete_snapshot(self, snapshot_id):
        self._ec2.delete_snapshot(SnapshotId=snapshot_id)

    def trail_is_logging(self, trail_name):
        return bool(self._ct.get_trail_status(Name=trail_name).get("IsLogging"))

    def start_logging(self, trail_name):
        self._ct.start_logging(Name=trail_name)

    def stop_logging(self, trail_name):
        self._ct.stop_logging(Name=trail_name)


class FakeActionExecutor:
    """In-memory executor mirroring :class:`Boto3ActionExecutor` for offline tests."""

    def __init__(self):
        # user -> {"keys": {id: status}, "inline": {name: doc}}
        self.users: dict[str, dict] = {}
        self.roles: dict[str, dict] = {}          # role -> {"inline": {name: doc}}
        self.instances: dict[str, list[str]] = {}  # id -> [sg]
        self.trails: dict[str, bool] = {}          # name -> IsLogging
        self.snapshots: dict[str, str] = {}        # snap_id -> volume

    # seeding helpers
    def add_user(self, name, keys: dict): self.users[name] = {"keys": dict(keys), "inline": {}}
    def add_role(self, name): self.roles[name] = {"inline": {}}
    def add_instance(self, iid, sgs): self.instances[iid] = list(sgs)
    def add_trail(self, name, logging): self.trails[name] = logging

    def list_access_keys(self, user_name):
        keys = self.users.get(user_name, {}).get("keys", {})
        return [{"AccessKeyId": k, "Status": s} for k, s in keys.items()]

    def update_access_key(self, user_name, key_id, status):
        self.users[user_name]["keys"][key_id] = status

    def put_user_policy(self, user_name, name, document):
        self.users.setdefault(user_name, {"keys": {}, "inline": {}})["inline"][name] = document

    def delete_user_policy(self, user_name, name):
        self.users[user_name]["inline"].pop(name, None)

    def list_user_policies(self, user_name):
        return list(self.users.get(user_name, {}).get("inline", {}))

    def put_role_policy(self, role_name, name, document):
        self.roles.setdefault(role_name, {"inline": {}})["inline"][name] = document

    def delete_role_policy(self, role_name, name):
        self.roles[role_name]["inline"].pop(name, None)

    def list_role_policies(self, role_name):
        return list(self.roles.get(role_name, {}).get("inline", {}))

    def instance_security_groups(self, instance_id):
        return list(self.instances.get(instance_id, []))

    def set_instance_security_groups(self, instance_id, groups):
        self.instances[instance_id] = list(groups)

    def create_snapshot(self, volume_id, description):
        sid = "snap-" + uuid.uuid4().hex[:8]
        self.snapshots[sid] = volume_id
        return sid

    def delete_snapshot(self, snapshot_id):
        self.snapshots.pop(snapshot_id, None)

    def trail_is_logging(self, trail_name):
        return bool(self.trails.get(trail_name, False))

    def start_logging(self, trail_name):
        self.trails[trail_name] = True

    def stop_logging(self, trail_name):
        self.trails[trail_name] = False
