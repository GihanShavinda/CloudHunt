"""The privilege-escalation technique catalogue.

Each technique is a way a principal can turn the permissions it *has* into
permissions it *wants* (usually admin). The detector (``detector.py``) encodes a
firing of one of these as a ``CAN_ESCALATE_VIA`` edge; the path search
(``pathfind.py``) chains those edges into a route to admin or to sensitive data.

The catalogue is deliberately the well-known AWS IAM privesc set (the "Rhino
Security Labs 21" lineage). Each entry carries an ATT&CK mapping so Milestone 4
can label a detected escalation without re-deriving it.

Targets:
  ADMIN   the technique yields arbitrary/admin-equivalent permissions in-account
  ROLE    the technique yields the privileges of a specific role (then continue)
"""

from __future__ import annotations

from dataclasses import dataclass

ADMIN = "admin"
ROLE = "role"


@dataclass(frozen=True)
class Technique:
    key: str                 # stable id used on the edge
    label: str               # human name
    target: str              # ADMIN | ROLE
    attack_id: str           # MITRE ATT&CK technique id
    attack_name: str
    description: str


# NOTE: keys are matched by the detector; don't rename without updating it.
CREATE_POLICY_VERSION = Technique(
    "CreatePolicyVersion", "Set a new default version of an attached policy", ADMIN,
    "T1098.003", "Account Manipulation: Additional Cloud Roles",
    "Principal is attached to a customer-managed policy it can call "
    "iam:CreatePolicyVersion on (with --set-as-default), rewriting its own "
    "permissions to admin.",
)
ATTACH_USER_POLICY = Technique(
    "AttachUserPolicy", "Attach AdministratorAccess to self (user)", ADMIN,
    "T1098.003", "Account Manipulation: Additional Cloud Roles",
    "Principal can call iam:AttachUserPolicy on itself and attach a managed "
    "admin policy.",
)
PUT_USER_POLICY = Technique(
    "PutUserPolicy", "Inline an admin policy on self (user)", ADMIN,
    "T1098.003", "Account Manipulation: Additional Cloud Roles",
    "Principal can call iam:PutUserPolicy on itself and inline an admin policy.",
)
ATTACH_ROLE_POLICY = Technique(
    "AttachRolePolicy", "Attach AdministratorAccess to self (role)", ADMIN,
    "T1098.003", "Account Manipulation: Additional Cloud Roles",
    "Role can call iam:AttachRolePolicy on itself and attach a managed admin policy.",
)
PUT_ROLE_POLICY = Technique(
    "PutRolePolicy", "Inline an admin policy on self (role)", ADMIN,
    "T1098.003", "Account Manipulation: Additional Cloud Roles",
    "Role can call iam:PutRolePolicy on itself and inline an admin policy.",
)
PASS_ROLE_LAMBDA = Technique(
    "PassRole:lambda", "PassRole a privileged role to a new Lambda function", ROLE,
    "T1548", "Abuse Elevation Control Mechanism",
    "Principal can iam:PassRole a more-privileged role that Lambda may assume, "
    "and create/invoke a function to run as that role.",
)
PASS_ROLE_EC2 = Technique(
    "PassRole:ec2", "PassRole a privileged role to a new EC2 instance", ROLE,
    "T1548", "Abuse Elevation Control Mechanism",
    "Principal can iam:PassRole a more-privileged role that EC2 may assume, and "
    "run an instance with that instance profile.",
)
ASSUME_ROLE = Technique(
    "AssumeRole", "Assume a more-privileged role", ROLE,
    "T1548", "Abuse Elevation Control Mechanism",
    "Principal is trusted by and permitted to sts:AssumeRole a more-privileged "
    "role (role-chaining when repeated).",
)

# Compute-launch techniques, indexed by service for the detector.
PASS_ROLE_SERVICES = {
    # service: (launch action to probe, service principal in the role's trust)
    "lambda": (PASS_ROLE_LAMBDA, "lambda:CreateFunction", "lambda.amazonaws.com"),
    "ec2": (PASS_ROLE_EC2, "ec2:RunInstances", "ec2.amazonaws.com"),
}

ALL = [
    CREATE_POLICY_VERSION, ATTACH_USER_POLICY, PUT_USER_POLICY,
    ATTACH_ROLE_POLICY, PUT_ROLE_POLICY, PASS_ROLE_LAMBDA, PASS_ROLE_EC2,
    ASSUME_ROLE,
]
BY_KEY = {t.key: t for t in ALL}
