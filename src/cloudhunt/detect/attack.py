"""ATT&CK Cloud technique registry.

Every detection (signature, behavioural, or correlated case) carries one or more
ATT&CK technique ids. This module is the single place those ids are resolved to a
name and tactic, so the whole engine speaks one vocabulary and a rule that cites
an unknown id fails loudly (see :func:`resolve`).

Only the techniques CloudHunt actually emits are listed — this is a working
subset of the ATT&CK Cloud matrix, not a mirror of it.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str


# id -> Technique. Tactic names follow ATT&CK's enterprise/cloud tactics.
TECHNIQUES: dict[str, Technique] = {
    t.id: t for t in [
        Technique("T1078", "Valid Accounts", "Defense Evasion"),
        Technique("T1078.004", "Valid Accounts: Cloud Accounts", "Persistence"),
        Technique("T1550", "Use Alternate Authentication Material", "Lateral Movement"),
        Technique("T1550.001", "Application Access Token", "Defense Evasion"),
        Technique("T1098", "Account Manipulation", "Persistence"),
        Technique("T1098.001", "Additional Cloud Credentials", "Persistence"),
        Technique("T1098.003", "Additional Cloud Roles", "Privilege Escalation"),
        Technique("T1136", "Create Account", "Persistence"),
        Technique("T1136.003", "Create Account: Cloud Account", "Persistence"),
        Technique("T1562", "Impair Defenses", "Defense Evasion"),
        Technique("T1562.007", "Disable or Modify Cloud Firewall", "Defense Evasion"),
        Technique("T1562.008", "Disable or Modify Cloud Logs", "Defense Evasion"),
        Technique("T1580", "Cloud Infrastructure Discovery", "Discovery"),
        Technique("T1526", "Cloud Service Discovery", "Discovery"),
        Technique("T1530", "Data from Cloud Storage", "Collection"),
        Technique("T1537", "Transfer Data to Cloud Account", "Exfiltration"),
        Technique("T1496", "Resource Hijacking", "Impact"),
        Technique("T1548", "Abuse Elevation Control Mechanism", "Privilege Escalation"),
    ]
}


def resolve(technique_id: str) -> Technique:
    """Look up a technique, raising if the id is not in the registry."""
    try:
        return TECHNIQUES[technique_id]
    except KeyError:
        raise KeyError(
            f"unknown ATT&CK technique id {technique_id!r}; add it to "
            f"cloudhunt.detect.attack.TECHNIQUES"
        )


def tactic_for(technique_id: str) -> str:
    return resolve(technique_id).tactic
