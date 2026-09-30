"""Warden: least-privilege check.

Compare the permissions an agent requests against what its task requires.
Both over-granting and under-granting fail; the minimal set matches exactly.
"""

from __future__ import annotations

from ..models import PermissionResult


def check(required: list[str], requested: list[str]) -> PermissionResult:
    req = set(required)
    got = set(requested)
    return PermissionResult(
        minimal=(req == got),
        over_grants=sorted(got - req),
        missing=sorted(req - got),
    )
