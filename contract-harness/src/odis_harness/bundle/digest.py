"""`policy_digest` — sha256 over the canonical-serialized bundle.

The digest covers the *entire* loaded bundle (metadata + policy + routing +
governed tools + per-family `default_mode`). Audit events stamp this digest so
the auditor can reconcile decisions against the exact bundle in force at the
time of the call, including the routing component (defense against the
mix-and-match attack — see [[bundle-signed-routing-and-policy]]).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from odis_harness.bundle.types import Bundle


def policy_digest(bundle: Bundle) -> str:
    """Return the sha256 hex digest of the bundle's canonical serialization.

    Canonicalization: `json.dumps(asdict(bundle), sort_keys=True)` — UTF-8
    encoded. `sort_keys=True` ensures dict insertion order does not affect the
    digest.
    """
    canonical = json.dumps(asdict(bundle), sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = ["policy_digest"]
