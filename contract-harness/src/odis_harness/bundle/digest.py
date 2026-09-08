"""`policy_digest` — sha256 over the canonical-serialized bundle.

The digest covers the *entire* loaded bundle (metadata + policy + routing + governed
tools + per-family `default_mode`), so policy and routing are bound together: a policy
re-pointed at a different vendor produces a different digest.

It *detects*, it does not prevent. Nothing compares it to a reference value — it is
stamped on every envelope so an auditor can reconcile a decision against the exact grant
that authorized it. Prevention is the signature over the whole payload, and only the
Vault path verifies it. On a local grant the caller must choose:
`--bundle-pubkey-file` verifies a sibling `.sig`, `--trust-bundle-unverified` accepts an
unverified payload, and there is no default.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from odis_harness.bundle.types import Bundle


#: The two fields excluded from the digest. They say *when* a grant was minted, which is
#: a property of the issuance rather than of the authority it confers. With a one-hour
#: default TTL, including them gives two grants with byte-identical policy, routing,
#: limits, actor and delegator different digests purely because they were issued an hour
#: apart — so an auditor grouping events by `policy_digest` gets a fresh bucket every
#: hour and cannot tell "policy changed" from "grant re-issued".
#:
#: Everything else stays in, including `actor` and `originating_principal`: re-issuing the
#: same policy to a different agent, or under a different delegator, is a different
#: authority and must not reuse the old trail identity. The cut is *when*, not *who*.
#: Both fields remain integrity-protected — the Ed25519 signature covers the whole
#: payload — they are simply not part of the policy's identity.
_ISSUANCE_WINDOW_FIELDS = frozenset({"issued_at", "expires_at"})


def policy_digest(bundle: Bundle) -> str:
    """Return the sha256 hex digest of the bundle's policy-bearing content.

    Canonicalization: `json.dumps(..., sort_keys=True)` over the bundle minus
    `_ISSUANCE_WINDOW_FIELDS`, UTF-8 encoded. `sort_keys=True` ensures dict insertion order
    does not affect the digest. What remains binds policy **and** routing together, so a
    policy re-pointed at a different vendor produces a different digest.
    """
    content = {
        k: v for k, v in asdict(bundle).items() if k not in _ISSUANCE_WINDOW_FIELDS
    }
    canonical = json.dumps(content, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


__all__ = ["policy_digest"]
