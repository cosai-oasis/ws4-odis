r"""`record_digest` — sha256 over the canonical serialization of a §6.1 record.

This is the specification §6.2 and §6.3 inherit, not an implementation detail.
Both carry a `record_digest` in a reference, and a verifier is expected to
recompute it from a record it resolved *independently* — so what exactly gets
digested has to be written down once and pinned.

| Rule | Value |
|---|---|
| Key order | lexicographic, recursive (`sort_keys=True`) |
| Separators | compact `(",", ":")` |
| Encoding | UTF-8, `ensure_ascii=False` |
| Timestamps | RFC 3339, normalised to UTC, `Z`, microsecond precision |
| Arrays | declared order — order is significant and part of the digest |
| Absent SHOULD field | key omitted entirely, never `null` |
| `null` as a value | emitted as `null` — a null entry is data, an absent key is not |
| Booleans | bare `true` / `false`, never `1` / `0` |
| Numbers | integers only, `abs(n) <= 2**53 - 1`; floats refused; decimals travel as strings |
| `lifecycle_state` | bare string |
| `<`, `>`, `&` | literal UTF-8, **not** `\uXXXX` escaped |

The numbers row is there because numbers are the only place Python and every
ECMAScript-derived implementation disagree on how to *spell* a value they agree
on. Measured against RFC 8785 (JCS), `json.dumps` spells
`1.0` where JCS spells `1`, `1e+16` where JCS spells `10000000000000000`, and
`1e-07` where JCS spells `1e-7` — while agreeing on `0.1` and `1e+21`. Partial
agreement is why the rule is "no floats" rather than "no diverging floats": a
rule that is almost right fails silently, which is the worst property a digest
rule can have.

Two fields carry numbers, and the rule has to reach both. `provider_entitlements`
is the one the record cannot type, so `canonical.frozen_json` enforces it there
at arbitrary depth. `record_version` is the one that is easy to miss — a plain
`int` with an obvious floor and no obvious ceiling — so `__post_init__` enforces
the same upper bound on it directly. Missing the second would leave a record
that constructs and digests cleanly but whose digest no ECMAScript verifier can
reproduce, which is the exact failure this row exists to prevent.

The float half is stated here rather than in the JSON Schema because JSON has a
single number type: `1` and `1.0` are the same *value*, the divergence is in
spelling, and no schema keyword expresses a spelling rule — `"type": "integer"`
accepts `1.0`. The bound half *is* expressible, and the schema does state it as
`maximum` on `record_version`. It is deliberately not restated for
`provider_entitlements`: reaching every nested number would take a recursive
subschema, and splitting one rule so that half of it is enforced by a keyword
and half by prose is how the two halves drift apart. This table is already where
the cross-language contract lives; it carries the HTML-escaping rule below for
exactly the same reason.

That escaping row is the one a non-Python issuer has to be told. Go's
`encoding/json.Marshal` — which is what
`vault-plugin/internal/apfbundle/bundle.go::CanonicalJSON` calls, twice — escapes
those three characters to `\u003c`, `\u003e`, and `\u0026` by default, and the
only way off that default is an `Encoder` with `SetEscapeHTML(false)`, which that
file does not use. So a Go issuer serialising an `owner_ref` of `team:R&D`
produces different bytes, and therefore a different `record_digest`, from this
module. `CanonicalJSON` is the right *shape* to copy (compact, key-sorted, no
HTML context anywhere near it) but it is not byte-compatible as written; a Go
implementation of this canonical form must switch the escaping off.
Recorded here rather than in a ticket because a digest whose reproduction rule is
wrong is worse than one with no rule at all.

**It deliberately differs from `bundle/digest.py::policy_digest`,** which uses
`json.dumps`'s default *spaced* separators. The difference is documented rather
than inherited silently because the two digests are different kinds of object:
`policy_digest` is an internal audit stamp over a Python projection that never
leaves the process, while `record_digest` is a cross-language wire commitment.
`asdict()` is not reusable here either — the record holds `datetime` fields that
`json.dumps` cannot serialise, which is why `to_document()` exists and why
canonicalisation is explicit instead of accidental.
"""

from __future__ import annotations

import hashlib
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from odis_harness.registration.types import AgentRegistrationRecord


def canonical_record_bytes(record: AgentRegistrationRecord) -> bytes:
    """The exact bytes an issuer signs and a verifier digests.

    `sort_keys=True` recursively, so neither the order `to_document` writes its
    keys nor the order a `provider_entitlements` mapping happens to be built in
    can move the digest. Arrays are left alone: a record listing two approved
    software refs in one order is a different record from one listing them in
    the other, and sorting them here would silently make those equal.
    """
    return json.dumps(
        record.to_document(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def record_digest(record: AgentRegistrationRecord) -> str:
    """The sha256 hex digest a `RegistrationRecordRef` commits to."""
    return hashlib.sha256(canonical_record_bytes(record)).hexdigest()


__all__ = ["canonical_record_bytes", "record_digest"]
