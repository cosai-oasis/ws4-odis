"""RegistrationRecordLoader — verify signature, parse, validate schema, construct.

Same pipeline shape as `bundle/loader.py::_verify_and_build`, and deliberately
so: the two artifacts have the same trust story, and a reader who knows one
should not have to learn a second.

**§6.1 resolution-rule clause 1 — "a resolver MUST authenticate `record_issuer`
and the record's integrity protection" — is discharged here, and only here.**
Not fully, though, so the claim is worth splitting in two:

- *Integrity protection: satisfied.* ed25519 over the exact canonical bytes,
  checked before the document is parsed, plus step 7's proof that those bytes
  are the record's canonical form.
- *Authenticating `record_issuer`: bounded by deployment configuration.* The
  loader holds a `Mapping[str, SignatureVerifier]` keyed by `record_issuer`, so
  a document claiming issuer `A` is verified only against `A`'s key, and a
  document naming an issuer with no configured key is refused. That is
  authentication against a pinned key, not against a PKI: certificate chains,
  issuer discovery, and cross-domain trust roots are all deferred, so clause 1 is
  only half satisfied here.

The other five clauses belong to `resolver.py`, which is where the clock and the
authority configuration live. The split mirrors `BundleLoader` → `Router`. A
reader looking only at the resolver would conclude clause 1 is skipped, which is
why both module docstrings state the division.

JSON only, via `json.loads` — not `yaml.safe_load` as the bundle loader uses.
The canonical form is JSON by definition, and admitting YAML would admit inputs
whose bytes do not round-trip to the bytes that were signed.

The last step is the one the bundle loader has no analogue for: the payload must
be the *canonical* serialization of the record it parses to, not merely a
serialization of it. The detached signature was chosen over a JWT precisely so
that the bytes signed, the bytes digested, and the bytes stored are one set of
bytes; a signature verifies over whatever bytes it was made against, so nothing
in steps 1-6 makes that true. Step 7 does.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from odis_harness.registration.digest import canonical_record_bytes
from odis_harness.registration.errors import (
    RegistrationRecordSchemaInvalid,
    RegistrationRecordSignatureInvalid,
)
from odis_harness.registration.types import AgentRegistrationRecord

if TYPE_CHECKING:
    from collections.abc import Mapping

    from odis_harness.bundle.loader import SignatureVerifier

_SCHEMA_FILENAME = "odis.registration.record.v1.json"


def _default_schema_path() -> Path:
    """Locate the record schema via the same fallback strategy as `BundleLoader`.

    Tries `$CWD/schemas`, then `<package>/../../../schemas` (source-tree
    layout). Callers needing an explicit path pass `schema_path=`.
    """
    candidates = [
        Path.cwd() / "schemas" / _SCHEMA_FILENAME,
        Path(__file__).resolve().parents[3] / "schemas" / _SCHEMA_FILENAME,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[-1]


@dataclass(frozen=True, kw_only=True, slots=True)
class SignedRegistrationRecord:
    """Canonical record bytes plus a detached signature. Mirrors `SignedBundle`.

    `payload` is the exact bytes that were signed, which — because the carrier
    is a detached signature over canonical JSON — are also the bytes whose
    sha256 is the record's `record_digest`. That is an invariant the loader
    *checks* rather than assumes: step 7 of `load_signed` re-serialises the
    constructed record and refuses a payload that differs. A signature over
    non-canonical bytes is otherwise indistinguishable from a signature over
    canonical ones, and would leave the record's digest covering bytes no
    issuer signed.

    `record_issuer` is carried alongside rather than read out of `payload`,
    because it selects the verifying key and so has to be known *before* the
    payload is trusted enough to parse. The loader checks that the envelope's
    claim and the document's own `record_issuer` agree, so this field cannot be
    used to route a document to a friendlier key.
    """

    payload: bytes
    signature: bytes
    record_issuer: str


@dataclass(frozen=True, kw_only=True, slots=True)
class RegistrationRecordLoader:
    """Construct with a verifier per issuer; call `load_signed`."""

    #: Keyed by `record_issuer`. The `bundle.loader.SignatureVerifier` Protocol
    #: is reused rather than redeclared, so `VaultTransitSignatureVerifier` and
    #: any production substitute work here unchanged.
    verifiers: Mapping[str, SignatureVerifier]
    schema_path: Path = field(default_factory=_default_schema_path)

    def load_signed(self, signed: SignedRegistrationRecord) -> AgentRegistrationRecord:
        """Verify, parse, schema-validate, construct.

        Raises:
            RegistrationRecordSignatureInvalid: the claimed issuer has no
                configured key, the signature does not verify, or the document's
                own `record_issuer` disagrees with the envelope's.
            RegistrationRecordSchemaInvalid: the payload is not parseable JSON,
                is not a JSON object, fails the schema, is refused by the
                dataclass invariants, or is not the canonical serialization of
                the record it parses to.
        """
        # 1. Resolve the verifying key from the *claimed* issuer. An unknown
        #    issuer is a signature failure, not a KeyError escaping the typed
        #    contract: from the caller's side "I cannot verify this" and "this
        #    does not verify" are the same outcome, and both fail closed.
        verifier = self.verifiers.get(signed.record_issuer)
        if verifier is None:
            message = f"no configured verifier for record_issuer {signed.record_issuer!r}"
            raise RegistrationRecordSignatureInvalid(message)

        # 2. Signature verification, before anything reads the payload.
        if not verifier.verify(signed.payload, signed.signature):
            message = (
                f"signature verification failed for a record claiming "
                f"record_issuer {signed.record_issuer!r}"
            )
            raise RegistrationRecordSignatureInvalid(message)

        # 3. Parse. JSON only — see the module docstring.
        try:
            parsed = json.loads(signed.payload)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            message = f"unparseable JSON in registration record: {exc}"
            raise RegistrationRecordSchemaInvalid(message) from exc

        if not isinstance(parsed, dict):
            message = f"record root must be a JSON object, got {type(parsed).__name__}"
            raise RegistrationRecordSchemaInvalid(message)

        # 4. Schema validation.
        validator = _validator(self.schema_path)
        try:
            validator.validate(parsed)
        except ValidationError as exc:
            message = f"schema validation failed at {list(exc.absolute_path)}: {exc.message}"
            raise RegistrationRecordSchemaInvalid(message) from exc

        # 5. Issuer substitution check. The signature proves the *envelope's*
        #    claimed issuer signed these bytes; it does not prove the document
        #    inside says the same thing. Without this, an issuer holding a valid
        #    key could sign a document attributed to another issuer, and the
        #    resolver — which reads the document, not the envelope — would apply
        #    the wrong authority configuration to it.
        if parsed.get("record_issuer") != signed.record_issuer:
            message = (
                f"record_issuer mismatch: the signed envelope claims "
                f"{signed.record_issuer!r} but the document says "
                f"{parsed.get('record_issuer')!r}"
            )
            raise RegistrationRecordSignatureInvalid(message)

        # 6. Construct. `__post_init__` re-checks invariants the schema also
        #    enforces; a ValueError or KeyError here means the schema let
        #    something through that construction did not accept.
        try:
            record = AgentRegistrationRecord.from_document(parsed)
        except (ValueError, KeyError) as exc:
            message = f"record rejected by dataclass invariants: {exc}"
            raise RegistrationRecordSchemaInvalid(message) from exc

        # 7. Canonicality. The carrier rests on the bytes signed, the bytes
        #    digested, and the bytes stored being the same bytes; steps 1-6
        #    prove the payload was signed and parses to a valid record, not
        #    that it *is* that record's canonical form. Without this check a
        #    signed but re-indented or re-ordered payload loads happily, and
        #    the loaded record's `record_digest` — which §6.2 and §6.3 refs
        #    commit to — is a digest of bytes nobody signed. Re-serialising is
        #    the whole check: `canonical_record_bytes` is deterministic, so
        #    equality here is exactly the invariant.
        if canonical_record_bytes(record) != signed.payload:
            message = (
                f"registration record {record.record_id!r} was signed, but the signed "
                "payload is not its canonical serialization; the bytes signed and the "
                "bytes `record_digest` covers must be the same bytes"
            )
            raise RegistrationRecordSchemaInvalid(message)

        return record


def _validator(schema_path: Path) -> Draft202012Validator:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


__all__ = ["RegistrationRecordLoader", "SignedRegistrationRecord"]
