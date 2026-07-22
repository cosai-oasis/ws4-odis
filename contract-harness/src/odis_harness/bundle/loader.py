"""BundleLoader — read bytes, verify signature, validate schema, construct `Bundle`.

Signature verification is delegated to the injected `SignatureVerifier` protocol;
the harness ships a fixture (`FixtureSignatureVerifier`) that accepts any payload.
Production substitutes a real verifier — the load-path stays the same.

Schema validation uses Draft 2020-12 against `schemas/odis.bundle.v1.json`.
Both signature and schema failures are terminal: typed exceptions surface to
the Router's startup, which exits non-zero rather than serving partial content.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import yaml
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError

from odis_harness.bundle.types import Bundle, Family, ToolPolicy, VendorMcp

if TYPE_CHECKING:
    from typing import Any


_SCHEMA_FILENAME = "odis.bundle.v1.json"


def _default_schema_path() -> Path:
    """Locate `odis.bundle.v1.json` via the same fallback strategy as the rest of the harness.

    Tries: $CWD/schemas, then `<package>/../../../schemas` (source-tree layout).
    Callers that need an explicit path pass `schema_path=` to `BundleLoader`.
    """
    candidates = [
        Path.cwd() / "schemas" / _SCHEMA_FILENAME,
        Path(__file__).resolve().parents[3] / "schemas" / _SCHEMA_FILENAME,
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    return candidates[-1]


class BundleSignatureInvalid(RuntimeError):  # noqa: N818 - reads clearer than the Error suffix
    """The bundle's signature failed verification. Terminal."""


class BundleSchemaInvalid(RuntimeError):  # noqa: N818 - reads clearer than the Error suffix
    """The bundle's structure violates the JSON Schema (or the file isn't parseable). Terminal."""


class SignatureVerifier(Protocol):
    """Out-of-scope-but-pluggable.

    The harness ships `FixtureSignatureVerifier`; production substitutes a real
    implementation that checks against the trust root. The Protocol exists so
    the load-path can call `.verify(payload, signature)` regardless of the
    implementation.
    """

    def verify(self, payload: bytes, signature: bytes) -> bool: ...


@dataclass(frozen=True, slots=True)
class FixtureSignatureVerifier:
    """Always returns True. For tests and local-dev only.

    Production deployments MUST substitute a real `SignatureVerifier` that
    checks the bundle's signature against the trust root.
    """

    def verify(self, payload: bytes, signature: bytes) -> bool:  # noqa: ARG002
        return True


@dataclass(frozen=True, kw_only=True, slots=True)
class BundleLoader:
    """Construct with a `SignatureVerifier`; call `load(path)` to get a `Bundle`."""

    signature_verifier: SignatureVerifier
    #: Schema file path. Defaults to the fallback-resolved location at
    #: construction time so most callers can omit it; explicit override is
    #: available for tests or non-standard deployments.
    schema_path: Path = field(default_factory=_default_schema_path)

    def load(self, bundle_path: Path) -> Bundle:
        """Read, verify signature, validate against schema, construct `Bundle`.

        Filesystem path: read the payload, resolve a sibling `.sig` (out of scope
        for the fixture path — the fixture verifier accepts any input). A real
        verifier resolves `bundle_path` → `.sig` and verifies both bytes here.
        """
        payload = bundle_path.read_bytes()
        signature = self._resolve_signature_bytes(bundle_path)
        return self._verify_and_build(payload, signature, source=str(bundle_path))

    def load_signed(self, payload: bytes, signature: bytes) -> Bundle:
        """Verify an in-memory payload/signature, validate schema, construct `Bundle`.

        The signed path for a freshly-minted bundle (no filesystem round-trip):
        the payload bytes and detached signature come from the issuer directly.
        Shares the verify → parse → schema-validate → construct pipeline with
        `load`; on signature failure raises `BundleSignatureInvalid`, on schema
        failure `BundleSchemaInvalid`.
        """
        return self._verify_and_build(payload, signature, source="<signed payload>")

    def _verify_and_build(self, payload: bytes, signature: bytes, *, source: str) -> Bundle:
        """Shared pipeline: verify signature, parse, schema-validate, construct.

        `source` only labels error messages — both entry points feed the same
        steps so the fixture/sidecar path and the signed path stay identical.
        """
        # 1. Signature verification.
        if not self.signature_verifier.verify(payload, signature):
            message = f"signature verification failed for {source}"
            raise BundleSignatureInvalid(message)

        # 2. Parse YAML. yaml.safe_load accepts bytes directly (and JSON is a
        #    YAML subset, so canonical JSON bytes parse too) — passing payload
        #    (not payload.decode(...)) avoids surfacing UnicodeDecodeError for
        #    non-UTF-8 bytes; PyYAML converts to a YAMLError we already catch.
        try:
            parsed = yaml.safe_load(payload)
        except yaml.YAMLError as exc:
            message = f"unparseable YAML in {source}: {exc}"
            raise BundleSchemaInvalid(message) from exc

        if not isinstance(parsed, dict):
            message = f"bundle root must be a mapping, got {type(parsed).__name__}"
            raise BundleSchemaInvalid(message)

        # 3. Schema validation.
        validator = _validator(self.schema_path)
        try:
            validator.validate(parsed)
        except ValidationError as exc:
            message = f"schema validation failed at {list(exc.absolute_path)}: {exc.message}"
            raise BundleSchemaInvalid(message) from exc

        # 4. Construct dataclasses. `__post_init__` re-checks invariants the
        #    schema also enforces (defense in depth — if the schema ever drifts,
        #    the dataclass still refuses to construct an invalid instance).
        try:
            return _build_bundle(parsed)
        except (ValueError, KeyError) as exc:
            # A ValueError (dataclass invariant) or KeyError (a required field the
            # schema should have required) means the schema let something through
            # that construction didn't accept — surface as schema invalid, not as
            # an uncaught error escaping the loader's typed contract.
            message = f"bundle structure rejected by dataclass invariants: {exc}"
            raise BundleSchemaInvalid(message) from exc

    @staticmethod
    def _resolve_signature_bytes(bundle_path: Path) -> bytes:
        """Look for a sibling `.sig` file; missing is fine for the fixture path."""
        sig_path = bundle_path.parent / (bundle_path.name + ".sig")
        if sig_path.is_file():
            return sig_path.read_bytes()
        return b""


def _validator(schema_path: Path) -> Draft202012Validator:
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema, format_checker=Draft202012Validator.FORMAT_CHECKER)


def _build_bundle(parsed: dict[str, Any]) -> Bundle:
    families: dict[str, Family] = {}
    for name, family_dict in parsed["families"].items():
        vendor_dict = family_dict["vendor_mcp"]
        families[name] = Family(
            vendor_mcp=VendorMcp(
                endpoint_id=vendor_dict["endpoint_id"],
                url=vendor_dict["url"],
            ),
            policy=family_dict["policy"],
            tools={
                tool_name: ToolPolicy(action_limits=dict(tool_dict.get("action_limits", {})))
                for tool_name, tool_dict in family_dict["tools"].items()
            },
            default_mode=family_dict["default_mode"],
        )
    return Bundle(
        bundle_id=parsed["bundle_id"],
        bundle_version=parsed["bundle_version"],
        trust_root_id=parsed["trust_root_id"],
        families=families,
    )


__all__ = [
    "BundleLoader",
    "BundleSchemaInvalid",
    "BundleSignatureInvalid",
    "FixtureSignatureVerifier",
    "SignatureVerifier",
]
