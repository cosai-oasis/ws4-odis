"""Cross-language golden.

The Go plugin's canonical serializer emits the exact bytes it signs. This test
asserts that form is a valid `odis.bundle.v1` document — i.e. the Python harness
loader/Router can consume what the Go signer produces. Hermetic: reads the committed
golden, no Go or Vault at test time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

_ROOT = Path(__file__).resolve().parents[2]
_GOLDEN = _ROOT / "vault-plugin" / "internal" / "apfbundle" / "testdata" / "golden_bundle.json"
_SCHEMA = _ROOT / "schemas" / "odis.bundle.v1.json"


def test_go_canonical_bundle_validates_against_schema() -> None:
    if not _GOLDEN.is_file():
        # The golden is committed alongside the Go plugin; a missing file means a
        # broken checkout, not an environment gap — fail, don't skip.
        pytest.fail(
            "Go canonical golden missing (regenerate with UPDATE_GOLDEN=1 via the Go test)"
        )
    bundle = json.loads(_GOLDEN.read_text(encoding="utf-8"))
    schema = json.loads(_SCHEMA.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(bundle)
