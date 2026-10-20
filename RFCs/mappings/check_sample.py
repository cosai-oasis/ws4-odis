"""Check the sample registration record against the 6.1 text proposed in #38.

Usage: python check_sample.py   (needs jsonschema >= 4.18)

Exits 0 only if the sample validates, a record without the new optional
fields still validates, and every malformed variant below is rejected.
"""
import copy
import json
import pathlib
import sys

from jsonschema import Draft202012Validator

HERE = pathlib.Path(__file__).parent
schema = json.loads((HERE / "registration-record-6.1-check.schema.json").read_text(encoding="utf-8"))
sample = json.loads((HERE / "sample-registration-record.json").read_text(encoding="utf-8"))
validator = Draft202012Validator(schema)
failures = 0


def errors(doc):
    return list(validator.iter_errors(doc))


def expect_valid(label, doc):
    global failures
    errs = errors(doc)
    print(f"{'ok  ' if not errs else 'FAIL'} valid:    {label}")
    for e in errs:
        print("       ", "/".join(map(str, e.path)) or "(root)", e.message[:100])
    failures += bool(errs)


def expect_rejected(label, mutate):
    global failures
    doc = copy.deepcopy(sample)
    mutate(doc)
    rejected = bool(errors(doc))
    print(f"{'ok  ' if rejected else 'FAIL'} rejected: {label}")
    failures += not rejected


expect_valid("sample record", sample)

plain = {k: v for k, v in sample.items()
         if k not in ("declared_intent", "reference_values", "evidence_requirements", "extensions")}
plain["approved_software_refs"] = ["sha256:" + "a" * 64]
plain["policy_profile_ref"] = "https://policy.example/bundles/payments@3.2.0"
expect_valid("record with none of the new fields", plain)

expect_rejected("typed ref without digest", lambda d: d["approved_software_refs"][0].pop("digest"))
expect_rejected("typed ref without ref_type", lambda d: d["approved_software_refs"][0].pop("ref_type"))
expect_rejected("digest without algorithm prefix",
                lambda d: d["approved_software_refs"][1].__setitem__("digest", "b" * 64))
expect_rejected("unknown enforcement_mode",
                lambda d: d["policy_profile_ref"].__setitem__("enforcement_mode", "strict"))
expect_rejected("policy object without digest", lambda d: d["policy_profile_ref"].pop("digest"))
expect_rejected("declared_intent not a string",
                lambda d: d.__setitem__("declared_intent", {"statement": "x"}))
expect_rejected("extension value not an object", lambda d: d["extensions"].__setitem__("p-v1", "x"))
expect_rejected("unknown top-level field", lambda d: d.__setitem__("safety_level", "high"))

print("PASS" if not failures else f"FAIL ({failures})")
sys.exit(1 if failures else 0)
