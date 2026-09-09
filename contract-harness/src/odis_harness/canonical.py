"""The canonical form the ODIS §6 data models share.

`registration/digest.py` already says its canonicalisation "is the specification
§6.2 and §6.3 inherit, not an implementation detail". This module is that
sentence made structural: the timestamp spelling, the JSON value rules, the
deep-freeze, and the awareness predicate live here, so that every §6 package can
serialise through them rather than through §6.1. `registration/` is the only
consumer today; §6.2 is what the module was extracted for.

A leaf module on purpose. It imports nothing from `odis_harness`, so
`registration/`, `credential/`, and any later `delegation/` can all depend on it
without depending on each other. The alternative — `credential/` reaching into
`registration.types` for a private helper — would make a §6.2 module import a
§6.1 module for a reason that has nothing to do with registration, and would put
the canonical form's definition inside one of its consumers.

What is *not* here: anything that names a field. `provider_entitlements` is
§6.1's; an evidence `statement` is §6.2's. The rules below take a `path` string
so a refusal can say where it came from without knowing whose document it was.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

#: The exact-integer range of an IEEE 754 double, which is the number model
#: RFC 8785 (JCS) pins JSON to. Above it, two distinct Python ints serialise to
#: one double in any ECMAScript-derived implementation, so a digest would stop
#: distinguishing two documents that genuinely differ.
MAX_SAFE_INTEGER = 2**53 - 1


def canonical_timestamp(value: datetime) -> str:
    """RFC 3339, normalised to UTC, `Z` suffix, microsecond precision.

    Normalising to UTC rather than preserving the original offset is what makes
    the same instant expressed as `+08:00` and as UTC digest identically. Fixed
    microsecond precision keeps a whole-second timestamp from serialising
    shorter than a sub-second one, which would otherwise make two records that
    differ only in how they were constructed digest differently.

    Built from the fields rather than by `strftime`: `%Y` is zero-padded on
    glibc but not on every libc, so a year before 1000 would serialise
    differently on different platforms — and a digest that depends on the host's
    C library is not the cross-language commitment §6.2 and §6.3 inherit.
    """
    moment = value.astimezone(UTC)
    return (
        f"{moment.year:04d}-{moment.month:02d}-{moment.day:02d}"
        f"T{moment.hour:02d}:{moment.minute:02d}:{moment.second:02d}"
        f".{moment.microsecond:06d}Z"
    )


def frozen_json(value: object, *, path: str) -> Any:  # noqa: ANN401 - a JSON value is Any
    """Deep-freeze a JSON value, refusing anything that is not canonicalisable.

    Two problems in one pass, because they have the same root: every §6 model
    has at least one open-typed field — §6.1's `provider_entitlements`, and
    §6.2's evidence `statement` when it lands — where a caller supplies a
    structure the model does not describe.

    *Refusing* covers what `json.dumps` would raise on later, plus what it would
    happily emit in a spelling no other language reproduces. The first would
    surface as a `TypeError` out of a digest function, which is neither
    `ValueError` nor `KeyError` and so escapes the fail-closed contract the
    loaders and resolvers document; the second would not surface at all.
    Failing here means a document that constructs is a document that digests,
    and digests to the same bytes everywhere.

    *Freezing* closes the aliasing hole the sequence fields are `tuple` to
    avoid. `frozen=True` protects rebinding, not the interior: a caller could
    otherwise pass a dict, keep the reference, and change the document's content
    after its digest was embedded in a §6.2 ref. Mappings become
    `MappingProxyType` and arrays become `tuple`, recursively, so there is no
    depth at which the interior is writable.

    Raises:
        ValueError: on a non-`str` key, a `float`, an `int` outside
            ±`MAX_SAFE_INTEGER`, or a value of a type with no JSON form.
    """
    # `bool` is checked here, before `int`, because `True` is an `int` in
    # Python — and `json.dumps` spells it `true` in every language, so booleans
    # are not part of the number problem below.
    if value is None or isinstance(value, str | bool):
        return value
    if isinstance(value, float):
        # No floats at all, rather than "no floats that diverge".
        #
        # Measured against RFC 8785, which is what a Go or JavaScript
        # implementation of this canonical form would follow, Python's
        # `json.dumps` diverges on integral-valued floats (`1.0` vs `1`), on the
        # exponent boundary (`1e+16` vs `10000000000000000`), and on
        # small-exponent spelling (`1e-07` vs `1e-7`) — while agreeing on `0.1`
        # and `1e+21`. That partial agreement is exactly what makes a narrower
        # rule dangerous: it would pass silently on the values that agree and
        # fail silently on the ones that do not, and silence is the worst
        # property a digest rule can have.
        #
        # A caller who needs a decimal carries it as a string, which is already
        # how `sha256:...` refs and timestamps travel in these documents.
        message = (
            f"{path} is a float; the canonical form admits no floats because Python and "
            "ECMAScript spell them differently (1.0 vs 1, 1e-07 vs 1e-7). "
            "Carry decimals as strings."
        )
        raise ValueError(message)  # noqa: TRY004 - see the Raises section
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INTEGER:
            # Above the double's exact-integer range two distinct Python ints
            # map to one double, and a canonical form that cannot distinguish
            # two documents is not a commitment to either.
            message = (
                f"{path} is {value!r}, outside ±(2**53 - 1), and has no stable "
                "cross-language form"
            )
            raise ValueError(message)
        return value
    if isinstance(value, Mapping):
        frozen: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                # Mixed key types make `sort_keys=True` raise a TypeError
                # comparing them, so this is a digest failure, not a taste
                # preference.
                message = f"{path} has a non-string key {key!r} of type {type(key).__name__}"
                raise ValueError(message)  # noqa: TRY004 - see the Raises section
            frozen[key] = frozen_json(item, path=f"{path}.{key}")
        return MappingProxyType(frozen)
    if isinstance(value, list | tuple):
        return tuple(frozen_json(item, path=f"{path}[{index}]") for index, item in enumerate(value))
    message = f"{path} is of type {type(value).__name__}, which has no JSON representation"
    raise ValueError(message)


def plain_json(value: object) -> object:
    """Undo `frozen_json` for serialisation.

    `json.dumps` serialises neither `MappingProxyType` nor a `tuple` nested
    inside a mapping into the form the canonical bytes are defined over, so the
    `to_document()` projections thaw before emitting. The result is plain
    `dict`/`list`.
    """
    if isinstance(value, Mapping):
        return {key: plain_json(item) for key, item in value.items()}
    if isinstance(value, tuple):
        return [plain_json(item) for item in value]
    return value


def is_aware(value: datetime) -> bool:
    """Whether `value` can be compared against another aware `datetime`.

    Both halves are needed. `tzinfo is None` is the naive case; a `tzinfo` whose
    `utcoffset()` returns `None` is the rarer one — it is legal to define, and a
    `datetime` carrying one still raises `TypeError` on comparison, which is the
    escape from the fail-closed contract these checks exist to prevent.

    One predicate, many callers — `parse_timestamp` on every load path and
    `__post_init__` on every construction — because two of them answering the
    question differently is the whole failure mode. `parse_timestamp` alone
    would not be enough anyway: a document built in Python never passes through
    it.
    """
    return value.tzinfo is not None and value.tzinfo.utcoffset(value) is not None


def parse_timestamp(raw: object, *, field: str) -> datetime:
    """Parse a canonical timestamp back into an aware `datetime`.

    Raises `ValueError` on anything a `from_document` caller should treat as a
    malformed document. The loaders catch that and re-raise it as a schema
    failure, so a bad timestamp never escapes as a bare `TypeError`.

    `__post_init__` re-checks awareness a moment later, so this branch is not
    load-bearing for the invariant. It is here for the message: at this point
    the offending text is still in hand, and `"2027-01-01T00:00:00" carries no
    timezone offset` locates the problem in the caller's document, where
    `valid_until must be timezone-aware` would only locate it in the record.
    """
    if not isinstance(raw, str):
        message = f"{field} must be a string timestamp, got {type(raw).__name__}"
        raise ValueError(message)  # noqa: TRY004 - deliberately ValueError; see the docstring
    # `fromisoformat` handles the trailing `Z` from 3.11 onward.
    parsed = datetime.fromisoformat(raw)
    if not is_aware(parsed):
        message = f"{field} {raw!r} carries no timezone offset"
        raise ValueError(message)
    return parsed


__all__ = [
    "MAX_SAFE_INTEGER",
    "canonical_timestamp",
    "frozen_json",
    "is_aware",
    "parse_timestamp",
    "plain_json",
]
