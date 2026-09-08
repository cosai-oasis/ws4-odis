"""Non-production stand-ins for the harness's injected seams.

**The core must not import this package.** Every module here implements a boundary the
harness declares as a Protocol, and the point of the inversion is that the *callers* — the
CLI's demo path, the runnable examples, and the test suite — supply them. Nothing under
`odis_harness/` outside `cli/` may depend on this namespace, and
`tests/test_fixture_isolation.py` enforces that.

The stakes: the signature verifier here accepts any payload. If the core could reach it,
a caller could end up trusting an unverified Authority Grant without saying so.

These ship in the wheel today, so an adopter can still import them. Withholding them from a
default install (an optional extra) is a separate decision.
"""

from __future__ import annotations

__all__: list[str] = []
