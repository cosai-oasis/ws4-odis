"""The harness core must not depend on its own non-production stand-ins.

This is the test that makes the dependency inversion an invariant rather than a tidy-up.
The seams are Protocols; `odis_harness.fixtures` holds implementations that are explicitly
not for production; and the *callers* — the CLI, the runnable examples, the test suite —
supply them. If the core can reach into that namespace, demo convenience becomes a library
default — a signature verifier that accepts any payload, reached without anyone choosing it.

AST-based rather than a grep so it catches a lazy import inside a function body, which is
the house convention for heavy dependencies and therefore the most likely way this would
regress unnoticed.
"""

from __future__ import annotations

import ast
from typing import TYPE_CHECKING

from odis_harness.paths import repo_root

if TYPE_CHECKING:
    from pathlib import Path

_FIXTURES_PACKAGE = "odis_harness.fixtures"
_CORE = repo_root() / "src" / "odis_harness"

#: `cli/` is the supplier: it is where the harness decides what to wire, so it is the one
#: place inside the distribution allowed to name a stand-in. Everything else is core.
#: `fixtures/` itself is excluded — siblings importing siblings is fine.
#: Matched on the FIRST component only: any-component matching would exempt a future
#: `vault/cli/` or `mcp_forwarder/fixtures/` from the invariant this test exists to hold.
_SUPPLIER_DIRS = frozenset({"cli", "fixtures"})


def _fixture_imports(tree: ast.AST) -> list[str]:
    """Every module this AST imports from the fixtures package, at any nesting depth."""
    found: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.module and node.module.startswith(_FIXTURES_PACKAGE):
                found.append(node.module)
        elif isinstance(node, ast.Import):
            found.extend(a.name for a in node.names if a.name.startswith(_FIXTURES_PACKAGE))
    return found


def _core_modules() -> list[Path]:
    return [
        path
        for path in sorted(_CORE.rglob("*.py"))
        if path.relative_to(_CORE).parts[0] not in _SUPPLIER_DIRS
    ]


def test_core_does_not_import_the_fixtures_package() -> None:
    offenders = {
        str(path.relative_to(repo_root())): imports
        for path in _core_modules()
        if (imports := _fixture_imports(ast.parse(path.read_text(encoding="utf-8"))))
    }
    assert offenders == {}, (
        "the harness core must not import its own non-production stand-ins; "
        f"the callers supply them. Offenders: {offenders}"
    )


def test_the_guard_is_actually_looking_at_something() -> None:
    """A subset check passes vacuously against an empty set, so assert the input is not.

    Without this, deleting the core or breaking `_core_modules()` would turn the test above
    into a green no-op — the same failure mode as a bare `set() <= anything`.
    """
    modules = _core_modules()
    assert len(modules) > 20, f"expected the core to have many modules, found {len(modules)}"
    assert any(p.name == "router.py" for p in modules), "the Router must be in scope"
