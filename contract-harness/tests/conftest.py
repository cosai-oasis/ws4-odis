"""Session-scoped fixtures + env bootstrap (per python-testing.md).

Imports of harness code are deliberately deferred into the fixtures and hooks that
need them. Collection must never abort: a module-level import here would put the whole
harness import graph (mcp, httpx, starlette, uvicorn) between pytest and a single
collected test, so one broken optional dependency would yield zero tests run instead
of a targeted skip.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

    from odis_harness.bundle.vault_client import VaultBundleClient
    from odis_harness.contracts import EnvelopeValidator
    from odis_harness.vault.dev import DevVaultContext

_TEST_ENV: dict[str, str] = {
    # Intentional scaffold per python-testing.md § Conftest Environment
    # Bootstrapping: populated as capability specs introduce env-driven
    # config (e.g., bundle paths, OPA binary path, audit output path).
}


@pytest.fixture(scope="session", autouse=True)
def _test_environment() -> Iterator[None]:
    with pytest.MonkeyPatch.context() as mp:
        for k, v in _TEST_ENV.items():
            mp.setenv(k, v)
        yield


@pytest.fixture(scope="session")
def dev_vault() -> Iterator[DevVaultContext]:
    """A booted, provisioned dev-mode Vault for requires_vault tests.

    Skipped (not failed) when the vault binary or built plugin is unavailable, so
    the suite stays green in environments without them — like requires_opa.
    """
    from odis_harness.vault.dev import DevVault, plugin_current, vault_bin  # noqa: PLC0415

    if vault_bin() is None:
        pytest.skip("vault binary not available (set ODIS_VAULT_BIN)")
    # Currency, not presence: a binary older than its sources fails on the fields it
    # does not yet emit, which looks like a code defect. Rebuilt when a toolchain is
    # available, skipped when not.
    if not plugin_current() and not DevVault.build_plugin():
        pytest.skip("apf-bundle-issuer plugin stale or unbuilt, and no Go toolchain")
    with DevVault() as ctx:
        yield ctx


@pytest.fixture(scope="session")
def vault_client(dev_vault: DevVaultContext) -> VaultBundleClient:
    """The Router-side Vault client, pointed at the session dev Vault."""
    from odis_harness.bundle.vault_client import VaultBundleClient  # noqa: PLC0415

    return VaultBundleClient(
        vault_addr=dev_vault.addr,
        jwt_login_mount=dev_vault.jwt_login_mount,
        jwt_login_role=dev_vault.jwt_login_role,
        issue_path=dev_vault.issue_path,
    )


@pytest.fixture(scope="session")
def envelope_validator() -> EnvelopeValidator:
    """A validator over the repo's schemas directory.

    Session-scoped: it loads and compiles every schema at construction, so building
    one per test is pure overhead.
    """
    from tests import factories  # noqa: PLC0415 - see the module note on collection safety

    return factories.envelope_validator()


@pytest.fixture(scope="session")
def opa_binary() -> str:
    """Path to the `opa` CLI, resolved by the harness's own `resolve_opa_binary`.

    Sharing the production resolver keeps the test-time and run-time lookup order
    identical. When it resolves nothing, every `@pytest.mark.requires_opa` test in
    the session is skipped with a clear reason.
    """
    from odis_harness.cli.builders import resolve_opa_binary  # noqa: PLC0415 - as above

    resolved = resolve_opa_binary(None)
    if not resolved:
        pytest.skip(
            "opa binary not found; set ODIS_OPA_BIN, install opa on PATH, "
            "or place the binary beside the harness root"
        )
    return resolved


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Auto-skip requires_opa / requires_vault tests when their binary is absent."""
    del config  # unused

    # Defensive: if the dev-vault harness (or an optional dep it imports) is
    # unavailable, treat vault as absent and skip — never abort collection.
    try:
        from odis_harness.vault.dev import vault_bin  # noqa: PLC0415

        vault_present = vault_bin() is not None
    except ImportError:
        vault_present = False

    from odis_harness.cli.builders import resolve_opa_binary  # noqa: PLC0415 - as above

    opa_found = bool(resolve_opa_binary(None))

    skips: list[tuple[str, pytest.MarkDecorator]] = []
    if not opa_found:
        skips.append(("requires_opa", pytest.mark.skip(reason="opa binary not available")))
    if not vault_present:
        skips.append(
            (
                "requires_vault",
                pytest.mark.skip(reason="vault binary not available (set ODIS_VAULT_BIN)"),
            )
        )
    if not skips:
        return

    for item in items:
        for marker_name, skip in skips:
            if item.get_closest_marker(marker_name) is not None:
                item.add_marker(skip)
