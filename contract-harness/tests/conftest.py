"""Session-scoped fixtures + env bootstrap (per python-testing.md)."""

from __future__ import annotations

import shutil
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:
    from collections.abc import Iterator

    from odis_harness.bundle.vault_client import VaultBundleClient
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
    from odis_harness.vault.dev import DevVault, plugin_built, vault_bin  # noqa: PLC0415

    if vault_bin() is None:
        pytest.skip("vault binary not available (set ODIS_VAULT_BIN)")
    if not plugin_built() and not DevVault.build_plugin():
        pytest.skip("apf-bundle-issuer plugin not built and no Go toolchain to build it")
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
def opa_binary() -> str:
    """Path to the `opa` CLI.

    Resolution order:
      1. `$ODIS_OPA_BIN` environment variable (explicit override).
      2. `shutil.which("opa")` (PATH lookup).
      3. `../opa` next to the repo root (the location the local install
         is currently sitting at).

    If none resolve, every `@pytest.mark.requires_opa` test in the
    session is skipped with a clear reason.
    """
    import os  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    candidates: list[str] = []
    env = os.environ.get("ODIS_OPA_BIN")
    if env:
        candidates.append(env)
    on_path = shutil.which("opa")
    if on_path:
        candidates.append(on_path)
    sibling = Path(__file__).resolve().parents[2] / "opa"
    candidates.append(str(sibling))

    for candidate in candidates:
        candidate_path = Path(candidate)
        if candidate_path.is_file() and os.access(candidate_path, os.X_OK):
            return str(candidate_path)

    pytest.skip(
        "opa binary not found; set ODIS_OPA_BIN, install opa on PATH, "
        "or place the binary at ../opa relative to the harness root"
    )
    raise AssertionError  # unreachable; pytest.skip raises Skipped


def pytest_collection_modifyitems(
    config: pytest.Config,
    items: list[pytest.Item],
) -> None:
    """Auto-skip requires_opa / requires_vault tests when their binary is absent."""
    del config  # unused
    import os  # noqa: PLC0415
    from pathlib import Path  # noqa: PLC0415

    # Defensive: if the dev-vault harness (or an optional dep it imports) is
    # unavailable, treat vault as absent and skip — never abort collection.
    try:
        from odis_harness.vault.dev import vault_bin  # noqa: PLC0415

        vault_present = vault_bin() is not None
    except ImportError:
        vault_present = False

    opa_found = bool(os.environ.get("ODIS_OPA_BIN")) or bool(shutil.which("opa"))
    if not opa_found:
        sibling = Path(__file__).resolve().parents[1] / ".." / "opa"
        opa_found = sibling.resolve().is_file() and os.access(sibling.resolve(), os.X_OK)

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
