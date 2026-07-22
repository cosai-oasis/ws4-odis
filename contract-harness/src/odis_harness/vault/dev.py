"""Dev-mode Vault lifecycle for hermetic `requires_vault` tests and the smoke.

Boots `vault server -dev` with the built apf-bundle-issuer plugin, provisions it via
`vault/provision.sh`, and exposes the workload JWT + the transit public key. Intended
for tests gated on `ODIS_VAULT_BIN` (skip when absent) — the dev server is local,
ephemeral, and torn down on exit, matching the harness's no-external-service ethos.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import httpx

if TYPE_CHECKING:
    from types import TracebackType

# Repo root — the dir holding src/, vault/, vault-plugin/. parents[3] of this file
# resolves it in BOTH the nested dev layout and a standalone clone of the repo.
_HARNESS = Path(__file__).resolve().parents[3]
_PLUGIN_DIR = _HARNESS / "vault-plugin" / "dist"
_PLUGIN_BIN = _PLUGIN_DIR / "apf-bundle-issuer"
_PROVISION = _HARNESS / "vault" / "provision.sh"
_READY_TIMEOUT_S = 20.0


def vault_bin() -> str | None:
    """The vault binary to drive: ODIS_VAULT_BIN, else on PATH, else a sibling beside
    the repo (dev convenience), else None."""
    env = os.environ.get("ODIS_VAULT_BIN")
    if env and Path(env).is_file():
        return env
    on_path = shutil.which("vault")
    if on_path:
        return on_path
    sibling = _HARNESS.parent / "vault"
    return str(sibling) if sibling.is_file() else None


def plugin_built() -> bool:
    return _PLUGIN_BIN.is_file()


@dataclass(frozen=True, kw_only=True, slots=True)
class DevVaultContext:
    """Handles to a provisioned dev Vault for the Router-side flow."""

    addr: str
    workload_jwt: str
    transit_public_key_b64: str
    jwt_login_mount: str
    jwt_login_role: str
    issue_path: str


class DevVault:
    """Context manager that boots, provisions, and tears down a dev-mode Vault."""

    def __init__(self, *, port: int = 8200, fixdir: str = "/tmp/odis-dev-fix") -> None:  # noqa: S108 — ephemeral dev fixture dir
        self._bin = vault_bin()
        self._port = port
        self._fixdir = fixdir
        self._addr = f"http://127.0.0.1:{port}"
        self._proc: subprocess.Popen[bytes] | None = None
        self._log = Path(f"/tmp/odis-dev-vault-{port}.log")  # noqa: S108 — ephemeral dev log

    def __enter__(self) -> DevVaultContext:
        if self._bin is None:
            message = "no vault binary (set ODIS_VAULT_BIN or place ./vault)"
            raise RuntimeError(message)
        if not plugin_built():
            message = f"plugin not built at {_PLUGIN_BIN} (run: mise run build-vault-plugin)"
            raise RuntimeError(message)

        with self._log.open("wb") as log:
            self._proc = subprocess.Popen(  # noqa: S603 — fixed argv, local dev binary
                [
                    self._bin,
                    "server",
                    "-dev",
                    "-dev-root-token-id=root",
                    f"-dev-plugin-dir={_PLUGIN_DIR}",
                    f"-dev-listen-address=127.0.0.1:{self._port}",
                ],
                stdout=log,
                stderr=subprocess.STDOUT,
            )
        # __exit__ (which terminates the process) only runs if __enter__ returns,
        # so tear the subprocess down here if readiness/provisioning fails —
        # otherwise a spawned dev Vault would leak.
        try:
            self._wait_ready()
            self._provision()
        except BaseException:
            self._terminate()
            raise
        return self._gather()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._terminate()

    def _terminate(self) -> None:
        """Terminate the dev Vault subprocess (idempotent; killed if it lingers)."""
        if self._proc is not None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self._proc.kill()

    def _wait_ready(self) -> None:
        deadline = time.monotonic() + _READY_TIMEOUT_S
        while time.monotonic() < deadline:
            try:
                resp = httpx.get(f"{self._addr}/v1/sys/health", timeout=1.0)
            except httpx.HTTPError:
                time.sleep(0.3)
                continue
            if resp.status_code in {200, 429, 473}:  # initialized/unsealed/standby
                return
            time.sleep(0.3)
        message = "dev Vault did not become ready in time"
        raise RuntimeError(message)

    def _provision(self) -> None:
        env = {
            **os.environ,
            "VAULT": self._bin or "",
            "VAULT_ADDR": self._addr,
            "VAULT_TOKEN": "root",
            "HARNESS": str(_HARNESS),
            "FIXDIR": self._fixdir,
        }
        subprocess.run(  # noqa: S603 — fixed script path, local dev
            ["bash", str(_PROVISION)],  # noqa: S607 — bash on PATH
            env=env,
            check=True,
            capture_output=True,
        )

    def _gather(self) -> DevVaultContext:
        workload_jwt = (Path(self._fixdir) / "jwt").read_text(encoding="ascii")
        resp = httpx.get(
            f"{self._addr}/v1/transit/keys/apf-bundle",
            headers={"X-Vault-Token": "root"},
            timeout=5.0,
        )
        resp.raise_for_status()
        pub_b64 = resp.json()["data"]["keys"]["1"]["public_key"]
        return DevVaultContext(
            addr=self._addr,
            workload_jwt=workload_jwt,
            transit_public_key_b64=pub_b64,
            jwt_login_mount="jwt",
            jwt_login_role="router",
            issue_path="apf/issue",
        )

    @classmethod
    def build_plugin(cls) -> bool:
        """Build the plugin if a Go toolchain is available; return whether it's present."""
        go = shutil.which("go") or str(Path.home() / ".local/go/bin/go")
        if Path(go).is_file():
            subprocess.run(  # noqa: S603 — fixed argv, local toolchain
                [go, "build", "-o", "dist/apf-bundle-issuer", "."],
                cwd=str(_HARNESS / "vault-plugin"),
                check=True,
                capture_output=True,
            )
        return plugin_built()
