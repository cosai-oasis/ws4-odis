"""Filesystem anchors for the harness's own data files.

Dependency-free on purpose: the bundle loader, the CLI's audit sink and the tests all
need the schemas directory, and none of them should import another package to find it.
"""

from __future__ import annotations

from pathlib import Path


def repo_root() -> Path:
    """The harness root, anchored to this file rather than the working directory."""
    # paths.py -> odis_harness -> src -> <repo root>
    return Path(__file__).resolve().parents[2]


def default_schemas_dir() -> Path:
    """`$CWD/schemas` when it holds the harness schemas, else the source-tree copy.

    The working-directory candidate comes first so a deployment can override the
    shipped schemas, but it has to actually hold `odis.bundle.v1.json` to win —
    otherwise any unrelated `schemas/` directory in the working directory captures
    resolution and the harness cannot load its own bundle. Returns the source-tree path
    when neither qualifies, so the caller fails on a clear missing-file error rather
    than on `None`.
    """
    candidates = [Path.cwd() / "schemas", repo_root() / "schemas"]
    for candidate in candidates:
        if (candidate / "odis.bundle.v1.json").is_file():
            return candidate
    return candidates[-1]


__all__ = ["default_schemas_dir", "repo_root"]
