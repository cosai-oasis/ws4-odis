"""The Typer application object and the process entry point.

Deliberately holds nothing else. Commands live one per module (`cli.serve`, `cli.demo`) and
register themselves with `@app.command()`; `cli/__init__.py` imports them so that happens
before anything calls `main`. Keeping `app` here rather than in a command module is what
lets those modules import it without a cycle.

Flat commands, so no sub-`Typer`s: `app.add_typer` is for nested groups
(`odis-harness vault issue`), which this CLI does not have.
"""

from __future__ import annotations

import typer

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="ODIS Contract Harness — local runnable entry point.",
)


def main(argv: list[str] | None = None) -> int:
    """Console-script / `python -m` entry: run the Typer app, return its exit code.

    `standalone_mode=False` makes Click return the code (and re-raise usage errors)
    instead of calling `sys.exit`, so this stays a testable `(argv) -> int` while the
    `demo` / `serve` commands raise `typer.Exit`. A usage error — an unknown option, a
    bad value — is reported as one line plus exit 2, matching Click's convention.
    """
    # Typer vendors its own copies of Click's exception types — `typer.Exit` inherits
    # `RuntimeError`, and `NoSuchOption` is not a `click.exceptions.ClickException`. Catching
    # click's misses every usage error, which then escapes as a traceback with exit 1 instead
    # of Click's one-line message and exit 2. Private module, so it is pinned by
    # `test_typer_usage_errors_map_to_exit_2`, which fails if the path moves.
    from typer._click.exceptions import ClickException, Exit  # noqa: PLC0415

    # Importing the command modules is what registers them on `app`. `cli/__init__.py`
    # does this too; repeating it here keeps `main` correct if someone imports this
    # module directly rather than the package.
    from odis_harness.cli import demo as _demo  # noqa: PLC0415, F401
    from odis_harness.cli import serve as _serve  # noqa: PLC0415, F401

    try:
        result = app(args=argv, standalone_mode=False)
    except Exit as exc:
        return int(getattr(exc, "exit_code", 0) or 0)
    except ClickException as exc:
        exc.show()
        return exc.exit_code
    return int(result or 0)


__all__ = ["app", "main"]
