"""Startup banner — declares the artifact unambiguously."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import TextIO

#: The exact banner string written on every CLI invocation. The banner exists
#: to make the artifact's identity unmistakable from any captured output.
BANNER_LINE: str = "ODIS Contract Harness"


def print_banner(stream: TextIO) -> None:
    """Write the banner line followed by a newline. No suppression flag."""
    stream.write(BANNER_LINE + "\n")
    stream.flush()


__all__ = ["BANNER_LINE", "print_banner"]
