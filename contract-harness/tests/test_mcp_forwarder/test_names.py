"""parse_tool_name + UnroutedToolName."""

from __future__ import annotations

import pytest

from odis_harness.mcp_forwarder.names import UnroutedToolName, parse_tool_name


@pytest.mark.parametrize(
    ("name", "expected"),
    [
        ("jira.update_issue", ("jira", "update_issue")),
        ("jira.foo.bar", ("jira", "foo.bar")),
        ("jira-prod.update_issue", ("jira-prod", "update_issue")),
    ],
)
def test_parse_tool_name_accepts_routed_names(name: str, expected: tuple[str, str]) -> None:
    assert parse_tool_name(name) == expected


@pytest.mark.parametrize(
    "name",
    [
        "",
        "update_issue",
        ".update_issue",
        "jira.",
        "Jira.update_issue",
        "1jira.update_issue",
    ],
)
def test_parse_tool_name_rejects_unrouted_names(name: str) -> None:
    with pytest.raises(UnroutedToolName):
        parse_tool_name(name)
