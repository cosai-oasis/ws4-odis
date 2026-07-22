"""enforce_action_limits for jira.update_issue."""

from __future__ import annotations

import pytest

from odis_harness.mcp_forwarder.action_limits import (
    ActionLimitViolation,
    enforce_action_limits,
)


def test_jira_update_issue_allows_labels_only_when_obligation_allows_labels() -> None:
    enforce_action_limits(
        "update_issue",
        {"issue_key": "APF-123", "fields": {"labels": ["odis-demo"]}},
        {"allowed_fields": ["labels"]},
    )


def test_jira_update_issue_allows_subset_of_allowed_fields() -> None:
    """Caller doesn't have to populate every allowed field."""
    enforce_action_limits(
        "update_issue",
        {"issue_key": "APF-123", "fields": {"labels": ["x"]}},
        {"allowed_fields": ["labels", "summary"]},
    )


def test_jira_update_issue_rejects_field_not_in_obligation() -> None:
    with pytest.raises(ActionLimitViolation, match="summary"):
        enforce_action_limits(
            "update_issue",
            {
                "issue_key": "APF-123",
                "fields": {"labels": ["x"], "summary": "no"},
            },
            {"allowed_fields": ["labels"]},
        )


def test_jira_update_issue_rejects_wrong_project_prefix() -> None:
    with pytest.raises(ActionLimitViolation, match="project"):
        enforce_action_limits(
            "update_issue",
            {"issue_key": "OTHER-1", "fields": {"labels": ["x"]}},
            {"allowed_fields": ["labels"], "project": "APF"},
        )


def test_jira_update_issue_accepts_correct_project_prefix() -> None:
    enforce_action_limits(
        "update_issue",
        {"issue_key": "APF-9999", "fields": {"labels": ["x"]}},
        {"allowed_fields": ["labels"], "project": "APF"},
    )


def test_jira_update_issue_with_no_obligation_keys_treats_as_no_constraint() -> None:
    """Empty obligations = the policy didn't restrict this call. Allow."""
    enforce_action_limits(
        "update_issue",
        {"issue_key": "APF-1", "fields": {"labels": ["x"]}},
        {},
    )


def test_jira_update_issue_missing_fields_rejected_when_obligation_restricts() -> None:
    """A call with no `fields` at all is malformed when the obligation restricts fields."""
    with pytest.raises(ActionLimitViolation):
        enforce_action_limits(
            "update_issue",
            {"issue_key": "APF-1"},  # no fields
            {"allowed_fields": ["labels"]},
        )


def test_jira_update_issue_rejects_sibling_mutation_channel() -> None:
    """The Router forwards the original arguments, so a mutation expressed
    outside the scoped `fields` object (Jira's parallel `update` verb) must be
    refused — otherwise the labels-only scope is trivially bypassed."""
    with pytest.raises(ActionLimitViolation, match="update"):
        enforce_action_limits(
            "update_issue",
            {
                "issue_key": "APF-123",
                "fields": {"labels": ["ok"]},
                "update": {"summary": [{"set": "pwned"}]},
            },
            {"allowed_fields": ["labels"]},
        )


def test_jira_update_issue_rejects_unknown_top_level_arg() -> None:
    """Any top-level key the enforcer doesn't recognize is a mutation surface
    it can't reason about — fail closed."""
    with pytest.raises(ActionLimitViolation, match="transition"):
        enforce_action_limits(
            "update_issue",
            {"issue_key": "APF-1", "fields": {"labels": ["x"]}, "transition": "Done"},
            {"allowed_fields": ["labels"]},
        )


def test_unknown_tool_raises_not_implemented() -> None:
    """Per design: per-tool dispatch — adding a new gated tool is an explicit add."""
    with pytest.raises(NotImplementedError, match="not_a_real_tool"):
        enforce_action_limits(
            "not_a_real_tool",
            {"anything": "goes"},
            {"allowed_fields": ["x"]},
        )
