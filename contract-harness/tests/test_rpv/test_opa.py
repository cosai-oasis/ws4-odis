"""`opa eval` subprocess wrapper.

Requires the `opa` binary; tests marked `@pytest.mark.requires_opa` are
auto-skipped when no binary is on PATH (see conftest).
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from odis_harness.rpv.opa import OpaEvalError, opa_eval

if TYPE_CHECKING:
    from pathlib import Path


def _repo_root() -> Path:
    from pathlib import Path as _Path  # noqa: PLC0415

    return _Path(__file__).resolve().parents[2]


@pytest.fixture(scope="module")
def policy_path() -> Path:
    return _repo_root() / "policy" / "odis-policy.rego"


def _input(
    *,
    project: str = "APF",
    labels: list[str] | None = None,
) -> dict[str, object]:
    return {
        "verb": "jira.update_issue",
        "target_resource": {"resource_family": "jira"},
        "request_body": {
            "project": project,
            "fields": {"labels": labels if labels is not None else ["odis-demo"]},
        },
        "task_intent": "test",
        "correlation_id": "11111111-2222-4333-8444-555555555555",
    }


@pytest.mark.requires_opa
def test_opa_eval_allow_for_project_apf_labels_only(
    opa_binary: str,
    policy_path: Path,
) -> None:
    result = opa_eval(
        opa_binary=opa_binary,
        rego_path=policy_path,
        input_payload=_input(),
    )
    assert result["decision"] == "allow"
    assert result["reason_code"] == "tier3_labels_only_project_apf"
    assert result["obligations"] == {"project": "APF", "fields": ["labels"]}


@pytest.mark.requires_opa
def test_opa_eval_deny_for_other_project(
    opa_binary: str,
    policy_path: Path,
) -> None:
    result = opa_eval(
        opa_binary=opa_binary,
        rego_path=policy_path,
        input_payload=_input(project="OTHER"),
    )
    assert result["decision"] == "deny"
    assert result["reason_code"] == "default_deny"


@pytest.mark.requires_opa
def test_opa_eval_require_review_for_sensitive_label(
    opa_binary: str,
    policy_path: Path,
) -> None:
    result = opa_eval(
        opa_binary=opa_binary,
        rego_path=policy_path,
        input_payload=_input(labels=["security"]),
    )
    assert result["decision"] == "require_review"
    assert result["reason_code"] == "sensitive_label"


@pytest.mark.requires_opa
def test_opa_eval_deny_for_field_outside_labels(
    opa_binary: str,
    policy_path: Path,
) -> None:
    payload = _input()
    payload["request_body"]["fields"] = {"summary": "x"}  # type: ignore[index]
    result = opa_eval(
        opa_binary=opa_binary,
        rego_path=policy_path,
        input_payload=payload,
    )
    assert result["decision"] == "deny"


def test_opa_eval_without_binary_raises() -> None:
    with pytest.raises(OpaEvalError, match="no opa binary"):
        opa_eval(
            opa_binary="",
            rego_path=_repo_root() / "policy" / "odis-policy.rego",
            input_payload=_input(),
        )


def test_opa_eval_missing_binary_raises() -> None:
    with pytest.raises(OpaEvalError, match="not found"):
        opa_eval(
            opa_binary="/nonexistent/opa",
            rego_path=_repo_root() / "policy" / "odis-policy.rego",
            input_payload=_input(),
        )


@pytest.mark.requires_opa
def test_opa_eval_sandbox_blocks_http_send(opa_binary: str, tmp_path: Path) -> None:
    """The policy sandbox drops network built-ins: a bundle's Rego calling
    `http.send` must fail to evaluate (fail closed) rather than reach the network."""
    rego = tmp_path / "exfil.rego"
    rego.write_text(
        "package odis_policy\n"
        'decision := {"decision": "allow", "resp": r} if {\n'
        '    r := http.send({"method": "get", "url": "http://example.com"})\n'
        "}\n",
        encoding="utf-8",
    )
    with pytest.raises(OpaEvalError, match=r"http\.send"):
        opa_eval(opa_binary=opa_binary, rego_path=rego, input_payload=_input())
