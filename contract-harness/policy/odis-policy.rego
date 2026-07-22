package odis_policy

import future.keywords.if
import future.keywords.in

# Sensitive labels require human review even when project + fields are OK.
SENSITIVE_LABELS := {"security"}

# Default deny.
default decision := {
	"decision": "deny",
	"reason_code": "default_deny",
	"obligations": {},
}

# Helper: does the request body's labels list contain a sensitive label?
has_sensitive_label if {
	some label in input.request_body.fields.labels
	label in SENSITIVE_LABELS
}

# Allow: jira.update_issue, project APF, labels-only, no sensitive labels.
decision := result if {
	input.verb == "jira.update_issue"
	input.target_resource.resource_family == "jira"
	input.request_body.project == "APF"
	every f, _ in input.request_body.fields {
		f == "labels"
	}
	not has_sensitive_label
	result := {
		"decision": "allow",
		"reason_code": "tier3_labels_only_project_apf",
		"obligations": {
			"project": "APF",
			"fields": ["labels"],
		},
	}
}

# Require review: same as allow, plus a sensitive label is present.
decision := result if {
	input.verb == "jira.update_issue"
	input.target_resource.resource_family == "jira"
	input.request_body.project == "APF"
	every f, _ in input.request_body.fields {
		f == "labels"
	}
	has_sensitive_label
	result := {
		"decision": "require_review",
		"reason_code": "sensitive_label",
		"obligations": {
			"project": "APF",
			"fields": ["labels"],
			"review_required_for": ["security"],
		},
	}
}
