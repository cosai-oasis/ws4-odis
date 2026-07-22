package backend

import (
	"odis-contract-harness/vault-plugin/internal/apfbundle"
	"odis-contract-harness/vault-plugin/internal/policydsl"
	"testing"
)

// project compiles each family's spec to Rego and derives governed tools from
// the same spec (data-driven).
func TestProjectCompilesAndDerivesTools(t *testing.T) {
	t.Parallel()

	g := grant{
		BundleID:      "b",
		BundleVersion: "1",
		TrustRootID:   "tr",
		Families: map[string]grantFamily{
			"jira-prod": {
				VendorMCP: apfbundle.VendorMCP{EndpointID: "ep", URL: "https://vendor.example/"},
				Policy: policydsl.PolicySpec{Rules: []policydsl.Rule{
					{Verb: "update_issue", AllowFields: []string{"labels"}},
				}},
			},
		},
	}

	got, err := project(g)
	if err != nil {
		t.Fatalf("project: %v", err)
	}
	fam, ok := got.Families["jira-prod"]
	if !ok {
		t.Fatal("projected bundle missing the jira-prod family")
	}
	if fam.Policy == "" {
		t.Error("family policy was not compiled to Rego")
	}
	tool, ok := fam.Tools["update_issue"]
	if !ok {
		t.Fatal("governed tool was not derived for update_issue")
	}
	if _, ok := tool.ActionLimits["allowed_fields"]; !ok {
		t.Error("allowed_fields was not derived into action limits")
	}
}
