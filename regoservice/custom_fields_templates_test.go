package regoservice

import (
	"encoding/json"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	rego_templates "github.com/aquasecurity/postee/v2/rego-templates"
	"github.com/aquasecurity/postee/v2/routes"
)

// customFieldsTemplatePackages maps every Custom Fields Message template to the label of a field that it always shows.
var customFieldsTemplatePackages = map[string]string{
	"postee.vuls.customfields.teams":     "Image name:",
	"postee.vuls.customfields.email":     "Image name:",
	"postee.iac.customfields":            "Repository name:",
	"postee.incident.customfields.teams": "Incident name:",
	"postee.incident.customfields.email": "Incident Name:",
	"postee.issues.customfields.teams":   "Issue name:",
	"postee.issues.customfields.email":   "Issue Name:",
}

func evalTemplate(t *testing.T, regoPackage string, input map[string]interface{}) map[string]string {
	t.Helper()
	evaluator, err := BuildBundledRegoEvaluator(regoPackage)
	require.NoError(t, err)
	out, err := evaluator.Eval(input, "")
	require.NoError(t, err)
	return out
}

func loadJSON(t *testing.T, path string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(path)
	require.NoError(t, err)
	in := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(b, &in))
	return in
}

func parseInput(t *testing.T, s string) map[string]interface{} {
	t.Helper()
	in := map[string]interface{}{}
	require.NoError(t, json.Unmarshal([]byte(s), &in))
	return in
}

// withOptions returns a copy of the input with the per-output options that enrichMsg adds.
func withOptions(in map[string]interface{}, fields []string, titleFormat string) map[string]interface{} {
	out := make(map[string]interface{}, len(in)+1)
	for k, v := range in {
		out[k] = v
	}
	opts := map[string]interface{}{}
	if fields != nil {
		list := make([]interface{}, len(fields))
		for i, f := range fields {
			list[i] = f
		}
		opts["fields"] = list
	}
	if titleFormat != "" {
		opts["title_format"] = titleFormat
	}
	out["template_options"] = opts
	return out
}

func TestCustomFieldsTemplatesEvaluateAnyInput(t *testing.T) {
	inputs := map[string]string{
		"empty":       `{}`,
		"wrong types": `{"image": 123, "registry": null, "application_scope": null, "vulnerability_summary": {"critical": "x"}, "data": 5, "issue_details": "x", "resources": "x", "template_options": {"fields": "x", "title_format": 7}}`,
		"null data":   `{"data": null, "issue_details": {"created_at": "x", "rule_filter": null}, "image_assurance_results": null}`,
		"odd items": `{"resources": [1, "x", {"resource": "str", "vulnerabilities": "nope"}, {"resource": {"name": 5}, "vulnerabilities": [1, {"aqua_severity": "low"}]}],
			"image_assurance_results": {"checks_performed": [1, {"control": 5, "failed": "yes"}]},
			"vulnerabilities_list": {"result": [1, null, {"resource": "str", "aqua_severity": 5}]},
			"issue_details": {"affected_resources": "str", "rule_filter": {"exploit_type": false}}}`,
	}
	for pkg, always := range customFieldsTemplatePackages {
		for name, input := range inputs {
			t.Run(pkg+"/"+name, func(t *testing.T) {
				out := evalTemplate(t, pkg, parseInput(t, input))
				assert.NotEmpty(t, out["title"])
				assert.Contains(t, out["description"], always)
				assert.NotContains(t, out["description"], "%!", "a format verb of the template went wrong")
				assertBalancedTags(t, out["description"], name)
			})
		}
	}
}

func TestVulsCustomFieldsTeams(t *testing.T) {
	scan := loadJSON(t, "../msgservice/testdata/all-in-one-image.json")
	// enrichMsg always sets these; vuls-html fails without response_policy_name.
	scan["response_policy_name"] = "rp1"
	scan["application_scope"] = []interface{}{"s1"}

	t.Run("standard title matches vuls-html", func(t *testing.T) {
		html := evalTemplate(t, "postee.vuls.html", scan)
		text := evalTemplate(t, "postee.vuls.customfields.teams", scan)
		assert.Equal(t, html["title"], text["title"])
	})

	t.Run("content as readable lines", func(t *testing.T) {
		d := evalTemplate(t, "postee.vuls.customfields.teams", scan)["description"]
		assert.Contains(t, d, "<p><b>Image name:</b> "+scan["image"].(string)+"</p>")
		assert.Contains(t, d, "<p><b>Registry:</b> "+scan["registry"].(string)+"</p>")
		assert.Contains(t, d, "<p><b>Compliance status:</b> Compliant</p>")
		assert.Contains(t, d, "<p><b>Vulnerability summary:</b> Critical 0, High 7, Medium 30, Low 6, Negligible 0</p>")
		assert.Contains(t, d, "<p>1. malware, Default: PASS</p>")
		assert.Contains(t, d, "High severity vulnerabilities")
		assert.NotContains(t, strings.ToLower(d), "<table")
		assert.NotContains(t, d, "<style")
	})

	t.Run("field subset", func(t *testing.T) {
		d := evalTemplate(t, "postee.vuls.customfields.teams", withOptions(scan, []string{"vulnerability_summary"}, ""))["description"]
		assert.Contains(t, d, "Image name:")
		assert.Contains(t, d, "Vulnerability summary:")
		assert.NotContains(t, d, "Registry:")
		assert.NotContains(t, d, "severity vulnerabilities")
	})

	t.Run("empty field list shows all fields", func(t *testing.T) {
		all := evalTemplate(t, "postee.vuls.customfields.teams", scan)["description"]
		empty := evalTemplate(t, "postee.vuls.customfields.teams", withOptions(scan, []string{}, ""))["description"]
		assert.Equal(t, all, empty)
	})

	t.Run("values are escaped in the body, title stays plain", func(t *testing.T) {
		out := evalTemplate(t, "postee.vuls.customfields.teams", parseInput(t, `{"image": "<b>x</b>", "registry": "a\"b'c&d"}`))
		assert.Contains(t, out["description"], "&lt;b&gt;x&lt;/b&gt;")
		assert.Contains(t, out["description"], "a&#34;b&#39;c&amp;d")
		assert.Equal(t, "Aqua security | Image | <b>x</b> | Scan report", out["title"])
	})

	t.Run("title drops line breaks", func(t *testing.T) {
		out := evalTemplate(t, "postee.vuls.customfields.teams", parseInput(t, `{"image": "evil\r\nBcc: x"}`))
		assert.NotContains(t, out["title"], "\r")
		assert.NotContains(t, out["title"], "\n")
	})

	t.Run("only http(s) urls become links", func(t *testing.T) {
		ok := evalTemplate(t, "postee.vuls.customfields.teams", parseInput(t, `{"url": "https://aqua.example/#/image/x"}`))["description"]
		assert.Contains(t, ok, `<a href="https://aqua.example/#/image/x">`)
		bad := evalTemplate(t, "postee.vuls.customfields.teams", parseInput(t, `{"url": "javascript:alert(1)"}`))["description"]
		assert.NotContains(t, bad, "<a href")
		assert.Contains(t, bad, "javascript:alert(1)")
	})

	t.Run("vm name and type", func(t *testing.T) {
		out := evalTemplate(t, "postee.vuls.customfields.teams", parseInput(t, `{"entity_type": 2, "image": "img", "host_info": {"logical_name": "vm1"}}`))
		assert.Contains(t, out["description"], "<p><b>VM name:</b> vm1</p>")
		assert.Equal(t, "Aqua security | VM | vm1 | Scan report", out["title"])
	})

	t.Run("summary title", func(t *testing.T) {
		tests := map[string]struct {
			input string
			want  string
		}{
			"no scope":      {`{"image": "img:1.0", "image_assurance_results": {"disallowed": true}}`, "Action required: Vulnerability summary | img:1.0"},
			"one scope":     {`{"image": "img:1.0", "application_scope": ["s1"]}`, "Vulnerability summary for s1 | img:1.0"},
			"three scopes":  {`{"image": "img:1.0", "application_scope": ["s1", "s2", "s3"]}`, "Vulnerability summary for s1, s2, s3 | img:1.0"},
			"five scopes":   {`{"image": "img:1.0", "application_scope": ["s1", "s2", "s3", "s4", "s5"]}`, "Vulnerability summary for s1, s2, s3 +2 more | img:1.0"},
			"non-compliant": {`{"image": "img:1.0", "application_scope": ["s1"], "image_assurance_results": {"disallowed": true}}`, "Action required: Vulnerability summary for s1 | img:1.0"},
		}
		for name, tt := range tests {
			t.Run(name, func(t *testing.T) {
				out := evalTemplate(t, "postee.vuls.customfields.teams", withOptions(parseInput(t, tt.input), nil, "summary"))
				assert.Equal(t, tt.want, out["title"])
			})
		}
	})
}

func TestIacCustomFields(t *testing.T) {
	repo := parseInput(t, `{"repository_name": "repo1", "url": "https://aqua.example/repo1", "triggered_by": "TRIGGERED_BY_PUSH",
		"vulnerability_critical_count": 2, "misconfiguration_high_count": 1, "application_scope": ["s1"], "response_policy_name": "rp1"}`)

	t.Run("standard title matches iac-html", func(t *testing.T) {
		assert.Equal(t, evalTemplate(t, "postee.iac.html", repo)["title"], evalTemplate(t, "postee.iac.customfields", repo)["title"])
	})

	t.Run("content as readable lines", func(t *testing.T) {
		d := evalTemplate(t, "postee.iac.customfields", repo)["description"]
		assert.Contains(t, d, "<p><b>Triggered by:</b> Push</p>")
		assert.Contains(t, d, "<p><b>Vulnerability summary:</b> Critical 2, High 0, Medium 0, Low 0, Unknown 0</p>")
		assert.Contains(t, d, "<p><b>Misconfiguration summary:</b> Critical 0, High 1, Medium 0, Low 0, Unknown 0</p>")
		assert.Contains(t, d, `<a href="https://aqua.example/repo1">`)
		assert.NotContains(t, strings.ToLower(d), "<table")
	})

	t.Run("field list is ignored", func(t *testing.T) {
		all := evalTemplate(t, "postee.iac.customfields", repo)["description"]
		subset := evalTemplate(t, "postee.iac.customfields", withOptions(repo, []string{"registry"}, ""))["description"]
		assert.Equal(t, all, subset)
	})

	t.Run("summary title", func(t *testing.T) {
		assert.Equal(t, "Scan summary for s1 | repo1", evalTemplate(t, "postee.iac.customfields", withOptions(repo, nil, "summary"))["title"])
	})
}

func TestIncidentCustomFieldsTeams(t *testing.T) {
	malware := parseInput(t, `{"name": "Malware found", "main_category": "malware", "severity": "high", "host": "host1", "container": "c1",
		"category": "Malware", "data": "{\"malware\": \"EICAR\", \"action\": \"Block\"}", "application_scope": ["s1"],
		"response_policy_name": "rp1", "timestamp": 1700000000000}`)

	t.Run("standard title matches incident-html", func(t *testing.T) {
		assert.Equal(t, evalTemplate(t, "postee.incident.html", malware)["title"], evalTemplate(t, "postee.incident.customfields.teams", malware)["title"])
	})

	t.Run("content as readable lines", func(t *testing.T) {
		d := evalTemplate(t, "postee.incident.customfields.teams", malware)["description"]
		assert.Contains(t, d, "<p><b>Incident name:</b> Malware found</p>")
		assert.Contains(t, d, "<p><b>Severity:</b> High</p>")
		assert.Contains(t, d, "<p><b>Type:</b> Malware</p>")
		assert.Contains(t, d, "<p><b>Malware detection:</b> </p>")
		assert.Contains(t, d, "<p><b>Malware name:</b> EICAR</p>")
		assert.Contains(t, d, "<p><b>Timestamp:</b> Nov 14, 2023 10:13:20.0</p>")
	})

	t.Run("field subset", func(t *testing.T) {
		d := evalTemplate(t, "postee.incident.customfields.teams", withOptions(malware, []string{"severity"}, ""))["description"]
		assert.Contains(t, d, "Incident name:")
		assert.Contains(t, d, "Severity:")
		assert.NotContains(t, d, "Malware name:")
	})

	t.Run("detection block follows the main category", func(t *testing.T) {
		tests := map[string]string{
			"runtime":    "Runtime control",
			"behavioral": "Behavioral detection",
			"other":      "No specific detection details available",
		}
		for category, want := range tests {
			in := withOptions(malware, nil, "")
			in["main_category"] = category
			assert.Contains(t, evalTemplate(t, "postee.incident.customfields.teams", in)["description"], want, category)
		}
	})

	t.Run("summary title", func(t *testing.T) {
		assert.Equal(t, "High incident for s1 | Malware found on c1", evalTemplate(t, "postee.incident.customfields.teams", withOptions(malware, nil, "summary"))["title"])
	})

	t.Run("title drops line breaks", func(t *testing.T) {
		in := parseInput(t, `{"name": "evil\r\nBcc: x", "main_category": "malware", "container": "c1\nBcc: y"}`)
		for _, format := range []string{"standard", "summary"} {
			title := evalTemplate(t, "postee.incident.customfields.teams", withOptions(in, nil, format))["title"]
			assert.NotContains(t, title, "\r", format)
			assert.NotContains(t, title, "\n", format)
		}
	})
}

func TestIssuesCustomFieldsTeams(t *testing.T) {
	issue := parseInput(t, `{"issue_details": {"name": "Critical vuln", "severity": "critical", "created_at": 1700000000, "description": "desc",
		"resource_type": "image", "affected_resources": ["img1", "img2"], "rule_filter": {"exploit_type": "remote", "internet_exposure": true}},
		"vulnerabilities_list": {"result": [{"name": "CVE-1", "resource": {"name": "openssl"}, "aqua_severity": "high", "fix_version": "1.2"}]},
		"response_policy_name": "rp1", "application_scope": ["s1"]}`)

	t.Run("standard title matches issues-email", func(t *testing.T) {
		assert.Equal(t, evalTemplate(t, "postee.issues.email", issue)["title"], evalTemplate(t, "postee.issues.customfields.teams", issue)["title"])
	})

	t.Run("content as readable lines", func(t *testing.T) {
		d := evalTemplate(t, "postee.issues.customfields.teams", issue)["description"]
		assert.Contains(t, d, "<p><b>Issue name:</b> Critical vuln</p>")
		assert.Contains(t, d, "<p><b>Severity:</b> Critical</p>")
		assert.Contains(t, d, "<p><b>Created:</b> Nov 14, 2023 10:13:20 PM</p>")
		assert.Contains(t, d, "<p><b>Security findings:</b> Internet Exposure, Vulnerabilities</p>")
		assert.Contains(t, d, "<p><b>Top 1 vulnerabilities:</b> </p><p>CVE-1, openssl, High, fix available: Yes</p>")
		assert.Contains(t, d, "<p><b>Resource name:</b> img1, img2</p>")
	})

	t.Run("summary title", func(t *testing.T) {
		assert.Equal(t, "Critical issue for s1 | Critical vuln", evalTemplate(t, "postee.issues.customfields.teams", withOptions(issue, nil, "summary"))["title"])
	})

	t.Run("title drops line breaks", func(t *testing.T) {
		in := parseInput(t, `{"issue_details": {"name": "evil\r\nBcc: x", "severity": "low"}}`)
		title := evalTemplate(t, "postee.issues.customfields.teams", withOptions(in, nil, "summary"))["title"]
		assert.NotContains(t, title, "\r")
		assert.NotContains(t, title, "\n")
	})
}

// enrichMsg injects routes.TemplateOptions; its json tags must match the keys the templates read.
func TestCustomFieldsTemplatesReadRouteTemplateOptions(t *testing.T) {
	in := parseInput(t, `{"image": "img:1.0", "registry": "r1", "application_scope": ["s1"]}`)
	in["template_options"] = routes.TemplateOptions{Fields: []string{"application_scopes"}, TitleFormat: "summary"}
	out := evalTemplate(t, "postee.vuls.customfields.teams", in)
	assert.Equal(t, "Vulnerability summary for s1 | img:1.0", out["title"])
	assert.NotContains(t, out["description"], "Registry:")
	assert.Contains(t, out["description"], "application scopes:")
}

// A broken template breaks the shared compile bundle, so every embedded template must build.
func TestAllEmbeddedTemplatesBuild(t *testing.T) {
	templates := rego_templates.GetAllTemplates()
	require.NotEmpty(t, templates)
	for _, tmpl := range templates {
		t.Run(tmpl.Name, func(t *testing.T) {
			_, err := BuildBundledRegoEvaluator(tmpl.RegoPackage)
			assert.NoError(t, err)
		})
	}
}

// The Email templates of the Custom Fields Message show the same fields, content and title as their Teams twins,
// in the styled layout of the legacy email templates. These tests check what the templates show and hide, and the
// escaping. The look is checked in the manual E2E run.

const (
	vulsEmailPkg     = "postee.vuls.customfields.email"
	incidentEmailPkg = "postee.incident.customfields.email"
	issuesEmailPkg   = "postee.issues.customfields.email"
)

// emailTemplateCase describes an Email template and its Teams twin for the tests that run on all of them.
// markers maps every field key to a text that is in the body only when the section is shown.
// hostile is an input whose values are HTML named after their field (hostileNames).
type emailTemplateCase struct {
	file         string
	pkg          string
	teamsFile    string
	teamsPkg     string
	always       string
	input        func(t *testing.T) map[string]interface{}
	hostile      func(t *testing.T) map[string]interface{}
	hostileNames []string
	markers      map[string]string
}

var emailTemplateCases = []emailTemplateCase{
	{
		file:         "vuls-custom-fields-email",
		pkg:          vulsEmailPkg,
		teamsFile:    "vuls-custom-fields-teams",
		teamsPkg:     "postee.vuls.customfields.teams",
		always:       "Image name:",
		input:        vulsEmailInput,
		hostile:      vulsEmailHostileInput,
		hostileNames: []string{"image", "registry", "url", "policy", "scope1", "scope2", "control", "check-policy", "resource", "version", "cve", "fix"},
		markers:      vulsEmailMarkers,
	},
	{
		file:         "incident-custom-fields-email",
		pkg:          incidentEmailPkg,
		teamsFile:    "incident-custom-fields-teams",
		teamsPkg:     "postee.incident.customfields.teams",
		always:       "Incident Name:",
		input:        incidentEmailInput,
		hostile:      incidentEmailHostileInput,
		hostileNames: []string{"name", "severity", "policy", "scope", "namespace", "category", "deployment", "host", "enforcer-group", "host-id", "image", "url", "cluster", "malware", "hostip", "malware_type", "action", "resource", "resource_digest", "tactic", "technique", "rule_type"},
		markers:      incidentEmailMarkers,
	},
	{
		file:         "issues-custom-fields-email",
		pkg:          issuesEmailPkg,
		teamsFile:    "issues-custom-fields-teams",
		teamsPkg:     "postee.issues.customfields.teams",
		always:       "Issue Name:",
		input:        issuesEmailInput,
		hostile:      issuesEmailHostileInput,
		hostileNames: []string{"name", "severity", "description", "type", "res1", "res2", "cve", "pkg", "vuln-severity", "policy", "scope"},
		markers:      issuesEmailMarkers,
	},
}

var vulsEmailMarkers = map[string]string{
	"registry":              "Registry:",
	"compliance_status":     "Compliance status:",
	"malware":               "Malware found:",
	"sensitive_data":        "Sensitive data found:",
	"vulnerability_summary": "Vulnerabilities summary",
	"assurance_controls":    "Assurance controls",
	"vulnerability_list":    "severity vulnerabilities",
	"response_policy_name":  "Response policy name:",
	"application_scopes":    "Response policy application scopes:",
	"link":                  `class="see-more"`,
}

var incidentEmailMarkers = map[string]string{
	"severity":             "height: 5px",
	"response_policy_name": "Response Policy Name:",
	"application_scopes":   "Application Scope:",
	"type":                 "<strong>Type:</strong>",
	"namespace":            "Namespace:",
	"category":             "Category:",
	"deployment":           "Deployment:",
	"host_name":            "Host Name:",
	"enforcer_group":       "Enforcer Group:",
	"host_id":              "Host ID:",
	"image_name":           "Image Name:",
	"link":                 "URL:",
	"cluster":              "Cluster Name:",
	"timestamp":            "Timestamp:",
	"detection_details":    "Malware Detection",
}

var issuesEmailMarkers = map[string]string{
	"severity":             `class="severity-box"`,
	"created":              "Created:",
	"description":          "Description:",
	"security_findings":    "Internet Exposure",
	"top_vulnerabilities":  "Top 3 Vulnerabilities:",
	"resource_type":        "Resource Type:",
	"resource_name":        "Resource Name:",
	"response_policy_name": "Response Policy Name:",
	"application_scopes":   "Application Scope:",
}

func vulsEmailInput(t *testing.T) map[string]interface{} {
	t.Helper()
	return parseInput(t, `{
		"image": "payments/api:2.4.1", "registry": "Prod ACR", "url": "https://cloud.aquasec.com/#/images/Prod%20ACR/payments%2Fapi:2.4.1/vulns",
		"response_policy_name": "Prod image gate", "application_scope": ["Payments", "Global"],
		"vulnerability_summary": {"critical": 1, "high": 1, "medium": 0, "low": 0, "negligible": 1, "malware": 2, "sensitive": 0},
		"image_assurance_results": {"disallowed": true, "checks_performed": [
			{"control": "max_severity", "policy_name": "Default", "failed": true},
			{"control": "malware", "policy_name": "Malware-Default-Policy"}]},
		"resources": [
			{"resource": {"name": "xz-utils", "version": "5.6.0"}, "vulnerabilities": [{"name": "CVE-2024-3094", "aqua_severity": "critical", "fix_version": "5.6.2"}]},
			{"resource": {"name": "curl", "version": "8.3.0"}, "vulnerabilities": [{"name": "CVE-2023-38545", "aqua_severity": "high", "fix_version": "8.4.0"}]},
			{"resource": {"name": "glibc", "version": "2.36"}, "vulnerabilities": [{"name": "CVE-2019-1010022", "aqua_severity": "negligible"}]}]}`)
}

func vulsEmailHostileInput(t *testing.T) map[string]interface{} {
	t.Helper()
	return parseInput(t, `{
		"image": "<b>image</b>", "registry": "<b>registry</b>", "url": "https://aqua.example/<b>url</b>",
		"response_policy_name": "<b>policy</b>", "application_scope": ["<b>scope1</b>", "<b>scope2</b>"],
		"image_assurance_results": {"checks_performed": [{"control": "<b>control</b>", "policy_name": "<b>check-policy</b>"}]},
		"resources": [{"resource": {"name": "<b>resource</b>", "version": "<b>version</b>"},
			"vulnerabilities": [{"name": "<b>cve</b>", "aqua_severity": "low", "fix_version": "<b>fix</b>"}]}]}`)
}

func incidentEmailInput(t *testing.T) map[string]interface{} {
	t.Helper()
	return parseInput(t, `{"name": "Malware found", "main_category": "malware", "severity": "high", "severity_score": 3, "host": "host1", "container": "c1",
		"category": "Malware", "namespace": "default", "deployment": "dep1", "host_group": "Enforcer-Group", "hostid": "host-id-1", "image": "test/image:latest",
		"cluster": "Cluster-Test", "url": "https://cloud.aquasec.com/#/incidents/1",
		"data": "{\"malware\": \"EICAR\", \"action\": \"Block\", \"hostip\": \"10.0.0.1\", \"malware_type\": \"Virus\", \"resource\": \"/tmp/eicar.test\", \"resource_digest\": \"0000\", \"tactic\": \"Execution\", \"technique\": \"Exploit\", \"rule_type\": \"host.runtime.policy\"}",
		"application_scope": ["s1"], "response_policy_name": "rp1", "timestamp": 1700000000000}`)
}

func incidentEmailHostileInput(t *testing.T) map[string]interface{} {
	t.Helper()
	in := parseInput(t, `{"name": "<b>name</b>", "main_category": "malware", "severity": "<b>severity</b>", "severity_score": 3,
		"category": "<b>category</b>", "namespace": "<b>namespace</b>", "deployment": "<b>deployment</b>", "host": "<b>host</b>",
		"host_group": "<b>enforcer-group</b>", "hostid": "<b>host-id</b>", "image": "<b>image</b>", "cluster": "<b>cluster</b>",
		"url": "https://aqua.example/<b>url</b>", "application_scope": ["<b>scope</b>"], "response_policy_name": "<b>policy</b>"}`)
	in["data"] = hostileDetail(t, "malware", "hostip", "malware_type", "action", "resource", "resource_digest", "tactic", "technique", "rule_type")
	return in
}

// hostileDetail returns the data of an incident (a JSON string) whose values are HTML named after their keys.
func hostileDetail(t *testing.T, keys ...string) string {
	t.Helper()
	detail := make(map[string]interface{}, len(keys))
	for _, key := range keys {
		detail[key] = "<b>" + key + "</b>"
	}
	data, err := json.Marshal(detail)
	require.NoError(t, err)
	return string(data)
}

func issuesEmailInput(t *testing.T) map[string]interface{} {
	t.Helper()
	return parseInput(t, `{"issue_details": {"name": "Critical vuln", "severity": "critical", "created_at": 1700000000, "description": "desc",
		"resource_type": "image", "affected_resources": ["img1", "img2"], "rule_filter": {"exploit_type": "remote", "internet_exposure": true}},
		"vulnerabilities_list": {"result": [
			{"name": "CVE-1", "resource": {"name": "openssl"}, "aqua_severity": "high", "fix_version": "1.2"},
			{"name": "CVE-2", "resource": {"name": "zlib"}, "aqua_severity": "critical"},
			{"name": "CVE-3", "resource": {"name": "glibc"}, "aqua_severity": "negligible", "fix_version": ""}]},
		"response_policy_name": "rp1", "application_scope": ["s1"]}`)
}

func issuesEmailHostileInput(t *testing.T) map[string]interface{} {
	t.Helper()
	return parseInput(t, `{"issue_details": {"name": "<b>name</b>", "severity": "<b>severity</b>", "created_at": 1700000000, "description": "<b>description</b>",
		"resource_type": "<b>type</b>", "affected_resources": ["<b>res1</b>", "<b>res2</b>"], "rule_filter": {"internet_exposure": true}},
		"vulnerabilities_list": {"result": [{"name": "<b>cve</b>", "resource": {"name": "<b>pkg</b>"}, "aqua_severity": "<b>vuln-severity</b>"}]},
		"response_policy_name": "<b>policy</b>", "application_scope": ["<b>scope</b>"]}`)
}

// emailBody renders the template and returns the body of the email.
func emailBody(t *testing.T, pkg string, in map[string]interface{}) string {
	t.Helper()
	return evalTemplate(t, pkg, in)["description"]
}

var emailTagPattern = regexp.MustCompile(`(?s)<(/?)([a-zA-Z][a-zA-Z0-9]*)[^>]*?(/?)>`)

// assertBalancedTags checks that every tag of the html that can have content is closed, in order. Values are escaped,
// so a tag in the body is a tag of the template.
func assertBalancedTags(t *testing.T, html, what string) {
	t.Helper()
	void := map[string]bool{"meta": true, "br": true, "img": true}
	var open []string
	for _, m := range emailTagPattern.FindAllStringSubmatch(html, -1) {
		tag := strings.ToLower(m[2])
		switch {
		case m[1] == "/":
			if len(open) == 0 || open[len(open)-1] != tag {
				t.Errorf("%s: unexpected </%s>, open tags: %v", what, tag, open)
				return
			}
			open = open[:len(open)-1]
		case m[3] != "/" && !void[tag]:
			open = append(open, tag)
		}
	}
	assert.Empty(t, open, "%s: tags left open", what)
}

var emailSectionKeyPattern = regexp.MustCompile(`(?m)^\t\["([a-z_]+)",`)

// sectionKeys lists the keys of the sections of a template, in order.
func sectionKeys(source string) []string {
	var keys []string
	for _, m := range emailSectionKeyPattern.FindAllStringSubmatch(source, -1) {
		keys = append(keys, m[1])
	}
	return keys
}

// The server reads the field keys from the source of the template, as ["<key>",
func TestCustomFieldsEmailSectionKeysMatchTeams(t *testing.T) {
	sources := rego_templates.EmbeddedTemplates()
	for _, tc := range emailTemplateCases {
		t.Run(tc.file, func(t *testing.T) {
			email, ok := sources[tc.file+".rego"]
			require.True(t, ok, "no embedded template %s", tc.file)
			teams, ok := sources[tc.teamsFile+".rego"]
			require.True(t, ok, "no embedded template %s", tc.teamsFile)

			keys := sectionKeys(teams)
			require.NotEmpty(t, keys)
			assert.Equal(t, keys, sectionKeys(email), "the Email template has the section keys of the Teams template, in the same order")
			for _, key := range keys {
				assert.Contains(t, email, `["`+key+`",`)
				assert.Contains(t, tc.markers, key, "the tests do not cover the field %q", key)
			}
			assert.Len(t, tc.markers, len(keys))
		})
	}
}

func TestCustomFieldsEmailAllFieldsRender(t *testing.T) {
	for _, tc := range emailTemplateCases {
		t.Run(tc.file, func(t *testing.T) {
			body := emailBody(t, tc.pkg, tc.input(t))
			assert.Contains(t, body, tc.always)
			for key, marker := range tc.markers {
				assert.Contains(t, body, marker, key)
			}
			assert.NotContains(t, body, "%!", "a format verb of the template went wrong")
			assertBalancedTags(t, body, "all fields")
		})
	}
}

func TestCustomFieldsEmailFieldSubsetHidesOtherSections(t *testing.T) {
	for _, tc := range emailTemplateCases {
		t.Run(tc.file, func(t *testing.T) {
			for key := range tc.markers {
				body := emailBody(t, tc.pkg, withOptions(tc.input(t), []string{key}, ""))
				assert.Contains(t, body, tc.always, key)
				assertBalancedTags(t, body, key)
				for other, marker := range tc.markers {
					if other == key {
						assert.Contains(t, body, marker, "%s must show its section", key)
					} else {
						assert.NotContains(t, body, marker, "%s must not show the %s section", key, other)
					}
				}
			}

			// the name is always shown, a list without a known field shows nothing else
			body := emailBody(t, tc.pkg, withOptions(tc.input(t), []string{"unknown"}, ""))
			assert.Contains(t, body, tc.always)
			for key, marker := range tc.markers {
				assert.NotContains(t, body, marker, key)
			}
		})
	}
}

func TestCustomFieldsEmailEmptyFieldListShowsAllFields(t *testing.T) {
	for _, tc := range emailTemplateCases {
		t.Run(tc.file, func(t *testing.T) {
			all := emailBody(t, tc.pkg, tc.input(t))
			assert.Equal(t, all, emailBody(t, tc.pkg, withOptions(tc.input(t), []string{}, "")))
			assert.Equal(t, all, emailBody(t, tc.pkg, withOptions(tc.input(t), nil, "summary")), "the title format does not change the body")
		})
	}
}

// Every value of every field is escaped, in the Email template and in its Teams twin.
func TestCustomFieldsTemplatesEscapeValues(t *testing.T) {
	for _, tc := range emailTemplateCases {
		for _, pkg := range []string{tc.pkg, tc.teamsPkg} {
			t.Run(pkg, func(t *testing.T) {
				body := emailBody(t, pkg, tc.hostile(t))
				assertBalancedTags(t, body, "hostile values")
				for _, name := range tc.hostileNames {
					assert.NotContains(t, body, "<b>"+name+"</b>", "a value reached the body unescaped")
					assert.Contains(t, body, "&lt;b&gt;"+name+"&lt;/b&gt;", name)
				}
			})
		}
	}
}

func TestVulsCustomFieldsEmail(t *testing.T) {
	t.Run("property cells flow two per row", func(t *testing.T) {
		tests := []struct {
			fields    []string
			rows      int
			twoCelled int
		}{
			{[]string{"vulnerability_summary"}, 1, 0},
			{[]string{"registry"}, 1, 1},
			{[]string{"registry", "compliance_status"}, 2, 1},
			{[]string{"registry", "compliance_status", "malware"}, 2, 2},
			{[]string{"registry", "compliance_status", "malware", "sensitive_data"}, 3, 2},
		}
		for _, tt := range tests {
			body := emailBody(t, vulsEmailPkg, withOptions(vulsEmailInput(t), tt.fields, ""))
			assert.Equal(t, tt.rows, strings.Count(body, `class="properties-row"`), "rows of %v", tt.fields)
			assert.Equal(t, tt.twoCelled, strings.Count(body, `class="properties-cell left-cell"`), "second cells of %v", tt.fields)
		}
	})

	t.Run("no assurance controls and no tables without data", func(t *testing.T) {
		body := emailBody(t, vulsEmailPkg, parseInput(t, `{"image": "i"}`))
		assert.NotContains(t, body, "Assurance controls")
		assert.NotContains(t, body, "severity vulnerabilities")
		assert.Contains(t, body, "Vulnerabilities summary")
	})

	t.Run("only http(s) urls get the button", func(t *testing.T) {
		for _, url := range []string{"https://aqua.example/#/image/x", "HTTP://AQUA.EXAMPLE/x"} {
			body := emailBody(t, vulsEmailPkg, parseInput(t, `{"url": "`+url+`"}`))
			assert.Contains(t, body, `<a href="`+url+`" class="see-more">See more</a>`, url)
		}
		escaped := emailBody(t, vulsEmailPkg, parseInput(t, `{"url": "https://aqua.example/?a=1&b=\"2\""}`))
		assert.Contains(t, escaped, `<a href="https://aqua.example/?a=1&amp;b=&#34;2&#34;" class="see-more">`)

		for _, url := range []string{`"javascript:alert(1)"`, `"ftp://aqua.example/x"`, `"data:text/html,x"`, `"//aqua.example/x"`, `""`, `5`, `null`} {
			body := emailBody(t, vulsEmailPkg, parseInput(t, `{"url": `+url+`}`))
			assert.NotContains(t, body, `class="see-more"`, url)
			assert.NotContains(t, body, "<a ", url)
		}
		assert.NotContains(t, emailBody(t, vulsEmailPkg, parseInput(t, `{}`)), `class="see-more"`)
	})
}

// The scan templates aggregate messages like vuls-email and vuls-html, so a route with aggregation sends one message.
func TestCustomFieldsScanTemplatesSupportAggregation(t *testing.T) {
	for _, pkg := range []string{vulsEmailPkg, "postee.vuls.customfields.teams"} {
		t.Run(pkg, func(t *testing.T) {
			evaluator, err := BuildBundledRegoEvaluator(pkg)
			require.NoError(t, err)
			require.True(t, evaluator.IsAggregationSupported())

			first := evalTemplate(t, pkg, parseInput(t, `{"image": "img:1"}`))
			second := evalTemplate(t, pkg, parseInput(t, `{"image": "img:2"}`))
			out, err := evaluator.BuildAggregatedContent([]map[string]string{first, second})
			require.NoError(t, err)
			for _, msg := range []map[string]string{first, second} {
				assert.Contains(t, out["description"], "<h1>"+msg["title"]+"</h1>")
				assert.Contains(t, out["description"], msg["description"])
			}
		})
	}
}

func TestIncidentCustomFieldsEmail(t *testing.T) {
	t.Run("policy information needs one of its fields", func(t *testing.T) {
		body := emailBody(t, incidentEmailPkg, withOptions(incidentEmailInput(t), []string{"namespace"}, ""))
		assert.NotContains(t, body, "Policy Information")
		assert.Contains(t, body, "Incident Overview")
		assert.NotContains(t, emailBody(t, incidentEmailPkg, withOptions(incidentEmailInput(t), []string{"application_scopes"}, "")), "Response Policy Name:")
	})

	t.Run("detection values are escaped for every category", func(t *testing.T) {
		categories := map[string][]string{
			"runtime":    {"control", "rule", "tactic", "level", "technique", "user", "resource"},
			"behavioral": {"user", "technique", "process", "tactic", "signature_description"},
		}
		for category, keys := range categories {
			in := incidentEmailInput(t)
			in["main_category"] = category
			in["container"] = "<b>container</b>"
			in["data"] = hostileDetail(t, keys...)
			body := emailBody(t, incidentEmailPkg, in)
			assert.NotContains(t, body, "<b>", category)
			for _, name := range append([]string{"container"}, keys...) {
				assert.Contains(t, body, "&lt;b&gt;"+name+"&lt;/b&gt;", category+" "+name)
			}
		}
	})

	t.Run("the badge shows a score only when the incident has one", func(t *testing.T) {
		scored := emailBody(t, incidentEmailPkg, parseInput(t, `{"severity": "high", "severity_score": 3}`))
		assert.Contains(t, scored, `<span style="font-size: 28px;">3</span>`)
		unscored := emailBody(t, incidentEmailPkg, parseInput(t, `{"severity": "low"}`))
		assert.NotContains(t, unscored, "font-size: 28px", "no made-up score")
	})

	t.Run("only http(s) urls become links", func(t *testing.T) {
		ok := emailBody(t, incidentEmailPkg, parseInput(t, `{"url": "https://aqua.example/#/i"}`))
		assert.Contains(t, ok, `<a href="https://aqua.example/#/i" style="color: #007BFF; text-decoration: underline;">https://aqua.example/#/i</a>`)
		bad := emailBody(t, incidentEmailPkg, parseInput(t, `{"url": "javascript:alert(1)"}`))
		assert.NotContains(t, bad, "<a ")
		assert.Contains(t, bad, "<strong>URL:</strong> javascript:alert(1)")
	})
}

var emailVulnerabilityRow = regexp.MustCompile(`(?s)<tr>\s*<td>([^<]*)</td>\s*<td>([^<]*)</td>\s*<td>(.*?)</td>\s*<td>(.*?)</td>\s*</tr>`)

func TestIssuesCustomFieldsEmail(t *testing.T) {
	t.Run("a section without shown fields is left out", func(t *testing.T) {
		body := emailBody(t, issuesEmailPkg, withOptions(issuesEmailInput(t), []string{"created"}, ""))
		assert.Contains(t, body, "Issues Details")
		for _, heading := range []string{"Security Findings", "Resource Details", "Policy Information"} {
			assert.NotContains(t, body, heading)
		}

		// a shown field without content adds no section
		empty := emailBody(t, issuesEmailPkg, withOptions(parseInput(t, `{"issue_details": {"name": "n"}}`), []string{"top_vulnerabilities"}, ""))
		assert.NotContains(t, empty, "Security Findings")
		assert.NotContains(t, empty, "Vulnerabilities:")
	})

	t.Run("the css keeps its percent signs", func(t *testing.T) {
		body := emailBody(t, issuesEmailPkg, issuesEmailInput(t))
		assert.Equal(t, 3, strings.Count(body, "width: 100%;"))
		assert.NotContains(t, body, "%!")
	})

	t.Run("every vulnerability has a row, and an empty fix version is no fix", func(t *testing.T) {
		rows := emailVulnerabilityRow.FindAllStringSubmatch(emailBody(t, issuesEmailPkg, issuesEmailInput(t)), -1)
		require.Len(t, rows, 3, "the negligible vulnerability has a row")
		assert.Equal(t, "CVE-3", rows[2][1])
		assert.NotEqual(t, rows[0][4], rows[2][4], "CVE-1 has a fix, CVE-3 has an empty fix version")
		assert.Equal(t, rows[1][4], rows[2][4], "CVE-2 has no fix version, CVE-3 has an empty one")
	})
}
