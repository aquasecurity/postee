package regoservice

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The legacy HTML templates escape their data values (html_escape in common.rego). The golden files hold each
// template's output from before escaping was added, for inputs without special characters, so the output must stay
// byte-identical. Regenerate them only on purpose: UPDATE_LEGACY_GOLDEN=1 go test ./regoservice/ -run Legacy
var updateLegacyGolden = os.Getenv("UPDATE_LEGACY_GOLDEN") == "1"

const legacyTestdata = "testdata/legacy-escaping"

// injectionMarker is added to every non-empty string value of an input; the rendered HTML must show it escaped.
const injectionMarker = "<inj>"

type legacyTemplateCase struct {
	pkg   string // rego package
	input string // fixture in testdata/legacy-escaping
	// jsonEncoded is a template that prints the input as JSON, which already encodes '<' and '>'
	jsonEncoded bool
}

var legacyTemplateCases = []legacyTemplateCase{
	{pkg: "postee.vuls.html", input: "scan"},
	{pkg: "postee.vuls.email", input: "scan"},
	{pkg: "postee.vuls.servicenow", input: "scan-servicenow"},
	{pkg: "postee.incident.html", input: "incident"},
	{pkg: "postee.incident.servicenow", input: "incident"},
	{pkg: "postee.insight.html", input: "insight"},
	{pkg: "postee.insight.servicenow", input: "insight"},
	{pkg: "postee.issues.email", input: "issue"},
	{pkg: "postee.iac.html", input: "iac"},
	{pkg: "postee.iac.servicenow", input: "iac"},
	{pkg: "postee.tracee.html", input: "tracee"},
	{pkg: "postee.rawmessage.html", input: "scan", jsonEncoded: true},
}

func loadLegacyFixture(t *testing.T, name string) map[string]interface{} {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(legacyTestdata, name+".json"))
	require.NoError(t, err)
	in := map[string]interface{}{}
	require.NoError(t, json.Unmarshal(b, &in))
	return in
}

func checkLegacyGolden(t *testing.T, name string, out map[string]string) {
	t.Helper()
	got, err := json.MarshalIndent(out, "", " ")
	require.NoError(t, err)
	path := filepath.Join(legacyTestdata, "golden", name+".json")
	if updateLegacyGolden {
		require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o755))
		require.NoError(t, os.WriteFile(path, append(got, '\n'), 0o644))
		return
	}
	want, err := os.ReadFile(path)
	require.NoError(t, err)
	assert.Equal(t, strings.TrimSuffix(string(want), "\n"), string(got), "%s must render exactly as before", name)
}

// inject adds the marker to every non-empty string value. An empty string stays empty: it has nothing to escape, and
// templates read it as "no value". A string that holds JSON (for example the data of an incident) gets the marker
// inside its values, so the template can still parse it.
func inject(v interface{}) interface{} {
	switch x := v.(type) {
	case map[string]interface{}:
		out := make(map[string]interface{}, len(x))
		for k, e := range x {
			out[k] = inject(e)
		}
		return out
	case []interface{}:
		out := make([]interface{}, len(x))
		for i, e := range x {
			out[i] = inject(e)
		}
		return out
	case string:
		if x == "" {
			return x
		}
		var nested interface{}
		if s := strings.TrimSpace(x); (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Unmarshal([]byte(s), &nested) == nil {
			b, _ := json.Marshal(inject(nested))
			return string(b)
		}
		return x + injectionMarker
	default:
		return v
	}
}

func legacyAggregationItems(marker string) []map[string]string {
	return []map[string]string{
		{"title": "t1" + marker, "description": "<p>first scan</p>"},
		{"title": "t2" + marker, "description": "<p>second scan</p>"},
	}
}

// aggregate renders postee.vuls.html.aggregation, the aggregation package of postee.vuls.html
func aggregate(t *testing.T, items []map[string]string) map[string]string {
	t.Helper()
	evaluator, err := BuildBundledRegoEvaluator("postee.vuls.html")
	require.NoError(t, err)
	require.True(t, evaluator.IsAggregationSupported())
	out, err := evaluator.BuildAggregatedContent(items)
	require.NoError(t, err)
	return out
}

func TestLegacyTemplatesRenderAsBefore(t *testing.T) {
	for _, tc := range legacyTemplateCases {
		t.Run(tc.pkg, func(t *testing.T) {
			checkLegacyGolden(t, tc.pkg, evalTemplate(t, tc.pkg, loadLegacyFixture(t, tc.input)))
		})
	}
	t.Run("postee.vuls.html.aggregation", func(t *testing.T) {
		checkLegacyGolden(t, "postee.vuls.html.aggregation", aggregate(t, legacyAggregationItems("")))
	})
	// a url that is not a string is printed as before, also in an href without quotes (unquoted_href)
	for _, pkg := range []string{"postee.iac.html", "postee.iac.servicenow"} {
		t.Run(pkg+".null-url", func(t *testing.T) {
			in := loadLegacyFixture(t, "iac")
			in["url"] = nil
			checkLegacyGolden(t, pkg+".null-url", evalTemplate(t, pkg, in))
		})
	}
}

func TestLegacyTemplatesEscapeValues(t *testing.T) {
	for _, tc := range legacyTemplateCases {
		t.Run(tc.pkg, func(t *testing.T) {
			in := inject(loadLegacyFixture(t, tc.input)).(map[string]interface{})
			description := evalTemplate(t, tc.pkg, in)["description"]
			assert.NotContains(t, description, injectionMarker)
			if !tc.jsonEncoded {
				assert.Contains(t, description, "&lt;inj&gt;")
			}
		})
	}
	t.Run("postee.vuls.html.aggregation", func(t *testing.T) {
		// each description is HTML that a template already rendered; only the title is data
		description := aggregate(t, legacyAggregationItems(injectionMarker))["description"]
		assert.NotContains(t, description, "t1"+injectionMarker)
		assert.Contains(t, description, "t1&lt;inj&gt;")
	})
}
