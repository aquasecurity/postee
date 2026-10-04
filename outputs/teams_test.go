package outputs

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTeamsOutput_SendEscapesTitle(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	teams := &TeamsOutput{Name: "my-teams", Webhook: srv.URL}
	require.NoError(t, teams.Init())

	_, err := teams.Send(map[string]string{"title": `Scope "R&D" <b>x</b> \ end`, "description": "<p>body</p>"})
	require.NoError(t, err)

	// TitleH2 ends with a raw newline inside the JSON string (existing behavior, accepted by Teams).
	var payload struct {
		Text string `json:"text"`
	}
	require.NoError(t, json.Unmarshal([]byte(strings.ReplaceAll(string(body), "\n", `\n`)), &payload), string(body))
	assert.Equal(t, "<h2>Scope &#34;R&amp;D&#34; &lt;b&gt;x&lt;/b&gt; \\ end</h2>\n<p>body</p>", payload.Text)
}

func TestTeamsOutput_SendPlainTitleUnchanged(t *testing.T) {
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	teams := &TeamsOutput{Name: "my-teams", Webhook: srv.URL}
	require.NoError(t, teams.Init())

	_, err := teams.Send(map[string]string{"title": "Aqua security | Image | nginx:1.25 | Scan report", "description": "body"})
	require.NoError(t, err)
	assert.Equal(t, "{\"text\":\"<h2>Aqua security | Image | nginx:1.25 | Scan report</h2>\nbody\"}", string(body))
}
