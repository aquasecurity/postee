package webserver

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aquasecurity/postee/v2/router"
	"github.com/stretchr/testify/assert"
)

func TestWebServer_eventsHandler(t *testing.T) {
	rtr := router.Instance()
	rtr.Send([]byte(`{"SigMetadata":{"ID":"TRC-2", "hostname":"postee-0"}}`))
	rtr.Send([]byte(`{"SigMetadata":{"ID":"TRC-3", "hostname":"postee-0"}}`))

	ws := WebServer{}
	w := httptest.NewRecorder()
	var r *http.Request
	ws.eventsHandler(w, r)

	resp := w.Result()
	defer resp.Body.Close()
	got, _ := ioutil.ReadAll(resp.Body)

	assert.JSONEq(t, `[
   {
      "SigMetadata":{
         "ID":"TRC-2",
         "hostname":"postee-0"
      }
   },
   {
      "SigMetadata":{
         "ID":"TRC-3",
         "hostname":"postee-0"
      }
   }
]`, string(got))
}
