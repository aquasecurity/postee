package uiserver

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	testCfgFile = "test.cfg"

	inputConfigJson = `[{"type":"common"}]}`
)

func TestUpdateConfig(t *testing.T) {
	tests := []struct {
		input  string
		status int
	}{
		{inputConfigJson, http.StatusOK},
	}

	srv := &uiServer{
		cfgPath: testCfgFile,
	}
	//	defer os.RemoveAll(testCfgFile)

	for _, test := range tests {
		req := httptest.NewRequest("POST", "/update", strings.NewReader(test.input))
		w := httptest.NewRecorder()
		srv.updateConfig(w, req)
		if st := w.Result().StatusCode; st != test.status {
			t.Errorf("request to /update returns a wrong status %d, wanted %d.\nData: %q", st, test.status, test.input)
		}
	}
}
