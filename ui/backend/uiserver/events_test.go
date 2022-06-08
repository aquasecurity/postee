package uiserver

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/stretchr/testify/require"
)

func TestUiServer_getEvents(t *testing.T) {
	testCases := []struct {
		name          string
		tsHandlerFunc http.HandlerFunc
		expectedResp  string
	}{
		{
			name: "happy path",
			tsHandlerFunc: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte(`[
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
]`))
			},
			expectedResp: `[
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
]`,
		},
		{
			name:         "sad path, no postee url set",
			expectedResp: "No Postee URL configured, set POSTEE_UI_UPDATE_URL to the Postee URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.tsHandlerFunc != nil {
				ts := httptest.NewServer(tc.tsHandlerFunc)
				defer ts.Close()

				require.NoError(t, os.Setenv("POSTEE_UI_UPDATE_URL", ts.URL))
				defer func() {
					_ = os.Unsetenv("POSTEE_UI_UPDATE_URL")
				}()
			}

			w := httptest.NewRecorder()
			var r *http.Request
			srv := uiServer{}
			srv.getEvents(w, r)

			resp := w.Result()
			defer func() {
				_ = resp.Body.Close()
			}()
			got, _ := ioutil.ReadAll(resp.Body)
			if tc.tsHandlerFunc != nil {
				assert.JSONEq(t, tc.expectedResp, string(got), tc.name)
			} else {
				assert.Equal(t, tc.expectedResp, string(got), tc.name)
			}
		})
	}
}
