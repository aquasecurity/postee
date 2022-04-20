package actions

import (
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const createdAppId = "cd8fd2f4f289445b8975092e7d3045ba"

func TestSanitizedAppName(t *testing.T) {
	testCases := []struct {
		name        string
		image       string
		application string
	}{{
		name:        "Dot",
		image:       "alpine-3.7",
		application: "alpine-3_7",
	}, {
		name:        "Both dot and colon",
		image:       "all-in-one:3.5.19223",
		application: "all-in-one_3_5_19223",
	}, {

		name:        "Slash",
		image:       "bpdockerlab/pii-data:1_0",
		application: "bpdockerlab_pii-data_1_0",
	}}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appName := sanitizedAppName(tc.image)
			assert.Equal(t, tc.application, appName)
		})
	}
}

func TestNexusiq_Init(t *testing.T) {
	nx := NexusIqAction{}
	require.NoError(t, nx.Init())
}

func TestNexusiq_GetName(t *testing.T) {
	nx := NexusIqAction{Name: "my-nexusiq"}
	require.NoError(t, nx.Init())
	require.Equal(t, "my-nexusiq", nx.GetName())
}

func TestNexusiq_Send(t *testing.T) {
	organizationId := "9beee80c6fc148dfa51e8b0359ee4d4e"
	applicationsJson := fmt.Sprintf(`
	{
		"applications": [
			{
				"id": "4bb67dcfc86344e3a483832f8c496419",
				"publicId": "alpine-3_7",
				"name": "MySecondApplication",
				"organizationId": "%s",
				"contactUserName": "NewAppContact"
			}
		]
	}	
`, organizationId)
	createAppPld := fmt.Sprintf(`{"name":"nginx-1_7_1","organizationId":"%s","publicId":"nginx-1_7_1"}`, organizationId)
	testCases := []struct {
		name               string
		image              string
		applications       string
		expctdCreateAppPld string
		expctdAppId        string
	}{{
		name:         "Existing application",
		image:        "alpine-3.7",
		applications: applicationsJson,
		expctdAppId:  "4bb67dcfc86344e3a483832f8c496419",
	}, {
		name:               "New application",
		image:              "nginx-1.7.1",
		applications:       applicationsJson,
		expctdCreateAppPld: createAppPld,
		expctdAppId:        createdAppId,
	},
	}

	b, err := ioutil.ReadFile("testdata/nexus-iq-sbom.xml")
	if err != nil {
		t.Fatal("unable to read test data %w", err)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]string{
				"title":       tc.image,
				"description": string(b),
			}
			ts := configureHttp(t, tc.applications, tc.expctdCreateAppPld, tc.expctdAppId)
			nx := NexusIqAction{Name: "my-nexusiq", Url: ts.URL, User: "admin", Password: "admin", OrganizationId: "9beee80c6fc148dfa51e8b0359ee4d4e"}
			require.NoError(t, nx.Send(input))
			defer ts.Close()
		})
	}

}

func configureHttp(t *testing.T, applicationsJson, expctdCreateAppPld, expctdAppId string) *httptest.Server {
	router := mux.NewRouter()

	//get applications
	router.HandleFunc("/api/v2/applications/organization/{organization:[a-z0-9]+}", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "GET", r.Method)
		_, _ = w.Write([]byte(applicationsJson))
	})

	//create application
	router.HandleFunc("/api/v2/applications", func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)

		require.NoError(t, err)

		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, expctdCreateAppPld, string(body))

		_, _ = w.Write([]byte(fmt.Sprintf(`{"id":"%s"}`, createdAppId)))
	})

	//register bom
	router.HandleFunc("/api/v2/scan/applications/{app:[a-z0-9]+}/sources/cyclone", func(w http.ResponseWriter, r *http.Request) {
		vars := mux.Vars(r)
		assert.Equal(t, "POST", r.Method)
		assert.Equal(t, expctdAppId, vars["app"])

		_, _ = w.Write([]byte("{}"))
	})

	return httptest.NewServer(router)
}
