package actions

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDependencyTrackAction_Send(t *testing.T) {
	bomJSON := `{
		"$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:78f7eeb2-25fd-45ce-9ece-63cf0ca9b1af",
		"version": 1,
		"metadata": {
		  "timestamp": "2023-07-26T07:42:41+00:00",
		  "tools": [
			{
			  "vendor": "aquasecurity",
			  "name": "trivy",
			  "version": "0.43.1"
			}
		  ],
		  "component": {
			"bom-ref": "pkg:oci/busybox@sha256:caa382c432891547782ce7140fb3b7304613d3b0438834dce1cad68896ab110a?repository_url=index.docker.io%2Flibrary%2Fbusybox\u0026arch=arm64",
			"type": "container",
			"name": "busybox:latest",
			"purl": "pkg:oci/busybox@sha256:caa382c432891547782ce7140fb3b7304613d3b0438834dce1cad68896ab110a?repository_url=index.docker.io%2Flibrary%2Fbusybox\u0026arch=arm64",
			"properties": [
			  {
				"name": "aquasecurity:trivy:DiffID",
				"value": "sha256:57d0c5e3b21e4fdac106cfee383d702b92cd433e6e45588153228670b616bc59"
			  },
			  {
				"name": "aquasecurity:trivy:ImageID",
				"value": "sha256:d38589532d9756ff743d2149a143bfad79833261ff18c24b22088183a651ff65"
			  },
			  {
				"name": "aquasecurity:trivy:RepoDigest",
				"value": "busybox@sha256:caa382c432891547782ce7140fb3b7304613d3b0438834dce1cad68896ab110a"
			  },
			  {
				"name": "aquasecurity:trivy:RepoTag",
				"value": "busybox:latest"
			  },
			  {
				"name": "aquasecurity:trivy:SchemaVersion",
				"value": "2"
			  }
			]
		  }
		},
		"components": [],
		"dependencies": [
		  {
			"ref": "pkg:oci/busybox@sha256:caa382c432891547782ce7140fb3b7304613d3b0438834dce1cad68896ab110a?repository_url=index.docker.io%2Flibrary%2Fbusybox\u0026arch=arm64",
			"dependsOn": []
		  }
		],
		"vulnerabilities": []
	  }`
	type fields struct {
		Name   string
		Url    string
		APIKey string
	}
	type args struct {
		content map[string]string
	}
	tests := []struct {
		name        string
		fields      fields
		args        args
		wantErr     string
		errMsg      string
		handlerFunc http.HandlerFunc
	}{
		{
			name: "valid content JSON BOM",
			fields: fields{
				Name:   "test",
				APIKey: "key",
			},
			args: args{
				content: map[string]string{
					"title":       "test-project:test-version",
					"description": bomJSON,
				},
			},
			handlerFunc: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, err := w.Write([]byte(`{"token":"6026693d-b182-4569-8ba1-0b2c0cc509be"}`))
				if err != nil {
					panic(err)
				}
			}),
		},
		{
			name: "not found title",
			fields: fields{
				Name:   "test",
				APIKey: "key",
			},
			args: args{
				content: map[string]string{
					"description": bomJSON,
				},
			},
			wantErr: "title key not found",
		},
		{
			name: "invalid title format",
			fields: fields{
				Name:   "test",
				APIKey: "key",
			},
			args: args{
				content: map[string]string{
					"title":       "invalid",
					"description": bomJSON,
				},
			},
			wantErr: "title key has wrong format",
		},
		{
			name: "invalid description format",
			fields: fields{
				Name:   "test",
				APIKey: "key",
			},
			args: args{
				content: map[string]string{
					"title":       "test-project:test-version",
					"description": "invalid",
				},
			},
			wantErr: "description key has wrong format: json: error calling MarshalJSON for type json.RawMessage: invalid character 'i' looking for beginning of value",
			handlerFunc: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}),
		},
		{
			name: "failed to upload BOM",
			fields: fields{
				Name:   "test",
				APIKey: "invalid",
			},
			args: args{
				content: map[string]string{
					"title":       "test-project:test-version",
					"description": bomJSON,
				},
			},
			wantErr: "failed to upload BOM: api error (status: 401)",
			handlerFunc: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
			}),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(tt.handlerFunc)
			defer ts.Close()

			url := tt.fields.Url
			if url == "" {
				url = ts.URL
			}

			dta := &DependencyTrackAction{
				Name:   tt.fields.Name,
				Url:    url,
				APIKey: tt.fields.APIKey,
			}

			err := dta.Send(tt.args.content)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				assert.NoError(t, err, tt.name)
			}
		})
	}
}
