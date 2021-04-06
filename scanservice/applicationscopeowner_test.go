package scanservice

import (
	"github.com/aquasecurity/postee/dbservice"
	"encoding/json"
	"os"
	"github.com/aquasecurity/postee/plugins"
	"strings"
	"testing"
)

func TestApplicationScopeOwner(t *testing.T) {
	dbPathReal := dbservice.DbPath
	defer func() {
		os.Remove(dbservice.DbPath)
		dbservice.DbPath = dbPathReal
	}()
	dbservice.DbPath = "test_webhooks.db"

	srv := new(ScanService)

	b, err := json.Marshal(AshexPokemongoResult)
	if err != nil {
		panic(err)
	}

	email := &MockPlugin{
		sender: func(data map[string]string) error {
			emails := strings.Split(data["owners"], ";")
			count := len(AshexPokemongoResult.ApplicationScopeOwners)
			if l := len(emails); l != count {
				t.Errorf("failed emails number! waited %d, got: %d", count, l)
				return nil
			}
			m := make(map[string]bool)
			for _, e := range emails {
				m[e] = true
			}
			for _, e := range AshexPokemongoResult.ApplicationScopeOwners {
				if !m[e] {
					t.Errorf("can't find %q in result %v", e, emails)
				}
			}
			return nil
		},
	}
	plugins := map[string]plugins.Plugin{
		"email": email,
	}
	srv.ResultHandling(string(b), plugins)
}
