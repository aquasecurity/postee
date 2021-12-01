package postgresdb

import (
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

func TestAggregateScans(t *testing.T) {
	var (
		scan1 = map[string]string{"title": "t1", "description": "d1"}
		scan2 = map[string]string{"title": "t2", "description": "d2"}
		scan3 = map[string]string{"title": "t3", "description": "d3"}
		scan4 = map[string]string{"title": "t4", "description": "d4"}
	)

	var tests = []struct {
		output         string
		currentScan    map[string]string
		scansPerTicket int
		want           []map[string]string
	}{
		{
			"jira",
			scan1,
			3,
			nil,
		},
		{
			"jira",
			scan2,
			3,
			nil,
		},
		{
			"jira",
			scan3,
			3,
			[]map[string]string{scan3, scan2, scan1},
		},
		{
			"jira",
			scan4,
			3,
			nil,
		},
	}

	saving := ""
	for i := 0; i < len(tests); i++ {
		savedInitTable := initTable
		initTable = func(db *sqlx.DB, tableName string) error { return nil }
		savedInsert := insert
		insert = func(db *sqlx.DB, table, id, columnName2, value2, columnName3, value3 string) error {
			saving = value3
			return nil
		}
		savedPsqlConnect := psqlConnect
		psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
			db, mock, err := sqlxmock.Newx()
			if err != nil {
				log.Println("failed to open sqlmock database:", err)
			}
			rows := sqlxmock.NewRows([]string{"saving"}).AddRow(saving)
			mock.ExpectQuery("SELECT").WillReturnRows(rows)
			return db, err
		}
		defer func() {
			initTable = savedInitTable
			insert = savedInsert
			psqlConnect = savedPsqlConnect
		}()

		test := tests[i]
		aggregated, err := db.AggregateScans(test.output, test.currentScan, test.scansPerTicket, false)
		if err != nil {
			t.Errorf("AggregateScans Error: %v", err)
			continue
		}

		if len(aggregated) != len(test.want) {
			t.Errorf("Wrong result size\nResult: %v\nWaited: %v", aggregated, test.want)
			continue
		}

		for i := 0; i < len(aggregated); i++ {
			if aggregated[i]["title"] != test.want[i]["title"] {
				t.Errorf("Wrong title\nResult: %q\nWaited: %q", aggregated[i]["title"], test.want[i]["title"])
			}
			if aggregated[i]["description"] != test.want[i]["description"] {
				t.Errorf("Wrong Description\nResult: %q\nWaited: %q", aggregated[i]["description"], test.want[i]["description"])
			}
		}
	}

	// Test of existence last scan in DB
	lastScan, err := db.AggregateScans("jira", nil, 0, false)
	if err != nil {
		t.Fatalf("AggregateScans Error: %v", err)
	}

	if len(lastScan) != 1 {
		t.Fatalf("Db don't contain last scan")
	}

	if lastScan[0]["title"] != scan4["title"] {
		t.Errorf("Wrong title\nResult: %q\nWaited: %q", lastScan[0]["title"], scan4["title"])
	}
	if lastScan[0]["description"] != scan4["description"] {
		t.Errorf("Wrong Description\nResult: %q\nWaited: %q", lastScan[0]["description"], scan4["description"])
	}
}
