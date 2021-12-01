package postgresdb

import (
	"errors"
	"log"
	"testing"

	"github.com/jmoiron/sqlx"
	sqlxmock "github.com/zhashkevych/go-sqlxmock"
)

var (
	AlpineImageKey    = "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1-alpine:3.8-Docker Hub"
	AlpineImageResult = `{
		"image": "alpine:3.8",
		"registry": "Docker Hub",
		"digest": "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"previous_digest": "sha256:c8bccc0af9571ec0d006a43acb5a8d08c4ce42b6cc7194dd6eb167976f501ef1",
		"image_assurance_results": {
			"disallowed": true,
			"checks_performed": [
				{
					"control": "max_severity",
					"policy_name": "Default",
					"failed": false
				},
				{
					"control": "trusted_base_images",
					"policy_name": "Default",
					"failed": true
				},
				{
					"control": "max_score",
					"policy_name": "Default",
					"failed": false
				}
			]
		},
		"vulnerability_summary": {
			"total": 2,
			"critical": 0,
			"high": 0,
			"medium": 2,
			"low": 0,
			"negligible": 0,
			"sensitive": 0,
			"malware": 0
		},
		"scan_options": {
			"scan_sensitive_data": true,
			"scan_malware": true
		},
		"resources": [
			{
				"vulnerabilities": [
					{
						"name": "CVE-2018-20679",
						"version": "",
						"fix_version": "",
						"aqua_severity": "medium"
					},
					{
						"name": "CVE-2019-5747",
						"version": "",
						"fix_version": "",
						"aqua_severity": "medium"
					}
				],
				"resource": {
					"name": "busybox",
					"version": "1.28.4-r3"
				}
			}
		]
	}`

	db = NewPostgresDb("id", "postgresql://user:secret@localhost/dbname?sslmode=disable")
)

func TestInitError(t *testing.T) {
	initErr := errors.New("init error")

	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("CREATE").WillReturnError(initErr)
		return db, err
	}
	defer func() {
		psqlConnect = savedPsqlConnect
	}()
	isNew, err := db.MayBeStoreMessage([]byte(AlpineImageResult), AlpineImageKey, nil)

	if isNew {
		t.Errorf("Scan shouldn't be marked as new\n")
	}

	if err.Error() != initErr.Error() {
		t.Errorf("Unexpected error: expected %s, got %s \n", initErr, err)
	}
}

func TestDeleteRow(t *testing.T) {
	t.Log("happy delete row")
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		savedDeleteRow := deleteRow
		defer func() {
			deleteRow = savedDeleteRow
		}()
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("DELETE").WillReturnResult(sqlxmock.NewResult(1, 1))
		return db, err
	}
	defer func() {
		psqlConnect = savedPsqlConnect
	}()

	psqlDb, _ := psqlConnect(db.ConnectUrl)
	err := deleteRow(psqlDb, "table", "id", "column", "value")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	t.Log("bad delete row")
	deleteError := errors.New("delete - error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		savedDeleteRow := deleteRow
		defer func() {
			deleteRow = savedDeleteRow
		}()
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("DELETE").WillReturnError(deleteError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = deleteRow(psqlDb, "table", "id", "column", "value")
	if deleteError != err {
		t.Errorf("Unexpected error, expected: %v, got: %v", deleteError, err)
	}
}
func TestDeleteRowsById(t *testing.T) {
	t.Log("happy delete rows by id")
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		savedDeleteRowsById := deleteRowsById
		defer func() {
			deleteRowsById = savedDeleteRowsById
		}()
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("DELETE").WillReturnResult(sqlxmock.NewResult(1, 1))
		return db, err
	}
	defer func() {
		psqlConnect = savedPsqlConnect
	}()

	psqlDb, _ := psqlConnect(db.ConnectUrl)
	err := deleteRowsById(psqlDb, "table", "id")
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	t.Log("bad delete row")
	deleteError := errors.New("delete - error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		savedDeleteRowsById := deleteRowsById
		defer func() {
			deleteRowsById = savedDeleteRowsById
		}()
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("DELETE").WillReturnError(deleteError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = deleteRowsById(psqlDb, "table", "id")
	if deleteError != err {
		t.Errorf("Unexpected error, expected: %v, got: %v", deleteError, err)
	}
}

func TestInsertAndInsertOutputStats(t *testing.T) {
	t.Log("happy insert")
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(0)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		mock.ExpectExec("INSERT").WillReturnResult(sqlxmock.NewResult(1, 1))
		return db, err
	}
	defer func() {
		psqlConnect = savedPsqlConnect
	}()

	psqlDb, _ := psqlConnect(db.ConnectUrl)
	err := insert(psqlDb, "table", "id", "column2", "value2", "column3", "value3")
	if err != nil {
		t.Errorf("Unexpected error in 'insert': %v", err)
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != nil {
		t.Errorf("Unexpected error in 'insertOutputStats': %v", err)
	}

	t.Log("happy update")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		mock.ExpectExec("UPDATE").WillReturnResult(sqlxmock.NewResult(1, 1))
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insert(psqlDb, "table", "id", "column2", "value2", "column3", "value3")
	if err != nil {
		t.Errorf("Unexpected error in 'insert': %v", err)
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != nil {
		t.Errorf("Unexpected error in 'insertOutputStats': %v", err)
	}

	t.Log("bad select")
	badSelectError := errors.New("bad select")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectQuery("SELECT").WillReturnError(badSelectError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insert(psqlDb, "table", "id", "column2", "value2", "column3", "value3")
	if err != badSelectError {
		t.Errorf("Unexpected error in 'insert', expected: %v, got: %v", badSelectError, err)
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != badSelectError {
		t.Errorf("Unexpected error in 'insertOutputStats', expected: %v, got: %v", badSelectError, err)
	}

	t.Log("bad insert")
	badInsertError := errors.New("bad insert")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(0)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		mock.ExpectExec("INSERT").WillReturnError(badInsertError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insert(psqlDb, "table", "id", "column2", "value2", "column3", "value3")
	if err != badInsertError {
		t.Errorf("Unexpected error in 'insert', expected: %v, got: %v", badInsertError, err)
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != badInsertError {
		t.Errorf("Unexpected error in 'insertOutputStats', expected: %v, got: %v", badInsertError, err)
	}

	t.Log("bad update")
	badUpdateError := errors.New("bad update")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(1)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		mock.ExpectExec("UPDATE").WillReturnError(badUpdateError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insert(psqlDb, "table", "id", "column2", "value2", "column3", "value3")
	if err != badUpdateError {
		t.Errorf("Unexpected error in 'insert', expected: %v, got: %v", badUpdateError, err)
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != badUpdateError {
		t.Errorf("Unexpected error in 'insertOutputStats', expected: %v, got: %v", badUpdateError, err)
	}
}
