package postgresdb

import (
	"errors"
	"log"
	"testing"
	"time"

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
	initTablesErr := errors.New("init tables error")
	testConnectErr := errors.New("test connect error")

	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("CREATE").WillReturnError(initTablesErr)
		return db, err
	}

	err := InitPostgresDb("connectUrl")
	if err.Error() != initTablesErr.Error() {
		t.Errorf("Unexpected error: expected %s, got %s \n", initTablesErr, err)
	}

	savedTestConnect := testConnect
	testConnect = func(connectUrl string) (*sqlx.DB, error) { return nil, testConnectErr }
	defer func() {
		psqlConnect = savedPsqlConnect
		testConnect = savedTestConnect
	}()
	err = InitPostgresDb("ConnectUrl")
	if err.Error() != testConnectErr.Error() {
		t.Errorf("Unexpected error: expected %s, got %s \n", testConnectErr, err)
	}
}

func TestDeleteRowsByIdAndTime(t *testing.T) {
	t.Log("happy delete row")
	savedPsqlConnect := psqlConnect
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		savedDeleteRow := deleteRowsByIdAndTime
		defer func() {
			deleteRowsByIdAndTime = savedDeleteRow
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
	err := deleteRowsByIdAndTime(psqlDb, "id", time.Now())
	if err != nil {
		t.Errorf("Unexpected error: %v", err)
	}

	t.Log("bad delete row")
	deleteError := errors.New("delete - error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		savedDeleteRow := deleteRowsByIdAndTime
		defer func() {
			deleteRowsByIdAndTime = savedDeleteRow
		}()
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectExec("DELETE").WillReturnError(deleteError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = deleteRowsByIdAndTime(psqlDb, "id", time.Now())
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

func TestInsertInTableSharedConfig(t *testing.T) {
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
	err := insertInTableSharedConfig(psqlDb, "id", "value2", "value3")
	if err != nil {
		t.Errorf("Unexpected error in 'insertInTableSharedConfig': %v", err)
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
	err = insertInTableSharedConfig(psqlDb, "id", "value2", "value3")
	if err != nil {
		t.Errorf("Unexpected error in 'insertInTableSharedConfig': %v", err)
	}

	t.Log("select error")
	selectError := errors.New("select error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectQuery("SELECT").WillReturnError(selectError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertInTableSharedConfig(psqlDb, "id", "value2", "value3")
	if err != selectError {
		t.Errorf("Unexpected error in 'insertInTableSharedConfig', expected: %v, got: %v", selectError, err)
	}

	t.Log("select 2 rows")
	select2RowsError := "error insert in postgresDb. Table:WebhookSharedConfig where id=id, apikeyname=value2, have 2 rows"
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(2)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertInTableSharedConfig(psqlDb, "id", "value2", "value3")
	if err.Error() != select2RowsError {
		t.Errorf("Unexpected error in 'insertInTableSharedConfig', expected: %v, got: %v", select2RowsError, err)
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
	err = insertInTableSharedConfig(psqlDb, "id", "value2", "value3")
	if err != badInsertError {
		t.Errorf("Unexpected error in 'insertInTableSharedConfig', expected: %v, got: %v", badInsertError, err)
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
	err = insertInTableSharedConfig(psqlDb, "id", "value2", "value3")
	if err != badUpdateError {
		t.Errorf("Unexpected error in 'insertInTableSharedConfig', expected: %v, got: %v", badUpdateError, err)
	}
}

func TestInsertInTableAggregator(t *testing.T) {
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
	err := insertInTableAggregator(psqlDb, "id", "value2", []byte("value3"))
	if err != nil {
		t.Errorf("Unexpected error in 'insert': %v", err)
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
	err = insertInTableAggregator(psqlDb, "id", "value2", []byte("value3"))
	if err != nil {
		t.Errorf("Unexpected error in 'insertInTableAggregator': %v", err)
	}

	t.Log("select error")
	selectError := errors.New("select error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectQuery("SELECT").WillReturnError(selectError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertInTableAggregator(psqlDb, "id", "value2", []byte("value3"))
	if err != selectError {
		t.Errorf("Unexpected error in 'insertInTableAggregator', expected: %v, got: %v", selectError, err)
	}

	t.Log("select 2 rows")
	select2RowsError := "error insert in postgresDb. Table:WebhookAggregator where id=id, output=value2, have 2 rows"
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(2)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertInTableAggregator(psqlDb, "id", "value2", []byte("value3"))
	if err.Error() != select2RowsError {
		t.Errorf("Unexpected error in 'insertInTableAggregator', expected: %v, got: %v", select2RowsError, err)
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
	err = insertInTableAggregator(psqlDb, "id", "value2", []byte("value3"))
	if err != badInsertError {
		t.Errorf("Unexpected error in 'insertInTableAggregator', expected: %v, got: %v", badInsertError, err)
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
	err = insertInTableAggregator(psqlDb, "id", "value2", []byte("value3"))
	if err != badUpdateError {
		t.Errorf("Unexpected error in 'insertInTableAggregator', expected: %v, got: %v", badUpdateError, err)
	}
}

func TestInsertOutputStats(t *testing.T) {
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
	err := insertOutputStats(psqlDb, "id", "outputName", 1)
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
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != nil {
		t.Errorf("Unexpected error in 'insertOutputStats': %v", err)
	}

	t.Log("select error")
	selectError := errors.New("select error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectQuery("SELECT").WillReturnError(selectError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != selectError {
		t.Errorf("Unexpected error in 'insertOutputStats', expected: %v, got: %v", selectError, err)
	}

	t.Log("select 2 rows")
	select2RowsError := "error insert in postgresDb. Table:WebhookOutputStats where id=id, outputName=outputName, have 2 rows"
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(2)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err.Error() != select2RowsError {
		t.Errorf("Unexpected error in 'insertOutputStats', expected: %v, got: %v", select2RowsError, err)
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
	err = insertOutputStats(psqlDb, "id", "outputName", 1)
	if err != badUpdateError {
		t.Errorf("Unexpected error in 'insertOutputStats', expected: %v, got: %v", badUpdateError, err)
	}
}

func TestInsertInTableName(t *testing.T) {
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
	err := insertInTableName(psqlDb, "id", "messageKey", []byte("messageValue"), nil)
	if err != nil {
		t.Errorf("Unexpected error in 'insertInTableName': %v", err)
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
	err = insertInTableName(psqlDb, "id", "messageKey", []byte("messageValue"), nil)
	if err != nil {
		t.Errorf("Unexpected error in 'insertInTableName': %v", err)
	}

	t.Log("select error")
	selectError := errors.New("select error")
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		mock.ExpectQuery("SELECT").WillReturnError(selectError)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertInTableName(psqlDb, "id", "messageKey", []byte("messageValue"), nil)
	if err != selectError {
		t.Errorf("Unexpected error in 'insertInTableName', expected: %v, got: %v", selectError, err)
	}

	t.Log("select 2 rows")
	select2RowsError := "error insert in postgresDb. Table:WebhookBucket where id=id, messageKey=messageKey, have 2 rows"
	psqlConnect = func(connectUrl string) (*sqlx.DB, error) {
		db, mock, err := sqlxmock.Newx()
		if err != nil {
			log.Println("failed to open sqlmock database:", err)
		}
		rows := sqlxmock.NewRows([]string{"count"}).AddRow(2)
		mock.ExpectQuery("SELECT").WillReturnRows(rows)
		return db, err
	}
	psqlDb, _ = psqlConnect(db.ConnectUrl)
	err = insertInTableName(psqlDb, "id", "messageKey", []byte("messageValue"), nil)
	if err.Error() != select2RowsError {
		t.Errorf("Unexpected error in 'insertInTableName', expected: %v, got: %v", select2RowsError, err)
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
	err = insertInTableName(psqlDb, "id", "messageKey", []byte("messageValue"), nil)
	if err != badInsertError {
		t.Errorf("Unexpected error in 'insertInTableName', expected: %v, got: %v", badInsertError, err)
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
	err = insertInTableName(psqlDb, "id", "messageKey", []byte("messageValue"), nil)
	if err != badUpdateError {
		t.Errorf("Unexpected error in 'insertInTableName', expected: %v, got: %v", badUpdateError, err)
	}
}
