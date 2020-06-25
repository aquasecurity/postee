package dbservice

import (
	"os"
	"testing"
	"time"
)
func TestExpiredDates(t *testing.T) {
	dbPathReal := DbPath
	realDueDate := DbDueDate
	realDueTimeBase := dueTimeBase
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
		DbDueDate = realDueDate
		dueTimeBase = realDueTimeBase
	}()
	dueTimeBase = time.Nanosecond
	DbPath = "test_webhooks.db"
	tests := []struct {
		title string
		limit int
		needRun bool
		isNew bool
	}{
		{ "First scan", 0, false, true },
		{ "Second scan", 0, true, false },
		{ "Third scan", 1, true, true },
	}

	DbDueDate = 1
	checkExpiredData()

	for _, test := range tests {
		t.Log(test.title)
		DbDueDate = test.limit
		if test.needRun {
			checkExpiredData()
		}

		_, isNew, err := HandleCurrentInfo(&AlpineImageResult)
		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if isNew != test.isNew {
			t.Errorf("Error handling! Want isNew: %t, rgot: %t", test.isNew, isNew)
		}
	}
}

func TestDbSizeLimnit(t *testing.T) {
	dbPathReal := DbPath
	realSizeLimit := DbSizeLimit
	defer func() {
		os.Remove(DbPath)
		DbPath = dbPathReal
		DbSizeLimit = realSizeLimit
	}()
	DbPath = "test_webhooks.db"

	tests := []struct {
		title string
		limit int
		needRun bool
		isNew bool
	}{
		{ "First scan", 0, false, true },
		{ "Second scan", 0, true, false },
		{ "Third scan", 1, true, true },
	}

	DbSizeLimit = 1
	checkSizeLimit()

	for _, test := range tests {
		t.Log(test.title)
		DbSizeLimit = test.limit
		if test.needRun {
			checkSizeLimit()
		}

		_, isNew, err := HandleCurrentInfo(&AlpineImageResult)
		if err != nil {
			t.Fatal("First Add AlpineImageResult Error", err)
		}

		if isNew != test.isNew {
			t.Errorf("Error handling! Want isNew: %t, rgot: %t", test.isNew, isNew)
		}
	}
}