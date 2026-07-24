package layout

import "testing"

// shortRowProvider is a minimal LayoutProvider for exercising VulnerabilitiesTable.
type shortRowProvider struct{}

func (shortRowProvider) TitleH1(title string) string          { return title }
func (shortRowProvider) TitleH2(title string) string          { return title }
func (shortRowProvider) TitleH3(title string) string          { return title }
func (shortRowProvider) ColourText(text, color string) string { return text }
func (shortRowProvider) Table(rows [][]string) string         { return "table" }
func (shortRowProvider) P(p string) string                    { return p }
func (shortRowProvider) A(url, title string) string           { return url }

func TestVulnerabilitiesTableShortRowReturnsEmpty(t *testing.T) {
	// rows[1] has only 3 columns, not the 5 the function indexes into.
	// The guard is supposed to reject this and return "".
	rows := [2][]string{
		{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"},
		{"1", "2", "3"},
	}
	got := VulnerabilitiesTable(shortRowProvider{}, rows)
	if got != "" {
		t.Fatalf("expected empty string for a short row, got %q", got)
	}
}

func TestVulnerabilitiesTableFullRowRenders(t *testing.T) {
	rows := [2][]string{
		{"CRITICAL", "HIGH", "MEDIUM", "LOW", "NEGLIGIBLE"},
		{"1", "2", "3", "4", "5"},
	}
	if got := VulnerabilitiesTable(shortRowProvider{}, rows); got != "table" {
		t.Fatalf("expected the table to render, got %q", got)
	}
}
