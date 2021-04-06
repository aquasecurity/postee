package layout

type LayoutProvider interface {
	TitleH1(title string) string
	TitleH2(title string) string
	TitleH3(title string) string
	ColourText(text, color string) string
	Table(rows [][]string) string
	P(p string) string
	A(url, title string) string
}
