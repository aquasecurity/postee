package layout

import (
	"bytes"
	"data"
)

func RenderSensitiveData(sensitive []data.SensitiveData, provider LayoutProvider, builder *bytes.Buffer) {
	var table [][]string
	table = append(table, []string{"File name", "Path", "Type", "Hash"})

	for _, s := range sensitive {
		table = append(table, []string{s.Filename, s.Path, s.Type, s.Hash})
	}
	builder.WriteString(provider.Table(table))
}
