package formatting

import (
	"bytes"
	"data"
	"encoding/json"
	"fmt"
	"log"
)

func getMrkdwnText(text string) string {
	block := &data.SlackBlock{
		TypeField: "section",
		TextField: &data.SlackTextBlock{
			TypeField: "mrkdwn",
			TextField: text,
		},
	}
	result,err := json.Marshal(block)
	if err != nil {
		log.Printf("SlackMrkdwnProvider Error: %v", err)
		return ""
	}
	result = append(result, ',')
	return string(result)
}

type SlackMrkdwnProvider struct {}

func (mrkdwn *SlackMrkdwnProvider) TitleH2(title string) string {
	return getMrkdwnText(fmt.Sprintf("*%s*", title))
}

func (mrkdwn *SlackMrkdwnProvider) TitleH3(title string) string {
	return mrkdwn.TitleH2(title)
}

func (mrkdwn *SlackMrkdwnProvider) ColourText(text, color string) string {
	return fmt.Sprintf("*%s*", text)
}

func (mrkdwn *SlackMrkdwnProvider) Table(rows [][]string) string {
	if len(rows) == 0 {
		return ""
	}
	var builder bytes.Buffer

	fields := &data.SlackBlock{
		TypeField: "section",
	}
	if len(rows) == 2 && len(rows[0]) == 5 {
		fields.Fields = make([]data.SlackTextBlock, 2*len(rows[0]))
		for i, r := range rows {
			for j, f := range r {
				if i == 0 {
					fields.Fields[j*2] = data.SlackTextBlock{
						TypeField: "mrkdwn",
						TextField: fmt.Sprintf("*%s*", f),
					}
				} else {
					fields.Fields[j*2+1] = data.SlackTextBlock{
						TypeField: "mrkdwn",
						TextField: f,
					}
				}
			}
		}
	} else {
		totalRows := len(rows)
		for line, r := range rows {
			if line%5 == 0 {
				if fields.Fields != nil {
					block,err := json.Marshal(fields)
					if err != nil {
						log.Printf("SlackMrkdwnProvider Error: %v", err)
						return ""
					}
					builder.Write(block)
					builder.WriteByte(',')
				}
				fields = new(data.SlackBlock)
				fields.TypeField = "section"
				current := 5
				if (totalRows-line) < 5 {
					current = totalRows-line
				}
				fields.Fields = make([]data.SlackTextBlock,  current*2)
			}
			var cell1, cell2 bytes.Buffer
			for j, f := range r {
				bold := ""
				if line == 0 {
					bold = "*"
				}
				switch j {
				case 0:
					fmt.Fprintf(&cell1, "%s%s%s", bold, f, bold)
				case 1:
					if rows[0][0] == "#" {
						fmt.Fprintf(&cell1, " %s%s%s", bold, f, bold)
					} else {
						fmt.Fprintf(&cell2, "%s%s%s / ", bold, f, bold)
					}
				default:
					if j > 2 {
						cell2.WriteString(" / ")
					}
					fmt.Fprintf(&cell2, "%s%s%s", bold, f, bold)
				}
			}
			fields.Fields[(line%5)*2] = data.SlackTextBlock{
				TypeField: "mrkdwn",
				TextField: cell1.String(),
			}
			fields.Fields[(line%5)*2+1] = data.SlackTextBlock{
				TypeField: "mrkdwn",
				TextField: cell2.String(),
			}
		}
	}
	result,err := json.Marshal(fields)
	if err != nil {
		log.Printf("SlackMrkdwnProvider Error: %v", err)
		return ""
	}
	builder.Write(result)
	builder.WriteByte(',')
	return builder.String()
}

func (mrkdwn *SlackMrkdwnProvider) P(p string) string {
	return getMrkdwnText(p)
}
