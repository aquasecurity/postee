package formatting

import "testing"

func TestSlackMrkdwn(t *testing.T) {
	tests := []tagsTest{
		{
			"Lorem Ipsum",
			"red",
			"url",
			"*Lorem Ipsum*",
			"{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Lorem Ipsum*\"}},",
			"{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Lorem Ipsum*\"}},",
			"{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"*Lorem Ipsum*\"}},",
			"{\"type\":\"section\",\"text\":{\"type\":\"mrkdwn\",\"text\":\"Lorem Ipsum\"}},",
			"<url|Lorem Ipsum>",
		},
	}
	tagsTesting(tests, t, new(SlackMrkdwnProvider))
}

func TestSlackMrkdwnProvider_Table(t *testing.T) {
	var tests = []tableTest{
		{
			source: [][]string{
				{"Header1", "Header2"},
				{"Field1", "Field2"},
			},
			result: `{"type":"section","fields":[{"type":"mrkdwn","text":"*Header1*"},{"type":"mrkdwn","text":"*Header2*"},{"type":"mrkdwn","text":"Field1"},{"type":"mrkdwn","text":"Field2"}]},`,
		},
		{
			source: [][]string{
				{"Header1", "Header2", "Header3"},
				{"Field1", "Field2", "Field3"},
			},
			result: `{"type":"section","fields":[{"type":"mrkdwn","text":"*Header1*"},{"type":"mrkdwn","text":"*Header2* / *Header3*"},{"type":"mrkdwn","text":"Field1"},{"type":"mrkdwn","text":"Field2 / Field3"}]},`,
		},
		{
			source: [][]string{
				{"Critical", "High", "Medium", "Low", "Negligible"},
				{"Field10", "Field5", "Field3", "F27", "F232"},
			},
			result: `{"type":"section","fields":[{"type":"mrkdwn","text":"*Critical*"},{"type":"mrkdwn","text":"Field10"},{"type":"mrkdwn","text":"*High*"},{"type":"mrkdwn","text":"Field5"},{"type":"mrkdwn","text":"*Medium*"},{"type":"mrkdwn","text":"Field3"},{"type":"mrkdwn","text":"*Low*"},{"type":"mrkdwn","text":"F27"},{"type":"mrkdwn","text":"*Negligible*"},{"type":"mrkdwn","text":"F232"}]},`,
		},
	}
	tableTesting(tests, t, new(SlackMrkdwnProvider))
}
