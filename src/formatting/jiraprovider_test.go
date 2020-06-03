package formatting

import "testing"

func TestJiraLayoutProvider_Tags(t *testing.T) {
	tests := []tagsTest {
		{
			"Lorem Ipsum",
			"red",
			"{color:red}Lorem Ipsum{color}",
			"h1. Lorem Ipsum\n",
			"h2. Lorem Ipsum\n",
			"h3. Lorem Ipsum\n",
			"Lorem Ipsum\n",
		},
	}
	tagsTesting(tests, t, new(JiraLayoutProvider))
}

func TestJiraLayoutProvider_Table(t *testing.T) {
	var tests = []tableTest {
		{
			source: [][]string{
				{"Header1", "Header2",},
				{"Field1", "Field2",},
			},
			result:`||Header1||Header2||
|Field1|Field2|

`,
		},
	}
	tableTesting(tests, t, new(JiraLayoutProvider))
}
