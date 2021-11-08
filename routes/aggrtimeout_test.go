package routes

import "testing"

var (
	tests = []struct {
		caseDesc      string
		timeout       string
		expctdSeconds int
	}{
		{
			"One minute",
			"1m",
			60,
		},
		{
			"Six hundredths seconds",
			"600s",
			600,
		},
		{
			"Two hours",
			"2h",
			7200,
		},
		{
			"Two days",
			"2d",
			172800,
		},
		{
			"Two days with space between",
			"2 d",
			172800,
		},
		{
			"Exact number of seconds",
			"300",
			300,
		},
		{
			"Invalid format",
			"xxxl",
			0,
		},
		{
			"Empty string",
			"",
			0,
		},
		{
			"a space",
			" ",
			0,
		},
	}
)

func TestTimeouts(t *testing.T) {
	for _, test := range tests {
		route := &InputRoute{}
		route.Plugins.AggregateMessageTimeout = test.timeout
		route.Plugins.UniqueMessageTimeout = test.timeout
		route = ConfigureTimeouts(route)
		if route.Plugins.AggregateTimeoutSeconds != test.expctdSeconds {
			t.Errorf("[%s] Invalid number of seconds in AggregateTimeoutSeconds, expected %d, got %d \n", test.caseDesc, test.expctdSeconds, route.Plugins.AggregateTimeoutSeconds)
		}
		if route.Plugins.UniqueMessageTimeoutSeconds != test.expctdSeconds {
			t.Errorf("[%s] Invalid number of seconds in UniqueMessageTimeout, expected %d, got %d \n", test.caseDesc, test.expctdSeconds, route.Plugins.UniqueMessageTimeoutSeconds)
		}
	}

}
