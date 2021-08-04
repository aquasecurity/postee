package router

import (
	"testing"
	"time"

	"github.com/aquasecurity/postee/routes"
)

var (
	singleRoute = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Outputs:  []string{"my-slack"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}

	noAssociatedOutput = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}
	twoRoutes = &TenantSettings{
		InputRoutes: []routes.InputRoute{
			{

				Name:     "route1",
				Outputs:  []string{"my-slack"},
				Template: "raw",
				Plugins: routes.Plugins{
					PolicyShowAll: true,
				},
			},
			{

				Name:     "route2",
				Outputs:  []string{"my-slack"},
				Template: "raw",
				Plugins: routes.Plugins{
					PolicyShowAll: true,
				},
			}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}
	twoOutputs = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Outputs:  []string{"my-slack", "my-slack2"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/XXX",
			},
			{
				Name:   "my-slack2",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}
	noOutputs = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Outputs:  []string{"my-slack"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
	}
	noTemplates = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Outputs:  []string{"my-slack"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/XXX",
			},
			{
				Name:   "my-slack2",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}
	invalidTemplate = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Outputs:  []string{"my-slack"},
			Template: "rawx",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}
	invalidOutput = &TenantSettings{
		InputRoutes: []routes.InputRoute{{

			Name:     "route1",
			Outputs:  []string{"x-slack"},
			Template: "raw",
			Plugins: routes.Plugins{
				PolicyShowAll: true,
			},
		}},
		Templates: []Template{
			{
				Name: "raw",
				Body: `package postee
result:=input`,
			},
		},
		Outputs: []OutputSettings{
			{
				Name:   "my-slack",
				Type:   "slack",
				Enable: true,
				Url:    "https://hooks.slack.com/services/ABCDF/1234/TTT",
			},
		},
	}

	payload = `{"image" : "alpine"}`
)

func TestHandling(t *testing.T) {
	tests := []struct {
		caseDesc      string
		cfg           *TenantSettings
		expctdInvctns []invctn
	}{
		{
			"Single Route",
			singleRoute,
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1",
				},
			},
		},
		{
			"2 Routes",
			twoRoutes,
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1",
				},
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route2",
				},
			},
		},
		{
			"2 Outputs per single route",
			twoOutputs,
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1",
				},
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1",
				},
			},
		},
		{
			"No Outputs configured",
			noOutputs,
			[]invctn{},
		},
		{
			"No Template configured",
			noTemplates,
			[]invctn{},
		},
		{
			"Invalid Output reference",
			invalidOutput,
			[]invctn{},
		},
		{
			"Invalid Template reference",
			invalidTemplate,
			[]invctn{},
		},
		{
			"No outputs associated with route",
			noAssociatedOutput,
			[]invctn{},
		},
	}
	for _, test := range tests {
		runTestRouteHandlingCase(t, test.caseDesc, test.cfg, test.expctdInvctns)
	}
}
func runTestRouteHandlingCase(t *testing.T, caseDesc string, cfg *TenantSettings, expctdInvctns []invctn) {
	actualInvctCnt := 0
	t.Logf("Case: %s\n", caseDesc)
	wrap := ctxWrapper{}
	wrap.setup(cfg)

	defer wrap.teardown()

	wrap.instance.handle([]byte(payload))
	timeoutDuration := 3 * time.Second
	if len(expctdInvctns) == 0 {
		timeoutDuration = time.Second
	}
	timeout := time.After(timeoutDuration)
	for {
		select {
		case <-timeout:
			if len(expctdInvctns) > 0 {
				t.Fatal("test didn't finish in time")
			}
			return
		case r := <-wrap.buff:
			t.Logf("[%s] received invocation (%s, %s, %s)", caseDesc, r.routeName, r.outputCls, r.templateCls)
			actualInvctCnt++
			found := false
			for _, expect := range expctdInvctns {
				if r == expect {
					found = true
					break
				}
			}
			if actualInvctCnt == len(expctdInvctns) {
				return //everything is ok, exiting
			}
			if !found && len(expctdInvctns) > 0 {
				t.Errorf("[%s] Unexpected invocation (%s, %s, %s)", caseDesc, r.routeName, r.outputCls, r.templateCls)
				return
			}
			if actualInvctCnt > len(expctdInvctns) {
				t.Errorf("[%s] Service should be called %d times but called %d times", caseDesc, len(expctdInvctns), actualInvctCnt)
				return
			}
		}
	}

}
func TestInvalidRouteName(t *testing.T) {
	expctdInvctns := 0
	actualInvctCnt := 0
	wrap := ctxWrapper{}
	wrap.setup(singleRoute)

	defer wrap.teardown()

	wrap.instance.HandleRoute("not-exist", []byte(payload))
	timeout := time.After(1 * time.Second)
	for {
		select {
		case <-timeout:
			return
		case <-wrap.buff:
			actualInvctCnt++
			if actualInvctCnt > expctdInvctns {
				t.Errorf("Service shouldn't be called if invalid route is specified")
				return
			}
		}
	}

}
func TestSend(t *testing.T) {
	expctdInvctns := 1
	actualInvctCnt := 0
	wrap := ctxWrapper{}
	wrap.setup(singleRoute)

	defer wrap.teardown()

	wrap.instance.Send([]byte(payload))
	timeout := time.After(1 * time.Second)
	for {
		select {
		case <-timeout:
			return
		case <-wrap.buff:
			actualInvctCnt++
			if actualInvctCnt != expctdInvctns {
				t.Errorf("Service shouldn't be called once")
				return
			}
		}
	}
}
