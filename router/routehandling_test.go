package router

import (
	"io/ioutil"
	"path/filepath"
	"testing"
	"time"
)

var (
	singleRoute string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack"]
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	noAssociatedOutput string = `
Name: tenant

routes:
- name: route1
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	twoRoutes string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack"]
  template: raw
  plugins:
   Policy-Show-All: true

- name: route2
  outputs: ["my-slack"]
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`

	twoOutputs string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack", "my-slack2"]
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/XXX
- name: my-slack2
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	noOutputs string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack3"]
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input`
	noTemplates string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack", "my-slack2"]
  template: raw
  plugins:
   Policy-Show-All: true

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/XXX
- name: my-slack2
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	invalidTemplate string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack"]
  template: rawx
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	invalidOutput string = `
Name: tenant

routes:
- name: route1
  outputs: ["x-slack"]
  template: raw
  plugins:
   Policy-Show-All: true

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	singleRouteSingelInput string = `
Name: tenant

routes:
- name: fail_evaluation
  outputs: ["my-slack"]
  template: raw
  input-files:
   - Allow-Registry.rego

templates:
- name: raw
  body: |
   package postee
   result:=input

outputs:
- name: my-slack
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`
	payload = `{"image" : "alpine"}`
)

func TestHandling(t *testing.T) {
	tests := []struct {
		caseDesc      string
		cfgPath       string
		expctdInvctns []invctn
	}{
		{
			"Single Route",
			"single-route.yaml",
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1", false,
				},
			},
		},
		{
			"2 Routes",
			"two-routes.yaml",
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1", false,
				},
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route2", false,
				},
			},
		},
		{
			"2 Outputs per single route",
			"two-outputs.yaml",
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1", false,
				},
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1", false,
				},
			},
		},
		{
			"No Outputs configured",
			"no-outputs.yaml",
			[]invctn{},
		},
		{
			"No Template configured",
			"no-templates.yaml",
			[]invctn{},
		},
		{
			"Invalid Output reference",
			"invalid-output.yaml",
			[]invctn{},
		},
		{
			"Invalid Template reference",
			"invalid-template.yaml",
			[]invctn{},
		},
		{
			"No outputs associated with route",
			"no-associated-output.yaml",
			[]invctn{},
		},
		{
			"Route with input filter",
			"with-input-filter.yaml",
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1", false,
				},
			},
		},
		{
			"Route with input filter - no match",
			"with-input-filter-no-match.yaml",
			[]invctn{},
		},
		{
			"Route with input filter (empty)",
			"with-input-filter-empty.yaml",
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1", false,
				},
			},
		},
		{
			"Route with input filter - invalid",
			"with-input-filter-invalid.yaml",
			[]invctn{},
		},
	}
	for _, test := range tests {
		runTestRouteHandlingCase(t, test.caseDesc, test.cfgPath, test.expctdInvctns)
	}
}
func runTestRouteHandlingCase(t *testing.T, caseDesc string, cfgPath string, expctdInvctns []invctn) {
	actualInvctCnt := 0
	t.Logf("Case: %s\n", caseDesc)
	wrap := ctxWrapper{}

	b, err := ioutil.ReadFile(filepath.Join("testdata/configs", cfgPath))
	if err != nil {
		t.Errorf("Failed to open file %s, %s", cfgPath, err)
	}

	wrap.setup(string(b))

	defer wrap.teardown()

	err = wrap.instance.ApplyFileCfg(wrap.cfgPath, "", "", false)

	if err != nil {
		t.Fatalf("[%s] Unexpected error %v", caseDesc, err)
	}

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
			found := false
			for i, expect := range expctdInvctns {
				if r == expect {
					actualInvctCnt++
					t.Logf("r: %v\n", r)
					t.Logf("expect: %v\n", expect)
					found = true
					expctdInvctns[i].found = true // won't be matched anymore
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

	b, err := ioutil.ReadFile("testdata/configs/single-route.yaml")
	if err != nil {
		t.Errorf("Failed to open file %s, %s", "single-route.yaml", err)
	}

	wrap.setup(string(b))

	defer wrap.teardown()

	err = wrap.instance.ApplyFileCfg(wrap.cfgPath, "", "", false)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

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

func TestRouteWithNoValidRego(t *testing.T) {
	expctdInvctns := 0
	actualInvctCnt := 0
	wrap := ctxWrapper{}
	wrap.setup(singleRouteSingelInput)

	defer wrap.teardown()

	err := wrap.instance.Start(wrap.cfgPath)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

	wrap.instance.HandleRoute("fail_evaluation", []byte(payload))
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

	b, err := ioutil.ReadFile("testdata/configs/single-route.yaml")
	if err != nil {
		t.Errorf("Failed to open file %s, %s", "single-route.yaml", err)
	}

	wrap.setup(string(b))

	defer wrap.teardown()

	err = wrap.instance.ApplyFileCfg(wrap.cfgPath, "", "", false)
	if err != nil {
		t.Fatalf("Unexpected error %v", err)
	}

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

func TestCallBack(t *testing.T) {
	tests := []struct {
		name          string
		callback      InputCallbackFunc
		expctdInvctns int
	}{
		{
			name: "negative response",
			callback: func(inputMessage map[string]interface{}) bool {
				return false
			},
			expctdInvctns: 0,
		},
		{
			name: "positive response",
			callback: func(inputMessage map[string]interface{}) bool {
				return true
			},
			expctdInvctns: 1,
		},
		{
			name:          "no callback",
			callback:      nil,
			expctdInvctns: 1,
		},
	}
	b, err := ioutil.ReadFile("testdata/configs/single-route.yaml")

	if err != nil {
		t.Errorf("Failed to open file %s, %s", "single-route.yaml", err)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actualInvctCnt := 0
			wrap := ctxWrapper{}

			wrap.setup(string(b))

			defer wrap.teardown()

			err = wrap.instance.ApplyFileCfg(wrap.cfgPath, "", "", false)
			if err != nil {
				t.Fatalf("Unexpected error %v", err)
			}

			if tt.callback != nil {
				wrap.instance.setInputCallbackFunc("route1", tt.callback)
			}

			wrap.instance.handle([]byte(payload))
			timeout := time.After(1 * time.Second)
			for {
				select {
				case <-timeout:
					return
				case <-wrap.buff:
					actualInvctCnt++
					if actualInvctCnt != tt.expctdInvctns {
						t.Errorf("Incorrect number of invocations!  expected %d, got %d \n", tt.expctdInvctns, actualInvctCnt)
						return
					}
				}
			}
		})
	}
}
