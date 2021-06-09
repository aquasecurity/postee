package alertmgr

import "testing"

var (
	config1 string = `
Name: tenant

routes:
- name: route1
  outputs: ["my-slack"]
  template: raw
  plugins:
   Policy-Show-All: true

- name: route2
  outputs: ["my-slack2"]
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
  url: https://hooks.slack.com/services/ABCDF/1234/XYZ
- name: my-slack2
  type: slack
  enable: true
  url: https://hooks.slack.com/services/ABCDF/1234/TTT`

	payload = `{"image" : "alpine"}`
)

func TestHandling(t *testing.T) {
	tests := []struct {
		caseDesc      string
		cfg           string
		expctdInvctns []invctn
	}{
		{
			"basic config",
			config1,
			[]invctn{
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route1",
				},
				{
					"*outputs.SlackOutput", "*regoservice.regoEvaluator", "route2",
				},
			},
		},
	}
	actualInvctCnt := 0
	for _, test := range tests {
		wrap := ctxWrapper{}
		wrap.setup(test.cfg)

		defer wrap.teardown()

		err := wrap.instance.Start(wrap.cfgPath)
		if err != nil {
			t.Fatalf("[%s] Unexpected error %v", test.caseDesc, err)
		}

		wrap.instance.handle([]byte(payload))
		//TODO handle the case when it's invoked less than expected
		/*
			func TestWithTimeOut(t *testing.T) {
			  timeout := time.After(3 * time.Second)
			  done := make(chan bool)

			  go func() {

			    // do your testing here
			    testTheActualTest(t)

			    done <- true
			  }()

			  select {
			    case <-timeout:
			      t.Fatal("test didn't finish in time")
			    case <-done:
			  }
			}*/
		for i := 0; i < len(test.expctdInvctns); i++ {
			r := <-wrap.buff
			actualInvctCnt++
			found := false
			for _, expect := range test.expctdInvctns {
				if r == expect {
					found = true
					break
				}
			}
			if !found && len(test.expctdInvctns) > 0 {
				t.Errorf("[%s] Unexpected invocation (%s, %s, %s)", test.caseDesc, r.routeName, r.outputCls, r.templateCls)
			}
		}
		if actualInvctCnt != len(test.expctdInvctns) {
			t.Errorf("[%s] Service should be called %d times but called %d times", test.caseDesc, len(test.expctdInvctns), actualInvctCnt)
		}

	}

}
