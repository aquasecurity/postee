package scanservice

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
)

func isRegoCorrect(files []string, scanResult string) (bool, error) {
	ctx := context.Background()

	r := rego.New(
		rego.Query("x = data.postee.allow"),
		rego.Load(files, nil))

	query, err := r.PrepareForEval(ctx)
	if err != nil {
		return false, err
	}

	var input interface{}
	if err := json.Unmarshal([]byte(scanResult), &input); err != nil {
		return false, err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}

	if len(rs) > 0 {

		fmt.Println("Result:", rs[0].Bindings["x"])
		//		return rs[0].Bindings["x"], nil
	}
	return false, nil
}
