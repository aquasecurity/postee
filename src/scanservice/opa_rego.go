package scanservice

import (
	"context"
	"encoding/json"
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
		switch rs[0].Bindings["x"].(type)  {
		case bool:
			return rs[0].Bindings["x"].(bool) , nil
		}
	}
	return false, nil
}
