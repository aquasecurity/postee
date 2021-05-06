package regoservice

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/aquasecurity/postee/utils"
	"github.com/open-policy-agent/opa/rego"
)

var (
	errNoResults = errors.New("there isn't result")
)

func BuildRegoTemplate(input map[string]interface{}, rule *string) ([]byte, error) {
	utils.Debug("Template Rules: %q", *rule)
	ctx := context.Background()
	r, err := rego.New(
		rego.Query("data.postee.result"),
		rego.Module("template.rego", *rule),
	).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}

	rs, err := r.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errNoResults
	}
	val, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	return val, nil
}
