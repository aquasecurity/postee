package regoservice

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aquasecurity/postee/data"
	"github.com/open-policy-agent/opa/rego"
)

type regoEvaluator struct {
	prepQuery *rego.PreparedEvalQuery
}

func (regoEvaluator *regoEvaluator) Eval(in map[string]interface{}, serverUrl string) (string, error) {
	ctx := context.Background()
	rs, err := regoEvaluator.prepQuery.Eval(ctx, rego.EvalInput(in))

	if err != nil {
		return "", err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return "", errors.New("no results") //TODO error definition
	}

	expr := rs[0].Expressions[0].Value //TODO external modules require some logic to get actual result

	switch v := expr.(type) {
	case string:
		return v, nil
	case interface{}:
		val, err := json.Marshal(expr)
		if err != nil {
			return "", err
		}
		return string(val), nil
	default:
		return "", errors.New("Unknow result") //TODO error definition
	}

}

func BuildBundledRegoEvaluator(rego_package string) (data.Inpteval, error) {
	ctx := context.Background()
	query := fmt.Sprintf("data.%s.result", rego_package)

	r, err := rego.New(
		rego.Query(query),
		rego.Load([]string{"./rego-templates"}, nil),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	return &regoEvaluator{
		prepQuery: &r,
	}, nil
}
func BuildExternalRegoEvaluator(body *string) (data.Inpteval, error) {
	return nil, errors.New("not implemented") //TODO implement
}
