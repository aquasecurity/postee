package regoservice

import (
	"context"
	"testing"

	"github.com/open-policy-agent/opa/rego"
)

var benchInput = map[string]interface{}{"image": "alpine", "vulnerabilities": 3}

const benchRule = `input.image == "alpine"`

// Per-message path used by msgservice.EvaluateRegoRule.
func BenchmarkDoesMatchRegoCriteria(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		ok, err := DoesMatchRegoCriteria(benchInput, nil, benchRule)
		if err != nil || !ok {
			b.Fatalf("ok=%v err=%v", ok, err)
		}
	}
}

// Same rule prepared once, evaluated per message.
func BenchmarkPreparedOnce(b *testing.B) {
	ctx := context.Background()
	q, err := rego.New(rego.Query("x = data.postee.allow"), buildRegoLoader(nil, benchRule)).PrepareForEval(ctx)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs, err := q.Eval(ctx, rego.EvalInput(benchInput))
		if err != nil || len(rs) == 0 {
			b.Fatalf("rs=%v err=%v", rs, err)
		}
	}
}
