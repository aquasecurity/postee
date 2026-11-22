package regoservice

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/rego"
)

const (
	module = `package postee
		default allow = false
	`
	allow = `
		allow {
			%s
		}
	`

	defaultPathToRegoFilters = "./rego-filters"
)

var PathToRegoFilters = ""

// inlineRuleQueries holds the prepared query per inline rule text, so a route
// filter is compiled once instead of on every message.
var (
	inlineRuleMu       sync.Mutex
	inlineRuleQueries  = map[string]rego.PreparedEvalQuery{}
	inlineRuleCompiles atomic.Int64
)

func getFilesWithPathToRegoFilters(files []string) []string {
	if PathToRegoFilters == "" {
		if os.Getenv("REGO_FILTERS_PATH") != "" {
			PathToRegoFilters = os.Getenv("REGO_FILTERS_PATH")
		} else {
			PathToRegoFilters = defaultPathToRegoFilters
		}
	}
	filesWithPath := make([]string, len(files))
	copy(filesWithPath, files)
	for i, file := range filesWithPath {
		if !strings.HasPrefix(file, PathToRegoFilters) {
			filesWithPath[i] = filepath.Join(PathToRegoFilters, file)
		}
	}
	return filesWithPath
}

func buildRegoLoader(files []string, rule string) func(r *rego.Rego) {
	if IsUsedRegoFiles(files) {
		filesWithPath := getFilesWithPathToRegoFilters(files)
		return rego.Load(filesWithPath, nil)
	}

	regoInput := module
	orSplit := strings.Split(rule, "||")
	for _, rule := range orSplit {
		regoInput += fmt.Sprintf(allow, rule)
	}

	return rego.Module("postee.rego", regoInput)
}
func IsUsedRegoFiles(files []string) bool {
	return len(files) != 0 && files[0] != ""
}
func preparedQuery(ctx context.Context, files []string, rule string) (rego.PreparedEvalQuery, error) {
	// Filter files are re-read on every call so edits on disk take effect.
	cacheable := !IsUsedRegoFiles(files)
	if cacheable {
		inlineRuleMu.Lock()
		defer inlineRuleMu.Unlock()
		if q, ok := inlineRuleQueries[rule]; ok {
			return q, nil
		}
	}

	query, err := rego.New(
		rego.Query("x = data.postee.allow"),
		buildRegoLoader(files, rule),
	).PrepareForEval(ctx)
	if err == nil && cacheable {
		inlineRuleCompiles.Add(1)
		inlineRuleQueries[rule] = query
	}
	return query, err
}

func DoesMatchRegoCriteria(input interface{}, files []string, rule string) (bool, error) {
	if !IsUsedRegoFiles(files) && rule == "" {
		return true, nil
	}

	ctx := context.Background()

	query, err := preparedQuery(ctx, files, rule)
	if err != nil {
		return false, err
	}

	rs, err := query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return false, err
	}

	if len(rs) > 0 {
		switch rs[0].Bindings["x"].(type) {
		case bool:
			return rs[0].Bindings["x"].(bool), nil
		}
	}
	return false, nil
}
