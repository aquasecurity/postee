package regoservice

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/aquasecurity/postee/v2/data"
	"github.com/open-policy-agent/opa/rego"
	"io/fs"
	"log"
)

const (
	result_prop          = "result"
	title_prop           = "title"
	url_prop             = "url"
	aggregation_pkg_prop = "aggregation_pkg"

	//ServiceNow props
	dateProp          = "result_date"
	severityProp      = "result_severity"
	categoryProp      = "result_category"
	subcategoryProp   = "result_subcategory"
	assignedToProp    = "result_assigned_to"
	assignedGroupProp = "result_assigned_group"
	summaryProp       = "result_summary"
)

var (
	buildinRegoTemplates = []string{"./rego-templates"}
	commonRegoTemplates  = []string{"./rego-templates/common"}
)

type regoEvaluator struct {
	prepQuery        *rego.PreparedEvalQuery
	aggrQuery        *rego.PreparedEvalQuery
	isPackageDefined bool
}

func (regoEvaluator *regoEvaluator) IsAggregationSupported() bool {
	return regoEvaluator.aggrQuery != nil
}

func (regoEvaluator *regoEvaluator) Eval(in map[string]interface{}, serverUrl string) (map[string]string, error) {
	ctx := context.Background()
	rs, err := regoEvaluator.prepQuery.Eval(ctx, rego.EvalInput(in))

	if err != nil {
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errors.New("no results") //TODO error definition
	}

	var expr interface{}
	if regoEvaluator.isPackageDefined {
		expr = rs[0].Expressions[0].Value
	} else {
		expr = getFirstElement(rs[0].Expressions[0].Value.(map[string]interface{}), result_prop)
		if expr == nil {
			return nil, errors.New("invalid rego template structure")
		}
	}

	data := expr.(map[string]interface{})

	title, err := asStringOrJson(data, title_prop)
	if err != nil {
		return nil, err
	}

	description, err := asStringOrJson(data, result_prop)

	if err != nil {
		return nil, err
	}

	shortMessageUrl, ok := data[url_prop].(string)
	if !ok {
		shortMessageUrl = ""
	}

	// variables for servicenow
	// for other templates must be empty
	date := getStringFromData(data, dateProp)
	severity := getStringFromData(data, severityProp)
	category := getStringFromData(data, categoryProp)
	subcategory := getStringFromData(data, subcategoryProp)
	assignedTo := getStringFromData(data, assignedToProp)
	assignedGroup := getStringFromData(data, assignedGroupProp)
	summary := getStringFromData(data, summaryProp)

	return map[string]string{
		"title":         title,
		"description":   description,
		"url":           shortMessageUrl,
		"date":          date,
		"severity":      severity,
		"summary":       summary,
		"category":      category,
		"subcategory":   subcategory,
		"assignedTo":    assignedTo,
		"assignedGroup": assignedGroup,
	}, nil

}
func getStringFromData(data map[string]interface{}, prop string) string {
	value := ""
	v, ok := data[prop]
	if ok {
		switch v.(type) {
		case string:
			value = v.(string)
		case json.Number:
			value = v.(json.Number).String()
		}

	}
	return value
}

func getFirstElement(context map[string]interface{}, key string) interface{} {
	for _, v := range context {
		log.Printf("checking: %s ...\n", key)
		childCtx, ok := v.(map[string]interface{})
		if !ok {
			return nil
		}
		if childCtx[key] != nil {
			return v
		} else {
			found := getFirstElement(childCtx, key)
			if found != nil {
				return found
			}
		}
	}
	return nil
}

func asStringOrJson(data map[string]interface{}, prop string) (string, error) {
	expr, ok := data[prop]
	if !ok {
		return "", errors.New(fmt.Sprintf("property %s is not found", prop))
	}
	switch v := expr.(type) { // TODO: Use json.Valid() instead
	case string:
		return v, nil
	default:
		val, err := json.Marshal(expr)
		if err != nil {
			return "", err
		}

		var out bytes.Buffer
		if err = json.Compact(&out, val); err != nil { // Remove extra '\n' et al.
			return "", err
		}

		return out.String(), nil
	}
}
func (regoEvaluator *regoEvaluator) BuildAggregatedContent(scans []map[string]string) (map[string]string, error) {
	aggregatedJson := make([]map[string]interface{}, len(scans), len(scans))

	for _, scan := range scans {
		desc := scan["description"]
		var in []map[string]interface{}

		item := make(map[string]interface{})

		if err := json.Unmarshal([]byte(desc), &in); err != nil {
			item["description"] = desc //description is not json, so it's passed as string
		} else {
			item["description"] = in
		}

		item["title"] = scan["title"]

		item[url_prop] = scan[url_prop]

		// ServiceNow
		item["date"] = scan["date"]
		item["severity"] = scan["severity"]
		item["summary"] = scan["summary"]
		item["category"] = scan["category"]
		item["subcategory"] = scan["subcategory"]
		item["assignedTo"] = scan["assignedTo"]
		item["assignedGroup"] = scan["assignedGroup"]

		aggregatedJson = append(aggregatedJson, item)
	}

	ctx := context.Background()
	rs, err := regoEvaluator.aggrQuery.Eval(ctx, rego.EvalInput(aggregatedJson))

	if err != nil {
		return nil, err
	}

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errors.New("no results") //TODO error definition
	}

	expr := rs[0].Expressions[0].Value

	data := expr.(map[string]interface{})

	title, err := asStringOrJson(data, title_prop)

	if err != nil {
		return nil, err
	}

	description, err := asStringOrJson(data, result_prop)

	if err != nil {
		return nil, err
	}

	shortMessageUrl, ok := data[url_prop].(string)
	if !ok {
		shortMessageUrl = ""
	}

	// variables for servicenow
	// for other templates must be empty
	date := getStringFromData(data, dateProp)
	severity := getStringFromData(data, severityProp)
	category := getStringFromData(data, categoryProp)
	subcategory := getStringFromData(data, subcategoryProp)
	assignedTo := getStringFromData(data, assignedToProp)
	assignedGroup := getStringFromData(data, assignedGroupProp)
	summary := getStringFromData(data, summaryProp)

	return map[string]string{
		"title":         title,
		"description":   description,
		"url":           shortMessageUrl,
		"date":          date,
		"severity":      severity,
		"summary":       summary,
		"category":      category,
		"subcategory":   subcategory,
		"assignedTo":    assignedTo,
		"assignedGroup": assignedGroup,
	}, nil
}

func BuildBundledRegoEvaluator(rego_package string) (data.Inpteval, error) {
	r, err := buildBundledRegoForPackage(rego_package)

	if err != nil {
		return nil, err
	}

	aggrQuery, err := buildAggregatedRego(r)

	if err != nil {
		return nil, err
	}

	return &regoEvaluator{
		prepQuery:        r,
		isPackageDefined: true,
		aggrQuery:        aggrQuery,
	}, nil
}
func buildBundledRegoForPackage(rego_package string) (*rego.PreparedEvalQuery, error) {
	ctx := context.Background()
	query := fmt.Sprintf("data.%s", rego_package)

	// there is case when k8s creates `lost+found` file without access (bad permission) in template folder
	// skip this file to avoid error
	filter := func(abspath string, info fs.FileInfo, depth int) bool {
		if info.Name() == "lost+found" {
			return true
		}
		return false
	}

	r, err := rego.New(
		rego.Query(query),
		jsonFmtFunc(),
		rego.Load(buildinRegoTemplates, filter),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	return &r, nil
}
func buildAggregatedRego(query *rego.PreparedEvalQuery) (*rego.PreparedEvalQuery, error) {
	ctx := context.Background()

	//execute query with empty input and check if aggregation package is defined
	rs, err := query.Eval(ctx, rego.EvalInput(make(map[string]interface{})))

	if len(rs) == 0 || len(rs[0].Expressions) == 0 {
		return nil, errors.New("no results") //TODO error definition
	}

	expr := rs[0].Expressions[0].Value.(map[string]interface{})

	aggregation_pkg_val := expr[aggregation_pkg_prop]

	var aggrQuery *rego.PreparedEvalQuery

	if aggregation_pkg_val != nil {
		aggregation_pkg := aggregation_pkg_val.(string)
		aggrQuery, err = buildBundledRegoForPackage(aggregation_pkg)
		if err != nil {
			return nil, err
		}
	} else {
		//it's ok skip aggregation package - no aggregation features will be available
		log.Printf("No aggregation package configured!!!")
	}
	return aggrQuery, nil
}

func BuildExternalRegoEvaluator(filename string, body string) (data.Inpteval, error) {
	ctx := context.Background()

	// there is case when k8s creates `lost+found` file without access (bad permission) in template folder
	// skip this file to avoid error
	filter := func(abspath string, info fs.FileInfo, depth int) bool {
		if info.Name() == "lost+found" {
			return true
		}
		return false
	}

	r, err := rego.New(
		rego.Query("data"),
		jsonFmtFunc(),
		rego.Load(commonRegoTemplates, filter), //only common modules
		rego.Module(filename, body),
	).PrepareForEval(ctx)

	if err != nil {
		return nil, err
	}

	aggrQuery, err := buildAggregatedRego(&r)

	if err != nil {
		return nil, err
	}

	return &regoEvaluator{
		prepQuery:        &r,
		isPackageDefined: false,
		aggrQuery:        aggrQuery,
	}, nil
}
