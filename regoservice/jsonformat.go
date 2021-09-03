package regoservice

import (
	"encoding/json"
	"log"

	"github.com/open-policy-agent/opa/ast"
	"github.com/open-policy-agent/opa/rego"
	"github.com/open-policy-agent/opa/types"
)

func jsonFmtFunc() func(r *rego.Rego) {
	return rego.Function1(
		&rego.Function{
			Name: "jsonformat",
			Decl: types.NewFunction(types.Args(&types.Object{}), types.S),
		},

		func(_ rego.BuiltinContext, a *ast.Term) (*ast.Term, error) {
			obj := make(map[string]interface{})
			err := ast.As(a.Value, &obj)
			if err != nil {
				//Rego doesn't show errors
				log.Printf("Can't convert OPA object: %v\n", err)
				return nil, err
			}
			b, err := json.MarshalIndent(obj, "", " ")
			if err != nil {
				//Rego doesn't show errors
				log.Printf("Error while json format: %v\n", err)
				return nil, err
			}
			return ast.StringTerm(string(b)), nil
		})
}
