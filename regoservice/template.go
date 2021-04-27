package regoservice

import (
	"errors"
	"fmt"
	"github.com/open-policy-agent/opa/rego"
	"log"
)

func BuildRegoTemplate(input interface{}, rule *string) ([]byte, error) {
	log.Printf("Template Rules: %q", *rule)

	r := rego.New(
		rego.Query("x = data.postee.allow"),
		rego.Module("postee.rego", fmt.Sprintf(module, rule)),
	)
	if r == nil {
		return nil, errors.New("REGO is nil")
	}
	return nil, nil
}
