package msgservice

import (
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/regoservice"
	"github.com/aquasecurity/postee/v2/routes"
)

type MsgService struct {
}

func (scan *MsgService) MsgHandling(input []byte, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, AquaServer *string) {
	if output == nil {
		return
	}

	in := map[string]interface{}{}
	if err := json.Unmarshal(input, &in); err != nil {
		prnInputLogs("json.Unmarshal error for %q: %v", input, err)
		return
	}

	//TODO move logic below somewhere close to Jira output implementation
	owners := ""
	applicationScopeOwnersObj, ok := in["application_scope_owners"]
	if ok {
		applicationScopeOwners := make([]string, 0)

		for _, owner := range applicationScopeOwnersObj.([]interface{}) {
			applicationScopeOwners = append(applicationScopeOwners, owner.(string))
		}

		if len(applicationScopeOwners) > 0 {
			owners = strings.Join(applicationScopeOwners, ";")
		}
	}

	if route.Plugins.UniqueMessageProps != nil && len(route.Plugins.UniqueMessageProps) > 0 {
		msgKey := GetMessageUniqueId(in, route.Plugins.UniqueMessageProps)
		expired := calculateExpired(route.Plugins.UniqueMessageTimeoutSeconds)

		wasStored, err := dbservice.MayBeStoreMessage(input, msgKey, expired)
		if err != nil {
			log.Printf("Error while storing input: %v", err)
			return
		}
		if !wasStored {
			log.Printf("The same message was received before: %s", msgKey)
			return
		}

	}

	posteeOpts := map[string]string{
		"AquaServer": *AquaServer,
	}

	in["postee"] = posteeOpts

	content, err := inpteval.Eval(in, *AquaServer)
	if err != nil {
		log.Printf("Error while evaluating input: %v", err)
		return
	}

	if owners != "" {
		content["owners"] = owners
	}

	if route.Plugins.AggregateMessageNumber > 0 && inpteval.IsAggregationSupported() {
		aggregated := AggregateScanAndGetQueue(route.Name, content, route.Plugins.AggregateMessageNumber, false)
		if len(aggregated) > 0 {
			content, err = inpteval.BuildAggregatedContent(aggregated)
			if err != nil {
				log.Printf("Error while building aggregated content: %v", err)
				return
			}
			if route.SerializeOutputs {
				send(output, content)
			} else {
				go send(output, content)
			}
		}
	} else if route.Plugins.AggregateTimeoutSeconds > 0 && inpteval.IsAggregationSupported() {
		AggregateScanAndGetQueue(route.Name, content, 0, true)

		if !route.IsSchedulerRun() { //TODO route shouldn't have any associated logic
			log.Printf("about to schedule %s\n", route.Name)
			RunScheduler(route, send, AggregateScanAndGetQueue, inpteval, &route.Name, output)
		} else {
			log.Printf("%s is already scheduled\n", route.Name)
		}
	} else {
		if route.SerializeOutputs {
			send(output, content)
		} else {
			go send(output, content)
		}
	}
}

// EvaluateRegoRule returns true in case the given input ([]byte) matches the input of the given route
func (scan *MsgService) EvaluateRegoRule(r *routes.InputRoute, input []byte) bool {
	in := map[string]interface{}{}
	if err := json.Unmarshal(input, &in); err != nil {
		prnInputLogs("json.Unmarshal error for %q: %v", input, err)
		return false
	}

	if ok, err := regoservice.DoesMatchRegoCriteria(in, r.InputFiles, r.Input); err != nil {
		if !regoservice.IsUsedRegoFiles(r.InputFiles) {
			prnInputLogs("Error while evaluating rego rule %s :%v for the input %s", r.Input, err, input)
		} else {
			prnInputLogs("Error while evaluating rego rule for input files :%v for the input %s", err, input)
		}
		return false
	} else if !ok {
		if !regoservice.IsUsedRegoFiles(r.InputFiles) {
			prnInputLogs("Input %s... doesn't match a REGO rule: %s", input, r.Input)
		} else {
			prnInputLogs("Input %s... doesn't match a REGO input files rule", input)
		}
		return false
	}

	return true
}

func send(otpt outputs.Output, cnt map[string]string) {
	err := otpt.Send(cnt)
	if err != nil {
		log.Printf("Error while sending event: %v", err)
	}

	err = dbservice.RegisterPlgnInvctn(otpt.GetName())
	if err != nil {
		log.Printf("Error while building aggregated content: %v", err)
		return
	}

}
func calculateExpired(UniqueMessageTimeoutSeconds int) *time.Time {
	if UniqueMessageTimeoutSeconds == 0 {
		return nil
	}
	timeToExpire := time.Duration(UniqueMessageTimeoutSeconds) * time.Second
	expired := time.Now().UTC().Add(timeToExpire)
	return &expired
}

var AggregateScanAndGetQueue = func(outputName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
	aggregatedScans, err := dbservice.AggregateScans(outputName, currentContent, counts, ignoreLength)
	if err != nil {
		log.Printf("AggregateScans Error: %v", err)
		return aggregatedScans
	}
	if len(currentContent) != 0 && len(aggregatedScans) == 0 {
		log.Printf("New scan was added to the queue of %q without sending.", outputName)
		return nil
	}
	return aggregatedScans
}
