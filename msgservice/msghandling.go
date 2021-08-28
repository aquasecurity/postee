package msgservice

import (
	"encoding/json"
	"log"
	"strings"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/outputs"
	"github.com/aquasecurity/postee/regoservice"
	"github.com/aquasecurity/postee/routes"
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

	if ok, err := regoservice.DoesMatchRegoCriteria(in, route.Input); err != nil {
		prnInputLogs("Error while evaluating rego rule %s :%v for the input %s", route.Input, err, input)
		return
	} else if !ok {
		prnInputLogs("Input %s... doesn't match a REGO rule: %s", input, route.Input)
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
		wasStored, err := dbservice.MayBeStoreMessage(input, msgKey)
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

	if route.Plugins.AggregateIssuesNumber > 0 && inpteval.IsAggregationSupported() {
		aggregated := AggregateScanAndGetQueue(route.Name, content, route.Plugins.AggregateIssuesNumber, false)
		if len(aggregated) > 0 {
			content, err = inpteval.BuildAggregatedContent(aggregated)
			if err != nil {
				log.Printf("Error while building aggregated content: %v", err)
				return
			}
			send(output, content)
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
		send(output, content)

	}
}

func send(otpt outputs.Output, cnt map[string]string) {
	go otpt.Send(cnt)
	err := dbservice.RegisterPlgnInvctn(otpt.GetName())
	if err != nil {
		log.Printf("Error while building aggregated content: %v", err)
		return
	}

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
