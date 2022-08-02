package msgservice

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/dbservice"
	"github.com/aquasecurity/postee/v2/log"
	"github.com/aquasecurity/postee/v2/outputs"
	"github.com/aquasecurity/postee/v2/regoservice"
	"github.com/aquasecurity/postee/v2/routes"
)

type MsgService struct {
}

func (scan *MsgService) MsgHandling(in map[string]interface{}, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, AquaServer *string) {
	if output == nil {
		return
	}

	//TODO marshalling message back to bytes, change after merge with https://github.com/aquasecurity/postee/pull/150
	input, _ := json.Marshal(in)

	//TODO move logic below somewhere close to Jira output implementation
	owners := scan.scopeOwners(in)

	if route.Plugins.UniqueMessageProps != nil && len(route.Plugins.UniqueMessageProps) > 0 {
		msgKey := GetMessageUniqueId(in, route.Plugins.UniqueMessageProps)
		expired := calculateExpired(route.Plugins.UniqueMessageTimeoutSeconds)

		wasStored, err := dbservice.Db.MayBeStoreMessage(input, msgKey, expired)
		if err != nil {
			log.Logger.Errorf("Error while storing input: %v", err)
			return
		}
		if !wasStored {
			log.Logger.Infof("The same message was received before: %s", msgKey)
			return
		}

	}

	scan.enrichMsg(in, route, *AquaServer)

	content, err := inpteval.Eval(in, *AquaServer)
	if err != nil {
		log.Logger.Errorf("Error while evaluating input: %v", err)
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
				log.Logger.Errorf("Error while building aggregated content: %v", err)
				return
			}
			send(output, content)
		}
	} else if route.Plugins.AggregateTimeoutSeconds > 0 && inpteval.IsAggregationSupported() {
		AggregateScanAndGetQueue(route.Name, content, 0, true)

		if !route.IsSchedulerRun() { //TODO route shouldn't have any associated logic
			log.Logger.Infof("about to schedule %s", route.Name)
			RunScheduler(route, send, AggregateScanAndGetQueue, inpteval, &route.Name, output)
		} else {
			log.Logger.Infof("%s is already scheduled", route.Name)
		}
	} else {
		send(output, content)

	}
}

func (scan *MsgService) HandleSendToOutput(in map[string]interface{}, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, AquaServer *string) (data.OutputResponse, error) {
	if output == nil {
		return data.OutputResponse{}, xerrors.Errorf("The given output is nil")
	}

	owners := scan.scopeOwners(in)
	scan.enrichMsg(in, route, *AquaServer)

	content, err := inpteval.Eval(in, *AquaServer)
	if err != nil {
		log.Logger.Errorf("Error while evaluating input: %v", err)
		return data.OutputResponse{}, err
	}

	if owners != "" {
		content["owners"] = owners
	}

	if route.Plugins.AggregateMessageNumber > 0 && inpteval.IsAggregationSupported() {
		aggregated := AggregateScanAndGetQueue(route.Name, content, route.Plugins.AggregateMessageNumber, false)
		if len(aggregated) > 0 {
			content, err = inpteval.BuildAggregatedContent(aggregated)
			if err != nil {
				log.Logger.Errorf("Error while building aggregated content: %v", err)
				return data.OutputResponse{}, err
			}
			return output.Send(content)
		}
	} else if route.Plugins.AggregateTimeoutSeconds > 0 && inpteval.IsAggregationSupported() {
		AggregateScanAndGetQueue(route.Name, content, 0, true)

		if !route.IsSchedulerRun() { //TODO route shouldn't have any associated logic
			log.Logger.Infof("about to schedule %s", route.Name)
			RunScheduler(route, send, AggregateScanAndGetQueue, inpteval, &route.Name, output)
		} else {
			log.Logger.Infof("%s is already scheduled", route.Name)
		}
	} else {
		return output.Send(content)
	}

	return data.OutputResponse{}, nil
}

// EvaluateRegoRule returns true in case the given input ([]byte) matches the input of the given route
func (scan *MsgService) EvaluateRegoRule(r *routes.InputRoute, input map[string]interface{}) bool {
	if ok, err := regoservice.DoesMatchRegoCriteria(input, r.InputFiles, r.Input); err != nil {
		if !regoservice.IsUsedRegoFiles(r.InputFiles) {
			log.PrnInputError("Error while evaluating rego rule %s :%v for the input %s", r.Input, err, input)
		} else {
			log.PrnInputError("Error while evaluating rego rule for input files :%v for the input %s", err, input)
		}
		return false
	} else if !ok {
		if !regoservice.IsUsedRegoFiles(r.InputFiles) {
			log.Logger.Debugf("Input doesn't match for route '%s' and REGO rule: %s", r.Name, r.Input)
		} else {
			log.PrnInputInfo("Input %s... doesn't match a REGO input files rule", input)
		}
		return false
	}

	return true
}

func (scan *MsgService) scopeOwners(in map[string]interface{}) string {
	//TODO move logic below somewhere close to Jira output implementation
	owners := ""
	applicationScopeOwnersObj, ok := in["application_scope_owners"]
	if ok {
		ownersList, ok := applicationScopeOwnersObj.([]interface{})
		if !ok {
			log.Logger.Error("Error while asserting application_scope_owners attribute: type of []interface{} is expected")
		} else {
			if len(ownersList) > 0 {
				for i, owner := range ownersList {
					if i > 0 {
						owners += ";"
					}
					owners += fmt.Sprint(owner)
				}
			}
		}
	}
	return owners
}

func (scan *MsgService) enrichMsg(in map[string]interface{}, route *routes.InputRoute, aquaServer string) {
	in["postee"] = map[string]string{
		"AquaServer": aquaServer,
	}

	policyName := route.Name
	policyID := ""

	dash := strings.LastIndex(route.Name, "-")
	if dash != -1 {
		policyName = route.Name[:dash]
		policyID = route.Name[dash+1:]
	}

	//enrich those fields even if they are empty, so the rego evaluation will not fail
	in["response_policy_name"] = policyName
	in["response_policy_id"] = policyID

	scan.enrichInsightVulnsPackageName(in)
}

func (scan *MsgService) enrichInsightVulnsPackageName(in map[string]interface{}) {
	ev, ok := in["evidence"]
	if ok {
		evMap, ok := ev.(map[string]interface{})
		if ok {
			vulns, ok := evMap["vulnerabilities"]
			if ok {
				vulnsList, ok := vulns.([]interface{})
				if ok {
					var newList []interface{}
					for _, v := range vulnsList {
						vulnsMap, ok := v.(map[string]interface{})
						if ok {
							pkg, ok := vulnsMap["package"]
							if ok {
								packgeName, ok := pkg.(string)
								if ok {
									vulnsMap["package_name"] = packgeName

								}
							}
							newList = append(newList, vulnsMap)
						}
					}

					evMap["vulnerabilities"] = newList
					in["evidence"] = evMap
				}
			}
		}
	}
}

func send(otpt outputs.Output, cnt map[string]string) {
	go func() {
		_, err := otpt.Send(cnt)
		if err != nil {
			log.Logger.Errorf("Error while sending event: %v", err)
		}
	}()

	if dbservice.Db != nil {
		err := dbservice.Db.RegisterPlgnInvctn(otpt.GetName())
		if err != nil {
			log.Logger.Errorf("Error while building aggregated content: %v", err)
			return
		}
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
	aggregatedScans, err := dbservice.Db.AggregateScans(outputName, currentContent, counts, ignoreLength)
	if err != nil {
		log.Logger.Errorf("AggregateScans Error: %v", err)
		return aggregatedScans
	}
	if len(currentContent) != 0 && len(aggregatedScans) == 0 {
		log.Logger.Infof("New scan was added to the queue of %q without sending.", outputName)
		return nil
	}
	return aggregatedScans
}

func (scan *MsgService) GetMessageUniqueId(in map[string]interface{}, props []string) string {
	return GetMessageUniqueId(in, props)
}
