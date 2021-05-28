package scanservice

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

type ScanService struct {
	scanInfo *data.ScanImageInfo
	prevScan *data.ScanImageInfo
	isNew    bool
}

func (scan *ScanService) ResultHandling(input []byte, name *string, output outputs.Output, route *routes.InputRoute, inpteval data.Inpteval, AquaServer *string) {
	if output == nil {
		return
	}

	in := map[string]interface{}{}
	if err := json.Unmarshal(input, &in); err != nil {
		prnInputLogs("json.Unmarshal error for %q: %v", input, err)
		return
	}

	if ok, err := regoservice.IsRegoCorrectInterface(in, route.Input); err != nil {
		prnInputLogs("IsRegoCorrectInterface error for %q: %v", input)
		return
	} else if !ok {
		prnInputLogs("Input %q... doesn't match a REGO rule: %q", input, route.Input)
		return
	}

	if err := scan.init(input); err != nil {
		log.Println("ScanService.Init Error: Can't init service with data:", input, "\nError:", err)
		return
	}

	//TODO move logic below somewhere close to Jira output implementation
	owners := ""
	if len(scan.scanInfo.ApplicationScopeOwners) > 0 {
		owners = strings.Join(scan.scanInfo.ApplicationScopeOwners, ";")
	}

	if scan.scanInfo.HasId() && !scan.isNew && !route.Plugins.PolicyShowAll {
		log.Println("This scan's result is old:", scan.scanInfo.GetUniqueId())
		return
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
		aggregated := AggregateScanAndGetQueue(*name, content, route.Plugins.AggregateIssuesNumber, false)
		if len(aggregated) > 0 {
			content, err = inpteval.BuildAggregatedContent(aggregated)
			if err != nil {
				log.Printf("Error while building aggregated content: %v", err)
				return
			}
			send(output, name, content)
		}
	} else if route.Plugins.AggregateTimeoutSeconds > 0 && inpteval.IsAggregationSupported() {
		AggregateScanAndGetQueue(*name, content, 0, true)

		if !route.IsSchedulerRun() { //TODO route shouldn't have any associated logic
			log.Printf("about to schedule %s\n", *name)
			route.RunScheduler(send, AggregateScanAndGetQueue, inpteval, name, output)
		} else {
			log.Printf("%s is already scheduled\n", *name)
		}
	} else {
		send(output, name, content)

	}
}

func send(otpt outputs.Output, name *string, cnt map[string]string) {
	go otpt.Send(cnt)
	dbservice.RegisterPlgnInvctn(*name)
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

func (scan *ScanService) init(data []byte) (err error) {
	scan.scanInfo, err = parseImageInfo(data)
	if err != nil {
		return err
	}
	var prevScanSource []byte
	prevScanSource, scan.isNew, err = dbservice.HandleCurrentInfo(scan.scanInfo)
	if err != nil {
		return err
	}
	if !scan.isNew {
		return nil
	}

	if len(prevScanSource) > 0 {
		scan.prevScan, err = parseImageInfo(prevScanSource)
		return err
	}
	return nil
}

func parseImageInfo(source []byte) (*data.ScanImageInfo, error) {
	scanInfo := new(data.ScanImageInfo)
	err := json.Unmarshal(source, scanInfo)
	if err != nil {
		return nil, err
	}
	return scanInfo, nil
}
