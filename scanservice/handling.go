package scanservice

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/aquasecurity/postee/data"
	"github.com/aquasecurity/postee/dbservice"
	"github.com/aquasecurity/postee/plugins"
	"github.com/aquasecurity/postee/regoservice"
	"github.com/aquasecurity/postee/routes"
)

type ScanService struct {
	scanInfo *data.ScanImageInfo
	prevScan *data.ScanImageInfo
	isNew    bool
}

func (scan *ScanService) ResultHandling(input []byte, name *string, plugin plugins.Plugin, route *routes.InputRoutes, inpteval data.Inpteval, AquaServer *string) {
	if plugin == nil {
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
	log.Printf("Handling a scan result of '%s/%s'", scan.scanInfo.Registry, scan.scanInfo.Image)
	owners := ""

	if len(scan.scanInfo.ApplicationScopeOwners) > 0 {
		owners = strings.Join(scan.scanInfo.ApplicationScopeOwners, ";")
	}

	if !scan.isNew && !route.PolicyShowAll {
		log.Println("This scan's result is old:", scan.scanInfo.GetUniqueId())
		return
	}

	title := fmt.Sprintf("%s vulnerability scan report", in["image"])
	description, err := inpteval.Eval(in, *AquaServer)
	if err != nil {
		log.Printf("Error while evaluation input: %v", err)
		return
	}

	content := buildMapContent(title, description, *AquaServer) //TODO pass pointer to description
	content["src"] = string(input)
	if owners != "" {
		content["owners"] = owners
	}

	wasHandled := false
	if route.AggregateIssuesNumber > 0 {
		aggregated := AggregateScanAndGetQueue(*name, content, route.AggregateIssuesNumber, false)
		if len(aggregated) > 0 {
			content = buildAggregatedContent(aggregated, plugin.GetLayoutProvider())
		} else {
			content = nil
		}
		wasHandled = true
	}

	if route.AggregateTimeoutSeconds > 0 {
		if !wasHandled {
			AggregateScanAndGetQueue(*name, content, 0, true)
			content = nil
		}
		if !route.IsSchedulerRun() {
			route.RunScheduler(send, AggregateScanAndGetQueue)
		}
	}
	if len(content) > 0 {
		send(plugin, name, content)
	}
}

func send(plg plugins.Plugin, name *string, cnt map[string]string) {
	go plg.Send(cnt)
	dbservice.RegisterPlgnInvctn(*name)
}

var AggregateScanAndGetQueue = func(pluginName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
	aggregatedScans, err := dbservice.AggregateScans(pluginName, currentContent, counts, ignoreLength)
	if err != nil {
		log.Printf("AggregateScans Error: %v", err)
		return aggregatedScans
	}
	if len(currentContent) != 0 && len(aggregatedScans) == 0 {
		log.Printf("New scan was added to the queue of %q without sending.", pluginName)
		return nil
	}
	return aggregatedScans
}

func (scan *ScanService) checkFixVersions() bool {
	for _, r := range scan.scanInfo.Resources {
		for _, v := range r.Vulnerabilities {
			if len(v.FixVersion) > 0 {
				return true
			}
		}
	}
	return false
}

func (scan *ScanService) checkVulnerabilitiesLevel(minLevel string) bool {
	vulns := [...]int{scan.scanInfo.Negligible, scan.scanInfo.Low, scan.scanInfo.Medium, scan.scanInfo.High, scan.scanInfo.Critical}
	for i := SeverityIndexes[strings.ToLower(minLevel)]; i < len(vulns); i++ {
		if vulns[i] > 0 {
			return true
		}
	}
	return false
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
