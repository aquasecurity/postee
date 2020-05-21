package scanservice

import (
	"data"
	"dbservice"
	"fmt"
	"layout"
	"log"
	"plugins"
	"strings"
)

var (
	SeverityPriorities = map[string]int{
		"critical":5,
		"high":4,
		"medium":3,
		"low":2,
		"negligible":1,
	}
)

type ScanService struct {
	scanInfo *data.ScanImageInfo
	prevScan *data.ScanImageInfo
	isNew    bool
}

func (scan *ScanService) ResultHandling(input string, settings *ScanSettings, plugins map[string]plugins.Plugin) {
	if err := scan.init(input); err != nil {
		log.Println("ScanService.Init Error: Can't init service with data:", input, "\nError:", err)
		return
	}
	if len(settings.PolicyImageName) > 0 && !compliesPolicies(settings.PolicyImageName, scan.scanInfo.Image) {
		log.Printf("ScanService: Image %q was ignored (missed) by settings.\n", scan.scanInfo.Image)
		return
	}

	if len(settings.PolicyRegistry) > 0 && !compliesPolicies(settings.PolicyRegistry, scan.scanInfo.Registry) {
		log.Printf("ScanService: Registry %q was ignored by settings.\n", scan.scanInfo.Registry)
		return
	}

	if len (settings.PolicyMinVulnerability) > 0 {
		scan.removeLowLevelVulnerabilities(settings.PolicyMinVulnerability)
	}

	isCorrectNonCompliantSetting := true
	if settings.PolicyNonCompliant && !scan.scanInfo.Disallowed {
		isCorrectNonCompliantSetting = false
	}

	if scan.isNew && isCorrectNonCompliantSetting {
		for _, plugin := range plugins {
			if plugin != nil {
				plugin.Send( scan.getContent( plugin.GetLayoutProvider() ))
			}
		}
	} else {
		log.Println("This scan's result is old:", scan.scanInfo.GetUniqueId())
	}
}

func (scan *ScanService) removeLowLevelVulnerabilities(down string)  {
	min := SeverityPriorities[strings.ToLower(down)]

	for r:=0; r<len(scan.scanInfo.Resources); r++ {
		for i:= len(scan.scanInfo.Resources[r].Vulnerabilities)-1; i >= 0; i-- {
			if SeverityPriorities[scan.scanInfo.Resources[r].Vulnerabilities[i].Severity] < min {
				scan.scanInfo.Resources[r].Vulnerabilities = scan.scanInfo.Resources[r].Vulnerabilities[:i]
			}
		}
	}
}

func (scan *ScanService) getContent(provider layout.LayoutProvider) map[string]string {
	content := make(map[string]string)
	content["title"] = fmt.Sprintf("%s vulnerability scan report", scan.scanInfo.Image)
	content["description"] = layout.GenTicketDescription(provider, scan.scanInfo, scan.prevScan)
	return content
}

func (scan *ScanService) init(data string) ( err error) {
	scan.scanInfo, err = parseImageInfo([]byte(data))
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