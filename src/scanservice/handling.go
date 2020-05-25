package scanservice

import (
	"bytes"
	"data"
	"dbservice"
	"fmt"
	"layout"
	"log"
	"plugins"
	"settings"
	"strings"
)

type ScanService struct {
	scanInfo *data.ScanImageInfo
	prevScan *data.ScanImageInfo
	isNew    bool
}

func (scan *ScanService) ResultHandling(input string, plugins map[string]plugins.Plugin) {
	if err := scan.init(input); err != nil {
		log.Println("ScanService.Init Error: Can't init service with data:", input, "\nError:", err)
		return
	}
	if !scan.isNew {
		log.Println("This scan's result is old:", scan.scanInfo.GetUniqueId())
		return
	}

	for name, plugin := range plugins {
		if plugin == nil {
			continue
		}

		currentSettings := plugin.GetSettings()
		if currentSettings == nil {
			currentSettings = settings.GetDefaultSettings()
		}

		if len(currentSettings.PolicyMinVulnerability) > 0 && !scan.checkVulnerabilitiesLevel(currentSettings.PolicyMinVulnerability) {
			log.Printf("ScanService: Scan %q contains only low-level vulnerabilities. Min level for %q is %q.\n",
				scan.scanInfo.GetUniqueId(), name,currentSettings.PolicyMinVulnerability)
			continue
		}

		if len(currentSettings.IgnoreRegistry) > 0 && compliesPolicies(currentSettings.IgnoreRegistry, scan.scanInfo.Registry) {
			log.Printf("ScanService: Registry %q was ignored by currentSettings for %q.\n", scan.scanInfo.Registry, name)
			continue
		}

		if len(currentSettings.IgnoreImageName) > 0 && compliesPolicies(currentSettings.IgnoreImageName, scan.scanInfo.Image) {
			log.Printf("ScanService: Image %q was ignored by currentSettings for %q.\n", scan.scanInfo.Image, name)
			continue
		}

		if len(currentSettings.PolicyImageName) > 0 && !compliesPolicies(currentSettings.PolicyImageName, scan.scanInfo.Image) {
			log.Printf("ScanService: Image %q wasn't allowed (missed) by currentSettings for %q.\n", scan.scanInfo.Image, name)
			continue
		}

		if len(currentSettings.PolicyRegistry) > 0 && !compliesPolicies(currentSettings.PolicyRegistry, scan.scanInfo.Registry) {
			log.Printf("ScanService: Registry %q wasn't allowed by currentSettings for %q.\n", scan.scanInfo.Registry, name)
			continue
		}

		if currentSettings.PolicyNonCompliant && !scan.scanInfo.Disallowed {
			log.Printf("This scan %q isn't Disallowed and will not sent by currentSettings for %q.\n", scan.scanInfo.GetUniqueId(), name)
			continue
		}

		content := scan.getContent(plugin.GetLayoutProvider())
		if currentSettings.AggregateTimeoutSeconds > 0 || currentSettings.AggregateIssuesPerTicket > 0 {
			content = scan.aggregateScans(name, content, plugin.GetLayoutProvider(), currentSettings.AggregateIssuesPerTicket)
		}
		if len(content) > 0 {
			plugin.Send(content)
		}
	}
}

func (scan *ScanService) aggregateScans(pluginName string, currentContent map[string]string,
	layoutProvider layout.LayoutProvider, counts int) map[string]string {
	aggregatedScans, err := dbservice.AggregateScans(pluginName, currentContent, counts)
	if err != nil {
		log.Printf("AggregateScans Error: %v", err)
		return currentContent
	}

	if len(aggregatedScans) == 0 {
		log.Printf( "Scan was added to the queue without sengins. ScanId: %q", scan.scanInfo.GetUniqueId())
		return nil
	}

	var descr bytes.Buffer
	var names []string

	for _, scan := range aggregatedScans {
		descr.WriteString(layoutProvider.TitleH1(scan["title"]))
		descr.WriteString(scan["description"])
		if len(scan["name"]) > 0 {
			names = append(names, scan["name"])
		}
	}
	title := fmt.Sprintf("%s vulnerabilities scan report", strings.Join(names, ", "))
	return BuildMapContent(title, descr.String(), "")
}

func (scan *ScanService) checkVulnerabilitiesLevel(minLevel string) bool {
	vulns := [...]int { scan.scanInfo.Negligible, scan.scanInfo.Low, scan.scanInfo.Medium, scan.scanInfo.High, scan.scanInfo.Critical }
	for i:=SeverityIndexes[strings.ToLower(minLevel)]; i < len(vulns); i++ {
		if vulns[i] > 0 {
			return true
		}
	}
	return false
}

func (scan *ScanService) getContent(provider layout.LayoutProvider) map[string]string {
	return BuildMapContent(
		fmt.Sprintf("%s vulnerability scan report", scan.scanInfo.Image),
		layout.GenTicketDescription(provider, scan.scanInfo, scan.prevScan),
		scan.scanInfo.Image)
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