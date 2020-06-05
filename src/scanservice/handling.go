package scanservice

import (
	"data"
	"dbservice"
	"fmt"
	"layout"
	"log"
	"plugins"
	"settings"
	"strings"
	"time"
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

		if currentSettings.PolicyOnlyFixAvailable && !scan.checkFixVersions() {
			log.Printf("This scan %q doesn't contain vulnerabilities which have a fix version. Settings for %q.\n", scan.scanInfo.GetUniqueId(), name)
			continue
		}

		content := scan.getContent(plugin.GetLayoutProvider())
		wasHandled := false
		if currentSettings.AggregateIssuesNumber > 0  {
			aggregated := AggregateScanAndGetQueue(name, content, currentSettings.AggregateIssuesNumber, false)
			if len(aggregated) > 0 {
				content = buildAggregatedContent(aggregated, plugin.GetLayoutProvider())
			} else {
				content = nil
			}
			wasHandled = true
		}

		if currentSettings.AggregateTimeoutSeconds > 0  {
			if !wasHandled {
				AggregateScanAndGetQueue(name, content, 0, true)
				content = nil
			}
			if !currentSettings.IsScheduleRun {
				plg := plugin
				go func(nm string) {
					log.Printf("Scheduler is actived for %q(%q). Period: %d sec",
						nm, plg.GetSettings().PluginName, plg.GetSettings().AggregateTimeoutSeconds)
					for {
						time.Sleep(time.Duration(plg.GetSettings().AggregateTimeoutSeconds) * time.Second)
						queue := AggregateScanAndGetQueue(nm, nil, 0, false)
						if len(queue) > 0 {
							send(plg, buildAggregatedContent(queue, plg.GetLayoutProvider()), nm)
						}
					}
				}(name)
				currentSettings.IsScheduleRun = true
			}
		}

		if len(content) > 0 {
			send(plugin, content, name)
		}
	}
}

func send( plg plugins.Plugin, cnt map[string]string, name string) {
	log.Printf("Sending message via %q", name)
	go plg.Send(cnt)
}

func AggregateScanAndGetQueue(pluginName string, currentContent map[string]string, counts int, ignoreLength bool) []map[string]string {
	aggregatedScans, err := dbservice.AggregateScans(pluginName, currentContent, counts, ignoreLength)
	if err != nil {
		log.Printf("AggregateScans Error: %v", err)
		return aggregatedScans
	}
	if len(currentContent) != 0 && len(aggregatedScans) == 0 {
		log.Printf( "New scan was added to the queue of %q without sending.", pluginName)
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
	vulns := [...]int { scan.scanInfo.Negligible, scan.scanInfo.Low, scan.scanInfo.Medium, scan.scanInfo.High, scan.scanInfo.Critical }
	for i:=SeverityIndexes[strings.ToLower(minLevel)]; i < len(vulns); i++ {
		if vulns[i] > 0 {
			return true
		}
	}
	return false
}

func (scan *ScanService) getContent(provider layout.LayoutProvider) map[string]string {
	return buildMapContent(
		fmt.Sprintf("%s vulnerability scan report", scan.scanInfo.Image),
		layout.GenTicketDescription(provider, scan.scanInfo, scan.prevScan))
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