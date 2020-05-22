package scanservice

import (
	"data"
	"dbservice"
	"fmt"
	"layout"
	"log"
	"plugins"
	"settings"
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

		var base []data.InfoResources
		var prev []data.InfoResources
		if len (currentSettings.PolicyMinVulnerability) > 0 {
			if len(plugins) > 1 {
				base = scan.scanInfo.GetCopyOfResources()
				if scan.prevScan != nil {
					prev = scan.prevScan.GetCopyOfResources()
				}
			}
			scan.scanInfo.RemoveLowLevelVulnerabilities(currentSettings.PolicyMinVulnerability)
			if scan.prevScan != nil {
				scan.prevScan.RemoveLowLevelVulnerabilities(currentSettings.PolicyMinVulnerability)
			}
		}

		plugin.Send(scan.getContent(plugin.GetLayoutProvider()))

		if base != nil {
			scan.scanInfo.SetCopyOfResources(base)
			if scan.prevScan != nil {
				scan.prevScan.SetCopyOfResources(prev)
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