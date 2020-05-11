package alertmgr

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"

	"io/ioutil"
	"log"
	"strconv"

	"net/http"
	"os"
	"strings"

	"github.com/andygrunwald/go-jira"
)

type Totals struct {
	Total        int64   `json:"total"`
	High         int64   `json:"high"`
	Medium       int64   `json:"medium"`
	Low          int64   `json:"low"`
	ScoreAverage float64 `json:"score_average"`
}

type CVES []Vulnerability

type Vulnerability struct {
	File           string  `json:"file"`
	Name           string  `json:"name"`
	Type           string  `json:"type"`
	Description    string  `json:"description"`
	Score          float32 `json:"score"`
	VendorSeverity string  `json:"vendor_severity"`
	PublishDate    string  `json:"publishdate"`
	InstallVersion string  `json:"have_version"`
	FixVersion     string  `json:"fix_version"`
	Vectors        string  `json:"vectors"`
}

type Cves struct {
	ImageName  string `json:"image"`
	Registry   string `json:"registry"`
	Totals     Totals `json:"cves_counts"`
	Disallowed bool   `json:"disallowed"`
	CVES       CVES   `json:"cves"`
}

type JiraAPI struct {
	url       string
	user      string
	password  string
	tlsVerify bool

	issuetype   string
	projectKey  string
	projectName string
	projectId   string

	priority    string
	assignee    string
	description string
	summary     string
	sprintName  string
	sprintId    int

	isDescriptionProvided bool
	isSummaryProvided     bool

	fixVersions     []string
	affectsVersions []string
	labels          []string

	unknowns map[string]string
	BoardId  int
}

func (ctx *JiraAPI) fetchBoardId() {
	client, err := ctx.createClient()
	if err != nil {
		log.Printf("unable to create Jira client: %s, please check your credentials.", err)
		return
	}

	boardlist, _, err := client.Board.GetAllBoards(&jira.BoardListOptions{ProjectKeyOrID: ctx.projectId})
	if err != nil {
		log.Printf("failed to get boards from Jira API GetAllBoards with ProjectID %s. %s", ctx.projectId, err)
		return
	}
	var matches int
	for _, board := range boardlist.Values {
		if board.Name == fmt.Sprintf("%s board", ctx.projectKey) { // "<board_name> board"
			ctx.BoardId = board.ID
			matches++
		}
	}

	if matches > 1 {
		log.Printf("found more than one boards with name %s, working with board id %d", ctx.projectKey, ctx.BoardId)
	} else if matches == 0 {
		log.Printf("no boards found with name %s when getting all boards for user", ctx.projectKey)
		return
	} else {
		log.Printf("using board ID %d with Name %s", ctx.BoardId, ctx.projectKey)
	}

}

func (ctx *JiraAPI) fetchSprintId(client jira.Client) {
	sprints, _, err := client.Board.GetAllSprintsWithOptions(ctx.BoardId, &jira.GetAllSprintsOptions{State: "active"})
	if err != nil {
		log.Printf("failed to get active sprint for board ID %d from Jira API. %s", ctx.BoardId, err)
		return
	}
	if len(sprints.Values) > 1 {
		ctx.sprintId = len(sprints.Values) - 1
		log.Printf("Found more than one active sprint, using sprint id %d as the active sprint", ctx.sprintId)
	} else if len(sprints.Values) == 1 {
		if sprints.Values[0].ID != ctx.sprintId {
			ctx.sprintId = sprints.Values[0].ID
			log.Printf("using sprint id %d as the active sprint", ctx.sprintId)
		}
	} else {
		log.Printf("no active sprints exist in board ID %d Name %s", ctx.BoardId, ctx.projectKey)
	}
}

func NewJiraAPI(settings PluginSettings) *JiraAPI {
	jiraApi := &JiraAPI{
		url:             settings.Url,
		user:            settings.User,
		password:        settings.Password,
		tlsVerify:       settings.TlsVerify,
		issuetype:       settings.IssueType,
		projectKey:      settings.ProjectKey,
		projectName:     settings.ProjectName,
		projectId:       settings.ProjectId,
		priority:        settings.Priority,
		assignee:        settings.Assignee,
		description:     settings.Description,
		summary:         settings.Summary,
		fixVersions:     settings.FixVersions,
		affectsVersions: settings.AffectsVersions,
		labels:          settings.Labels,
		unknowns:        settings.Unknowns,
		sprintName:      settings.Sprint,
		sprintId:        -1,
	}
	if settings.Description != "" {
		jiraApi.isDescriptionProvided = true
	}

	if settings.Summary != "" {
		jiraApi.isSummaryProvided = true
	}

	// validate ProjectID, ProjectName, Board(projectKey)

	jiraApi.fetchBoardId()
	return jiraApi
}

func (ctx *JiraAPI) Terminate() error {
	log.Printf("Jira plugin terminated\n")
	return nil
}

func (ctx *JiraAPI) Init() error {
	log.Printf("Starting Jira plugin....")
	if len(ctx.password) == 0 {
		ctx.password = os.Getenv("JIRA_PASSWORD")
	}
	return nil
}

func (ctx *JiraAPI) createClient() (*jira.Client, error) {
	tp := jira.BasicAuthTransport{
		Username: ctx.user,
		Password: ctx.password,
	}

	if !ctx.tlsVerify {
		tp.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}
	}
	client, err := jira.NewClient(tp.Client(), ctx.url)
	if err != nil {
		return client, fmt.Errorf("unable to create new JIRA client. %v", err)
	}
	return client, nil
}

func (ctx *JiraAPI) Send(data string) error {
	client, err := ctx.createClient()
	if err != nil {
		log.Printf("unable to create Jira client: %s", err)
		return err
	}

	ctx.fetchSprintId(*client)

	metaProject, err := createMetaProject(client, ctx.projectKey)
	if err != nil {
		return fmt.Errorf("Failed to create meta project: %s\n", err)
	}

	// For some reason, the customer wants to provide
	// the project id and not to rely on the id which is in the project
	// meta information.
	if len(ctx.projectId) > 0 {
		if ctx.projectId != metaProject.Id {
			log.Printf("Config supplied a different project ID than the board's project ID: using %s instead of %s", ctx.projectId, metaProject.Id)
		}
		metaProject.Id = ctx.projectId
	}

	// For some reason, the customer wants to provide
	// the project name and not to rely on the name which is in the project
	// meta information.
	if len(ctx.projectName) > 0 {
		if ctx.projectName != metaProject.Name {
			log.Printf("Config supplied a different project Name than the board's project Name: using %s instead of %s", ctx.projectName, metaProject.Name)
		}
		metaProject.Name = ctx.projectName
	}

	metaIssueType, err := createMetaIssueType(metaProject, ctx.issuetype)
	if err != nil {
		return fmt.Errorf("Failed to create meta issue type: %s", err)
	}

	if !ctx.isSummaryProvided {
		ctx.summary = ctx.buildSummary(data)
	}
	if !ctx.isDescriptionProvided {
		ctx.description = ctx.buildDescription(data)
	}

	fieldsConfig := map[string]string{
		"Issue Type":  ctx.issuetype,
		"Project":     ctx.projectKey, // TODO: What is project here?
		"Priority":    ctx.priority,
		"Assignee":    ctx.assignee,
		"Description": ctx.description,
		"Summary":     ctx.summary,
	}
	if ctx.sprintId >=0 {
		fieldsConfig["Sprint"] = strconv.Itoa(ctx.sprintId)
	}

	//Add all custom fields that are unknown to fieldsConfig. Unknown are fields that are custom user defined in jira.
	for k, v := range ctx.unknowns {
		fieldsConfig[k] = v
	}
	if len(ctx.unknowns) > 0 {
		log.Printf("added %d custom fields to issue.", len(ctx.unknowns))
	}

	type Version struct {
		Name string `json:"name"`
	}

	issue, err := InitIssue(metaProject, metaIssueType, fieldsConfig)
	if err != nil {
		log.Printf("Failed to init issue: %s\n", err)
		return err
	}

	if len(ctx.labels) > 0 {
		for _, l := range ctx.labels {
			issue.Fields.Labels = append(issue.Fields.Labels, l)
		}
	}

	if len(ctx.fixVersions) > 0 {
		for _, v := range ctx.fixVersions {
			issue.Fields.FixVersions = append(issue.Fields.FixVersions, &jira.FixVersion{
				Name: v,
			})
		}
	}

	if len(ctx.affectsVersions) > 0 {
		affectsVersions := []*Version{}
		for _, v := range ctx.affectsVersions {
			affectsVersions = append(affectsVersions, &Version{
				Name: v,
			})
		}
		issue.Fields.Unknowns["versions"] = affectsVersions
		log.Printf("added %d affected versions into Versions field", len(ctx.affectsVersions))
	}

	i, err := ctx.openIssue(client, issue)
	if err != nil {
		log.Printf("Failed to open jira issue, %s\n", err)
		return err
	}
	log.Printf("Created new jira issue %s", i.ID)
	return nil
}

func (ctx *JiraAPI) login(client *jira.Client) error {
	_, err := client.Authentication.AcquireSessionCookie(ctx.user, ctx.password)
	return err
}

func (ctx *JiraAPI) openIssue(client *jira.Client, issue *jira.Issue) (*jira.Issue, error) {
	i, res, err := client.Issue.Create(issue)

	defer res.Body.Close()
	resp, _ := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, errors.New(string(resp))
	}
	return i, nil
}

func (ctx *JiraAPI) buildSummary(data string) string {

	res := Cves{}
	err := json.Unmarshal([]byte(data), &res)
	if err != nil {
		log.Printf("Failed to render scan results, %s\n", err)
		return ""
	}
	return fmt.Sprintf("%s vulnerability scan report", res.ImageName)
}

func (ctx *JiraAPI) buildDescription(data string) string {

	//const (
	//	JIRA_MARKDOWN_NL = "\\\\\n"
	//)
	//
	//res := scanmgr.ImageScanResult{}
	//err := json.Unmarshal([]byte(data), &res)
	//if err != nil {
	//	log.Printf("Failed to render scan results, %s\n", err)
	//	return ""
	//}
	//
	//description := ""
	//
	//description += fmt.Sprintf("h1. Vulnerability Report: %s\n\n", res.Image)
	//description += JIRA_MARKDOWN_NL
	//description += "||HIGH||MEDIUM||LOW||\n"
	//description += fmt.Sprintf("|{color:red}%d{color}|{color:orange}%d{color}|{color:green}%d{color}|\n\n", res.VulnerabilitySummary.High, res.VulnerabilitySummary.Medium, res.VulnerabilitySummary.Low)
	//description += JIRA_MARKDOWN_NL
	//
	//if res.ImageAssuranceResults.GetDisallowed() {
	//	description += fmt.Sprintf("h2. {color:red}Image %s is disallowed by Aqua Security{color}\n\n", res.Image)
	//} else {
	//	description += fmt.Sprintf("h2. {color:green}Image %s is allowed by Aqua Security{color}\n\n", res.Image)
	//}
	//
	//description += JIRA_MARKDOWN_NL
	//description += "The following vulnerabilities were found:\n"
	//description += JIRA_MARKDOWN_NL
	//
	//description += "||NAME||RESOURCE||SEVERITY||SCORE||INSTALLED VERSION||FIX VERSION||VECTORS||\n"
	//
	//for _, resource := range res.Resources {
	//	for _, cve := range resource.Vulnerabilities {
	//
	//		nvdSeverity := cve.NvdSeverity
	//		vendorSeverity := cve.VendorSeverity
	//		installVersion := resource.Resource.Version
	//		fixVersion := cve.FixVersion
	//		nvdVectors := cve.NvdVectors
	//		vendorVectors := cve.VendorVectors
	//		nvdScore := cve.NvdScore
	//		vendorScore := cve.VendorScore
	//
	//		if len(nvdSeverity) == 0 {
	//			nvdSeverity = " "
	//		}
	//		if len(vendorSeverity) == 0 {
	//			vendorSeverity = " "
	//		}
	//		if len(installVersion) == 0 {
	//			installVersion = " "
	//		}
	//		if len(fixVersion) == 0 {
	//			fixVersion = " "
	//		}
	//
	//		if nvdSeverity == "negligible" || nvdSeverity == "unknown" {
	//			nvdScore = 0
	//			nvdVectors = ""
	//		}
	//
	//		if vendorSeverity == "negligible" || vendorSeverity == "unknown" {
	//			vendorScore = 0
	//			vendorVectors = ""
	//		}
	//
	//		if len(nvdVectors) == 0 {
	//			nvdVectors = " "
	//		}
	//
	//		if len(vendorVectors) == 0 {
	//			vendorVectors = " "
	//		}
	//
	//		nvdVectors = strings.Replace(nvdVectors, ":P", "\\:P", -1)
	//		nvdVectors = strings.Replace(nvdVectors, ":D", "\\:D", -1)
	//
	//		vendorVectors = strings.Replace(vendorVectors, ":P", "\\:P", -1)
	//		vendorVectors = strings.Replace(vendorVectors, ":D", "\\:D", -1)
	//
	//		severityStr := buildString(nvdSeverity, vendorSeverity)
	//
	//		vectorsStr := buildString(nvdVectors, vendorVectors)
	//
	//		nameStr := ""
	//		if strings.TrimSpace(cve.NvdUrl) != "" {
	//			nameStr += fmt.Sprintf("Nvd: [%s|%s]", cve.Name, cve.NvdUrl)
	//		}
	//		if strings.TrimSpace(cve.VendorUrl) != "" {
	//			nameStr += fmt.Sprintf("\\\\Vendor: [%s|%s]", cve.Name, cve.VendorUrl)
	//		}
	//
	//		scoreStr := fmt.Sprintf("*NVD:* %.2f\n*Vendor:* %.2f&nbsp;  &nbsp;  &nbsp;&nbsp; &nbsp; &nbsp; &nbsp;", nvdScore, vendorScore)
	//		severityStr += "&nbsp; &nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp; &nbsp;"
	//		vectorsStr += "&nbsp; &nbsp; &nbsp; &nbsp;&nbsp; &nbsp; &nbsp; &nbsp;"
	//
	//		line := fmt.Sprintf("|"+nameStr+"|%s|"+severityStr+"|"+scoreStr+"|%s|%s|"+vectorsStr+"|\n", resource.Resource.Name, installVersion, fixVersion)
	//
	//		description += line
	//	}
	//}

	// return description

	return "TODO"
}

func buildString(nvd string, vendor string) string {
	severityStr := ""
	high := "#e0443d"
	medium := "#f79421"
	low := "#e1c930"
	negligible := "green"

	if strings.TrimSpace(nvd) != "" {
		color := ""
		if nvd == "high" {
			color = high
		} else if nvd == "medium" {
			color = medium
		} else if nvd == "low" {
			color = low
		} else if nvd == "negligible" {
			color = negligible
		}
		severityStr += fmt.Sprintf("*NVD:* {color:%s}%s{color}\n", color, nvd)
	}

	if strings.TrimSpace(vendor) != "" {
		color := ""
		if vendor == "high" {
			color = high
		} else if vendor == "medium" {
			color = medium
		} else if vendor == "low" {
			color = low
		} else if vendor == "negligible" {
			color = negligible
		}
		severityStr += fmt.Sprintf("*Vendor:* {color:%s}%s{color}", color, vendor)
	}
	return severityStr
}

/*func (ctx *JiraAPI) buildDescription(data string) string {

	const (
		JIRA_MARKDOWN_NL = "\\\\\n"
		JIRA_REDHAT_FMT  = "|[%s|https://rhn.redhat.com/errata/%s.html]|%s|%s|%.2f|%s|%s|%s|\n"
		JIRA_NVD_FMT     = "|[%s|https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s]|%s|%s|%.2f|%s|%s|%s|\n"
	)

	res := Cves{}
	err := json.Unmarshal([]byte(data), &res)
	if err != nil {
		log.Printf("Failed to render scan results, %s\n", err)
		return ""
	}

	description := ""

	// Add user defined description
	if len(ctx.description) > 0 {
		description = fmt.Sprintf("{panel:title=%s}{panel}\n", ctx.description)
		description += JIRA_MARKDOWN_NL
		description += JIRA_MARKDOWN_NL
	}

	description += fmt.Sprintf("Vulnerability Report: %s\n\n", res.ImageName)
	description += JIRA_MARKDOWN_NL
	description += "||HIGH||MEDIUM||LOW||SCORE AVG.||\n"
	description += fmt.Sprintf("|%d|%d|%d|%.2f|\n\n", res.Totals.High, res.Totals.Medium, res.Totals.Low, res.Totals.ScoreAverage)
	description += JIRA_MARKDOWN_NL

	if res.Disallowed {
		description += fmt.Sprintf("{color:red}Image %s is disallowed by Aqua Security{color}\n\n", res.ImageName)
	} else {
		description += fmt.Sprintf("Image %s is allowed by Aqua Security\n\n", res.ImageName)
	}

	description += JIRA_MARKDOWN_NL
	description += "The following vulnerabilities were found:\n"
	description += JIRA_MARKDOWN_NL

	description += "||NAME||RESOURCE||SEVERITY||SCORE||INSTALLED VERSION||FIX VERSION||VECTORS||\n"

	sort.Sort(sort.Reverse(res.CVES))

	for _, cve := range res.CVES {
		severity := cve.VendorSeverity
		installVersion := cve.InstallVersion
		fixVersion := cve.FixVersion
		vectors := cve.Vectors
		score := cve.Score

		if len(severity) == 0 {
			severity = " "
		}
		if len(installVersion) == 0 {
			installVersion = " "
		}
		if len(fixVersion) == 0 {
			fixVersion = " "
		}

		if severity == "negligible" || severity == "unknown" {
			score = 0
			vectors = ""
		}

		if len(vectors) == 0 {
			vectors = " "
		}

		vectors = strings.Replace(vectors, ":P", "\\:P", -1)
		vectors = strings.Replace(vectors, ":D", "\\:D", -1)

		line := ""

		if strings.HasPrefix(cve.Name, "RHSA") {
			cvename := strings.Replace(cve.Name, ":", "-", -1)
			line = fmt.Sprintf("|[%s|https://rhn.redhat.com/errata/%s.html]|%s|%s|%.2f|%s|%s|%s|\n", cvename, cvename, cve.File, severity, score, installVersion, fixVersion, vectors)
		} else if strings.HasPrefix(cve.Name, "CVE") {
			line = fmt.Sprintf("|[%s|https://web.nvd.nist.gov/view/vuln/detail?vulnId=%s]|%s|%s|%.2f|%s|%s|%s|\n", cve.Name, cve.Name, cve.File, severity, score, installVersion, fixVersion, vectors)
		} else {
			line = fmt.Sprintf("|%s|%s|%s|%.2f|%s|%s|%s|\n", cve.Name, cve.File, severity, cve.Score, installVersion, fixVersion, vectors)
		}

		description += line
	}

	return description
}*/

func (slice CVES) Len() int {
	return len(slice)
}

func (slice CVES) Less(i, j int) bool {
	return slice[i].Score < slice[j].Score
}

func (slice CVES) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}

func createMetaProject(c *jira.Client, project string) (*jira.MetaProject, error) {
	meta, _, err := c.Issue.GetCreateMeta(project)
	if err != nil {
		return nil, fmt.Errorf("failed to get create meta : %s", err)
	}

	// get right project
	metaProject := meta.GetProjectWithKey(project)
	if metaProject == nil {
		return nil, fmt.Errorf("could not find project with key %s", project)
	}

	return metaProject, nil
}

func createMetaIssueType(metaProject *jira.MetaProject, issueType string) (*jira.MetaIssueType, error) {
	metaIssuetype := metaProject.GetIssueTypeWithName(issueType)
	if metaIssuetype == nil {
		return nil, fmt.Errorf("could not find issuetype %s", issueType)
	}

	return metaIssuetype, nil
}

func InitIssue(metaProject *jira.MetaProject, metaIssuetype *jira.MetaIssueType, fieldsConfig map[string]string) (*jira.Issue, error) {
	issue := new(jira.Issue)
	issueFields := new(jira.IssueFields)
	issueFields.Unknowns =  make(map[string]interface{})

	// map the field names the User presented to jira's internal key
	allFields, _ := metaIssuetype.GetAllFields()
	for key, value := range fieldsConfig {

		jiraKey, found := allFields[key]
		if !found {
			return nil, fmt.Errorf("key %s is not found in the list of fields", key)
		}

		valueType, err := metaIssuetype.Fields.String(jiraKey + "/schema/type")
		if err != nil {
			return nil, err
		}

		switch valueType {
		case "array":
			// split value (string) into slice by delimiter
			elements := strings.Split(value, ",")

			elemType, err := metaIssuetype.Fields.String(jiraKey + "/schema/items")
			if err != nil {
				return nil, err
			}
			switch elemType {
			case "component":
				issueFields.Unknowns[jiraKey] = []jira.Component{{Name: value}}
			case "option":
				optionsMap := make([]map[string]string, 0)

				for _, element := range elements {
					optionsMap = append(optionsMap, map[string]string{"value": element})
				}
				issueFields.Unknowns[jiraKey] = optionsMap
			default:
				if key == "Sprint" {
					num, err := strconv.Atoi(value)
					if err != nil {
						return nil, err
					}
					issueFields.Unknowns[jiraKey] = num // Due to Jira REST API behavior, needed to specify not a slice but a number.
				} else {
					issueFields.Unknowns[jiraKey] = []string{value}
				}
			}
		case "number":
			val, err := strconv.Atoi(value)
			if err != nil {
				fmt.Printf("Failed convert value(string) to int: %s\n", err)
			}
			issueFields.Unknowns[jiraKey] = val

		// TODO: Handle Cascading Select List
		//case "option-with-child":
		//	type CustomField struct {
		//		Value string `json:"value"`
		//	}
		//	type CustomFieldCascading struct {
		//		Value string `json:"value"`
		//		Child CustomField `json:"child"`
		//	}
		//
		//	a := CustomFieldCascading{ Value: "1", Child: CustomField{Value: "a"}}

		case "string":
			issueFields.Unknowns[jiraKey] = value
		case "date":
			issueFields.Unknowns[jiraKey] = value
		case "datetime":
			issueFields.Unknowns[jiraKey] = value
		case "any":
			// Treat any as string
			issueFields.Unknowns[jiraKey] = value
		case "project":
			issueFields.Unknowns[jiraKey] = jira.Project{
				Name: metaProject.Name,
				ID:   metaProject.Id,
			}
		case "priority":
			issueFields.Unknowns[jiraKey] = jira.Priority{Name: value}
		case "user":
			issueFields.Unknowns[jiraKey] = jira.User{
				Name: value,
			}
		case "issuetype":
			issueFields.Unknowns[jiraKey] = jira.IssueType{
				Name: value,
			}
		case "option":
			issueFields.Unknowns[jiraKey] = jira.Option{
				Value: value,
			}

		default:
			return nil, fmt.Errorf("Unknown issue type encountered: %s for %s", valueType, key)
		}
	}

	issue.Fields = issueFields

	return issue, nil
}
