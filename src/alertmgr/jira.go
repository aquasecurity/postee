package alertmgr

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/andygrunwald/go-jira"
	"io/ioutil"
	"log"
	"sort"
	"strings"
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
	ImageName  string `json:"image_name"`
	Registry   string `json:"registry"`
	Totals     Totals `json:"cves_counts"`
	Disallowed bool   `json:"disallowed"`
	CVES       CVES   `json:"cves"`
}

type JiraAPI struct {
	url         string
	user        string
	password    string
	board       string
	assignee    string
	ticket      string
	description string
	summary     string
}

func NewJiraAPI(settings PluginSettings) *JiraAPI {
	return &JiraAPI{
		url:         settings.Url,
		user:        settings.User,
		password:    settings.Password,
		board:       settings.Board,
		assignee:    settings.Assignee,
		ticket:      settings.Ticket,
		description: settings.Description,
		summary:     settings.Summary,
	}
}

func (ctx *JiraAPI) Terminate() error {
	log.Printf("Jira plugin terminated\n")
	return nil
}

func (ctx *JiraAPI) Init() error {
	log.Printf("Starting Jira plugin....")
	return nil
}

func (ctx *JiraAPI) Send(data string) error {
	client, err := jira.NewClient(nil, ctx.url)
	if err != nil {
		log.Printf("Failed to connect to %s: %s\n", ctx.url, err)
		return err
	}
	err = ctx.login(client)
	if err != nil {
		log.Printf("Failed login to jira: %s\n", err)
		return err
	}

	summary := ctx.buildSummary(data)
	description := ctx.buildDescription(data)

	issue := &jira.Issue{
		Fields: &jira.IssueFields{
			Type: jira.IssueType{
				Name: ctx.ticket,
			},
			Project: jira.Project{
				Key: ctx.board,
			},
			Assignee: &jira.User{
				Name: ctx.assignee,
			},
			Description: description,
			Summary:     summary,
		},
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
	if len(ctx.summary) > 0 {
		return ctx.summary
	}
	res := Cves{}
	err := json.Unmarshal([]byte(data), &res)
	if err != nil {
		log.Printf("Failed to render scan results, %s\n", err)
		return ""
	}
	return fmt.Sprintf("%s vulnerability scan report", res.ImageName)
}

func (ctx *JiraAPI) buildDescription(data string) string {

	// TODO: use text/template package

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
}

func (slice CVES) Len() int {
	return len(slice)
}

func (slice CVES) Less(i, j int) bool {
	return slice[i].Score < slice[j].Score
}

func (slice CVES) Swap(i, j int) {
	slice[i], slice[j] = slice[j], slice[i]
}
