package outputs

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strconv"

	"github.com/aquasecurity/postee/v2/data"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/log"

	"net/http"
	"net/url"
	"os"
	"strings"

	jira "github.com/aquasecurity/go-jira"
)

const (
	JiraType = "jira"
)

type JiraAPI struct {
	Name            string
	Url             string
	User            string
	Password        string
	Token           string
	TlsVerify       bool
	Issuetype       string
	ProjectKey      string
	Priority        string
	Assignee        []string
	Description     string
	Summary         string
	SprintName      string
	SprintId        int
	FixVersions     []string
	AffectsVersions []string
	Labels          []string
	Unknowns        map[string]string
	BoardName       string
	boardId         int
	boardType       string
}

func (ctx *JiraAPI) GetType() string {
	return JiraType
}

func (ctx *JiraAPI) GetName() string {
	return ctx.Name
}

func (ctx *JiraAPI) CloneSettings() *data.OutputSettings {
	return &data.OutputSettings{
		Name: ctx.Name,
		Url:  ctx.Url,
		User: ctx.User,
		//password is omitted
		TlsVerify:       ctx.TlsVerify,
		IssueType:       ctx.Issuetype,
		ProjectKey:      ctx.ProjectKey,
		Priority:        ctx.Priority,
		Assignee:        data.CopyStringArray(ctx.Assignee),
		Summary:         ctx.Summary,
		Sprint:          ctx.SprintName,
		FixVersions:     data.CopyStringArray(ctx.FixVersions),
		AffectsVersions: data.CopyStringArray(ctx.AffectsVersions),
		Labels:          data.CopyStringArray(ctx.Labels),
		Unknowns:        cpyUnknowns(ctx.Unknowns),
		Enable:          true,
		Type:            "Jira",
	}
}

func (ctx *JiraAPI) fetchBoardId(boardName string) {
	// Basic authentication with passwords is deprecated for this API
	if ctx.Token == "" {
		return
	}

	client, err := ctx.createClient()
	if err != nil {
		log.Logger.Error(fmt.Errorf("unable to create Jira client: %w, please check your credentials", err))
		return
	}

	boardlist, _, err := client.Board.GetAllBoards(&jira.BoardListOptions{ProjectKeyOrID: ctx.ProjectKey})
	if err != nil {
		log.Logger.Error(fmt.Errorf("failed to get boards from Jira API GetAllBoards with ProjectID %s. %w", ctx.ProjectKey, err))
		return
	}
	var matches int
	for _, board := range boardlist.Values {
		if board.Name == boardName {
			ctx.boardId = board.ID
			ctx.boardType = board.Type
			matches++
		}
	}

	if matches > 1 {
		log.Logger.Debugf("found more than one boards with name %q, working with board id %d", boardName, ctx.boardId)
	} else if matches == 0 {
		log.Logger.Debugf("no boards found with name %s when getting all boards for User", boardName)
		return
	} else {
		log.Logger.Debugf("using board ID %d with Name %q", ctx.boardId, boardName)
	}
}

func (ctx *JiraAPI) fetchSprintId(client jira.Client) {
	sprints, _, err := client.Board.GetAllSprintsWithOptions(ctx.boardId, &jira.GetAllSprintsOptions{State: "active"})
	if err != nil {
		log.Logger.Error(fmt.Errorf("failed to get active sprint for board ID %d from Jira API. %w", ctx.boardId, err))
		return
	}
	if len(sprints.Values) > 1 {
		ctx.SprintId = len(sprints.Values) - 1
		log.Logger.Debugf("Found more than one active sprint, using sprint id %d as the active sprint", ctx.SprintId)
	} else if len(sprints.Values) == 1 {
		if sprints.Values[0].ID != ctx.SprintId {
			ctx.SprintId = sprints.Values[0].ID
			log.Logger.Debugf("using sprint id %d as the active sprint", ctx.SprintId)
		}
	} else {
		log.Logger.Debugf("no active sprints exist in board ID %d Name %s", ctx.boardId, ctx.ProjectKey)
	}
}

func (ctx *JiraAPI) Terminate() error {
	log.Logger.Debug("Jira output terminated")
	return nil
}

func (ctx *JiraAPI) Init() error {
	if ctx.BoardName == "" {
		ctx.BoardName = fmt.Sprintf("%s board", ctx.ProjectKey)
	}
	ctx.fetchBoardId(ctx.BoardName)

	if len(ctx.Password) == 0 {
		ctx.Password = os.Getenv("JIRA_PASSWORD")
	}

	log.Logger.Infof("Successfully initialized Jira output %q", ctx.Name)
	return nil
}

func (ctx *JiraAPI) GetLayoutProvider() layout.LayoutProvider {
	return new(formatting.JiraLayoutProvider)
}

func (ctx *JiraAPI) buildTransportClient() (*http.Client, error) {
	if ctx.Token != "" {
		if !isServerJira(ctx.Url) {
			return nil, errors.New("jira Cloud can't work with PAT")
		}
		if ctx.Password != "" {
			log.Logger.Warn("Found both Password and PAT, using PAT to authenticate.")
		}
		tp := jira.BearerTokenAuthTransport{
			Token: ctx.Token,
		}
		if !ctx.TlsVerify {
			tp.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		return tp.Client(), nil
	} else {
		tp := jira.BasicAuthTransport{
			Username: ctx.User,
			Password: ctx.Password,
		}
		if !ctx.TlsVerify {
			tp.Transport = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			}
		}
		return tp.Client(), nil
	}
}

func (ctx *JiraAPI) createClient() (*jira.Client, error) {
	tpClient, err := ctx.buildTransportClient()
	if err != nil {
		return nil, fmt.Errorf("unable to create new JIRA client. %w", err)
	}
	client, err := jira.NewClient(tpClient, ctx.Url)
	if err != nil {
		return client, fmt.Errorf("unable to create new JIRA client. %w", err)
	}
	return client, nil
}

func (ctx *JiraAPI) Send(content map[string]string) (data.OutputResponse, error) {
	log.Logger.Infof("Sending to JIRA via %q", ctx.Name)
	client, err := ctx.createClient()
	if err != nil {
		log.Logger.Errorf("unable to create Jira client: %s", err)
		return data.OutputResponse{}, err
	}

	if ctx.boardType == "scrum" {
		ctx.fetchSprintId(*client)
	}

	metaProject, err := createMetaProject(client, ctx.ProjectKey)
	if err != nil {
		return data.OutputResponse{}, fmt.Errorf("failed to create meta project: %w", err)
	}

	metaIssueType, err := createMetaIssueType(metaProject, ctx.Issuetype)
	if err != nil {
		return data.OutputResponse{}, fmt.Errorf("failed to create meta issue type: %w", err)
	}

	summary, ok := content["title"]
	if ok && summary != "" {
		trimmed := strings.Trim(summary, " ")
		if trimmed != "-" {
			ctx.Summary = summary
		}
	}
	ctx.Description = content["description"]

	assignee := ctx.User
	if len(ctx.Assignee) > 0 {
		assignees := getHandledRecipients(ctx.Assignee, &content, ctx.Name)
		if len(assignees) > 0 {
			assignee = assignees[0]
		}
	}

	fieldsConfig := map[string]string{
		"Issue Type":  ctx.Issuetype,
		"Project":     ctx.ProjectKey,
		"Priority":    ctx.Priority,
		"Assignee":    assignee,
		"Description": ctx.Description,
		"Summary":     ctx.Summary,
	}
	if ctx.SprintId > 0 {
		fieldsConfig["Sprint"] = strconv.Itoa(ctx.SprintId)
	}

	//Add all custom fields that are unknown to fieldsConfig. Unknown are fields that are custom User defined in jira.
	for k, v := range ctx.Unknowns {
		fieldsConfig[k] = v
	}
	if len(ctx.Unknowns) > 0 {
		log.Logger.Debugf("added %d custom fields to issue.", len(ctx.Unknowns))
	}

	type Version struct {
		Name string `json:"name"`
	}

	issue, err := InitIssue(client, metaProject, metaIssueType, fieldsConfig, isServerJira(ctx.Url))

	if err != nil {
		log.Logger.Error(fmt.Errorf("failed to init issue: %w", err))
		return data.OutputResponse{}, err
	}

	if len(ctx.Labels) > 0 {
		issue.Fields.Labels = append(issue.Fields.Labels, ctx.Labels...)
	}

	if len(ctx.FixVersions) > 0 {
		for _, v := range ctx.FixVersions {
			issue.Fields.FixVersions = append(issue.Fields.FixVersions, &jira.FixVersion{
				Name: v,
			})
		}
	}

	if len(ctx.AffectsVersions) > 0 {
		affectsVersions := []*Version{}
		for _, v := range ctx.AffectsVersions {
			affectsVersions = append(affectsVersions, &Version{
				Name: v,
			})
		}
		issue.Fields.Unknowns["versions"] = affectsVersions
		log.Logger.Debugf("added %d affected versions into Versions field", len(ctx.AffectsVersions))
	}

	i, err := ctx.openIssue(client, issue)
	if err != nil {
		log.Logger.Error(fmt.Errorf("failed to open jira issue, %w", err))
		return data.OutputResponse{}, err
	}
	ticketLink := fmt.Sprintf("%s/browse/%s", ctx.Url, i.Key)
	log.Logger.Infof("Successfully created a new jira issue %s, %s", i.Key, ticketLink)
	return data.OutputResponse{Key: i.Key, Url: ticketLink}, nil
}

func (ctx *JiraAPI) openIssue(client *jira.Client, issue *jira.Issue) (*jira.Issue, error) {
	i, _, err := client.Issue.Create(issue)
	if err != nil {
		return nil, err
	}

	return i, nil
}

func createMetaProject(c *jira.Client, project string) (*jira.MetaProject, error) {
	meta, _, err := c.Issue.GetCreateMeta(project)
	if err != nil {
		return nil, fmt.Errorf("failed to get create meta : %w", err)
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

func InitIssue(c *jira.Client, metaProject *jira.MetaProject, metaIssuetype *jira.MetaIssueType, fieldsConfig map[string]string, useSrvApi bool) (*jira.Issue, error) {
	issue := new(jira.Issue)
	issueFields := new(jira.IssueFields)
	issueFields.Unknowns = make(map[string]interface{})

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

		switch strings.ToLower(valueType) {
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
				log.Logger.Warnf("Failed convert value(string) to int: %s", err)
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
			var users []jira.User
			var resp *jira.Response
			var err error

			if useSrvApi {
				users, resp, err = findUserOnJiraServer(c, value)
			} else {
				users, resp, err = c.User.Find(value)
			}

			if err != nil {
				log.Logger.Error(fmt.Errorf("fet Jira User info error: %w", err))
				continue
			}
			if resp.StatusCode != http.StatusOK {
				log.Logger.Error(fmt.Errorf("http response failed: %s", resp.Status))
				continue
			}
			if len(users) == 0 {
				log.Logger.Error(fmt.Errorf("there is no user for %s", value))
				continue
			}
			issueFields.Unknowns[jiraKey] = users[0]
		case "issuetype":
			issueFields.Unknowns[jiraKey] = jira.IssueType{
				Name: value,
			}
		case "option":
			issueFields.Unknowns[jiraKey] = jira.Option{
				Value: value,
			}

		default:
			return nil, fmt.Errorf("unknown issue type encountered: %s for %s", valueType, key)
		}
	}
	issue.Fields = issueFields
	return issue, nil
}

func findUserOnJiraServer(c *jira.Client, email string) ([]jira.User, *jira.Response, error) {
	req, _ := c.NewRequest("GET", fmt.Sprintf("/rest/api/2/user/search?username=%s", email), nil)

	users := []jira.User{}

	resp, err := c.Do(req, &users)
	if err != nil {
		log.Logger.Errorf("%v", err)
		return nil, resp, err
	}
	return users, resp, nil
}

func isServerJira(rawUrl string) bool {
	jiraUrl, err := url.Parse(rawUrl)

	if err == nil {
		return !strings.HasSuffix(jiraUrl.Host, "atlassian.net")
	}

	return false
}

func cpyUnknowns(source map[string]string) map[string]string {
	dst := make(map[string]string)
	for k, v := range source {
		dst[k] = v
	}
	return dst
}
