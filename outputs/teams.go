package outputs

import (
	"encoding/json"
	"log"

	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
	"github.com/aquasecurity/postee/v2/utils"

	msteams "github.com/aquasecurity/postee/v2/teams"
)

const (
	teamsSizeLimit = 18000 // 28 KB is an approximate limit for MS Teams
)

type TeamsOutput struct {
	Name        string
	AquaServer  string
	teamsLayout layout.LayoutProvider
	Webhook     string
}

func (teams *TeamsOutput) GetName() string {
	return teams.Name
}

func (teams *TeamsOutput) Init() error {
	log.Printf("Starting MS Teams output %q....", teams.Name)
	teams.teamsLayout = new(formatting.HtmlProvider)
	return nil
}

func (teams *TeamsOutput) Send(input map[string]string) error {
	log.Printf("Sending to MS Teams via %q...", teams.Name)
	utils.Debug("Title for %q: %q\n", teams.Name, input["title"])
	utils.Debug("Url(s) for %q: %q\n", teams.Name, input["url"])
	utils.Debug("Webhook for %q: %q\n", teams.Name, teams.Webhook)
	utils.Debug("Length of Description for %q: %d/%d\n",
		teams.Name, len(input["description"]), teamsSizeLimit)

	var body string
	if len(input["description"]) > teamsSizeLimit {
		utils.Debug("MS Team output will send SHORT message\n")
		body = buildShortMessage(teams.AquaServer, input["url"], teams.teamsLayout)
	} else {
		utils.Debug("MS Team output will send LONG message\n")
		body = input["description"]
	}
	utils.Debug("Message is: %q\n", body)

	escaped, err := escapeJSON(body)
	if err != nil {
		log.Printf("Error while escaping payload: %v", err)
		return err
	}

	err = msteams.CreateMessageByWebhook(teams.Webhook, teams.teamsLayout.TitleH2(input["title"])+escaped)

	if err != nil {
		log.Printf("TeamsOutput Send Error: %v", err)
		return err
	}

	log.Printf("Sending to MS Teams via %q was successful!", teams.Name)
	return nil
}

func (teams *TeamsOutput) Terminate() error {
	log.Printf("MS Teams output %q terminated", teams.Name)
	return nil
}

func (teams *TeamsOutput) GetLayoutProvider() layout.LayoutProvider {
	return teams.teamsLayout
}

func escapeJSON(s string) (string, error) {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	// Trim the beginning and trailing " character
	return string(b[1 : len(b)-1]), nil
}
