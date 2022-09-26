package actions

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/PagerDuty/go-pagerduty"
	"github.com/aquasecurity/postee/v2/formatting"
	"github.com/aquasecurity/postee/v2/layout"
)

type Clock interface {
	Now() time.Time
}

type realClock struct{}

func (rc *realClock) Now() time.Time {
	return time.Now()
}

type PagerdutyClient struct {
	client *pagerduty.Client
	clock  Clock

	Name       string
	AuthToken  string
	RoutingKey string
}

func (p *PagerdutyClient) GetName() string {
	return p.Name
}

func (p *PagerdutyClient) Init() error {
	if len(p.AuthToken) <= 0 {
		return fmt.Errorf("pagerduty auth token is required to send events")
	}
	if len(p.RoutingKey) <= 0 {
		return fmt.Errorf("pagerduty routing key is required to send events")
	}

	p.client = pagerduty.NewClient(p.AuthToken)
	p.clock = &realClock{}
	return nil
}

func (p *PagerdutyClient) Send(m map[string]string) error {
	ctx := context.Background()
	resp, err := p.client.ManageEventWithContext(ctx, &pagerduty.V2Event{
		RoutingKey: p.RoutingKey,
		Action:     "trigger",
		Payload: &pagerduty.V2Payload{
			Summary:   m["title"], // required
			Source:    "postee",
			Severity:  "critical",
			Timestamp: p.clock.Now().Format(time.RFC3339),
			Details:   m["description"], // required
		},
	})
	if err != nil {
		return fmt.Errorf("failed to send event to pagerduty: %w", err)
	}

	log.Printf("successfully sent event to pagerduty, response msg: %s, status: %s", resp.Message, resp.Status)
	return nil
}

func (p *PagerdutyClient) Terminate() error {
	return nil
}

func (p *PagerdutyClient) GetLayoutProvider() layout.LayoutProvider {
	/*TODO come up with smaller interface that doesn't include GetLayoutProvider()*/
	return new(formatting.HtmlProvider)
}
