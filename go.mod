module github.com/aquasecurity/postee

go 1.15

require (
	github.com/andygrunwald/go-jira v1.14.0
	github.com/ghodss/yaml v1.0.0
	github.com/gorilla/mux v1.8.0
	github.com/open-policy-agent/opa v0.27.1
	github.com/spf13/cobra v1.1.3
	github.com/stretchr/testify v1.4.0
	go.etcd.io/bbolt v1.3.5
)

replace github.com/andygrunwald/go-jira => github.com/DmitriyLewen/go-jira v1.14.1-0.20211027084757-49364f29be7f
