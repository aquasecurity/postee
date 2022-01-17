module github.com/aquasecurity/postee

go 1.15

require (
	github.com/aquasecurity/go-jira v0.0.0-20211103111421-b62ce48827be
	github.com/ghodss/yaml v1.0.0
	github.com/gorilla/mux v1.8.0
	github.com/jmoiron/sqlx v1.3.4
	github.com/lib/pq v1.2.0
	github.com/open-policy-agent/opa v0.35.0
	github.com/spf13/cobra v1.2.1
	github.com/stretchr/testify v1.7.0
	github.com/zhashkevych/go-sqlxmock v1.5.2-0.20201023121933-f973d0041cfc
	go.etcd.io/bbolt v1.3.6
	go.uber.org/zap v1.19.1
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1
)

replace golang.org/x/crypto v0.0.0-20200622213623-75b288015ac9 => golang.org/x/crypto v0.0.0-20201216223049-8b5274cf687f
