# Set the default goal
.DEFAULT_GOAL := build
VERSION := $(shell git describe --tags)
LDFLAGS=-ldflags "-s -w -X=main.version=$(VERSION)"

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on

GO_FMT=gofmt

.PHONY: build fmt vet test

default : build

.PHONY: build
build :
	@echo "Building Postee...."
	CGO_ENABLED=0 go build $(LDFLAGS) -o ./postee main.go
	@echo "Done!"

fmt :
	@echo "fmt...."
	$(GO_FMT) -s -w ./

test :
	go test -race -v -timeout=30s ./...

test-integration:
	go test -race -v -tags=integration -timeout=30s ./...

cover :
	go test ./msgservice ./dbservice ./router ./formatting ./data ./regoservice ./routes ./actions -v -coverprofile=cover.out
	go tool cover -html=cover.out

composer :
	@echo "Running Postee UI...."
	docker-compose up --build

docker-webhook : build
	@echo "Building image Dockerfile.release...."
	docker build --no-cache -t aquasec/postee:latest -f Dockerfile.release .
	docker run -p 8082:8082 -p 8445:8445 aquasec/postee:latest --cfgfile /server/cfg.yaml

docker-ui :
	@echo "Building image Dockerfile.ui...."
	docker build --no-cache -t aquasec/postee-ui:latest -f Dockerfile.ui .

deploy-k8s :
	@echo "Deploy Postee in Kubernetes...."
	kubectl create -f deploy/kubernetes
	kubectl wait --for=condition=available \
          --timeout=1m deploy/postee
