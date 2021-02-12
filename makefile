GO_FMT=gofmt
GO_GET=go get
GO_BUILD=go build
GO_INSTALL=go install
GO_CLEAN=go clean
EXENAME=webhooksrv
BUILDPATH=$(CURDIR)
export GOPATH=$(CURDIR)

.PHONY: all clean get build fmt vet test

default : all

makedir :
	@if [ ! -d $(BUILDPATH)/bin ] ; then mkdir -p $(BUILDPATH)/bin ; fi
	@if [ ! -d $(BUILDPATH)/pkg ] ; then mkdir -p $(BUILDPATH)/pkg ; fi

build :
	@echo "building...."
	$(GO_INSTALL)  $(EXENAME)
	@echo "Done!"

get :
	@echo "download 3rd party packages...."
	@$(GO_GET) github.com/ghodss/yaml github.com/gorilla/mux github.com/andygrunwald/go-jira go.etcd.io/bbolt github.com/spf13/cobra

all : makedir get build

clean :
	@echo "cleaning...."
	@rm -rf $(BUILDPATH)/bin/$(EXENAME)
	@rm -rf $(BUILDPATH)/pkg

docker :
	@echo "Building image...."
	docker build -t aquasec/webhook-server:latest -f Dockerfile.webhook-server .

fmt :
	@echo "fmt...."
	$(GO_FMT) -w ./src

test :
	go test -v -race -coverprofile=coverage.txt -covermode=atomic -short  ./src/alertmgr ./src/scanservice ./src/dbservice ./src/formatting

cover :
	go test ./src/scanservice -v -coverprofile=scanservice.out
	go test ./src/dbservice -v -coverprofile=dbservice.out
	go test ./src/alertmgr -v -coverprofile=alertmgr.out
	go test ./src/formatting -v -coverprofile=formatting.out
	go tool cover -html=scanservice.out
	go tool cover -html=dbservice.out
	go tool cover -html=alertmgr.out
	go tool cover -html=formatting.out
