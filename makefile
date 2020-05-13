GOPATH=$(CURDIR)
GO=/usr/local/go/bin/go
GO_FMT=/usr/local/go/bin/gofmt
GO_GET=$(GO) get
GO_BUILD=$(GO) build
GO_INSTALL=$(GO) install
GO_CLEAN=$(GO) clean
EXENAME=webhooksrv
BUILDPATH=$(CURDIR)
export GOPATH=$(BUILDPATH)

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
	@$(GO_GET) github.com/gorilla/mux
	@$(GO_GET) github.com/ghodss/yaml
	@$(GO_GET) github.com/andygrunwald/go-jira
	@$(GO_GET) go.etcd.io/bbolt

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
	go test ./src/alertmgr -v -coverprofile=alertmgr.out
	go tool cover -html=alertmgr.out