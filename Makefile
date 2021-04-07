# Set the default goal
.DEFAULT_GOAL := build

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on
GOPATH=$(shell go env GOPATH)
GOBIN=$(GOPATH)/bin

GO_FMT=gofmt
GO_GET=go get
GO_BUILD=go build
GO_INSTALL=go install
GO_CLEAN=go clean
EXENAME=webhooksrv

.PHONY: all build fmt vet test

default : all

.PHONY: build
build :
	@echo "building...."
	CGO_ENABLED=0 go build -o ./bin/postee main.go
	@echo "Done!"

docker :
	@echo "Building image...."
	docker build -t aquasec/postee:latest -f Dockerfile .

fmt :
	@echo "fmt...."
	$(GO_FMT) -s -w ./

test :
	go test -v -race -coverprofile=coverage.txt -covermode=atomic -short  ./alertmgr ./scanservice ./dbservice ./formatting

cover :
	go test ./scanservice -v -coverprofile=scanservice.out
	go test ./dbservice -v -coverprofile=dbservice.out
	go test ./alertmgr -v -coverprofile=alertmgr.out
	go test ./formatting -v -coverprofile=formatting.out
	go tool cover -html=scanservice.out
	go tool cover -html=dbservice.out
	go tool cover -html=alertmgr.out
	go tool cover -html=formatting.out