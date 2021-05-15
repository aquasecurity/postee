# Set the default goal
.DEFAULT_GOAL := build

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on

GO_FMT=gofmt

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
	go test -v -race -coverprofile=coverage.txt -covermode=atomic ./alertmgr ./scanservice ./dbservice ./formatting ./data

cover :
	go test ./scanservice -v -coverprofile=scanservice.out
	go test ./dbservice -v -coverprofile=dbservice.out
	go test ./alertmgr -v -coverprofile=alertmgr.out
	go test ./formatting -v -coverprofile=formatting.out
	go tool cover -html=scanservice.out
	go tool cover -html=dbservice.out
	go tool cover -html=alertmgr.out
	go tool cover -html=formatting.out