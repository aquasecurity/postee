# Set the default goal
.DEFAULT_GOAL := build

# Active module mode, as we use Go modules to manage dependencies
export GO111MODULE=on

GO_FMT=gofmt

.PHONY: all build fmt vet test

default : all

.PHONY: build
build :
	@echo "Building Postee...."
	CGO_ENABLED=0 go build -o ./postee main.go
	@echo "Done!"

fmt :
	@echo "fmt...."
	$(GO_FMT) -s -w ./

test :
	go test -race -coverprofile=coverage.txt -covermode=atomic ./router ./msgservice ./dbservice ./formatting ./data ./regoservice ./routes

cover :
	go test ./msgservice ./dbservice ./router ./formatting ./data ./regoservice ./routes -v -coverprofile=cover.out
	go tool cover -html=cover.out

composer :
	@echo "Running Postee UI...."
	docker-compose up --build

docker-webhook : build
	@echo "Building image...."
	docker build --no-cache -t aquasec/postee:latest -f Dockerfile.release .
	docker run -p 8082:8082 -p 8445:8445 aquasec/postee:latest --cfgfile /server/cfg.yaml

deploy-k8s :
	@echo "Deploy Postee in Kubernetes...."
	kubectl create -f deploy/kubernetes
	kubectl wait --for=condition=available \
          --timeout=1m deploy/postee
