BINARY_NAME := "log-enricher"
IMAGE_NAME := $(shell basename "$(PWD)")
VERSION := $(shell git describe --tags --always)

GOBASE := $(shell pwd)
GOPATH := $(GOBASE)/vendor:$(GOBASE)
GOBIN := $(GOBASE)/bin
GOFILES := $(wildcard *.go)

GOSECNAME := "gosec_2.6.1_linux_amd64"

LDFLAGS :=-ldflags "-w -extldflags -static"


all: build

build: 
	@-$(MAKE) -s go-compile

run: 
	@-$(GOBIN)/$(BINARY_NAME)

clean:
	@-rm $(GOBIN)/$(BINARY_NAME) 2> /dev/null
	@-$(MAKE) go-clean

image: 
	@-$(MAKE) docker-build

push: 
	@-$(MAKE) docker-push

docker-build: 
	@echo "  >  Building image $(REGISTRY)/$(IMAGE_NAME):$(VERSION)"
	@docker build -t $(REGISTRY)/$(IMAGE_NAME):$(VERSION) .

docker-push: 
	@echo "  >  Building image $(REGISTRY)/$(IMAGE_NAME):$(VERSION)"
	@docker build -t $(REGISTRY)/$(IMAGE_NAME):$(VERSION) .

test: go-test

go-compile: go-build

go-build:
	@echo "  >  Building binary..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go build -a $(LDFLAGS) -o $(GOBIN)/$(BINARY_NAME) $(GOFILES)

go-generate:
	@echo "  >  Generating dependency files..."
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go generate $(generate)

go-clean:
	@echo "  >  Cleaning build cache"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go clean

go-test:
	@echo "  >  Running tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -mod=mod ./...

go-test-coverage:
	@echo "  >  Running tests"
	@GOPATH=$(GOPATH) GOBIN=$(GOBIN) go test -mod=mod -coverprofile=coverage.txt -covermode=atomic ./... 


verify: verify-gospec

verify-gospec:
	@echo "  >  Downloading $(GOSECNAME)"
	@GOSECNAME=$(GOSECNAME) .github/tools/run-gosec.sh	

export-coverage:
	@-$(MAKE) go-test-coverage && .github/tools/codecov.sh