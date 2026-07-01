VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X 'github.com/versus/wg-webui/web.Version=$(VERSION)'"
BINARY  := wg-webui
DIST    := dist

.PHONY: build all linux-amd64 linux-arm64 linux-arm clean

## build: build for the current platform
build:
	go build $(LDFLAGS) -o $(BINARY) .

## all: build for all supported platforms into ./dist
all: linux-amd64 linux-arm64 linux-arm

linux-amd64:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-$(VERSION)-linux-amd64 .

linux-arm64:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-$(VERSION)-linux-arm64 .

linux-arm:
	@mkdir -p $(DIST)
	GOOS=linux GOARCH=arm GOARM=7 go build $(LDFLAGS) -o $(DIST)/$(BINARY)-$(VERSION)-linux-arm7 .

## clean: remove build artifacts
clean:
	rm -rf $(DIST) $(BINARY)
