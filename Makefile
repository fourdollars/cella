.PHONY: build run clean test

BINARY := cella
VERSION := 0.1.0-dev
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

build:
	go build $(LDFLAGS) -o $(BINARY) ./cmd/

run: build
	./$(BINARY)

clean:
	rm -f $(BINARY)

test:
	go test ./...

# Cross compile for deployment to LXD hosts
build-linux-amd64:
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o $(BINARY)-linux-amd64 ./cmd/

build-linux-arm64:
	GOOS=linux GOARCH=arm64 go build $(LDFLAGS) -o $(BINARY)-linux-arm64 ./cmd/
