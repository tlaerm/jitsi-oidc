BINARY := jitsi-oidc

.PHONY: build test tidy lint run

build:
	go build -ldflags "-s -w" -o $(BINARY) ./cmd/jitsi-oidc

test:
	go test ./...

tidy:
	go mod tidy

run:
	go run ./cmd/jitsi-oidc

