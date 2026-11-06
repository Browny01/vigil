.PHONY: build test run
build:
	CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o bin/vigil .
test:
	go test -race ./...
run: build
	./bin/vigil -allow-signals
