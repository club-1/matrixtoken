VERSION ?= $(shell git describe --tags --always)
BIN     ?= ./matrixtoken

all: matrixtoken matrixtoken.1

matrixtoken: go.mod go.sum *.go
	go build -ldflags '-X main.version=$(VERSION)'

matrixtoken.1: $(BIN) matrixtoken.h2m
	help2man --include=matrixtoken.h2m --no-info --section=1 $(BIN) -o $@

check:
	! gofmt -s -d . | grep ''
	go vet ./...
	go test -cover ./...

clean:
	rm -f matrixtoken matrixtoken.1

.PHONY: all check clean
