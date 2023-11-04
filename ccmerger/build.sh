#!/bin/bash

go mod tidy
rm -rf main main.zip

GOOS=linux GOARCH=amd64 go build -a -ldflags '-linkmode external -extldflags "-static"' -tags musl -o main main.go lib.go
zip main.zip main scf_bootstrap ../*.yaml
