#!/bin/bash

go mod tidy
rm -rf main main.zip

GOOS=linux GOARCH=amd64 go build -a -ldflags '-linkmode external -extldflags "-static"' -tags musl -o main main.go lib.go
WORKDIR=$(mktemp -d)
cp main $WORKDIR && cp scf_bootstrap $WORKDIR && cp ../*.yaml $WORKDIR
cp -r ../cache $WORKDIR
(cd $WORKDIR && zip -r main.zip ./*)
cp $WORKDIR/main.zip ./
rm -rf $WORKDIR
