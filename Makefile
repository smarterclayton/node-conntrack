build:
	go build -o bin/node-conntrack ./cmd/node-conntrack
.PHONY: build

test:
	go test ./...
.PHONY: test

vendor:
	glide up -v --skip-test
.PHONY: vendor

deploy.yaml: manifests/*
	for i in manifests/*; do echo '---'; cat $$i; echo; done > deploy.yaml