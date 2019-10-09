SOURCEDIR = .
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

# Require the Go compiler/toolchain to be installed
ifeq (, $(shell which go 2>/dev/null))
$(error No 'go' found in $(PATH), please install the Go compiler for your system)
endif

.DEFAULT_GOAL: generate

.PHONY: generate
generate:
	go generate ./...

.PHONY: test
test:
	go test -race ./...

.PHONY: testv
testv:
	go test -v -race ./...

.PHONY: modprobe
modprobe:
ifeq ($(shell id -u),0)
	-modprobe -a nf_conntrack nf_conntrack_ipv4 nf_conntrack_ipv6
else
	-sudo modprobe -a nf_conntrack nf_conntrack_ipv4 nf_conntrack_ipv6
endif

.PHONY: integration
integration: modprobe
ifeq ($(shell id -u),0)
	go test -v -race -coverprofile=cover-int.out -covermode=atomic -tags=integration ./...
else
	$(info Running integration tests under sudo..)
	go test -v -race -coverprofile=cover-int.out -covermode=atomic -tags=integration -exec sudo ./...
endif

.PHONY: coverhtml-integration
coverhtml-integration: integration
	go tool cover -html=cover-int.out

.PHONY: bench
bench:
	go test -bench=. ./...

.PHONY: bench-integration
bench-integration: modprobe
	go test -bench=. -tags=integration -exec sudo ./...

cover: cover.out
cover.out: $(SOURCES)
	go test -coverprofile=cover.out -covermode=atomic ./...
	go tool cover -func=cover.out

.PHONY: coverhtml
coverhtml: cover
	go tool cover -html=cover.out

.PHONY: check
check: test cover
	go vet ./...
	megacheck ./...
	golint -set_exit_status ./...

# Build integration test binary to run in Vagrant VM
build-integration: build/integration.test
build/integration.test: $(SOURCES)
	go test -c -o build/integration.test -covermode=atomic -tags integration

# Execute the integration tests in Vagrant VM
CMD := sudo /build/integration.test -test.v -test.coverprofile /build/
vagrant-integration: build/integration.test

	@echo -e "\n\e[33m-> centos7"
	@vagrant ssh centos7 -c "${CMD}centos7.out" && echo "centos7 successful!"

	@echo -e "\n\e[94m-> ubuntu-precise"
	@vagrant ssh precise -c "${CMD}precise.out" && echo "ubuntu-precise successful!"

	@echo -e "\n\e[95m-> ubuntu-trusty"
	@vagrant ssh trusty -c "${CMD}trusty.out" && echo "ubuntu-trusty successful!"

	@echo -e "\n\e[96m-> ubuntu-xenial"
	@vagrant ssh xenial -c "${CMD}xenial.out" && echo "ubuntu-xenial successful!"

	@echo -e "\e[0m"
