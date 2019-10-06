FROM openshift/origin-release:golang-1.12 AS builder
WORKDIR /go/src/github.com/smarterclayton/node-conntrack/
COPY . .
RUN GOPATH=/go go build -o /usr/bin/node-conntrack ./cmd/node-conntrack

FROM centos:7
COPY --from=builder /usr/bin/node-conntrack /usr/bin/
ENTRYPOINT [ "/usr/bin/node-conntrack" ]