FROM ghcr.io/inspektor-gadget/local-gadget-builder:latest

WORKDIR /go/src/github.com/inspektor-gadget/inspektor-gadget/integration/local-gadget

RUN go test -c -o local-gadget-integration.test ./...
