FROM golang:1.18-alpine as builder

RUN mkdir /acme-aws-cert-manager
COPY go.mod /acme-aws-cert-manager/
COPY go.sum /acme-aws-cert-manager/
COPY main.go /acme-aws-cert-manager/

RUN cd /acme-aws-cert-manager;go mod tidy;go mod download;go build -o acme-aws-cert-manager
RUN echo "build complete"


#Runtime container
FROM alpine:3


COPY --from=builder /acme-aws-cert-manager/acme-aws-cert-manager /usr/local/bin/

RUN adduser -D certmanager
USER certmanager

ENTRYPOINT ["/usr/local/bin/acme-aws-cert-manager"]
