# Build stage
FROM golang:1.20.3 AS builder
WORKDIR /go/src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV CGO_ENABLED=0
RUN go build -o /go/bin/cvedetect cmd/cvedetect/main.go

# Prod stage
FROM cgr.dev/chainguard/busybox:latest
COPY --from=builder /go/bin/cvedetect /bin/cvedetect
ENTRYPOINT [ "/bin/cvedetect" ]
