# Build stage
FROM golang:1.18.2 AS builder
WORKDIR /go/src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ENV GOOS=linux
ENV GOARCH=amd64
ENV CGO_ENABLED=0
RUN go build -o /go/bin/cvedetect cmd/cvedetect/main.go

# Prod stage
FROM alpine:3.16
COPY --from=builder /go/bin/cvedetect /bin/cvedetect
ENTRYPOINT [ "/bin/cvedetect" ]
