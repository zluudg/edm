FROM golang:1.22.3 as build

ARG RUN_TESTS=1

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN test $RUN_TESTS -eq 1 && go vet ./...
RUN test $RUN_TESTS -eq 1 && go test -race ./...

RUN CGO_ENABLED=0 go build -o /go/bin/dtm


FROM cgr.dev/chainguard/static:latest

COPY --from=build /go/bin/dtm /
CMD ["/dtm"]
