FROM golang:1.22.3 as build

WORKDIR /go/src/app
COPY . .

RUN go mod download
RUN go vet ./...
RUN go test -race ./...

RUN CGO_ENABLED=0 go build -o /go/bin/dtm

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /go/bin/dtm /
CMD ["/dtm"]
