FROM golang:1.22.3 as build

ARG TEST_ARCH=

WORKDIR /go/src/app
COPY . .

RUN make download
RUN make TEST_ARCH=$TEST_ARCH test
RUN make build


FROM cgr.dev/chainguard/static:latest

COPY --from=build /go/bin/dtm /
CMD ["/dtm"]
