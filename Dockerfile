FROM golang:1.22.3 as build

ARG TEST_ARCH=

WORKDIR /go/src/app
COPY . .

RUN make TEST_ARCH=$TEST_ARCH OUTPUT=/go/bin/edm build


FROM cgr.dev/chainguard/static:latest

COPY --from=build /go/bin/edm /
CMD ["/edm"]
