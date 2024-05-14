ARCH=		$(shell arch)
TEST_ARCH=

run_tests=	yes
ifdef TEST_ARCH
ifneq "$(TEST_ARCH)" "$(ARCH)"
run_tests=	no
endif
endif


all:

container:
	docker buildx bake

download:
	go mod download

build:
	CGO_ENABLED=0 go build -o /go/bin/dtm

test:
ifeq "$(run_tests)" "yes"
	go vet ./...
	go test -race ./...
endif
