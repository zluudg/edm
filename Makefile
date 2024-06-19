ARCH=		$(shell arch)
TEST_ARCH=
OUTPUT=		edm

run_tests=	yes
ifdef TEST_ARCH
ifneq "$(TEST_ARCH)" "$(ARCH)"
run_tests=	no
endif
endif


all:

container:
	docker buildx bake

build:
	go mod download
ifeq "$(run_tests)" "yes"
	go vet ./...
	go test -race ./...
endif
	CGO_ENABLED=0 go build -o $(OUTPUT)

clean:
	rm -f $(OUTPUT)
