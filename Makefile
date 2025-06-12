ARCH=		$(shell arch)
TEST_ARCH=
OUTPUT=tapir-edm
SPECFILE:=rpm/SPECS/tapir-edm.spec

run_tests=	yes
ifdef TEST_ARCH
ifneq "$(TEST_ARCH)" "$(ARCH)"
run_tests=	no
endif
endif


all:

container:
	KO_DOCKER_REPO=ko.local ko build --bare

build:
	go mod download
ifeq "$(run_tests)" "yes"
	go vet ./...
	go test -race ./...
endif
	CGO_ENABLED=0 go build -o $(OUTPUT)

clean:
	-rm -f $(OUTPUT)
	-rm -f edm
	-rm -f VERSION
	-rm -f *.tar.gz
	-rm -f rpm/SOURCES/*.tar.gz
	-rm -rf rpm/{BUILD,BUILDROOT,SRPMS,RPMS}

tarball:
	git describe --always --tags --dirty | awk -F "-" '{print $$1"^"$$2"."$$3}' > VERSION
	git archive --format=tar.gz --prefix=$(OUTPUT)/ -o $(OUTPUT).tar.gz --add-file VERSION HEAD

srpm: SHELL:=/bin/bash
srpm: tarball
	mkdir -p rpm/{BUILD,RPMS,SRPMS}
	cp $(OUTPUT).tar.gz rpm/SOURCES/
	rpmbuild -bs --define "%_topdir ./rpm" --define "%_tapirrelease $$(cat VERSION)" --undefine=dist $(SPECFILE)
	test -z "$(outdir)" || cp rpm/SRPMS/*.src.rpm "$(outdir)"
