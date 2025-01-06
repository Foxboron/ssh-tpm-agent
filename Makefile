PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
SHRDIR := $(PREFIX)/share
MANDIR := $(PREFIX)/share/man
BINS = $(filter-out %_test.go,$(notdir $(wildcard cmd/*)))
TAG = $(shell git describe --abbrev=0 --tags)
VERSION = $(shell git describe --abbrev=7 | sed 's/-/./g;s/^v//;')

MANPAGES = \
	man/ssh-tpm-hostkeys.1 \
	man/ssh-tpm-agent.1 \
	man/ssh-tpm-keygen.1 \
	man/ssh-tpm-add.1

all: man build
build: $(BINS)
man: $(MANPAGES)

.PHONY: $(addprefix bin/,$(BINS))
$(addprefix bin/,$(BINS)):
	go build -buildmode=pie -trimpath -o $@ ./cmd/$(@F)

# TODO: Needs to be better written
$(BINS): $(addprefix bin/,$(BINS))


.PHONY: install
install: $(BINS)
	@for bin in $(BINS); do \
		install -Dm755 "bin/$$bin" -t '$(DESTDIR)$(BINDIR)'; \
	done;
	for manfile in $(MANPAGES); do \
		install -Dm644 "$$manfile" -t '$(DESTDIR)$(MANDIR)/man'"$${manfile##*.}"; \
	done;
	@install -dm755 $(DESTDIR)$(LIBDIR)/systemd/system
	@install -dm755 $(DESTDIR)$(LIBDIR)/systemd/user
	@DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) bin/ssh-tpm-hostkeys --install-system-units 
	@TEMPLATE_BINARY=$(BINDIR)/ssh-tpm-agent DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) bin/ssh-tpm-agent --install-user-units --install-system

.PHONY: lint
lint:
	go vet ./...
	staticcheck ./...

.PHONY: test
test:
	go test -v ./...

.PHONY: clean
clean:
	rm -rf bin/
	rm -f $(MANPAGES)

sign-release:
	gh release download $(TAG)
	gpg --sign ssh-tpm-agent-$(TAG)-linux-amd64.tar.gz
	gpg --sign ssh-tpm-agent-$(TAG)-linux-arm64.tar.gz
	gpg --sign ssh-tpm-agent-$(TAG)-linux-arm.tar.gz
	bash -c "gh release upload $(TAG) ssh-tpm-agent-$(TAG)*.gpg"

man/%: man/%.adoc Makefile
	asciidoctor -b manpage -amansource="ssh-tpm-agent $(VERSION)" -amanversion="$(VERSION)" $<
