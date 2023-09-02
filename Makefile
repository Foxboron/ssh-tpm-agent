PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
LIBDIR := $(PREFIX)/lib
SHRDIR := $(PREFIX)/share
BINS = $(notdir $(wildcard cmd/*))
SRC = $(shell find . -type f -name '*.go' -not -path "./vendor/*")
TAG = $(shell git describe --abbrev=0 --tags)

all: build
build: $(BINS)

$(addprefix bin/,$(BINS)): $(SRC)
	go build -buildmode=pie -trimpath -o $@ ./cmd/$(@F)

# TODO: Needs to be better written
$(BINS): $(addprefix bin/,$(BINS))


.PHONY: install
install: $(BINS)
	@for bin in $(BINS); do \
		install -Dm644 "bin/$$bin" -t '$(DESTDIR)$(BINDIR)'; \
	done;
	@install -dm755 $(DESTDIR)$(LIBDIR)/systemd/system
	@install -dm755 $(DESTDIR)$(LIBDIR)/systemd/user
	@DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) bin/ssh-tpm-hostkeys --install-system-units 
	@TEMPLATE_BINARY=1 DESTDIR=$(DESTDIR) PREFIX=$(PREFIX) bin/ssh-tpm-agent --install-user-units --install-system

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
