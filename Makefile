.DEFAULT_GOAL := help

SHELL := /bin/bash

GO111MODULE := on

GOPKG += github.com/veraison/evcli/cmd/psa
GOPKG += github.com/veraison/evcli/cmd/cca

MOCKGEN := $(shell go env GOPATH)/bin/mockgen
INTERFACES := common/iveraisonclient.go
MOCKPKG := mocks

GOLINT ?= golangci-lint

ifeq ($(MAKECMDGOALS),lint)
GOLINT_ARGS ?= run --timeout=3m
else
  ifeq ($(MAKECMDGOALS),lint-extra)
  GOLINT_ARGS ?= run --timeout=3m --issues-exit-code=0 -E dupl -E gocritic -E gosimple -E lll -E prealloc
  endif
endif

.PHONY: lint lint-extra
lint lint-extra: _mocks; $(GOLINT) $(GOLINT_ARGS)

ifeq ($(MAKECMDGOALS),test)
GOTEST_ARGS ?= -v -race $(GOPKG)
else
  ifeq ($(MAKECMDGOALS),test-cover)
  GOTEST_ARGS ?= -short -cover $(GOPKG)
  endif
endif

COVER_THRESHOLD := $(shell grep '^name: cover' .github/workflows/ci-go-cover.yml | cut -c13-)

define MOCK_template
mock_$(1): $(1)
	$$(MOCKGEN) -source=$$< -destination=cmd/mocks/$$$$(basename $$@) -package=$$(MOCKPKG)
endef

$(foreach m,$(INTERFACES),$(eval $(call MOCK_template,$(m))))
MOCK_FILES := $(foreach m,$(INTERFACES),$(join mock_,$(m)))
CLEANFILES := $(MOCK_FILES)

_mocks: $(MOCK_FILES)
.PHONY: _mocks

.PHONY: test test-cover
test test-cover: _mocks; go test $(GOTEST_ARGS)

.PHONY: clean
clean: ; $(RM) $(CLEANFILES)

presubmit:
	@echo
	@echo ">>> Check that the reported coverage figures are $(COVER_THRESHOLD)"
	@echo
	$(MAKE) test-cover
	@echo
	@echo ">>> Fix any lint error"
	@echo
	$(MAKE) lint-extra

.PHONY: licenses
licenses: ; @./scripts/licenses.sh

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  * test:       run unit tests for $(GOPKG)"
	@echo "  * test-cover: run unit tests and measure coverage for $(GOPKG)"
	@echo "  * lint:       lint sources using default configuration"
	@echo "  * lint-extra: lint sources using default configuration and some extra checkers"
	@echo "  * presubmit:  check you are ready to push your local branch to remote"
	@echo "  * help:       print this menu"
	@echo "  * licenses:   check licenses of dependent packages"
