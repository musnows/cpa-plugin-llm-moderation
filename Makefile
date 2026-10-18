GO ?= go
GOOS ?= $(shell $(GO) env GOOS)
GOARCH ?= $(shell $(GO) env GOARCH)
EXT := so
EXE :=
ifeq ($(GOOS),darwin)
EXT := dylib
endif
ifeq ($(GOOS),windows)
EXT := dll
EXE := .exe
endif
OUT := artifacts/$(GOOS)/$(GOARCH)/llm-moderation.$(EXT)

.PHONY: build fixture test verify
build:
	mkdir -p artifacts/$(GOOS)/$(GOARCH)
	CGO_ENABLED=1 GOOS=$(GOOS) GOARCH=$(GOARCH) $(GO) build -trimpath -buildmode=c-shared -o $(OUT) .

fixture:
	mkdir -p artifacts
	$(GO) build -o artifacts/mockserver$(EXE) ./testsupport/mockserver

test:
	$(GO) test ./...

verify:
	$(GO) vet ./...
	$(GO) test -race ./...
