PROJECT := github.com/juju/http

.PHONY: check-go check

check:  check-go
	go test --race -gocheck.v $(PROJECT)/...

check-go:
	$(eval GOFMT := $(strip $(shell gofmt -l .| sed -e "s/^/ /g")))
	@(if [ x$(GOFMT) != x"" ]; then \
		echo go fmt is sad: $(GOFMT); \
		exit 1; \
	fi )
	@(go vet -all -composites=false -copylocks=false $(PROJECT)/...)

vendor-dependencies:
## vendor-dependencies: updates vendored dependencies
	@go mod vendor

# Reformat source files.
format:
## format: Format the go source code
	gofmt -w -l .
