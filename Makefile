MODULE := github.com/cayo-rodrigues/safe
COVERPROFILE := coverage.out

.PHONY: test coverage coverage-html tag release pkg-go-dev

test:
	go test -run 'TestFields' -v ./internal/tests/

coverage:
	go test ./internal/tests/ -coverpkg=./... -coverprofile=$(COVERPROFILE)
	go tool cover -func=$(COVERPROFILE)

coverage-html: coverage
	go tool cover -html=$(COVERPROFILE)

# Usage: make tag VERSION=vX.Y.Z
tag:
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)

# Usage: make pkg-go-dev VERSION=vX.Y.Z
pkg-go-dev:
	curl -fsSL "https://proxy.golang.org/$(MODULE)/@v/$(VERSION).info"

# Usage: make release VERSION=vX.Y.Z
release: tag pkg-go-dev
