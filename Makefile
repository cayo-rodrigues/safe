MODULE := github.com/cayo-rodrigues/safe

.PHONY: test tag release pkg-go-dev

test:
	go test -v ./internal/tests/

# Usage: make tag VERSION=vX.Y.Z
tag:
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)

# Usage: make pkg-go-dev VERSION=vX.Y.Z
pkg-go-dev:
	curl -fsSL "https://proxy.golang.org/$(MODULE)/@v/$(VERSION).info"

# Usage: make release VERSION=vX.Y.Z
release: tag pkg-go-dev
