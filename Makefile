MODULE := github.com/cayo-rodrigues/safe

.PHONY: test release pkg-go-dev

test:
	go test -v ./internal/tests/

# Usage: make release VERSION=vX.Y.Z
release:
	git tag -a $(VERSION) -m "Release $(VERSION)"
	git push origin $(VERSION)
	$(MAKE) pkg-go-dev VERSION=$(VERSION)

# Usage: make pkg-go-dev VERSION=vX.Y.Z
pkg-go-dev:
	curl -fsSL "https://proxy.golang.org/$(MODULE)/@v/$(VERSION).info"
