.PHONY: all build install uninstall clean test help

VERSION := 0.3.0
PREFIX  := $(HOME)/.local

all: build

## Build daemon and client
build:
	cargo build --release
	cd scrt-client && cargo build --release

## Build, install binaries, and start systemd service
install: build
	@mkdir -p $(PREFIX)/bin
	install -m 755 target/release/scrt-daemon $(PREFIX)/bin/
	install -m 755 scrt-client/target/release/scrt-client $(PREFIX)/bin/
	install -m 755 bin/scrt $(PREFIX)/bin/
	@# Ensure LF line endings on the shell script
	@sed -i 's/\r$$//' $(PREFIX)/bin/scrt
	./install/install.sh

## Remove installed files and stop service
uninstall:
	./install/uninstall.sh

## Remove build artifacts
clean:
	cargo clean
	cd scrt-client && cargo clean

## Run tests
test:
	cargo test
	cd scrt-client && cargo test

## Show available targets
help:
	@echo "scrt WSL daemon v$(VERSION)"
	@echo ""
	@echo "Targets:"
	@echo "  make build     - Build daemon and client"
	@echo "  make install   - Build, install, and start service"
	@echo "  make uninstall - Stop service and remove binaries"
	@echo "  make clean     - Remove build artifacts"
	@echo "  make test      - Run tests"
