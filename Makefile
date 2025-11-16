.PHONY: install install-cli install-relay test relay cache-dir

CARGO_TARGET_DIR ?= $(HOME)/.cache/lit/target
export CARGO_TARGET_DIR

install: install-cli install-relay

install-cli: cache-dir
	cargo install --path lit-cli --force

install-relay: cache-dir
	cargo install --path lit-relay --force

test: cache-dir
	cargo fmt --all
	cargo test --all

relay: cache-dir
	cargo run --bin lit-relay -- --listen 127.0.0.1:50051 --storage-root ./.lit-relay

cache-dir:
	mkdir -p $(CARGO_TARGET_DIR)
