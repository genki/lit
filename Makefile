.PHONY: install install-cli install-relay test relay

install: install-cli install-relay

install-cli:
	cargo install --path lit-cli --force

install-relay:
	cargo install --path lit-relay --force

test:
	cargo fmt --all
	cargo test --all

relay:
	cargo run --bin lit-relay -- --listen 127.0.0.1:50051 --storage-root ./.lit-relay
