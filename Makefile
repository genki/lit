.PHONY: install install-cli install-relay

install: install-cli install-relay

install-cli:
	cargo install --path lit-cli --force

install-relay:
	cargo install --path lit-relay --force
