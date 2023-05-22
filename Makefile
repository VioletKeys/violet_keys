# Third verse same as the first....

all: test

# Build all the things
build:
	cargo build

# Upgrade the dependencis
upgrade:
	cargo update --aggressive

# Test suite, define all our tests here
test: test-rust

# Run tests for Rust code without localstack
test-rust: build
	cargo test

clean: 
	cargo clean

