.PHONY: build test clippy fmt doc clean install ci check bench

all: check

build:
	@echo "Building Sylva..."
	cargo build

build-release:
	@echo "Building Sylva (release)..."
	cargo build --release

test:
	@echo "Running tests..."
	cargo test

test-verbose:
	@echo "Running tests (verbose)..."
	cargo test -- --nocapture

clippy:
	@echo "Running clippy..."
	cargo clippy -- -D warnings

fmt-check:
	@echo "Checking code formatting..."
	cargo fmt -- --check

fmt:
	@echo "Formatting code..."
	cargo fmt

doc:
	@echo "Generating documentation..."
	cargo doc --no-deps

doc-open:
	@echo "Generating and opening documentation..."
	cargo doc --no-deps --open

clean:
	@echo "Cleaning build artifacts..."
	cargo clean

install:
	@echo "Installing Sylva..."
	cargo install --path .

bench:
	@echo "Running benchmarks..."
	cargo bench

ci: build test clippy fmt-check doc
	@echo "✅ All CI checks passed!"

check: build test clippy
	@echo "✅ Quick checks passed!"

dev: fmt check
	@echo "✅ Development checks complete!"

run-help:
	@echo "Testing CLI help output..."
	cargo run -- --help

verify: clean build test clippy fmt-check doc run-help
	@echo ""
	@echo "✅ All quality gates passed!"
	@echo "✅ cargo build - Clean compilation"
	@echo "✅ cargo test - All tests pass"
	@echo "✅ cargo clippy -- -D warnings - Zero clippy warnings"  
	@echo "✅ cargo fmt -- --check - Proper formatting"
	@echo "✅ cargo run -- --help - Shows Sylva usage correctly"
	@echo "✅ cargo doc --no-deps - Documentation generates without warnings"

help:
	@echo "Sylva Makefile Commands:"
	@echo ""
	@echo "Building:"
	@echo "  build         - Build the project"
	@echo "  build-release - Build in release mode"
	@echo "  clean         - Clean build artifacts"
	@echo "  install       - Install the binary"
	@echo ""
	@echo "Testing:"
	@echo "  test          - Run tests"
	@echo "  test-verbose  - Run tests with verbose output"
	@echo "  bench         - Run benchmarks"
	@echo ""
	@echo "Code Quality:"
	@echo "  clippy        - Run clippy lints"
	@echo "  fmt           - Format code"
	@echo "  fmt-check     - Check code formatting"
	@echo "  doc           - Generate documentation"
	@echo "  doc-open      - Generate and open documentation"
	@echo ""
	@echo "Workflows:"
	@echo "  ci            - Full CI pipeline"
	@echo "  check         - Quick development checks"
	@echo "  dev           - Development workflow (format + check)"
	@echo "  verify        - Complete quality gate verification"
	@echo "  run-help      - Test CLI help output"
	@echo ""
	@echo "  help          - Show this help message"