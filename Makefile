.PHONY: build test lint fmt check doc clean all help

# Default target
all: check

# Build the project
build:
	cargo build

# Run tests
test:
	cargo test

# Run clippy linting
lint:
	cargo clippy -- -D warnings

# Format code
fmt:
	cargo fmt

# Check formatting
fmt-check:
	cargo fmt -- --check

# Generate documentation
doc:
	cargo doc --no-deps

# Run all quality gates
check: build test lint fmt-check doc
	@echo "✅ All quality gates passed!"

# Run all quality gates using automation script
verify:
	./scripts/verify.sh

# Clean build artifacts
clean:
	cargo clean

# Show help
help:
	@echo "Sylva Build System"
	@echo "=================="
	@echo "Available targets:"
	@echo "  build     - Build the project"
	@echo "  test      - Run all tests"
	@echo "  lint      - Run clippy linting"
	@echo "  fmt       - Format code"
	@echo "  fmt-check - Check code formatting"
	@echo "  doc       - Generate documentation"
	@echo "  check     - Run all quality gates"
	@echo "  verify    - Run all quality gates using automation script"
	@echo "  clean     - Clean build artifacts"
	@echo "  help      - Show this help message"