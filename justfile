# Default recipe: list available commands
default:
    @just --list

# Format all code (Rust + Nix + Markdown)
fmt:
    treefmt

# Check formatting (Rust + Nix + Markdown)
fmt-check:
    treefmt --fail-on-change --no-cache

# Run clippy lints
lint:
    cargo clippy --all-targets --all-features -- -D warnings

# Run all tests
test:
    cargo test --all-features

# Run the tests that talk to the real API. Needs DESEC_TOKEN from a test account with
# perm_create_domain, perm_delete_domain and perm_manage_tokens. Override the parent zone
# for scratch domains with DESEC_TEST_PARENT (default dedyn.io).
#
# These are #[ignore]d so `just test` and CI skip them; --ignored is what opts in. The
# thread cap bounds how many scratch domains exist at once, against limit_domains.
live-test *args='':
    cargo test --all-features --test live -- --ignored --nocapture --test-threads 4 {{args}}

# Build release
build:
    cargo build --release --all-features

# Generate documentation
doc *args='':
    cargo doc --no-deps --all-features {{args}}

readme_args := "--project-root crates/desec --input src/lib.rs --template ../../README.tpl"

# Regenerate README.md from README.tpl and the crate docs
readme:
    cargo readme {{readme_args}} | mdformat - > README.md

# Check README.md is in sync with README.tpl and the crate docs
readme-check:
    cargo readme {{readme_args}} | mdformat - | diff - README.md

# Assert the release tag names the version cargo would publish
check-version version:
    @pkgid="$(cargo pkgid -p desec)"; crate="v${pkgid##*#}"; \
    if [ "$crate" != "{{version}}" ]; then \
        echo "tag {{version}} does not match crate version $crate" >&2; exit 1; \
    fi

# Run CI checks locally
ci: fmt-check lint test doc readme-check build
    @echo "All CI checks passed!"

# Clean build artifacts
clean:
    cargo clean
