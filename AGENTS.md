# Repository Guidelines

## Project Structure & Module Organization
- `src/`: Library crate (`saorsa-core`) with modules like `dht/`, `transport/`, `identity/`, `adaptive/`, `placement/`, `security.rs`, `validation.rs` (see `src/lib.rs` for exports).
- `tests/`: Integration and scenario tests (e.g., `*_integration_test.rs`, `*_property_tests.rs`).
- `benches/`: Criterion benchmarks; compiled with `cargo bench`.
- `examples/`: Build-only examples and snippets.
- `fuzz/`: `cargo-fuzz` targets (e.g., `fuzz_validation`, `fuzz_address_parsing`).
- `scripts/`: Helpers like `scripts/local_ci.sh` (full local CI) and `test_adaptive_network.sh`.
- `docs/`, `benches/`, `saorsa-testnet/`: Docs, perf, and local testnet assets.

## Architecture Overview
- Core: `network`, `transport` (QUIC), `dht` (+ `dht_network_manager`).
- Security: `quantum_crypto` (saorsa-pqc), `security`, `secure_memory`, `key_derivation`.
- Data/Storage: `storage`, `persistence`, `placement` (orchestrator, records, strategies).
- Apps/UX: `chat`, `messaging`, `discuss`, `projects`, `health`.
- Control/Config: `bootstrap`, `config`, `validation`, `production`, `utils`.

## Build, Test, and Development Commands
- Build: `cargo build --all-features` (release: `cargo build --release`).
- Test (all): `cargo test --all-features` (doc tests: `cargo test --doc`).
- Lint: `cargo clippy --all-features -- -D clippy::panic -D clippy::unwrap_used -D clippy::expect_used` (pedantic lints optional; treat them as warnings).
- Format: `cargo fmt --all -- --check` (apply fixes with `cargo fmt --all`).
- CI locally: `./scripts/local_ci.sh` (runs fmt, clippy, build, tests, extras safely).
- Bench: `cargo bench --all-features`.
- Fuzz: `cargo fuzz run fuzz_validation -- -max_total_time=60` (install with `cargo install cargo-fuzz`).

## Coding Style & Naming Conventions
- Rust 2024 edition; format with `rustfmt` (4 spaces, standard rules).
- No panics in non-test code: avoid `unwrap`, `expect`, and `panic!` in library/production paths (CI enforces).
- Tests are pragmatic: using `unwrap/expect/panic` in tests is fine for clarity and speed (see `.clippy.toml`).
- Pedantic lints: not required to be zero; fix if they improve clarity, otherwise treat as warnings.
- Naming: modules/dirs `snake_case`; types/traits `PascalCase`; functions `snake_case`; constants `SCREAMING_SNAKE_CASE`.
- Prefer `anyhow::Result`/`thiserror` for errors and `tracing` for logs.

## Testing Guidelines
- Use Rust tests in `src` and integration tests in `tests/`. Name files by concern, e.g., `gossipsub_integration_test.rs`, `property_tests.rs`.
- Property tests: `proptest`/`quickcheck`; isolate with `serial_test` when needed.
- Coverage (optional): `cargo llvm-cov --all-features --workspace --summary-only`.
- Mutation testing (optional): `cargo mutants` (configured by `mutation-testing.toml`).
- Fuzz critical parsers via `cargo-fuzz` targets in `fuzz/`.

## Commit & Pull Request Guidelines
- Follow Conventional Commits: `feat:`, `fix:`, `chore:`, `security:`, optional scopes (e.g., `feat(crypto): ...`).
- Keep changes focused; include tests and docs updates.
- Before opening a PR, run `./scripts/local_ci.sh` and ensure green.
- PRs should include: rationale, summary of changes, linked issues, test notes; attach logs if CI fails.

## Security & Configuration Tips
- Run `cargo audit` locally when touching dependencies.
- Default feature `metrics` enables Prometheus; disable with `--no-default-features` when necessary.

## Module Ownership
- Use focused PRs per module; ping maintainers by area in description: `[dht]`, `[transport]`, `[security]`, `[placement]`, `[adaptive]`.
- Add reviewers familiar with touched modules; align with `src/lib.rs` exports for boundaries.
- If adding a new module, update `src/lib.rs` exports and include tests under `tests/` with the module prefix.

## Local CI: How-To + Media
- Quick run: `./scripts/local_ci.sh` (ensures fmt, clippy, build, tests; protects `Cargo.lock`).
- Record a terminal GIF (optional):
  - asciinema: `asciinema rec docs/assets/ci.cast` then convert via `agg docs/assets/ci.cast docs/assets/ci_workflow.gif`.
  - Or Terminalizer: `terminalizer record ci` → `terminalizer render ci -o docs/assets/ci_workflow.gif`.
- Add screenshot/GIF under `docs/assets/` and reference in docs:
  - `![Local CI Workflow](docs/assets/ci_workflow.gif)`
- Share failures: attach `local_ci` output snippet and the GIF/screenshot in the PR for clarity.
