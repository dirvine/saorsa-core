# Saorsa Core - Task Completion Workflow

## MANDATORY Steps Before Any Commit

### 1. Code Quality Checks (MUST PASS)
```bash
# Format code
cargo fmt

# Strict linting with ZERO tolerance
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used

# Security audit
cargo audit
```

### 2. Testing (MUST ALL PASS)
```bash
# Run all tests
cargo test

# Run adaptive network test suite
./scripts/test_adaptive_network.sh

# Run specific tests if needed
cargo test --test <specific_test>
```

### 3. Build Verification
```bash
# Debug build
cargo build

# Release build (for final verification)
cargo build --release
```

### 4. Documentation (if public APIs changed)
```bash
# Build documentation
cargo doc --open

# Verify all public items are documented
```

## Critical Requirements

### Zero Panic Policy Enforcement
- **NO** `.unwrap()` in production code
- **NO** `.expect()` in production code  
- **NO** `panic!()` in production code
- **NO** `todo!()` or `unimplemented!()`
- Use proper error handling with `Result` types

### Version Management
- Update `Cargo.toml` version for releases
- Follow semantic versioning
- Update version in README examples if needed

### Git Workflow
```bash
# Check status
git status

# Stage changes
git add .

# Commit with conventional commit format
git commit -m "feat: description" # or fix:, chore:, etc.

# Push changes
git push
```

## Publishing Workflow (crates.io)
```bash
# 1. Ensure all tests pass
cargo test

# 2. Ensure clean build
cargo build --release

# 3. Update version in Cargo.toml
# 4. Commit version bump
git commit -am "chore: bump version to X.Y.Z"

# 5. Publish
cargo publish

# 6. Tag release
git tag vX.Y.Z
git push --tags
```

## CI/CD Considerations
- GitHub Actions enforces all quality checks
- Tests run on stable and nightly Rust
- Code coverage tracked
- Security audits automated
- Documentation builds verified

## Key Points
- **Quality over speed** - Never compromise on code quality
- **Test coverage** - All new features need tests
- **Documentation** - Public APIs must be documented
- **Security** - Follow secure coding practices
- **Performance** - Consider performance implications