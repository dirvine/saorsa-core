# Code Quality Standards

## Overview

This project enforces strict code quality standards to ensure production-ready, panic-free Rust code.

## Enforced Standards

### 🚫 No Panics in Production Code

Production code **MUST NOT** contain:
- `.unwrap()` - Use `?` operator or proper error handling
- `.expect()` - Use `.context()` from `anyhow` instead
- `panic!()` - Return errors instead
- `unimplemented!()` - Complete implementations before merging
- `todo!()` - Finish all TODOs before committing

**Exception**: Test code may use `.unwrap()` and `.expect()` for assertions.

### ✅ Required Patterns

```rust
// ❌ BAD: Can panic
let value = some_option.unwrap();
let result = some_result.expect("failed");

// ✅ GOOD: Proper error handling
let value = some_option.ok_or(Error::MissingValue)?;
let result = some_result.context("operation failed")?;
```

### 🔍 Automatic Enforcement

1. **Pre-commit Hooks**: Run checks locally before committing
2. **CI/CD Pipeline**: GitHub Actions enforces all standards
3. **Clippy Warnings**: Configured to catch unsafe patterns

## Setup

### Enable Git Hooks (Recommended)

```bash
# Run once after cloning the repository
./setup-git-hooks.sh
```

This will configure Git to run quality checks before each commit.

### Manual Checks

```bash
# Format code
cargo fmt

# Run clippy with strict checks
cargo clippy -- -D warnings -D clippy::unwrap_used -D clippy::expect_used

# Run tests
cargo test

# Security audit
cargo audit
```

## CI/CD Pipeline

The `.github/workflows/rust-quality.yml` workflow enforces:

1. **Clippy** - Strict safety and quality checks
2. **Format** - Consistent code formatting
3. **Production Safety** - No unwrap/expect in production code
4. **Security Audit** - Check for known vulnerabilities

All checks must pass before merging to main branch.

## Common Issues and Solutions

### Issue: "use of `.unwrap()`"

**Solution**: Replace with proper error handling:

```rust
// Array conversion
hash_bytes[0..4].try_into()
    .map_err(|_| Error::InvalidByteArray)?

// Option handling
value.ok_or(Error::MissingValue)?

// Sorting with partial_cmp
items.sort_by(|a, b| a.partial_cmp(b).unwrap_or(Ordering::Equal))
```

### Issue: "use of `.expect()`"

**Solution**: Use `.context()` from anyhow:

```rust
// Instead of:
file.read_to_string(&mut contents).expect("Failed to read file");

// Use:
file.read_to_string(&mut contents)
    .context("Failed to read file")?;
```

### Issue: Silent Failures

**Solution**: Always propagate errors:

```rust
// ❌ BAD: Silent failure
if let Some(value) = might_fail() {
    process(value);
}
// Missing else - error is ignored!

// ✅ GOOD: Handle all cases
let value = might_fail()
    .ok_or(Error::OperationFailed)?;
process(value);
```

## Bypassing Checks (Emergency Only)

In rare cases where you need to bypass checks:

```bash
# Skip pre-commit hooks (not recommended)
git commit --no-verify

# Allow specific clippy warnings in code
#[allow(clippy::unwrap_used)]  // Document why this is safe
```

**Note**: Any bypassed checks must be documented and justified in code review.

## Benefits

Following these standards ensures:
- 🛡️ **No runtime panics** in production
- 🔒 **Predictable error handling**
- 📊 **Better error reporting**
- 🚀 **Higher reliability**
- ⚡ **Easier debugging**

## Questions?

If you encounter issues with these standards, please:
1. Check this documentation
2. Run `cargo clippy --explain <lint_name>` for specific lint help
3. Ask in code review for guidance