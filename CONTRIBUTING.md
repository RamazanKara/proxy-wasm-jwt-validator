# Contributing

Thanks for improving proxy-wasm-jwt-validator.

Run the checks before opening a change:

```bash
cargo fmt --all --check
cargo test --all
cargo clippy --target wasm32-unknown-unknown --all-targets -- -D warnings
cargo build --release --target wasm32-unknown-unknown
```

To verify behavior against vmod-wasm:

```bash
VMOD_WASM_REPO=../vmod-wasm ./scripts/test-vmod-wasm.sh
```

Changes to token parsing, signature verification, time validation, claim
validation, or failure mode should include both Rust unit tests and a VTC case.
