# Fuzzing

One target per parser in `fuzz_targets/`, each calling an entry point in
`rescue_core::fuzz_api` so the harness and the regression replay cannot drift
apart. The fuzz crate builds on the pinned nightly named in
`.github/workflows/fuzz.yml`; `cargo-fuzz` is pinned there too.

The fixed-seed smoke CI runs on every pull request:

```sh
cargo +nightly-2026-10-15 fuzz run parse_secret -- -runs=10000 -seed=1 -max_len=16384
```

A finding lands in `fuzz/artifacts/<target>/`. Copy it to
`fuzz/regressions/<target>/<name>.bin` and it replays on stable from then on.
