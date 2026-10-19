# Winnow Rescue

A rescue-only Bitcoin tool: it gets coins out of any old wallet, from recovery
words, a single key or another wallet's export, and sweeps them into a taproot
account the person already has. It is not for everyday use and privacy is not
its design goal; every check it makes is a published standard with vectors.

The core is a pure Rust library that wallets embed. The standalone product is a
desktop command-line tool and a desktop window, on macOS, Linux and Windows.

## Layout

| Path | Holds |
| --- | --- |
| `crates/rescue-core` | the pure core: derivation plans, coin proofs, the sweep and its checks; no I/O |
| `crates/rescue-electrum` | the default I/O: an Electrum client over TLS and an Esplora adapter |
| `crates/rescue-cli` | `rescue`, the five steps on the command line, with an offline signing mode |
| `crates/rescue-gui` | `rescue-gui`, the same five steps in one window |
| `fuzz/` | one fuzz target per parser; kept findings replay on stable |
| `vectors/` | reference data, one directory per upstream source |

## Checks

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo deny check
```

The toolchain is pinned in `rust-toolchain.toml`; `rustup show` installs it.
Every pull request is one commit, named `area: subject`, and lands only when
the checks above and the fuzz smoke are green.

Winnow Rescue is available under the [MIT License](LICENSE).
