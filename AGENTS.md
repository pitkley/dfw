# Repository Guidelines

## Project Structure

DFW is a Rust 2024 tool that manages Docker firewall rules. `src/bin/dfw.rs` handles the CLI and Docker events. Shared configuration and rule processing live in `src/types.rs` and `src/process.rs`. The default nftables backend and the iptables backend live in `src/nftables/` and `src/iptables/`. Tests live in `tests/`, fixtures in `resources/test/`, and sample configurations and user guides in `examples/` and `docs/`.

## Build and Development

- `cargo build` compiles DFW; `cargo build --release` builds the optimized binary.
- `cargo run -- --check-config --config-file examples/minimal/dfw.toml` validates the sample configuration. Use `--dry-run` when exercising rule generation against a Docker environment without applying firewall changes.
- Before submitting, run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --features docker-tests -- -D warnings`, and `./hack/check-license-headers.sh`. CI also checks YAML with `yamllint`.

## Coding Style

Use rustfmt defaults, including four-space indentation. Use `snake_case` for modules and functions and `UpperCamelCase` for types and traits. Follow `.editorconfig`: use LF line endings, a final newline, and two-space indentation in YAML. Copy the existing dual-license header into new Rust files and Dockerfiles.

## Testing

Run `cargo test` for the default suite; use `cargo test parse_conf_file` to filter by name. Name new tests for the behavior they cover. Add parsing cases in `tests/types.rs` and rule regressions under `resources/test/docker/_regression-tests/`. Keep expected rules in the corresponding backend's `expected-*.txt` files. Run `cargo test --features docker-tests --test dfw -- --test-threads=1` with the Docker Compose plugin and `DOCKER_HOST` pointing to a test daemon (for example, `tcp://127.0.0.1:2375`). No numeric coverage threshold is configured.

## Commits and Pull Requests

Use short, imperative commit subjects such as `Update reverseproxy example`. History also uses prefixes like `fix(ci):` and `chore:` where helpful. In pull requests, describe the problem, the behavior change, and how you verified it. Link related issues and update the relevant examples or documentation when configuration changes.

Follow the [AI disclosure policy](README.md#aidisclosure). If Codex authors any part of a commit, add `Co-Authored-By: Codex <codex@users.noreply.github.com>` as a trailer in the commit body. This applies to commits written partly or entirely by Codex.
