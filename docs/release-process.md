# Release process

A release has four steps. `scripts/release.py` does the first and the last.

1. `scripts/release.py prepare X.Y.Z` writes the release commit.
2. `git push origin main` puts the commit on GitHub.
3. Wait for the `CI` workflow to pass on that commit.
4. `scripts/release.py publish` tags it and checks the GitHub release.

`scripts/release.py --dry-run prepare X.Y.Z` and `--dry-run publish` show every
command and file change and carry none out. Both commands still run their
read-only checks, so a stop shows up in a dry run too.

## prepare

Needs `git`, `cargo`, `rustc`, `rustup` and `cargo-audit`. Stops, before it
writes anything, when:

- `X.Y.Z` is not a version like `2.1.0` or `2.1.0-rc1`.
- A tracked file has uncommitted changes.
- The tag `vX.Y.Z` exists locally or on `origin`.
- The first `## [` heading of `CHANGELOG.md` has a date, so no section is open.

CI installs the latest stable Rust, so `prepare` stops when the `rustc` on
PATH is not rustup's stable one. Put `~/.cargo/bin` first in PATH and run
`rustup update stable` first.

Then it runs the checks of the `CI` workflow: `cargo fmt --check`, both
clippy runs, `scripts/check-docs-tools.sh`, `cargo audit`,
`cargo build --release` and the CI test command. A failure stops the script
with nothing written. `--skip-test` leaves out the tests.

Then it:

- sets `version` under `[package]` in `Cargo.toml`,
- runs `cargo update -p narsil-xref --offline` so `Cargo.lock` follows,
- renames the open `CHANGELOG.md` section to `## [X.Y.Z] - <today>`,
- commits all three files as `Release X.Y.Z`.

It prints the push command and does not push.

## publish

Needs `git` and `gh`. Run it from the checkout that holds the release commit.
Stops when:

- A tracked file has uncommitted changes.
- `HEAD` is not the commit `origin/main` points at.
- The `CI` run for `HEAD` is missing, still running, or did not succeed.
  `--skip-ci-check` bypasses this.
- The tag `vX.Y.Z` is on `origin` at another commit than `HEAD`.

The version is read from `Cargo.toml` at `HEAD`.

Then it:

- creates the annotated tag `vX.Y.Z` at `HEAD` and pushes it, unless `origin`
  has the tag at `HEAD` already (a repeated `publish` continues from there),
- waits for the `Release` workflow run of the tag with
  `gh run watch --exit-status`,
- replaces the generated release notes with the `CHANGELOG.md` section of
  `X.Y.Z` (`gh release edit --notes-file`),
- checks the release lists, for `linux-x86_64` and `linux-aarch64`, the
  tarball, the `.deb` and a `.sha256` file of each, and fails naming every
  file that is missing.

The `Release` workflow (`.github/workflows/release.yml`) starts on tags
`v[0-9]+.*`. It fails when the tag does not match the `Cargo.toml` version.

## Forks

Workflows of a GitHub fork do not run until the owner enables them on the
Actions tab of the fork. Until then `publish` finds no `CI` run for `HEAD`
and no `Release` run for the tag, and stops.
