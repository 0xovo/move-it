# Contributing to Move It

Move It moves a whole browser (logins, cookies, passwords, extensions and
their settings, bookmarks, history) between devices and between browsers,
end to end encrypted.

## Layout

- `core/` is the Rust engine (`moveit-core`): store readers and writers,
  per-OS crypto, the sealed box, pairing, and transactions with backup
  and undo.
- `harness/` is `moveit-harness`: an overnight stress test over the core
  (fleet convergence, idempotence, undo), plus `probe-logins` and
  `probe-cookies`.
- `tools/proof-matrix/`, the automated proof harness (below), is not in
  this tree yet; the maintainers run it.
- `design/` holds the app screens and the loader: plain HTML, CSS, and
  JS. The wiring contract is in `design/README.md`. The app shell that
  serves them is not in this repo yet.

## Setup

Stable Rust toolchain (workspace edition 2021).

```sh
cargo build --workspace
cargo test --workspace
```

Tests must be green before you open a PR. If a test fails on a clean
checkout, open an issue instead of working around it.

## Proof runs

The engine is also proven end to end by a proof matrix. It downloads
real browsers into a throwaway workspace, drives each one against a
local test server (fake sign-in, saved password, cookies, a bookmark,
history from the test pages, and a test extension writing markers
through every extension storage type), moves the profile to a second
throwaway profile, verifies the decrypted values there, then deletes
what it created. It never touches a real browser profile. It runs on
Python 3 and bootstraps its own Python dependencies.

The matrix is not in this tree yet, so it is maintainer-run: on a PR
that changes the engine, a store, or the crypto, the maintainers run
it over the affected browsers and post the summary on the PR. What a
contributor owes is in the tree: the test suite green, and tests for
new behavior.

How its verdicts work:

- The default mover is the Rust core. A Python reference lane exists;
  its two known limits (login writes into current-schema / v43
  profiles, and the leveldb localStorage reader via plyvel) report
  LIMITED there. Under Rust those rows are real pass/fail.
- Cleanup is part of the verdict: leftover processes, profiles, or
  downloads fail the run even if every row passed.
- Windows and macOS runs need a signed-in desktop session, or the
  credential store is locked and the run reports INCONCLUSIVE
  (honest, not a pass, not an engine failure). FAIL, LIMITED, and
  INCONCLUSIVE are all legitimate when true. Never massage a verdict.
- Do not commit raw run output; summaries say the OS and the browser
  versions they ran on.
- Its self-tests include a deliberately broken mover
  (`fake-drop-logins`) that must fail in exactly one row; a self-test
  that cannot fail is not a test.

## Opening a pull request

- One topic per PR. A bug fix and a refactor are two PRs.
- Branch names are `yourname/short-topic`: lowercase, hyphens, your
  own handle.
- New behavior ships with tests.
- Commit messages are one short lowercase line. No body, no trailers.
  Say what changed.
- Keep PRs clean: no personal data, no credentials, nothing that is
  not part of the project.
- Dependencies must be GPL-3.0-compatible (see License). Ask before
  adding one you are unsure about.

## Review

A PR gets a first review from a maintainer, then a final review, and
merges only on the project owner's word. Maintainers run their own
pre-release checks before merging and publishing. Expect questions about
evidence: what you ran, and what it showed.

Fast rejections:

- Failing tests, or tests removed to hide a failure.
- Compatibility or performance claims with no tests behind them.
- Personal data or credentials in the diff.
- Style drift: match the surrounding code (naming, error handling,
  comment density).

## The release bar

A release means the engine is proven, not just built: proof matrix green
across Linux, Windows, and macOS on the browsers people use (Brave,
Chrome, Chromium, Edge, and family members as they are added). Changes
that touch that claim wait until the runs exist.

## License

Move It is GPL-3.0-or-later, and by contributing you agree that your
contribution is licensed the same way. The Move It name, the lemur,
and the logo are not covered by the license; forks need their own name
and art.
