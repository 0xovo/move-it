# Desktop releases

The release workflow builds a **draft**, never publishes it. It uses the official
MIT-licensed `tauri-action` 0.5.23 (2025-08-25), pinned to its full commit. Action
versions and licenses are noted in the workflow. Desktop dependencies and their
pins are listed in `app/README.md`.

Before the first release, the repository owner must generate and retain the
production updater key privately. Set `TAURI_SIGNING_PRIVATE_KEY` and, if used,
`TAURI_SIGNING_PRIVATE_KEY_PASSWORD` as Actions secrets. Commit only the public
key to `app/src-tauri/tauri.conf.json`. Never use a test signing key for a release.
The workflow refuses a missing secret or malformed public key. Keep a secure
backup of the private key: replacing the key is not a transparent update for
existing installations.

After review and merge, create a stable `vX.Y.Z` tag on a commit contained in
`main`. The version must match the Tauri config. Pushing the tag starts the
workflow on that commit only. Published releases are not valid rebuild targets.

The matrix builds Linux x86_64 (AppImage, deb, rpm), Windows x86_64 (NSIS and MSI),
and macOS arm64 and x86_64 (app archive and DMG). Uploads run serially because the
action reads and merges the draft's `latest.json`. The verification job checks
all four updater platforms, their matching signature sidecars, expected installer
types, and versioned HTTPS asset URLs, then uploads `SHA256SUMS` for every asset.
A follow-up job refreshes ClamAV definitions, scans every draft asset, and
optionally looks up each SHA256 on VirusTotal when `VT_API_KEY` is configured.
Any detection fails the workflow and leaves the release a draft. These checks
validate packaging completeness; the updater verifies signatures when installing.
Production installation and upgrade smoke tests remain required.

The dependency job runs `cargo audit --locked` and `npm audit --audit-level=high`
with pinned tooling before any installer build begins.

Review the draft assets and machine proof report before manually publishing.
The stable feed is:
`https://github.com/0xovo/move-it/releases/latest/download/latest.json`.
A draft does not replace that feed. AppImage, Windows, and macOS support in-app
updates; deb/rpm installations direct users to GitHub for a new package.

Updater signing is separate from Windows Authenticode, Apple Developer signing,
and notarization. This workflow does not provision paid developer accounts or
platform certificates. Unsigned platform installers can show OS trust warnings;
production distribution policy must be settled before publishing.

Run `python3 -m unittest discover -s scripts -p 'test_release.py'` for the local
release-metadata checks. Run heavy app builds and tests through the local job
gate when required by the development environment.
