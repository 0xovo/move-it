# Move It desktop

A Tauri 2 shell over `moveit_core::api`, using the approved Calm paper styling,
Figtree font, and lemur loader from `design/`. The production page is assembled
from `src/`; design mockup scripts and fake progress timers are never loaded.
`prepare.mjs` copies the local UI and approved assets into `dist/` without a
bundler or network fetch.

From this directory:

```
npm ci
npm run tauri -- dev
npm run tauri -- build --locked
npm test
npm run test:e2e
```

Use the local job gate for installs, builds, and browser tests when required by
your environment. Linux builds need the Tauri GTK/WebKit system prerequisites.
The desktop Rust crate is a separate workspace in `src-tauri/`, with its own
lockfile; the repository workspace remains the engine and test harness.

Native commands run on blocking workers and share one engine instance under a
mutex, so logs and state survive navigation. A busy operation refuses another
command, and closing the window waits while an engine operation is active.
Browser-open checks run before moves and are also enforced by the engine.
Undo never forces replacement of changed browser data without a confirmation.
Cloud choices use existing local folders; there is no OAuth flow. Git uses an
existing clone. The shell does not copy a browser profile merely to render a
screen.

For an isolated debug smoke run, pass `--fixture-root <scratch-directory>` to
the debug binary. Both browser discovery and app state stay beneath that root,
and the sync key uses an in-memory test store. This switch is absent in release
behavior. Do not launch tests against real profiles or a real desktop keychain.
The Playwright tests use a mock IPC boundary; they prove UI behavior, not native
browser compatibility. Real-browser readback needs a separate machine proof.

## Direct dependency pins

| Dependency | Version | Published | License |
|---|---|---|---|
| tauri | 2.12.5 | crates.io (lockfile) | MIT OR Apache-2.0 |
| tauri-build | 2.7.4 | crates.io (lockfile) | MIT OR Apache-2.0 |
| tauri-plugin-dialog | 2.4.0 | crates.io (lockfile) | MIT OR Apache-2.0 |
| tauri-plugin-single-instance | 2.3.4 | crates.io (lockfile) | MIT OR Apache-2.0 |
| tauri-plugin-updater | 2.11.0 | 2026-08-31 | Apache-2.0 OR MIT |
| @tauri-apps/cli | 2.8.4 | 2025-09-01 | MIT OR Apache-2.0 |
| @playwright/test (tests only) | 1.55.1 | 2025-09-23 | Apache-2.0 |

All direct desktop platform/tooling versions are pinned and older than fourteen
days at selection. Their full dependency graphs are committed in lockfiles.
Artwork and font licensing remain as documented in the repository README.
