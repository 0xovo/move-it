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
Cloud pipes can sign in with Google Drive or Dropbox (PKCE, loopback in the
system browser, tokens in the OS keychain). Folder and git choices use local
paths only. The shell does not copy a browser profile merely to render a
screen.

### Release OAuth bundle

Release builds read provider client config from the Tauri bundle resource
`oauth/` (written in CI from repository secrets, never committed). Dev builds
fall back to `~/.config/moveit/oauth.json` and `google-client.json` (or
`MOVEIT_OAUTH_DIR` in tests).

Example shape (dummy values only):

```json
{
  "dropbox": {
    "app_key": "your-dropbox-app-key",
    "flow": "pkce",
    "scopes": ["files.metadata.read", "files.content.read", "files.content.write"],
    "access": "app_folder"
  },
  "google": {
    "client_id": "your-google-client-id.apps.googleusercontent.com",
    "client_file": "google-client.json",
    "flow": "pkce",
    "scopes": ["https://www.googleapis.com/auth/drive.file"]
  }
}
```

`google-client.json` uses the standard Google installed-app JSON form with a
`client_secret` field (not confidential for desktop clients, but still shipped
only in the bundle or the user config dir).

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
