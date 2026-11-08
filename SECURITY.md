# Security

Move It is pre-release software. The latest reviewed source is the supported version;
older builds do not receive separate security fixes. Browser compatibility is
listed in [README.md](README.md), including features that have not been verified.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/0xovo/move-it/security/advisories/new)
when available. If that form is unavailable, ask for a private reporting channel
in an issue without including exploit details, browser data, credentials, or keys.
Do not attach a real browser profile, sealed box, pairing offer, or raw logs to a
public issue. A minimal reproduction with invented data is preferable.

## What is protected

The engine encrypts move payloads with AES-256-GCM using a randomly generated
256-bit sync key and a fresh nonce. The desktop API keeps that key in the OS
keychain: Secret Service on Linux, Credential Manager on Windows, and Keychain
on macOS. A locked or unavailable keychain causes an error rather than a silent
plaintext fallback. The command-line harness also has explicit key-file helpers
for isolated testing; those files are secrets and are not the desktop storage path.

The transport folder contains encrypted payloads. Its provider can still see
filenames, sizes, timing, and pairing metadata, and can retain historical copies.
A provider can delete, delay, or replay files; authenticated encryption detects
tampering but does not itself guarantee freshness or availability. There is no
hosted Move It account or OAuth connection in this version.

Pairing seals the sync key under a short code stretched with Argon2id (64 MiB,
three passes). Offers expire after ten minutes and the app limits local failed
attempts. **Anyone who obtains an offer can guess its code offline.** Expiry,
local attempt limits, and deleting the current offer cannot revoke a copy already
held by someone else. Pair only through a folder whose access you trust, share
the code separately, and complete pairing promptly. This is not a claim that a
six-digit code provides 256-bit security.

## Limits and local data

Move It must read decrypted cookies, passwords, history, and extension data in
memory to transfer them. Local browser databases, temporary database copies,
and undo journals retain sensitive data under the local account's protection;
the transport encryption does not encrypt those local backups. Protect the OS
account and disk, and keep backups out of publicly shared folders. Secure deletion
on SSDs or synced storage is not guaranteed.

The engine requires browsers to be closed before writing and journals changes
for recovery and undo. These checks reduce conflicts; they cannot prevent a
browser or another process from opening a store after a check. Preview, close
browsers on both devices, and inspect the move report before reopening them.

Windows App-Bound (`v20`) cookies and saved passwords are skipped. Move It does
not bypass that protection or weaken browser policy. Other unsupported or
unreadable data may also be skipped or block a move. Site sessions tied to a
device may require signing in again. Browser and extension versions can reject
transferred data even when a fixture round trip succeeds.

Anyone controlling a paired device or the current OS account may access the
browser data and sync key. Pairing is not a defense against malware on an
endpoint. Logs redact known secret and home-path shapes, but redaction is not a
proof that an arbitrary message is safe to share: inspect an export first.

## Release updates

Desktop updates use the official Tauri updater with signature verification and
an HTTPS release feed. Production signing requires an owner-managed private key
kept outside source control; only its public key belongs in application config.
A release must not be published with a test key. SHA256 files help detect download
corruption but do not replace signature verification. Updater signatures are
separate from platform code signing and macOS notarization.

## Installing Move It safely

Official installers and update metadata are published only on
[GitHub Releases](https://github.com/0xovo/move-it/releases) for this repository.
The site at [getmoveit.tech](https://getmoveit.tech) links to those assets; it does
not host installers. Do not download Move It from third-party mirrors, file lockers,
or reposted copies.

Each draft or published release includes a `SHA256SUMS` file. After downloading an
installer, verify it locally before running it:

```bash
sha256sum -c SHA256SUMS --ignore-missing
```

On Windows, compare the file hash from `Get-FileHash` with the matching line in
`SHA256SUMS`. The in-app updater still checks cryptographic signatures on update
packages; checksum verification is an additional guard for manual downloads.
