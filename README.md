<div align="center">

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/lemur-dark.png">
  <img src="docs/img/lemur-light.png" alt="The Move It lemur dancing while it fills up" width="230">
</picture>
<br>
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/img/wordmark-dark.png">
  <img src="docs/img/wordmark-light.png" alt="Move It" width="300">
</picture>

**Your whole browser, on every device.**

<a href="https://ko-fi.com/0xovo" target="_blank"><img src="docs/img/btn-coffee.png" alt="Buy me a coffee on Ko-fi" height="46"></a>&nbsp;&nbsp;<a href="https://x.com/0xovoo" target="_blank"><img src="docs/img/btn-x.png" alt="Follow @0xovoo on X" height="46"></a>

</div>

<br>

I dual boot and I use more than one computer, and my browser never came with me. Every switch meant logging in to everything again and setting my extensions up from zero. So I built Move It.

It picks up your whole browser and sets it down on your other device. You stay logged in, your extensions keep their settings, and your bookmarks and history follow. The lemur fills up as your stuff moves, and when he is full, you are done.

## What comes with you

<table>
<tr>
<td align="center" width="20%"><img src="docs/img/icons/cookie.svg" width="56" alt=""><br><b>Logins and cookies</b></td>
<td align="center" width="20%"><img src="docs/img/icons/password.svg" width="56" alt=""><br><b>Saved passwords</b></td>
<td align="center" width="20%"><img src="docs/img/icons/puzzle.svg" width="56" alt=""><br><b>Extensions</b><br>and their settings</td>
<td align="center" width="20%"><img src="docs/img/icons/bookmark.svg" width="56" alt=""><br><b>Bookmarks</b></td>
<td align="center" width="20%"><img src="docs/img/icons/history.svg" width="56" alt=""><br><b>History</b></td>
</tr>
</table>

## How it works

<table>
<tr>
<td align="center" width="33%"><img src="docs/img/icons/pair.svg" width="56" alt=""><br><b>1. Pair</b><br>One device shows a short code. Type it on the other. Nothing to save, nothing to remember.</td>
<td align="center" width="33%"><img src="docs/img/icons/sealed.svg" width="56" alt=""><br><b>2. Pick a home for the sealed box</b><br>A folder you already have: Google Drive, Dropbox, iCloud, or a git repo. Only your devices can open it.</td>
<td align="center" width="33%"><img src="docs/img/icons/move.svg" width="56" alt=""><br><b>3. Move It</b><br>See what is about to move, press one button, watch the lemur fill up.</td>
</tr>
</table>

<img src="docs/img/icons/undo.svg" width="22" align="absmiddle" alt=""> &nbsp;Nothing gets deleted. Move It backs up before every change, and one button undoes the last sync.

## Two ways to use it

<table>
<tr>
<td width="50%"><img src="docs/img/icons/move.svg" width="44" alt=""><br><b>Move once</b><br>New laptop, new browser, Brave to Chrome, Linux to Windows. Everything comes over in one go.</td>
<td width="50%"><img src="docs/img/icons/sync.svg" width="44" alt=""><br><b>Keep in sync</b><br>Runs quietly when you sign in and out, so every machine is simply the same browser.</td>
</tr>
</table>

## Browsers

| | Windows | Linux | macOS |
|---|---|---|---|
| Brave | Works | Works | Not yet |
| Chrome | Testing | Works | Not yet |
| Edge | Testing | Not yet | Not yet |
| Chromium | Testing | Works | Not yet |
| Firefox | Later | Later | Later |

"Works" means proven against the real browser with a real login. A few strict sites tie a login to your device, so they may ask you to sign in once more.

<details>
<summary><b>Under the hood</b></summary>

<br>

- Rust core, one self-contained binary per platform. Tauri shell with a small web UI (`design/`).
- Pairing creates a random 256-bit secret that lives in the OS keychain. You never see or type it.
- The sealed box is one file with authenticated encryption (AES-256-GCM or XChaCha20-Poly1305) and a fresh nonce every time. Your storage provider only ever holds ciphertext.
- Each device reads its own browser locally with that system's native scheme (DPAPI on Windows, the v10 and v11 store on Linux) and re-encrypts on import with the target's own scheme.
- Per cookie, the newest wins, and both sides merge instead of overwriting.
- The browser must be closed for every write, there is a backup before each one, and anything the engine cannot fully read is left alone.


</details>

## Support

Move It is free. If it saved you a weekend of logging back in, a coffee keeps it going. Updates land on X first.

<a href="https://ko-fi.com/0xovo" target="_blank"><img src="docs/img/btn-coffee.png" alt="Buy me a coffee on Ko-fi" height="46"></a>&nbsp;&nbsp;<a href="https://x.com/0xovoo" target="_blank"><img src="docs/img/btn-x.png" alt="Follow @0xovoo on X" height="46"></a>

## License

[GPL-3.0](LICENSE). Use it, change it, share it. If you ship a changed version, you share its source too.

The Move It name, the lemur and the logo are not covered by the license. Forks need their own name and art.

<sub>Icons, including the coffee and X buttons, are Move It's own. Type: [Figtree](https://github.com/erikdkennedy/figtree) (OFL). Google Drive and Dropbox marks from [Phosphor](https://phosphoricons.com) (MIT). QR codes by [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (MIT).</sub>
