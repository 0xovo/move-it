"""Validate a stable release and its draft assets without printing signing material."""
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from urllib.parse import unquote, urlsplit

REPO = "0xovo/move-it"
FEED = f"https://github.com/{REPO}/releases/latest/download/latest.json"
PLATFORMS = {"linux-x86_64", "windows-x86_64", "darwin-aarch64", "darwin-x86_64"}
VT_NO_KEY_NOTICE = "VirusTotal: not run (no key)"
VT_DIRECT_UPLOAD_MAX_BYTES = 32 * 1024 * 1024
VT_POLL_TIMEOUT_SEC = 600
VT_POLL_INTERVAL_SEC = 15


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def tag_name():
    tag = os.environ["RELEASE_TAG"]
    if not re.fullmatch(r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", tag):
        raise ValueError("expected a stable vX.Y.Z tag")
    return tag


def validate_config(config, tag):
    if config.get("version") != tag[1:]:
        raise ValueError("tag and application version differ")
    if config.get("bundle", {}).get("createUpdaterArtifacts") is not True:
        raise ValueError("signed updater artifacts must be enabled")
    updater = config.get("plugins", {}).get("updater", {})
    if updater.get("endpoints") != [FEED]:
        raise ValueError("unexpected updater feed")
    if updater.get("dangerousInsecureTransportProtocol"):
        raise ValueError("insecure updater transport is forbidden")
    try:
        public = base64.b64decode(updater.get("pubkey", ""), validate=True).decode()
        lines = public.strip().splitlines()
        raw = base64.b64decode(lines[1], validate=True)
        valid = lines[0].startswith("untrusted comment:") and len(raw) == 42 and raw[:2] in (b"Ed", b"ED")
    except (ValueError, IndexError, UnicodeError):
        valid = False
    if not valid:
        raise ValueError("owner public signing key is missing or invalid")


def release_info(tag):
    return json.loads(run("gh", "release", "view", tag, "--repo", REPO,
                          "--json", "id,isDraft,tagName"))


def prepare():
    tag = tag_name()
    sha = run("git", "rev-parse", f"refs/tags/{tag}^{{commit}}")
    if run("git", "rev-parse", "HEAD") != sha:
        raise ValueError("checkout is not the requested tag")
    subprocess.run(["git", "merge-base", "--is-ancestor", sha, "origin/main"], check=True)
    validate_config(json.loads(Path("app/src-tauri/tauri.conf.json").read_text()), tag)
    # List first so network/authentication errors cannot be mistaken for absence.
    releases = json.loads(run("gh", "api", "--paginate", "--slurp", f"repos/{REPO}/releases"))
    existing = [r for page in releases for r in page if r["tag_name"] == tag]
    if existing and not existing[0]["draft"]:
        raise ValueError("refusing to modify a published release")
    if not existing:
        subprocess.run(["gh", "release", "create", tag, "--repo", REPO, "--verify-tag",
                        "--draft", "--title", f"Move It {tag[1:]}", "--notes",
                        "Review the installers, checksums, signed updater feed, and platform smoke results before publishing."], check=True)
    # REST numeric release id is what tauri-action expects. The list can lag a
    # fresh draft by a few seconds, so look again before giving up.
    release = None
    for attempt in range(10):
        releases = json.loads(run("gh", "api", "--paginate", "--slurp", f"repos/{REPO}/releases"))
        release = next((r for page in releases for r in page if r["tag_name"] == tag), None)
        if release:
            break
        time.sleep(3)
    if not release:
        raise ValueError("draft release did not appear")
    if not release["draft"]:
        raise ValueError("release must remain a draft")
    with open(os.environ["GITHUB_OUTPUT"], "a") as out:
        out.write(f"tag={tag}\nsha={sha}\nid={release['id']}\n")


def validate_assets(directory, tag):
    directory = Path(directory)
    feed = json.loads((directory / "latest.json").read_text())
    if feed.get("version", "").removeprefix("v") != tag[1:]:
        raise ValueError("updater version differs from tag")
    platforms = feed.get("platforms", {})
    if not PLATFORMS <= platforms.keys():
        raise ValueError("updater feed is missing a platform")
    for name, item in platforms.items():
        url = urlsplit(item["url"])
        prefix = f"/{REPO}/releases/download/{tag}/"
        filename = unquote(url.path.removeprefix(prefix))
        if (url.scheme != "https" or url.netloc != "github.com" or
                not url.path.startswith(prefix) or url.query or url.fragment or
                not filename or Path(filename).name != filename or "\\" in filename):
            raise ValueError(f"unexpected updater URL for {name}")
        if not (directory / filename).is_file():
            raise ValueError(f"missing updater asset for {name}")
        signature_file = directory / (filename + ".sig")
        signature = item.get("signature", "").strip()
        if not signature or not signature_file.is_file() or signature_file.read_text().strip() != signature:
            raise ValueError(f"missing or mismatched signature for {name}")
    names = [p.name for p in directory.iterdir() if p.is_file()]
    for suffix in (".AppImage", ".deb", ".rpm", ".exe", ".msi", ".dmg"):
        if not any(n.endswith(suffix) for n in names):
            raise ValueError(f"missing installer type {suffix}")
    lines = []
    for path in sorted(directory.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            with path.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            lines.append(f"{digest}  {path.name}\n")
    (directory / "SHA256SUMS").write_text("".join(lines))


def verify():
    tag = tag_name()
    if not release_info(tag)["isDraft"]:
        raise ValueError("refusing to modify a published release")
    with tempfile.TemporaryDirectory() as temp:
        subprocess.run(["gh", "release", "download", tag, "--repo", REPO, "--dir", temp], check=True)
        validate_assets(temp, tag)
        if not release_info(tag)["isDraft"]:
            raise ValueError("release was published during verification")
        subprocess.run(["gh", "release", "upload", tag, "--repo", REPO,
                        str(Path(temp) / "SHA256SUMS"), "--clobber"], check=True)


CLAMAV_MAX_BYTES = 2000 * 1024 * 1024


def clamscan(path):
    # clamscan skips files over --max-filesize (100M by default) and still exits
    # 0, so raise the limits and refuse anything ClamAV cannot fully scan.
    if path.stat().st_size > CLAMAV_MAX_BYTES:
        raise ValueError(f"{path.name} is too large for ClamAV to scan")
    completed = subprocess.run(
        ["clamscan", "--infected", "--no-summary",
         "--max-filesize=2000M", "--max-scansize=2000M", str(path)],
        capture_output=True,
        text=True,
    )
    if completed.returncode == 1:
        raise ValueError(f"ClamAV detected malware in {path.name}")
    if completed.returncode not in (0, 1):
        raise ValueError(f"ClamAV failed on {path.name}: {completed.stderr.strip() or completed.stdout.strip()}")


def append_job_summary(line):
    summary = os.environ.get("GITHUB_STEP_SUMMARY", "").strip()
    if summary:
        with open(summary, "a", encoding="utf-8") as out:
            out.write(line.rstrip() + "\n")


def append_release_note(tag, line):
    body = run("gh", "release", "view", tag, "--repo", REPO, "--json", "body", "-q", ".body")
    if line in body:
        return
    joined = f"{body.rstrip()}\n\n{line}".strip() + "\n"
    subprocess.run(["gh", "release", "edit", tag, "--repo", REPO, "--notes", joined], check=True)


def virustotal_vt_request(url, api_key, *, data=None, headers=None, method=None, timeout=60):
    header_map = {"x-apikey": api_key}
    if headers:
        header_map.update(headers)
    request = urllib.request.Request(url, data=data, headers=header_map, method=method)
    return urllib.request.urlopen(request, timeout=timeout)


def virustotal_stats_fail_closed(stats, label):
    if not stats:
        raise ValueError(f"VirusTotal returned no analysis statistics for {label}")
    counts = {}
    for field in ("malicious", "suspicious"):
        if field not in stats:
            raise ValueError(f"VirusTotal stats missing {field} for {label}")
        value = stats[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"VirusTotal stats invalid {field} for {label}")
        counts[field] = value
    if counts["malicious"] + counts["suspicious"]:
        raise ValueError(f"VirusTotal reported detections for {label}")


def virustotal_poll_analysis(analysis_id, api_key):
    deadline = time.monotonic() + VT_POLL_TIMEOUT_SEC
    while time.monotonic() < deadline:
        with virustotal_vt_request(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            api_key,
        ) as response:
            payload = json.load(response)
        attributes = payload.get("data", {}).get("attributes", {})
        status = attributes.get("status")
        if status == "completed":
            return attributes.get("stats") or attributes.get("last_analysis_stats")
        time.sleep(VT_POLL_INTERVAL_SEC)
    raise ValueError(f"VirusTotal analysis timed out for {analysis_id}")


def virustotal_multipart_body(path):
    boundary = hashlib.sha256(os.urandom(32)).hexdigest()[:24]
    payload = path.read_bytes()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{path.name}"\r\n'
        f"Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + payload + f"\r\n--{boundary}--\r\n".encode()
    return body, boundary


def virustotal_upload(path, api_key):
    body, boundary = virustotal_multipart_body(path)
    headers = {"Content-Type": f"multipart/form-data; boundary={boundary}"}
    if path.stat().st_size > VT_DIRECT_UPLOAD_MAX_BYTES:
        with virustotal_vt_request(
            "https://www.virustotal.com/api/v3/files/upload_url",
            api_key,
        ) as response:
            upload_payload = json.load(response)
        upload_url = upload_payload.get("data")
        if not isinstance(upload_url, str) or not upload_url:
            raise ValueError(f"VirusTotal returned no upload URL for {path.name}")
        target_url = upload_url
    else:
        target_url = "https://www.virustotal.com/api/v3/files"
    with virustotal_vt_request(
        target_url,
        api_key,
        data=body,
        headers=headers,
        method="POST",
        timeout=120,
    ) as response:
        payload = json.load(response)
    analysis_id = payload.get("data", {}).get("id")
    if not analysis_id:
        raise ValueError(f"VirusTotal upload for {path.name} returned no analysis id")
    return analysis_id


def virustotal_check(path, api_key):
    with path.open("rb") as stream:
        sha256 = hashlib.file_digest(stream, "sha256").hexdigest()
    try:
        with virustotal_vt_request(
            f"https://www.virustotal.com/api/v3/files/{sha256}",
            api_key,
        ) as response:
            payload = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise ValueError(f"VirusTotal lookup failed for {path.name}") from error
        analysis_id = virustotal_upload(path, api_key)
        stats = virustotal_poll_analysis(analysis_id, api_key)
        virustotal_stats_fail_closed(stats, path.name)
        return
    stats = payload.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    virustotal_stats_fail_closed(stats, path.name)


def scan():
    tag = tag_name()
    if not release_info(tag)["isDraft"]:
        raise ValueError("refusing to scan a published release")
    api_key = os.environ.get("VT_API_KEY", "").strip()
    with tempfile.TemporaryDirectory() as temp:
        directory = Path(temp)
        subprocess.run(["gh", "release", "download", tag, "--repo", REPO, "--dir", temp], check=True)
        assets = sorted(path for path in directory.iterdir() if path.is_file())
        if not assets:
            raise ValueError("release has no assets to scan")
        for path in assets:
            clamscan(path)
            if api_key:
                virustotal_check(path, api_key)
        if not api_key:
            append_job_summary(VT_NO_KEY_NOTICE)


if __name__ == "__main__":
    try:
        {"prepare": prepare, "verify": verify, "scan": scan}[sys.argv[1]]()
    except (ValueError, KeyError, IndexError, subprocess.CalledProcessError) as error:
        sys.exit(str(error))
