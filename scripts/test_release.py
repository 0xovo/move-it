import base64
import io
import json
from pathlib import Path
import tempfile
import unittest
import urllib.error
from unittest.mock import patch

import release
from release import (
    FEED,
    PLATFORMS,
    VT_DIRECT_UPLOAD_MAX_BYTES,
    VT_NO_KEY_NOTICE,
    VT_POLL_TIMEOUT_SEC,
    validate_assets,
    validate_config,
    virustotal_check,
    virustotal_poll_analysis,
    virustotal_stats_fail_closed,
    virustotal_upload,
)


class ReleaseChecks(unittest.TestCase):
    def config(self):
        # Public-format dummy bytes, no signing key and no release authorization.
        key = base64.b64encode(b"untrusted comment: fixture\n" + base64.b64encode(b"Ed" + bytes(40))).decode()
        return {"version": "1.2.3", "bundle": {"createUpdaterArtifacts": True},
                "plugins": {"updater": {"endpoints": [FEED], "pubkey": key}}}

    def test_release_config_requires_version_feed_and_public_key(self):
        validate_config(self.config(), "v1.2.3")
        for edit in (lambda c: c.update(version="1.2.2"),
                     lambda c: c["bundle"].update(createUpdaterArtifacts=False),
                     lambda c: c["plugins"]["updater"].update(pubkey=""),
                     lambda c: c["plugins"]["updater"].update(endpoints=["http://example.invalid"])):
            with self.subTest(edit=edit):
                config = self.config()
                edit(config)
                with self.assertRaises(ValueError):
                    validate_config(config, "v1.2.3")

    def assets(self, folder):
        names = ["app.AppImage", "app.deb", "app.rpm", "app.exe", "app.msi", "arm.dmg", "intel.dmg"]
        for name in names:
            (folder / name).write_bytes(b"installer fixture")
            (folder / (name + ".sig")).write_text("signature fixture")
        feed = {"version": "1.2.3", "platforms": {p: {
            "url": f"https://github.com/0xovo/move-it/releases/download/v1.2.3/{name}",
            "signature": "signature fixture"} for p, name in zip(sorted(PLATFORMS), ["arm.dmg", "intel.dmg", "app.AppImage", "app.exe"])}}
        (folder / "latest.json").write_text(json.dumps(feed))
        return feed

    def test_complete_feed_gets_deterministic_checksums(self):
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp)
            self.assets(folder)
            validate_assets(folder, "v1.2.3")
            first = (folder / "SHA256SUMS").read_text()
            self.assertIn("  latest.json\n", first)
            self.assertNotIn("  SHA256SUMS\n", first)
            validate_assets(folder, "v1.2.3")
            self.assertEqual(first, (folder / "SHA256SUMS").read_text())

    def test_missing_platform_wrong_version_and_external_url_refuse(self):
        for mode in ("platform", "version", "url", "signature", "asset", "installer"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as temp:
                folder = Path(temp)
                feed = self.assets(folder)
                item = feed["platforms"]["linux-x86_64"]
                if mode == "platform": del feed["platforms"]["darwin-aarch64"]
                if mode == "version": feed["version"] = "1.2.4"
                if mode == "url": item["url"] = "https://example.invalid/app.AppImage"
                if mode == "signature": item["signature"] = "other"
                if mode == "asset": (folder / "app.AppImage").unlink()
                if mode == "installer": (folder / "app.rpm").unlink()
                (folder / "latest.json").write_text(json.dumps(feed))
                with self.assertRaises(ValueError):
                    validate_assets(folder, "v1.2.3")


class VirusTotalGate(unittest.TestCase):
    def test_missing_stats_rejected(self):
        with self.assertRaises(ValueError):
            virustotal_stats_fail_closed({}, "fixture")

    def test_detections_rejected(self):
        with self.assertRaises(ValueError):
            virustotal_stats_fail_closed({"malicious": 1, "suspicious": 0}, "fixture")

    def test_clean_stats_accepted(self):
        virustotal_stats_fail_closed({"malicious": 0, "suspicious": 0}, "fixture")

    def test_partial_stats_rejected(self):
        for stats in ({"undetected": 70}, {"malicious": 0}, {"suspicious": 0}):
            with self.subTest(stats=stats):
                with self.assertRaises(ValueError):
                    virustotal_stats_fail_closed(stats, "fixture")

    def test_non_integer_stats_rejected(self):
        for stats in ({"malicious": "0", "suspicious": 0}, {"malicious": 0, "suspicious": True}):
            with self.subTest(stats=stats):
                with self.assertRaises(ValueError):
                    virustotal_stats_fail_closed(stats, "fixture")

    def test_lookup_404_uploads_and_polls(self):
        digest = "a" * 64
        responses = [
            urllib.error.HTTPError("https://vt", 404, "missing", None, None),
            json.dumps({"data": {"id": "analysis-1"}}).encode(),
            json.dumps({"data": {"attributes": {"status": "completed", "stats": {"malicious": 0, "suspicious": 0}}}}).encode(),
        ]

        class Response:
            def __init__(self, body):
                self._body = body

            def read(self):
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def urlopen(request, timeout=60):
            item = responses.pop(0)
            if isinstance(item, urllib.error.HTTPError):
                raise item
            return Response(item)

        with tempfile.NamedTemporaryFile() as handle:
            handle.write(b"installer")
            handle.flush()
            path = Path(handle.name)
            digest_mock = type("Digest", (), {"hexdigest": lambda self: digest})()
            with patch.object(release.hashlib, "file_digest", return_value=digest_mock), \
                 patch.object(release.urllib.request, "urlopen", side_effect=urlopen):
                virustotal_check(path, "fixture-key")

    def test_lookup_empty_200_rejected(self):
        class Response:
            def read(self):
                return b"{}"

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with patch.object(release.urllib.request, "urlopen", return_value=Response()):
            with tempfile.NamedTemporaryFile() as handle:
                with self.assertRaises(ValueError):
                    virustotal_check(Path(handle.name), "fixture-key")

    def test_poll_timeout_rejected(self):
        class Response:
            def read(self):
                return json.dumps({"data": {"attributes": {"status": "queued"}}}).encode()

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        with patch.object(release.urllib.request, "urlopen", return_value=Response()), \
             patch.object(release.time, "monotonic", side_effect=[0, 0, VT_POLL_TIMEOUT_SEC + 1]), \
             patch.object(release.time, "sleep"):
            with self.assertRaises(ValueError):
                virustotal_poll_analysis("analysis-1", "fixture-key")

    def test_scan_without_key_records_notice(self):
        summary = tempfile.NamedTemporaryFile(delete=False)
        summary.close()
        try:
            def download(*args, **kwargs):
                Path(args[0][args[0].index("--dir") + 1], "installer.exe").write_bytes(b"fixture")

            with patch.dict(release.os.environ, {"RELEASE_TAG": "v1.2.3", "VT_API_KEY": "", "GITHUB_STEP_SUMMARY": summary.name}), \
                 patch.object(release, "release_info", return_value={"isDraft": True}), \
                 patch.object(release.subprocess, "run", side_effect=download), \
                 patch.object(release, "clamscan"), \
                 patch.object(release, "append_release_note") as note, \
                 patch.object(release, "virustotal_check") as vt:
                release.scan()
                vt.assert_not_called()
                note.assert_not_called()
                self.assertIn(VT_NO_KEY_NOTICE, Path(summary.name).read_text())
        finally:
            Path(summary.name).unlink(missing_ok=True)

    def test_large_upload_uses_upload_url(self):
        calls = []

        class Response:
            def __init__(self, body):
                self._body = body

            def read(self):
                return self._body

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

        def vt_request(url, api_key, **kwargs):
            calls.append((url, kwargs.get("method")))
            if url.endswith("/files/upload_url"):
                return Response(json.dumps({"data": "https://upload.fixture/large"}).encode())
            return Response(json.dumps({"data": {"id": "analysis-large"}}).encode())

        with tempfile.TemporaryDirectory() as temp:
            large = Path(temp) / "installer.AppImage"
            with large.open("wb") as handle:
                handle.truncate(VT_DIRECT_UPLOAD_MAX_BYTES + 1)
            with patch.object(release, "virustotal_vt_request", side_effect=vt_request):
                virustotal_upload(large, "fixture-key")
        self.assertEqual(calls[0][0], "https://www.virustotal.com/api/v3/files/upload_url")
        self.assertIsNone(calls[0][1])
        self.assertEqual(calls[1][0], "https://upload.fixture/large")
        self.assertEqual(calls[1][1], "POST")

class ClamScanChecks(unittest.TestCase):
    def test_limits_raised_so_large_installers_are_scanned(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.AppImage"
            path.write_bytes(b"x")
            with patch.object(release.subprocess, "run") as run:
                run.return_value.returncode = 0
                release.clamscan(path)
            args = run.call_args[0][0]
            self.assertIn("--max-filesize=2000M", args)
            self.assertIn("--max-scansize=2000M", args)

    def test_file_too_large_to_scan_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "huge.AppImage"
            with open(path, "wb") as f:
                f.truncate(release.CLAMAV_MAX_BYTES + 1)
            with patch.object(release.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    release.clamscan(path)
            run.assert_not_called()

    def test_detection_and_scanner_error_fail(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "app.exe"
            path.write_bytes(b"x")
            for code in (1, 2):
                with patch.object(release.subprocess, "run") as run:
                    run.return_value.returncode = code
                    run.return_value.stderr = run.return_value.stdout = ""
                    with self.assertRaises(ValueError):
                        release.clamscan(path)

