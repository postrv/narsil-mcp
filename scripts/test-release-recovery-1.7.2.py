#!/usr/bin/env python3
"""Inert regression tests: no API calls, credentials, binaries, or publication."""
import copy
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace
import zipfile

spec = importlib.util.spec_from_file_location("recovery", Path(__file__).with_name("recover-release-1.7.2.py"))
recovery = importlib.util.module_from_spec(spec)
spec.loader.exec_module(recovery)


class RecoveryTests(unittest.TestCase):
    def setUp(self):
        self.run = {"id": recovery.RUN, "head_sha": recovery.COMMIT, "head_branch": recovery.TAG,
                    "event": "push", "path": ".github/workflows/release.yml", "status": "completed"}
        self.jobs = [{"name": name, "conclusion": "success"} for name in recovery.REQUIRED_JOBS]
        self.assets = {target: {"url": f"https://github.com/{recovery.REPO}/releases/download/{recovery.TAG}/narsil-mcp-{recovery.TAG}-{target}.tar.gz",
                               "sha256": "a" * 64} for target in recovery.ARTIFACTS}
        self.assets["windows-x86_64"]["url"] = self.assets["windows-x86_64"]["url"].replace(".tar.gz", ".zip")

    def test_unrelated_public_url_is_rejected_before_network_access(self):
        with patch.object(recovery.urllib.request, "build_opener") as opened:
            with self.assertRaises(ValueError):
                recovery.fetch("https://example.invalid/not-a-release-input")
            opened.assert_not_called()

    def test_redirects_cannot_leave_the_fixed_release_inputs(self):
        with self.assertRaises(ValueError):
            recovery.NoRedirect().redirect_request(None, None, 302, "Moved", {}, "https://example.invalid/redirect")

    def test_gate_binding_rejects_wrong_source_and_missing_failed_or_duplicate_gates(self):
        recovery.verify_run(self.run, self.jobs)
        for key, value in [("head_sha", "0" * 40), ("event", "pull_request"), ("head_branch", "main"), ("status", "in_progress")]:
            with self.subTest(key=key), self.assertRaises(ValueError):
                recovery.verify_run({**self.run, key: value}, self.jobs)
        for jobs in [self.jobs[:-1], self.jobs + [self.jobs[0]], [{**job, "conclusion": "failure"} for job in self.jobs]]:
            with self.assertRaises(ValueError):
                recovery.verify_run(self.run, jobs)

    def test_artifact_digest_and_members_are_checked_before_use(self):
        def archive(names):
            out = io.BytesIO()
            with zipfile.ZipFile(out, "w") as z:
                for name in names:
                    z.writestr(name, b"inert fixture")
            return out.getvalue()
        good = archive(["narsil-mcp"])
        self.assertEqual(recovery.binary_from_artifact(good, "linux-x86_64", recovery.sha(good)), ("narsil-mcp", b"inert fixture"))
        with self.assertRaises(ValueError):
            recovery.binary_from_artifact(good, "linux-x86_64", "0" * 64)
        for names in [["../narsil-mcp"], ["narsil-mcp", "other"], ["narsil-mcp.exe"]]:
            payload = archive(names)
            with self.assertRaises(ValueError):
                recovery.binary_from_artifact(payload, "linux-x86_64", recovery.sha(payload))

    def test_archives_are_repeatable_preserve_bytes_and_unix_executable_mode(self):
        data = b"inert owned fixture, never executed\n"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for target in recovery.ARTIFACTS:
                name = "narsil-mcp.exe" if target.startswith("windows") else "narsil-mcp"
                first = recovery.package_binary(root, target, name, data)
                self.assertEqual(first, recovery.package_binary(root, target, name, data))
                path = root / first["name"]
                if target.startswith("windows"):
                    with zipfile.ZipFile(path) as archive:
                        self.assertEqual(archive.namelist(), [name])
                        self.assertEqual(archive.read(name), data)
                else:
                    with tarfile.open(path) as archive:
                        member = archive.getmembers()[0]
                        self.assertEqual(member.mode, 0o755)
                        self.assertEqual((member.mtime, member.uid, member.gid), (0, 0, 0))
                        self.assertEqual(archive.extractfile(member).read(), data)
                self.assertEqual(path.with_name(path.name + ".sha256").read_text(), f'{first["sha256"]}  {path.name}\n')

    def test_existing_release_is_only_completed_when_existing_bytes_match(self):
        release = {"tag_name": recovery.TAG, "draft": False, "prerelease": False, "assets": [{"name": "one", "digest": "sha256:" + "a" * 64, "state": "uploaded",
                    "browser_download_url": f"https://github.com/{recovery.REPO}/releases/download/{recovery.TAG}/one"}]}
        self.assertEqual(recovery.validate_existing_assets(release, {"one": "a" * 64, "two": "b" * 64}), {"two"})
        with self.assertRaises(ValueError):
            recovery.validate_existing_assets(release, {"one": "b" * 64})
        with self.assertRaises(ValueError):
            recovery.validate_existing_assets({**release, "draft": True}, {"one": "a" * 64})

    def test_prepared_output_is_bound_to_the_source_and_unchanged_archive_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = {"version": recovery.VERSION, "sourceCommit": recovery.COMMIT,
                      "originalRun": recovery.RUN, "crateSha256": recovery.CRATE_SHA, "assets": {}}
            inert_artifacts = {}
            for target, (identifier, digest) in recovery.ARTIFACTS.items():
                name = "narsil-mcp.exe" if target.startswith("windows") else "narsil-mcp"
                original = root / f"artifact-{identifier}.zip"
                with zipfile.ZipFile(original, "w") as archive:
                    archive.writestr(name, b"inert")
                digest = recovery.sha(original.read_bytes())
                inert_artifacts[target] = (identifier, digest)
                report["assets"][target] = recovery.package_binary(root, target, name, b"inert")
                report["assets"][target].update(artifactId=identifier, artifactZipSha256=digest)
            (root / "prepared.json").write_text(json.dumps(report))
            with self.assertRaises(ValueError):
                recovery.load_prepared(root)  # Inert bytes cannot claim real artifact identities.
            with patch.object(recovery, "ARTIFACTS", inert_artifacts):
                self.assertEqual(recovery.load_prepared(root), report)
                report["sourceCommit"] = "0" * 40
                (root / "prepared.json").write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    recovery.load_prepared(root)
                report["sourceCommit"] = recovery.COMMIT
                changed = recovery.package_binary(root, "linux-x86_64", "narsil-mcp", b"changed binary")
                report["assets"]["linux-x86_64"].update(changed)
                (root / "prepared.json").write_text(json.dumps(report))
                with self.assertRaises(ValueError):
                    recovery.load_prepared(root)  # Both archive and report changed; original ZIP is authoritative.

    def test_formula_update_preserves_body_and_rejects_ambiguous_or_conflicting_versions(self):
        body = 'class NarsilMcp < Formula\n  license "MIT"\n'
        for target, asset in self.assets.items():
            if not target.startswith("windows"):
                body += f'  url "{asset["url"].replace("1.7.2", "1.7.1")}"\n  sha256 "{"b" * 64}"\n'
        body += '  def install\n    bin.install "narsil-mcp"\n  end\nend\n'
        updated = recovery.update_homebrew(body, self.assets)
        self.assertIn('bin.install "narsil-mcp"', updated)
        self.assertEqual(recovery.update_homebrew(updated, self.assets), updated)
        for invalid in [body.replace("1.7.1", "1.7.3"), body + '  version "1.7.1"\n', updated.replace("a" * 64, "b" * 64)]:
            with self.assertRaises(ValueError):
                recovery.update_homebrew(invalid, self.assets)

    def test_scoop_update_is_idempotent_and_refuses_conflicting_same_version(self):
        original = {"version": "1.7.1", "bin": "narsil-mcp.exe", "architecture": {"64bit": {"url": "old", "hash": "b" * 64}}, "notes": ["preserve"]}
        updated = recovery.update_scoop(copy.deepcopy(original), self.assets)
        self.assertEqual(updated["notes"], original["notes"])
        self.assertEqual(recovery.update_scoop(copy.deepcopy(updated), self.assets), updated)
        with self.assertRaises(ValueError):
            recovery.update_scoop({**original, "version": "1.7.2"}, self.assets)
        with self.assertRaises(ValueError):
            recovery.update_scoop({**original, "version": "1.7.3"}, self.assets)

    def test_existing_valid_npm_version_is_not_published_again(self):
        with patch.object(recovery, "command", side_effect=[SimpleNamespace(stdout=recovery.COMMIT.encode()), SimpleNamespace(stdout=b"")]) as commands:
            with patch.object(recovery, "verify_npm", return_value=True):
                recovery.publish_npm(Path("inert-source"))
            self.assertEqual(commands.call_count, 2)  # Only the two read-only Git checks.

    def test_missing_npm_version_cannot_downgrade_a_newer_latest(self):
        with patch.object(recovery, "command", side_effect=[SimpleNamespace(stdout=recovery.COMMIT.encode()), SimpleNamespace(stdout=b"")]) as commands:
            with patch.object(recovery, "verify_npm", return_value=False), patch.object(recovery, "fetch", return_value=b'{"latest":"1.7.3"}'):
                with self.assertRaises(ValueError):
                    recovery.publish_npm(Path("inert-source"))
            self.assertEqual(commands.call_count, 2)

    def test_npm_integrity_and_unique_regular_members_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            names = ["package.json", "README.md", "install.js", "bin/narsil-mcp.js"]
            for name in names:
                path = source / "npm" / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(name.encode())
            for duplicate, wrong_integrity in [(False, False), (True, False), (False, True)]:
                output = io.BytesIO()
                with tarfile.open(fileobj=output, mode="w:gz") as archive:
                    for name in names + ([names[0]] if duplicate else []):
                        member = tarfile.TarInfo("package/" + name)
                        member.size = len(name.encode())
                        archive.addfile(member, io.BytesIO(name.encode()))
                payload = output.getvalue()
                integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
                metadata = {"version": recovery.VERSION, "gitHead": recovery.COMMIT,
                            "dist": {"tarball": "https://registry.npmjs.org/narsil-mcp/-/narsil-mcp-1.7.2.tgz",
                                     "integrity": "incorrect" if wrong_integrity else integrity}}
                with patch.object(recovery, "fetch", side_effect=[json.dumps(metadata).encode(), payload, b'{"latest":"1.7.2"}']):
                    if duplicate or wrong_integrity:
                        with self.assertRaises(ValueError):
                            recovery.verify_npm(source)
                    else:
                        self.assertTrue(recovery.verify_npm(source))


if __name__ == "__main__":
    unittest.main()
