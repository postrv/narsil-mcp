#!/usr/bin/env python3
"""Finish the interrupted 1.7.2 distribution, without rebuilding or publishing Cargo.

This deliberately fixed recovery is bound to the reviewed tag, public crate, and
five successful artifacts. It refuses conflicting existing publications.
"""
import argparse
import base64
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import stat
import subprocess
import tarfile
import urllib.error
import urllib.request
import zipfile

REPO = "postrv/narsil-mcp"
VERSION = "1.7.2"
TAG = "v" + VERSION
COMMIT = "cf8eac40ce736f3706450e4b256b56f6845af8e5"
TAG_OBJECT = "050628b3cf0cab8bfbdb8dd81c71e8372ce07d81"
RUN = 37635101431
CRATE_SHA = "f2b02d1fed13146468340aa8a244b9b6009a98ef390b4899155a1d69c7cc7b88"
LOCK_SHA = "2b9678c4c71f31015258989e1e5c7865e2265d77e886b62a173bd50c9ede0ad2"
ARTIFACTS = {
    "linux-x86_64": (11491773375, "73c03ea2a31f6dbb877147fc503acf233e81c96ee5f2229ae51ffb66d9c182bf"),
    "linux-aarch64": (11492411826, "8da750f8f382efa056cd0b773187ff6fb3f86dd4512654647e8cdec6be9af664"),
    "macos-x86_64": (11492147238, "7c7a71ef7ac27efaf0a74abbae512882c3885bb2eb646a4d9476e09b686cbca8"),
    "macos-aarch64": (11492641986, "86d0b788ded1d2bbf461a1d065e3c41c9858357f7a64a404d83d2b8d738f51dd"),
    "windows-x86_64": (11491967962, "7dbee346d42e53826496904311e2e7f885cd8e514b1e84b4ff1e8b3c08c97930"),
}
BUILD_TARGETS = ("x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu",
                 "x86_64-apple-darwin", "aarch64-apple-darwin", "x86_64-pc-windows-msvc")
REQUIRED_JOBS = {"Lint", "Version Consistency Check", "Security Audit", "Test", "Publish to crates.io"} | {
    f"Build Release Binaries / Build ({target})" for target in BUILD_TARGETS
}
PUBLIC_URLS = {
    f"https://crates.io/api/v1/crates/narsil-mcp/{VERSION}",
    f"https://static.crates.io/crates/narsil-mcp/narsil-mcp-{VERSION}.crate",
    f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}",
    f"https://registry.npmjs.org/narsil-mcp/{VERSION}",
    f"https://registry.npmjs.org/narsil-mcp/-/narsil-mcp-{VERSION}.tgz",
    "https://registry.npmjs.org/-/package/narsil-mcp/dist-tags",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """These fixed public metadata/archive endpoints need no redirected authority."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Unexpected redirect from a fixed release input")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def command(args, **kwargs):
    return subprocess.run(args, check=True, timeout=kwargs.pop("timeout", 180), **kwargs)


def api(path):
    return json.loads(command(["gh", "api", f"repos/{REPO}/{path}"], capture_output=True).stdout)


def fetch(url, limit=2 * 1024 * 1024, missing_ok=False):
    require(url in PUBLIC_URLS, "URL is not a fixed public release input")
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "narsil-release-recovery", "Cache-Control": "no-cache"})
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=30) as response:
            data = response.read(limit + 1)
        require(len(data) <= limit, "public response exceeds size limit")
        return data
    except urllib.error.HTTPError as error:
        if missing_ok and error.code == 404:
            return None
        raise


def verify_run(run, jobs):
    require(run["head_sha"] == COMMIT and run["head_branch"] == TAG, "release run source mismatch")
    require(run["event"] == "push" and run["path"] == ".github/workflows/release.yml", "not the tagged release workflow")
    require(run["status"] == "completed" and run["id"] == RUN, "original release run is not complete")
    for name in REQUIRED_JOBS:
        matches = [job for job in jobs if job["name"] == name]
        require(len(matches) == 1 and matches[0]["conclusion"] == "success", f"required gate did not pass: {name}")


def verify_tag():
    ref = api(f"git/ref/tags/{TAG}")["object"]
    require(ref["sha"] == TAG_OBJECT and ref["type"] == "tag", "immutable tag object changed")
    target = api(f"git/tags/{TAG_OBJECT}")["object"]
    require(target["type"] == "commit" and target["sha"] == COMMIT, "tag source changed")


def binary_from_artifact(payload, target, expected_sha):
    require(sha(payload) == expected_sha, "artifact ZIP digest mismatch")
    name = "narsil-mcp.exe" if target.startswith("windows") else "narsil-mcp"
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        entries = archive.infolist()
        require(len(entries) == 1 and entries[0].filename == name, "unexpected artifact members")
        entry = entries[0]
        require(not entry.flag_bits & 1 and not stat.S_ISLNK(entry.external_attr >> 16), "invalid artifact member")
        require(0 < entry.file_size <= 128 * 1024 * 1024, "binary exceeds bounded size")
        return name, archive.read(entry)


def package_binary(output, target, name, data):
    suffix = "zip" if target.startswith("windows") else "tar.gz"
    path = output / f"narsil-mcp-{TAG}-{target}.{suffix}"
    if suffix == "zip":
        with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.external_attr = (stat.S_IFREG | 0o755) << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED)
    else:
        with path.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                member = tarfile.TarInfo(name)
                member.size, member.mode, member.mtime = len(data), 0o755, 0
                archive.addfile(member, io.BytesIO(data))
    digest = sha(path.read_bytes())
    sidecar = path.with_name(path.name + ".sha256")
    sidecar.write_text(f"{digest}  {path.name}\n")
    return {"name": path.name, "sha256": digest, "binarySha256": sha(data), "binaryBytes": len(data),
            "url": f"https://github.com/{REPO}/releases/download/{TAG}/{path.name}"}


def prepare(output):
    verify_tag()
    verify_run(api(f"actions/runs/{RUN}"), api(f"actions/runs/{RUN}/jobs?per_page=100")["jobs"])
    metadata = json.loads(fetch(f"https://crates.io/api/v1/crates/narsil-mcp/{VERSION}"))["version"]
    require(metadata["crate"] == "narsil-mcp" and metadata["num"] == VERSION
            and metadata["checksum"] == CRATE_SHA and not metadata["yanked"], "public crate identity changed")
    crate = fetch(f"https://static.crates.io/crates/narsil-mcp/narsil-mcp-{VERSION}.crate")
    require(sha(crate) == CRATE_SHA, "public crate checksum mismatch")
    with tarfile.open(fileobj=io.BytesIO(crate), mode="r:gz") as archive:
        vcs = json.load(archive.extractfile(f"narsil-mcp-{VERSION}/.cargo_vcs_info.json"))
        lock = archive.extractfile(f"narsil-mcp-{VERSION}/Cargo.lock").read()
    require(vcs == {"git": {"sha1": COMMIT}, "path_in_vcs": ""} and sha(lock) == LOCK_SHA, "crate source/lock mismatch")
    inventory = api(f"actions/runs/{RUN}/artifacts?per_page=100")["artifacts"]
    require({item["name"] for item in inventory} == {"narsil-mcp-" + target for target in ARTIFACTS}
            and len(inventory) == 5, "unexpected artifact inventory")
    result = {"version": VERSION, "sourceCommit": COMMIT, "originalRun": RUN, "crateSha256": CRATE_SHA, "assets": {}}
    for target, (identifier, digest) in ARTIFACTS.items():
        item = next(item for item in inventory if item["id"] == identifier)
        require(item["name"] == "narsil-mcp-" + target and item["digest"] == "sha256:" + digest
                and not item["expired"], "artifact identity mismatch")
        require(item["workflow_run"]["id"] == RUN and item["workflow_run"]["head_sha"] == COMMIT, "artifact source mismatch")
        require(item["size_in_bytes"] < 32 * 1024 * 1024, "artifact too large")
        payload = command(["gh", "api", f"repos/{REPO}/actions/artifacts/{identifier}/zip"], capture_output=True).stdout
        require(len(payload) == item["size_in_bytes"], "artifact size mismatch")
        name, data = binary_from_artifact(payload, target, digest)
        (output / f"artifact-{identifier}.zip").write_bytes(payload)
        result["assets"][target] = package_binary(output, target, name, data)
        result["assets"][target]["artifactId"] = identifier
        result["assets"][target]["artifactZipSha256"] = digest
    (output / "prepared.json").write_text(json.dumps(result, indent=2) + "\n")
    load_prepared(output)


def existing_release():
    data = fetch(f"https://api.github.com/repos/{REPO}/releases/tags/{TAG}", missing_ok=True)
    return json.loads(data) if data is not None else None


def load_prepared(output):
    report = json.loads((output / "prepared.json").read_text())
    require(report["version"] == VERSION and report["sourceCommit"] == COMMIT
            and report["originalRun"] == RUN and report["crateSha256"] == CRATE_SHA, "prepared source identity mismatch")
    require(set(report["assets"]) == set(ARTIFACTS), "prepared asset inventory mismatch")
    for target, (identifier, digest) in ARTIFACTS.items():
        asset = report["assets"][target]
        suffix = "zip" if target.startswith("windows") else "tar.gz"
        name = f"narsil-mcp-{TAG}-{target}.{suffix}"
        require(asset["name"] == name and asset["artifactId"] == identifier
                and asset["artifactZipSha256"] == digest, "prepared artifact identity mismatch")
        require(asset["url"] == f"https://github.com/{REPO}/releases/download/{TAG}/{name}", "prepared URL mismatch")
        original = output / f"artifact-{identifier}.zip"
        require(original.is_file() and not original.is_symlink() and original.stat().st_size < 32 * 1024 * 1024, "original artifact absent or too large")
        binary_name, original_binary = binary_from_artifact(original.read_bytes(), target, digest)
        require(asset["binarySha256"] == sha(original_binary) and asset["binaryBytes"] == len(original_binary), "prepared binary identity mismatch")
        path = output / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size < 32 * 1024 * 1024
                and sha(path.read_bytes()) == asset["sha256"], "prepared archive bytes changed")
        if target.startswith("windows"):
            _, published_binary = binary_from_artifact(path.read_bytes(), target, asset["sha256"])
        else:
            with tarfile.open(path, "r:gz") as archive:
                members = archive.getmembers()
                require(len(members) == 1 and members[0].name == binary_name and members[0].isfile()
                        and members[0].mode == 0o755 and members[0].size == len(original_binary), "invalid packaged Unix binary")
                published_binary = archive.extractfile(members[0]).read()
        require(published_binary == original_binary, "packaged binary differs from verified original artifact")
        require(path.with_name(name + ".sha256").read_text() == f'{asset["sha256"]}  {name}\n', "prepared sidecar changed")
    return report


def validate_existing_assets(release, expected):
    require(release["tag_name"] == TAG and not release["draft"] and not release["prerelease"], "existing release identity mismatch")
    require(len({item["name"] for item in release["assets"]}) == len(release["assets"]), "duplicate release assets")
    for item in release["assets"]:
        require(item["name"] in expected and item["digest"] == "sha256:" + expected[item["name"]]
                and item["state"] == "uploaded"
                and item["browser_download_url"] == f'https://github.com/{REPO}/releases/download/{TAG}/{item["name"]}', "conflicting published asset")
    return set(expected) - {item["name"] for item in release["assets"]}


def publish_github(output):
    verify_tag()
    report = load_prepared(output)
    paths = sorted(output / (asset["name"] + suffix) for asset in report["assets"].values() for suffix in ("", ".sha256"))
    expected = {path.name: sha(path.read_bytes()) for path in paths}
    release = existing_release()
    if release is None:
        command(["gh", "release", "create", TAG, "--repo", REPO, "--verify-tag", "--title", f"narsil-mcp {TAG}",
                 "--generate-notes", *map(str, paths)])
    else:
        missing = validate_existing_assets(release, expected)
        if missing:
            command(["gh", "release", "upload", TAG, "--repo", REPO, *[str(output / name) for name in sorted(missing)]])
    require(not validate_existing_assets(existing_release(), expected), "release assets still missing")


def verify_npm(source):
    data = fetch(f"https://registry.npmjs.org/narsil-mcp/{VERSION}", missing_ok=True)
    if data is None:
        return False
    metadata = json.loads(data)
    require(metadata["gitHead"] == COMMIT and metadata["version"] == VERSION, "conflicting npm publication")
    require(metadata["dist"]["tarball"] == f"https://registry.npmjs.org/narsil-mcp/-/narsil-mcp-{VERSION}.tgz", "unexpected npm archive URL")
    payload = fetch(metadata["dist"]["tarball"])
    integrity = "sha512-" + base64.b64encode(hashlib.sha512(payload).digest()).decode()
    require(metadata["dist"]["integrity"] == integrity, "npm dist.integrity mismatch")
    names = {"package.json", "README.md", "install.js", "bin/narsil-mcp.js"}
    with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
        members = archive.getmembers()
        require(len(members) == 4 and {item.name for item in members} == {"package/" + name for name in names}
                and all(item.isfile() for item in members), "unexpected or duplicate npm members")
        for name in names:
            member = archive.getmember("package/" + name)
            require(member.isfile() and archive.extractfile(member).read() == (source / "npm" / name).read_bytes(), "npm bytes differ from tag")
    require(json.loads(fetch("https://registry.npmjs.org/-/package/narsil-mcp/dist-tags"))["latest"] == VERSION, "npm latest differs; do not overwrite it")
    return True


def publish_npm(source):
    require(command(["git", "rev-parse", "HEAD"], cwd=source, capture_output=True).stdout.decode().strip() == COMMIT, "npm checkout is not tagged source")
    require(not command(["git", "status", "--porcelain"], cwd=source, capture_output=True).stdout, "npm source checkout is dirty")
    if not verify_npm(source):
        latest = json.loads(fetch("https://registry.npmjs.org/-/package/narsil-mcp/dist-tags")).get("latest")
        require(latest == "1.7.1", "refusing to replace a newer or unknown npm latest version")
        command(["npm", "publish", "--access", "public"], cwd=source / "npm")
    require(verify_npm(source), "npm publication is not visible yet; safe to rerun after registry propagation")


def update_homebrew(text, assets):
    pattern = r'(?m)^(\s*)url "https://github.com/postrv/narsil-mcp/releases/download/v(\d+\.\d+\.\d+)/narsil-mcp-v\2-([^"/]+)\.tar\.gz"\n\s*sha256 "([0-9a-f]{64})"$'
    matches = list(re.finditer(pattern, text))
    require(len(matches) == 4 and {m[3] for m in matches} == set(ARTIFACTS) - {"windows-x86_64"}, "unknown Homebrew formula layout")
    require(not re.search(r'^\s*version\s', text, re.M), "formula must infer version from URLs")
    require(len({m[2] for m in matches}) == 1, "mixed formula versions")
    def replace(match):
        version, target, old_hash = match[2], match[3], match[4]
        require(version in ("1.7.1", VERSION), "refusing formula downgrade or unknown version")
        asset = assets[target]
        require(version != VERSION or old_hash == asset["sha256"], "conflicting existing formula hash")
        return f'{match[1]}url "{asset["url"]}"\n{match[1]}sha256 "{asset["sha256"]}"'
    return re.sub(pattern, replace, text)


def update_scoop(manifest, assets):
    require(manifest["version"] in ("1.7.1", VERSION) and set(manifest["architecture"]) == {"64bit"}, "unknown Scoop version/architecture")
    require(manifest["bin"] == "narsil-mcp.exe", "unexpected Scoop command")
    expected = {"url": assets["windows-x86_64"]["url"], "hash": assets["windows-x86_64"]["sha256"]}
    require(manifest["version"] != VERSION or manifest["architecture"]["64bit"] == expected, "conflicting existing Scoop manifest")
    manifest["version"], manifest["architecture"]["64bit"] = VERSION, expected
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["prepare", "github", "npm", "distributions"])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source", type=Path)
    parser.add_argument("--homebrew", type=Path)
    parser.add_argument("--scoop", type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=True)
    if args.phase == "prepare":
        prepare(args.output)
    elif args.phase == "github":
        publish_github(args.output)
    elif args.phase == "npm":
        publish_npm(args.source.resolve())
    else:
        report = load_prepared(args.output)
        formula = args.homebrew / "Formula/narsil-mcp.rb"
        bucket = args.scoop / "bucket/narsil-mcp.json"
        changed_formula = update_homebrew(formula.read_text(), report["assets"])
        changed_bucket = update_scoop(json.loads(bucket.read_text()), report["assets"])
        formula.write_text(changed_formula)
        bucket.write_text(json.dumps(changed_bucket, indent=4) + "\n")
    print(f"PASS {args.phase}: immutable {TAG} / {COMMIT}")


if __name__ == "__main__":
    main()
