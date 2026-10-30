"""Download the official Suzaku 3.x release for this platform and verify its published SHA-256.

KamoTrace never bundles Suzaku (AGPL-3.0, Yamato Security). This helper fetches the analyst's own
copy from https://github.com/Yamato-Security/suzaku/releases into a tools folder, where
`kamotrace suzaku` finds it. GitHub's asset digest guards against corrupted or altered downloads;
it cannot vouch for the release itself.
"""
import argparse
import hashlib
import json
import os
import platform
import shutil
import stat
import sys
import tempfile
from pathlib import Path, PurePosixPath
from urllib.request import Request, urlopen
import zipfile

RELEASES = "https://api.github.com/repos/Yamato-Security/suzaku/releases"
SUPPORTED_MAJOR = "3"  # The suzaku_meta schema `kamotrace suzaku` imports


def tools_folder():
    return Path(os.environ.get("KAMOTRACE_TOOLS") or Path.home() / ".kamotrace" / "tools")


def platform_tag():
    machine = platform.machine().lower()
    arch = {"amd64": "x64", "x86_64": "x64", "arm64": "aarch64", "aarch64": "aarch64", "x86": "x86", "i686": "x86"}.get(machine)
    if sys.platform == "win32" and arch:
        return f"win-{arch}"
    if sys.platform == "darwin" and arch in ("x64", "aarch64"):
        return f"mac-{arch}"
    if sys.platform.startswith("linux"):
        # Suzaku 3's gnu builds need glibc 2.39+ (Ubuntu 24.04, Debian 13); older systems get the musl build.
        library, version = platform.libc_ver()
        new_glibc = library == "glibc" and tuple(int(p) for p in version.split(".")[:2]) >= (2, 39)
        if arch == "x64":
            return "lin-x64-gnu" if new_glibc else "lin-x64-musl"
        if arch == "aarch64" and new_glibc:
            return "lin-aarch64-gnu"
    raise RuntimeError(f"No Suzaku release for {sys.platform}/{machine}; download it manually and pass --suzaku")


def installed(folder=None):
    """Newest Suzaku installed by this helper: (version folder, executable) or None."""
    found = []
    for meta in (folder or tools_folder()).glob("suzaku-*/kamotrace-download.json"):
        info = json.loads(meta.read_text(encoding="utf-8"))
        executable = meta.parent / info["executable"]
        if executable.is_file():
            found.append((tuple(int(p) for p in info["version"].split(".")), executable))
    return max(found)[1] if found else None


def get(url):
    request = Request(url, headers={"Accept": "application/vnd.github+json", "User-Agent": "kamotrace"})
    return urlopen(request, timeout=60)


def choose_release(version=None):
    with get(RELEASES + "?per_page=30") as response:
        releases = [r for r in json.load(response) if not r["draft"] and not r["prerelease"]]
    if version:
        releases = [r for r in releases if r["tag_name"].lstrip("v") == version]
    else:
        releases = [r for r in releases if r["tag_name"].lstrip("v").split(".")[0] == SUPPORTED_MAJOR]
    if not releases:
        raise RuntimeError(f"No Suzaku {version or SUPPORTED_MAJOR + '.x'} release found at {RELEASES}")
    release = releases[0]  # GitHub lists newest first
    if release["tag_name"].lstrip("v").split(".")[0] != SUPPORTED_MAJOR:
        raise RuntimeError(f"KamoTrace imports Suzaku {SUPPORTED_MAJOR}.x output; {release['tag_name']} is not supported")
    return release


def install(archive, digest, version, tag, destination):
    """Verify `archive` against `digest` ("sha256:<hex>") and unpack it into destination/suzaku-<version>."""
    actual = hashlib.sha256(archive.read_bytes()).hexdigest()
    if digest != f"sha256:{actual}":
        raise RuntimeError(f"{archive.name}: SHA-256 {actual} does not match the published {digest}")
    target = destination / f"suzaku-{version}"
    staging = Path(tempfile.mkdtemp(prefix=".suzaku-", dir=destination))
    try:
        with zipfile.ZipFile(archive) as bundle:
            for name in bundle.namelist():
                parts = PurePosixPath(name).parts
                if name.startswith(("/", "\\")) or ".." in parts or ":" in name:
                    raise RuntimeError(f"{archive.name}: unsafe path {name!r} in archive")
            bundle.extractall(staging)
        executable = next((p for p in staging.iterdir() if p.is_file() and p.name.startswith("suzaku-")), None)
        if executable is None:
            raise RuntimeError(f"{archive.name}: no Suzaku executable at the top level")
        executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
        (staging / "kamotrace-download.json").write_text(json.dumps({
            "version": version, "platform": tag, "archive": archive.name, "sha256": actual,
            "executable": executable.name, "source": RELEASES}, indent=2), encoding="utf-8")
        if target.exists():
            shutil.rmtree(target)
        staging.replace(target)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return target / executable.name


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace get-suzaku", description=__doc__.splitlines()[0])
    parser.add_argument("--version", help=f"Suzaku version such as 3.0.0 (default: latest {SUPPORTED_MAJOR}.x)")
    parser.add_argument("--dest", type=Path, help="Tools folder (default: $KAMOTRACE_TOOLS or ~/.kamotrace/tools)")
    args = parser.parse_args(argv)
    destination = (args.dest or tools_folder()).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    try:
        release = choose_release(args.version)
        version, tag = release["tag_name"].lstrip("v"), platform_tag()
        asset = next((a for a in release["assets"] if a["name"] == f"suzaku-{version}-{tag}.zip"), None)
        if asset is None or not (asset.get("digest") or "").startswith("sha256:"):
            raise RuntimeError(f"Suzaku {version} has no {tag} download with a published SHA-256 digest")
        with tempfile.TemporaryDirectory(dir=destination) as work:
            archive = Path(work) / asset["name"]
            print(f"Downloading {asset['browser_download_url']} ({asset['size']:,} bytes)", file=sys.stderr)
            with get(asset["browser_download_url"]) as response, archive.open("wb") as stream:
                shutil.copyfileobj(response, stream)
            executable = install(archive, asset["digest"], version, tag, destination)
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps({"suzaku": str(executable), "version": version, "sha256": asset["digest"],
                      "licence": "AGPL-3.0 (https://github.com/Yamato-Security/suzaku)"}, indent=2))
