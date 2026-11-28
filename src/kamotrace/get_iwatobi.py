"""Build and verify the pinned Iwatobi forensic-export fork (requires Git and Rust 1.88+).

Iwatobi is not bundled. The qualified fork, not an upstream 1.0.0 release,
provides the exact source references understood by KamoTrace's native attachment.
Only synthetic packaged examples are scanned during installation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .get_suzaku import tools_folder
from .iwatobi import reference_key

SOURCE = "https://github.com/truekonrads/iwatobi.git"
REVISION = "d4b5f02cbd7fe7a044f8a5e1153157355489bd5b"
SCHEMA = "iwatobi-forensic-1.0.0"
PROFILE = "uac-1.0.0"
LICENCE = "RPL-1.5 (https://github.com/truekonrads/iwatobi)"


def run(command, cwd, timeout=180):
    result = subprocess.run([str(p) for p in command], cwd=cwd, capture_output=True,
                            text=True, errors="replace", timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"{command[0]} failed ({result.returncode}):\n"
                           + (result.stderr + result.stdout)[-4000:])
    return result.stdout


def verify(executable, folder, work):
    """Exercise a bound, three-line synthetic correlation, not a version string."""
    help_text = run([executable, "dfir-timeline", "--help"], folder)
    if not all(flag in help_text for flag in ("--forensic-output", "--evidence-manifest")):
        raise RuntimeError("Iwatobi lacks --forensic-output / --evidence-manifest; upstream 1.0.0 is insufficient")
    example = folder / "docs/examples/forensic"
    output = work / "forensic-smoke.json"
    run([executable, "dfir-timeline", "-f", example / "access.log", "-r",
         folder / "rules/iwatobi/web/webserver/web_rapid_posts_to_php_index.yml",
         "-z", "UTC", "--forensic-output", output, "--evidence-manifest",
         example / "evidence-manifest.json", "-q", "-K", "-w", "-Q"], folder, timeout=60)
    bundle = json.loads(output.read_text(encoding="utf-8"))
    if bundle.get("schema") != SCHEMA or bundle.get("source_reference_profile") != PROFILE:
        raise RuntimeError(f"Iwatobi must produce {SCHEMA} / {PROFILE}")
    alerts = bundle.get("alerts", [])
    if len(alerts) != 1:
        raise RuntimeError("Iwatobi synthetic smoke expected one correlation alert")
    alert = alerts[0]
    members = alert.get("members", [])
    if (alert.get("kind") != "correlation" or alert.get("members_total") != 3
            or alert.get("members_truncated") is not False or alert.get("exact_members") != 3
            or alert.get("evidence_status") != "exact" or len(members) != 3):
        raise RuntimeError("Iwatobi synthetic smoke did not retain three exact correlation members")
    sha256 = hashlib.sha256((example / "access.log").read_bytes()).hexdigest()
    keys = []
    for member in members:
        location = member.get("evidence", {}).get("location", {})
        refs = location.get("source_refs", [])
        if location.get("status") != "exact" or len(refs) != 1:
            raise RuntimeError("Iwatobi synthetic smoke lacks exact source references")
        keys.append(reference_key(alert.get("uac", {}).get("acquisition"), refs[0]))
    expected = [("synthetic-example-acquisition", "supplied", "synthetic-web-server",
                 "var/log/apache2/access.log", sha256, line) for line in (1, 2, 3)]
    if set(keys) != set(expected):
        raise RuntimeError("Iwatobi synthetic smoke has incompatible acquisition/hash/decoded-text-line locators")
    return {"schema": SCHEMA, "source_reference_profile": PROFILE, "exact_members": 3}


def install(destination):
    target = destination / f"iwatobi-{REVISION}"
    if target.exists() or target.is_symlink():
        raise RuntimeError(f"{target} already exists; use its executable or choose another --dest (no overwrite)")
    for tool in ("git", "cargo"):
        if not shutil.which(tool):
            raise RuntimeError(f"{tool} is required; install Git and Rust 1.88+ with Cargo, then retry")
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix=".iwatobi-", dir=destination) as temporary:
        work = Path(temporary)
        folder = work / "source"
        print(f"Fetching {SOURCE} at {REVISION}", file=sys.stderr)
        run(["git", "clone", "--quiet", "--no-checkout", SOURCE, folder], destination)
        run(["git", "checkout", "--quiet", "--detach", REVISION], folder)
        actual = run(["git", "rev-parse", "HEAD"], folder).strip()
        if actual != REVISION:
            raise RuntimeError(f"Iwatobi checkout {actual} does not match required {REVISION}")
        print("Building Iwatobi with cargo build --release --locked (may take several minutes)", file=sys.stderr)
        # An external CARGO_TARGET_DIR must not redirect our build or smoke binary.
        run(["cargo", "build", "--release", "--locked", "--target-dir", folder / "target"], folder, timeout=1800)
        name = "iwatobi.exe" if sys.platform == "win32" else "iwatobi"
        executable = folder / name
        shutil.move(folder / "target/release" / name, executable)
        smoke = verify(executable, folder, work)
        receipt = {"source": SOURCE, "revision": REVISION, "executable": name,
                   "sha256": hashlib.sha256(executable.read_bytes()).hexdigest(),
                   "build": "cargo build --release --locked", "smoke": smoke, "licence": LICENCE}
        (folder / "kamotrace-download.json").write_text(json.dumps(receipt, indent=2), encoding="utf-8")
        shutil.rmtree(folder / "target")
        # Keep the source, pinned rules/config and licence together with the binary.
        if target.exists() or target.is_symlink():
            raise RuntimeError(f"{target} appeared while building; it was not replaced")
        folder.rename(target)
    return target / name, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace get-iwatobi", description=__doc__.splitlines()[0])
    parser.add_argument("--dest", type=Path, help="Tools folder (default: $KAMOTRACE_TOOLS or ~/.kamotrace/tools)")
    args = parser.parse_args(argv)
    try:
        executable, receipt = install((args.dest or tools_folder()).resolve())
    except (OSError, RuntimeError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        parser.error(str(error))
    print(json.dumps({"iwatobi": str(executable), "folder": str(executable.parent), **receipt}, indent=2))
