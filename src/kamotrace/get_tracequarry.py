"""Set up the pinned TraceQuarry fork and native journal reader in an isolated tools folder."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

from .get_suzaku import tools_folder
from .importer import sha256, write_lock
from .tracequarry import check_manifest, check_record

REPOSITORY = "https://github.com/truekonrads/TraceQuarry.git"
REVISION = "26c941fb575347c055f79a1c10ed68ba9bdb8a2d"
RUST = "1.100.0"


def run(command, *, cwd=None, env=None, stage):
    print(f"TraceQuarry: {stage}", file=sys.stderr)
    try:
        result = subprocess.run([str(c) for c in command], cwd=cwd, env=env,
                                text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as error:
        raise RuntimeError(f"{stage}: {error}") from error
    if result.returncode:
        diagnostic = (result.stdout or "") + (result.stderr or "")
        raise RuntimeError(f"{stage} failed (exit {result.returncode}):\n{diagnostic[-12000:]}")
    return result.stdout.strip()


def install(destination, source=None):
    destination = Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=True)
    target = destination / f"tracequarry-{REVISION}"
    with write_lock(target):
        if target.exists():
            raise FileExistsError(f"Refusing to overwrite {target}; choose a different --dest")
        for tool in ("git", "uv", "rustup", "cargo"):
            if not shutil.which(tool):
                raise RuntimeError(f"Missing {tool}; install Git, uv and Rust via rustup, including toolchain {RUST}. "
                                   "A native linker is required (MSVC Build Tools + Windows SDK on Windows).")
        run(["cargo", f"+{RUST}", "--version"],
            stage=f"check Rust toolchain (install with rustup toolchain install {RUST} --profile minimal)")
        # Never inherit a developer's parser/helper or target directory.
        env = os.environ.copy()
        for key in ("PYTHONPATH", "PYTHONHOME", "VIRTUAL_ENV", "TRACEQUARRY_JOURNAL_READER",
                    "CARGO_TARGET_DIR", "CARGO_BUILD_TARGET"):
            env.pop(key, None)
        with tempfile.TemporaryDirectory(prefix=".tracequarry-", dir=destination) as folder:
            work = Path(folder)
            checkout = work / "source"
            run(["git", "clone", "--no-checkout", "--", str(source or REPOSITORY), checkout], env=env,
                stage="clone pinned fork source")
            present = subprocess.run(["git", "cat-file", "-e", REVISION + "^{commit}"], cwd=checkout,
                                     env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0
            if not present:
                run(["git", "fetch", "origin", REVISION], cwd=checkout, env=env,
                    stage=f"fetch required revision {REVISION}; the fork must publish this commit, "
                          "or supply --source /path/to/verified-source.bundle (no fallback to main)")
            run(["git", "checkout", "--detach", REVISION], cwd=checkout, env=env, stage="checkout exact revision")
            actual = run(["git", "rev-parse", "HEAD"], cwd=checkout, env=env, stage="verify source revision")
            if actual != REVISION:
                raise RuntimeError(f"Wrong TraceQuarry revision: {actual}; expected {REVISION}")
            tree = run(["git", "rev-parse", "HEAD^{tree}"], cwd=checkout, env=env, stage="record source tree")
            venv = work / "venv"
            run(["uv", "venv", "--python", "3.12", "--relocatable", venv], env=env, stage="create isolated Python 3.12")
            python_relative = Path("venv/Scripts/python.exe" if sys.platform == "win32" else "venv/bin/python")
            python = work / python_relative
            run(["uv", "pip", "install", "--python", python, checkout, "tzdata>=2025.2"], env=env,
                stage="install TraceQuarry dependencies and IANA timezones")
            native = checkout / "native/journal-reader"
            cargo = ["cargo", f"+{RUST}"]
            build = work / "build"
            build_args = ["--release", "--locked", "--manifest-path", native / "Cargo.toml", "--target-dir", build]
            run([*cargo, "build", *build_args], env=env,
                stage="build native journal reader (requires native linker; see compiler output)")
            helper_name = "tracequarry-journal-reader" + (".exe" if sys.platform == "win32" else "")
            helper = work / helper_name
            shutil.copy2(build / "release" / helper_name, helper)
            env["TRACEQUARRY_TEST_PYTHON"] = str(python)
            env["TRACEQUARRY_JOURNAL_READER"] = str(helper)
            run([*cargo, "test", *build_args, "--test", "stream"], cwd=checkout, env=env,
                stage="verify native protocol, repeated journal entries and public Python intake")
            # A real public parse-only run must satisfy the same interchange checks as import-uac.
            probe = work / "probe"
            evidence = probe / "evidence"
            evidence.mkdir(parents=True)
            (evidence / "auth.log").write_text(
                "Jan  2 03:04:05 synthetic sshd[42]: Accepted password for analyst from 192.0.2.7 port 2222 ssh2\n" * 2,
                encoding="utf-8")
            output = probe / "parsed"
            run([python, "-m", "uac_parser.cli", evidence, "--parse-only", "--year", "2025", "--timezone", "UTC",
                 "--acquisition-id", "kamotrace-setup-probe", "--out", output], cwd=work, env=env,
                stage="verify parse-only ECS contract and duplicate occurrences")
            manifest = json.loads((output / "run_manifest.json").read_text(encoding="utf-8"))
            check_manifest(manifest)
            rows = [json.loads(line) for line in (output / "observations.jsonl").read_text(encoding="utf-8").splitlines()]
            for row in rows:
                check_record(row, manifest)
            if manifest["coverage"]["events"] != 2 or len(rows) != 2 or rows[0]["event"]["id"] == rows[1]["event"]["id"]:
                raise ValueError("TraceQuarry capability check failed: expected two distinct duplicate occurrences")
            dependencies = run(["uv", "pip", "list", "--format", "json", "--python", python], env=env,
                               stage="record Python dependencies")
            receipt = {"repository": REPOSITORY, "source": str(source or REPOSITORY), "revision": actual, "tree": tree,
                       "rust_toolchain": RUST, "python": str(python_relative), "journal_reader": helper_name,
                       "journal_reader_sha256": sha256(helper), "python_dependencies": json.loads(dependencies),
                       "capabilities": ["parse-only-ecs-8.17.0", "source-emission-v1", "native-journal-protocol-1"],
                       "platform": sys.platform}
            (work / "kamotrace-install.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
            shutil.rmtree(probe)
            shutil.rmtree(build)
            work.rename(target)
    return {**receipt, "python": str(target / python_relative), "journal_reader": str(target / helper_name),
            "receipt": str(target / "kamotrace-install.json")}


def main(argv=None):
    parser = argparse.ArgumentParser(prog="kamotrace get-tracequarry", description=__doc__)
    parser.add_argument("--dest", type=Path, help="Tools folder (default: $KAMOTRACE_TOOLS or ~/.kamotrace/tools)")
    parser.add_argument("--source", type=Path, help="Explicit local source Git bundle/repository containing the exact pinned commit")
    args = parser.parse_args(argv)
    try:
        result = install(args.dest or tools_folder(), args.source.resolve() if args.source else None)
    except (OSError, RuntimeError, ValueError) as error:
        parser.error(str(error))
    print(json.dumps(result, indent=2))
    return 0
