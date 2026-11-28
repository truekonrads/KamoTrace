"""Real offline image qualification, separate from unittest discovery.

Run: python tests/docker_smoke.py --image kamotrace:local
Requires a local Docker daemon, not host KamoTrace/parser/compiler dependencies.
Only disposable synthetic inputs, containers and uniquely named volumes are used.
"""
import argparse
import hashlib
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
import uuid


def docker(*args, check=True):
    result = subprocess.run(["docker", *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    if check and result.returncode:
        raise RuntimeError(f"docker {' '.join(map(str, args))}\n{result.stdout}")
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="kamotrace:local")
    parser.add_argument("--network", default="bridge", help="Viewer network (one-off stages always use none)")
    args = parser.parse_args()
    key = "kamotrace-smoke-" + uuid.uuid4().hex[:12]
    case, tools, viewer = key + "-case", key + "-tools", key + "-viewer"
    scratch = Path(".amp/in/orb-backup").resolve()
    scratch.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="docker-smoke-", dir=scratch) as folder:
        inputs = Path(folder)
        inputs.chmod(0o755)  # The image runs as UID 10001, not the host test owner.
        first, second = inputs / "first", inputs / "second"
        first.mkdir()
        second.mkdir()
        (first / "access.log").write_text(
            '192.0.2.17 - - [25/Nov/2026:07:01:02 +0000] "POST /index.php HTTP/1.1" 200 149 "-" "-"\n' * 3)
        auth = "Jan  2 03:04:05 synthetic sshd[42]: Accepted password for first-load from 192.0.2.7 port 2222 ssh2\n"
        (first / "auth.log").write_text(auth * 2)
        (second / "auth.log").write_text(auth.replace("first-load", "second-load"))
        (inputs / "cloudtrail.json").write_text(json.dumps({"Records": [{
            "eventVersion": "1.11", "eventTime": "2026-11-25T07:01:02Z", "eventID": "synthetic-delete-trail",
            "eventSource": "cloudtrail.amazonaws.com", "eventName": "DeleteTrail", "awsRegion": "us-east-1",
            "recipientAccountId": "123456789012", "sourceIPAddress": "192.0.2.7",
            "userIdentity": {"type": "IAMUser", "accountId": "123456789012", "userName": "synthetic"},
            "requestParameters": {"name": "synthetic-trail"}, "responseElements": None}]}))
        # Make the mount, not host UID permissions, enforce the read-only contract.
        for path in inputs.rglob("*"):
            if path.is_file():
                path.chmod(0o666)
        original = {str(p.relative_to(inputs)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in inputs.rglob("*") if p.is_file()}
        mounts = ["-v", f"{inputs}:/input:ro", "-v", f"{case}:/case", "-v", f"{tools}:/tools"]

        def run(*command, entrypoint=None, workdir=None):
            options = ["--entrypoint", entrypoint] if entrypoint else []
            if workdir:
                options += ["--workdir", workdir]
            return docker("run", "--rm", "--network", "none", *mounts, *options, args.image, *command)

        def python(code):
            return run("-c", code, entrypoint="python")

        with socket.socket() as available:
            available.bind(("127.0.0.1", 0))
            port = available.getsockname()[1]
        base = f"http://127.0.0.1:{port}"

        def api(path, data=None):
            request = Request(base + path, data=json.dumps(data).encode() if data is not None else None,
                              headers={"Content-Type": "application/json"})
            with urlopen(request, timeout=15) as response:
                return json.load(response)

        def start():
            docker("run", "-d", "--name", viewer, "--network", args.network,
                   "-p", f"127.0.0.1:{port}:{port}", "-v", f"{case}:/case", "-v", f"{tools}:/tools", args.image,
                   "serve", "--case", "/case/case.json", "--port", port, "--iwatobi", "/case/iwatobi.json")
            for _ in range(120):
                try:
                    api("/api/meta")
                    return
                except (URLError, TimeoutError, ConnectionError):
                    if docker("inspect", "-f", "{{.State.Running}}", viewer) != "true":
                        raise RuntimeError(docker("logs", viewer))
                    time.sleep(0.5)
            raise RuntimeError("Viewer did not become ready\n" + docker("logs", viewer))

        def stop():
            docker("stop", "--timeout", "30", viewer)
            code = docker("inspect", "-f", "{{.State.ExitCode}}", viewer)
            assert code == "0", f"Viewer exited {code}\n" + docker("logs", viewer)
            docker("rm", viewer)

        try:
            docker("volume", "create", case)
            docker("volume", "create", tools)
            # Verify relocatability, native dynamic libraries, pins and non-root permissions.
            python("""
import hashlib, json, os, pathlib, shutil, subprocess
assert os.getuid() == 10001
assert shutil.which('cargo') is None and shutil.which('gcc') is None
root = pathlib.Path('/opt/tools')
iwa = root/'iwatobi-d4b5f02cbd7fe7a044f8a5e1153157355489bd5b'
receipt = json.loads((iwa/'kamotrace-download.json').read_text())
assert receipt['revision'] == 'd4b5f02cbd7fe7a044f8a5e1153157355489bd5b'
assert receipt['sha256'] == hashlib.sha256((iwa/'iwatobi').read_bytes()).hexdigest()
tq = root/'tracequarry-26c941fb575347c055f79a1c10ed68ba9bdb8a2d'
receipt = json.loads((tq/'kamotrace-install.json').read_text())
assert receipt['revision'] == '26c941fb575347c055f79a1c10ed68ba9bdb8a2d'
assert receipt['journal_reader_sha256'] == hashlib.sha256(pathlib.Path(os.environ['TRACEQUARRY_JOURNAL_READER']).read_bytes()).hexdigest()
subprocess.run(['tracequarry-python', '-c', 'import sys, tzdata; assert sys.version_info[:2] == (3,12)'], check=True)
bad = pathlib.Path('/case/invalid.journal'); bad.write_bytes(b'not a journal')
result = subprocess.run([os.environ['TRACEQUARRY_JOURNAL_READER'], str(bad)], capture_output=True, text=True)
assert result.returncode != 0 and json.loads(result.stdout)['kind'] == 'error'
bad.unlink()
try:
    pathlib.Path('/input/first/auth.log').write_text('must not write')
except OSError:
    pass
else:
    raise AssertionError('Original input mount is writable')
from kamotrace.get_suzaku import installed
exe = installed(); assert exe is not None
assert os.access(exe.parent, os.W_OK), 'Default user must be able to maintain its tools volume'
assert json.loads((exe.parent/'kamotrace-download.json').read_text())['version'] == '3.0.0'
source = root/'suzaku-source-3.0.0'
assert (source/'kamotrace-source-revision').read_text().strip() == 'c88eca3a03227a0d9a55d59a1c45677315cf4fc8'
assert not (source/'.git').exists()  # Git objects would retain excluded geolocation fixtures.
assert not list(root.rglob('*.mmdb')) and not list(pathlib.Path('/tools').rglob('*.mmdb'))
assert (exe.parent/'LICENSE.txt').read_bytes() == (source/'LICENSE.txt').read_bytes()
assert (iwa/'LICENSE').is_file() and (tq/'source/LICENSE').is_file()
subprocess.run([str(exe), '--version'], check=True)
""")
            for name in ("first", "second"):
                run("-m", "uac_parser.cli", "/input/" + name, "--parse-only", "--year", "2026",
                    "--timezone", "UTC", "--acquisition-id", name, "--out", "/case/parsed-" + name,
                    entrypoint="tracequarry-python")
            # Bind detector input to the actual parser's physical refs, never time/IP guesses.
            python("""
import json, pathlib
root = pathlib.Path('/case')
rows = [json.loads(s) for s in (root/'parsed-first/observations.jsonl').read_text().splitlines()]
assert len(rows) == 5
web = [r for r in rows if r['uac']['source_refs'][0]['path'].endswith('access.log')]
assert len(web) == 3
ref = web[0]['uac']['source_refs'][0]
manifest = {'acquisition_id': 'first', 'sources': [{'input_path': '/input/first/access.log',
            'collection_id': ref['collection_id'], 'path': ref['path'], 'sha256': ref['sha256']}]}
(root/'iwatobi-manifest.json').write_text(json.dumps(manifest))
""")
            iwa = "/opt/tools/iwatobi-d4b5f02cbd7fe7a044f8a5e1153157355489bd5b"
            run("dfir-timeline", "-f", "/input/first/access.log", "-r",
                "rules/iwatobi/web/webserver/web_rapid_posts_to_php_index.yml", "-z", "UTC",
                "--forensic-output", "/case/iwatobi.json", "--evidence-manifest", "/case/iwatobi-manifest.json",
                "-q", "-K", "-w", "-Q", entrypoint="iwatobi", workdir=iwa)
            run("import-uac", "--case", "/case/case.json", "--unit", "first", "--source", "/case/parsed-first")
            run("prepare", "--case", "/case/case.json", "--unit", "first")
            start()
            assert api("/api/events", {})["last_row"] == 5
            assert api("/api/events", {"search": "first-load"})["last_row"] == 2
            detections = api("/api/detections")
            assert detections["iwatobi"]["counts"]["linked"] == 1, detections
            rule = detections["rules"][0]["rule_id"]
            linked = api("/api/events", {"rules": [rule]})["data"]
            assert len(linked) == 3
            assert len(api("/api/events/" + str(linked[0]["id"]))["iwatobi_alerts"]) == 1
            hashes = [linked[0]["record_sha256"]]
            api("/api/reviews", {"action": "annotate", "hashes": hashes, "body": "Docker retained finding"})
            api("/api/reviews", {"action": "tag", "hashes": hashes, "slug": "retained", "color": "#123456"})
            stop()
            run("import-uac", "--case", "/case/case.json", "--unit", "second", "--source", "/case/parsed-second")
            run("prepare", "--case", "/case/case.json", "--unit", "second")
            # Suzaku runs offline too, using the seeded named tools volume.
            run("import", "--case", "/case/case.json", "--unit", "cloud", "--source", "/input/cloudtrail.json")
            run("prepare", "--case", "/case/case.json", "--unit", "cloud")
            run("suzaku", "--case", "/case/case.json", "--source", "/input/cloudtrail.json")
            start()
            assert api("/api/events", {})["last_row"] == 7
            assert api("/api/events", {"search": "second-load"})["last_row"] == 1
            retained = api("/api/events", {"search": "first-load"})
            assert retained["last_row"] == 2, retained
            assert api("/api/events", {"tags": ["retained"]})["last_row"] == 1
            assert api("/api/reviews")["annotations"][0]["body"] == "Docker retained finding"
            assert api("/api/detections")["iwatobi"]["counts"]["linked"] == 1
            assert api("/api/detections")["run"]["linked_rows"] >= 1
            # The image's configured stop signal must also work for restart.
            docker("restart", "--timeout", "30", viewer)
            for _ in range(120):
                try:
                    assert api("/api/events", {})["last_row"] == 7
                    break
                except (URLError, TimeoutError, ConnectionError):
                    time.sleep(0.5)
            else:
                raise AssertionError("Restart did not recover the case")
            try:
                urlopen(Request(base + "/api/meta", headers={"Host": "untrusted.example"}), timeout=5)
            except HTTPError as error:
                assert error.code == 403
            else:
                raise AssertionError("Host check was bypassed")
            stop()
            assert original == {str(p.relative_to(inputs)): hashlib.sha256(p.read_bytes()).hexdigest()
                                for p in inputs.rglob("*") if p.is_file()}
            print("PASS: offline parse/import/prepare/search (5 → 6 UAC + 1 CloudTrail), exact 3-member Iwatobi attachment, "
                  "Suzaku detection, additive load, Findings/tags after recreation, restart, clean stop, read-only inputs and Host checks")
        finally:
            docker("rm", "-f", viewer, check=False)
            docker("volume", "rm", case, tools, check=False)


if __name__ == "__main__":
    main()
