"""
Launcher arguments remain compatible with x11vnc discovery without changing Git bytes.
"""

import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from hermes_cli import _early_recovery, _launchers
from hermes_platform.resolver.core import locate_command


# The FINDDISPLAY filter from x11vnc's src/ssltools.h, fed synthetic ps output only.
_FIND_DISPLAY = (
    r"grep '/X.* :[0-9][0-9]* .*-auth' | egrep -v 'startx|xinit' | "
    r"sed -e 's,^.*/X.* \(:[0-9][0-9]*\) .* -auth \([^ ][^ ]*\).*$,\1\,\2,' | sort -u"
)
_REPAIR_PROBE = """\
import json, subprocess, sys
fixture = json.load(sys.stdin)
def git_output(command, **kwargs):
    if command[4] == 'ls-tree':
        output = bytes.fromhex(fixture['tree'])
    else:
        assert command[4:6] == ['cat-file', 'blob'], command
        output = bytes.fromhex(fixture['objects'][command[6]])
    return subprocess.CompletedProcess(command, 0, stdout=output, stderr=b'')
subprocess.run = git_output
exec(compile(fixture['script'], '<generated launcher>', 'exec'))
"""


@pytest.mark.platforms("linux")
@pytest.mark.parametrize("entry_point", _launchers.ENTRY_POINTS)
def test_launcher_process_listing_preserves_x11vnc_auth_discovery(tmp_path: Path, entry_point: str) -> None:
    dash = locate_command("dash").command
    assert dash, "x11vnc regression requires dash"
    version = subprocess.run(["grep", "--version"], capture_output=True, check=True, timeout=10)
    assert b"GNU grep" in version.stdout, "x11vnc regression requires GNU grep"
    probe = subprocess.run([*dash, "-c", r'echo "\0"'], capture_output=True, check=True, timeout=10)
    assert probe.stdout == b"\0\n", "the selected shell must interpret echo escapes"

    script = _launchers._launcher_script(entry_point, tmp_path / "checkout", None)
    compile(script, "<generated launcher>", "exec")
    # Keep the NUL-producing launcher before Xorg, independent of grep's read buffer size.
    listing = (
        f"user 102 python3 -I -c {script}\n"
        "root 101 /usr/lib/xorg/Xorg -core :0 -seat seat0 "
        "-auth /run/lightdm/root/:0 -nolisten tcp vt7\n"
    ).encode()
    for emitter in ("printf '%s\\n' \"$psout\"", 'echo "$psout"'):
        result = subprocess.run(
            [*dash, "-c", "psout=$(cat)\n" + emitter + " | " + _FIND_DISPLAY],
            input=listing, capture_output=True, timeout=10, env={**os.environ, "LC_ALL": "C"},
        )
        assert result.returncode == 0, result.stderr
        assert result.stdout == b":0,/run/lightdm/root/:0\n", (emitter, result.stdout, result.stderr)
        assert b"binary file matches" not in result.stderr, (emitter, result.stderr)


@pytest.mark.platforms("any")
@pytest.mark.parametrize("object_format", ["sha1", "sha256"])
@pytest.mark.parametrize("corrupt", [False, True])
def test_emitted_repair_preserves_git_blob_and_record_bytes(
    tmp_path: Path, object_format: str, corrupt: bool,
) -> None:
    git = locate_command("git").command
    assert git, "Git is required as the independent blob-hash oracle"
    root = tmp_path / "checkout"
    root.mkdir()
    (root / "hermes_bootstrap.py").write_text("raise ImportError('damaged fixture bootstrap')\n", encoding="utf-8")
    env = {**os.environ, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull}
    subprocess.run(
        [*git, "init", "-q", f"--object-format={object_format}", str(root)],
        env=env, capture_output=True, check=True, timeout=10,
    )
    # Git reads bytes only: this fixture never stages files, writes objects, or creates commits.
    blobs = dict(zip(_early_recovery.RECOVERY_CLOSURE, (
        b"def restore_interrupted_pull(root):\n    print('VERIFIED_REPAIR')\n    return False\n",
        b"",
        b"binary\0payload\xff\n",
    ), strict=True))
    object_ids = {}
    for relative, data in blobs.items():
        hashed = subprocess.run(
            [*git, "-C", str(root), "hash-object", "--stdin"], input=data,
            env=env, capture_output=True, check=True, timeout=10,
        )
        object_ids[relative] = hashed.stdout.decode("ascii").strip()
    pre = "1" * len(next(iter(object_ids.values())))
    (root / ".git" / _early_recovery.INTERRUPTED_PULL_MARKER).write_text(
        f"pre={pre}\ngit={git[0]}\n", encoding="utf-8",
    )
    records = [f"100644 blob {oid}\t{relative}".encode() for relative, oid in object_ids.items()]
    # A newline in an unrelated filename must not inject a second record for the repair module.
    records.append(f"100644 blob {pre}\tspace in name\n100644 blob {pre}\t{next(iter(blobs))}".encode())
    objects = {object_ids[relative]: data.hex() for relative, data in blobs.items()}
    if corrupt:
        objects[object_ids[next(iter(blobs))]] = b"print('UNVERIFIED_RAN')\n".hex()
    result = subprocess.run(
        [sys.executable, "-I", "-c", _REPAIR_PROBE],
        input=json.dumps({"script": _launchers._launcher_script("hermes", root, None),
                          "tree": (b"\0".join(records) + b"\0").hex(), "objects": objects}),
        cwd=tmp_path, env=env, capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    # The repair entry is a receipt; the generated bootstrap's verification and publication are real.
    assert result.returncode == 1, result.stderr
    assert "UNVERIFIED_RAN" not in result.stdout
    closure = root / ".git" / _early_recovery.RECOVERY_CLOSURE_DIR / pre
    if corrupt:
        assert result.stdout == "", result.stderr
        assert "damaged fixture bootstrap" in result.stderr, result.stderr
        assert not closure.exists(), "unverified object bytes must never be published"
    else:
        assert result.stdout == "VERIFIED_REPAIR\n", result.stderr
        for relative, data in blobs.items():
            assert (closure / relative).read_bytes() == data
        assert (closure / _early_recovery.RECOVERY_CLOSURE_INIT).read_bytes() == b""
        manifest = dict(line.split(" ", 1)[::-1] for line in (
            closure / _early_recovery.RECOVERY_CLOSURE_MANIFEST
        ).read_text(encoding="utf-8").splitlines())
        assert manifest == {**object_ids, _early_recovery.RECOVERY_CLOSURE_INIT:
                            object_ids[_early_recovery.RECOVERY_CLOSURE[1]]}
