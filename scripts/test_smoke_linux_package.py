#!/usr/bin/env python3
"""Pure safety tests: never install a package or launch a display."""
import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("smoke_linux_package", Path(__file__).with_name("smoke-linux-package.py"))
smoke = importlib.util.module_from_spec(spec)
spec.loader.exec_module(smoke)


def archive(entries):
    encoded = io.BytesIO()
    with tarfile.open(fileobj=encoded, mode="w") as tar:
        for name, content, mode, kind in entries:
            member = tarfile.TarInfo(name)
            member.mode, member.uid, member.gid = mode, 0, 0
            if kind == "directory":
                member.type = tarfile.DIRTYPE
                tar.addfile(member)
            elif kind == "symlink":
                member.type, member.linkname = tarfile.SYMTYPE, "/outside"
                tar.addfile(member)
            else:
                member.size = len(content)
                tar.addfile(member, io.BytesIO(content))
    return encoded.getvalue()


CONTROL = b"Package: devdrop\nVersion: 0.1.0\nArchitecture: amd64\nDepends: libgtk-3-0, libwebkit2gtk-4.1-0\nDescription: generated fixture\n"
PAYLOAD = [
    ("usr", b"", 0o755, "directory"),
    ("usr/bin", b"", 0o755, "directory"),
    ("usr/bin/devdrop-desktop", b"generated binary fixture", 0o755, "file"),
    ("usr/share/applications/DevDrop.desktop", b"[Desktop Entry]\nName=DevDrop\nExec=devdrop-desktop\n", 0o644, "file"),
]


class SafetyTests(unittest.TestCase):
    def refused(self, fn, *args, **kwargs):
        with self.assertRaises(smoke.SmokeError):
            fn(*args, **kwargs)

    def test_refuses_outside_ci_before_any_subprocess(self):
        with patch.dict(os.environ, {}, clear=True), patch.object(smoke.subprocess, "Popen") as popen, patch.object(smoke.subprocess, "run") as run:
            self.refused(smoke.ci_context, Path("/tmp/fake"), Path("/tmp/report"))
            popen.assert_not_called()
            run.assert_not_called()

    def test_checksum_mismatch_and_manifest_paths_fail_closed(self):
        import hashlib
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            deb = root / "DevDrop_0.1.0_amd64.deb"
            deb.write_bytes(b"generated archive fixture")
            manifest = root / "SHA256SUMS-Linux-X64.txt"
            digest = hashlib.sha256(deb.read_bytes()).hexdigest()
            manifest.write_text(f"{digest}  {deb.name}\n")
            self.assertEqual(smoke.verified_deb(root), (deb, digest))
            for line in [f"{'0'*64}  {deb.name}\n", f"{digest}  ../outside.deb\n", f"{digest}  {deb.name}\n{digest}  {deb.name}\n"]:
                manifest.write_text(line)
                self.refused(smoke.verified_deb, root)

    def test_control_rejects_hooks_unrelated_packages_and_system_changes(self):
        valid = [("control", CONTROL, 0o644, "file")]
        self.assertEqual(smoke.inspect_control(archive(valid))["Package"], "devdrop")
        for name in ["postinst", "preinst", "prerm", "postrm", "triggers", "conffiles"]:
            self.refused(smoke.inspect_control, archive(valid + [(name, b"generated", 0o755, "file")]))
        for changed in [CONTROL.replace(b"Package: devdrop", b"Package: unrelated"), CONTROL + b"Conflicts: openssh-server\n", CONTROL + b"Essential: yes\n", CONTROL.replace(b"libgtk-3-0", b"ufw"), CONTROL.replace(b"libgtk-3-0, libwebkit2gtk-4.1-0", b"libgtk-3-0,\n ufw")]:
            self.refused(smoke.inspect_control, archive([("control", changed, 0o644, "file")]))

    def test_payload_refuses_namespace_metadata_links_and_unsafe_exec(self):
        self.assertEqual(smoke.inspect_payload(archive(PAYLOAD), "devdrop"), 2)
        variants = [
            PAYLOAD + [("etc/generated.conf", b"generated", 0o644, "file")],
            PAYLOAD + [("usr/lib/unrelated", b"", 0o755, "directory")],
            [("usr/bin", b"", 0, "directory")] + PAYLOAD[2:],
            PAYLOAD + [("usr/bin/unrelated", b"generated", 0o755, "file")],
            PAYLOAD + [("usr/lib/devdrop/link", b"", 0o755, "symlink")],
            [("usr/bin/devdrop-desktop", b"generated", 0o4755, "file")],
            [("../outside", b"generated", 0o644, "file")],
            [PAYLOAD[2], (PAYLOAD[3][0], b"Exec=sh -c generated\n", 0o644, "file")],
        ]
        for entries in variants:
            self.refused(smoke.inspect_payload, archive(entries), "devdrop")

    def test_app_env_preserves_home_and_drops_credentials_and_bypass_flags(self):
        with tempfile.TemporaryDirectory() as directory, patch.dict(os.environ, {"HOME": "/home/runner", "GH_TOKEN": "generated-canary", "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS": "1"}):
            env = smoke.isolated_env(Path(directory), ":199", Path(directory) / "Xauthority")
            self.assertEqual(env["HOME"], "/home/runner")
            self.assertNotIn("GH_TOKEN", env)
            self.assertNotIn("WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS", env)
            for key in ["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_RUNTIME_DIR"]:
                self.assertEqual(Path(env[key]).parent, Path(directory))
                self.assertEqual(Path(env[key]).stat().st_mode & 0o777, 0o700)

    def test_empty_state_observation_never_registers_or_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "metadata.sqlite3"
            self.refused(smoke.empty_state, path)
            self.assertFalse(path.exists())
            with sqlite3.connect(path) as db:
                db.executescript("CREATE TABLE schema_version(version INTEGER); INSERT INTO schema_version VALUES(2); CREATE TABLE pairs(id TEXT); CREATE TABLE plans(id TEXT);")
            before = path.read_bytes()
            smoke.empty_state(path)
            self.assertEqual(path.read_bytes(), before)
            with sqlite3.connect(path) as db:
                db.execute("INSERT INTO pairs VALUES('generated')")
            self.refused(smoke.empty_state, path)

    def test_window_requires_viewable_title_and_exact_pid(self):
        tree = b'  0x120001 "DevDrop": ("devdrop-desktop" "Devdrop-desktop")\n'
        outputs = [tree, b"Map State: IsViewable", b"_NET_WM_PID(CARDINAL) = 123"]
        with patch.object(smoke, "command", side_effect=outputs):
            self.assertEqual(smoke.mapped_window({}, 123), "0x120001")
        outputs = [tree, b"Map State: IsViewable", b"_NET_WM_PID(CARDINAL) = 456"]
        with patch.object(smoke, "command", side_effect=outputs):
            self.assertIsNone(smoke.mapped_window({}, 123))

    def test_sandbox_diagnostic_is_allowlisted_not_raw_stderr(self):
        text = b"private arbitrary data\nbwrap: Creating new namespace failed: Operation not permitted\n"
        self.assertEqual(smoke.app_diagnostic(text), "bwrap: Creating new namespace failed: Operation not permitted")
        self.assertIsNone(smoke.app_diagnostic(b"unknown generated canary"))

    def test_exclusive_report_does_not_follow_dangling_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report.json"
            outside = root / "must-not-be-created"
            report.symlink_to(outside)
            context = {"report": report}
            result = {"schema": smoke.SCHEMA, "status": "passed"}
            with patch.object(smoke, "ci_context", return_value=context), patch.object(smoke, "smoke", return_value=result), patch.object(sys, "argv", ["smoke", "--artifact-dir", str(root), "--report", str(report)]), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(smoke.main(), 1)
            self.assertFalse(outside.exists())

    def test_bounded_command_refuses_large_output_and_timeout(self):
        self.refused(smoke.command, [sys.executable, "-c", "print('x'*100000)"], "generated_command", limit=1024)
        self.refused(smoke.command, [sys.executable, "-c", "import time; time.sleep(2)"], "generated_command", timeout=0.01)

    def test_cleanup_stops_only_created_process_group_and_waits(self):
        from unittest.mock import Mock
        process = Mock(pid=12345)
        process.wait.side_effect = [subprocess.TimeoutExpired("generated", 4), 0]
        with patch.object(smoke.os, "killpg") as kill:
            smoke.stop_group(process)
            self.assertEqual(kill.call_count, 2)
            self.assertEqual({call.args[0] for call in kill.call_args_list}, {12345})
            self.assertEqual(process.wait.call_count, 2)


if __name__ == "__main__":
    unittest.main()
