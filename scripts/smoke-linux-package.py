#!/usr/bin/env python3
"""Install/start/remove only this run's DevDrop .deb on a disposable hosted VM.

This is a guarded CI smoke test, not a local installer or a bare-OS acceptance
claim. No project is registered and no GUI action is sent to the application.
"""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import signal
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
from urllib.parse import quote


SCHEMA = "devdrop-linux-runtime-evidence/v1"
APP = Path("/usr/bin/devdrop-desktop")
# Tauri's Debian bundler writes heck::AsKebabCase(product_name()) as Package.
# The tracked productName "DevDrop" therefore generates exactly "dev-drop";
# Cargo's devdrop-desktop remains the executable name, not the package name.
PACKAGES = {"dev-drop"}


class SmokeError(Exception):
    def __init__(self, code, exit_code=None, diagnostic=None):
        self.code, self.exit_code, self.diagnostic = code, exit_code, diagnostic


def require(condition, code):
    if not condition:
        raise SmokeError(code)


def ci_context(artifact, report):
    """Refuse before subprocesses unless this is the specifically scoped CI job."""
    require(os.environ.get("GITHUB_ACTIONS") == "true", "github_actions_required")
    require(os.environ.get("RUNNER_ENVIRONMENT") == "github-hosted", "hosted_runner_required")
    require(os.environ.get("GITHUB_REPOSITORY") == "Rickythegreat1/dropdev", "wrong_repository")
    require(os.environ.get("GITHUB_EVENT_NAME") == "push", "public_push_required")
    require(os.environ.get("GITHUB_JOB") == "linux_runtime", "wrong_ci_job")
    require(platform.system() == "Linux" and platform.machine() == "x86_64", "linux_x64_required")
    distro = platform.freedesktop_os_release()
    require(distro.get("ID") == "ubuntu" and distro.get("VERSION_ID") == "22.04", "ubuntu_2204_required")
    require(os.geteuid() != 0, "non_root_runner_required")
    root = Path(os.environ["RUNNER_TEMP"]).resolve(strict=True)
    require(root.is_dir() and str(root).startswith("/home/runner/work/"), "hosted_temp_required")
    event = Path(os.environ["GITHUB_EVENT_PATH"])
    require(event.is_file() and event.stat().st_size <= 2 * 1024 * 1024, "bounded_event_required")
    payload = json.loads(event.read_text())
    require(payload.get("repository", {}).get("private") is False, "public_repository_required")
    commit = os.environ.get("GITHUB_SHA", "")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None, "source_sha_required")
    require(payload.get("after") == commit, "push_source_mismatch")
    artifact, report = artifact.absolute(), report.absolute()
    require(artifact == root / "linux-package" and not artifact.is_symlink(), "scoped_artifact_directory_required")
    require(artifact.resolve(strict=True) == artifact and artifact.is_dir(), "artifact_directory_links_refused")
    require(report == root / "devdrop-linux-runtime.json" and not report.exists() and not report.is_symlink(), "new_scoped_report_required")
    return {"root": root, "artifact": artifact, "report": report, "commit": commit,
            "run_id": os.environ["GITHUB_RUN_ID"], "job_id": os.environ["GITHUB_JOB"]}


def supervised_command(args, timeout):
    if args[:2] == ["sudo", "-n"]:
        # The timeout supervisor runs as root alongside apt/dpkg, even if sudo
        # creates a PTY/session with a different process group from its parent.
        return args[:2] + ["timeout", "--signal=TERM", "--kill-after=5s", str(timeout)] + args[2:], timeout + 15
    return args, timeout


def command(args, code, *, limit=65536, timeout=60, env=None, input_bytes=None, quiet=False):
    """Bound output in RAM; command errors never echo stderr or arguments."""
    args, timeout = supervised_command(args, timeout)
    process = subprocess.Popen(args, stdin=subprocess.PIPE if input_bytes else subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL if quiet else subprocess.PIPE,
                               stderr=subprocess.DEVNULL, env=env, start_new_session=True)
    output, overflow = bytearray(), threading.Event()

    def read():
        if quiet:
            return
        while True:
            block = process.stdout.read(65536)
            if not block:
                break
            remaining = limit + 1 - len(output)
            if remaining > 0:
                output.extend(block[:remaining])
            if len(output) > limit:
                overflow.set()

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    if input_bytes:
        try:
            process.stdin.write(input_bytes)
            process.stdin.close()
        except BrokenPipeError:
            pass
    end = time.monotonic() + timeout
    while process.poll() is None and not overflow.is_set() and time.monotonic() < end:
        time.sleep(0.05)
    stopped_early = process.poll() is None
    if stopped_early:
        # sudo's child may be root-owned. Only target this command's newly
        # created process group; never search for or kill global package tools.
        if args[0] == "sudo":
            cleanup = subprocess.run(["sudo", "-n", "/bin/kill", "-KILL", "--", f"-{process.pid}"],
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10)
            if cleanup.returncode != 0 and process.poll() is None:
                raise SmokeError(code + "_uncertain_package_operation", diagnostic="Owned package command cleanup failed; disposable VM teardown is required.")
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    try:
        result = process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        raise SmokeError(code + "_uncertain_command_operation") from None
    reader.join(timeout=5)
    if not reader.is_alive() and process.stdout:
        process.stdout.close()
    require(not reader.is_alive() and not overflow.is_set(), "bounded_command_output_exceeded")
    require(not stopped_early, code + "_timeout")
    if result != 0:
        raise SmokeError(code, result)
    return bytes(output)


def verified_deb(folder):
    manifest = folder / "SHA256SUMS-Linux-X64.txt"
    require(manifest.is_file() and not manifest.is_symlink() and manifest.stat().st_size <= 65536, "checksum_manifest_required")
    hashes = {}
    for line in manifest.read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.+-]+)", line)
        require(match is not None, "checksum_manifest_invalid")
        digest, name = match.groups()
        require(name not in hashes and name not in {".", ".."}, "checksum_manifest_duplicate_or_traversal")
        hashes[name] = digest
    candidates = list(folder.glob("*.deb"))
    require(len(candidates) == 1, "exactly_one_deb_required")
    deb = candidates[0]
    require(deb.is_file() and not deb.is_symlink() and deb.stat().st_size <= 128 * 1024 * 1024, "bounded_regular_deb_required")
    digest = hashlib.sha256()
    with deb.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    require(hashes.get(deb.name) == digest.hexdigest(), "deb_checksum_mismatch")
    return deb, digest.hexdigest()


def tar_name(name):
    path = PurePosixPath(name)
    require(not path.is_absolute() and ".." not in path.parts, "package_path_traversal_refused")
    return path.as_posix().removeprefix("./")


def inspect_control(encoded):
    """DevDrop needs no privileged maintainer scripts or global configuration."""
    fields = None
    with tarfile.open(fileobj=io.BytesIO(encoded)) as archive:
        entries = archive.getmembers()
        require(len(entries) <= 16, "control_archive_budget_exceeded")
        for entry in entries:
            name = tar_name(entry.name)
            if entry.isdir() and name == ".":
                continue
            require(entry.isfile() and name in {"control", "md5sums"}, "maintainer_hooks_or_unknown_control_refused")
            require(entry.size <= 65536, "control_file_budget_exceeded")
            if name == "control":
                require(fields is None, "duplicate_package_control")
                text = archive.extractfile(entry).read().decode("utf-8")
                fields = {}
                previous = None
                for line in text.splitlines():
                    if not line:
                        continue
                    if line[0].isspace():
                        require(previous is not None, "invalid_control_continuation")
                        fields[previous] += " " + line.strip()
                        continue
                    require(":" in line, "invalid_package_control")
                    key, value = line.split(":", 1)
                    require(key not in fields, "duplicate_control_field")
                    fields[key] = value.strip()
                    previous = key
    require(fields is not None and fields.get("Package") in PACKAGES, "own_package_only")
    require(fields.get("Architecture") == "amd64", "amd64_package_required")
    require(re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,64}", fields.get("Version", "")) is not None, "invalid_package_version")
    for name in ("Pre-Depends", "Conflicts", "Breaks", "Replaces", "Provides", "Essential", "Protected"):
        require(not fields.get(name), "package_system_changes_refused")
    for dependency in fields.get("Depends", "").split(","):
        for alternative in dependency.split("|"):
            name = alternative.strip().split(" ", 1)[0]
            require(not name or re.fullmatch(r"lib[a-z0-9+.-]+", name) is not None, "non_library_runtime_dependency_refused")
    return {key: fields[key] for key in ("Package", "Version", "Architecture")}


def inspect_payload(encoded, package):
    seen_binary, files = False, 0
    with tarfile.open(fileobj=io.BytesIO(encoded)) as archive:
        entries = archive.getmembers()
        require(len(entries) <= 2000, "package_entry_budget_exceeded")
        directories = {"."}
        for entry in entries:
            if entry.isfile():
                directories.update(str(parent) for parent in PurePosixPath(tar_name(entry.name)).parents)
        private_roots = (f"usr/lib/{package}", f"usr/share/doc/{package}")
        for entry in entries:
            name = tar_name(entry.name)
            require(not entry.mode & 0o7022 and entry.uid == 0 and entry.gid == 0, "unsafe_package_permissions_or_ownership")
            if entry.isdir():
                private = any(name == root or name.startswith(root + "/") for root in private_roots)
                require(name in directories or private, "package_directory_outside_own_app")
                if not private:
                    require(entry.mode & 0o7777 == 0o755, "shared_package_directory_mode_refused")
                continue
            require(entry.isfile(), "package_links_or_special_files_refused")
            allowed = name == "usr/bin/devdrop-desktop"
            allowed |= bool(re.fullmatch(r"usr/share/applications/(?:DevDrop|devdrop|devdrop-desktop)\.desktop", name))
            allowed |= bool(re.fullmatch(r"usr/share/icons/hicolor/[0-9]+x[0-9]+(?:@2)?/apps/(?:DevDrop|devdrop|devdrop-desktop)\.(?:png|svg)", name))
            allowed |= name.startswith(f"usr/share/doc/{package}/")
            allowed |= name.startswith(f"usr/lib/{package}/")
            allowed |= name == "usr/share/metainfo/com.devdrop.app.metainfo.xml"
            require(allowed, "package_file_outside_own_app")
            if name == "usr/bin/devdrop-desktop":
                require(entry.mode & 0o111 and entry.size > 0 and not seen_binary, "invalid_or_duplicate_app_binary")
                seen_binary = True
            if name.endswith(".desktop"):
                require(entry.size <= 8192, "desktop_entry_budget_exceeded")
                text = archive.extractfile(entry).read().decode("utf-8")
                commands = [line[5:] for line in text.splitlines() if line.startswith("Exec=")]
                require(len(commands) == 1 and re.fullmatch(r"(?:/usr/bin/)?devdrop-desktop(?: %[fFuU])?", commands[0]), "unexpected_desktop_command")
            files += 1
    require(seen_binary, "app_binary_missing")
    return files


def isolated_env(scratch, display, authority):
    # Preserve HOME exactly; never pass CI/cloud credentials to the application.
    env = {"PATH": "/usr/bin:/bin", "HOME": os.environ["HOME"], "LANG": "C.UTF-8",
           "DISPLAY": display, "XAUTHORITY": str(authority), "GDK_BACKEND": "x11"}
    for key, directory in (("XDG_DATA_HOME", "data"), ("XDG_CONFIG_HOME", "config"),
                           ("XDG_CACHE_HOME", "cache"), ("XDG_RUNTIME_DIR", "runtime")):
        path = scratch / directory
        path.mkdir(mode=0o700)
        env[key] = str(path)
    return env


def stop_group(process):
    if process is None:
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=4)


def installed(package):
    result = subprocess.run(["dpkg-query", "-W", "-f=${db:Status-Status}", package],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
    return result.returncode == 0 and result.stdout.strip() not in {b"", b"not-installed"}


def empty_state(path):
    require(path.is_file() and not path.is_symlink(), "appdata_database_missing")
    with sqlite3.connect("file:" + quote(str(path), safe="/") + "?mode=ro", uri=True, timeout=0.2) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("PRAGMA trusted_schema=OFF")
        require(db.execute("SELECT version FROM schema_version").fetchall() == [(3,)], "unexpected_appdata_schema")
        require(db.execute("SELECT count(*) FROM pairs").fetchone() == (0,), "nonempty_project_registry")
        require(db.execute("SELECT count(*) FROM plans").fetchone() == (0,), "unexpected_sync_plan")


def mapped_window(env, pid):
    tree = command(["xwininfo", "-root", "-tree"], "window_tree_query_failed", env=env).decode("utf-8", "replace")
    matches = re.findall(r'^\s*(0x[0-9a-fA-F]+) "DevDrop"', tree, re.MULTILINE)
    for window in matches:
        info = command(["xwininfo", "-id", window], "window_query_failed", env=env).decode("utf-8", "replace")
        prop = command(["xprop", "-id", window, "_NET_WM_PID"], "window_pid_query_failed", env=env).decode("utf-8", "replace")
        match = re.search(r"_NET_WM_PID\(CARDINAL\) = ([0-9]+)", prop)
        if "Map State: IsViewable" in info and match and int(match.group(1)) == pid:
            return window
    return None


def app_diagnostic(stderr):
    for text in (
        "bwrap: Creating new namespace failed: Operation not permitted",
        "bwrap: No permissions to create new namespace",
        "bwrap: setting up uid map: Permission denied",
        "Running as root without --no-sandbox is not supported",
        "Failed to set up the sandbox",
    ):
        if text.encode() in stderr:
            return text
    return None


def smoke(context):
    report = {"schema": SCHEMA, "commit": context["commit"], "workflow_run_id": context["run_id"],
              "job_id": context["job_id"], "status": "failed", "checks": [],
              "baseline": "fresh-disposable-github-hosted-vm-with-runtime-dependencies",
              "topology": {"host_os": "linux", "architecture": "x86_64", "distribution": "ubuntu", "version": "22.04"},
              "sandbox_disabled": False, "projects_registered": 0}
    stage, package, attempted = "validate_package", None, False
    app = xserver = bus = None
    stderr, reader = bytearray(), None
    temporary = tempfile.TemporaryDirectory(prefix="devdrop-runtime-", dir=context["root"])
    scratch = Path(temporary.name)
    os.chmod(scratch, 0o700)
    cleanup_errors = []
    try:
        deb, digest = verified_deb(context["artifact"])
        control = command(["dpkg-deb", "--ctrl-tarfile", str(deb)], "control_inspection_failed", limit=1024 * 1024)
        metadata = inspect_control(control)
        package = metadata["Package"]
        payload = command(["dpkg-deb", "--fsys-tarfile", str(deb)], "payload_inspection_failed", limit=128 * 1024 * 1024)
        files = inspect_payload(payload, package)
        del payload
        require(not APP.exists() and not any(installed(name) for name in PACKAGES), "preexisting_app_refused")
        report["package"] = {"name": package, "version": metadata["Version"], "architecture": metadata["Architecture"], "sha256": digest, "files_inspected": files, "maintainer_hooks": "absent"}
        report["checks"].append({"name": "package_checksum_identity_and_payload_verified", "passed": True})
        stage = "install_runtime_dependencies"
        command(["sudo", "-n", "apt-get", "update"], "official_apt_update_failed", timeout=300, quiet=True)
        command(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "--no-install-recommends", "-y", "xvfb", "xauth", "x11-utils", "dbus-x11"], "official_runtime_dependencies_failed", timeout=300, quiet=True)
        stage, attempted = "install_own_package", True
        command(["sudo", "-n", "env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "install", "--no-install-recommends", "-y", str(deb)], "own_package_install_failed", timeout=300, quiet=True)
        require(installed(package) and APP.is_file() and not APP.is_symlink(), "installed_app_binary_missing")
        report["checks"].append({"name": "own_package_installed", "passed": True})
        stage = "start_isolated_display"
        display = next((f":{n}" for n in range(150, 200) if not Path(f"/tmp/.X{n}-lock").exists() and not Path(f"/tmp/.X11-unix/X{n}").exists()), None)
        require(display is not None, "unused_display_required")
        authority = scratch / "Xauthority"
        authority.touch(mode=0o600)
        env = isolated_env(scratch, display, authority)
        command(["xauth", "-f", str(authority), "source", "-"], "temporary_xauth_failed", env=env,
                input_bytes=f"add {display} . {secrets.token_hex(16)}\n".encode())
        xserver = subprocess.Popen(["Xvfb", display, "-screen", "0", "1280x900x24", "-nolisten", "tcp", "-auth", str(authority)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            require(xserver.poll() is None, "isolated_xserver_exited")
            try:
                command(["xwininfo", "-root"], "display_not_ready", env=env, timeout=2)
                break
            except SmokeError:
                time.sleep(0.2)
        else:
            raise SmokeError("isolated_display_start_timeout")
        stage = "start_private_dbus_session"
        address = f"unix:path={scratch / 'session-bus'}"
        bus = subprocess.Popen(["dbus-daemon", "--session", "--nofork", "--address=" + address],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env=env, start_new_session=True)
        deadline = time.monotonic() + 10
        while not (scratch / "session-bus").exists() and time.monotonic() < deadline:
            require(bus.poll() is None, "private_dbus_exited")
            time.sleep(0.1)
        require((scratch / "session-bus").exists(), "private_dbus_start_timeout")
        env["DBUS_SESSION_BUS_ADDRESS"] = address
        cwd = scratch / "cwd"
        cwd.mkdir(mode=0o700)
        stage = "launch_packaged_app"
        app = subprocess.Popen([str(APP)], cwd=cwd, env=env, stdout=subprocess.DEVNULL,
                               stderr=subprocess.PIPE, start_new_session=True)

        def drain_stderr():
            for block in iter(lambda: os.read(app.stderr.fileno(), 4096), b""):
                if len(stderr) < 16384:
                    stderr.extend(block[:16384 - len(stderr)])

        reader = threading.Thread(target=drain_stderr, daemon=True)
        reader.start()
        database = Path(env["XDG_DATA_HOME"]) / "com.devdrop.app/local/metadata.sqlite3"
        deadline, window, state_ready = time.monotonic() + 60, None, False
        while time.monotonic() < deadline:
            if app.poll() is not None:
                raise SmokeError("packaged_app_exited_before_acceptance", app.returncode, app_diagnostic(stderr))
            window = mapped_window(env, app.pid)
            if window and database.is_file():
                try:
                    empty_state(database)
                    state_ready = True
                    break
                except sqlite3.OperationalError:
                    pass  # The frontend may still be committing its first schema.
                except SmokeError as error:
                    if error.code != "unexpected_appdata_schema":
                        raise
            time.sleep(0.25)
        if not window or not state_ready:
            raise SmokeError("mapped_window_or_frontend_database_timeout", diagnostic=app_diagnostic(stderr))
        stage = "observe_stable_window_and_empty_state"
        start = time.monotonic()
        while time.monotonic() - start < 5:
            require(app.poll() is None and Path(f"/proc/{app.pid}/exe").resolve() == APP, "app_pid_not_stable")
            require(mapped_window(env, app.pid) == window, "app_window_not_stable")
            empty_state(database)
            time.sleep(0.5)
        report["checks"].extend([{"name": "mapped_devdrop_window_and_stable_pid_at_least_5_seconds", "passed": True},
                                 {"name": "frontend_ipc_created_schema3_empty_pairs_and_plans", "passed": True},
                                 {"name": "isolated_xdg_cwd_and_authenticated_x11_without_tcp", "passed": True}])
        report["observed"] = {"window_title": "DevDrop", "map_state": "IsViewable", "stable_seconds_minimum": 5,
                              "sqlite_schema": 3, "pairs": 0, "plans": 0}
        report["status"] = "passed"
    except SmokeError as error:
        report["failure"] = {"stage": stage, "code": error.code, "exit_code": error.exit_code, "diagnostic": error.diagnostic}
    except Exception as error:
        report["failure"] = {"stage": stage, "code": "unexpected_smoke_failure", "exception_type": type(error).__name__}
    finally:
        for name, process in (("app", app), ("dbus", bus), ("xvfb", xserver)):
            try:
                stop_group(process)
            except Exception:
                cleanup_errors.append(name + "_stop_failed")
        if reader:
            reader.join(timeout=2)
            if reader.is_alive():
                cleanup_errors.append("app_stderr_reader_cleanup_failed")
            else:
                app.stderr.close()
        if attempted and package:
            try:
                command(["sudo", "-n", "dpkg", "--remove", package], "own_package_remove_failed", timeout=120, quiet=True)
                require(not installed(package) and not APP.exists(), "own_package_removal_not_verified")
                report["checks"].append({"name": "own_package_uninstalled_and_binary_absent", "passed": True})
            except Exception:
                cleanup_errors.append("own_package_removal_failed")
        try:
            temporary.cleanup()
            require(not scratch.exists(), "scratch_cleanup_failed")
            report["checks"].append({"name": "temporary_xauth_xdg_and_cwd_removed", "passed": True})
        except Exception:
            cleanup_errors.append("scratch_cleanup_failed")
        report["cleanup_errors"] = cleanup_errors
        if cleanup_errors:
            report["status"] = "failed"
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        context = ci_context(args.artifact_dir, args.report)
    except Exception as error:
        code = error.code if isinstance(error, SmokeError) else "ci_guard_failed"
        print("LINUX_RUNTIME_EVIDENCE=" + json.dumps({"schema": SCHEMA, "status": "failed", "failure": {"stage": "ci_guard", "code": code}}))
        return 1
    report = smoke(context)
    try:
        with context["report"].open("x") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(report, indent=2) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
    except OSError:
        report["status"] = "failed"
        report["failure"] = {"stage": "report", "code": "exclusive_report_write_failed"}
    print("LINUX_RUNTIME_EVIDENCE=" + json.dumps(report, sort_keys=True))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
