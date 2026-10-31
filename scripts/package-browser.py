#!/usr/bin/env python3
"""Package only the compiled, browser-only DevDrop demo; never local state."""

import argparse
import hashlib
import json
from pathlib import Path
import zipfile


def package(build: Path, output: Path) -> None:
    build = build.resolve(strict=True)
    if not (build / "index.html").is_file():
        raise SystemExit("Build the desktop web assets before packaging.")
    files = sorted(path for path in build.rglob("*") if path.is_file())
    allowed = {".html", ".js", ".css", ".svg", ".png", ".ico", ".webp", ".woff", ".woff2"}
    for path in build.rglob("*"):
        if path.is_symlink() or (path.is_file() and path.suffix not in allowed):
            raise SystemExit("Refusing unexpected files or links in the web build.")
    output = output.absolute()
    if output == build or build in output.parents:
        raise SystemExit("Place the archive outside the build directory.")
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        path.relative_to(build).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in files
    }
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, path.relative_to(build).as_posix())
        archive.writestr("SHA256SUMS.json", json.dumps(manifest, indent=2) + "\n")
        archive.writestr(
            "README.txt",
            "DevDrop browser demo\n\n"
            "Serve index.html and assets over HTTPS using a static host.\n"
            "This browser demo uses disposable sample data. It cannot access or\n"
            "synchronize local project folders. Real sync runs in the local Rust\n"
            "desktop/CLI application and requires approval of a specific plan.\n"
            "No daemon, content store, credentials, or local state are included.\n",
        )
    print(f"Packaged {len(files)} browser assets: {output}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--build", type=Path, default=Path("apps/desktop/dist"))
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    package(arguments.build, arguments.output)
