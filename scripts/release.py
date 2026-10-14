"""Build Linux release archives and a clean GitHub source ZIP (Python 3.10+)."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parent.parent
SOURCE_FILES = (
    ".gitignore", ".dockerignore", ".env.example", "README.md", "LICENSE",
    "go.mod", "go.sum", "Dockerfile", "compose.yaml", "compose.build.yaml",
    "web/package.json", "web/package-lock.json", "web/index.html",
    "web/tsconfig.json", "web/vite.config.ts", "web/playwright.config.ts",
)
SOURCE_DIRS = ("cmd", "internal", "web/src", "web/public", "web/tests", "docs", "deploy", "scripts", ".github")


def run(args, **kwargs):
    print("+", " ".join(map(str, args)), flush=True)
    subprocess.run(args, check=True, cwd=ROOT, **kwargs)


def public_sources():
    for name in SOURCE_FILES:
        yield ROOT / name
    for name in SOURCE_DIRS:
        for path in sorted((ROOT / name).rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts:
                yield path


def checksums(output):
    entries = []
    for path in sorted(output.iterdir()):
        if path.is_file() and path.name != "checksums.txt":
            with path.open("rb") as stream:
                digest = hashlib.sha256()
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
            entries.append(f"{digest.hexdigest()}  {path.name}\n")
    (output / "checksums.txt").write_text("".join(entries), encoding="utf-8", newline="\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", default="v0.1.0")
    parser.add_argument("--arch", choices=("amd64", "arm64", "all"), default="all")
    parser.add_argument("--skip-frontend", action="store_true", help="reuse an existing web/dist build")
    args = parser.parse_args()
    if not re.fullmatch(r"v\d+\.\d+\.\d+(?:-[A-Za-z0-9.-]+)?", args.version):
        parser.error("version must be vMAJOR.MINOR.PATCH with an optional prerelease suffix")
    output = ROOT / "dist" / args.version
    output.mkdir(parents=True, exist_ok=True)
    if not args.skip_frontend:
        npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
        if not npm:
            parser.error("Node.js 22 and npm are required")
        run([npm, "--prefix", "web", "ci"])
        run([npm, "--prefix", "web", "run", "build"])
    if not (ROOT / "web/dist/index.html").is_file():
        parser.error("web/dist is missing; build the frontend first")
    for arch in (("amd64", "arm64") if args.arch == "all" else (args.arch,)):
        name = f"web-console_{args.version}_linux_{arch}"
        stage = ROOT / ".build" / "release" / args.version / arch / name
        stage.mkdir(parents=True, exist_ok=True)
        env = dict(os.environ, CGO_ENABLED="0", GOOS="linux", GOARCH=arch)
        run(["go", "build", "-trimpath", "-buildvcs=false", "-ldflags",
             f"-s -w -X main.version={args.version}", "-o", str(stage / "web-console"),
             "./cmd/web-console"], env=env)
        for filename in ("README.md", "LICENSE", ".env.example"):
            shutil.copy2(ROOT / filename, stage / filename)
        for directory in ("docs", "deploy", "web/dist"):
            shutil.copytree(ROOT / directory, stage / directory, dirs_exist_ok=True)

        def metadata(info):
            info.uid = info.gid = info.mtime = 0
            info.uname = info.gname = ""
            info.mode = 0o755 if info.isdir() or info.name == f"{name}/web-console" else 0o644
            return info

        with tarfile.open(output / f"{name}.tar.gz", "w:gz") as archive:
            archive.add(stage, arcname=name, filter=metadata)
    with zipfile.ZipFile(output / f"web-console_{args.version}_source.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in public_sources():
            archive.write(path, f"web-console/{path.relative_to(ROOT).as_posix()}")
    checksums(output)
    print(f"Release files: {output}")


if __name__ == "__main__":
    main()
