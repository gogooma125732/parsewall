#!/usr/bin/env python3
"""Build versioned local, offline, Python, and Codex release artifacts."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT = ROOT / "dist" / "releases"


def project_version() -> str:
    with (ROOT / "pyproject.toml").open("rb") as stream:
        return str(tomllib.load(stream)["project"]["version"])


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _tar_filter(info: tarfile.TarInfo) -> tarfile.TarInfo | None:
    parts = Path(info.name).parts
    if "__pycache__" in parts or info.name.endswith((".pyc", ".DS_Store")):
        return None
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    return info


def _add_tar_sources(
    archive: tarfile.TarFile, sources: tuple[Path, ...], prefix: str
) -> None:
    for source in sources:
        archive.add(
            source,
            arcname=str(Path(prefix) / source.relative_to(ROOT)),
            recursive=True,
            filter=_tar_filter,
        )


def build_compose(output: Path, version: str) -> Path:
    destination = output / f"document-injection-firewall-{version}-compose.tar.gz"
    prefix = f"document-injection-firewall-{version}"
    sources = (
        ROOT / ".dockerignore",
        ROOT / ".env.example",
        ROOT / "Dockerfile",
        ROOT / "README.md",
        ROOT / "assets",
        ROOT / "compose.yaml",
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
        ROOT / "src",
        ROOT / "deploy" / "LOCAL_INSTALL.md",
        ROOT / "scripts" / "install-local.sh",
        ROOT / "scripts" / "verify-local.sh",
        ROOT / "scripts" / "uninstall-local.sh",
    )
    with tarfile.open(destination, "w:gz", format=tarfile.PAX_FORMAT) as archive:
        _add_tar_sources(archive, sources, prefix)
    return destination


def _docker_platform(image: str) -> tuple[str, str]:
    completed = subprocess.run(
        ["docker", "image", "inspect", image, "--format", "{{.Os}} {{.Architecture}}"],
        check=True,
        capture_output=True,
        text=True,
    )
    operating_system, architecture = completed.stdout.strip().split()
    return operating_system, architecture


def _save_image(image: str, destination: Path) -> None:
    process = subprocess.Popen(["docker", "image", "save", image], stdout=subprocess.PIPE)
    if process.stdout is None:
        raise RuntimeError("docker image stream unavailable")
    try:
        with destination.open("wb") as raw, gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0
        ) as compressed:
            shutil.copyfileobj(process.stdout, compressed, length=1024 * 1024)
    finally:
        process.stdout.close()
    if process.wait() != 0:
        destination.unlink(missing_ok=True)
        raise subprocess.CalledProcessError(process.returncode, process.args)


def _write_checksums(directory: Path, names: tuple[str, ...]) -> None:
    contents = "".join(f"{sha256(directory / name)}  {name}\n" for name in sorted(names))
    (directory / "SHA256SUMS").write_text(contents, encoding="ascii")


def build_offline(output: Path, version: str) -> Path:
    image = f"document-injection-firewall:{version}"
    operating_system, architecture = _docker_platform(image)
    platform = f"{operating_system}-{architecture}"
    destination = output / f"document-injection-firewall-{version}-offline-{platform}.tar"

    with tempfile.TemporaryDirectory(prefix="dif-offline-") as temporary:
        bundle = Path(temporary) / f"document-injection-firewall-{version}-offline-{platform}"
        bundle.mkdir(mode=0o700)
        shutil.copy2(ROOT / "deploy" / "offline-compose.yaml", bundle / "compose.yaml")
        shutil.copy2(ROOT / "deploy" / "OFFLINE_INSTALL.md", bundle / "README.md")
        for source, name in (
            (ROOT / "scripts" / "install-offline.sh", "install.sh"),
            (ROOT / "scripts" / "verify-offline.sh", "verify.sh"),
            (ROOT / "scripts" / "uninstall-offline.sh", "uninstall.sh"),
        ):
            shutil.copy2(source, bundle / name)
        (bundle / ".env").write_text(
            "DIF_BIND_ADDRESS=127.0.0.1\n"
            "DIF_PORT=8000\n"
            f"DIF_IMAGE={image}\n",
            encoding="ascii",
        )
        _save_image(image, bundle / "image.tar.gz")
        checked = (".env", "README.md", "compose.yaml", "image.tar.gz", "install.sh", "uninstall.sh", "verify.sh")
        _write_checksums(bundle, checked)
        with tarfile.open(destination, "w", format=tarfile.PAX_FORMAT) as archive:
            archive.add(bundle, arcname=bundle.name, recursive=True, filter=_tar_filter)
    return destination


def build_python(output: Path, _version: str) -> tuple[Path, ...]:
    destination = output / "python"
    destination.mkdir(mode=0o755, exist_ok=True)
    subprocess.run(
        ["uv", "build", "--wheel", "--sdist", "--out-dir", str(destination)],
        cwd=ROOT,
        check=True,
    )
    (destination / ".gitignore").unlink(missing_ok=True)
    shutil.copy2(ROOT / "deploy" / "PYTHON_CLI.md", destination / "README.md")
    return tuple(sorted(path for path in destination.iterdir() if path.is_file()))


def _zip_tree(source: Path, destination: Path, prefix: Path) -> None:
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(source.rglob("*")):
            if path.is_dir() or "__pycache__" in path.parts or path.suffix == ".pyc":
                continue
            info = zipfile.ZipInfo.from_file(path, arcname=str(prefix / path.relative_to(source)))
            info.date_time = (1980, 1, 1, 0, 0, 0)
            info.external_attr = (path.stat().st_mode & 0xFFFF) << 16
            archive.writestr(info, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED)


def build_plugin(output: Path, version: str) -> tuple[Path, Path]:
    plugin = ROOT / "plugins" / "document-injection-firewall"
    plugin_archive = output / f"document-injection-firewall-codex-plugin-{version}.zip"
    _zip_tree(plugin, plugin_archive, Path(plugin.name))

    marketplace_archive = output / f"document-injection-firewall-codex-marketplace-{version}.zip"
    with tempfile.TemporaryDirectory(prefix="dif-marketplace-") as temporary:
        marketplace = Path(temporary) / "document-injection-firewall-marketplace"
        shutil.copytree(plugin, marketplace / "plugins" / plugin.name, ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
        manifest = {
            "name": "document-injection-firewall-local",
            "interface": {"displayName": "Parsewall Local"},
            "plugins": [
                {
                    "name": plugin.name,
                    "source": {"source": "local", "path": f"./plugins/{plugin.name}"},
                    "policy": {"installation": "AVAILABLE", "authentication": "ON_INSTALL"},
                    "category": "Developer Tools",
                }
            ],
        }
        (marketplace / "marketplace.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        shutil.copy2(ROOT / "deploy" / "CODEX_PLUGIN.md", marketplace / "README.md")
        _zip_tree(marketplace, marketplace_archive, Path(marketplace.name))
    return plugin_archive, marketplace_archive


def write_manifest(output: Path, version: str) -> None:
    artifacts = []
    for path in sorted(output.rglob("*")):
        if not path.is_file() or path.name in {"release-manifest.json", "SHA256SUMS"}:
            continue
        artifacts.append(
            {
                "path": str(path.relative_to(output)),
                "sha256": sha256(path),
                "size": path.stat().st_size,
            }
        )
    manifest = {"name": "document-injection-firewall", "version": version, "artifacts": artifacts}
    (output / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    checksum_names = tuple(
        path.name
        for path in output.iterdir()
        if path.is_file() and path.name != "SHA256SUMS"
    )
    _write_checksums(output, checksum_names)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--channel", choices=("compose", "offline", "python", "plugin", "all"), default="all"
    )
    parser.add_argument("--clean", action="store_true")
    args = parser.parse_args()
    version = project_version()
    output = args.output.resolve() / version
    if args.clean and output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True, mode=0o755, exist_ok=True)

    channels = ("compose", "offline", "python", "plugin") if args.channel == "all" else (args.channel,)
    for channel in channels:
        if channel == "compose":
            build_compose(output, version)
        elif channel == "offline":
            build_offline(output, version)
        elif channel == "python":
            build_python(output, version)
        elif channel == "plugin":
            build_plugin(output, version)
    write_manifest(output, version)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
