import json
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_local_compose_keeps_security_boundaries_and_healthcheck() -> None:
    compose = (ROOT / "compose.yaml").read_text("utf-8")

    assert '"${DIF_BIND_ADDRESS:-127.0.0.1}:${DIF_PORT:-8000}:8000"' in compose
    assert compose.count("read_only: true") == 2
    assert compose.count("cap_drop: [ALL]") == 2
    assert compose.count("security_opt: [no-new-privileges:true]") == 2
    assert "network_mode: none" in compose
    assert "healthcheck:" in compose
    assert "condition: service_healthy" in compose

    offline = (ROOT / "deploy/offline-compose.yaml").read_text("utf-8")
    assert "build:" not in offline
    assert offline.count("pull_policy: never") == 2
    assert offline.count("read_only: true") == 2
    assert offline.count("cap_drop: [ALL]") == 2
    assert "network_mode: none" in offline


def test_plugin_manifest_is_closed_and_version_matches_python_package() -> None:
    manifest = json.loads(
        (ROOT / "plugins/document-injection-firewall/.codex-plugin/plugin.json").read_text("utf-8")
    )
    pyproject = (ROOT / "pyproject.toml").read_text("utf-8")

    assert manifest["name"] == "document-injection-firewall"
    assert manifest["interface"]["displayName"] == "Parsewall"
    assert f'version = "{manifest["version"]}"' in pyproject
    assert manifest["skills"] == "./skills/"
    assert manifest["mcpServers"] == "./.mcp.json"
    assert "apps" not in manifest


def test_repository_is_a_codex_marketplace_for_the_parsewall_plugin() -> None:
    marketplace = json.loads(
        (ROOT / ".agents/plugins/marketplace.json").read_text("utf-8")
    )

    assert marketplace["name"] == "parsewall"
    assert marketplace["interface"]["displayName"] == "Parsewall"
    assert marketplace["plugins"] == [
        {
            "name": "document-injection-firewall",
            "source": {
                "source": "local",
                "path": "./plugins/document-injection-firewall",
            },
            "policy": {
                "installation": "AVAILABLE",
                "authentication": "ON_INSTALL",
            },
            "category": "Developer Tools",
        }
    ]


def test_python_distribution_uses_parsewall_brand_with_compatibility_scripts() -> None:
    pyproject = (ROOT / "pyproject.toml").read_text("utf-8")

    assert 'name = "parsewall"' in pyproject
    assert 'Homepage = "https://github.com/gogooma125732/parsewall"' in pyproject
    assert 'parsewall = "injection_firewall.cli:main"' in pyproject
    assert 'document-firewall = "injection_firewall.cli:main"' in pyproject


def test_compose_release_archive_contains_one_command_installer(tmp_path: Path) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_release.py"),
            "--output",
            str(tmp_path),
            "--channel",
            "compose",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    archive_path = next((tmp_path / "0.1.0").glob("*-compose.tar.gz"))
    with tarfile.open(archive_path, "r:gz") as archive:
        names = set(archive.getnames())
    prefix = "document-injection-firewall-0.1.0"
    assert f"{prefix}/compose.yaml" in names
    assert f"{prefix}/scripts/install-local.sh" in names
    assert f"{prefix}/scripts/verify-local.sh" in names
    assert f"{prefix}/src/injection_firewall/api.py" in names
    assert f"{prefix}/assets/parsewall-logo.png" in names


def test_codex_release_contains_plugin_hook_mcp_and_marketplace_policy(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts/build_release.py"),
            "--output",
            str(tmp_path),
            "--channel",
            "plugin",
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    output = tmp_path / "0.1.0"
    plugin_path = next(output.glob("*-codex-plugin-*.zip"))
    marketplace_path = next(output.glob("*-codex-marketplace-*.zip"))

    with zipfile.ZipFile(plugin_path) as archive:
        names = set(archive.namelist())
    prefix = "document-injection-firewall"
    assert f"{prefix}/.codex-plugin/plugin.json" in names
    assert f"{prefix}/.mcp.json" in names
    assert f"{prefix}/hooks/hooks.json" in names
    assert f"{prefix}/skills/inspect-untrusted-files/SKILL.md" in names
    assert not any("__pycache__" in name or name.endswith(".pyc") for name in names)

    with zipfile.ZipFile(marketplace_path) as archive:
        manifest = json.loads(
            archive.read("parsewall-marketplace/marketplace.json")
        )
    assert marketplace_path.name == "parsewall-codex-marketplace-0.1.0.zip"
    assert plugin_path.name == "parsewall-codex-plugin-0.1.0.zip"
    assert manifest["name"] == "parsewall-local"
    entry = manifest["plugins"][0]
    assert entry["source"] == {
        "source": "local",
        "path": "./plugins/document-injection-firewall",
    }
    assert entry["policy"] == {
        "installation": "AVAILABLE",
        "authentication": "ON_INSTALL",
    }
    assert entry["category"] == "Developer Tools"
