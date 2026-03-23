"""
CodeQL subprocess wrapper.

Responsibility: given a repo path or GitHub URL, run CodeQL to produce
a SARIF file, then call cryptobom-forge to produce a CBOM JSON.

This is a stub implementation — the core audit logic (parser, rule engine,
AI layer) works independently of this module. Wire in real CodeQL execution
once the rest of the pipeline is validated.

Design note: subprocess calls are intentionally simple. No async, no
streaming — CodeQL analysis is expected to take 30s–5min and we want
the user to see live output on stdout.
"""

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

CODEQL_QUERY_PACK = "codeql/python-queries"
SARIF_SUBDIR = "sarif"
CBOM_SUBDIR = "cbom"


class ScannerError(Exception):
    """Raised when CodeQL or cryptobom-forge fails or is not installed."""


def run_scan(
    repo_path: str,
    project_name: str,
    output_root: Path = Path("audits"),
    language: str = "python",
) -> Path:
    """
    Run CodeQL → cryptobom-forge on a local repository path.

    Returns:
        Path to the generated cbom.json file.

    Raises:
        ScannerError: if any step fails or required tools are missing.
    """
    _check_tool("codeql", "Install CodeQL CLI: https://github.com/github/codeql-cli-binaries")
    _check_tool("cryptobom", "Install cryptobom-forge: pip install cryptobom_forge-*.whl")

    sarif_dir = output_root / project_name / SARIF_SUBDIR
    cbom_dir = output_root / project_name / CBOM_SUBDIR
    sarif_dir.mkdir(parents=True, exist_ok=True)
    cbom_dir.mkdir(parents=True, exist_ok=True)

    sarif_path = sarif_dir / "results.sarif"
    cbom_path = cbom_dir / "cbom.json"

    logger.info("Running CodeQL analysis on %s ...", repo_path)
    _run_codeql(repo_path, sarif_path, language)

    logger.info("Generating CBOM from SARIF ...")
    _run_cryptobom_forge(sarif_path, cbom_path)

    logger.info("CBOM written to %s", cbom_path)
    return cbom_path


def _run_codeql(repo_path: str, sarif_path: Path, language: str) -> None:
    """
    Run CodeQL database create + analyze.

    Two-step process:
    1. codeql database create → builds a CodeQL DB from source
    2. codeql database analyze → runs queries → produces SARIF
    """
    db_path = sarif_path.parent / "codeql_db"

    _run_subprocess([
        "codeql", "database", "create",
        str(db_path),
        f"--language={language}",
        f"--source-root={repo_path}",
        "--overwrite",
    ], "CodeQL database create failed")

    _run_subprocess([
        "codeql", "database", "analyze",
        str(db_path),
        CODEQL_QUERY_PACK,
        "--format=sarifv2.1.0",
        f"--output={sarif_path}",
    ], "CodeQL database analyze failed")


def _run_cryptobom_forge(sarif_path: Path, cbom_path: Path) -> None:
    """Run cryptobom-forge to convert SARIF → CBOM JSON."""
    _run_subprocess([
        "cryptobom", "generate",
        str(sarif_path),
        "--output-file", str(cbom_path),
    ], "cryptobom-forge failed to generate CBOM")


def _run_subprocess(cmd: list[str], error_prefix: str) -> None:
    """Run a command, streaming output, raising ScannerError on failure."""
    logger.debug("Running: %s", " ".join(cmd))
    result = subprocess.run(cmd, capture_output=False)
    if result.returncode != 0:
        raise ScannerError(f"{error_prefix} (exit code {result.returncode})")


def _check_tool(name: str, install_hint: str) -> None:
    """Raise ScannerError if a CLI tool is not on PATH."""
    if shutil.which(name) is None:
        raise ScannerError(f"'{name}' not found on PATH. {install_hint}")
