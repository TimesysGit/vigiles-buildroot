##########################################################################
#
# normalize.py - Collect and normalize child CycloneDX SBOMs
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import re
import shutil
import tempfile

try:
    from utils import info
except ModuleNotFoundError:
    from scripts.utils import info

from .constants import NORMALIZED_VERSION
from .errors import ChildSbomError, CycloneDxCliError
from .utils import (
    convert_sbom,
    cyclonedx_version,
    load_cyclonedx_json,
    resolve_cyclonedx_cli,
    resolve_path,
    root_component_name,
    validate_sbom,
)


@dataclass(frozen=True)
class ChildSbom:
    """Describe a validated child SBOM before normalization."""

    source_id: str
    path: Path
    version: str
    root_component_name: str
    sha256: str


@dataclass(frozen=True)
class NormalizedChildSbom:
    """Describe a child SBOM normalized to the workflow version."""

    source_id: str
    original_path: Path
    normalized_path: Path
    original_version: str
    root_component_name: str
    sha256: str


def _sha256(path):
    """Return the SHA-256 digest of a child SBOM file."""
    digest = hashlib.sha256()
    try:
        with path.open("rb") as input_file:
            for block in iter(lambda: input_file.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise ChildSbomError(f"Could not read child SBOM {path}: {exc}") from exc
    return digest.hexdigest()


def _source_id(root_component_name, sha256):
    """Build a reproducible source identifier from a subject and digest."""
    safe_name = re.sub(r"[^A-Za-z0-9._-]+", "-", root_component_name)
    safe_name = safe_name.strip(".-_") or "child"
    return f"{safe_name[:63]}-{sha256}"


def expand_child_sbom_paths(arguments):
    """Expand CLI and menuconfig child path values into a flat list."""
    if not arguments:
        return []
    if not isinstance(arguments, (list, tuple)):
        raise ChildSbomError("Child SBOM arguments must be a list of paths")

    paths = []
    for argument in arguments:
        if not isinstance(argument, str):
            raise ChildSbomError("Each child SBOM path must be a string")
        entries = argument.split(",")
        if any(not entry.strip() for entry in entries):
            raise ChildSbomError("Child SBOM paths contain an empty entry")
        paths.extend(entry.strip() for entry in entries)
    return paths


def _collect_child_sboms(vgls):
    """Preflight configured child SBOMs and discard exact duplicates."""
    configured_paths = vgls.get("child_sboms", [])
    if not configured_paths:
        return []
    if not isinstance(configured_paths, (list, tuple)):
        raise ChildSbomError("Child SBOM paths must be provided as a list")
    if any(
        not isinstance(entry, str) or not entry.strip()
        for entry in configured_paths
    ):
        raise ChildSbomError("Each child SBOM path must be a non-empty string")

    base_path = Path(vgls.get("topdir") or Path.cwd()).expanduser().resolve()
    children = []
    seen_paths = set()
    seen_source_ids = set()
    for entry in configured_paths:
        path = resolve_path(entry.strip(), base_path)
        if path in seen_paths:
            info(f"Ignoring duplicate child SBOM path: {path}")
            continue
        seen_paths.add(path)
        if not path.is_file():
            raise ChildSbomError(
                f"Child SBOM does not exist or is not a file: {path}"
            )

        sha256 = _sha256(path)
        document = load_cyclonedx_json(path, error_type=ChildSbomError)
        version = cyclonedx_version(
            document,
            path,
            error_type=ChildSbomError,
        )
        root_name = root_component_name(
            document,
            path,
            error_type=ChildSbomError,
        )
        source_id = _source_id(root_name, sha256)
        if source_id in seen_source_ids:
            info(
                "Ignoring duplicate child SBOM content for "
                f"metadata.component {root_name}: {path}"
            )
            continue
        seen_source_ids.add(source_id)

        children.append(ChildSbom(
            source_id=source_id,
            path=path,
            version=version,
            root_component_name=root_name,
            sha256=sha256,
        ))

    return sorted(children, key=lambda child: child.source_id)


def normalize_child_sboms(vgls, cli=None):
    """Validate and normalize configured child SBOMs to JSON 1.6."""
    children = _collect_child_sboms(vgls)
    if not children:
        return []

    if cli is None:
        cli = resolve_cyclonedx_cli(vgls.get("cyclonedx_cli", ""))

    output_dir = (
        Path(vgls["vdir"]) / "cyclonedx" / "normalized"
    ).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    normalized = []
    with tempfile.TemporaryDirectory(
        prefix=".normalize-",
        dir=output_dir,
    ) as work_dir:
        work_dir = Path(work_dir)
        staged_outputs = []
        for child in children:
            staged_path = work_dir / f"{child.source_id}.cdx.json"
            final_path = output_dir / staged_path.name

            validate_sbom(
                cli,
                child.path,
                child.version,
                f"Validating child SBOM {child.source_id}",
            )

            if child.version == NORMALIZED_VERSION:
                shutil.copyfile(child.path, staged_path)
            else:
                convert_sbom(cli, child.path, staged_path)

            if not staged_path.is_file():
                raise CycloneDxCliError(
                    "CycloneDX CLI did not create normalized output for "
                    f"{child.source_id}"
                )

            normalized_document = load_cyclonedx_json(
                staged_path,
                error_type=ChildSbomError,
            )
            normalized_version = cyclonedx_version(
                normalized_document,
                staged_path,
                error_type=ChildSbomError,
            )
            if normalized_version != NORMALIZED_VERSION:
                raise ChildSbomError(
                    f"Normalized child SBOM {child.source_id} is "
                    f"JSON {normalized_version}, expected JSON 1.6"
                )
            normalized_root_name = root_component_name(
                normalized_document,
                staged_path,
                error_type=ChildSbomError,
            )
            if normalized_root_name != child.root_component_name:
                raise ChildSbomError(
                    f"Normalized child SBOM {child.source_id} changed "
                    "metadata.component.name from "
                    f"{child.root_component_name} to {normalized_root_name}"
                )
            if child.version != NORMALIZED_VERSION:
                validate_sbom(
                    cli,
                    staged_path,
                    normalized_version,
                    f"Validating normalized child SBOM {child.source_id}",
                )

            staged_outputs.append((staged_path, final_path))
            normalized.append(NormalizedChildSbom(
                source_id=child.source_id,
                original_path=child.path,
                normalized_path=final_path,
                original_version=child.version,
                root_component_name=child.root_component_name,
                sha256=child.sha256,
            ))

        for staged_path, final_path in staged_outputs:
            os.replace(staged_path, final_path)

    for child in normalized:
        info(
            f"Normalized child SBOM {child.source_id} "
            f"(JSON {child.original_version}) to "
            f"{child.normalized_path}"
        )
    return normalized
