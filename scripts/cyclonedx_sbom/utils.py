##########################################################################
#
# utils.py - Shared CycloneDX document and command helpers
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

from copy import deepcopy
import json
import os
from pathlib import Path
import shutil
import subprocess

from .constants import (
    CLI_TIMEOUT_SECONDS,
    COMMAND_ERROR_OUTPUT_MAX_CHARS,
    REFERENCE_ARRAY_FIELDS,
    SUPPORTED_INPUT_VERSIONS,
)
from .errors import CycloneDxCliError, CycloneDxDocumentError


def resolve_path(path, base=None):
    """Return an absolute normalized path, resolving relative paths to base."""
    resolved = Path(path).expanduser()
    if not resolved.is_absolute():
        resolved = (base or Path.cwd()) / resolved
    return resolved.resolve()


def load_cyclonedx_json(path, *, error_type=CycloneDxDocumentError):
    """Load a CycloneDX JSON object or raise the requested document error."""
    path = Path(path)
    try:
        with path.open(encoding="utf-8-sig") as input_file:
            document = json.load(input_file)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise error_type(
            f"Invalid CycloneDX JSON SBOM {path}: {exc}. "
            "Only JSON SBOMs are supported"
        ) from exc

    if not isinstance(document, dict) or document.get("bomFormat") != "CycloneDX":
        raise error_type(f"JSON input is not a CycloneDX document: {path}")
    return document


def write_cyclonedx_json(path, document, *, error_type=CycloneDxDocumentError):
    """Write a CycloneDX object as deterministic, formatted JSON."""
    path = Path(path)
    try:
        with path.open("w", encoding="utf-8") as output_file:
            json.dump(document, output_file, indent=2, sort_keys=True)
            output_file.write("\n")
    except OSError as exc:
        raise error_type(f"Could not write CycloneDX SBOM {path}: {exc}") from exc


def cyclonedx_version(document, source, *, error_type=CycloneDxDocumentError):
    """Return a supported CycloneDX specVersion from a document."""
    version = document.get("specVersion")
    if not isinstance(version, str):
        raise error_type(
            f"CycloneDX JSON input does not declare specVersion: {source}"
        )
    if version not in SUPPORTED_INPUT_VERSIONS:
        raise error_type(
            f"Unsupported CycloneDX version {version} in {source}; supported "
            f"input versions are {', '.join(SUPPORTED_INPUT_VERSIONS)}"
        )
    return version


def root_component(document, source, *, error_type=CycloneDxDocumentError):
    """Return a document's metadata.component object."""
    metadata = document.get("metadata")
    component = metadata.get("component") if isinstance(metadata, dict) else None
    if not isinstance(component, dict):
        raise error_type(
            f"CycloneDX SBOM does not define metadata.component: {source}"
        )
    return component


def root_component_name(document, source, *, error_type=CycloneDxDocumentError):
    """Return the non-empty name of a document's metadata component."""
    component = root_component(document, source, error_type=error_type)
    name = component.get("name")
    if not isinstance(name, str) or not name.strip():
        raise error_type(
            "CycloneDX SBOM metadata.component does not define a name: "
            f"{source}"
        )
    return name.strip()


def resolve_cyclonedx_cli(configured_cli):
    """Resolve an executable CycloneDX CLI path from configuration or PATH."""
    if not configured_cli or not str(configured_cli).strip():
        raise CycloneDxCliError(
            "CycloneDX CLI executable is required but was not specified. "
            "Install the CycloneDX CLI and configure a valid executable path"
        )

    configured_cli = str(configured_cli).strip()
    if os.sep in configured_cli or Path(configured_cli).is_absolute():
        executable = resolve_path(configured_cli)
        if executable.is_file() and os.access(executable, os.X_OK):
            return executable
    else:
        resolved = shutil.which(configured_cli)
        if resolved:
            return Path(resolved).resolve()

    raise CycloneDxCliError(
        "CycloneDX CLI executable is not reachable or executable: "
        f"{configured_cli}. Install the CycloneDX CLI and configure a valid "
        "executable path"
    )


def run_command(
    command,
    *,
    description,
    timeout,
    error_type,
    cwd=None,
    input_text=None,
):
    """Run a command and map execution failures to the requested error type."""
    command = [str(argument) for argument in command]
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd else None,
            input=input_text,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise error_type(
            f"{description} could not be executed: {' '.join(command)}\n{exc}"
        ) from exc

    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        if len(detail) > COMMAND_ERROR_OUTPUT_MAX_CHARS:
            detail = (
                "Command output truncated; showing the final "
                f"{COMMAND_ERROR_OUTPUT_MAX_CHARS} characters:\n"
                + detail[-COMMAND_ERROR_OUTPUT_MAX_CHARS:]
            )
        message = (
            f"{description} failed with exit code {result.returncode}: "
            f"{' '.join(command)}"
        )
        if detail:
            message += f"\n{detail}"
        raise error_type(message)
    return result


def run_cyclonedx_cli(command, description, timeout=CLI_TIMEOUT_SECONDS):
    """Run a CycloneDX CLI command and raise CycloneDxCliError on failure."""
    return run_command(
        command,
        description=description,
        timeout=timeout,
        error_type=CycloneDxCliError,
    )


def validate_sbom(cli, path, version, description):
    """Validate a JSON SBOM against its declared CycloneDX schema version."""
    run_cyclonedx_cli([
        cli,
        "validate",
        "--input-file",
        path,
        "--input-format",
        "json",
        "--input-version",
        f"v{version.replace('.', '_')}",
        "--fail-on-errors",
    ], description)


def convert_sbom(cli, source, destination, output_version="v1_6"):
    """Convert an SBOM and repair known invalid null justification output."""
    run_cyclonedx_cli([
        cli,
        "convert",
        "--input-file",
        source,
        "--input-format",
        "json",
        "--output-file",
        destination,
        "--output-format",
        "json",
        "--output-version",
        output_version,
    ], f"Converting SBOM {source} to CycloneDX {output_version} JSON")

    converted = load_cyclonedx_json(
        destination,
        error_type=CycloneDxCliError,
    )
    repaired = False
    for vulnerability in converted.get("vulnerabilities", []):
        if not isinstance(vulnerability, dict):
            continue
        analysis = vulnerability.get("analysis")
        # Some cyclonedx-cli versions convert an absent justification
        # to the invalid string "null" instead of leaving it absent.
        if (
            isinstance(analysis, dict)
            and analysis.get("justification") == "null"
        ):
            del analysis["justification"]
            repaired = True

    if repaired:
        write_cyclonedx_json(
            destination,
            converted,
            error_type=CycloneDxCliError,
        )


def walk_components(components, pointer):
    """Yield nested components with their JSON pointer locations."""
    for index, component in enumerate(components or []):
        component_pointer = f"{pointer}/{index}"
        yield component_pointer, component
        yield from walk_components(
            component.get("components"),
            f"{component_pointer}/components",
        )


def walk_services(services):
    """Yield every service in a nested CycloneDX service tree."""
    for service in services or []:
        yield service
        yield from walk_services(service.get("services"))


def component_objects(document):
    """Yield all components in metadata and top-level component trees."""
    root = document.get("metadata", {}).get("component")
    if root:
        yield "/metadata/component", root
        yield from walk_components(
            root.get("components"),
            "/metadata/component/components",
        )
    yield from walk_components(document.get("components"), "/components")


def walk_bom_ref_objects(value, pointer=""):
    """Yield every nested object defining a bom-ref and its JSON pointer."""
    if isinstance(value, dict):
        if "bom-ref" in value:
            yield pointer or "/", value
        for key, child in value.items():
            yield from walk_bom_ref_objects(child, f"{pointer}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from walk_bom_ref_objects(child, f"{pointer}/{index}")


def component_identities(component, *, error_type=CycloneDxDocumentError):
    """Return normalized PURL and CPE identities for a component."""
    identities = []
    purl = component.get("purl")
    if purl:
        try:
            from packageurl import PackageURL
        except ImportError as exc:
            raise error_type(
                "packageurl-python is required to process PURLs during "
                "CycloneDX SBOM composition; install the dependencies with "
                "'python3 -m pip install -r requirements.txt'"
            ) from exc
        try:
            normalized = PackageURL.from_string(purl.strip()).to_string()
        except ValueError as exc:
            raise error_type(f"Invalid component PURL: {purl}") from exc
        identities.append(("purl", normalized))

    cpe = component.get("cpe")
    if cpe:
        identities.append(("cpe", cpe.strip().lower()))
    return identities


def rewrite_references(value, reference_map):
    """Rewrite known CycloneDX references recursively in place."""
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "ref" and isinstance(child, str):
                value[key] = reference_map.get(child, child)
            elif key in REFERENCE_ARRAY_FIELDS and isinstance(child, list):
                for index, item in enumerate(child):
                    if isinstance(item, str):
                        child[index] = reference_map.get(item, item)
                    else:
                        rewrite_references(item, reference_map)
            else:
                rewrite_references(child, reference_map)
    elif isinstance(value, list):
        for child in value:
            rewrite_references(child, reference_map)
    return value


def json_key(value):
    """Return a stable JSON representation suitable as a deduplication key."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def extend_unique(destination, values):
    """Append deep copies of values not already present by JSON equality."""
    known = {json_key(item) for item in destination}
    for item in values:
        key = json_key(item)
        if key not in known:
            destination.append(deepcopy(item))
            known.add(key)


def add_dependency(document, source_reference, target_reference):
    """Add a unique dependency edge between two distinct references."""
    if source_reference == target_reference:
        return
    for dependency in document.setdefault("dependencies", []):
        if dependency["ref"] == source_reference:
            targets = dependency.setdefault("dependsOn", [])
            if target_reference not in targets:
                targets.append(target_reference)
                targets.sort()
            return
    document["dependencies"].append({
        "ref": source_reference,
        "dependsOn": [target_reference],
    })


def validate_reference_integrity(
    document,
    *,
    error_type=CycloneDxDocumentError,
):
    """Validate bom-ref uniqueness and dependency and affects resolution."""
    definitions = set()
    for pointer, item in walk_bom_ref_objects(document):
        reference = item.get("bom-ref")
        if not reference:
            raise error_type(f"Missing bom-ref at {pointer} in merged SBOM")
        if reference in definitions:
            raise error_type(f"Duplicate bom-ref in merged SBOM: {reference}")
        definitions.add(reference)

    target_references = {
        component["bom-ref"] for _, component in component_objects(document)
    }
    target_references.update(
        service["bom-ref"]
        for service in walk_services(document.get("services"))
        if service.get("bom-ref")
    )

    dependency_references = set()
    for dependency in document.get("dependencies", []):
        reference = dependency["ref"]
        if reference in dependency_references:
            raise error_type(f"Duplicate dependency entry: {reference}")
        dependency_references.add(reference)
        targets = [reference]
        targets.extend(dependency.get("dependsOn", []))
        targets.extend(dependency.get("provides", []))
        for target in targets:
            if target not in target_references:
                raise error_type(f"Unresolved dependency reference: {target}")

    for vulnerability in document.get("vulnerabilities", []):
        for affected in vulnerability.get("affects", []):
            if affected["ref"] not in target_references:
                raise error_type(
                    "Unresolved vulnerability affects reference: "
                    f"{affected['ref']}"
                )
