##########################################################################
#
# validation.py - Finalize and validate a composed CycloneDX SBOM
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

from copy import deepcopy
from datetime import datetime, timezone
import os
from pathlib import Path
import tempfile

try:
    from utils import info
except ModuleNotFoundError:
    from scripts.utils import info

from .constants import (
    NORMALIZED_VERSION,
    REFERENCE_ARRAY_FIELDS,
    REFERENCE_RECORD_ARRAY_FIELDS,
)
from .errors import CycloneDxValidationError
from .utils import (
    component_identities,
    cyclonedx_version,
    extend_unique,
    json_key,
    load_cyclonedx_json,
    resolve_cyclonedx_cli,
    rewrite_references,
    validate_reference_integrity,
    validate_sbom,
    walk_services,
    write_cyclonedx_json,
)


def _component_identities(component):
    """Return validated strong identities for a component."""
    return component_identities(
        component,
        error_type=CycloneDxValidationError,
    )


def _merge_compatible_records(current, incoming, ignored_fields):
    """Merge compatible records or return the first conflicting field."""
    merged = deepcopy(current)
    for field, value in incoming.items():
        if field in ignored_fields:
            continue
        if field not in merged or merged[field] in (None, ""):
            merged[field] = deepcopy(value)
        elif value in (None, "") or merged[field] == value:
            continue
        elif isinstance(merged[field], list) and isinstance(value, list):
            extend_unique(merged[field], value)
        else:
            return None, field
    return merged, None


def _build_domain(component):
    """Return the Buildroot target, host, or build domain of a component."""
    for prop in component.get("properties", []):
        if prop.get("name") == "BR_TYPE":
            value = str(prop.get("value", "")).strip().lower()
            if value in {"target", "host", "build"}:
                return value
    return None


def _components_can_merge(first, second):
    """Return whether identities and Buildroot domains permit a merge."""
    first_ids = dict(_component_identities(first))
    second_ids = dict(_component_identities(second))
    for identity_kind in {"purl", "cpe"}:
        if (
            identity_kind in first_ids
            and identity_kind in second_ids
            and first_ids[identity_kind] != second_ids[identity_kind]
        ):
            return False

    first_domain = _build_domain(first)
    second_domain = _build_domain(second)
    if first_domain == second_domain:
        return True
    if "host" in {first_domain, second_domain}:
        return False
    if "build" in {first_domain, second_domain}:
        return False
    return True


def _flatten_components(document):
    """Flatten nested components and return their containment edges."""
    flattened = []
    containment_edges = []

    def collect(components, parent_reference=None):
        """Move a nested component tree into the flattened collection."""
        for component in components or []:
            nested = component.pop("components", [])
            reference = component["bom-ref"]
            flattened.append(component)
            if parent_reference and parent_reference != reference:
                containment_edges.append((parent_reference, reference))
            collect(nested, reference)

    collect(document.get("components"))
    root = document.get("metadata", {}).get("component")
    if root:
        collect(root.pop("components", []), root["bom-ref"])
    return flattened, containment_edges


def _deduplicate_components(document):
    """Deduplicate compatible strongly identified components in place."""
    components, containment_edges = _flatten_components(document)
    canonical = []
    indexes = {"purl": {}, "cpe": {}}
    reference_map = {}

    for component in components:
        identities = _component_identities(component)
        candidate_indexes = set()
        for identity_kind, identity in identities:
            candidate_indexes.update(
                indexes[identity_kind].get(identity, [])
            )

        compatible = [
            index
            for index in candidate_indexes
            if _components_can_merge(canonical[index], component)
        ]
        if len(compatible) > 1:
            raise CycloneDxValidationError(
                "Component has multiple compatible canonical identities: "
                f"{component.get('name')} {component.get('version', '')}"
            )

        if compatible:
            index = compatible[0]
            merged, conflict = _merge_compatible_records(
                canonical[index],
                component,
                {"bom-ref", "components"},
            )
            if conflict:
                raise CycloneDxValidationError(
                    "Conflicting component metadata for strong identity "
                    f"{identities[0]} in field {conflict}"
                )
            reference_map[component["bom-ref"]] = merged["bom-ref"]
            canonical[index] = merged
            for identity_kind, identity in _component_identities(merged):
                identity_indexes = indexes[identity_kind].setdefault(
                    identity, []
                )
                if index not in identity_indexes:
                    identity_indexes.append(index)
            continue

        index = len(canonical)
        canonical.append(component)
        for identity_kind, identity in identities:
            indexes[identity_kind].setdefault(identity, []).append(index)

    document["components"] = canonical
    return reference_map, containment_edges


def _vulnerability_identity(vulnerability):
    """Return a normalized vulnerability and source identity tuple."""
    vulnerability_id = str(vulnerability.get("id", "")).strip().lower()
    if not vulnerability_id:
        return None
    source = vulnerability.get("source") or {}
    return (
        vulnerability_id,
        str(source.get("name", "")).strip().lower(),
        str(source.get("url", "")).strip(),
    )


def _deduplicate_vulnerabilities(document):
    """Deduplicate compatible vulnerabilities and return reference rewrites."""
    canonical = []
    index = {}
    reference_map = {}
    for vulnerability in document.get("vulnerabilities", []):
        identity = _vulnerability_identity(vulnerability)
        if identity is None or identity not in index:
            if identity is not None:
                index[identity] = len(canonical)
            canonical.append(vulnerability)
            continue

        canonical_index = index[identity]
        merged, conflict = _merge_compatible_records(
            canonical[canonical_index],
            vulnerability,
            {"bom-ref", "id", "source"},
        )
        if conflict:
            raise CycloneDxValidationError(
                "Conflicting vulnerability metadata for "
                f"{vulnerability.get('id')} in field {conflict}"
            )
        reference_map[vulnerability["bom-ref"]] = merged["bom-ref"]
        canonical[canonical_index] = merged

    if canonical:
        document["vulnerabilities"] = canonical
    else:
        document.pop("vulnerabilities", None)
    return reference_map


def _component_references(document):
    """Return component and service references valid in dependency entries."""
    references = set()
    root = document.get("metadata", {}).get("component")
    if root:
        references.add(root["bom-ref"])
    references.update(
        component["bom-ref"]
        for component in document.get("components", [])
    )
    references.update(
        service["bom-ref"]
        for service in walk_services(document.get("services"))
        if service.get("bom-ref")
    )
    return references


def _deduplicate_reference_lists(value):
    """Remove exact duplicates from known reference-bearing arrays."""
    if isinstance(value, dict):
        for key, child in value.items():
            _deduplicate_reference_lists(child)
            if (
                key in REFERENCE_ARRAY_FIELDS | REFERENCE_RECORD_ARRAY_FIELDS
                and isinstance(child, list)
            ):
                unique = []
                known = set()
                for item in child:
                    item_key = json_key(item)
                    if item_key not in known:
                        unique.append(item)
                        known.add(item_key)
                child[:] = unique
    elif isinstance(value, list):
        for child in value:
            _deduplicate_reference_lists(child)


def _rebuild_dependency_graph(document, containment_edges):
    """Rebuild a complete dependency graph from valid edges and containment."""
    valid_references = _component_references(document)
    combined = {
        reference: {"dependsOn": set(), "provides": set()}
        for reference in valid_references
    }
    for dependency in document.get("dependencies", []):
        reference = dependency.get("ref")
        if reference not in valid_references:
            raise CycloneDxValidationError(
                f"Unresolved dependency reference: {reference}"
            )
        for field in ("dependsOn", "provides"):
            for target in dependency.get(field, []):
                if target not in valid_references:
                    raise CycloneDxValidationError(
                        f"Unresolved dependency reference: {target}"
                    )
                if target != reference:
                    combined[reference][field].add(target)

    for source, target in containment_edges:
        if source in valid_references and target in valid_references:
            if source != target:
                combined[source]["dependsOn"].add(target)

    rebuilt = []
    for reference in sorted(combined):
        dependency = {"ref": reference}
        for field in ("dependsOn", "provides"):
            if combined[reference][field]:
                dependency[field] = sorted(combined[reference][field])
        rebuilt.append(dependency)
    document["dependencies"] = rebuilt


def _add_missing_timestamp(document):
    """Add a UTC metadata timestamp, honoring SOURCE_DATE_EPOCH when set."""
    metadata = document.setdefault("metadata", {})
    if metadata.get("timestamp"):
        return

    source_date_epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        timestamp = (
            datetime.fromtimestamp(int(source_date_epoch), timezone.utc)
            if source_date_epoch is not None
            else datetime.now(timezone.utc)
        )
    except (OverflowError, TypeError, ValueError) as exc:
        raise CycloneDxValidationError(
            f"Invalid SOURCE_DATE_EPOCH: {source_date_epoch}"
        ) from exc
    metadata["timestamp"] = (
        timestamp.replace(microsecond=0).isoformat().replace("+00:00", "Z")
    )


def validate_cyclonedx_sbom(vgls, merged_path):
    """Finalize and independently validate a composed CycloneDX 1.6 SBOM."""
    if not merged_path:
        raise CycloneDxValidationError(
            "Merged CycloneDX SBOM path is unavailable"
        )
    merged_path = Path(merged_path).resolve()
    document = load_cyclonedx_json(
        merged_path,
        error_type=CycloneDxValidationError,
    )
    if cyclonedx_version(
        document,
        merged_path,
        error_type=CycloneDxValidationError,
    ) != NORMALIZED_VERSION:
        raise CycloneDxValidationError(
            "Merged CycloneDX SBOM must be JSON 1.6"
        )

    component_map, containment_edges = _deduplicate_components(document)
    vulnerability_map = _deduplicate_vulnerabilities(document)
    reference_map = {**component_map, **vulnerability_map}
    rewrite_references(document, reference_map)
    _deduplicate_reference_lists(document)
    containment_edges = [
        (
            reference_map.get(source, source),
            reference_map.get(target, target),
        )
        for source, target in containment_edges
    ]
    _rebuild_dependency_graph(document, containment_edges)
    _add_missing_timestamp(document)
    validate_reference_integrity(
        document,
        error_type=CycloneDxValidationError,
    )

    cli = resolve_cyclonedx_cli(vgls.get("cyclonedx_cli", ""))
    validation_dir = (Path(vgls["vdir"]) / "cyclonedx").resolve()
    validation_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(
        prefix=".validate-",
        dir=validation_dir,
    ) as work_dir:
        candidate_path = Path(work_dir) / "final.cdx.json"
        write_cyclonedx_json(
            candidate_path,
            document,
            error_type=CycloneDxValidationError,
        )
        validate_sbom(
            cli,
            candidate_path,
            NORMALIZED_VERSION,
            "Validating final CycloneDX SBOM",
        )

    info(
        "Validated final CycloneDX SBOM with "
        f"{len(document.get('components', []))} component(s) and "
        f"{len(document.get('vulnerabilities', []))} vulnerability record(s)"
    )
    return document
