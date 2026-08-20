##########################################################################
#
# composition.py - Clean and merge CycloneDX SBOMs
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

from copy import deepcopy
import os
from pathlib import Path
import sys
import tempfile
import uuid

try:
    from utils import info, warn
except ModuleNotFoundError:
    from scripts.utils import info, warn

from .constants import (
    MIN_COMPOSITION_PYTHON,
    NORMALIZED_VERSION,
    OPTIONAL_SECTIONS,
    REFERENCE_NAMESPACE,
    REQUIRED_SECTIONS,
)
from .errors import CycloneDxCompositionError
from .generator import BuildrootGenerator, VigilesGenerator
from .normalize import normalize_child_sboms
from .utils import (
    add_dependency,
    component_identities,
    component_objects,
    convert_sbom,
    cyclonedx_version,
    extend_unique,
    load_cyclonedx_json,
    resolve_cyclonedx_cli,
    rewrite_references,
    root_component_name,
    validate_sbom,
    walk_bom_ref_objects,
    write_cyclonedx_json,
)


def _component_identities(component):
    """Return validated strong identities for a component."""
    return component_identities(
        component,
        error_type=CycloneDxCompositionError,
    )


def _remove_signatures(value, source_id, pointer=""):
    """Remove signatures invalidated by composition and return their count."""
    removed = 0
    if isinstance(value, dict):
        if "signature" in value:
            value.pop("signature")
            removed += 1
        for key, child in value.items():
            removed += _remove_signatures(child, source_id, f"{pointer}/{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            removed += _remove_signatures(
                child,
                source_id,
                f"{pointer}/{index}",
            )
    if not pointer and removed:
        warn(
            f"Removed {removed} invalidated signature(s) from {source_id}; "
            "composition rewrites signed content"
        )
    return removed


def _referencable_objects(document):
    """Yield components and vulnerabilities that require stable references."""
    for pointer, component in component_objects(document):
        yield "component", pointer, component
    for index, vulnerability in enumerate(document.get("vulnerabilities", [])):
        yield "vulnerability", f"/vulnerabilities/{index}", vulnerability


def _deduplicate_identical_components(document, source_id):
    """Collapse identical repeated component references within one SBOM."""
    seen = {}

    def clean(components, pointer):
        """Remove identical components recursively from a component list."""
        if not components:
            return
        retained = []
        for index, component in enumerate(components):
            component_pointer = f"{pointer}/{index}"
            reference = component.get("bom-ref")
            if reference and reference in seen:
                original_pointer, original = seen[reference]
                if component != original:
                    raise CycloneDxCompositionError(
                        f"Duplicate bom-ref in {source_id}: {reference}"
                    )
                info(
                    "Ignoring identical duplicate component "
                    f"{reference} at {component_pointer}; already present at "
                    f"{original_pointer}"
                )
                continue
            if reference:
                seen[reference] = (component_pointer, deepcopy(component))
            clean(
                component.get("components"),
                f"{component_pointer}/components",
            )
            retained.append(component)
        components[:] = retained

    root = document.get("metadata", {}).get("component")
    if root:
        reference = root.get("bom-ref")
        if reference:
            seen[reference] = ("/metadata/component", deepcopy(root))
        clean(root.get("components"), "/metadata/component/components")
    clean(document.get("components"), "/components")


def _object_identity(kind, item):
    """Return stable identity material for a referencable object."""
    if kind == "vulnerability":
        return f"vulnerability:{item.get('id', '')}"
    if kind == "object":
        return f"object:{item.get('bom-ref', '')}"

    identities = _component_identities(item)
    if identities:
        identity_kind, identity = identities[0]
        return f"{identity_kind}:{identity}"
    coordinates = (
        item.get("type", ""),
        item.get("group", ""),
        item.get("name", ""),
        item.get("version", ""),
    )
    return "component:" + "\0".join(str(value) for value in coordinates)


def _new_bom_ref(source_id, kind, pointer, item):
    """Generate a reproducible UUID reference for an imported object."""
    value = "\0".join((
        source_id,
        kind,
        _object_identity(kind, item),
        pointer,
    ))
    return f"urn:uuid:{uuid.uuid5(REFERENCE_NAMESPACE, value)}"


def _clean_document(document, source_id):
    """Copy an SBOM, normalize its references, and remove invalid signatures."""
    cleaned = deepcopy(document)
    _remove_signatures(cleaned, source_id)
    _deduplicate_identical_components(cleaned, source_id)
    reference_map = {}
    managed_objects = set()

    for kind, pointer, item in _referencable_objects(cleaned):
        managed_objects.add(id(item))
        old_reference = item.get("bom-ref")
        if old_reference in reference_map:
            raise CycloneDxCompositionError(
                f"Duplicate bom-ref in {source_id}: {old_reference}"
            )
        item["bom-ref"] = _new_bom_ref(source_id, kind, pointer, item)
        if old_reference:
            reference_map[old_reference] = item["bom-ref"]

    for pointer, item in walk_bom_ref_objects(cleaned):
        if id(item) in managed_objects:
            continue
        old_reference = item.get("bom-ref")
        if old_reference in reference_map:
            raise CycloneDxCompositionError(
                f"Duplicate bom-ref in {source_id}: {old_reference}"
            )
        item["bom-ref"] = _new_bom_ref(source_id, "object", pointer, item)
        if old_reference:
            reference_map[old_reference] = item["bom-ref"]

    rewrite_references(cleaned, reference_map)
    return cleaned


def _index_parent_components(parent):
    """Index parent component references by normalized PURL and CPE."""
    index = {"purl": {}, "cpe": {}}
    for _, component in component_objects(parent):
        for identity_kind, identity in _component_identities(component):
            index[identity_kind].setdefault(identity, set()).add(
                component["bom-ref"]
            )
    return index


def _find_parent_reference(parent_index, child_root):
    """Return the unique parent reference matching a child subject."""
    for identity_kind, identity in _component_identities(child_root):
        matches = parent_index[identity_kind].get(identity, set())
        if len(matches) > 1:
            raise CycloneDxCompositionError(
                "Child metadata.component has multiple parent matches for "
                f"{identity_kind} {identity}"
            )
        if matches:
            return next(iter(matches)), identity_kind
    return None, None


def _replace_reference(document, old_reference, new_reference):
    """Replace a reference definition and every use within a document."""
    for _, item in walk_bom_ref_objects(document):
        if item.get("bom-ref") == old_reference:
            item["bom-ref"] = new_reference
    rewrite_references(document, {old_reference: new_reference})


def _component_by_reference(document, reference):
    """Resolve a component by bom-ref or raise a composition error."""
    for _, component in component_objects(document):
        if component.get("bom-ref") == reference:
            return component
    raise CycloneDxCompositionError(
        f"Could not resolve matched parent component: {reference}"
    )


def _add_child_provenance(child_root, child_source):
    """Add source identity, digest, and version properties to a child root."""
    if child_source is None:
        return
    properties = child_root.setdefault("properties", [])
    extend_unique(properties, [
        {
            "name": "vigiles:child-sbom:source-id",
            "value": child_source.source_id,
        },
        {
            "name": "vigiles:child-sbom:sha256",
            "value": child_source.sha256,
        },
        {
            "name": "vigiles:child-sbom:spec-version",
            "value": child_source.original_version,
        },
    ])


def _merge_child_subject(parent_component, child_root):
    """Merge child subject data while preserving parent scalar values."""
    for field, value in child_root.items():
        if field == "bom-ref":
            continue
        if field == "components":
            destination = parent_component.setdefault("components", [])
            extend_unique(destination, value)
            continue
        if field not in parent_component or parent_component[field] in (None, ""):
            parent_component[field] = deepcopy(value)
        elif isinstance(parent_component[field], list) and isinstance(value, list):
            extend_unique(parent_component[field], value)
        # The Buildroot component remains authoritative for scalar conflicts.


def _attach_child(parent, child, parent_index=None, child_source=None):
    """Attach a child subject to its matched component or the image root."""
    parent_root = parent["metadata"]["component"]
    child_root = child["metadata"]["component"]
    _add_child_provenance(child_root, child_source)
    child_reference = child_root["bom-ref"]
    target_reference, match_kind = _find_parent_reference(
        parent_index or _index_parent_components(parent),
        child_root,
    )

    if target_reference:
        _replace_reference(child, child_reference, target_reference)
        parent_component = _component_by_reference(parent, target_reference)
        _merge_child_subject(parent_component, child_root)
        info(
            "Matched child metadata.component "
            f"{child_root.get('name')} to parent by {match_kind}"
        )
    else:
        target_reference = child_reference
        child.setdefault("components", []).append(deepcopy(child_root))
        info(
            "Attaching unmatched child metadata.component "
            f"{child_root.get('name')} to the Buildroot image"
        )

    add_dependency(parent, parent_root["bom-ref"], target_reference)
    child["metadata"].pop("component")


def _prepare_parent(vgls, cli, work_dir):
    """Generate, validate, and normalize the Buildroot parent to JSON 1.6."""
    native = BuildrootGenerator(vgls)
    if native.is_present():
        native.validate()
        info(f"Using {native.description}")
        parent = native.generate()
        version = cyclonedx_version(
            parent,
            native.utility_path,
            error_type=CycloneDxCompositionError,
        )
        if version != NORMALIZED_VERSION:
            raise CycloneDxCompositionError(
                "Buildroot CycloneDX utility produced "
                f"{version}, expected {NORMALIZED_VERSION}"
            )
    else:
        warn(
            "Buildroot CycloneDX utility is unavailable; using the Vigiles "
            "CycloneDX 1.4 generator and converting the parent to 1.6"
        )
        fallback = VigilesGenerator(vgls)
        info(f"Using {fallback.description}")
        parent = fallback.generate()
        version = cyclonedx_version(
            parent,
            "Vigiles parent SBOM",
            error_type=CycloneDxCompositionError,
        )

    original_path = work_dir / f"parent-{version}.cdx.json"
    write_cyclonedx_json(
        original_path,
        parent,
        error_type=CycloneDxCompositionError,
    )
    validate_sbom(
        cli,
        original_path,
        version,
        "Validating Buildroot parent SBOM",
    )

    normalized_path = original_path
    if version != NORMALIZED_VERSION:
        normalized_path = work_dir / "parent-1.6.cdx.json"
        convert_sbom(cli, original_path, normalized_path)

    normalized_parent = load_cyclonedx_json(
        normalized_path,
        error_type=CycloneDxCompositionError,
    )
    normalized_version = cyclonedx_version(
        normalized_parent,
        normalized_path,
        error_type=CycloneDxCompositionError,
    )
    if normalized_version != NORMALIZED_VERSION:
        raise CycloneDxCompositionError(
            "Normalized Buildroot parent SBOM is "
            f"{normalized_version}, expected {NORMALIZED_VERSION}"
        )
    root_component_name(
        normalized_parent,
        normalized_path,
        error_type=CycloneDxCompositionError,
    )
    if normalized_path != original_path:
        validate_sbom(
            cli,
            normalized_path,
            normalized_version,
            "Validating normalized Buildroot parent SBOM",
        )
    return normalized_parent


def _merge_documents(parent, children):
    """Copy child required and optional sections into the parent document."""
    merged = deepcopy(parent)
    for child in children:
        for section in REQUIRED_SECTIONS:
            if child.get(section):
                merged.setdefault(section, []).extend(deepcopy(child[section]))

        for section in OPTIONAL_SECTIONS:
            if child.get(section):
                extend_unique(
                    merged.setdefault(section, []),
                    child[section],
                )
    return merged


def compose_cyclonedx_sboms(vgls):
    """Compose the Buildroot parent and configured children into JSON 1.6."""
    if sys.version_info < MIN_COMPOSITION_PYTHON:
        raise CycloneDxCompositionError(
            "CycloneDX 1.6 SBOM composition requires Python 3.9 or newer; "
            f"current interpreter is Python {sys.version_info[0]}."
            f"{sys.version_info[1]}"
        )

    cli = resolve_cyclonedx_cli(vgls.get("cyclonedx_cli", ""))
    normalized_children = normalize_child_sboms(vgls, cli=cli)
    if not normalized_children:
        raise CycloneDxCompositionError(
            "Child SBOM composition requires at least one unique child SBOM"
        )

    merged_dir = (Path(vgls["vdir"]) / "cyclonedx" / "merged").resolve()
    merged_dir.mkdir(parents=True, exist_ok=True)
    merged_name = f"{vgls['manifest_name']}-merged.cdx.json"
    final_merged_path = merged_dir / merged_name
    with tempfile.TemporaryDirectory(
        prefix=".compose-",
        dir=merged_dir,
    ) as work_dir:
        work_dir = Path(work_dir)
        parent = _clean_document(
            _prepare_parent(vgls, cli, work_dir),
            "buildroot-parent",
        )
        parent_index = _index_parent_components(parent)
        child_documents = []
        for child in normalized_children:
            child_document = _clean_document(
                load_cyclonedx_json(
                    child.normalized_path,
                    error_type=CycloneDxCompositionError,
                ),
                child.source_id,
            )
            _attach_child(parent, child_document, parent_index, child)
            child_documents.append(child_document)

        merged = _merge_documents(parent, child_documents)
        merged_path = work_dir / merged_name
        write_cyclonedx_json(
            merged_path,
            merged,
            error_type=CycloneDxCompositionError,
        )
        os.replace(merged_path, final_merged_path)

    info(
        "Merged Buildroot parent with "
        f"{len(normalized_children)} child SBOM(s) to {final_merged_path}"
    )
    return final_merged_path
