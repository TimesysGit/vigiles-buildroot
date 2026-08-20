##########################################################################
#
# cyclonedx_sbom_v1_4.py - Generate a CycloneDX 1.4 SBOM
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

from datetime import datetime, timezone
import uuid

from amendments import (
    _filter_excluded_packages,
    _get_excld_packages,
    _get_user_whitelist,
    _parse_addl_pkg_csv,
)
from manifest import (
    DEFAULT_SUPPLIER,
    VIGILES_TOOL_NAME,
    VIGILES_TOOL_VENDOR,
    VIGILES_TOOL_VERSION,
)
from .constants import (
    LEGACY_BOM_AUTHOR,
    LEGACY_BOM_VERSION,
    LEGACY_HASH_ALGORITHMS,
    LEGACY_NOT_AFFECTED_DETAIL,
    LEGACY_SCHEMA_URL,
)


def generate_bom_ref():
    """Return a new component reference value."""
    return str(uuid.uuid4()).upper()


def generate_bom_refs(packages):
    """Assign a new component reference to every package name."""
    return {package: generate_bom_ref() for package in packages}


def get_bom_ref(bom_refs, package):
    """Return the existing package reference or create and store one."""
    bom_ref = bom_refs.get(package)
    if not bom_ref:
        bom_ref = generate_bom_ref()
        bom_refs[package] = bom_ref
    return bom_ref


def get_dependency_names(dependencies):
    """Return unique build and runtime dependency names in stable order."""
    return sorted(set(
        dependencies.get("build", [])
        + dependencies.get("runtime", [])
    ))


def is_image_component(package):
    """Return whether a package belongs to the target image inventory."""
    component_roles = package.get("component_type", [])
    if isinstance(component_roles, str):
        component_roles = [component_roles]
    return (
        not component_roles
        or "component" in component_roles
        or "runtime" in component_roles
    )


def _component_type(package):
    """Return a JSON-compatible CycloneDX component type."""
    component_type = package.get("type", "library")
    return getattr(component_type, "value", component_type)


def _licenses(value):
    """Convert a package license value to CycloneDX license choices."""
    if not value:
        return []
    return [{"license": {"name": str(value)}}]


def _hashes(checksums):
    """Convert supported package checksums to CycloneDX hashes."""
    hashes = []
    for checksum in checksums or []:
        algorithm = LEGACY_HASH_ALGORITHMS.get(checksum.get("algorithm"))
        content = checksum.get("checksum_value")
        if algorithm and content:
            hashes.append({"alg": algorithm, "content": content})
    return sorted(hashes, key=lambda item: (item["alg"], item["content"]))


def _pedigree(package):
    """Build CycloneDX patch pedigree data for a package."""
    patched_cves = package.get("patched_cves", {})
    patches = []
    for patch_name in sorted(package.get("patches") or []):
        patch = {
            "type": "backport",
            "diff": {"url": patch_name},
        }
        resolves = [
            {
                "type": "security",
                "id": cve,
                "name": cve,
            }
            for cve, patch_names in sorted(patched_cves.items())
            if patch_name in patch_names
        ]
        if resolves:
            patch["resolves"] = resolves
        patches.append(patch)
    return {"patches": patches} if patches else None


def _properties(package):
    """Build lifecycle and comment properties for a component."""
    fields = (
        ("comment", "comment"),
        ("release-date", "release_date"),
        ("end-of-life", "end_of_life"),
        ("level-of-support", "level_of_support"),
    )
    properties = [
        {"name": property_name, "value": package[source_name]}
        for source_name, property_name in fields
        if package.get(source_name)
    ]
    return sorted(
        properties,
        key=lambda item: (item["name"], str(item["value"])),
    )


def create_component(vgls, package_name, package, additional_pkg=False):
    """Create a CycloneDX component from Vigiles package metadata."""
    name = package.get("name", package_name)
    version = package.get("cve_version", package.get("version"))
    component = {
        "bom-ref": get_bom_ref(vgls["bom_refs"], name),
        "type": _component_type(package),
        "name": name,
    }
    if version is not None:
        component["version"] = version
    if additional_pkg:
        component["description"] = "Additional package"

    licenses = _licenses(package.get("license"))
    if licenses:
        component["licenses"] = licenses

    supplier = package.get("package-supplier") or DEFAULT_SUPPLIER
    component["supplier"] = {
        "name": supplier.replace("Organization:", "").strip()
    }

    hashes = _hashes(package.get("checksums"))
    if hashes:
        component["hashes"] = hashes

    cpe = package.get("cpe-id") or ""
    if cpe and cpe.lower() != "unknown":
        component["cpe"] = cpe

    pedigree = _pedigree(package)
    if pedigree:
        component["pedigree"] = pedigree

    properties = _properties(package)
    if properties:
        component["properties"] = properties
    return component


def create_vulnerability(cve, status, component, detail=None):
    """Create a vulnerability analysis record affecting one component."""
    states = {
        "patched": "resolved_with_pedigree",
        "ignored": "not_affected",
    }
    if detail is None and status == "ignored":
        detail = LEGACY_NOT_AFFECTED_DETAIL

    analysis = {"state": states[status]}
    if detail:
        analysis["detail"] = detail

    target = {"ref": component["bom-ref"]}
    if component.get("version"):
        target["versions"] = [{"version": component["version"]}]

    return {
        "bom-ref": generate_bom_ref(),
        "id": cve,
        "analysis": analysis,
        "affects": [target],
    }


def _dependency(component, dependencies=None):
    """Create a dependency graph entry for a component."""
    entry = {"ref": component["bom-ref"]}
    references = sorted({
        dependency["bom-ref"]
        for dependency in dependencies or []
        if dependency is not component
    })
    if references:
        entry["dependsOn"] = references
    return entry


def create_cyclonedx_sbom(vgls):
    """Generate a CycloneDX 1.4 JSON document from Vigiles metadata."""
    excluded_packages = _get_excld_packages(vgls["excld"])
    _filter_excluded_packages(vgls["packages"], excluded_packages)

    package_names = [
        package.get("name", key)
        for key, package in vgls.get("packages", {}).items()
    ]
    vgls["bom_refs"] = generate_bom_refs(package_names)

    manifest_name = "-".join([vgls["manifest_name"], "cyclonedx"])
    root_component = create_component(vgls, manifest_name, {
        "type": "application",
        "version": LEGACY_BOM_VERSION,
    })

    package_components = []
    components_by_name = {}
    vulnerabilities = []
    for package_name, package in vgls.get("packages", {}).items():
        component = create_component(vgls, package_name, package)
        package_components.append((package_name, package, component))
        components_by_name[package_name] = component
        components_by_name[package.get("name", package_name)] = component

        ignored_cves = set(package.get("ignore-cves", "").split())
        patched_cves = set(package.get("patched_cves", {}))
        for cve in sorted(ignored_cves.union(patched_cves)):
            status = "patched" if cve in patched_cves else "ignored"
            detail = LEGACY_NOT_AFFECTED_DETAIL if status == "ignored" else None
            vulnerabilities.append(
                create_vulnerability(cve, status, component, detail=detail)
            )

    additional_components = []
    additional_packages = (
        _parse_addl_pkg_csv(vgls["addl"])
        if vgls.get("addl")
        else []
    )
    for entry in additional_packages:
        package, version, license_name, release, eol, support = entry
        component = create_component(vgls, package, {
            "version": version,
            "license": license_name,
            "release-date": release,
            "end-of-life": eol,
            "level-of-support": support,
        }, additional_pkg=True)
        additional_components.append(component)

    dependencies = []
    for _, package, component in package_components:
        direct_dependencies = [
            components_by_name[name]
            for name in get_dependency_names(package.get("dependencies", {}))
            if name in components_by_name
        ]
        dependencies.append(_dependency(component, direct_dependencies))
    dependencies.extend(
        _dependency(component)
        for component in additional_components
    )

    image_components = [
        component
        for _, package, component in package_components
        if is_image_component(package)
    ]
    image_components.extend(additional_components)
    dependencies.append(_dependency(root_component, image_components))

    for cve in _get_user_whitelist(vgls["whtlst"]):
        vulnerabilities.append(
            create_vulnerability(cve, "ignored", root_component)
        )

    document = {
        "$schema": LEGACY_SCHEMA_URL,
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": "urn:uuid:" + str(uuid.uuid4()),
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "authors": [{"name": LEGACY_BOM_AUTHOR}],
            "tools": [{
                "vendor": VIGILES_TOOL_VENDOR,
                "name": VIGILES_TOOL_NAME,
                "version": VIGILES_TOOL_VERSION,
            }],
            "component": root_component,
        },
        "components": sorted(
            [item[2] for item in package_components]
            + additional_components,
            key=lambda item: (
                item["name"],
                str(item.get("version", "")),
                item["bom-ref"],
            ),
        ),
        "dependencies": sorted(
            dependencies,
            key=lambda item: item["ref"],
        ),
    }
    if vulnerabilities:
        document["vulnerabilities"] = sorted(
            vulnerabilities,
            key=lambda item: (item["id"], item["bom-ref"]),
        )

    del vgls["bom_refs"]
    return document
