##########################################################################
#
# constants.py - Shared CycloneDX workflow constants
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

from pathlib import Path
import uuid


BUILDROOT_GENERATOR = Path("utils") / "generate-cyclonedx"
NORMALIZED_VERSION = "1.6"
MIN_COMPOSITION_PYTHON = (3, 9)

SUPPORTED_GENERATION_VERSIONS = frozenset({"1.4", "1.6"})
SUPPORTED_INPUT_VERSIONS = (
    "1.0",
    "1.1",
    "1.2",
    "1.3",
    "1.4",
    "1.5",
    "1.6",
)

GENERATOR_PROBE_TIMEOUT_SECONDS = 30
GENERATION_TIMEOUT_SECONDS = 300
CLI_TIMEOUT_SECONDS = 300
COMMAND_ERROR_OUTPUT_MAX_CHARS = 6000

REFERENCE_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL,
    "https://github.com/TimesysGit/vigiles-buildroot/cyclonedx",
)
OPTIONAL_SECTIONS = (
    "services",
    "annotations",
    "compositions",
    "formulation",
)
# Required by the Vigiles composition workflow, not the CycloneDX schema.
REQUIRED_SECTIONS = (
    "components",
    "vulnerabilities",
    "dependencies",
)
REFERENCE_ARRAY_FIELDS = frozenset({
    "assemblies",
    "dependencies",
    "dependsOn",
    "provides",
    "subjects",
    "vulnerabilities",
})
REFERENCE_RECORD_ARRAY_FIELDS = frozenset({"affects"})

LEGACY_BOM_AUTHOR = "vigiles-buildroot"
LEGACY_BOM_VERSION = "1"
LEGACY_SCHEMA_URL = "http://cyclonedx.org/schema/bom-1.4.schema.json"
LEGACY_NOT_AFFECTED_DETAIL = "CVE included in SBOM's Not Affected"
LEGACY_HASH_ALGORITHMS = {
    "MD5": "MD5",
    "SHA1": "SHA-1",
    "SHA256": "SHA-256",
    "SHA384": "SHA-384",
    "SHA512": "SHA-512",
}
