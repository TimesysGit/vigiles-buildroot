##########################################################################
#
# generator.py - Select and invoke a Buildroot CycloneDX generator
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################

import json
import os
from pathlib import Path
import sys
import tempfile

try:
    from utils import info, warn
except ModuleNotFoundError:
    from scripts.utils import info, warn

from .constants import (
    BUILDROOT_GENERATOR,
    GENERATION_TIMEOUT_SECONDS,
    GENERATOR_PROBE_TIMEOUT_SECONDS,
    SUPPORTED_GENERATION_VERSIONS,
)
from .errors import CycloneDxGenerationError
from .utils import (
    load_cyclonedx_json,
    run_command,
    convert_sbom,
    resolve_cyclonedx_cli,
    validate_sbom,
    write_cyclonedx_json,
)


class BuildrootGenerator:
    """Generate an SBOM with Buildroot's utils/generate-cyclonedx."""

    def __init__(self, context):
        self.context = context
        self._command = None
        self._capabilities = None

    @property
    def utility_path(self):
        """Return the configured Buildroot CycloneDX utility path."""
        topdir = self.context.get("topdir")
        if not topdir:
            raise CycloneDxGenerationError(
                "Buildroot source directory is not configured"
            )
        return Path(topdir).expanduser().resolve() / BUILDROOT_GENERATOR

    @property
    def description(self):
        """Return a human-readable generator description."""
        return f"Buildroot CycloneDX utility: {self.utility_path}"

    def is_present(self):
        """Return whether the native utility exists in the Buildroot tree."""
        path = self.utility_path
        return path.exists() or path.is_symlink()

    @staticmethod
    def _has_python_shebang(path):
        """Return whether a file declares a Python interpreter."""
        try:
            with path.open("rb") as script:
                shebang = script.readline(256).lower()
        except OSError:
            return False
        return shebang.startswith(b"#!") and b"python" in shebang

    def _native_command(self):
        """Build the command prefix used to invoke the native utility."""
        path = self.utility_path
        if not path.is_file():
            raise CycloneDxGenerationError(
                f"Buildroot CycloneDX utility is not a regular file: {path}"
            )
        if not os.access(path, os.R_OK):
            raise CycloneDxGenerationError(
                f"Buildroot CycloneDX utility is not readable: {path}"
            )
        if os.access(path, os.X_OK):
            return [str(path)]
        if self._has_python_shebang(path):
            return [sys.executable, str(path)]
        raise CycloneDxGenerationError(
            "Buildroot CycloneDX utility is neither executable nor a "
            f"readable Python script: {path}"
        )

    def validate(self):
        """Probe the native utility and cache its supported options."""
        if self._command is not None:
            return
        command = self._native_command()
        result = run_command(
            command + ["--help"],
            description="Buildroot CycloneDX utility probe",
            timeout=GENERATOR_PROBE_TIMEOUT_SECONDS,
            error_type=CycloneDxGenerationError,
            cwd=Path(self.context["topdir"]),
        )
        self._command = command
        self._capabilities = (result.stdout or "") + (result.stderr or "")

    def _show_info(self):
        """Return Buildroot package metadata from the show-info target."""
        command = [
            "make",
            "-s",
            "--no-print-directory",
            "-C",
            str(Path(self.context["topdir"])),
        ]
        if self.context.get("odir"):
            command.append(f"O={self.context['odir']}")
        command.append("show-info")

        output = run_command(
            command,
            description="Buildroot show-info",
            timeout=GENERATION_TIMEOUT_SECONDS,
            error_type=CycloneDxGenerationError,
        ).stdout
        if not output or not output.strip():
            raise CycloneDxGenerationError(
                "Buildroot show-info returned no output"
            )
        return output

    def _native_arguments(self):
        """Build optional arguments supported by the native utility."""
        arguments = []
        capabilities = self._capabilities or ""
        if "--project-name" in capabilities and self.context.get("manifest_name"):
            arguments.extend(["--project-name", self.context["manifest_name"]])

        buildroot_version = (
            self.context.get("make", {})
            .get("br2", {})
            .get("meta", {})
            .get("version")
        )
        if "--project-version" in capabilities and buildroot_version:
            arguments.extend(["--project-version", str(buildroot_version)])

        if (
            "--virtual" in capabilities
            and self.context.get("include_virtual_pkgs")
        ):
            arguments.append("--virtual")
        return arguments

    def _parse_output(self, output):
        """Parse and verify the native generator's JSON output."""
        try:
            sbom = json.loads(output)
        except (TypeError, json.JSONDecodeError) as exc:
            raise CycloneDxGenerationError(
                "Buildroot CycloneDX utility returned invalid JSON: "
                f"{self.utility_path}"
            ) from exc

        if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
            raise CycloneDxGenerationError(
                "Buildroot CycloneDX utility output is not a CycloneDX "
                f"document: {self.utility_path}"
            )
        if not sbom.get("specVersion"):
            raise CycloneDxGenerationError(
                "Buildroot CycloneDX utility output does not declare "
                f"specVersion: {self.utility_path}"
            )
        return sbom

    def generate(self):
        """Generate and parse a native Buildroot CycloneDX SBOM."""
        self.validate()
        show_info = self._show_info()
        result = run_command(
            self._command + self._native_arguments(),
            description="Buildroot CycloneDX generation",
            timeout=GENERATION_TIMEOUT_SECONDS,
            error_type=CycloneDxGenerationError,
            cwd=Path(self.context["topdir"]),
            input_text=show_info,
        )
        return self._parse_output(result.stdout)


class VigilesGenerator:
    """Generate the legacy CycloneDX 1.4 SBOM with the Vigiles writer."""

    def __init__(self, context):
        self.context = context

    @property
    def description(self):
        """Return a human-readable generator description."""
        return "Vigiles CycloneDX 1.4 generator"

    def generate(self):
        """Generate a CycloneDX 1.4 SBOM with the Vigiles writer."""
        from .cyclonedx_sbom_v1_4 import create_cyclonedx_sbom

        return create_cyclonedx_sbom(self.context)


def _normalize_requested_version(requested_version):
    """Return a supported CycloneDX generation version string."""
    requested_version = str(requested_version).strip().lower()
    if requested_version not in SUPPORTED_GENERATION_VERSIONS:
        raise CycloneDxGenerationError(
            "Unsupported CycloneDX generation version "
            f"'{requested_version}'; choose 1.4 or 1.6"
        )
    return requested_version


def select_generator(vgls, requested_version):
    """Select and validate the generator for the requested version."""
    requested_version = _normalize_requested_version(requested_version)

    if requested_version == "1.4":
        return VigilesGenerator(vgls)

    native = BuildrootGenerator(vgls)
    if not native.is_present():
        raise CycloneDxGenerationError(
            "CycloneDX 1.6 generation requires Buildroot's "
            "utils/generate-cyclonedx utility, but it was not found at "
            f"{native.utility_path}"
        )

    native.validate()
    return native


def generate_cyclonedx_sbom(vgls, requested_version):
    """Generate an SBOM and verify that its version was requested."""
    requested_version = str(requested_version).strip().lower()
    convert = False

    try:
        generator = select_generator(vgls, requested_version)
    except CycloneDxGenerationError as exc:
        if requested_version != "1.6":
            raise

        warn(f"{exc}. Falling back to CycloneDX 1.4 and converting to 1.6")

        generator = select_generator(vgls, "1.4")
        convert = True

    info(f"Using {generator.description}")
    sbom = generator.generate()

    if convert:
        cli = resolve_cyclonedx_cli(vgls.get("cyclonedx_cli", ""))
        
        with tempfile.TemporaryDirectory() as tmpdir:
            source = os.path.join(tmpdir, "sbom-1.4.json")
            destination = os.path.join(tmpdir, "sbom-1.6.json")

            write_cyclonedx_json(
                source,
                sbom,
                error_type=CycloneDxGenerationError,
            )

            convert_sbom(
                cli,
                source=source,
                destination=destination,
                output_version="v1_6",
            )

            validate_sbom(
                cli,
                destination,
                requested_version,
                "Validating Converted CycloneDX SBOM",
            )

            sbom = load_cyclonedx_json(
                destination,
                error_type=CycloneDxGenerationError,
            )

    actual_version = sbom.get("specVersion")
    if actual_version != requested_version:
        raise CycloneDxGenerationError(
            f"CycloneDX {requested_version} was requested, but "
            f"the selected generator produced {actual_version or 'no version'}"
        )

    return sbom
