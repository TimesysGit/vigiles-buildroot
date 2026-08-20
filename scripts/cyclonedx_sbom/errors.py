##########################################################################
#
# errors.py - CycloneDX workflow exceptions
#
# Copyright (C) 2026 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
##########################################################################


class CycloneDxError(RuntimeError):
    """Base error for CycloneDX generation and composition."""


class CycloneDxCliError(CycloneDxError):
    """Raised when cyclonedx-cli cannot be resolved or executed."""


class CycloneDxDocumentError(CycloneDxError):
    """Raised when a CycloneDX document cannot be read or interpreted."""


class CycloneDxGenerationError(CycloneDxError):
    """Raised when a CycloneDX generator cannot produce a valid document."""


class ChildSbomError(CycloneDxError):
    """Raised when a child SBOM cannot be collected or normalized."""


class CycloneDxCompositionError(CycloneDxError):
    """Raised when normalized SBOMs cannot be composed safely."""


class CycloneDxValidationError(CycloneDxError):
    """Raised when a composed SBOM cannot be finalized safely."""
