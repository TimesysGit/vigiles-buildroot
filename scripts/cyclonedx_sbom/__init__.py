from .errors import (
    ChildSbomError,
    CycloneDxCliError,
    CycloneDxCompositionError,
    CycloneDxDocumentError,
    CycloneDxError,
    CycloneDxGenerationError,
    CycloneDxValidationError,
)
from .generator import (
    BuildrootGenerator,
    VigilesGenerator,
    generate_cyclonedx_sbom,
    select_generator,
)


def compose_cyclonedx_sboms(*args, **kwargs):
    """Load and run the optional CycloneDX composition workflow."""
    from .composition import compose_cyclonedx_sboms as compose

    return compose(*args, **kwargs)


def expand_child_sbom_paths(*args, **kwargs):
    """Load child SBOM path handling only when composition is requested."""
    from .normalize import expand_child_sbom_paths as expand

    return expand(*args, **kwargs)


def normalize_child_sboms(*args, **kwargs):
    """Load and run child SBOM normalization only when requested."""
    from .normalize import normalize_child_sboms as normalize

    return normalize(*args, **kwargs)


def validate_cyclonedx_sbom(*args, **kwargs):
    """Load and run composed SBOM validation only when requested."""
    from .validation import validate_cyclonedx_sbom as validate

    return validate(*args, **kwargs)

__all__ = [
    "BuildrootGenerator",
    "ChildSbomError",
    "CycloneDxCliError",
    "CycloneDxCompositionError",
    "CycloneDxDocumentError",
    "CycloneDxError",
    "CycloneDxGenerationError",
    "CycloneDxValidationError",
    "VigilesGenerator",
    "compose_cyclonedx_sboms",
    "expand_child_sbom_paths",
    "generate_cyclonedx_sbom",
    "normalize_child_sboms",
    "select_generator",
    "validate_cyclonedx_sbom",
]
