import sys
import pkg_resources

try:
    import cyclonedx
    cyclonedx_ver = pkg_resources.get_distribution("cyclonedx-python-lib").version
    if cyclonedx_ver == "3.1.5":
        from .cyclonedx_sbom_v1 import create_cyclonedx_sbom
    else:
        print("Vigiles ERROR: cyclonedx-python-lib version %s is not supported. Use version 3.1.5" % cyclonedx_ver)
        sys.exit(1)
except ImportError:
    print("Vigiles ERROR: CycloneDX is not installed. Run pip install cyclonedx-python-lib==3.1.5")
    sys.exit(1)

