# Changelog

## [v1.20.0] - 2025-11-03

### Added

* feature: Add support for package lifecycle information in SBOM

## [v1.19.0] - 2025-07-22

### Changed

* [checkcves.py] Removed demo mode

### Fixed

* [packages.py] fix python regex warning
* [cyclonedx_sbom_v1.py] Add dependency type as property in cyclonedx SBOM

## [v1.18.0] - 2025-07-08

### Changed

* Updated timesys and linuxLink references

## [v1.17.0] - 2025-03-24

### Added
* Feature: Added support to subscribe frequency for notification during manifest upload
* Feature: Added option to specify ecosystems for generating vulnerability report

### Changed

* docs: remove references to free account registration

### Fixed

* [checkcves.py] Handle KeyErrors when data is unavailable from upload API response
* [amendments.py] Dont allow empty rows to be parsed from additional packages CSV file

## [v1.16.2] - 2025-02-19

### Fixed

* [cyclonedx_sbom_v1.py]: Fix where Patched CVEs are not marked correctly in
the generated cyclonedx manifest
* [buildroot.py] Include CPE_ID_UPDATE to parse the correct cve-version from
cpe_id

## [v1.16.1] - 2024-09-03

### Changed

* [Readme.md] Update the requirements for vigiles-buildroot to be setup

### Fixed

* [packages.py] Exclude output dir from makefile searches
* [kernel_uboot.py] Improve parsing of version from makefile

## [v1.16.0] - 2024-08-08

### Added

* [Feature] Add option to raise error when config.in or hash files are missing

### Changed
* [packages.py] Include checksums from external sources

## [v1.15.0] - 2024-06-25

### Added

* [feature] Add option to specify the vigiles output location
* [internal] Include Config.in files from external_dirs
* [feature] Add option to generate SBOMs in CycloneDx format
* [cyclonedx] Add vulnerabilities
* [CHANGELOG.md] add changelog

### Changed
* [cyclonedx_sbom] remap patch names from pedigree.patches.resolves.source.name to pedigree.patches.diff.url
* [Readme.md] Update the Using Vigiles CVE Check section
* [Readme.md] Replace manifest with SBOM in readme
* [buildroot.py] Parse package version from makefile if src override is used

### Fixed

* [checkcves.py] Fix API key parsing in 'check_linuxlink_key' function

## [v1.14.0] - 2024-03-04

### Added

* [packages.py] add patches for dependencies
* [packages.py] Include patches from multiple GLOBAL_PATCH_DIR into generated SBOM
* [feature] add option in menuconfig to generate the manifest only

### Changed

* [checkcves.py] Display warning if linuxlink_key or dashboard config not found or parsed
* [packages.py] Include patches based on package version from GLOBAL_PATCH_DIR
* [internal] updates related to cpe id variables
* [buildroot.py] Use make-pattern with make command to get the package info
* [Config.in] Replace "manifest" with "SBOM" in menuconfig

### Fixed

* [checkcves.py] Remove arch_count from the demo summary
* [buildroot.py] Fix Error handling while running make

## [v1.13.0] - 2023-08-08

### Added

* [llapi] add enterprise vigiles support
* [buildroot.py] Identify and exclude virtual packages from generated SBOM
* [packages.py] report package dependencies in the generated SBOM
* [packages.py] include package checksums in generated SBOM
* [SBOM] SBOM updates for NTIA minimum elements compliance

### Changed

* [ammendments.py] Set default values to required fields in SBOM

### Fixed

* [amendments.py] Fix excluded virtual package with the name variable missing still shows in the generated SBOM

## [v1.12.0] - 2023-02-28

### Added

* [packages.py] Include packages from BR2_EXTERNAL in generated SBOM

## [v1.11.0] - 2022-12-21

### Added

* [packages.py] find patches located in BR2_GLOBAL_PATCH_DIR

## [v1.10.1] - 2022-06-17

### Fixed

* [make] Add workaround for Make 4.3 bug

## [v1.10.0] - 2022-04-29

### Added

* [manifest] add download_location for packages
* [manifest] add package supplier for packages
* [manifest] add cpe_id for packages

### Changed

* [manifest] truncate manifest name to 256 characters
* [linuxlink] use new v1 api route for manifest upload

## [v1.9.0] - 2021-11-09

### Added

* [make] add dynamic subfolder option

### Changed

* Readme.md: updated instructions for dashboard conf

## [v1.8.2] - 2021-08-10

### Fixed

* Fix typo in args to _print_list
* Remove json load encoding parameter

## [v1.8.1] - 2021-07-12

### Fixed

* [make] Quote CONFIG'd file names to allow spaces in paths

## [v1.8.0] - 2021-01-20

### Changed

* [parser] Drop printvars output without '='

### Removed

* [config] Remove VIGILES_METADATA_ONLY option

## [v1.7.0] - 2020-12-09

### Added

* [reports] Add support to upload Manifest without waiting for CVE Report

## [v1.6.0] - 2020-12-07

### Added

* [credentials] Add ability to override via environment.
* [images] Add ability to override the manifest and report name.
* [llapi] Add verbose and non-fatal error reporting.

### Changed

* [llapi] Update LinuxLinux route and handling

## [v1.5.1] - 2020-11-10

### Fixed

* [compat] Add fixups to support Buildroot 2016.08.x

## [v1.5.0] - 2020-10-19

### Changed

* [parser] Split package makefile variable parsing into 2 steps.

### Fixed

* [whitelist] Fix typo when gathering CVE IDs from packages

## [v1.4.0] - 2020-09-30

### Added

* [linuxlink] Add support for Dashboard Folders

### Fixed

* [packages] Fixup import to resolve json module
* [packages] Fixup regex for finding CVEs in patch headers

## [v1.3.0] - 2020-07-02

### Added

* [firmware] Add support for capturing all firmware, not just u-boot.

## [v1.2.0] - 2020-06-24

### Added

* [feature] Add vigiles-image make target

## [v1.1.0] - 2020-06-09

### Added

* [features] Add support for amending CVE manifest + report
* [kconfig] Add option to enable debug output from vigiles-buildroot.

### Changed

* [internal] Streamline manifest construction WRT packages.
* [internal] Improve messaging helpers and fixup users.

## [v1.0.0] - 2020-05-08

### Added

* First vigiles-buildroot release.
