import csv
import json
import os

from collections import defaultdict

from utils import mkdirhier
from utils import dbg, info, warn


def _parse_addl_pkg_csv(extra_csv):
    extra_rows = []

    if not os.path.exists(extra_csv):
        warn("Skipping Non-Existent additional-package File: %s" % extra_csv)
        return extra_rows
    
    try:
        with open(extra_csv) as csv_in:
            reader = csv.reader(csv_in)
            for row in reader:
                if not any(row):
                    continue
                if row[0].startswith('#'):
                    continue

                pkg = row[0].strip()
                if not pkg:
                    continue

                if len(row) > 1:
                    ver = row[1].strip()
                else:
                    ver = ''
                if len(row) > 2:
                    license = row[2].strip()
                else:
                    license = 'unknown'
                extra_rows.append([pkg,ver,license])
    except Exception as e:
        warn("Additional Packages: %s" % e)
        return []
    
    # Check for a CSV header of e.g. "product,version,license" and skip it
    header = extra_rows[0]
    if header[0].lower() == "product":
        extra_rows = extra_rows[1:]

    return extra_rows


def _get_addl_packages(extra_csv):
    if not extra_csv:
        return {}

    additional = {
        'additional_licenses': defaultdict(str),
        'additional_packages': defaultdict(dict)
    }

    extra_rows = _parse_addl_pkg_csv(extra_csv)
    if not extra_rows:
        return {}

    for row in extra_rows:
        pkg = row[0].replace(' ', '-')
        ver = row[1].replace(' ', '.')
        license = row[2]
        license_key = pkg + ver

        dbg("Extra Package: %s, Version: %s, License: %s = %s" %
             (pkg, ver, license_key, license))

        pkg_vers = set(additional['additional_packages'].get(pkg, []))
        pkg_vers.add(ver)

        additional['additional_packages'][pkg] = sorted(list(pkg_vers))
        additional['additional_licenses'][license_key] = license

    dbg("Adding Package Info: %s" %
         json.dumps(additional, indent=4, sort_keys=True))
    info("Adding Packages: %s" % list(additional['additional_licenses'].keys()))

    return additional


def _get_excld_packages(excld_csv):
    if not excld_csv:
        return []

    if not os.path.exists(excld_csv):
        warn("Skipping Non-Existent exclude-package File: %s" % excld_csv)
        return []

    dbg("Importing Excluded Packages from %s" % excld_csv)

    excld_pkgs = set()
    try:
        with open(excld_csv) as csv_in:
            reader = csv.reader(csv_in)
            for row in reader:
                if not len(row):
                    continue
                if row[0].startswith('#'):
                    continue

                pkg = row[0].strip().lower()
                excld_pkgs.add(pkg.replace(' ', '-'))
    except Exception as e:
        warn("exclude-packages: %s" % e)
        return []

    dbg("Requested packages to exclude: %s" % list(excld_pkgs))
    return list(excld_pkgs)


def _filter_excluded_packages(vgls_pkgs, excld_pkgs):
    if not excld_pkgs or not vgls_pkgs:
        return

    pkg_matches = set()

    for k,v in vgls_pkgs.items():
        if v.get('name', k) in excld_pkgs:
            pkg_matches.add(k)
        
        # Also exclude pkg as dependencies
        for excld_pkg in excld_pkgs:
            try:
                v.get("dependencies", {}).get("build", []).remove(excld_pkg)
            except ValueError:
                pass

    info("Vigiles: Excluding Packages: %s" % sorted(pkg_matches))
    for pkg_key in pkg_matches:
        vgls_pkgs.pop(pkg_key)


def _get_user_whitelist(whtlst_csv):
    if not whtlst_csv:
        return []

    if not os.path.exists(whtlst_csv):
        warn("Skipping Non-Existent CVE Whitelist File: %s" % whtlst_csv)
        return []

    dbg("Importing Whitelisted CVEs from %s" % whtlst_csv)

    whtlst_cves = set()
    try:
        with open(whtlst_csv) as csv_in:
            reader = csv.reader(csv_in)
            for row in reader:
                if not len(row):
                    continue
                if row[0].startswith('#'):
                    continue

                pkg = row[0].strip().upper()
                whtlst_cves.add(pkg.replace(' ', '-'))
    except Exception as e:
        warn("whitelist-cves: %s" % e)
        return []

    dbg("Requested CVEs to Ignore: %s" % list(whtlst_cves))
    return whtlst_cves


def _get_package_whitelist(pkg_dict):
    whitelist = set()
    for pdict in pkg_dict.values():
        wl = [
            cve
            for cve in pdict.get('ignore_cves', '').split(' ')
            if cve
        ]
        whitelist.update(wl)
    return whitelist


def _build_whitelist(vgls, manifest):
    whtlst = set()
    whtlst.update(_get_user_whitelist(vgls['whtlst']))
    whtlst.update(_get_package_whitelist(manifest['packages']))
    return list(whtlst)


def _set_package_field_defaults(manifest):
    for pkg, pkg_dict in manifest["packages"].items():
        if not pkg_dict.get("version", ""):
            pkg_dict["version"] = "unset"
        if not pkg_dict.get("cve_version", ""):
            pkg_dict["cve_version"] = pkg_dict["version"]
        if not pkg_dict.get("name", ""):
            pkg_dict["name"] = pkg
        if not pkg_dict.get("cve_product", ""):
            pkg_dict["cve_product"] = pkg
        if not pkg_dict.get("license", ""):
            pkg_dict["license"] = "unknown"
        if not pkg_dict.get("checksums", ""):
            pkg_dict["checksums"] = []

    
def amend_manifest(vgls, manifest): 
    _set_package_field_defaults(manifest)
    addl_pkgs = _get_addl_packages(vgls['addl'])
    if addl_pkgs:
        manifest.update(addl_pkgs)

    excld_pkgs = _get_excld_packages(vgls['excld'])
    _filter_excluded_packages(manifest['packages'], excld_pkgs)

    whtlst_cves = _build_whitelist(vgls, manifest)
    if whtlst_cves:
        dbg("Ignoring CVEs: %s" %
            json.dumps(whtlst_cves, indent=4, sort_keys=True))
        manifest['whitelist'] = sorted(whtlst_cves)
