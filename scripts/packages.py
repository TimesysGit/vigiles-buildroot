###############################################################
#
# packages.py - Helpers for parsing Buildroot package metadata
#
# Copyright (C) 2018 - 2020 Timesys Corporation
#
#
# This source is loosely based on the Buildroot 'pkg-stats'
#  script (ca. April 2020), which is licensed under the GPLv2
#  and bears the following copyright:
#
# Copyright (C) 2009 by Thomas Petazzoni <thomas.petazzoni@free-electrons.com>
#
###############################################################

import fnmatch
import json
import os
import re

from collections import defaultdict

from utils import write_intm_json
from utils import kconfig_to_py, py_to_kconfig
from utils import dbg, info, warn


def get_package_info(vgls):
    config_dict = vgls.get('config', {})
    pkg_dict = defaultdict(lambda: defaultdict(dict))

    def _config_packages(config_dict):
        config_pkgs = set()

        fw_list =  [
            '-'.join(['target', entry.name])
            for entry in 
            os.scandir(os.path.join(vgls['topdir'], 'boot'))
            if entry.is_dir()
        ]

        for key, value in config_dict.items():
            if value is not True:
                continue

            if key.startswith('package-'):
                if not key.endswith('-supports'):
                    pkg = key[8:]
                    config_pkgs.add(pkg)
            elif key in fw_list:
                pkg = key[7:]
                dbg("Buildroot Config -- Adding Firmware: %s" % pkg)
                config_pkgs.add(pkg)
            elif key == 'linux-kernel':
                pkg = 'linux'
                dbg("Buildroot Config -- Adding Kernel: %s" % pkg)
                config_pkgs.add(pkg)

        dbg("Buildroot Config: %d possible packages (including firmware)"
            % len(config_pkgs))
        return sorted(list(config_pkgs))

    def _package_makefiles(package_list):
        """
        Builds a mapping of Buildroot package names (as defined by 'package_list')
        by walking through the Buildroot source tree.

        Originally from the pkg-stats script.
        """
        WALK_USEFUL_SUBDIRS = ["boot", "linux", "package"]
        WALK_EXCLUDES = ["boot/common.mk",
                         "linux/linux-ext-.*.mk",
                         "package/freescale-imx/freescale-imx.mk",
                         "package/gcc/gcc.mk",
                         "package/gstreamer/gstreamer.mk",
                         "package/gstreamer1/gstreamer1.mk",
                         "package/gtk2-themes/gtk2-themes.mk",
                         "package/matchbox/matchbox.mk",
                         "package/opengl/opengl.mk",
                         "package/qt5/qt5.mk",
                         "package/x11r7/x11r7.mk",
                         "package/doc-asciidoc.mk",
                         "package/pkg-.*.mk",
                         "package/nvidia-tegra23/nvidia-tegra23.mk"]
        pkg_dict = defaultdict()
        for root, dirs, files in os.walk("."):
            rootdir = root.split("/")
            if len(rootdir) < 2:
                continue
            if rootdir[1] not in WALK_USEFUL_SUBDIRS:
                continue
            for f in files:
                if not f.endswith(".mk"):
                    continue
                # Strip ending ".mk"
                pkgname = kconfig_to_py(f[:-3])
                if package_list and pkgname not in package_list:
                    continue
                pkgpath = os.path.join(root, f)
                skip = False
                for exclude in WALK_EXCLUDES:
                    # pkgpath[2:] strips the initial './'
                    if re.match(exclude, pkgpath[2:]):
                        skip = True
                        continue
                if skip:
                    continue
                pkg_dict[pkgname] = os.path.relpath(pkgpath)
        dbg("Found %d packages" % len(pkg_dict.keys()))
        return pkg_dict


    def _patched_cves(src_patches):
        patched_dict = dict()

        cve_match = re.compile("CVE:( CVE\-\d{4}\-\d+)+")

        # Matches last CVE-1234-211432 in the file name, also if written
        # with small letters. Not supporting multiple CVE id's in a single
        # file name.
        cve_file_name_match = re.compile(".*([Cc][Vv][Ee]\-\d{4}\-\d+)")

        for patch_path in src_patches:
            found_cves = list()

            patch_name = os.path.basename(patch_path)
            # Check patch file name for CVE ID
            fname_match = cve_file_name_match.search(patch_name)
            if fname_match:
                cve = fname_match.group(1).upper()
                found_cves.append(cve)

            with open(patch_path, "r", encoding="utf-8") as f:
                try:
                    patch_text = f.read()
                except UnicodeDecodeError:
                    info(vgls, "Failed to read patch %s using UTF-8 encoding"
                          " trying with iso8859-1" % patch_path)
                    f.close()
                    with open(patch_path, "r", encoding="iso8859-1") as f:
                        patch_text = f.read()

            # Search for one or more "CVE: " lines
            for match in cve_match.finditer(patch_text):
                # Get only the CVEs without the "CVE: " tag
                cves = patch_text[match.start() + 5:match.end()]
                dbg("Patches: Matched CVEs for Someone: %s" % json.dumps(cves))
                for cve in cves.split():
                    found_cves.append(cve)

            if len(found_cves):
                dbg("Patches: Found CVEs for Someone: %s" % json.dumps(found_cves))

            for cve in found_cves:
                entry = patched_dict.get(cve, list())
                if patch_name not in entry:
                    entry.append(patch_name)
                patched_dict.update({cve: entry})

        if len(patched_dict.keys()):
            dbg("Patches: Patched CVEs for Someone: %s" % json.dumps(patched_dict))

        return {
            key: sorted(patched_dict[key])
            for key in sorted(patched_dict.keys())
        }


    def _pkg_patches(pkg):
        makefile = pkg.get('makefile', '')
        patch_list = []

        if not makefile:
            return

        makedir = os.path.dirname(makefile)
        for subdir, _, _ in os.walk(makedir):
            patch_list.extend(
                fnmatch.filter(
                    [p.path for p in os.scandir(subdir)],
                    '*.patch'
                )
            )
        if patch_list:
            pkg['patches'] = sorted([
                os.path.basename(p) for p in patch_list
            ])
            pkg['patched_cves'] = _patched_cves(patch_list)
            if pkg['patched_cves']:
                dbg("Patched CVEs for %s" % pkg['name'],
                    [
                        "Total Patches: %d" % len(patch_list),
                        "Patch List: %s" % json.dumps(
                            patch_list,
                            indent=12,
                            sort_keys=True
                        ),
                        "CVEs: %s" % json.dumps(
                            pkg['patched_cves'],
                            indent=12,
                            sort_keys=True
                        )
                    ]
                )



    pkg_list = _config_packages(config_dict)

    if not pkg_list:
        warn("No packages found in Buildroot .config.")
        return None

    known_packages = _package_makefiles(pkg_list)

    if not known_packages:
        warn("No configured packages seem to exist in tree.")
        return None

    for name, makefile in known_packages.items():
        pkg_dict[name]['name'] = name
        pkg_dict[name]['makefile'] = makefile
        _pkg_patches(pkg_dict[name])

    write_intm_json(vgls, 'config-packages', pkg_dict)
    return pkg_dict
