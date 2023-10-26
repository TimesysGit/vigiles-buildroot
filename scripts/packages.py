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

from utils import write_intm_json, get_external_dirs
from utils import kconfig_to_py, py_to_kconfig
from utils import dbg, info, warn, err

def get_patches(vgls):
    def _patched_cves(src_patches):
        patched_dict = dict()

        cve_match = re.compile("CVE\-\d{4}\-\d+")

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

            # Search for one or more "CVE-XXXX-XXXX+" lines
            for match in cve_match.finditer(patch_text):
                found_cves.append(match.group())

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
        makefile = pkg_make_map.get(pkg.get("rawname", pkg.get("name")), "")
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
        
        # Include patches in global patch directory
        if global_patch_dir:
            pkg_patch_dir = os.path.join(global_patch_dir, pkg.get("name", ""), pkg.get("version", pkg.get("cve_version", "")))
            if not os.path.exists(pkg_patch_dir):
                pkg_patch_dir = os.path.join(global_patch_dir, pkg.get("name", ""))
            
            if os.path.exists(pkg_patch_dir):
                patch_list.extend(
                    fnmatch.filter(
                        [p.path for p in os.scandir(pkg_patch_dir)],
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

    pkg_make_map = vgls.get("pkg_make_map", {})
    config_dict = vgls.get('config', {})
    global_patch_dir = config_dict.get("global-patch-dir", None)

    for pkg, pkg_dict in vgls.get("packages", {}).items():
        _pkg_patches(pkg_dict)
    return vgls['packages']


def get_package_info(vgls):
    config_dict = vgls.get('config', {})
    all_pkg_make_info = vgls.get('all_pkg_make_info', {})
    pkg_dict = defaultdict(lambda: defaultdict(dict))
    global_patch_dir = config_dict.get("global-patch-dir", None)

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
        
        def _get_pkg_dict(layer_dir):
            for root, dirs, files in os.walk(layer_dir):
                rootdir = root.replace(layer_dir, "").split("/")
                if len(rootdir) < 2:
                    continue
                if rootdir[1] not in WALK_USEFUL_SUBDIRS:
                    continue
                for f in files:
                    if not f.endswith(".mk"):
                        continue
                    # Strip ending ".mk"
                    pkgname = f[:-3]
                    pkgname = all_pkg_make_info.get(pkgname, {}).get("name", kconfig_to_py(pkgname))
                    pkgpath = os.path.join(root, f)
                    skip = False
                    for exclude in WALK_EXCLUDES:
                        # pkgpath[2:] strips the initial './'
                        if re.match(exclude, pkgpath[2:]):
                            skip = True
                            continue
                    if skip:
                        continue
                    if package_list and pkgname in package_list:
                        pkg_dict[pkgname] = os.path.relpath(pkgpath)
                    
                    # add makefiles to pkg_make_map map
                    pkg_make_map[pkgname] = os.path.relpath(pkgpath)

        pkg_make_map = defaultdict()
        pkg_dict = defaultdict()
        
        _get_pkg_dict(".")
        
        ext_dirs = get_external_dirs(vgls)
        if ext_dirs:
            for d in ext_dirs:
                _get_pkg_dict(d)

        dbg("Found %d packages" % len(pkg_dict.keys()))
        vgls["pkg_make_map"] = pkg_make_map
        return pkg_dict

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
        pkg_dict[name]['component_type'] = ["component"]

    write_intm_json(vgls, 'config-packages', pkg_dict)
    return pkg_dict


def get_package_dependencies(vgls, packages):
    def _get_pkg_make_info(pkg):
        kconfig_pkg = py_to_kconfig(pkg)
        kconfig_pkg_info = all_pkg_make_info.get(kconfig_pkg, {})
        return kconfig_pkg_info

    def _fixup_deps(deps):
        # Replaces the package names with their raw package names
        fixed_deps = set()
        include_virtual_pkgs = vgls.get("include_virtual_pkgs")
        for dep in deps:
            kconfig_dep_info = _get_pkg_make_info(dep)
            fixed_dep_name = kconfig_dep_info.get("rawname", dep)
            if not include_virtual_pkgs:
                is_virtual = _get_pkg_make_info(fixed_dep_name).get("is-virtual")
                if is_virtual:
                    continue
            fixed_deps.add(fixed_dep_name)
        return sorted(list(fixed_deps))

    def _get_build_dependencies(pkg):
        package_dict = _get_pkg_make_info(pkg)
        if package_dict:
            dependencies = package_dict.get("dependencies", [])
            return dependencies
        return []

    def _get_runtime_dependencies(pkg):
        pkg = _get_pkg_make_info(pkg).get("rawname", pkg)
        runtime_deps = set()
        if pkg == 'linux':
            config_path = os.path.join(".", pkg, "Config.in")
        else:
            dirs = ["boot", "package", "toolchain"]
            for dir in dirs:
                config_path = os.path.join(".", dir, pkg, "Config.in")
                if os.path.exists(config_path):
                    break

        if os.path.exists(config_path):
            with open(config_path, "r") as config_file:
                config = config_file.read()

            match = re.findall(r'select BR2_PACKAGE_(.*) #\s*(runtime|run-time)'.format(pkg), config)
            if match:
                for pkg_str, _ in match:
                    pkgname = pkg_str.split()[0] or ""
                    pkgname = all_pkg_make_info.get(pkgname, {}).get("rawname", kconfig_to_py(pkgname))
                    runtime_deps.add(pkgname)
        else:
            missing_configs.add(pkg)

        runtime_deps = [dep for dep in runtime_deps if _get_pkg_make_info(dep)]
        return runtime_deps

    def add_dependencies(pkg):
        # runtime dependencies
        runtime_deps = _get_runtime_dependencies(pkg)
        dbg("Runtime dependencies for %s: %s" % (pkg, runtime_deps))
        include_deps_as_pkgs(runtime_deps, "runtime")
        
        # build dependencies
        build_deps = _get_build_dependencies(pkg)
        dbg("Build dependencies for %s: %s" % (pkg, build_deps))
        include_deps_as_pkgs(build_deps, "build")

        pkg_dict[pkg]["dependencies"] = {
            "build": _fixup_deps(build_deps),
            "runtime": _fixup_deps(runtime_deps)
        }

    def include_deps_as_pkgs(deps, component_type):
        dependency_only_comment = {
            "build": "Dependency Only; This component was identified as a build dependency by Vigiles",
            "runtime": "Dependency Only; This component was identified as a runtime dependency by Vigiles",
            "build&runtime": "Dependency Only; This component was identified as a build and runtime dependency by Vigiles",
        }
        for dep in deps:
            fixed_dep = _get_pkg_make_info(dep).get("rawname")
            if fixed_dep and fixed_dep in pkg_dict.keys():
                _update_comments(fixed_dep, component_type, dependency_only_comment)
            elif dep not in pkg_dict.keys():
                pkg_dict[dep]["comment"] = dependency_only_comment[component_type]
                pkg_dict[dep]["component_type"] = [component_type]
                add_dependencies(dep)
                dep_pkgs.add(dep)
            else:
                _update_comments(dep, component_type, dependency_only_comment)

    def _update_comments(dep, component_type, comment_map):
        component_type_list = pkg_dict[dep].get("component_type", [])
        if component_type and component_type not in component_type_list:
            pkg_dict[dep]["component_type"].append(component_type)
            pkg_dict[dep]["component_type"].sort()
        if "component" not in component_type_list:
            if "build" in component_type_list and "runtime" in component_type_list:
                pkg_dict[dep]["comment"] = comment_map["build&runtime"]
            elif "build" in component_type_list:
                pkg_dict[dep]["comment"] = comment_map["build"]
            elif "runtime" in component_type_list:
                pkg_dict[dep]["comment"] = comment_map["runtime"]

    missing_configs = set()
    dep_pkgs = set()
    all_pkg_make_info = vgls["all_pkg_make_info"]
    pkg_dict = packages.copy()

    for pkg, _ in packages.items():
        add_dependencies(pkg)
    
    if missing_configs:
        warn("Config.in not found for packages: %s" % list(missing_configs))

    vgls['packages'] = pkg_dict


def _get_pkg_hash_map(vgls):
    pkg_hash_map = {}
    dirs = ["package", "boot", "linux"]
    for dir in dirs:
        dir_path = os.path.join(vgls["topdir"], dir)
        for root, dir, files in os.walk(dir_path):
            for f in files:
                if f.endswith(".hash"):
                    pkg = os.path.basename(root)
                    hash_path = os.path.join(root, f)
                    pkg_hash_map[pkg] = hash_path
    return pkg_hash_map


def get_checksum_info(vgls):
    allowed_checksums = ("SHA1", "SHA224", "SHA256", "SHA384", "SHA512", "MD2", "MD4", "MD5", "MD6")
    pkg_hash_map = _get_pkg_hash_map(vgls)

    missing_hashfiles = []

    for pkg, pkg_info in vgls['packages'].items():
        checksums = []
        hash_fp = pkg_hash_map.get(pkg, "")
        if not os.path.exists(hash_fp):
            missing_hashfiles.append(pkg)
            continue

        with open(hash_fp, "r") as f:
            for line in f.readlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                data = line.split()
                if len(data) != 3:
                    continue
                algo, checksum, filename = data
                if algo.upper() not in allowed_checksums:
                    continue

                download_location = pkg_info.get("download_location", "")
                download_filename = os.path.basename(download_location)
                if filename == download_filename:
                    checksums.append({
                        "algorithm": algo.upper(),
                        "checksum_value": checksum
                    })
        
            pkg_info["checksums"] = checksums

    if missing_hashfiles:
        warn(".hash files not found for packages: %s" % missing_hashfiles)
    return vgls['packages']
