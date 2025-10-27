###############################################################
#
# br2_make.py - Helpers for parsing Buildroot make variables
#
# Copyright (C) 2018 - 2020 Timesys Corporation
# Copyright (C) 2025 Lynx Software Technologies, Inc. All rights reserved.
#
# This source is released under the MIT License.
#
# Partially inspired by the Buildroot 'pkg-stats' script.
#
###############################################################

import os
import re
import subprocess

from collections import defaultdict

from kernel_uboot import _get_version_from_makefile
from manifest import DEFAULT_SUPPLIER
from utils import py_to_kconfig, kconfig_to_py, kconfig_bool
from utils import write_intm_json, get_valid_los
from utils import dbg, info, warn, err


def _find_dot_config(vgls):
    odir_dot_config = os.path.join(vgls['odir'], '.config')
    topdir_dot_config = os.path.join(vgls['topdir'], '.config')
    curdir_dot_config = os.path.join(os.curdir, '.config')

    if os.path.exists(odir_dot_config):
        dot_config = odir_dot_config
    elif os.path.exists(topdir_dot_config):
        dot_config = topdir_dot_config
    elif os.path.exists(curdir_dot_config):
        dot_config = curdir_dot_config
    else:
        dot_config = None
    return dot_config


def get_config_options(vgls):
    config_dict = defaultdict()
    config_options = []

    dot_config = _find_dot_config(vgls)
    if not dot_config:
        err([
            "No Buildroot .config found.",
            "Please configure the Buildroot build.",
            "Or, specify the build directory on the command line"
        ])
        return None

    dbg("Using Buildroot Config at %s" % dot_config)
    try:
        with open(dot_config, 'r') as config_in:
            config_options = [
                f_line.rstrip()[4:]
                for f_line in config_in
                if f_line.startswith('BR2_')
            ]
    except Exception as e:
        err([
            "Could not read/parse Buildroot .config",
            "File: %s" % dot_config,
            "Error: %s" % e,
        ])
        return None

    for opt in config_options:
        key, value = opt.split('=', 1)
        key = kconfig_to_py(key)
        value = kconfig_bool(value.replace('"', ''))
        config_dict[key] = value

    dbg("Buildroot Config: %d Options" % len(config_dict.keys()))
    write_intm_json(vgls, 'config-vars', config_dict)
    return config_dict


br2_internal_pkg_vars = [
    'builddir',
    'is-virtual',
    'rawname',
    'srcdir',
    'override-srcdir'
]

br2_user_pkg_vars = [
    'ignore-cves',
    'license',
    'version',
    'pkg-cpe-id',
    'site-method',
    'site',
    'source',
    'spdx-org',
    'release-date',
    'end-of-life',
    'level-of-support'
]

br2_cpe_id_components = [
    'cpe-id-prefix',
    'cpe-id-vendor',
    'cpe-id-product',
    'cpe-id-version',
    'cpe-id-update',
    'cpe-id-edition',
    'cpe-id-language',
    'cpe-id-software-edition',
    'cpe-id-target-software',
    'cpe-id-target-hardware',
    'cpe-id-other',
]

def _get_make_variables(packages):
    package_vars = []

    for p in packages:
        package_vars.append("%s-%%" % p)

    br2_single = [
        '-'.join(['br2', var])
        for var in [
            "arch",
            "defconfig",
            "version",
        ]
    ]
    br2_multi = [
        '-'.join(['br2', var + '%'])
        for var in [
            "gcc-target",
            "linux-kernel",
            "package",
            "target-uboot",
        ]
    ]
    var_string = py_to_kconfig(
        ' '.join(package_vars + br2_single + br2_multi)
    )
    return var_string


def _run_make(mk_opts=[], mk_args=[], mk_context=[]):
    mk_cmd = ['make', '-s']

    mk_output = ""
    try:
        mk_output = subprocess.check_output(
            mk_context + mk_cmd + mk_opts + mk_args
        ).decode()
    except Exception as exc:
        err('Could not execute Make',
        [    
            f'Command:   {mk_cmd}',
            f'Arguments: {mk_args}',
            f'Context:   {mk_context}',
            f'Error: {exc}'
        ])
    return mk_output


def _have_buggy_make():
    MakeStackBugVersions = ['4.3']

    mk_output = _run_make(mk_args=['--version'])
    mk_ver = mk_output.splitlines()[0].split()[-1]
    have_bug = (mk_ver in MakeStackBugVersions)
    if have_bug:
        info(f'Detected buggy Make version ({mk_ver}); working around..')
    else:
        dbg(f'Make version Ok ({mk_ver})')
    return have_bug


def _printvars(odir, var_string, mk_context=[]):
    vgls_opts = [f'O={odir}', 'BR2_HAVE_DOT_CONFIG=y']
    printvar_args = ['printvars', f'VARS={var_string}']
    return _run_make(vgls_opts, printvar_args, mk_context)


def _printvars_workaround(odir, var_string):
    from pathlib import Path
    from tempfile import NamedTemporaryFile
    from resource import getrlimit, setrlimit, RLIMIT_STACK
    from shutil import copy as sh_copy

    # Step 1 -- Undo the Buildroot fixup.
    #  Backup the Buildroot Makefile
    f_make = Path(Path.cwd(), 'Makefile')
    f_backup = f_make.with_suffix('.vgls-orig')

    try:
        sh_copy(f_make, f_backup)
    except Exception as exc:
        err([
            f'make-workaround: Could not backup {f_name} to {f_backup}',
            f'Error: {exc}'
        ])
        raise exc
    dbg(f'make-workaround: Makefile backed up at {f_backup}')

    # Step 2 -- Fixup the Makefile
    #  Remove printvars dependencies
    try:
        f_make.write_text(
            re.compile(r'\nprintvars:.*').sub(
                '\nprintvars:', f_make.read_text()
            )
        )
    except Exception as exc:
        err([
            f'make-workaround: Could not fixup {f_make}',
            f'Error: {exc}'
        ])
        f_backup.replace(f_make)
        raise exc

    # Step 3 -- Set workaround context for the upstream Make bug
    #  Increase the process stack limit when run make
    fixup_context = ['/usr/bin/env', 'prlimit', '--stack=16777216:']

    # Step 4 -- Actually run 'make printvars'
    dbg(f'make-workaround: Calling "make printvars"..')
    mk_output = _printvars(odir, var_string, fixup_context)

    # Step 4 -- Cleanup
    dbg(f'make-workaround: Cleaning up')
    f_backup.replace(f_make)

    return mk_output


def _get_make_output(odir, var_string):
    if _have_buggy_make():
        mk_output = _printvars_workaround(odir, var_string)
    else:
        mk_output = _printvars(odir, var_string)

    return [
        var for var in mk_output.splitlines() if '=' in var
    ]


def _transform_make_info(vgls, variable_list):
    pkg_dict = vgls['packages']
    make_dict = defaultdict(lambda: defaultdict(dict))

    for v in variable_list:
        key, value = v.split('=', 1)
        key = kconfig_to_py(key)
        value = kconfig_bool(value.replace('"', ''))

        if not value:
            continue

        if key.startswith('br2-'):
            key = key[4:]
            if key.startswith('package-provides-'):
                var = key[17:]
                make_dict['providers'][var] = value
            elif key.startswith('package-'):
                var = key[8:]
                if var.startswith('host-') or var.endswith('-supports'):
                    continue
                make_dict['br2']['packages'][var] = value
            elif key.startswith('linux-kernel-'):
                var = key[13:]
                make_dict['br2']['kernel'][var] = value
            elif key.startswith('target-uboot-'):
                var = key[13:]
                make_dict['br2']['uboot'][var] = value
            elif key.startswith('gcc-target-'):
                var = key[11:]
                make_dict['br2']['gcc'][var] = value
            else:
                make_dict['br2']['meta'][key] = value
            continue

        #
        # The following is done in 2 loops to first gather the automatically
        # set variables by the build system to prime the list of known
        # packages; then to gather the variables that can be over-ridden
        # by the package makefiles, checking if the package is already known
        # in the 2nd.
        # This is done in case there are conflicts where the name of one
        # variable is a subset of another and separated with the only
        # delimeter we can use ('_' in makefiles, transformed to '-' here),
        # and because we don't want to rely on the order of the list of 
        # variables above for priority or the order of the incoming strings
        # to parse.
        # Think 'foo-version' vs. 'foo-cve-version' -- if 'version' is in
        # the list first, but 'foo-cve-version' is parsed first, then a bogus
        # 'foo-cve' package would be added.
        # Sure, if everything is guaranteed to be in alphabetical order, that
        # particular example is moot, but will that always be the case for
        # what we need to parse (i.e. it's 'future-proof').
        for pkgkey in br2_internal_pkg_vars:
            pkgvar = '-' + pkgkey
            if key.endswith(pkgvar):
                pkgname = key[:-len(pkgvar)]
                if pkgkey == 'rawname':
                    value = value.split(' ')[0]
                if pkgname not in pkg_dict.keys():
                    continue
                pkg_dict[pkgname][pkgkey] = value
                break

        for pkgkey in br2_user_pkg_vars + br2_cpe_id_components:
            pkgvar = '-' + pkgkey
            if key.endswith(pkgvar):
                pkgname = key[:-len(pkgvar)]
                if pkgname not in pkg_dict:
                    continue
                if pkgkey not in ['license', 'ignore-cves', 'spdx-org', 'level-of-support']:
                    value = value.split(' ')[0]

                if key.endswith('-site'):
                    pkg_dict[pkgname]['download_location'] = value
                    break
                elif key.endswith('source'):
                    if pkg_dict[pkgname]['site-method'] != 'git':
                        pkg_dict[pkgname]['download_location'] = os.path.join(pkg_dict[pkgname]['download_location'], value)

                    del pkg_dict[pkgname]['site-method']
                    break

                if not pkg_dict[pkgname]['download_location']:
                    pkg_dict[pkgname]['download_location'] = 'UNKNOWN'

                pkg_dict[pkgname][pkgkey] = value
                break

    write_intm_json(vgls, 'packages-makevars-raw', pkg_dict)
    return make_dict


shaver_string = '[0-9A-Fa-f]{40}'
shaver_straight = re.compile('^%s$' % shaver_string)
shaver_appendage = re.compile('%s%s$' % (re.escape('-g'), shaver_string))

def _sanitize_version(vgls, version_in):
    sha_match = shaver_appendage.search(version_in)
    version_out = version_in \
        if not sha_match \
        else version_in.replace(sha_match.group(), '')
    if version_out != version_in:
        info("CVE Version Fixed Up: %s -> %s" % (version_in, version_out))
    return version_out


def _is_valid_cpe_id(cpe_id):
    cpe22type = r'''c[pP][eE]:[aho](?::(?:[a-zA-Z0-9!\"#$%&'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+){3}$'''
    cpe23type = r"cpe:2\.3:[aho](?::(?:[a-zA-Z0-9!\"#$%&'()*+,\\\-_.\/;<=>?@\[\]^`{|}~]|\\:)+){10}$"
    return True if (re.fullmatch(cpe22type, cpe_id) or re.fullmatch(cpe23type, cpe_id)) else False


def _generate_cpe_id(pkg_info):
    cpe_id = ""
    for item in br2_cpe_id_components:
        cpe_id += f"{pkg_info.get(item, '*')}:"

    cpe_id = cpe_id[:-1]  # remove extra colon at the end of string
    return cpe_id if _is_valid_cpe_id(cpe_id) else "UNKNOWN"


def _fixup_make_info(vgls):
    make_dict = vgls['make']
    pkg_dict = vgls['packages']
    providers = make_dict.get('providers', {})
    rawname_fixups = defaultdict()
    all_pkg_make_info = vgls.get('all_pkg_make_info', {})

    for name, pdict in pkg_dict.items():
        rawname = pdict.get('rawname', name)
        if rawname != name:
            rawname_fixups[name] = rawname

        # Get cve_product and cve_version from cpe variables
        cpe_product = pdict.get('cpe-id-product')
        if cpe_product:
            pdict["cve-product"] = cpe_product
        
        override_srcdir = pdict.get('override-srcdir')
        cpe_version = pdict.get('cpe-id-version', '')
        if cpe_version:
            if cpe_version == 'custom' and override_srcdir:
                if os.path.exists(override_srcdir):
                    version = _get_version_from_makefile(override_srcdir)
                    if version:
                        pdict['cve-version'] = pdict['version'] = version
                        pdict['cpe-id-version'] = version
                    else:
                        warn("Unable to parse version for package %s" % name)
                else:
                    warn("Invalid Source override path given for package %s: %s" % (name, override_srcdir))
                del pdict['override-srcdir']
            else:
                cpe_update = pdict.get('cpe-id-update', '')
                _cve_version = cpe_version
                
                if cpe_update and cpe_update != "*":
                    _cve_version += cpe_update
                    
                pdict['cve-version'] = _cve_version

    for current, needed in rawname_fixups.items():
        pkg_dict[needed] = pkg_dict.pop(current, {})
        pkg_dict[needed]['name'] = needed

    for name, pdict in pkg_dict.items():
        if 'name' not in pdict:
            pkg_dict[name]['name'] = name
        if not pdict.get('version', ''):
            pkg_dict[name]['version'] = 'unset'
        if 'license' not in pdict:
            pkg_dict[name]['license'] = 'unknown'
        if 'cve-product' not in pdict:
            pkg_dict[name]['cve-product'] = name
        if not pdict.get('cve-version', ''):
            pkg_dict[name]['cve-version'] = pdict['version']
        if pdict.get('pkg-cpe-id', ''):
            pkg_dict[name]['cpe-id'] = pdict['pkg-cpe-id']
            del pkg_dict[name]['pkg-cpe-id']
        else:
            # Generate CPE ID using br2_cpe_id_components
            pkg_dict[name]['cpe-id'] = _generate_cpe_id(pdict)

        # Validate the level_of_support value
        if pkg_dict[name]['level-of-support']:
            level_of_support = pkg_dict[name]['level-of-support']
            los_value = get_valid_los(level_of_support)
            if los_value:
                pkg_dict[name]['level-of-support'] = los_value
            else:
                del pkg_dict[name]['level-of-support']
                warn("Invalid level_of_support '%s' for package '%s'. Refer to the README for valid values."% (level_of_support, name))

        # Remove br2_cpe_id_components from pkg_dict once cpe id is generated
        for item in br2_cpe_id_components:
            try:
                del pkg_dict[name][item]
            except KeyError:
                # key doesn't exist, continue
                continue

        # Add package supplier
        pkg_dict[name]['package-supplier'] = f"Organization: {pdict.get('spdx-org', DEFAULT_SUPPLIER)}"
        if 'spdx-org' in pdict.keys():
            del pkg_dict[name]['spdx-org']

    for name, pdict in pkg_dict.items():
        pdict['version'] = _sanitize_version(vgls, pdict['version'])
        pdict['cve-version'] = _sanitize_version(vgls, pdict['cve-version'])
        if 'builddir' in pdict:
            pdict['builddir'] = os.path.join(vgls['bdir'], pdict['builddir'])
        if 'srcdir' in pdict:
            pdict['srcdir'] = os.path.join(vgls['bdir'], pdict['srcdir'])

    excluded_virtual_pkgs = []
    include_virtual_pkgs = vgls.get("include_virtual_pkgs")
    for virt, real in providers.items():
        if include_virtual_pkgs:
            if real in pkg_dict:
                pkg_dict[virt]['provider'] = real
                # For virtual packages set version of its provider
                for key in ['version', 'cve-version']:
                    virt_value = pkg_dict[virt].get(key, 'unset')
                    pkg_dict[virt][key] = pkg_dict[real].get(key, virt_value)

    # some pkgs like toolchain and toolchain-buildroot, doesnt have provider details
    # so exclude virtual packages using global make dict
    pkgs = list(pkg_dict.keys())
    if not include_virtual_pkgs:
        for pkg in pkgs:
            kconfig_virt_pkg = py_to_kconfig(pkg)
            pkg_info = all_pkg_make_info.get(kconfig_virt_pkg, {})
            is_virtual = pkg_info.get("is-virtual", False)
            if is_virtual:
                virt_pkg = pkg_info.get("rawname", pkg)
                if virt_pkg in pkg_dict:
                    del pkg_dict[virt_pkg]
                    excluded_virtual_pkgs.append(virt_pkg)

    if not include_virtual_pkgs and excluded_virtual_pkgs:
        info("Excluded virtual packages from SBOM: %s" % excluded_virtual_pkgs)

    # For packages with missing versions check for version in makefile 
    # Scripts included with buildroot mostly does not have a version in makefile, 
    # So set the version to buildroot version/commit hash

    br_version = make_dict.get("br2",{}).get("meta",{}).get("version")
    if not br_version:
        try:
            br_version = subprocess.check_output([
                    'git', 'rev-parse', 'HEAD'
                ]).splitlines()[0].decode()
        except Exception as e:
            warn("Could not determine Buildroot git HEAD.")
            warn("\tError: %s" % e)
            br_version = 'Release'

    for pkg, pdict in pkg_dict.items():
        if not pdict.get("version") or pdict.get("version") == "unset":
            version = br_version
            pdict["version"] = pdict["cve_version"] = _sanitize_version(vgls, version)

    write_intm_json(vgls, 'packages-makevars-fixedup', pkg_dict)
    return make_dict


def get_make_info(vgls):
    # Executing make is very time-consuming, so do it just once and
    # fetch all variables at once -- packages, build data, and all
    # that we'll need for kernel and u-boot metadata.

    odir = vgls['odir']
    pkg_dict = vgls['packages']

    var_string = _get_make_variables(pkg_dict.keys())
    variable_list = _get_make_output(odir, var_string)
    if not variable_list:
        info('No make variables found')
        return None

    vgls['make'] = _transform_make_info(vgls, variable_list)
    make_dict = _fixup_make_info(vgls)

    write_intm_json(vgls, 'make-vars', make_dict)
    return make_dict


def get_all_pkg_make_info(odir):
    # This gets the make info for all the packages in buildroot
    make_vars = [
        "FINAL_RECURSIVE_DEPENDENCIES",
        "IS_VIRTUAL",
        "RAWNAME"
    ]

    make_dict = {}
    var_list = ["%_" + var for var in make_vars]
    var_string = " ".join(var_list)
    variable_list = _get_make_output(odir, var_string)
    if not variable_list:
        warn('No make variables found')
        return make_dict
    
    for var in variable_list:
        key, value = var.split("=")

        for mk_key in make_vars:
            if not key.endswith(mk_key):
                continue
            pkg = key[:-len("_"+mk_key)]
            if pkg not in make_dict.keys():
                make_dict[pkg] = {}

            if mk_key == "FINAL_RECURSIVE_DEPENDENCIES":
                make_dict[pkg]["dependencies"] = value.strip().split(" ")
            else:
                make_dict[pkg][kconfig_to_py(mk_key)] = kconfig_bool(value.strip())

    return make_dict

