###############################################################
#
# br2_make.py - Helpers for parsing Buildroot make variables
#
# Copyright (C) 2018 - 2020 Timesys Corporation
#
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

from utils import py_to_kconfig, kconfig_to_py, kconfig_bool
from utils import write_intm_json
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
    'srcdir'
]

br2_user_pkg_vars = [
    'cve-product',
    'cve-version',
    'ignore-cves',
    'license',
    'version',
    'pkg-cpe-id',
    'site-method',
    'site',
    'source',
    'spdx-org',
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
        package_vars.extend([
            '-'.join([p, var])
            for var in br2_internal_pkg_vars + br2_user_pkg_vars + br2_cpe_id_components
        ])

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


def _get_make_output(odir, var_string):
    try:
        variables = subprocess.check_output(
            [
                "make",
                ("O=%s" % odir),
                "BR2_HAVE_DOT_CONFIG=y",
                "-s",
                "printvars",
                ("VARS=%s" % var_string)
            ]
        )
    except Exception as e:
        err([
            " Could not execute Buildroot Make process",
            "Error: %s" % e,
        ])
        return None
    return [var for var in variables.decode().splitlines() if '=' in var]


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
                if var.startswith('host-'):
                    continue
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
                pkg_dict[pkgname][pkgkey] = value
                break

        for pkgkey in br2_user_pkg_vars + br2_cpe_id_components:
            pkgvar = '-' + pkgkey
            if key.endswith(pkgvar):
                pkgname = key[:-len(pkgvar)]
                if pkgname not in pkg_dict:
                    continue
                if pkgkey not in ['license', 'ignore-cves', 'spdx-org']:
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

    for name, pdict in pkg_dict.items():
        rawname = pdict.get('rawname', name)
        if rawname != name:
            rawname_fixups[name] = rawname

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

        # Remove br2_cpe_id_components from pkg_dict once cpe id is generated
        for item in br2_cpe_id_components:
            try:
                del pkg_dict[name][item]
            except KeyError:
                # key doesn't exist, continue
                continue

        # Add package supplier
        pkg_dict[name]['package-supplier'] = f"Organization: {pdict.get('spdx-org', 'Buildroot ()')}"
        if 'spdx-org' in pdict.keys():
            del pkg_dict[name]['spdx-org']

    for name, pdict in pkg_dict.items():
        pdict['cve-version'] = _sanitize_version(vgls, pdict['cve-version'])
        if 'builddir' in pdict:
            pdict['builddir'] = os.path.join(vgls['bdir'], pdict['builddir'])
        if 'srcdir' in pdict:
            pdict['srcdir'] = os.path.join(vgls['bdir'], pdict['srcdir'])

    for virt, real in providers.items():
        if real in pkg_dict:
            pkg_dict[virt]['provider'] = real
            for key in ['version', 'cve-version', 'license']:
                virt_value = pkg_dict[virt].get(key, 'unset')
                pkg_dict[virt][key] = pkg_dict[real].get(key, virt_value)

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
        return None

    vgls['make'] = _transform_make_info(vgls, variable_list)
    make_dict = _fixup_make_info(vgls)

    write_intm_json(vgls, 'make-vars', make_dict)
    return make_dict
