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


def get_config_options(vgls):
    odir = vgls['bdir']
    config_dict = defaultdict()
    config_options = []
    dot_config = os.path.join(odir, '.config')

    if not os.path.exists(dot_config):
        print("ERROR: No Buildroot .config found.")
        print("\tPlease configure the Buildroot build,")
        print("\tor specify the build directory on the command line")
        return None

    print("Using Buildroot Config at %s" % dot_config)
    with open(dot_config, 'r') as config_in:
        config_options = [
            f_line.rstrip()[4:]
            for f_line in config_in
            if f_line.startswith('BR2_')
        ]

    for opt in config_options:
        key, value = opt.split('=', 1)
        key = kconfig_to_py(key)
        value = kconfig_bool(value.replace('"', ''))
        config_dict[key] = value

    print("Buildroot Config: %d Options" % len(config_dict.keys()))
    write_intm_json(vgls, 'config-vars', config_dict)
    return config_dict

br2_pkg_var_list = [
    'builddir',
    'is-virtual',
    'license',
    'version',
    'cve-product',
    'cve-version',
    'ignore-cves',
    'srcdir'
]


def _get_make_variables(packages):
    package_vars = []

    for p in packages:
        package_vars.extend([
            '-'.join([p, var])
            for var in br2_pkg_var_list
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
    return variables.decode().splitlines()


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

        for pkgkey in br2_pkg_var_list:
            pkgvar = '-' + pkgkey
            if key.endswith(pkgvar):
                pkgname = key[:-len(pkgvar)]
                make_dict[pkgkey][pkgname] = value
                pkg_dict[pkgname][pkgkey] = value
                break

    write_intm_json(vgls, 'packages-makevars-raw', pkg_dict)
    return make_dict


shaver_string = '[0-9A-Fa-f]{40}'
shaver_straight = re.compile('^%s$' % shaver_string)
shaver_appendage = re.compile('%s%s$' % (re.escape('-g'), shaver_string))

def _sanitize_version(version_in):
    sha_match = shaver_appendage.search(version_in)
    version_out = version_in \
        if not sha_match \
        else version_in.replace(sha_match.group(), '')
    if version_out != version_in:
        print("CVE Version Fixed Up: %s -> %s" % (version_in, version_out))
    return version_out


def _fixup_make_info(vgls):
    make_dict = vgls['make']
    pkg_dict = vgls['packages']
    providers = make_dict.get('providers', {})

    for name, pdict in pkg_dict.items():
        if 'name' not in pdict:
            pkg_dict[name]['name'] = name
        if 'version' not in pdict:
            pkg_dict[name]['version'] = 'unset'
        if 'license' not in pdict:
            pkg_dict[name]['license'] = 'unknown'
        if 'cve-product' not in pdict:
            pkg_dict[name]['cve-product'] = name
        if 'cve-version' not in pdict:
            pkg_dict[name]['cve-version'] = pdict['version']

    for name, pdict in pkg_dict.items():
        pdict['cve-version'] = _sanitize_version(pdict['cve-version'])

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

    bdir = vgls['bdir']
    pkg_dict = vgls['packages']

    var_string = _get_make_variables(pkg_dict.keys())
    variable_list = _get_make_output(bdir, var_string)
    vgls['make'] = _transform_make_info(vgls, variable_list)
    make_dict = _fixup_make_info(vgls)

    write_intm_json(vgls, 'make-vars', make_dict)
    return make_dict
