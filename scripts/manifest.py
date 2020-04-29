##########################################################################
#
# manifest.py - Helpers for building a Vigiles (Buildroot) image manifest
#
# Copyright (C) 2018 - 2020 Timesys Corporation
#
#
# This source is released under the MIT License.
##########################################################################

import json
import os
import subprocess
import time

from utils import mkdirhier

VIGILES_DIR = 'vigiles'
VIGILES_DEFAULT_DISTRO = 'buildroot'
VIGILES_DEFAULT_IMAGE = 'rootfs'
VIGILES_DEFAULT_MANIFEST = 'buildroot-rootfs.json'
VIGILES_DEFAULT_REPORT = 'buildroot-rootfs-report.txt'
VIGILES_MANIFEST_VERSION = '1.20'


def _get_machine_name(vgls):
    # BR2_DEFCONFIG is always set in the .config file, which is in
    #   vgls['config']['defconfig'].
    # If an existing defconfig is used, it's set to the pathname of the
    #   defconfig: <Buildroot Source>/configs/imx8mpico_defconfig
    # But, if it's configured from scratch, it's set to '$(CONFIG_DIR)/defconfig',
    #   so we use the best value we have for the sub-architecture.
    _defconfig = os.path.basename(vgls['config'].get('defconfig', 'custom'))
    if _defconfig != 'defconfig':
        _machine = _defconfig.replace('_defconfig', '')
    else:
        _machine = vgls['config'].get('gcc-target-cpu', vgls['config']['arch'])
    return _machine


def _init_manifest(vgls):
    try:
        _commit = subprocess.check_output([
                'git', 'rev-parse',
                'HEAD'
            ]).splitlines()[0].decode()
    except Exception as e:
        print("Vigiles WARNING: Could not determine Buildroot git HEAD.")
        print("\tError: %s" % e)
        _commit = 'Release'

    build_dict = {
        'arch': vgls['config']['arch'],
        'cpu': vgls['config'].get('gcc-target-cpu', vgls['config']['arch']),
        'commit': _commit,
        'date': time.strftime('%Y-%m-%d', time.gmtime()),
        'distro': VIGILES_DEFAULT_DISTRO,
        'distro_version': vgls['make']['br2']['meta']['version'],
        'hostname': vgls['config'].get('target-generic-hostname', 'buildroot'),
        'image': VIGILES_DEFAULT_IMAGE,
        'machine': _get_machine_name(vgls),
        'manifest_version': VIGILES_MANIFEST_VERSION,
    }
    return build_dict


def _strip_package_dict(vgls):
    excluded_fields = [
        'builddir',
        'is-virtual',
        'srcdir'
    ]
    pkg_dict = {
        pkgname: {
            k.replace('-', '_'): v
            for k, v in pdict.items()
            if v
            and k not in excluded_fields
        } for pkgname, pdict in vgls['packages'].items()
    }
    return pkg_dict


def _build_whitelist(vgls):
    pkg_dict = vgls['packages']

    whitelist = set()
    for pdict in pkg_dict.values():
        wl = [
            cve
            for cve in pdict.get('ignore-cves', '').split(' ')
            if cve
        ]
        whitelist.update(wl)
    return sorted(list(whitelist))


def _make_file_name(vgls, manifest_dict, suffix, ext):
    _machine = manifest_dict['machine']
    _hostname = manifest_dict['hostname']
    file_spec = '-'.join([_hostname, _machine, suffix])
    file_name = '.'.join([file_spec, ext])
    file_path = os.path.join(vgls['vdir'], file_name)
    return file_path


def _manifest_name(vgls, manifest_dict):
    return _make_file_name(vgls, manifest_dict, 'manifest', 'json')


def _report_name(vgls, manifest_dict):
    return _make_file_name(vgls, manifest_dict, 'report', 'txt')


def write_manifest(vgls):
    final = _init_manifest(vgls)
    final['packages'] = _strip_package_dict(vgls)
    final['whitelist'] = _build_whitelist(vgls)

    vgls['manifest'] = _manifest_name(vgls, final)
    vgls['report'] = _report_name(vgls, final)

    mkdirhier(vgls['vdir'])

    print("Writing Manifest to %s" % vgls['manifest'])
    with open(vgls['manifest'], 'w') as f:
        json.dump(final, f, indent=4, separators=(',', ': '), sort_keys=True)
        f.write('\n')
