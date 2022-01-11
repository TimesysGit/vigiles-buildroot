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
from utils import dbg, info, warn

from amendments import amend_manifest

VIGILES_DIR = 'vigiles'
VIGILES_DEFAULT_DISTRO = 'buildroot'
VIGILES_DEFAULT_IMAGE = 'rootfs'
VIGILES_DEFAULT_MANIFEST = 'buildroot-rootfs.json'
VIGILES_DEFAULT_REPORT = 'buildroot-rootfs-report.txt'
VIGILES_MANIFEST_VERSION = '1.20'
VIGILES_MANIFEST_NAME_MAX_LENGTH = 256


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


def _limit_manifest_name_length(name, max_limit):
    if len(name) > max_limit:
        warn("Manifest Name: Only the first %d characters will be used for the manifest name." % max_limit)
    return name[:max_limit]


def _init_manifest(vgls):
    def _stripped_packages(pkgs):
        excluded_fields = [
            'builddir',
            'is-virtual',
            'srcdir'
        ]
        return {
            pkgname: {
                k.replace('-', '_'): v
                for k, v in pdict.items()
                if v
                and k not in excluded_fields
            } for pkgname, pdict in pkgs.items()
        }

    try:
        _commit = subprocess.check_output([
                'git', 'rev-parse',
                'HEAD'
            ]).splitlines()[0].decode()
    except Exception as e:
        warn("Could not determine Buildroot git HEAD.")
        warn("\tError: %s" % e)
        _commit = 'Release'

    _hostname = vgls['config'].get('target-generic-hostname', 'buildroot')
    _machine = _get_machine_name(vgls)
    _name = vgls.get('manifest_name')
    if not _name:
        _name = '-'.join([_hostname, _machine])

    _name = _limit_manifest_name_length(_name, VIGILES_MANIFEST_NAME_MAX_LENGTH)

    build_dict = {
        'arch': vgls['config']['arch'],
        'cpu': vgls['config'].get('gcc-target-cpu', vgls['config']['arch']),
        'commit': _commit,
        'date': time.strftime('%Y-%m-%d', time.gmtime()),
        'distro': VIGILES_DEFAULT_DISTRO,
        'distro_version': vgls['make']['br2']['meta']['version'],
        'hostname': _hostname,
        'image': VIGILES_DEFAULT_IMAGE,
        'machine': _machine,
        'manifest_version': VIGILES_MANIFEST_VERSION,
        'manifest_name': _name,
        'packages': _stripped_packages(vgls['packages'])
    }
    return build_dict


def _make_file_name(vgls, manifest_dict, suffix, ext):
    file_spec = "-".join([manifest_dict["manifest_name"][:VIGILES_MANIFEST_NAME_MAX_LENGTH - len(suffix) - len(ext) - 3], suffix])
    file_name = '.'.join([file_spec, ext])
    file_path = os.path.join(vgls['vdir'], file_name)
    return file_path


def _manifest_name(vgls, manifest_dict):
    return _make_file_name(vgls, manifest_dict, 'manifest', 'json')


def _report_name(vgls, manifest_dict):
    return _make_file_name(vgls, manifest_dict, 'report', 'txt')


def write_manifest(vgls):
    final = _init_manifest(vgls)

    amend_manifest(vgls, final)

    vgls['manifest'] = _manifest_name(vgls, final)
    vgls['report'] = _report_name(vgls, final)

    mkdirhier(vgls['vdir'])

    info("Writing Manifest to %s" % vgls['manifest'])
    with open(vgls['manifest'], 'w') as f:
        json.dump(final, f, indent=4, separators=(',', ': '), sort_keys=True)
        f.write('\n')
