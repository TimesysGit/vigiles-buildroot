#!/usr/bin/env python3

###########################################################################
# vigiles-buildoot.py -- Timesys Vigiles Interface for Buildroot2
#
# Copyright (C) 2020 Timesys
#
# This source is released under the MIT License.
#
###########################################################################

###########################################################################
#
# This script is intended to be executed by the Buildroot make system, but
#  can be run manually using the following options.
# It assumes that the Vigiles credentials are in the environment (Key File
#  and Dashboard configuration).
#
"""
usage: vigiles-buildroot.py [-h] [-B IDIR] [-o ODIR] [-b BDIR] [-k KCONFIG]
                            [-u UCONFIG] [-D] [-I] [-M]

optional arguments:
  -h, --help            show this help message and exit
  -B IDIR, --base IDIR  Buildroot Source Directory
  -o ODIR, --output ODIR
                        Buildroot Output Directory
  -b BDIR, --build BDIR
                        Buildroot Build Directory
  -k KCONFIG, --kernel-config KCONFIG
                        Custom Kernel Config to Use
  -u UCONFIG, --uboot-config UCONFIG
                        Custom U-Boot Config(s) to Use
  -D, --enable-debug    Enable Debug Output
  -I, --write-intermediate
                        Save Intermediate JSON Dictionaries
  -M, --metadata-only   Only collect metadata, don't run online Check
"""
###########################################################################


import argparse
import os
import sys
import json

from buildroot import get_config_options, get_make_info, get_all_pkg_make_info
from manifest import VIGILES_DIR, write_manifest
import packages
from checkcves import vigiles_request
from kernel_uboot import get_kernel_info, get_uboot_info

from utils import set_debug, set_verbose
from utils import dbg, info, warn

def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-B', '--base', dest='idir',
                        help='Buildroot Source Directory')
    parser.add_argument('-o', '--output', dest='odir',
                        help='Buildroot Output Directory')
    parser.add_argument('-b', '--build', dest='bdir',
                        help='Buildroot Build Directory')
    parser.add_argument('-k', '--kernel-config', dest='kconfig',
                        help='Custom Kernel Config to Use')
    parser.add_argument('-u', '--uboot-config', dest='uconfig',
                        help='Custom U-Boot Config(s) to Use')

    parser.add_argument('-N', '--name', dest='manifest_name',
                        help='Custom Manifest/Report Name', default='')
    parser.add_argument('-F', '--subfolder', dest='subfolder_name',
                        help='Name of subfolder to upload to', default='')
    parser.add_argument('-A', '--additional-packages', dest='addl',
                        help='File of Additional Packages to Include')
    parser.add_argument('-E', '--exclude-packages', dest='excld',
                        help='File of Packages to Exclude')
    parser.add_argument('-W', '--whitelist-cves', dest='whtlst',
                        help='File of CVEs to Ignore/Whitelist')

    parser.add_argument('-K', '--keyfile', dest='llkey',
                        help='Location of LinuxLink credentials file')
    parser.add_argument('-C', '--dashboard-config', dest='lldashboard',
                        help='Location of LinuxLink Dashboard Config file')

    parser.add_argument('-U', '--upload-only', dest='upload_only',
                        help='Upload the manifest only; do not wait for report.',
                        action='store_true', default=False)

    parser.add_argument('-D', '--enable-debug', dest='debug',
                        help='Enable Debug Output',
                        action='store_true')
    parser.add_argument('-I', '--write-intermediate', dest='write_intm',
                        help='Save Intermediate JSON Dictionaries',
                        action='store_true')
    parser.add_argument('-M', '--metadata-only', dest='do_check',
                        help='Only collect metadata, don\'t run online Check',
                        action='store_false')
    parser.add_argument('-v', '--include-virtual', dest='include_virtual_pkgs',
                        help='Include virtual packages in generated SBOM',
                        action='store_true')
    parser.add_argument('-c', '--require-all-configs', dest='require_all_configs',
                        help='Throw an error on missing Config.in',
                        action='store_true')
    parser.add_argument('-i', '--require-all-hashfiles', dest='require_all_hashfiles',
                        help='Throw an error on missing hashfiles',
                        action='store_true')
    args = parser.parse_args()

    set_debug(args.debug)

    sbom_only = os.getenv('GENERATE_SBOM_ONLY', None)
    if sbom_only is not None:
        sbom_only = sbom_only.lower() == "true"

    vgls = {
        'write_intm': args.write_intm,
        'do_check': args.do_check if sbom_only is None else not bool(sbom_only),
        'topdir': args.idir.strip() \
            if args.idir else os.path.abspath(os.curdir),
        'odir': args.odir.strip() if args.odir else None,
        'bdir': args.bdir.strip() if args.bdir else None,
        'kconfig': args.kconfig.strip() \
            if args.kconfig \
            else 'auto',
        'uconfig': args.uconfig.strip() \
            if args.uconfig \
            else 'auto',
        'manifest_name': args.manifest_name.strip(),
        'subfolder_name': args.subfolder_name.strip(),
        'addl': args.addl.strip() if args.addl else '',
        'excld': args.excld.strip() if args.excld else '',
        'whtlst': args.whtlst.strip() if args.whtlst else '',
        'llkey': args.llkey.strip() if args.llkey else '',
        'lldashboard': args.lldashboard.strip() if args.lldashboard else '',
        'upload_only': args.upload_only,
        'include_virtual_pkgs': args.include_virtual_pkgs,
        'require_all_configs': args.require_all_configs,
        'require_all_hashfiles': args.require_all_hashfiles
    }

    if not vgls.get('odir', None):
        vgls['odir'] = os.path.join(vgls['topdir'], 'output')
    if not vgls.get('bdir', None):
        vgls['bdir'] = os.path.join(vgls['odir'], 'build')
    vgls['vdir'] = os.path.join(vgls['odir'], VIGILES_DIR)

    dbg("Vigiles Buildroot Config: %s" %
        json.dumps(vgls, indent=4, sort_keys=True))
    return vgls


def collect_metadata(vgls):
    vgls["all_pkg_make_info"] = get_all_pkg_make_info(vgls["odir"])

    dbg("Getting Config Info ...")
    vgls['config'] = get_config_options(vgls)
    if not vgls['config']:
        sys.exit(1)

    dbg("Getting Package List ...")
    vgls['packages'] = packages.get_package_info(vgls)
    if not vgls['packages']:
        sys.exit(1)

    dbg("Getting Package Dependencies ...")
    packages.get_package_dependencies(vgls, vgls['packages'])

    dbg("Getting Make Variables ...")
    vgls['make'] = get_make_info(vgls)
    if not vgls['make']:
        sys.exit(1)

    if 'linux' in vgls['packages']:
        dbg("Getting Kernel Info ...")
        get_kernel_info(vgls)

    if 'uboot' in vgls['packages']:
        dbg("Getting U-Boot Info ...")
        get_uboot_info(vgls)

    dbg("Getting Package Patches")
    vgls['packages'] = packages.get_patches(vgls)

    dbg("Getting Package Checksums ...")
    vgls['packages'] = packages.get_checksum_info(vgls)


def run_check(vgls):
    kconfig_path = ''
    _kconfig = vgls.get('kconfig', 'none')
    if _kconfig != 'none' and os.path.exists(_kconfig):
        kconfig_path = _kconfig

    uconfig_path = ''
    _uconfig = vgls.get('uconfig', 'none')
    if _uconfig != 'none' and os.path.exists(_uconfig):
        uconfig_path = _uconfig

    vgls_chk = {
        'keyfile': vgls.get('llkey', ''),
        'dashboard': vgls.get('lldashboard', ''),
        'manifest': vgls.get('manifest', ''),
        'report': vgls.get('report', ''),
        'kconfig': kconfig_path,
        'uconfig': uconfig_path,
        'upload_only': vgls.get('upload_only', False),
        'subfolder_name': vgls.get('subfolder_name', ''),
    }
    vigiles_request(vgls_chk)


def __main__():

    vgls = parse_args()

    collect_metadata(vgls)

    write_manifest(vgls)

    if vgls['do_check']:
        run_check(vgls)

    if vgls['require_all_configs'] and vgls['missing_configs']:
        sys.exit(1)

    if vgls['require_all_hashfiles'] and vgls['missing_hashfiles']:
        sys.exit(1)

__main__()
