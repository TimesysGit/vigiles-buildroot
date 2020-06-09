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

from buildroot import get_config_options, get_make_info
from manifest import VIGILES_DIR, write_manifest
from packages import get_package_info
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

    parser.add_argument('-D', '--enable-debug', dest='debug',
                        help='Enable Debug Output',
                        action='store_true')
    parser.add_argument('-I', '--write-intermediate', dest='write_intm',
                        help='Save Intermediate JSON Dictionaries',
                        action='store_true')
    parser.add_argument('-M', '--metadata-only', dest='do_check',
                        help='Only collect metadata, don\'t run online Check',
                        action='store_false')
    args = parser.parse_args()

    set_debug(args.debug)

    vgls = {
        'write_intm': args.write_intm,
        'do_check': args.do_check,
        'topdir': args.idir.strip() \
            if args.idir else os.path.abspath(os.curdir),
        'odir': args.odir.strip() if args.odir else None,
        'bdir': args.bdir.strip() if args.bdir else None,
        'kconfig': args.kconfig.strip() \
            if args.kconfig \
            else 'auto',
        'uconfig': args.uconfig.strip() \
            if args.uconfig \
            else 'auto'
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
    dbg("Getting Config Info ...")
    vgls['config'] = get_config_options(vgls)
    if not vgls['config']:
        sys.exit(1)

    dbg("Getting Package List ...")
    vgls['packages'] = get_package_info(vgls)
    if not vgls['packages']:
        sys.exit(1)

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


def run_check(vgls):
    manifest_path = vgls['manifest']
    if not manifest_path or not os.path.exists(manifest_path):
        print("ERROR: Manifest does not exist at expected path.")
        print("\tPath: %s" % manifest_path)
        sys.exit(1)

    kconfig_path = ''
    _kconfig = vgls.get('kconfig', 'none')
    if _kconfig != 'none' and os.path.exists(_kconfig):
        kconfig_path = _kconfig

    uconfig_path = ''
    _uconfig = vgls.get('uconfig', 'none')
    if _uconfig != 'none' and os.path.exists(_uconfig):
        uconfig_path = _uconfig

    report_path = vgls['report']
    vigiles_request(
        manifest_path,
        kconfig_path,
        uconfig_path,
        report_path
    )


def __main__():

    vgls = parse_args()

    collect_metadata(vgls)

    write_manifest(vgls)

    if vgls['do_check']:
        run_check(vgls)


__main__()
