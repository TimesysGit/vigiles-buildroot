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
vigiles-buildoot.py [-h] [-b ODIR] [-k KCONFIG] [-u UCONFIG] [-D] [-I] [-M]

optional arguments:
  -h, --help            show this help message and exit
  -b ODIR, --build ODIR
                        Buildroot Output Directory
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

from buildroot import get_config_options, get_make_info
from manifest import VIGILES_DIR, write_manifest
from packages import get_package_info
from checkcves import vigiles_request
from kernel_uboot import get_kernel_info, get_uboot_info


def parse_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-b', '--build', dest='odir',
                        help='Buildroot Output Directory')
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

    vgls = {
        'debug': args.debug,
        'write_intm': args.write_intm,
        'do_check': args.do_check,
        'bdir': args.odir.strip() if args.odir else '.',
        'kconfig': args.kconfig.strip() \
            if args.kconfig \
            else 'auto',
        'uconfig': args.uconfig.strip() \
            if args.uconfig \
            else 'auto'
    }
    vgls['vdir'] = os.path.join(vgls['bdir'], VIGILES_DIR)
    return vgls


def collect_metadata(vgls):
    print("Getting Config Info ...")
    vgls['config'] = get_config_options(vgls)
    if not vgls['config']:
        sys.exit(1)

    print("Getting Package List ...")
    vgls['packages'] = get_package_info(vgls)
    if not vgls['packages']:
        sys.exit(1)

    print("Getting Make Variables ...")
    vgls['make'] = get_make_info(vgls)
    if not vgls['make']:
        sys.exit(1)

    if 'linux' in vgls['packages']:
        print("Getting Kernel Info ...")
        get_kernel_info(vgls)

    if 'uboot' in vgls['packages']:
        print("Getting U-Boot Info ...")
        get_uboot_info(vgls)


def run_check(vgls):
    manifest_path = vgls['manifest']
    if not manifest_path or not os.path.exists(manifest_path):
        print("ERROR: Manifest does not exist at expected path.")
        print("\tPath: %s" % manifest_path)
        sys.exit(1)

    kconfig_path = vgls['kconfig']
    if kconfig_path and not os.path.exists(kconfig_path):
        print("ERROR: Given Kernel config does not exist at expected path.")
        print("\tPath: %s" % kconfig_path)
        sys.exit(1)

    uconfig_path = vgls['uconfig']
    if uconfig_path and not os.path.exists(uconfig_path):
        print("ERROR: Given U-Boot config does not exist at expected path.")
        print("\tPath: %s" % uconfig_path)
        sys.exit(1)

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
