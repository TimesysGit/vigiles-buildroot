###############################################################
#
# kernel_uboot.py - Helpers for parsing Kernel/U-Boot metadata
#
# Copyright (C) 2018 - 2020 Timesys Corporation
#
#
# This source is released under the MIT License.
###############################################################

import os

from utils import mkdirhier


def _get_version_from_makefile(sdir):
    v = {
        'major': None,
        'minor': None,
        'revision': None,
        'extra': None
    }

    if not sdir:
        print("WARNING: Source directory not defined.")
        return None

    makefile_path = os.path.join(sdir, 'Makefile')
    if not os.path.exists(makefile_path):
        print("WARNING: Source directory not found: %s." % makefile_path)
        return None

    try:
        with open(makefile_path) as f_in:
            for line in f_in:
                _split = line.split('=')
                if len(_split) != 2:
                    continue
                key, val = [x.strip() for x in _split]
                if key == 'VERSION':
                    v['major'] = val
                elif key == 'PATCHLEVEL':
                    v['minor'] = val
                elif key == 'SUBLEVEL':
                    v['revision'] = val
                elif key == 'EXTRAVERSION':
                    v['extra'] = val
            f_in.close()
    except Exception as e:
        print("WARNING: Could not read/parse Makefile: %s." % makefile_path)
        print("\tError: %s" % e)
        return None
    return v


def _get_config_opts(config_file, preamble_length=0):
    config_preamble = []
    config_set = set()
    config_options = list()

    if not os.path.exists(config_file):
        print("WARNING: Config File Not Found: %s" % config_file)
        return None

    print("\t* Config: Using %s" % config_file)
    try:
        with open(config_file, 'r') as config_in:
            f_data = [f_line.rstrip() for f_line in config_in]
            if preamble_length:
                config_preamble = f_data[:preamble_length]
                f_data = f_data[preamble_length + 1:]
            config_set.update([
                f_line
                for f_line in f_data
                if f_line.startswith('CONFIG_') and
                f_line.endswith(('=y', '=m'))
            ])
    except Exception as e:
        print("WARNING: Config: Could not read/parse %s." % config_file)
        print("\tError: %s" % e)
        return None
    config_options = config_preamble + sorted(list(config_set))
    print("\t* Config: %d Options" % len(config_options))
    return config_options


def _kernel_version(kdir) -> str:
    v = _get_version_from_makefile(kdir)
    if not v:
        return None
    if v['major'] and v['minor']:
        ver = '.'.join([v['major'], v['minor']])
    if v['revision']:
        ver = '.'.join([ver, v['revision']])
    if v['extra']:
        ver = ver + v['extra']
    return ver


def _kernel_config(kdir, kconfig) -> list:

    if kconfig == 'auto':
        dot_config = os.path.relpath(os.path.join(kdir, '.config'))
    else:
        dot_config = kconfig

    config_options = []
    dot_config_options = _get_config_opts(dot_config, preamble_length=4)

    if dot_config_options:
        config_options.extend(dot_config_options)
    print("\t* Kernel Config: %d Options" % len(config_options))
    return config_options


def _write_config(vgls, pkg_dict, config_options):
    vgls_dir = vgls['vdir']
    vgls_config_dir = os.path.join(vgls_dir, 'kconfig')
    _name = pkg_dict.get('name')
    _ver = pkg_dict.get('cve-version')
    _spec = '-'.join([_name, _ver])

    _fname = '.'.join([_spec, 'config'])
    config_file = os.path.join(vgls_dir, _fname)

    if not config_options:
        return

    mkdirhier(vgls_dir)

    print("\t* Writing Output: %s" % config_file)
    with open(config_file, 'w') as config_out:
        print('\n'.join(config_options), file=config_out, flush=True)
        print('\n', file=config_out, flush=True)

    return config_file


def get_kernel_info(vgls):
    linux_dict = vgls['packages']['linux']
    kdir = linux_dict.get('builddir', '')
    kconfig_in = vgls['kconfig']

    if not kdir:
        print("WARNING: Kernel Config: Build directory not defined.")
        return None

    linux_dict['cve-product'] = 'linux_kernel'

    ver = _kernel_version(kdir)
    if ver:
        print("\t* Kernel Version: %s" % ver)
        linux_dict['cve-version'] = ver

    if kconfig_in and kconfig_in != 'none':
        if os.path.exists(kconfig_in) or kconfig_in == 'auto':
            config_opts = _kernel_config(kdir, kconfig_in)
            kconfig_out = _write_config(vgls, linux_dict, config_opts)
            vgls['kconfig'] = kconfig_out


def _uboot_version(udir):
    v = _get_version_from_makefile(udir)
    if not v:
        return None
    if v['major'] and v['minor']:
        ver = '.'.join([v['major'], v['minor']])
    if v['revision']:
        ver = '.'.join([ver, v['revision']])
    if v['extra']:
        ver = ver + v['extra']
    return ver


def _uboot_config(udir, uconfig):
    if uconfig == 'auto':
        dot_config = os.path.relpath(os.path.join(udir, '.config'))
        autoconf = os.path.relpath(
            os.path.join(udir, 'include', 'autoconf.mk')
        )
    else:
        dot_config = uconfig
        autoconf = ''

    config_options = []
    dot_config_options = _get_config_opts(dot_config, preamble_length=4)
    if dot_config_options:
        config_options.extend(dot_config_options)
        print("\t* U-Boot Config: %d .config Options" %
              len(dot_config_options))

    if autoconf:
        autoconf_options = _get_config_opts(autoconf)
        if autoconf_options:
            config_options.extend(autoconf_options)
            print("\t* U-Boot Config: %d autoconf Options" %
                  len(autoconf_options))

    print("\t* U-Boot Config: %d Options" % len(config_options))
    return config_options


def get_uboot_info(vgls):
    uboot_dict = vgls['packages']['uboot']
    udir = uboot_dict.get('builddir', '')
    uconfig_in = vgls['uconfig']

    if not udir:
        print("WARNING: U-Boot Config: Build directory not defined.")
        return None

    if udir:
        ver = _uboot_version(udir)
        uboot_dict['cve-version'] = ver
        print("\t* U-Boot Version: %s" % ver)

    uboot_dict['cve-product'] = 'u-boot'

    if uconfig_in and uconfig_in != 'none':
        if os.path.exists(uconfig_in) or uconfig_in == 'auto':
            config_opts = _uboot_config(udir, uconfig_in)
            uconfig_out = _write_config(vgls, uboot_dict, config_opts)
            vgls['uconfig'] = uconfig_out
