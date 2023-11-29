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
from utils import dbg, info, warn

def _get_version_from_makefile(sdir, with_extra=True):
    v = {
        'major': None,
        'minor': None,
        'revision': None,
        'extra': None
    }
    version_string = None

    if not sdir:
        warn("Source directory not defined.")
        return None

    makefile_path = os.path.join(sdir, 'Makefile')
    if not os.path.exists(makefile_path):
        warn("Source directory not found: %s." % makefile_path)
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
        warn("Versions: Could not read/parse Makefile.",
            [
                "Path: %s." % makefile_path,
                "Error: %s" % e
            ]
        )
        return None

    if v['major'] and v['minor']:
        version_string = '.'.join([v['major'], v['minor']])
    if v['revision']:
        version_string = '.'.join([version_string, v['revision']])
    if v['extra'] and with_extra:
        version_string = version_string + v['extra']
    return version_string


def _get_config_opts(config_file, preamble_length=0):
    config_preamble = []
    config_set = set()
    config_options = list()

    if not os.path.exists(config_file):
        warn("Config File Not Found: %s" % config_file)
        return None

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
        warn("Config: Could not read/parse %s." % config_file)
        warn("\tError: %s" % e)
        return None
    config_options = config_preamble + sorted(list(config_set))
    return config_options


def _kernel_config(vgls, kdir) -> list:
    kconfig_in = vgls['kconfig']

    if not kconfig_in or kconfig_in == 'none':
        return None

    if kconfig_in == 'auto':
        dot_config = os.path.relpath(os.path.join(kdir, '.config'))
    else:
        dot_config = kconfig_in

    if not os.path.exists(dot_config):
        warn("Kernel .config file does not exist.",
            [
                "File: %s" % kconfig_in,
                "Kernel .config filtering will be disabled."
            ]
        )
        return None

    info("Kernel Config: Using %s" % dot_config)

    config_options = []
    dot_config_options = _get_config_opts(dot_config, preamble_length=4)

    if dot_config_options:
        config_options.extend(dot_config_options)
        dbg("Kernel Config: %d Options" % len(config_options))
    return config_options


def _write_config(vgls, pkg_dict, config_options):
    vgls_dir = vgls['vdir']
    _name = pkg_dict.get('name')
    _ver = pkg_dict.get('cve-version')
    _spec = '-'.join([_name, _ver])

    _fname = '.'.join([_spec, 'config'])
    config_file = os.path.join(vgls_dir, _fname)

    if not config_options:
        return

    mkdirhier(vgls_dir)

    try:
        with open(config_file, 'w') as config_out:
            print('\n'.join(config_options), file=config_out, flush=True)
            print('\n', file=config_out, flush=True)
    except Exception as e:
        warn("Could not write .config output.",
            [
                "File: %s" % config_file,
                "Error: %s" % e,
            ]
        )
        config_file = 'none'
    return config_file


def get_kernel_info(vgls):
    linux_dict = vgls['packages']['linux']
    kdir = linux_dict.get('builddir', '')

    if not linux_dict.get('cve-product'):
        linux_dict['cve-product'] = 'linux_kernel'

    if not kdir:
        warn("Kernel Config: Build directory not defined.")
        return None

    if not linux_dict.get('cve-version') or linux_dict.get('cve-version') == 'unset':
        if os.path.exists(kdir):
            ver = _get_version_from_makefile(kdir)
        else:
            warn("Linux Kernel: Build directory does not exist: %s" % kdir)
            return None

        dbg("Kernel Version: %s" % ver)
        linux_dict['cve-version'] = ver

    kconfig_out = 'none'
    config_opts = _kernel_config(vgls, kdir)
    if config_opts:
        kconfig_out = _write_config(vgls, linux_dict, config_opts)
    if kconfig_out != 'none':
        dbg("Kernel Config: Wrote %d options to %s" %
            (len(config_opts), kconfig_out))
    vgls['kconfig'] = kconfig_out


def _uboot_config(vgls, udir):
    uconfig_in = vgls['uconfig']

    if not uconfig_in or uconfig_in == 'none':
        return None

    if uconfig_in == 'auto':
        dot_config = os.path.relpath(os.path.join(udir, '.config'))
        autoconf = os.path.relpath(
            os.path.join(udir, 'include', 'autoconf.mk')
        )
    else:
        dot_config = uconfig_in
        autoconf = ''

    if not os.path.exists(dot_config):
        warn("U-Boot .config file does not exist.")
        warn("\tFile: %s" % uconfig_in)
        warn("\tU-Boot .config filtering will be disabled.")
        return None

    info("U-Boot Config: Using %s %s" % (dot_config, autoconf))

    config_options = []
    dot_config_options = _get_config_opts(dot_config, preamble_length=4)
    if dot_config_options:
        config_options.extend(dot_config_options)
        dbg("U-Boot Config: %d .config Options" %
            len(dot_config_options))

    if autoconf:
        autoconf_options = _get_config_opts(autoconf)
        if autoconf_options:
            config_options.extend(autoconf_options)
            dbg("U-Boot Config: %d autoconf Options" %
                len(autoconf_options))

    return config_options


def get_uboot_info(vgls):
    uboot_dict = vgls['packages']['uboot']
    udir = uboot_dict.get('builddir', '')

    if not uboot_dict.get('cve-product'):
        uboot_dict['cve-product'] = 'u-boot'

    if not udir:
        warn("U-Boot Config: Build directory not defined.")
        return None

    if not uboot_dict.get('cve-version') or uboot_dict.get('cve-version') == 'unset':
        if os.path.exists(udir):
            ver = _get_version_from_makefile(udir, with_extra=False)
        else:
            warn("U-Boot Config: Build directory does not exist.")
            warn("\tU-Boot build directory: %s" % udir)
            return None

        uboot_dict['cve-version'] = ver
        dbg("U-Boot Version: %s" % ver)

    uconfig_out = 'none'
    config_opts = _uboot_config(vgls, udir)
    if config_opts:
        uconfig_out = _write_config(vgls, uboot_dict, config_opts)
    if uconfig_out != 'none':
        dbg("U-Boot Config: Wrote %d options to %s" %
            (len(config_opts), uconfig_out))
    vgls['uconfig'] = uconfig_out
