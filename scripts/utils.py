###############################################################
#
# utils.py - Miscellaneous Helpers
#
# Copyright (C) 2018 - 2020 Timesys Corporation
#
#
# This source is released under the MIT License.
###############################################################

import errno
import json
import os


# Case conversion helpers --
# Make and Kconfig uses UPPERCASE_WITH_UNDERSCORES, but for dictionary
# names, we use lowercase-with-dashes.
# These helpers help to do it cleanly throughout.
def py_to_kconfig(name: str) -> str:
    return name.replace('-', '_').upper()


def kconfig_to_py(name: str) -> str:
    return name.replace('_', '-').lower()


def kconfig_bool(value: str):
    """ Helper to parse an affirmative either from make or kconfig
    """
    positive = ['y', 'yes', 'true']
    negative = ['n', 'no', 'false']
    lcase = value.lower()
    if lcase in positive:
        return True
    elif lcase in negative:
        return False
    else:
        return value


def dbg(vgls, s):
    if vgls['debug']:
        print("DEBUG: %s" % s, file=sys.stderr)


def info(vgls, s):
    if vgls['verbose'] or vgls['debug']:
        print("Vigiles INFO: %s" % s, file=sys.stderr)


def warn(vgls, s):
    print("Vigiles WARNING: %s" % s, file=sys.stderr)


def mkdirhier(directory):
    """Create a directory like 'mkdir -p', but does not complain if
    directory already exists like os.makedirs
    Borrowed from bitbake utils.
    """
    try:
        os.makedirs(directory)
    except OSError as e:
        if e.errno != errno.EEXIST or not os.path.isdir(directory):
            raise e


def write_intm_json(vgls, name, d):
    vdir = vgls['vdir']
    f_dir = os.path.join(vdir, 'debug')
    f_path = os.path.join(f_dir, '.'.join([name, 'json']))

    mkdirhier(f_dir)

    if vgls['write_intm']:
        try:
            with open(f_path, 'w') as fd:
                json.dump(d, fd,
                          indent=4, separators=(',', ': '), sort_keys=True)
                fd.write('\n')
        except Exception as e:
            print('Vigiles Warning: Could not write intermediate file.')
            print('\tFile Path: %s' % f_path)
            print('\tError: %s' % e)
