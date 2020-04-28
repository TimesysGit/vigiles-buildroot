###############################################################
#
# br2_config.py - Buildroot .config helper(s)
#
# Copyright (C) 2018 - 2020 Timesys Corporation
#
#
# This source is released under the MIT License.
###############################################################

import os
from collections import defaultdict

from utils import kconfig_to_py, kconfig_bool
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
