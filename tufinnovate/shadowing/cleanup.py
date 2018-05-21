#!/usr/bin/env python3

import argparse
from getpass import getpass
import sys
from pytos.securetrack.helpers import Secure_Track_Helper


def get_cli_args():
    parser = argparse.ArgumentParser('')
    parser.add_argument('--device', help='Device name or ID to get shadowed ACLs')
    parser.add_argument('--hostname', help='SecureTrack hostname or IP')
    parser.add_argument('--username', help='SecureTrack username')
    args = parser.parse_args()
    return args


def main():
    cli_args = get_cli_args()
    device = cli_args.device or input('Enter device ID or name: ')
    hostname = cli_args.hostname or input('Enter SecureTrack hostname or IP: ')
    username = cli_args.username or input('Enter SecureTrack username: ')
    password = getpass('Enter SecureTrack password: ')
    st_helper = Secure_Track_Helper(hostname, (username, password))
    try:
        device = st_helper.get_device_by_id(int(device))
    except ValueError:
        device = st_helper.get_device_by_name(device)
    print('.', end='')
    sys.stdout.flush()
    rules = {cleanup.rule.uid: cleanup.rule.rule_text for
             cleanup in st_helper.get_shadowed_rules_for_device_by_id(device.id).shadowed_rules_cleanup.shadowed_rules}

    print('.', end='')
    sys.stdout.flush()
    shadowed_rules = st_helper.\
        get_shadowing_rules_for_device_id_and_rule_uids(device.id,
                                                        [u for u in rules]).shadowed_rules_cleanup.shadowed_rules
    print('.')
    sys.stdout.flush()
    print('Rules to remove for device: {}'.format(device.name))

    shadowing_warning = {cleanup.rule.uid: [shadowing_rule.rule_text for shadowing_rule in cleanup.shadowing_rules]
                         for cleanup in shadowed_rules if any([shadowing_rule.src_services
                                                              for shadowing_rule in cleanup.shadowing_rules])}

    shadowed_warning = {cleanup.rule.uid: [shadowing_rule.rule_text for shadowing_rule in cleanup.shadowing_rules]
                        for cleanup in shadowed_rules if cleanup.rule.src_services}

    print('no {}'.format('\nno '.join([rules[uid] for uid in set(rules) - set(shadowed_warning) - set(shadowing_warning)])))

    print('***THE BELOW SHADOWING RULES CONTAIN SOURCE PORTS/SERVICES, MANUAL REVIEW IS STRONGLY RECOMMENDED***')
    print('\n'.join(['{}\n -> no {}'.format('\n'.join(shadowed_rules), rules[uid]) for
                     uid, shadowed_rules in shadowing_warning.items()]))

    print('***THE BELOW SHADOWED RULES CONTAIN SOURCE PORTS/SERVICES, MANUAL REVIEW IS STRONGLY RECOMMENDED***')
    print('\n'.join(['{}\n -> no {}'.format('\n'.join(shadowed_rules), rules[uid]) for
                     uid, shadowed_rules in shadowed_warning.items()]))


if __name__ == '__main__':
    main()
