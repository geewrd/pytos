#!/opt/tufin/securitysuite/ps/python/bin/python3

import argparse
import shlex
import sys


from pytos.securechange.helpers import Secure_Change_Helper
from pytos.securechange.helpers import Secure_Change_API_Handler
from pytos.securechange.xml_objects.restapi.step.access_request.accessrequest import Named_Access_Request_Device
from pytos.common.definitions.xml_tags import Attributes
from pytos.common.base_types import XML_List

sc_helper = Secure_Change_Helper('localhost', ('scuser', 'password'))

targets_field_name = 'Devices'


def get_cli_args():
    parser = argparse.ArgumentParser('')
    parser.add_argument('--debug', action='store_true', help='Print out logging information to STDOUT.')
    # Workaround for SC not passing arguments to the script
    args = parser.parse_args(shlex.split(' '.join(sys.argv[1:])))
    return args


def add_targets(ticket):

    previous_task = ticket.get_previous_step().get_last_task()
    current_task = ticket.get_last_task()
    target_field = previous_task.get_field_list_by_name(targets_field_name)[0]

    new_targets = []
    ar_field = current_task.get_field_list_by_type(Attributes.FIELD_TYPE_MULTI_ACCESS_REQUEST)[0]

    for target in target_field.targets:
        if not hasattr(target, 'object_name') or target.object_name.lower() == 'any':
            continue
        new_targets.append(Named_Access_Request_Device(None, target.object_name, target.object_type,
                                                       target.object_details, target.management_name,
                                                       target.management_id))

    for access_request in ar_field.access_requests:
        access_request.targets = XML_List('targets', new_targets)
    sc_helper.put_field(ar_field)


def main():
    cli_args = get_cli_args()

    if cli_args.debug:
        print('Automation!')
    try:
        ticket_info = sc_helper.read_ticket_info()
    except ValueError:
        sys.exit(0)

    ticket = sc_helper.get_ticket_by_id(ticket_info.id)

    ticket_handler = Secure_Change_API_Handler(ticket)
    ticket_handler.register_action(Secure_Change_API_Handler.CREATE, add_targets, ticket)
    ticket_handler.run()


if __name__ == '__main__':
    main()
