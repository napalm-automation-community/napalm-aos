# Copyright 2016 Dravetech AB. All rights reserved.
#
# The contents of this file are licensed under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with the
# License. You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations under
# the License.

"""Tests."""

import unittest
import string
import mock
import re

from napalm_aos import aos
from napalm.base.test.base import TestGettersNetworkDriver


class TestGetterAOSDriver(unittest.TestCase, TestGettersNetworkDriver):
    """Getters Tests for IOSDriver.

    Get operations:
    get_lldp_neighbors
    get_facts
    get_interfaces
    get_bgp_neighbors
    get_interfaces_counters
    """

    @classmethod
    def setUpClass(cls):
        """Executed when the class is instantiated."""
        cls.mock = True

        username = 'vagrant'
        ip_addr = '192.168.0.234'
        password = 'vagrant'
        cls.vendor = 'aos'
        optional_args = {}
        optional_args['dest_file_system'] = 'flash:'

        cls.device = aos.AOSDriver(ip_addr, username, password, optional_args=optional_args)

        if cls.mock:
            cls.device.device = FakeAOSDevice()
        else:
            cls.device.open()


class FakeAOSDevice:
    """Class to fake a AOS Device."""
    def __init__(self):
        self.remote_conn = mock.Mock()
        self.remote_conn.transport.is_active = mock.Mock(return_value=True)

    @staticmethod
    def read_txt_file(filename):
        """Read a txt file and return its content."""
        with open(filename) as data_file:
            return data_file.read()

    @staticmethod
    def is_printable(bt):
        printset = set(string.printable)
        return set(bt).issubset(printset)

    def send_command_expect(self, command, **kwargs):
        """Fake execute a command in the device by just returning the content of a file."""
        output = ''
        if self.is_printable(command):
            cmd = re.sub(r"[\[\]\;\?\/\$\*\^\+\s\|\'\:]", '_', command)
            output = self.read_txt_file('aos/mock_data/{}.txt'.format(cmd))
        return str(output)

    def send_command(self, command, **kwargs):
        """Fake execute a command in the device by just returning the content of a file."""
        return self.send_command_expect(command)

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        return True

    def send_command_std(self, command, **kwargs):
        """Fake execute a command in the device by just returning the content of a file."""
        return self.send_command_expect(command), "", 0


if __name__ == "__main__":
    unittest.main()
