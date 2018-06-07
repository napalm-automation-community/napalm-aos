"""Test fixtures."""
from builtins import super

import pytest
from napalm.base.test import conftest as parent_conftest

from napalm.base.test.double import BaseTestDouble
from napalm.base.utils import py23_compat
from napalm_aos import aos


@pytest.fixture(scope='class')
def set_device_parameters(request):
    """Set up the class."""
    def fin():
        request.cls.device.close()
    request.addfinalizer(fin)

    request.cls.driver = aos.AOSDriver
    request.cls.patched_driver = PatchedAOSDriver
    request.cls.vendor = 'aos'
    parent_conftest.set_device_parameters(request)


def pytest_generate_tests(metafunc):
    """Generate test cases dynamically."""
    parent_conftest.pytest_generate_tests(metafunc, __file__)


class PatchedAOSDriver(aos.AOSDriver):
    """Patched AOS Driver."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """Patched AOS Driver constructor."""
        super().__init__(hostname, username, password, timeout, optional_args)

        self.patched_attrs = ['device']
        self.device = FakeAOSDevice()

    def disconnect(self):
        pass

    def is_alive(self):
        return {
            'is_alive': True  # In testing everything works..
        }

    def open(self):
        pass


class FakeAOSDevice(BaseTestDouble):
    """AOS device test double."""

    def send_command(self, command, **kwargs):
        filename = '{}.txt'.format(self.sanitize_text(command))
        full_path = self.find_file(filename)
        result = self.read_txt_file(full_path)
        return py23_compat.text_type(result)

    def disconnect(self):
        pass

    def send_command_std(self, command, **kwargs):
        """Fake execute a command in the device by just returning the content of a file."""
        return self.send_command(command), "", 0
