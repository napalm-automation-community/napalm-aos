"""NAPALM Alcatel-Lucent AOS Handler."""
# Copyright 2017. All rights reserved.
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

# from __future__ import print_function
# from __future__ import unicode_literals

import uuid
import tempfile
import copy
import os

try:
    import napalm.base.constants as C
    from netaddr import IPAddress
    from napalm_aos.utils.AlcatelOS import *
    from napalm_aos.utils.utils import *
    from napalm.base import NetworkDriver
    from napalm.base.utils import py23_compat
    from napalm.base.exceptions import (
        ConnectionException,
        MergeConfigException,
        ReplaceConfigException,
        CommandErrorException,
    )
    from napalm.base.helpers import mac as standardize_mac
except ImportError:
    import napalm_base.constants as C
    from netaddr import IPAddress
    from napalm_aos.utils.AlcatelOS import *
    from napalm_aos.utils.utils import *
    from napalm_base import NetworkDriver
    from napalm_base.utils import py23_compat
    from napalm_base.exceptions import (
        ConnectionException,
        MergeConfigException,
        ReplaceConfigException,
        CommandErrorException,
    )
    from napalm_base.helpers import mac as standardize_mac


# STD REGEX PATTERNS
IP_ADDR_REGEX = r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"
IPV4_ADDR_REGEX = IP_ADDR_REGEX
IPV6_ADDR_REGEX_1 = r"::"
IPV6_ADDR_REGEX_2 = r"[0-9a-fA-F:]{1,39}::[0-9a-fA-F:]{1,39}"
IPV6_ADDR_REGEX_3 = r"[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:" \
                     "[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}:[0-9a-fA-F]{1,3}"
# Should validate IPv6 address using an IP address library after matching with this regex
IPV6_ADDR_REGEX = "(?:{}|{}|{})".format(IPV6_ADDR_REGEX_1, IPV6_ADDR_REGEX_2, IPV6_ADDR_REGEX_3)
MAC_REGEX = r"[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}"

INTERFACE_REGEX_1 = r'\d+[a-zA-Z]*\/\d+[a-zA-Z]*\/\d+[a-zA-Z]*'
INTERFACE_REGEX_2 = r'\d+[a-zA-Z]*\/\d+[a-zA-Z]*'

log_levels = {
    'CRITICAL': logging.CRITICAL,
    'ERROR': logging.ERROR,
    'WARN': logging.WARNING,
    'WARNING': logging.WARNING,
    'INFO': logging.INFO,
    'DEBUG': logging.DEBUG,
    'NOTSET': logging.NOTSET,
}
log_level = log_levels.get(os.getenv('NAPALM_AOS_LOG_LVL'))
if not log_level:
    log_level = logging.WARNING
logging.basicConfig(level=log_level)


class AOSDriver(NetworkDriver):
    """NAPALM Alcatel-Lucent AOS Handler."""

    def __init__(self, hostname, username, password, timeout=60, optional_args=None):
        """NAPALM Alcatel-Lucent AOS Handler."""
        if optional_args is None:
            optional_args = {}

        self.dest_file_system = optional_args.get('dest_file_system', '/flash/napalm')
        self.candidate_cfg_file = optional_args.get('candidate_cfg_file', 'candidate.cfg')
        self.config_replace = False
        self._scp_client = None

        self.device = AlcatelOS(hostname,
                                username,
                                password,
                                timeout,
                                optional_args)

    def open(self):
        """Open a connection to the device."""
        try:
            self.device.open()
            self._scp_client = AlcatelOSSCPConn(self.device)
        except Exception as e:
            logging.debug('Got exception open connection.', exc_info=True)
            self.close()
            raise ConnectionException(e)

    def close(self):
        """Close the connection to the device."""
        try:
            self.device.close()
            self._scp_client.close()
        except Exception as e:
            logging.debug('Got exception close connection.', exc_info=True)

    def _get_boot_config_location(self):
        boot_file = 'boot.cfg'
        running_dir = 'certified'
        command = 'show running-directory'
        output = self.device.send_command(command)
        running_dir_arr = re.findall(r'.*?Running configuration\s*?:(.+),\s*', output)
        if running_dir_arr:
            running_dir = running_dir_arr[0].strip()
            if running_dir == "WORKING" or running_dir == "CERTIFIED":
                running_dir = running_dir.lower()
        running_mode_arr = re.findall(r'.*?CMM Mode\s*?:(.+),\s*', output)
        if running_mode_arr and 'VIRTUAL-CHASSIS' in running_mode_arr[0].strip():
            boot_file = 'vcboot.cfg'

        return "/flash/" + running_dir, boot_file

    def cli(self, commands):
        """
        Execute a list of commands and return the output in a dictionary format using the command
        as the key.
        """
        cli_output = dict()
        if type(commands) is not list:
            raise TypeError('Please enter a list of commands!')

        for command in commands:
            output = self.device.send_command(command)
            cli_output.setdefault(command, {})
            cli_output[command] = output

        return cli_output

    def load_replace_candidate(self, filename=None, config=None):
        """
        SCP file to device filesystem, defaults to boot directory.

        Return None or raise exception
        """
        if config and filename:
            raise ReplaceConfigException("No configuration found")

        if config:
            filename = self._create_tmp_file(config, self.candidate_cfg_file)

        if filename and os.path.exists(filename) is True:
            command = 'mkdir -p {}'.format(self.dest_file_system)
            self.device.send_command(command)
            self._scp_client.scp_transfer_file(filename, "{}/{}".format(self.dest_file_system,
                                                                        self.candidate_cfg_file))
            self.config_replace = True
        else:
            raise ReplaceConfigException("Config file is not found")

    def load_merge_candidate(self, filename=None, config=None):
        """
        SCP file to remote device.

        Merge configuration in: copy <file> running-config
        """
        new_config = ''
        command = 'mkdir -p {}'.format(self.dest_file_system)
        self.device.send_command(command)
        if config:
            new_config = config
        elif filename and os.path.exists(filename) is True:
            with open(filename) as f:
                new_config = f.read()
        else:
            raise MergeConfigException("No configuration found")

        temp_file = self._create_tmp_file(new_config, self.candidate_cfg_file)
        self._scp_client.scp_transfer_file(temp_file, self.dest_file_system)
        self.candidate_cfg_file = path_leaf(temp_file)
        os.remove(temp_file)
        self.config_replace = False

    def compare_config(self):
        diff = ''
        config_dir = self.dest_file_system
        config_file = self.candidate_cfg_file
        running_cfg = self._get_config_snapshot()

        command = 'echo "`cat {}/{}`"'.format(config_dir, config_file)
        output, error, exitcode = self.device.send_command_std(command, throw_exception=False)

        if exitcode != 0:
            raise CommandErrorException("No candidate configuration found")
        if self.config_replace:
            diff = compare_configure(running_cfg, output)
        else:
            diff = compare_configure(running_cfg, output, '+')
        return '\n'.join(diff)

    def commit_config(self):
        if self.config_replace:
            boot_dir, boot_file = self._get_boot_config_location()
            self.device.send_command('cp -rf {}/{} {}/{}'.format(self.dest_file_system,
                                                                 self.candidate_cfg_file,
                                                                 boot_dir,
                                                                 boot_file))
            try:
                # Try to reboot switch
                self.device.send_command_non_blocking('echo Y | reload from {} no roll'.format(boot_dir), timeout=1)
            except socket.timeout:
                pass
        else:
            self.device.send_command('configuration apply {}/{}'.format(self.dest_file_system,
                                                                        self.candidate_cfg_file))

    def discard_config(self):
        command = 'rm -rf {}/{}'.format(self.dest_file_system, self.candidate_cfg_file)
        self.device.send_command(command)

    @staticmethod
    def _create_tmp_file(config, fname=''):
        """Write temp file and for use with inline config and SCP."""
        tmp_dir = tempfile.gettempdir()
        if not fname:
            fname = py23_compat.text_type(uuid.uuid4())
        filename = os.path.join(tmp_dir, fname)
        with open(filename, 'wt') as fobj:
            fobj.write(config)
        return filename

    def get_facts(self):
        """Implementation of NAPALM method get_facts."""
        system_info, chassis_info, interfaces = ({}, {}, [])

        show_sys = self.device.send_command('show system')
        show_chass = self.device.send_command('show chassis chassis-id 0')
        show_ip_inf = self.device.send_command("show ip interface | awk '{print $1}'")

        # Parse system info
        for line in show_sys.strip().splitlines():
            info = line.split(':', 1)
            key = info[0].strip()
            value = info[1].strip()
            if len(value) != 0 and value[len(value) - 1] == ',':
                value = value[:len(value)-1]

            system_info[key] = value

        # Parse uptime to second
        uptime_str = system_info["Up Time"]
        uptime = to_seconds(uptime_str)

        # Parse chassis info
        m_model = re.findall(r'Model Name:\s*([^\n,?]+)', show_chass)
        m_serial_num = re.findall(r'Serial Number:\s*([^\n,?]+)', show_chass)

        model_name = m_model[0] if m_model else u''
        serial_number = m_serial_num[0] if m_serial_num else u''

        # Parse os version and vendor
        description = system_info['Description']

        vendor, os_version = description.split(model_name)

        # Parse interfaces
        interface_data = show_ip_inf.strip().splitlines()
        indices = [i for i, s in enumerate(interface_data) if '-+-' in s]
        if indices != []:
            interfaces = interface_data[indices[0] + 1:]

        return {
            'hostname': system_info['Name'],
            'fqdn': u'',
            'vendor': vendor,
            'model': model_name,
            'serial_number': serial_number,
            'os_version': os_version,
            'uptime': uptime,
            'interface_list': interfaces,
        }

    def is_alive(self):
        """Returns a flag with the state of the SSH connection."""
        return {
            'is_alive': self.device.is_alive()
        }

    def get_arp_table(self):
        """
        Get arp table information.

        Return a list of dictionaries having the following set of keys:
            * interface (string)
            * mac (string)
            * ip (string)
            * age (float)

        For example::
            [
                {
                    'interface' : 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '5c:5e:ab:da:3c:f0',
                    'ip'        : '172.17.17.1',
                    'age'       : 1454496274.84
                },
                {
                    'interface': 'MgmtEth0/RSP0/CPU0/0',
                    'mac'       : '66:0e:94:96:e0:ff',
                    'ip'        : '172.17.17.2',
                    'age'       : 1435641582.49
                }
            ]
        """
        arp_table = []
        command = 'show arp'
        output = self.device.send_command(command)
        if len(output.strip()) == 0:
            return {}

        arp_tbl = AOSTable(output)
        for index, ipaddr in enumerate(arp_tbl.get_column_by_name("IP Addr")):
            ipaddr = ipaddr.strip()
            mac = arp_tbl.get_column_by_name("Hardware Addr")[index]
            interface = arp_tbl.get_column_by_name("Interface")[index]
            entry = {
                'interface': interface,
                'mac': standardize_mac(mac),
                'ip': ipaddr,
                'age': float(0)
            }

            arp_table.append(entry)
        return arp_table

    def get_interfaces_ip(self):
        """
        Get interface ip details.

        Returns a dict of dicts

        Example Output:

        {   u'FastEthernet8': {   'ipv4': {   u'10.66.43.169': {   'prefix_length': 22}}},
            u'Loopback555': {   'ipv4': {   u'192.168.1.1': {   'prefix_length': 24}},
                                'ipv6': {   u'1::1': {   'prefix_length': 64},
                                            u'2001:DB8:1::1': {   'prefix_length': 64},
                                            u'2::': {   'prefix_length': 64},
                                            u'FE80::3': {   'prefix_length': u'N/A'}}},
            u'Tunnel0': {   'ipv4': {   u'10.63.100.9': {   'prefix_length': 24}}},
            u'Tunnel1': {   'ipv4': {   u'10.63.101.9': {   'prefix_length': 24}}},
            u'Vlan100': {   'ipv4': {   u'10.40.0.1': {   'prefix_length': 24},
                                        u'10.41.0.1': {   'prefix_length': 24},
                                        u'10.65.0.1': {   'prefix_length': 24}}},
            u'Vlan200': {   'ipv4': {   u'10.63.176.57': {   'prefix_length': 29}}}}
        """

        interfaces = {}

        command = 'show ip interface'
        output = self.device.send_command(command)
        command = 'show ipv6 interface'
        outputv6 = self.device.send_command(command)

        iftable = AOSTable(output)
        ifv6table = AOSTable(outputv6)

        for index, iface in enumerate(iftable.get_column_by_name("Name")):
            ip_address = iftable.get_column_by_name("IP Address")[index]
            val = {
                'prefix_length': IPAddress(iftable.get_column_by_name("Subnet Mask")[index]).netmask_bits()}
            interfaces[iface] = {"ipv4": {ip_address: val}}

        for index, iface in enumerate(ifv6table.get_column_by_name("Name")):
            ipv6_cidr = ifv6table.get_column_by_name("IPv6 Address/Prefix Length")[index]
            ipv6_addr, prefix_length = (u'', -1)
            if ipv6_cidr != "":
                ipv6_addr, prefix_length = ipv6_cidr.split(r'/')
                prefix_length = int(prefix_length)

            interfaces[iface] = {'ipv6': {ipv6_addr: {'prefix_length': prefix_length}}}

        return interfaces

    def get_interfaces(self):
        """
        Get interface details.

        last_flapped is not implemented

        Example Output:

        {   u'Vlan1': {   'description': u'N/A',
                      'is_enabled': True,
                      'is_up': True,
                      'last_flapped': -1.0,
                      'mac_address': u'a493.4cc1.67a7',
                      'speed': 100},
        u'Vlan100': {   'description': u'Data Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100},
        u'Vlan200': {   'description': u'Voice Network',
                        'is_enabled': True,
                        'is_up': True,
                        'last_flapped': -1.0,
                        'mac_address': u'a493.4cc1.67a7',
                        'speed': 100}}
        """
        # default values.

        interfaces = {}
        last_flapped = -1.0
        is_enabled = False
        speed = 0
        description = u''

        command = 'show interfaces'
        output = self.device.send_command(command)
        raw_interfaces_dict = parse_block(output)

        command = 'show interfaces status'
        output = self.device.send_command(command)
        iface_status_table = AOSTable(output)

        command = 'show interfaces capability'
        output = self.device.send_command(command)
        iface_capability_table = AOSTable(output)

        for key in raw_interfaces_dict.keys():
            m_iface = re.findall(INTERFACE_REGEX_1, key)
            iface = m_iface[0] if m_iface else re.findall(INTERFACE_REGEX_2, key)[0]
            is_up = (raw_interfaces_dict[key]['Operational Status'].strip().replace(',', '') == 'up')
            cid = iface_status_table.get_id_by_value(0, iface)  # Name column
            if cid != -1:
                # Admin Status column
                is_enabled = (iface_status_table.get_column_by_index(1)[cid] == 'en')

            cid = iface_capability_table.get_id_by_value(0, iface)  # Name column
            if cid != -1:
                speed_str = iface_capability_table.get_column_by_name('Speed')[cid]
                max_speed = speed_str.split('/')[-1]
                speed_match = re.match(r"(\d*)([A-Z]*)", max_speed)
                speed = speed_match.groups()[0]
                speed = int(speed)
                speedformat = speed_match.groups()[1]
                if speedformat.startswith('G'):
                    speed = (speed * 1000)
            mac_address = raw_interfaces_dict[key]['MAC address']
            mac_address = mac_address.strip().replace(',', '')
            interfaces[iface] = {'is_enabled': is_enabled, 'is_up': is_up,
                                 'description': description, 'mac_address': mac_address,
                                 'last_flapped': last_flapped, 'speed': speed}
        return interfaces

    def get_interfaces_counters(self):
        """
        Return interface counters and errors.

        'tx_errors': int,
        'rx_errors': int,
        'tx_discards': int,
        'rx_discards': int,
        'tx_octets': int,
        'rx_octets': int,
        'tx_unicast_packets': int,
        'rx_unicast_packets': int,
        'tx_multicast_packets': int,
        'rx_multicast_packets': int,
        'tx_broadcast_packets': int,
        'rx_broadcast_packets': int,
        """
        counters = {}

        command = 'show interfaces'
        stdout = self.device.send_command(command)
        stdout = stdout.replace(', ', '\n ')
        stdout = stdout.replace(',', '')
        raw_interfaces_dict = parse_block(stdout)
        for key in raw_interfaces_dict.keys():
            tx_rx = {}
            m_iface = re.findall(INTERFACE_REGEX_1, key)
            iface = m_iface[0] if m_iface else re.findall(INTERFACE_REGEX_2, key)[0]
            tx_rx['tx_errors'] = int(raw_interfaces_dict[key]['Error Frames'][1].strip())
            tx_rx['rx_errors'] = int(raw_interfaces_dict[key]['Error Frames'][0].strip())
            tx_rx['tx_discards'] = 0  # Not support
            tx_rx['rx_discards'] = 0  # Not support
            tx_rx['tx_octets'] = 0  # Not support
            tx_rx['rx_octets'] = 0  # Not support
            tx_rx['tx_unicast_packets'] = int(raw_interfaces_dict[key]['Unicast Frames'][1].strip())
            tx_rx['rx_unicast_packets'] = int(raw_interfaces_dict[key]['Unicast Frames'][0].strip())
            tx_rx['tx_multicast_packets'] = int(raw_interfaces_dict[key]['M-cast Frames'][1].strip())
            tx_rx['rx_multicast_packets'] = int(raw_interfaces_dict[key]['M-cast Frames'][0].strip())
            tx_rx['tx_broadcast_packets'] = int(raw_interfaces_dict[key]['Broadcast Frames'][1].strip())
            tx_rx['rx_broadcast_packets'] = int(raw_interfaces_dict[key]['Broadcast Frames'][0].strip())
            counters[iface] = tx_rx
        return counters

    def get_mac_address_table(self):
        """
        Returns a lists of dictionaries. Each dictionary represents an entry in the MAC Address
        Table, having the following keys
            * mac (string)
            * interface (string)
            * vlan (int)
            * active (boolean)
            * static (boolean)
            * moves (int)
            * last_move (float)
        """
        macs = []
        command = 'show mac-learning'
        output = self.device.send_command(command)
        mac_tbl = AOSTable(output)

        for index, mac_addr in enumerate(mac_tbl.get_column_by_name("Mac Address")):
            moves = -1
            last_move = -1.0
            static = False
            active = False

            domain = mac_tbl.get_column_by_name("Domain")[index]
            mac_type = mac_tbl.get_column_by_name("Type")[index]
            if mac_type.lower() in ['self', 'static', 'system']:
                static = True

            if mac_type.lower() in ['dynamic']:
                active = True

            interface = mac_tbl.get_column_by_name("Interface")[index]
            try:
                vlan = int(mac_tbl.get_column_by_name('Vlan/SrvcId[ISId/vnId]')[index])
            except Exception:
                vlan = -1
            macs.append({
                'mac': mac_addr,
                'interface': interface,
                'vlan': vlan,
                'static': static,
                'active': active,
                'moves': moves,
                'last_move': last_move
            })

        return macs

    def get_lldp_neighbors(self):
        """AOS implementation of get_lldp_neighbors."""
        lldp = {}
        command = 'show lldp remote-system'
        output = self.device.send_command(command)
        output = output.replace(',', '')
        output = output.replace('\n\n', '\n')
        output = output.replace('=', ':')
        lldp_dict = parse_block(output, reverse_delimiter=True)
        for local_port in lldp_dict.keys():
            m_iface = re.findall(INTERFACE_REGEX_1, local_port)
            iface = m_iface[0] if m_iface else re.findall(INTERFACE_REGEX_2, local_port)[0]
            neighbors = []
            for chassis in lldp_dict[local_port].keys():
                hostname = lldp_dict[local_port][chassis]['System Name'].strip()
                port_match = re.match(r".*(Port) (\d+)", chassis)
                port = port_match.groups()[1]
                entry = {
                    'hostname': hostname,
                    'port': port,
                }
                neighbors.append(entry)
            lldp[iface] = neighbors

        return lldp

    def get_lldp_neighbors_detail(self, interface=''):
        """
        AOS implementation of get_lldp_neighbors_detail.
        """
        lldp = {}
        command = 'show lldp remote-system'
        output = self.device.send_command(command)
        output = output.replace(',', '')
        output = output.replace('\n\n', '\n')
        output = output.replace('=', ':')
        lldp_dict = parse_block(output, reverse_delimiter=True)
        for local_port in lldp_dict.keys():
            m_iface = re.findall(INTERFACE_REGEX_1, local_port)
            iface = m_iface[0] if m_iface else re.findall(INTERFACE_REGEX_2, local_port)[0]
            if not interface or iface == interface:
                neighbors = []
                for chassis in lldp_dict[local_port].keys():
                    port = ''
                    remote_chassis_id = ''
                    hostname = lldp_dict[local_port][chassis]['System Name'].strip()
                    description = lldp_dict[local_port][chassis]['System Description'].strip()
                    system_capab = lldp_dict[local_port][chassis]['Capabilities Supported'].strip()
                    system_enable_capab = lldp_dict[local_port][chassis]['Capabilities Enabled'].strip()
                    remote_port_description = lldp_dict[local_port][chassis]['Port Description'].strip()
                    port_match = re.match(r".*(Port) (\d+)", chassis)
                    if port_match and len(port_match.groups()) > 1:
                        port = port_match.groups()[1]

                    rmc = re.findall(r"(?:[0-9a-fA-F]:?){12}", chassis)  # Find MAC Address
                    if rmc != []:
                        remote_chassis_id = rmc[0]

                    entry = {
                        'parent_interface': u'',
                        'remote_chassis_id': remote_chassis_id,
                        'remote_system_name': hostname,
                        'remote_port': port,
                        'remote_port_description': remote_port_description,
                        'remote_system_description': description,
                        'remote_system_capab': system_capab,
                        'remote_system_enable_capab': system_enable_capab
                    }
                    neighbors.append(entry)
                lldp[iface] = neighbors
                if interface:
                    break

        return lldp

    def get_ntp_servers(self):
        """Implementation of get_ntp_servers for AOS.

        Returns the NTP servers configuration as dictionary.
        The keys of the dictionary represent the IP Addresses of the servers.
        Inner dictionaries do not have yet any available keys.
        Example::
            {
                '192.168.0.1': {},
                '17.72.148.53': {},
                '37.187.56.220': {},
                '162.158.20.18': {}
            }
        """
        ntp_servers = {}
        command = 'show ntp client server-list'
        output = self.device.send_command(command)
        ntp_srv_tbl = AOSTable(output)
        for ipaddr in ntp_srv_tbl.get_column_by_name("IP Address"):
            ntp_servers[ipaddr] = {}

        return ntp_servers

    def get_ntp_peers(self):
        """Returns the NTP peers configuration as dictionary. The keys of the dictionary represent
        the IP Addresses of the peers. Inner dictionaries do not have yet any available keys.
        Example:

        {
            '192.168.0.1': {},
            '17.72.148.53': {},
            '37.187.56.220': {},
            '162.158.20.18': {}
        }
        """
        ntp_peers = {}
        command = 'show ntp peers'
        output = self.device.send_command(command)
        ntp_peers_tbl = AOSTable(output)
        for ipaddr in ntp_peers_tbl.get_column_by_name("IP Address"):
            ntp_peers[ipaddr] = {}

        return ntp_peers

    def get_ntp_stats(self):
        """
        Returns a list of NTP synchronization statistics.
        [
            {
                'remote'        : u'188.114.101.4',
                'referenceid'   : u'188.114.100.1',
                'synchronized'  : True,
                'stratum'       : 4,
                'type'          : u'-',
                'when'          : u'107',
                'hostpoll'      : 256,
                'reachability'  : 377,
                'delay'         : 164.228,
                'offset'        : -13.866,
                'jitter'        : 2.695
            }
        ]
        """
        def extract_second(s_time):
            seconds_regex = r".*?([-+]?[0-9]+\.?[0-9]*) (seconds).*?"
            match = re.match(seconds_regex, s_time)
            if match and len(match.groups()) > 1:
                return match.groups()[0]
            return 0.0

        ntp_stats = []
        command = "show ntp server status"
        output = self.device.send_command(command)
        output = output.replace(',', '')
        output = output.strip()
        servers = output.split('\n\n')
        servers = filter(None, servers)

        for server in servers:
            server = parse_block(server, delimiter="=")
            when = extract_second(server['Uptime count'])
            delay = extract_second(server['Delay'])
            offset = extract_second(server['Offset'])
            jitter = extract_second(server['Dispersion'])
            hostpoll = extract_second(server['Minpoll'])
            synchronized = True if 'synchronization' in server['Status'] else False
            ntp_stats.append({
                    'remote': server['IP address'].strip(),
                    'synchronized': synchronized,
                    'referenceid': server['Reference IP'].strip(),
                    'stratum': int(server['Stratum']),
                    'type': u'',
                    'when': py23_compat.text_type(when),
                    'hostpoll': int(hostpoll),
                    'reachability': int(server['Reachability'], 16),
                    'delay': float(delay),
                    'offset': float(offset),
                    'jitter': float(jitter)
                })

        return ntp_stats

    def ping(self, destination, source=C.PING_SOURCE, ttl=C.PING_TTL, timeout=C.PING_TIMEOUT,
             size=C.PING_SIZE, count=C.PING_COUNT, vrf=C.PING_VRF):
        """
        Execute ping on the device and returns a dictionary with the result.

        Output dictionary has one of following keys:
            * success
            * error
        In case of success, inner dictionary will have the followin keys:
            * probes_sent (int)
            * packet_loss (int)
            * rtt_min (float)
            * rtt_max (float)
            * rtt_avg (float)
            * rtt_stddev (float)
            * results (list)
        'results' is a list of dictionaries with the following keys:
            * ip_address (str)
            * rtt (float)
        """
        ping_dict = {}
        if vrf:
            command = 'vrf {} ping {}'.format(vrf, destination)
        else:
            command = 'ping {}'.format(destination)

        command += ' timeout {}'.format(timeout)
        command += ' size {}'.format(size)
        command += ' count {}'.format(count)
        if source:
            command += ' source-interface {}'.format(source)

        output, error, retCode = self.device.send_command_std(command, throw_exception=False)

        if retCode != 0:
            ping_dict['error'] = error
            return ping_dict

        if 'ERROR' in output:
            ping_dict['error'] = output
            return ping_dict

        ping_dict['success'] = {
                'probes_sent': 0,
                'packet_loss': 0,
                'rtt_min': 0.0,
                'rtt_max': 0.0,
                'rtt_avg': 0.0,
                'rtt_stddev': 0.0,
                'results': []
        }

        results_array = []
        ping_data = output.splitlines()
        ping_data = filter(None, ping_data)
        for line in ping_data:
            if 'icmp' in line:
                ip_addr = re.findall(IPV4_ADDR_REGEX, line)
                mtime = re.match(r'.*?(time ?= ?)(\d+.?\d*)', line)
                rrt = mtime.groups()[1] if mtime and len(mtime.groups()[1]) > 1 else 0.0
                results_array.append(
                    {
                        'ip_address': ip_addr[0],
                        'rtt': float(rrt),
                    }
                )
            elif 'packets transmitted' in line:
                pkg_match = re.match(r'.*?([0-9]+) (packets transmitted).*?', line)
                probes_sent = int(pkg_match.groups()[0]) if pkg_match and len(pkg_match.groups()) > 1 else 0
                pkg_match = re.match(r'.*?([0-9]+) (received).*?', line)
                received = int(pkg_match.groups()[0]) if pkg_match and len(pkg_match.groups()) > 1 else 0
                # loss = re.match(r'.*?([0-9]+)%? (packet loss).*?', ping_data[indices[0]+1])

                ping_dict['success']['probes_sent'] = int(probes_sent)
                ping_dict['success']['packet_loss'] = int(probes_sent - received)
            elif 'min/avg/max/mdev' in line:
                rrt_match = re.match(r'.*?(\d+.?\d*)/(\d+.?\d*)/(\d+.?\d*)/(\d+.?\d*).*?', line)
                if rrt_match and len(rrt_match.groups()) > 3:
                    ping_dict['success'].update({
                                'rtt_min': float(rrt_match.groups()[0]),
                                'rtt_avg': float(rrt_match.groups()[1]),
                                'rtt_max': float(rrt_match.groups()[2]),
                                'rtt_stddev': float(rrt_match.groups()[3]),
                    })
        ping_dict['success'].update({'results': results_array})
        return ping_dict

    def get_network_instances(self, name=''):
        """get_network_instances implementation for AOS."""
        vrfs = {}
        command = 'show vrf'
        output = self.device.send_command(command)

        if "ERROR" in output or '-+-' not in output:
            raise ValueError("Unexpected response from the switch")

        vrf_tbl = AOSTable(output)

        for index, vrf_name in enumerate(vrf_tbl.get_column_by_name("Virtual Routers")):
            if name == '' or name == vrf_name:
                vrf = {'name': vrf_name,
                       'type': vrf_tbl.get_column_by_name("Profile")[index],
                       'state': {
                                    'route_distinguisher': u'None'
                                },
                       'interfaces': {
                                        'interface': {}
                                     }
                       }

                command = 'vrf {} show ip interface'.format(vrf_name)
                if_output = self.device.send_command(command)
                ip_inf_tbl = AOSTable(if_output)
                for index, iface_name in enumerate(ip_inf_tbl.get_column_by_index(0)):
                    vrf['interfaces']['interface'][iface_name] = {}

                vrfs[vrf_name] = vrf

        return vrfs

    def traceroute(self, destination, source=C.TRACEROUTE_SOURCE,
                   ttl=C.TRACEROUTE_TTL, timeout=C.TRACEROUTE_TIMEOUT, vrf=C.TRACEROUTE_VRF):
        """
        Executes traceroute on the device and returns a dictionary with the result.

        :param destination: Host or IP Address of the destination
        :param source (optional): Use a specific IP Address to execute the traceroute
        :param ttl (optional): Maimum number of hops -> int (0-255)
        :param timeout (optional): Number of seconds to wait for response -> int (1-3600)

        Output dictionary has one of the following keys:

            * success
            * error

        In case of success, the keys of the dictionary represent the hop ID, while values are
        dictionaries containing the probes results:
            * rtt (float)
            * ip_address (str)
            * host_name (str)
        """

        if vrf:
            command = "vrf {} traceroute {}".format(vrf, destination)
        else:
            command = "traceroute {}".format(destination)

        if source:
            command += " source-interface {}".format(source)
        if timeout and isinstance(timeout, int) and 1 <= timeout <= 3600:
            command += " timeout {}".format(str(timeout))

        if ttl and isinstance(ttl, int) and 0 <= ttl <= 255:
            command += " max-hop {}".format(str(ttl))

        # Calculation to leave enough time for traceroute to complete assumes send_command
        # delay of .2 seconds.

        output, error, retCode = self.device.send_command_std(command, throw_exception=False)
        traceroute_dict = {}

        if retCode != 0:
            traceroute_dict['error'] = error
            return traceroute_dict

        max_hop = 0
        traceroute_arr = output.splitlines()
        indices = next((i for i, s in enumerate(traceroute_arr) if 'traceroute to' in s), None)

        if indices is None:
            traceroute_dict['error'] = output
            return traceroute_dict

        indices = int(indices)
        traceroute_arr = traceroute_arr[indices:]
        results = {}
        for i in range(indices+1, len(traceroute_arr)):
            curr_hop_idx = i - indices
            current_hop = traceroute_arr[i]
            host_matches = re.findall(r"([^ ]+)?\s\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)", current_hop)
            rrt_matches = re.findall(r".*?(\d+.?\d*)\s?ms.*?", current_hop)
            if rrt_matches == []:
                continue

            results[curr_hop_idx] = {'probes': {}}
            for index, rrt in enumerate(rrt_matches):
                hostname, ip_address = host_matches[index] if index < len(host_matches) else ('', '')
                results[curr_hop_idx]['probes'][index+1] = {'rtt': float(rrt),
                                                            'ip_address': py23_compat.text_type(ip_address),
                                                            'host_name': py23_compat.text_type(hostname)
                                                            }

        traceroute_dict['success'] = results
        return traceroute_dict

    def get_users(self):
        command = 'show user'
        output = self.device.send_command(command)
        users = {}
        users_arr = re.findall(r".*User name = (.+),", output)
        for user in users_arr:
            users[user] = {'level': 0,
                           'password': u'',
                           'sshkeys': []
                           }
        return users

    def get_environment(self):
        """
        Get environment facts.

        power, fan, temperature are currently not implemented
        cpu is using 1-minute average
        cpu hard-coded to cpu0 (i.e. only a single CPU)
        """
        environment = {}
        command = 'show health all cpu'

        output = self.device.send_command(command)
        environment['cpu'] = dict()
        cpu_tbl = AOSTable(output)
        for index, cpu in enumerate(cpu_tbl.get_column_by_index(0)):
            per_usage = cpu_tbl.get_column_by_index(1)[index]
            environment['cpu'][cpu] = {'%usage': float(per_usage)}

        command = 'show temperature'
        output = self.device.send_command(command)
        temp_tbl = AOSTable(output)
        environment['temperature'] = dict()
        for index, chassis in enumerate(temp_tbl.get_column_by_index(0)):
            curr_temp = float(temp_tbl.get_column_by_name('Current')[index])
            danger = float(temp_tbl.get_column_by_name('Danger')[index])
            thresh = float(temp_tbl.get_column_by_name('Thresh')[index])
            environment['temperature'][chassis] = {"temperature": float(curr_temp),
                                                   "is_alert": (curr_temp > thresh),
                                                   "is_critical": (curr_temp > danger)
                                                   }

        # Fans
        command = 'show fan'
        output = self.device.send_command(command)
        fans_tbl = AOSTable(output)
        environment['fans'] = dict()
        for index, chassis in enumerate(fans_tbl.get_column_by_index(0)):
            fan = fans_tbl.get_column_by_name('Fan')[index]
            locate = 'Chassis/Tray ' + chassis + ' Fan ' + fan
            functional = fans_tbl.get_column_by_name('Functional')[index]
            environment['fans'][locate] = {'status': (functional == 'YES')}

        # Power Supply
        command = 'show powersupply'
        output = self.device.send_command(command)

        power_tbl = AOSTable(output)
        environment['power'] = dict()
        for index, chassis in enumerate(power_tbl.get_column_by_index(0)):
            chassis = chassis.strip()
            total_power_supply = power_tbl.get_column_by_index(1)[index]
            status = power_tbl.get_column_by_name('Status')[index]
            if chassis != 'Total' and chassis != '':
                environment['power'][chassis] = {'status': (status == 'UP'),
                                                 'output': 0.0,
                                                 'capacity': float(total_power_supply)
                                                 }

        # Memory is not supported
        environment['memory'] = {'available_ram': 0,
                                 'used_ram': 0
                                 }

        return environment

    def get_snmp_information(self):
        """
        Returns a dict of dicts

        Example Output:

        {   'chassis_id': u'Asset Tag 54670',
        'community': {   u'private': {   'acl': u'12', 'mode': u'rw'},
                         u'public': {   'acl': u'11', 'mode': u'ro'},
                         u'public_named_acl': {   'acl': u'ALLOW-SNMP-ACL',
                                                  'mode': u'ro'},
                         u'public_no_acl': {   'acl': u'N/A', 'mode': u'ro'}},
        'contact': u'Joe Smith',
        'location': u'123 Anytown USA Rack 404'}

        """
        command = 'show snmp community-map'
        output = self.device.send_command(command)
        snmp_dict = {
            'chassis_id': u'unknown',
            'community': {},
            'contact': u'unknown',
            'location': u'unknown'
        }

        comm_tbl = AOSTable(output)
        for index, comm_str in enumerate(comm_tbl.get_column_by_name('community string')):
            username = comm_tbl.get_column_by_name('user name')[index]
            snmp_dict['community'][comm_str] = {'acl': username,
                                                'mode': u'unknown'
                                                }
        return snmp_dict

    def get_config(self, retrieve='all'):
        """Implementation of get_config for AOS.

        Returns the startup or/and running configuration as dictionary.
        The keys of the dictionary represent the type of configuration
        (startup or running). The candidate is always empty string,
        since AOS does not support candidate configuration.
        """

        configs = {
            'startup': u'',
            'running': u'',
            'candidate': u'',
        }

        if retrieve in ('startup', 'all'):
            configs['startup'] = self._get_startup_config()

        if retrieve in ('running', 'all'):
            configs['running'] = self._get_config_snapshot()

        if retrieve in ('candidate', 'all'):
            startup_cfg = self._get_startup_config() if retrieve == 'candidate' else configs['startup']
            running_cfg = self._get_config_snapshot() if retrieve == 'candidate' else configs['running']
            diff = compare_configure(startup_cfg, running_cfg)
            configs['candidate'] = '\n'.join(diff)

        return configs

    def _get_config_snapshot(self):
        command = 'show configuration snapshot'
        running_cfg = self.device.send_command(command)
        return running_cfg

    def _get_startup_config(self):
        running_dir, boot_file = self._get_boot_config_location()
        command = 'cat {}/{}'.format(running_dir, boot_file)
        startup_cfg = self.device.send_command(command)
        return startup_cfg

    def get_route_to(self, destination='', protocol=''):
        """Implementation of NAPALM method get_route_to.

        Returns a dict of dicts
        Example Output:
        {
            "1.0.0.0/24": [
                {
                    "protocol"          : u"BGP",
                    "inactive_reason"   : u"Local Preference",
                    "last_active"       : False,
                    "age"               : 105219,
                    "next_hop"          : u"172.17.17.17",
                    "selected_next_hop" : True,
                    "preference"        : 170,
                    "current_active"    : False,
                    "outgoing_interface": u"ae9.0",
                    "routing_table"     : "inet.0",
                    "protocol_attributes": {
                        "local_as"          : 13335,
                        "as_path"           : u"2914 8403 54113 I",
                        "communities"       : [
                            u"2914:1234",
                            u"2914:5678",
                            u"8403:1717",
                            u"54113:9999"
                        ],
                        "preference2"       : -101,
                        "remote_as"         : 2914,
                        "local_preference"  : 100
                    }
                }
            ]
        }
        """
        def _get_route_database(destination, route_dict):
            command = 'show ip router database dest {}'.format(destination)
            output = self.device.send_command(command)
            is_active = False
            routes_db_tbl = AOSTable(output)
            for index, ipaddr in enumerate(routes_db_tbl.get_column_by_name("Destination")):
                if destination in ipaddr:
                    route_dict['last_active'] = True
                    if '+' in ipaddr:
                        route_dict['current_active'] = True
                        route_dict['selected_next_hop'] = True

                    interface = routes_db_tbl.get_column_by_name("Interface")[index]
                    metric = routes_db_tbl.get_column_by_name("Metric")[index]
                    route_dict['outgoing_interface'] = interface.strip()
                    route_dict['protocol_attributes']['metric'] = int(metric.strip())
                    break

        def _get_route_pref(protocol):
            command = 'show ip route-pref'
            output = self.device.send_command(command)
            route_pref = AOSTable(output)
            for index, _protocol in enumerate(route_pref.get_column_by_name("Protocol")):
                if _protocol.lower() == protocol.lower():
                    return int(route_pref.get_column_by_name("Route Preference Value")[index])
            return -1

        def _get_bgp_attributes(destination, route_dict):
            command = 'show ip bgp path ip-addr {}'.format(destination)
            output = self.device.send_command(command)
            bgp_path = parse_block(output, delimiter='=')
            nextHop = communities = ''
            local_preference = preference2 = 0

            if isinstance(bgp_path['Path protocol'], list):
                indices = next((i for i, s in enumerate(bgp_path['Path protocol']) if 'bgp' in s.lower()), None)
                indices = int(indices)
                nextHop = bgp_path['Path neighbor'][indices]['Path nextHop']
                communities = bgp_path['Path neighbor'][indices]['Path community']
                local_preference = bgp_path['Path neighbor'][indices]['Path preference degree']
                as_path = bgp_path['Path neighbor'][indices]['Path autonomous systems']
                preference2 = bgp_path['Path neighbor'][indices]['Path weight']
            else:
                nextHop = bgp_path['Path neighbor']['Path nextHop']
                communities = bgp_path['Path neighbor']['Path community']
                local_preference = bgp_path['Path neighbor']['Path preference degree']
                as_path = bgp_path['Path neighbor']['Path autonomous systems']
                preference2 = bgp_path['Path neighbor']['Path weight']

            route_dict['next_hop'] = re.sub(r"[\s,]", '', nextHop)

            route_dict['protocol_attributes']['as_path'] = re.sub(r"[\s,]", '', as_path)
            route_dict['protocol_attributes']['local_preference'] = re.sub(r"[\s,]", '', local_preference)
            route_dict['protocol_attributes']['preference2'] = int(re.sub(r"[\s,]", '', preference2))
            route_dict['protocol_attributes']['communities'].append(re.sub(r"[\s,]", '', communities))

        route_dict = {
            'current_active': False,
            'last_active': False,
            'age': 0,
            'next_hop': u'',
            'protocol': u'',
            'outgoing_interface': u'',
            'preference': 0,
            'inactive_reason': u'',
            'routing_table': u'',
            'selected_next_hop': True,
            'protocol_attributes': {
                'metric': u'',
                'as_path': u'',
                'local_preference': 0,
                'local_as': u'',
                'remote_as': u'',
                'remote_address': u'',
                'preference2': 0,
                'communities': []
            }
        }

        results = {destination: []}

        command = 'show vrf'
        output = self.device.send_command(command)

        vrf_tbl = AOSTable(output)
        vrfs = []

        for index, vrf in enumerate(vrf_tbl.get_column_by_name("Virtual Routers")):
            _protocol = vrf_tbl.get_column_by_name("Protocols")[index].lower()
            if protocol == '' or protocol in _protocol:
                vrfs.append(vrf.strip())

        commands_output = []
        for vrf in vrfs:
            command = 'vrf {} show ip routes'.format(vrf)
            commands_output.append(self.device.send_command(command))

        for vrf, command_output in zip(vrfs, commands_output):
            routes_tbl = AOSTable(command_output)
            for index, ipaddr in enumerate(routes_tbl.get_column_by_name("Dest Address")):
                _protocol = routes_tbl.get_column_by_name("Protocol")[index].strip().lower()
                if destination == ipaddr.strip() and (protocol == '' or protocol in _protocol):
                    c_route_dict = copy.deepcopy(route_dict)
                    c_route_dict['routing_table'] = vrf
                    _get_route_database(destination, c_route_dict)
                    age = routes_tbl.get_column_by_name("Age")[index]
                    c_route_dict['protocol'] = _protocol
                    c_route_dict['age'] = to_seconds(age)
                    c_route_dict['preference'] = _get_route_pref(_protocol)
                    if 'bgp' in _protocol:
                        _get_bgp_attributes(destination, c_route_dict)

                    results[destination].append(c_route_dict)

        return results

    def _get_vrfs_by_protocol(self, protocol):
        command = 'show vrf'
        output = self.device.send_command(command)
        vrf_tbl = AOSTable(output)
        vrfs = []

        for index, vrf in enumerate(vrf_tbl.get_column_by_name("Virtual Routers")):
            _protocol = vrf_tbl.get_column_by_name("Protocols")[index].lower()
            if protocol == '' or protocol in _protocol:
                vrfs.append(vrf.strip())

        return vrfs

    def get_bgp_neighbors(self):
        """Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).
        The inner dictionary will contain the following data for each vrf
        Example response:
        {
            "global": {
                "router_id": "10.0.1.1",
                "peers": {
                    "10.0.0.2": {
                        "local_as": 65000,
                        "remote_as": 65000,
                        "remote_id": "10.0.1.2",
                        "is_up": True,
                        "is_enabled": True,
                        "description": "internal-2",
                        "uptime": 4838400,
                        "address_family": {
                            "ipv4": {
                                "sent_prefixes": 637213,
                                "accepted_prefixes": 3142,
                                "received_prefixes": 3142
                            },
                            "ipv6": {
                                "sent_prefixes": 36714,
                                "accepted_prefixes": 148,
                                "received_prefixes": 148
                            }
                        }
                    }
                }
            }
        }
        """

        result = {}
        _PEER_FIELD_MAP_ = {
            "local_as": 0,
            "remote_as": 0,
            "remote_id": u'',
            "is_up": False,
            "is_enabled": False,
            "description": u"",
            "uptime": 0,
            "address_family": {
                "ipv4": {
                    "sent_prefixes": 0,
                    "accepted_prefixes": 0,
                    "received_prefixes": 0
                },
                "ipv6": {
                    "sent_prefixes": 0,
                    "accepted_prefixes": 0,
                    "received_prefixes": 0
                }
            }
        }

        ip_bgp_outs, bgp_neighbor_outs, v6_bgp_neighbor_outs, router_id_outs = [], [], [], []
        vrfs = self._get_vrfs_by_protocol('bgp')
        for vrf in vrfs:
            command = 'vrf {} show ip bgp'.format(vrf)
            ip_bgp_outs.append(self.device.send_command(command))

            command = 'vrf {} show ip router-id'.format(vrf)
            router_id_outs.append(self.device.send_command(command))

            command = 'vrf {} show ip bgp neighbors'.format(vrf)
            bgp_neighbor_outs.append(self.device.send_command(command))

            command = 'vrf {} show ipv6 bgp neighbors'.format(vrf)
            v6_bgp_neighbor_outs.append(self.device.send_command(command))

        for vrf, ip_bgp_out, router_id_out, bgp_neighbor_out, v6_bgp_neighbor_out in zip(vrfs, ip_bgp_outs,
                                                                                         router_id_outs,
                                                                                         bgp_neighbor_outs,
                                                                                         v6_bgp_neighbor_outs):
            peers = {}
            _vrf = vrf.strip()
            if _vrf == 'default':
                _vrf = 'global'
            ip_bgp_dict = parse_block(ip_bgp_out, delimiter='=')
            router_id = str_filter(ip_bgp_dict['BGP Router Id'])
            local_as = str_filter(ip_bgp_dict['Autonomous System Number'])

            result[_vrf] = {'router_id': router_id}

            bgp_neighbor_tbl = AOSTable(bgp_neighbor_out)
            for index, ipaddr in enumerate(bgp_neighbor_tbl.get_column_by_name("Nbr address")):
                ipaddr = ipaddr.strip()
                remote_as = bgp_neighbor_tbl.get_column_by_name("As")[index]
                remote_id = bgp_neighbor_tbl.get_column_by_name("BGP Id")[index]
                uptime = bgp_neighbor_tbl.get_column_by_name("Up/Down")[index]
                enable = True if bgp_neighbor_tbl.get_column_by_name(
                    "Admin state")[index].lower().strip() == 'enable' else False
                is_up = True if bgp_neighbor_tbl.get_column_by_name(
                    "Oper state")[index].lower().strip() == 'established' else False

                command = 'vrf {} show ip bgp neighbors {}'.format(vrf, ipaddr)
                bgp_neighbor_out = self.device.send_command(command)
                bgp_neighbor_dict = parse_block(bgp_neighbor_out, delimiter='=')
                received_prefixes = str_filter(bgp_neighbor_dict['# of prefixes received'])

                peer = _PEER_FIELD_MAP_.copy()
                peer.update({
                    "local_as": int(local_as),
                    "remote_as": int(remote_as),
                    "remote_id": remote_id,
                    "is_up": is_up,
                    "is_enabled": enable,
                    "uptime": to_seconds(uptime),
                    "address_family": {
                        "ipv4": {
                            "sent_prefixes": 0,
                            "accepted_prefixes": 0,
                            "received_prefixes": int(received_prefixes)
                        },
                        "ipv6": {
                            "sent_prefixes": 0,
                            "accepted_prefixes": 0,
                            "received_prefixes": 0
                        }
                    }
                })

                peers[ipaddr] = peer

            v6_bgp_neighbor_tbl = AOSTable(v6_bgp_neighbor_out)
            for index, ipaddr in enumerate(v6_bgp_neighbor_tbl.get_column_by_name("Nbr address")):
                ipaddr = ipaddr.strip()
                remote_as = bgp_neighbor_tbl.get_column_by_name("As")[index]
                remote_id = bgp_neighbor_tbl.get_column_by_name("BGP Id")[index]
                uptime = bgp_neighbor_tbl.get_column_by_name("Up/Down")[index]
                enable = True if bgp_neighbor_tbl.get_column_by_name(
                    "Admin state")[index].lower().strip() == 'enable' else False
                is_up = True if bgp_neighbor_tbl.get_column_by_name(
                    "Oper state")[index].lower().strip() == 'established' else False

                command = 'vrf {} show ipv6 bgp neighbors {}'.format(vrf, ipaddr)
                bgp_neighbor_dict = parse_block(self.device.send_command(command), delimiter='=')
                received_prefixes = str_filter(bgp_neighbor_dict['# of prefixes received'])

                peer = _PEER_FIELD_MAP_.copy()
                peer.update({
                    "local_as": int(local_as),
                    "remote_as": int(remote_as),
                    "remote_id": remote_id,
                    "is_up": is_up,
                    "is_enabled": enable,
                    "uptime": to_seconds(uptime),
                    "address_family": {
                        "ipv4": {
                            "sent_prefixes": 0,
                            "accepted_prefixes": 0,
                            "received_prefixes": 0
                        },
                        "ipv6": {
                            "sent_prefixes": 0,
                            "accepted_prefixes": 0,
                            "received_prefixes": int(received_prefixes)
                        }
                    }
                })

                peers[ipaddr] = peer

            result[_vrf]['peers'] = peers

        return result

    def get_bgp_neighbors_detail(self, neighbor_address=u''):
        """Returns a detailed view of the BGP neighbors as a dictionary of lists.
        Returns a dictionary of dictionaries. The keys for the first dictionary will be the vrf (global if no vrf).
        The keys of the inner dictionary represent the AS number of the neighbors.
        Leaf dictionaries contain the following fields:
        """
        result = {}
        _NEIGHBOR_FIELD = {
                'up': False,
                'local_as': 0,
                'remote_as': 0,
                'router_id': u'',
                'local_address': u'',
                'local_address_configured': u'',
                'local_port': 0,
                'routing_table': u'',
                'remote_address': u'',
                'remote_port': 0,
                'multihop': 0,
                'multipath': 0,
                'remove_private_as': False,
                'import_policy': u'',
                'export_policy': u'',
                'input_messages': 0,
                'output_messages': 0,
                'input_updates': 0,
                'output_updates': 0,
                'messages_queued_out': 0,
                'connection_state': u'',
                'previous_connection_state': u'',
                'last_event': u'',
                'suppress_4byte_as': False,
                'local_as_prepend': False,
                'holdtime': 0,
                'configured_holdtime': 0,
                'keepalive': 0,
                'configured_keepalive': 0,
                'active_prefix_count': 0,
                'received_prefix_count': 0,
                'accepted_prefix_count': 0,
                'suppressed_prefix_count': 0,
                'advertised_prefix_count': 0,
                'flap_count': 0
        }

        vrfs = self._get_vrfs_by_protocol('bgp')

        for vrf in vrfs:
            peers = {}
            routing_table = vrf.strip()
            if vrf == 'default':
                routing_table = u'global'

            command = 'vrf {} show ip bgp'.format(vrf)
            ip_bgp_out = self.device.send_command(command)

            ip_bgp_dict = parse_block(ip_bgp_out, delimiter='=')
            local_as = str_filter(ip_bgp_dict['Autonomous System Number'])
            router_id = str_filter(ip_bgp_dict['BGP Router Id'])

            # Ipv4
            command = 'vrf {} show ip bgp neighbors'.format(vrf, neighbor_address)
            bgp_neighbor_tbl = AOSTable(self.device.send_command(command))
            neighbors_detail = {}
            for ipaddr in bgp_neighbor_tbl.get_column_by_name("Nbr address"):
                ipaddr = ipaddr.strip()
                if neighbor_address == '' or ipaddr == neighbor_address:
                    command = 'vrf {} show ip bgp neighbors {}'.format(vrf, ipaddr)
                    bgp_neighbor_out = self.device.send_command(command)
                    bgp_neighbor_dict = parse_block(bgp_neighbor_out, delimiter='=')
                    connection_state = str_filter(bgp_neighbor_dict["Neighbor Oper state"])
                    is_up = True if connection_state.lower() == 'established' else False
                    remote_as = int(str_filter(bgp_neighbor_dict['Neighbor autonomous system']))
                    local_addr = str_filter(bgp_neighbor_dict['Neighbor local address'])
                    local_address_configured = True if local_addr != "" else False
                    local_port = str_filter(bgp_neighbor_dict['Neighbor local port'])
                    remote_address = str_filter(bgp_neighbor_dict['Neighbor address'])
                    multihop = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    multipath = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    remove_private_as = False if str_filter(
                        bgp_neighbor_dict['Neighbor remove private AS']) == 'disabled' else True
                    received_prefix_count = str_filter(bgp_neighbor_dict['# of prefixes received'])

                    command = 'vrf {} show ip bgp neighbors timer {}'.format(vrf, ipaddr)
                    bgp_neighbor_timer_out = self.device.send_command(command)
                    bgp_neighbor_timer_tbl = AOSTable(bgp_neighbor_timer_out)
                    holdtime = bgp_neighbor_timer_tbl.get_column_by_name("Hold")[0]
                    if not holdtime:
                        holdtime = 0
                    configured_holdtime = bgp_neighbor_timer_tbl.get_column_by_name("Hold(C)")[0]
                    if not configured_holdtime:
                        configured_holdtime = 0
                    keepalive = bgp_neighbor_timer_tbl.get_column_by_name("Kalive")[0]
                    if not keepalive:
                        keepalive = 0
                    configured_keepalive = bgp_neighbor_timer_tbl.get_column_by_name("Ka(C)")[0]
                    if not configured_keepalive:
                        configured_keepalive = 0

                    nbg_detail = _NEIGHBOR_FIELD.copy()
                    nbg_detail.update({
                        'up': is_up,
                        'local_as': int(local_as),
                        'remote_as': int(remote_as),
                        'router_id': router_id,
                        'local_address': local_addr,
                        'local_address_configured': local_address_configured,
                        'local_port': int(local_port),
                        'routing_table': routing_table,
                        'remote_address': remote_address,
                        'multihop': multihop,
                        'multipath': multipath,
                        'remove_private_as': remove_private_as,
                        'connection_state': connection_state,
                        'holdtime': int(holdtime),
                        'configured_holdtime': int(configured_holdtime),
                        'keepalive': int(keepalive),
                        'configured_keepalive': int(configured_keepalive),
                        'received_prefix_count': int(received_prefix_count)
                    })

                    if remote_as not in neighbors_detail:
                        neighbors_detail[remote_as] = []
                    neighbors_detail[remote_as].append(nbg_detail)
            # Ipv6
            command = 'vrf {} show ipv6 bgp neighbors'.format(vrf, neighbor_address)
            v6_bgp_neighbor_tbl = AOSTable(self.device.send_command(command))

            for ipaddr in v6_bgp_neighbor_tbl.get_column_by_name("Nbr address"):
                ipaddr = ipaddr.strip()
                if neighbor_address == '' or ipaddr == neighbor_address:
                    command = 'vrf {} show ipv6 bgp neighbors {}'.format(vrf, ipaddr)
                    bgp_neighbor_out = self.device.send_command(command)
                    bgp_neighbor_dict = parse_block(bgp_neighbor_out, delimiter='=')
                    connection_state = str_filter(bgp_neighbor_dict["Neighbor Oper state"])
                    is_up = True if connection_state.lower() == 'established' else False
                    remote_as = int(str_filter(bgp_neighbor_dict['Neighbor autonomous system']))
                    local_addr = str_filter(bgp_neighbor_dict['Neighbor local address'])
                    local_address_configured = True if local_addr != "" else False
                    local_port = str_filter(bgp_neighbor_dict['Neighbor local port'])
                    remote_address = str_filter(bgp_neighbor_dict['Neighbor address'])
                    multihop = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    multipath = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    remove_private_as = False if str_filter(
                        bgp_neighbor_dict['Neighbor remove private AS']) == 'disabled' else True
                    received_prefix_count = str_filter(bgp_neighbor_dict['# of prefixes received'])

                    command = 'vrf {} show ipv6 bgp neighbors timer {}'.format(vrf, ipaddr)
                    bgp_neighbor_timer_out = self.device.send_command(command)
                    bgp_neighbor_timer_tbl = AOSTable(bgp_neighbor_timer_out)
                    holdtime = next((item for item in bgp_neighbor_timer_tbl.get_column_by_name(
                        "Hold") if item is not None), 0)
                    configured_holdtime = next((item for item in bgp_neighbor_timer_tbl.get_column_by_name(
                        "Hold(C)") if item is not None), 0)
                    keepalive = next((item for item in bgp_neighbor_timer_tbl.get_column_by_name(
                        "Kalive") if item is not None), 0)
                    configured_keepalive = next((item for item in bgp_neighbor_timer_tbl.get_column_by_name(
                        "Ka(C)") if item is not None), 0)

                    nbg_detail = _NEIGHBOR_FIELD.copy()
                    nbg_detail.update({
                        'up': is_up,
                        'local_as': int(local_as),
                        'remote_as': int(remote_as),
                        'router_id': router_id,
                        'local_address': local_addr,
                        'local_address_configured': local_address_configured,
                        'local_port': int(local_port),
                        'routing_table': routing_table,
                        'remote_address': remote_address,
                        'multihop': multihop,
                        'multipath': multipath,
                        'remove_private_as': remove_private_as,
                        'connection_state': connection_state,
                        'holdtime': int(holdtime),
                        'configured_holdtime': int(configured_holdtime),
                        'keepalive': int(keepalive),
                        'configured_keepalive': int(configured_keepalive),
                        'received_prefix_count': int(received_prefix_count)
                    })

                    if remote_as not in neighbors_detail:
                        neighbors_detail[remote_as] = []
                    neighbors_detail[remote_as].append(nbg_detail)
            result[routing_table] = neighbors_detail
        return result

    def get_bgp_config(self, group='', neighbor=''):
        """Implementation of NAPALM method get_bgp_config."""

        _PEER_FIELD_MAP_ = {
            'description': u'',
            'import_policy': u'',
            'export_policy': u'',
            'local_address': u'',
            'local_as': 0,
            'remote_as': 0,
            'authentication_key': u'',
            'route_reflector_client': u'',
            'nhs': False,
            'prefix_limit': {}
        }

        group = {
            'type': u'',
            'apply_groups': [],
            'description': u'',
            'multihop_ttl': 0,
            'multipath': False,
            'local_address': u'',
            'local_as': 0,
            'remote_as': 0,
            'import_policy': u'',
            'export_policy': u'',
            'remove_private_as': False,
            'prefix_limit': {},
            'neighbors': {}
        }

        ip_bgp_outs, bgp_neighbor_outs, bgp_neighbor_timer_outs = [], [], []
        vrfs = self._get_vrfs_by_protocol('bgp')

        for vrf in vrfs:
            command = 'vrf {} show ip bgp'.format(vrf)
            ip_bgp_out = self.device.send_command(command)

            ip_bgp_dict = parse_block(ip_bgp_out, delimiter='=')
            remote_as = str_filter(ip_bgp_dict['Autonomous System Number'])

            command = 'vrf {} show ip bgp neighbors'.format(vrf)
            bgp_neighbor_tbl = AOSTable(self.device.send_command(command))
            for ipaddr in bgp_neighbor_tbl.get_column_by_name("Nbr address"):
                ipaddr = ipaddr.strip()
                if neighbor == '' or ipaddr == neighbor:
                    command = 'vrf {} show ip bgp neighbors {}'.format(vrf, ipaddr)
                    bgp_neighbor_out = self.device.send_command(command)
                    bgp_neighbor_dict = parse_block(bgp_neighbor_out, delimiter='=')
                    connection_state = str_filter(bgp_neighbor_dict["Neighbor Oper state"])
                    is_up = True if connection_state.lower() == 'established' else False
                    local_as = str_filter(bgp_neighbor_dict['Neighbor autonomous system'])
                    local_addr = str_filter(bgp_neighbor_dict['Neighbor local address'])
                    local_address_configured = True if local_addr != "" else False
                    local_port = str_filter(bgp_neighbor_dict['Neighbor local port'])
                    remote_address = str_filter(bgp_neighbor_dict['Neighbor address'])
                    multihop = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    multipath = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    remove_private_as = False if str_filter(
                        bgp_neighbor_dict['Neighbor remove private AS']) == 'disabled' else True
                    received_prefix_count = str_filter(bgp_neighbor_dict['# of prefixes received'])
                    route_reflector_client = False if str_filter(
                        bgp_neighbor_dict['Neighbor route-reflector-client']).lower() == 'disabled' else True
                    next_hop_self = False if str_filter(
                        bgp_neighbor_dict['Neighbor next hop self']).lower() == 'disabled' else True

                    peer = _PEER_FIELD_MAP_.copy()
                    peer.update({
                        'local_address': local_addr,
                        'local_as': int(local_as),
                        'remote_as': int(remote_as),
                        'route_reflector_client': route_reflector_client,
                        'nhs': next_hop_self,
                    })
                    group['neighbors'].update({ipaddr: peer})

            command = 'vrf {} show ipv6 bgp neighbors'.format(vrf)
            v6_bgp_neighbor_tbl = AOSTable(self.device.send_command(command))
            for ipaddr in v6_bgp_neighbor_tbl.get_column_by_name("Nbr address"):
                ipaddr = ipaddr.strip()
                if neighbor == '' or ipaddr == neighbor:
                    command = 'vrf {} show ipv6 bgp neighbors {}'.format(vrf, ipaddr)
                    bgp_neighbor_out = self.device.send_command(command)
                    bgp_neighbor_dict = parse_block(bgp_neighbor_out, delimiter='=')
                    connection_state = str_filter(bgp_neighbor_dict["Neighbor Oper state"])
                    is_up = True if connection_state.lower() == 'established' else False
                    local_as = str_filter(bgp_neighbor_dict['Neighbor autonomous system'])
                    local_addr = str_filter(bgp_neighbor_dict['Neighbor local address'])
                    local_address_configured = True if local_addr != "" else False
                    local_port = str_filter(bgp_neighbor_dict['Neighbor local port'])
                    remote_address = str_filter(bgp_neighbor_dict['Neighbor address'])
                    multihop = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    multipath = False if str_filter(
                        bgp_neighbor_dict['Neighbor EBGP multiHop']).lower() == 'disabled' else True
                    remove_private_as = False if str_filter(
                        bgp_neighbor_dict['Neighbor remove private AS']) == 'disabled' else True
                    received_prefix_count = str_filter(bgp_neighbor_dict['# of prefixes received'])
                    route_reflector_client = False if str_filter(
                        bgp_neighbor_dict['Neighbor route-reflector-client']).lower() == 'disabled' else True
                    next_hop_self = False if str_filter(
                        bgp_neighbor_dict['Neighbor next hop self']).lower() == 'disabled' else True

                    peer = _PEER_FIELD_MAP_.copy()
                    peer.update({
                        'local_address': local_addr,
                        'local_as': int(local_as),
                        'remote_as': int(remote_as),
                        'route_reflector_client': route_reflector_client,
                        'nhs': next_hop_self,
                    })
                    group['neighbors'].update({ipaddr: peer})

        return {'': group}

    def get_optics(self):
        """Fetches the power usage on the various transceivers installed
        on the switch (in dbm), and returns a view that conforms with the
        openconfig model openconfig-platform-transceiver.yang
        Returns a dictionary where the keys are as listed below:
            * intf_name (unicode)
                * physical_channels
                    * channels (list of dicts)
                        * index (int)
                        * state
                            * input_power
                                * instant (float)
                                * avg (float)
                                * min (float)
                                * max (float)
                            * output_power
                                * instant (float)
                                * avg (float)
                                * min (float)
                                * max (float)
                            * laser_bias_current
                                * instant (float)
                                * avg (float)
                                * min (float)
                                * max (float)
        Example:
            {
                    'et1': {
                        'physical_channels': {
                            'channel': [
                                {
                                    'index': 0,
                                    'state': {
                                        'input_power': {
                                            'instant': 0.0,
                                            'avg': 0.0,
                                            'min': 0.0,
                                            'max': 0.0,
                                        },
                                        'output_power': {
                                            'instant': 0.0,
                                            'avg': 0.0,
                                            'min': 0.0,
                                            'max': 0.0,
                                        },
                                        'laser_bias_current': {
                                            'instant': 0.0,
                                            'avg': 0.0,
                                            'min': 0.0,
                                            'max': 0.0,
                                        },
                                    }
                                }
                            ]
                        }
                    }
                }
        """
        dbgMsg()
        optics_detail = {}

        command = 'show interfaces ddm actual'
        ddm_output = self.device.send_command(command)
        ddm_tbl = AOSTable(ddm_output)

        for index, iface in enumerate(ddm_tbl.get_column_by_index(0)):
            iface_detail = {}
            iface_detail['physical_channels'] = {}
            iface_detail['physical_channels']['channel'] = []

            laser_bias_current = ddm_tbl.get_column_by_index(3)[index]
            output_power = ddm_tbl.get_column_by_index(4)[index]
            input_power = ddm_tbl.get_column_by_index(5)[index]

            # Defaulting avg, min, max values to 0.0 since device does not
            # return these values
            optic_states = {
                'index': 0,
                'state': {
                    'input_power': {
                        'instant': get_dec_num(input_power, float),
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    },
                    'output_power': {
                        'instant': get_dec_num(output_power, float),
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    },
                    'laser_bias_current': {
                        'instant': get_dec_num(laser_bias_current, float),
                        'avg': 0.0,
                        'min': 0.0,
                        'max': 0.0
                    }
                }
            }

            iface_detail['physical_channels']['channel'].append(optic_states)
            optics_detail[iface] = iface_detail

        return optics_detail
