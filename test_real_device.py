import napalm as napalm
from napalm_aos.utils.utils import *

driver = napalm.get_network_driver('aos')
device = driver(hostname='', username='', password='')
device.open()

print("is_alive")
jprint(device.is_alive())

print("get_arp_table")
jprint(device.get_arp_table())

print("get_bgp_neighbors")
jprint(device.get_bgp_neighbors())

print("get_environment")
jprint(device.get_environment())

print("get_facts")
jprint(device.get_facts())

print("get_interfaces")
jprint(device.get_interfaces())

print("get_interfaces_counters")
jprint(device.get_interfaces_counters())

print("get_interfaces_ip")
jprint(device.get_interfaces_ip())

print("get_lldp_neighbors")
jprint(device.get_lldp_neighbors())

print("get_mac_address_table")
jprint(device.get_mac_address_table())

print("get_ntp_peers")
jprint(device.get_ntp_peers())

print("get_ntp_servers")
jprint(device.get_ntp_servers())

print("get_ntp_stats")
jprint(device.get_ntp_stats())

print("get_route_to")
jprint(device.get_route_to())

print("get_snmp_information")
jprint(device.get_snmp_information())
                                                                                                                 
print("get_users")
jprint(device.get_users())

print("ping")
jprint(device.ping(destination="192.168.120.123"))

print("traceroute")
jprint(device.traceroute(destination="192.168.120.123"))

print("Send command: vlan 700")
device.cli(["vlan 700"])
cliOutput = device.cli(["show vlan"])
tableOutput = AOSTable(cliOutput["show vlan"])
for index, vlan in enumerate(tableOutput.get_column_by_name("vlan")):
    if(tableOutput.get_column_by_name("vlan")[index] == "700"):
        print("Create vlan 700: Success!")
        break

print("Send command: no vlan 700")
flag = 1
device.cli(["no vlan 700"])
cliOutput = device.cli(["show vlan"])
tableOutput = AOSTable(cliOutput["show vlan"])
for index, vlan in enumerate(tableOutput.get_column_by_name("vlan")):
    if(tableOutput.get_column_by_name("vlan")[index] == "700"):
        flag = 0
        print("Delete vlan 700: False!")
        break

if(flag == 1):
    print("Delete vlan 700: Success!")

device.close()
