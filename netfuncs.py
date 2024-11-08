import sys
import json

def ipv4_to_value(ipv4_addr):
    """
    Convert a dots-and-numbers IP address to a single 32-bit numeric
    value of integer type. Returns an integer type.
    """

    ip = ipv4_addr.split(".")
    ip = [int(i) for i in ip]
    ip_int = (ip[0] << 24) + (ip[1] << 16) + (ip[2] << 8) + ip[3]
    return ip_int
def value_to_ipv4(addr):
    """
    Convert a single 32-bit numeric value of integer type to a
    dots-and-numbers IP address. Returns a string type.
    """

    ip = []
    ip.append(str((addr >> 24) & 0xff))
    ip.append(str((addr >> 16) & 0xff))
    ip.append(str((addr >> 8) & 0xff))
    ip.append(str(addr & 0xff))
    return ".".join(ip)

def get_subnet_mask_value(slash):
    """
    Given a subnet mask in slash notation, return the value of the mask
    as a single number of integer type. The input can contain an IP
    address optionally, but that part should be discarded.

    Returns an integer type.
    """

    mask_int = int(slash.split("/")[1])
    mask = 0xffffffff << (32 - mask_int)
    return mask

def ips_same_subnet(ip1, ip2, slash):
    """
    Given two dots-and-numbers IP addresses and a subnet mask in slash
    notataion, return true if the two IP addresses are on the same
    subnet.

    Returns a boolean.
    """

    ip1_int = ipv4_to_value(ip1)
    ip2_int = ipv4_to_value(ip2)
    mask = get_subnet_mask_value(slash)
    return (ip1_int & mask) == (ip2_int & mask)

def get_network(ip_value, netmask):
    """
    Return the network portion of an address value as integer type.
    """
    return ip_value & netmask

def find_router_for_ip(routers, ip):
    """
    Search a dictionary of routers (keyed by router IP) to find which
    router belongs to the same subnet as the given IP.

    Return None if no routers is on the same subnet as the given IP.
    """
    for router_ip in routers:
        if ips_same_subnet(router_ip, ip, routers[router_ip]["netmask"]):
            return router_ip
    return None

# Uncomment this code to have it run instead of the real main.
# Be sure to comment it back out before you submit!
def test_ipv4_to_value(ip, expected):
    result = ipv4_to_value(ip)
    assert result == expected, f"Failed on {ip}"
    print(f"Success ipv4_to_value: ip: {ip} is: {result}")

def test_value_to_ipv4(value, expected):
    result = value_to_ipv4(value)
    assert result == expected, f"Failed on {value}"
    print(f"Success value_to_ipv4: int: {value} is ip: {result}")

def test_get_subnet_mask_value(slash, expected):
    result = get_subnet_mask_value(slash)
    assert result == expected, f"Failed on {slash}"
    print(f"Success get_subnet_mask_value: slash: {slash} is: {result}")

def test_ips_same_subnet(ip1, ip2, slash, expected):
    result = ips_same_subnet(ip1, ip2, slash)
    assert result == expected, f"Failed on {ip1}, {ip2}, {slash}"
    print(f"Success ips_name_subnet: ip: {ip1}, and ip: {ip2}, with subnet: {slash} are {result}ly on the same network")

def test_get_network(ip_value, netmask, expected):
    result = get_network(ip_value, netmask)
    assert result == expected, f"Failed on {ip_value}, {netmask}"
    print(f"Success get_network: ip: {ip_value}, with mask: {netmask}, got network: {result}")

def test_find_router_for_ip(routers, ip, expected):
    result = find_router_for_ip(routers, ip)
    assert result == expected, f"Failed on {routers}, {ip}"
    print(f"Success router_for_ip: routed {ip} to {result}")

global my_tests
def my_tests():
    print("-------------------------------------")
    print("This is the result of my custom tests")
    print("-------------------------------------")

    test_ipv4_to_value("190.168.97.0", 3198705920)
    test_value_to_ipv4(3198705920, "190.168.97.0")
    test_get_subnet_mask_value("/23", 2199023255040)
    test_ips_same_subnet("190.168.97.0", "190.168.97.255", "/23", True)
    test_get_network(3198705920, 2199023255040, 3198705664)
    test_find_router_for_ip({"190.168.97.0": {"netmask": "/23"}, "190.168.99.0": {"netmask": "/23"}}, "190.168.97.255", "190.168.97.0")


## -------------------------------------------
## Do not modify below this line
##
## But do read it so you know what it's doing!
## -------------------------------------------

def usage():
    print("usage: netfuncs.py infile.json", file=sys.stderr)

def read_routers(file_name):
    with open(file_name) as fp:
        json_data = fp.read()
        
    return json.loads(json_data)

def print_routers(routers):
    print("Routers:")

    routers_list = sorted(routers.keys())

    for router_ip in routers_list:

        # Get the netmask
        slash_mask = routers[router_ip]["netmask"]
        netmask_value = get_subnet_mask_value(slash_mask)
        netmask = value_to_ipv4(netmask_value)

        # Get the network number
        router_ip_value = ipv4_to_value(router_ip)
        network_value = get_network(router_ip_value, netmask_value)
        network_ip = value_to_ipv4(network_value)

        print(f" {router_ip:>15s}: netmask {netmask}: " \
            f"network {network_ip}")

def print_same_subnets(src_dest_pairs):
    print("IP Pairs:")

    src_dest_pairs_list = sorted(src_dest_pairs)

    for src_ip, dest_ip in src_dest_pairs_list:
        print(f" {src_ip:>15s} {dest_ip:>15s}: ", end="")

        if ips_same_subnet(src_ip, dest_ip, "/24"):
            print("same subnet")
        else:
            print("different subnets")

def print_ip_routers(routers, src_dest_pairs):
    print("Routers and corresponding IPs:")

    all_ips = sorted(set([i for pair in src_dest_pairs for i in pair]))

    router_host_map = {}

    for ip in all_ips:
        router = str(find_router_for_ip(routers, ip))
        
        if router not in router_host_map:
            router_host_map[router] = []

        router_host_map[router].append(ip)

    for router_ip in sorted(router_host_map.keys()):
        print(f" {router_ip:>15s}: {router_host_map[router_ip]}")

def main(argv):
    if "my_tests" in globals() and callable(my_tests):
        my_tests()
        return 0

    try:
        router_file_name = argv[1]
    except:
        usage()
        return 1

    json_data = read_routers(router_file_name)

    routers = json_data["routers"]
    src_dest_pairs = json_data["src-dest"]

    print_routers(routers)
    print()
    print_same_subnets(src_dest_pairs)
    print()
    print_ip_routers(routers, src_dest_pairs)

if __name__ == "__main__":
    sys.exit(main(sys.argv))
    
