import scapy.all as scapy
import netifaces as ni

def get_local_ip():
    try:
        return ni.ifaddresses('eth0')[ni.AF_INET][0]['addr']
    except:
        return None

def get_subnet_mask():
    try:
        return ni.ifaddresses('eth0')[ni.AF_INET][0]['netmask']
    except:
        return None

def get_network_range():
    local_ip = get_local_ip()
    subnet_mask = get_subnet_mask()

    if local_ip and subnet_mask:
        ip_parts = local_ip.split('.')
        mask_parts = subnet_mask.split('.')
        network_parts = [str(int(ip_parts[i]) & int(mask_parts[i])) for i in range(4)]
        network_range = '.'.join(network_parts) + '/24'  # Assuming a /24 subnet mask
        return network_range
    else:
        return None

def scan_network(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    devices_list = []
    for element in answered_list:
        device = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        devices_list.append(device)
    return devices_list

def get_vendor(mac_address):
    try:
        mac_address = mac_address.upper()
        vendor = scapy.ARP().hwsrc(mac_address)
        return vendor
    except:
        return "Unknown"

def print_results(results_list):
    print("IP\t\t\tMAC Address\t\t\tVendor")
    print("-" * 70)
    for device in results_list:
        vendor = get_vendor(device["mac"])
        print(device["ip"] + "\t\t" + device["mac"] + "\t\t" + vendor)

if __name__ == "__main__":
    ip_range = get_network_range()
    if ip_range:
        print(f"Scanning network range: {ip_range}")
        scanned_devices = scan_network(ip_range)
        print_results(scanned_devices)
    else:
        print("Failed to retrieve network information. Please check your network settings.")
