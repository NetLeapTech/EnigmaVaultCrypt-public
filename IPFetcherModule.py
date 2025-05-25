import socket
import requests
from typing import Dict, List, Optional, Tuple

try:
    import psutil
except ImportError:
    psutil = None


def get_local_ipv4(timeout: int = 5) -> Optional[str]:
    dns_servers = ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '114.114.114.114']

    for dns in dns_servers:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((dns, 80))
                return s.getsockname()[0]
        except (socket.timeout, socket.error):
            continue

    try:
        return socket.gethostbyname(socket.gethostname())
    except socket.error:
        return None


def get_local_ipv6(timeout: int = 5) -> Optional[str]:
    dns_servers = ['2001:4860:4860::8888', '2001:4860:4860::8844', '2606:4700:4700::1111']

    for dns in dns_servers:
        try:
            with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((dns, 80))
                return s.getsockname()[0]
        except (socket.timeout, socket.error):
            continue

    return None


def get_all_network_interfaces() -> Dict[str, Dict[str, List[str]]]:
    if psutil is None:
        raise ImportError("psutil is required for this function. Please install it with 'pip install psutil'.")

    interfaces = psutil.net_if_addrs()
    result = {}
    for interface_name, interface_addresses in interfaces.items():
        ipv4 = []
        ipv6 = []
        for addr in interface_addresses:
            if addr.family == socket.AF_INET:
                ipv4.append(addr.address)
            elif addr.family == socket.AF_INET6:
                ipv6.append(addr.address)
        result[interface_name] = {"ipv4": ipv4, "ipv6": ipv6}
    return result


def get_primary_ip(ip_version: str = 'ipv4', timeout: int = 5) -> Optional[Tuple[str, str]]:
    dns_servers = {
        'ipv4': ['8.8.8.8', '8.8.4.4', '1.1.1.1', '9.9.9.9', '114.114.114.114'],
        'ipv6': ['2001:4860:4860::8888', '2001:4860:4860::8844', '2606:4700:4700::1111']
    }

    for dns in dns_servers[ip_version]:
        try:
            family = socket.AF_INET if ip_version == 'ipv4' else socket.AF_INET6
            with socket.socket(family, socket.SOCK_DGRAM) as s:
                s.settimeout(timeout)
                s.connect((dns, 80))
                ip = s.getsockname()[0]
                interface = s.getsockname()[1]
                return ip, interface
        except (socket.timeout, socket.error):
            continue

    return None


def get_local_ip(interface: Optional[str] = None, ip_version: str = 'ipv4', timeout: int = 5) -> Dict[str, List[str]]:
    all_interfaces = get_all_network_interfaces()

    if interface:
        if interface in all_interfaces:
            return {interface: all_interfaces[interface][ip_version]}
        else:
            raise ValueError(f"Interface {interface} not found")

    primary_ip = get_primary_ip(ip_version, timeout)
    if primary_ip:
        primary_ip, primary_interface = primary_ip
        return {primary_interface: [primary_ip]}

    return {name: info[ip_version] for name, info in all_interfaces.items() if info[ip_version]}


def get_public_ipv4() -> Optional[str]:
    services = [
        'https://api.ipify.org',
        'https://api.my-ip.io/ip',
        'https://ip4.seeip.org'
    ]

    for service in services:
        try:
            response = requests.get(service, timeout=5)
            if response.status_code == 200:
                return response.text.strip()
        except requests.RequestException:
            continue

    return None