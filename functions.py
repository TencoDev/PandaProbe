from scapy.all import IP, sr, Scapy_Exception, UDP, TCP, ICMP
import dns.resolver
import requests
import whois
import ipaddress

def geotrack_ip(ip):
    try:
        # Validate the IP address
        ipaddress.IPv4Address(ip)

        # Make a request to ipinfo.io
        response = requests.get(f'https://ipinfo.io/{ip}/json')

        # Check if the request was successful
        if response.status_code == 200:
            # Parse the JSON response
            data = response.json()

            # Extract
            location_info = {
                'IP': data.get('ip', ''),
                'City': data.get('city', ''),
                'Region': data.get('region', ''),
                'Country': data.get('country', ''),
                'Location': data.get('loc', ''),
                'ISP': data.get('org', ''),
                'AS': data.get('asn', '')
            }

            return location_info
        else:
            return f"🐼 failed to get geolocation data. Status code: {response.status_code}"

    except ipaddress.AddressValueError:
        return "Invalid IP address entered. Please enter a valid IPv4 address."

    except Exception as e:
        return f"🐼 encountered an error occurred: {str(e)}"

def icmp_scan(target_ip):
    try:
        # Create an IP layer:
        ip_layer = IP(dst=target_ip)

        # Create an ICMP layer (Ping request):
        icmp_layer = ICMP()

        # Create the packet:
        packet = ip_layer / icmp_layer

        # Send the packet and wait for a response:
        response = sr1(packet, timeout=2, verbose=False)

        if response and response.haslayer(ICMP):
            return f"🐼 detected that {target_ip} is reachable (ICMP Reply received)🎉."
        else:
            return f"🐼 detected that {target_ip} is unreachable or not responding to ICMP😵."

    except Exception as e:
        return f"An error occurred: {str(e)}"


def tcp_scan(target_ip, port=80, scan_type="S"):
    try:
        # Validate target IP
        ipaddress.IPv4Address(target_ip)

        # Create an IP layer:
        ip_layer = IP(dst=target_ip)

        # Create a TCP layer:
        tcp_layer = TCP(dport=port, flags=scan_type)

        # Creating the packet:
        packet = ip_layer / tcp_layer

        # Get response
        response = sr(packet, iface="Wi-Fi", timeout=2, verbose=False)[0]

        if response:
            return response
        if scan_type == "A":
            return "🐼 detected that the port is likely to be filtered"
        else:
            return "Host may be protected or unreachable, 🐼 unable to fetch response"

    except ValueError:
        return "Invalid IP address entered. Please enter a valid IPv4 address."
    except Scapy_Exception as e:
        return f"An error occurred: {str(e)}"


def udp_scan(target_ip, port=80):
    try:
        # Validate target IP
        ipaddress.IPv4Address(target_ip)

        # Create an IP layer:
        ip_layer = IP(dst=target_ip)

        # Create a UDP layer:
        udp_layer = UDP(dport=port)

        # Creating the packet:
        packet = ip_layer / udp_layer

        # Get response
        response = sr(packet, iface="Wi-Fi", timeout=2, verbose=False)[0]

        if response:
            return response
        else:
            return "🐼 did not receive a response. The port may be closed or filtered 📪"

    except ValueError:
        return "Invalid IP address entered. Please enter a valid IPv4 address for 🐼 to function."
    except Scapy_Exception as e:
        return f"An error occurred: {str(e)}"


def dns_enum(domain):
    try:
        # Perform DNS A record query to get IP addresses associated with the domain
        a_records = dns.resolver.resolve(domain, 'A')
        ips = [record.address for record in a_records]

        # Perform DNS MX record query to get mail servers associated with the domain
        mx_records = dns.resolver.resolve(domain, 'MX')
        mail_servers = [(record.preference, str(record.exchange)) for record in mx_records]

        # Perform DNS NS record query to get name servers associated with the domain
        ns_records = dns.resolver.resolve(domain, 'NS')
        name_servers = [str(record) for record in ns_records]

        # Return the gathered information
        return {
            'IP Addresses': ips,
            'Mail Servers': mail_servers,
            'Name Servers': name_servers
        }

    except dns.resolver.NXDOMAIN:
        return f"🐼 was unable to find Domain: '{domain}'."

    except Exception as e:
        return f"🐼encountered an error: {str(e)}"

def whois_lookup(domain):
    try:
        result = whois.whois(domain)

        # Extract
        domain_info = {
            'Domain Name': result.domain_name,
            'Registrar': result.registrar,
            'Creation Date': result.creation_date,
            'Expiration Date': result.expiration_date,
            'Updated Date': result.updated_date,
            'Name Servers': result.name_servers,
            'Status': result.status,
            'WHOIS Server': result.whois_server,
            'Registrant': result.registrant,
            'Admin': result.admin,
            'Tech': result.tech
        }

        return domain_info

    except Exception as e:
        return f"🐼 encountered an error during WHOIS lookup: {str(e)}"
