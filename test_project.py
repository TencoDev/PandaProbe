from scanner.scans.tcp_scanner import tcp_scan
from scanner.scans.udp_scanner import udp_scan
from scanner.dns.dns_finder import dns_enum

def test_tcp_scan():
    result = tcp_scan("8.8.8.8", 80)
    assert "may be protected or unreachable" in result.lower()

def test_udp_scan():
    result = udp_scan("8.8.8.8", 53)
    assert "did not receive a response" in result.lower()

def test_dns_enum():
    result = dns_enum("example.com")
    assert isinstance(result, dict)
    assert "IP Addresses" in result
    assert "Mail Servers" in result
    assert "Name Servers" in result
