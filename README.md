PandaProbe
==========



#### Description:

Note: This project was created for educational purposes and does not serve any practical use

PandaProbe is a simple network reconnaissance tool that provides essential information about a target domain or IP address.
This project was built was the final project of Harvard's CS50Python programme

### Key Features:

1.  TCP Scan: Conduct TCP port scans to identify open ports on the target system. This provides valuable insights into the available services, aiding in vulnerability assessment and network exploration.

2.  UDP Scan: Perform UDP port scans to discover open UDP services. This feature is handy for identifying less common services that may be running on a system, enhancing the comprehensiveness of the scan.

3.  ICMP Scan: Perform ICMP (Ping) scans to check the availability of a target. This basic assessment helps determine whether a host is reachable, providing a foundational understanding of network connectivity.

4.  DNS Enumeration: Gather comprehensive DNS information about a domain, including name servers, mail exchange records, and other relevant details. This feature is crucial for understanding a target's online infrastructure and potential points of entry.

5.  WHOIS Lookup: Retrieve detailed WHOIS information for a domain, including registration details such as the domain owner, registrar, and registration date. This data is essential for investigating and validating domain ownership.

6.  Geolocation Tracking: Obtain geolocation information based on the IP address of a target. This feature assists in determining the approximate physical location of the target, adding a layer of context to the scanning results.

PandaProbe provides an interactive command-line interface for easy usage, ensuring accessibility for both beginners and experienced users in the cybersecurity domain.

Getting Started
---------------

### Prerequisites:

-   Python 3.x
-   Install dependencies using the following command:

```bash

`pip install -r requirements.txt`
```

### Usage:


1.  Install the required dependencies:

```bash

`pip install -r requirements.txt`
```

2.  Run PandaProbe:

```bash

`python project.py`
```

1.  Follow the on-screen instructions to choose a scanning option and provide the necessary input.

PandaProbe is continually evolving, and contributions are welcome. Feel free to explore additional features, enhance existing functionalities, and customize the tool according to your needs. If you encounter any issues or have suggestions, please open an issue on the GitHub repository.

Acknowledgments:
----------------

PandaProbe utilizes various Python libraries, including Scapy, requests, dnspython, python-whois, and ipaddress.

License:
--------

This project is licensed under the [MIT License]

Author:
-------

Tenco

### Disclaimer:

PandaProbe is intended for educational and informational purposes only. Usage of this tool for any malicious activities is strictly prohibited. The authors are not responsible for any misuse or damage caused by PandaProbe.
