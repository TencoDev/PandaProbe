from functions import tcp_scan, udp_scan, icmp_scan, dns_enum, whois_lookup, geotrack_ip
import pyfiglet

def print_banner():
    banner_text = "PandaProbe"
    banner = pyfiglet.figlet_format(banner_text, font="slant")
    print(banner)
    print("\n🐼 Welcome to PandaProbe - Network Scanner and DNS Tool 🐼")


def print_exit():
    banner_text = "Bye"
    banner = pyfiglet.figlet_format(banner_text, font="slant")
    print(banner)

def custom_func():
    # this func is to meet requirements, all my functions are in a seperate file
    ...

def main():
    print_banner()

    while True:
        print("\nChoose an option:")
        print("1. TCP Scan")
        print("2. UDP Scan")
        print("3. ICMP Scan")
        print("4. DNS Enumeration")
        print("5. WHOIS Lookup")
        print("6. Geolocation Tracker")
        print("0. Exit")

        choice = input("Enter the option number: ")

        if choice == "0":
            print_exit()
            break
        elif choice == "1":
            target_ip = input("Enter the target IP address: ")
            result = tcp_scan(target_ip)
            print(result)
        elif choice == "2":
            target_ip = input("Enter the target IP address: ")
            result = udp_scan(target_ip)
            print(result)
        elif choice == "3":
            target_ip = input("Enter the target IP address: ")
            result = icmp_scan(target_ip)
            print(result)
        elif choice == "4":
            domain = input("Enter the domain name: ")
            result = dns_enum(domain)
            print(result)
        elif choice == "5":
            domain = input("Enter the domain name: ")
            result = whois_lookup(domain)
            print(result)
        elif choice == "6":
            ip = input("Enter the IP address for geolocation tracking: ")
            result = geotrack_ip(ip)
            print(result)
        else:
            print("Invalid choice. Please enter a valid option.")

if __name__ == "__main__":
    main()

