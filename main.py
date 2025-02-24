
from colorama import Fore, Style, init
import socket
import requests
from scapy.all import ARP, Ether, srp
import subprocess
import os
os.system('cls')
import sys

# Initialize colorama
init(autoreset=True)

# Banner
def print_banner():
    banner = f"""
    {Fore.RED}███████╗ {Fore.GREEN}████████╗{Fore.BLUE}████████╗{Fore.YELLOW}████████╗{Fore.MAGENTA}████████╗{Fore.CYAN}████████╗
    {Fore.RED}╚════██║ {Fore.GREEN}╚══██╔══╝{Fore.BLUE}╚══██╔══╝{Fore.YELLOW}╚══██╔══╝{Fore.MAGENTA}╚══██╔══╝{Fore.CYAN}╚══██╔══╝
    {Fore.RED}  ██╔╝  {Fore.GREEN}   ██║   {Fore.BLUE}   ██║   {Fore.YELLOW}   ██║   {Fore.MAGENTA}   ██║   {Fore.CYAN}   ██║   
    {Fore.RED} ██╔╝   {Fore.GREEN}   ██║   {Fore.BLUE}   ██║   {Fore.YELLOW}   ██║   {Fore.MAGENTA}   ██║   {Fore.CYAN}   ██║   
    {Fore.RED}███████╗{Fore.GREEN}   ██║   {Fore.BLUE}   ██║   {Fore.YELLOW}   ██║   {Fore.MAGENTA}   ██║   {Fore.CYAN}   ██║   
    {Fore.RED}╚══════╝{Fore.GREEN}   ╚═╝   {Fore.BLUE}   ╚═╝   {Fore.YELLOW}   ╚═╝   {Fore.MAGENTA}   ╚═╝   {Fore.CYAN}   ╚═╝   
    {Style.RESET_ALL}
    {Fore.CYAN}Z-Tools: Ethical Hacking Toolkit{Style.RESET_ALL}
    """
    print(banner)

# Tools
def dns_lookup(domain):
    print(f"{Fore.GREEN}[*] Performing DNS Lookup for {domain}...{Style.RESET_ALL}")
    try:
        ip = socket.gethostbyname(domain)
        print(f"{Fore.GREEN}[+] IP Address: {ip}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def whois_lookup(domain):
    print(f"{Fore.BLUE}[*] Performing WHOIS Lookup for {domain}...{Style.RESET_ALL}")
    try:
        result = subprocess.run(['whois', domain], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def arp_scan(network):
    print(f"{Fore.YELLOW}[*] Performing ARP Scan on {network}...{Style.RESET_ALL}")
    try:
        arp = ARP(pdst=network)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether/arp
        result = srp(packet, timeout=2, verbose=0)[0]
        for sent, received in result:
            print(f"{Fore.GREEN}[+] IP: {received.psrc}, MAC: {received.hwsrc}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def http_header_check(url):
    print(f"{Fore.MAGENTA}[*] Checking HTTP Headers for {url}...{Style.RESET_ALL}")
    try:
        response = requests.get(url)
        for header, value in response.headers.items():
            print(f"{Fore.GREEN}[+] {header}: {value}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def subdomain_bruteforce(domain, wordlist):
    print(f"{Fore.CYAN}[*] Bruteforcing Subdomains for {domain}...{Style.RESET_ALL}")
    try:
        with open(wordlist, 'r') as f:
            for subdomain in f.readlines():
                subdomain = subdomain.strip()
                url = f"http://{subdomain}.{domain}"
                try:
                    requests.get(url)
                    print(f"{Fore.GREEN}[+] Found: {url}{Style.RESET_ALL}")
                except requests.ConnectionError:
                    pass
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def port_scan(target, ports):
    print(f"{Fore.RED}[*] Scanning Ports on {target}...{Style.RESET_ALL}")
    try:
        for port in ports:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Fore.GREEN}[+] Port {port} is open{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[-] Port {port} is closed{Style.RESET_ALL}")
            sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def reverse_dns_lookup(ip):
    print(f"{Fore.YELLOW}[*] Performing Reverse DNS Lookup for {ip}...{Style.RESET_ALL}")
    try:
        domain = socket.gethostbyaddr(ip)
        print(f"{Fore.GREEN}[+] Domain: {domain[0]}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def check_ssl_certificate(domain):
    print(f"{Fore.MAGENTA}[*] Checking SSL Certificate for {domain}...{Style.RESET_ALL}")
    try:
        result = subprocess.run(['openssl', 's_client', '-connect', f'{domain}:443'], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def geolocation_lookup(ip):
    print(f"{Fore.CYAN}[*] Performing Geolocation Lookup for {ip}...{Style.RESET_ALL}")
    try:
        response = requests.get(f"http://ip-api.com/json/{ip}")
        data = response.json()
        if data['status'] == 'success':
            print(f"{Fore.GREEN}[+] Country: {data['country']}")
            print(f"[+] City: {data['city']}")
            print(f"[+] ISP: {data['isp']}{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[-] Error: {data['message']}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

def check_robots_txt(url):
    print(f"{Fore.RED}[*] Checking robots.txt for {url}...{Style.RESET_ALL}")
    try:
        response = requests.get(f"{url}/robots.txt")
        if response.status_code == 200:
            print(f"{Fore.GREEN}[+] robots.txt found:{Style.RESET_ALL}")
            print(response.text)
        else:
            print(f"{Fore.RED}[-] robots.txt not found{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {e}{Style.RESET_ALL}")

# Main Menu
def main_menu():
    print_banner()
    print(f"{Fore.CYAN}1. DNS Lookup")
    print(f"{Fore.BLUE}2. WHOIS Lookup")
    print(f"{Fore.YELLOW}3. ARP Scan")
    print(f"{Fore.MAGENTA}4. HTTP Header Check")
    print(f"{Fore.CYAN}5. Subdomain Bruteforce")
    print(f"{Fore.RED}6. Port Scan")
    print(f"{Fore.YELLOW}7. Reverse DNS Lookup")
    print(f"{Fore.MAGENTA}8. SSL Certificate Check")
    print(f"{Fore.CYAN}9. Geolocation Lookup")
    print(f"{Fore.RED}10. Check robots.txt")
    print(f"{Fore.GREEN}0. Exit{Style.RESET_ALL}")

    choice = input(f"{Fore.CYAN}Enter your choice: {Style.RESET_ALL}")
    return choice

# Main Function
def main():
    while True:
        choice = main_menu()
        if choice == '1':
            domain = input(f"{Fore.GREEN}Enter domain: {Style.RESET_ALL}")
            dns_lookup(domain)
        elif choice == '2':
            domain = input(f"{Fore.GREEN}Enter domain: {Style.RESET_ALL}")
            whois_lookup(domain)
        elif choice == '3':
            network = input(f"{Fore.GREEN}Enter network (e.g., 192.168.1.0/24): {Style.RESET_ALL}")
            arp_scan(network)
        elif choice == '4':
            url = input(f"{Fore.GREEN}Enter URL: {Style.RESET_ALL}")
            http_header_check(url)
        elif choice == '5':
            domain = input(f"{Fore.GREEN}Enter domain: {Style.RESET_ALL}")
            wordlist = input(f"{Fore.GREEN}Enter path to wordlist: {Style.RESET_ALL}")
            subdomain_bruteforce(domain, wordlist)
        elif choice == '6':
            target = input(f"{Fore.GREEN}Enter target IP: {Style.RESET_ALL}")
            ports = list(map(int, input(f"{Fore.GREEN}Enter ports to scan (comma separated): {Style.RESET_ALL}").split(',')))
            port_scan(target, ports)
        elif choice == '7':
            ip = input(f"{Fore.GREEN}Enter IP address: {Style.RESET_ALL}")
            reverse_dns_lookup(ip)
        elif choice == '8':
            domain = input(f"{Fore.GREEN}Enter domain: {Style.RESET_ALL}")
            check_ssl_certificate(domain)
        elif choice == '9':
            ip = input(f"{Fore.GREEN}Enter IP address: {Style.RESET_ALL}")
            geolocation_lookup(ip)
        elif choice == '10':
            url = input(f"{Fore.GREEN}Enter URL: {Style.RESET_ALL}")
            check_robots_txt(url)
        elif choice == '0':
            print(f"{Fore.GREEN}Exiting...{Style.RESET_ALL}")
            break
        else:
            print(f"{Fore.RED}Invalid choice!{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
    os.system('cls')