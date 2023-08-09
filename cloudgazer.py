import json
import requests
import getpass
import socket
from prettytable import PrettyTable

def banner():
    print("""
      _
  ___| | ___  _   _  __| | __ _  __ _ _______ _ __
 / __| |/ _ \| | | |/ _` |/ _` |/ _` |_  / _ \ '__|
| (__| | (_) | |_| | (_| | (_| | (_| |/ /  __/ |
 \___|_|\___/ \__,_|\__,_|\__, |\__,_/___\___|_|
                          |___/
""")

def nslookup(domain):
    ip_list = []
    try:
        result = socket.getaddrinfo(domain, 0, 0, 0, 0)
        for r in result:
            if str(r[0]).endswith('AF_INET'):
                ip_list.append(r[-1][0])
        ip_list = list(set(ip_list))
        return ip_list
    except socket.gaierror:
        return ip_list

def find_real_ip(ip_list, HEADERS):
    url = 'https://api.criminalip.io/v1/ip/data'
    results = []

    for ip in ip_list:
        params = {'ip': ip}
        try:
            res = requests.get(url=url, params=params, headers=HEADERS)
            res.raise_for_status()  # Raise an exception for HTTP errors
            res_data = res.json()

            if res_data['status'] == 200:
                protected_ips = res_data.get('protected_ip', {}).get('data', [])
                real_ips = [d['ip_address'] for d in protected_ips]
                org_name = res_data.get('whois', {}).get('data', [{}])[0].get('org_name', 'N/A')
                opened_ports = [port['open_port_no'] for port in res_data.get('port', {}).get('data', [])]
                results.append({
                    'ip': ip,
                    'real_ip': real_ips,
                    'org': org_name,
                    'opened_ports': opened_ports
                })
            else:
                print("API Error:", res_data.get('message', 'Unknown error'))
        except requests.RequestException as e:
            print("Request Error:", e)
    
    return results

def print_result(results):
    table = PrettyTable(['IP Addr', 'Real IP Addr', 'Organization', 'Opened Ports'])
    for r in results:
        real_ip = '\n'.join(r['real_ip'])
        table.add_row([r['ip'], real_ip, r['org'], r['opened_ports']])
    print(table)

def main():
    domain = input("Enter domain: ")
    ip_list = nslookup(domain)

    api_key = getpass.getpass("Enter Criminal IP API KEY : ")
    HEADERS = {
        "x-api-key": api_key,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    }

    results = find_real_ip(ip_list, HEADERS)
    print_result(results)

if __name__ == '__main__':
    banner()
    main()
