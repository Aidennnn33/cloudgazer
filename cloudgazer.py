import json
import requests
import getpass
import socket
from prettytable import PrettyTable


def banner():
    print("""
      _                 _
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

    except:
        return ip_list


def find_real_ip(ip_list, HEADERS):
    url = 'https://api.criminalip.io/v1/asset/ip/report'
    
    results = []
    for ip in ip_list:
        params = {
            'ip': ip
        }

        res = requests.get(url=url, params=params, headers=HEADERS)
        res = res.json()

        if res['status'] == 200:
            
            protected_ip_data = res.get('protected_ip', {}).get('data', [])
            real_ip_addresses = [d['ip_address'] for d in protected_ip_data]

            org_data = res.get('whois', {}).get('data', [])
            org_name = org_data[0].get('org_name', 'Unknown Organization') if org_data else 'Unknown Organization'

            opened_ports_data = res.get('port', {}).get('data', [])
            opened_ports = [port.get('open_port_no', 'Unknown Port') for port in opened_ports_data]

            results.append({
                'ip': res['ip'],
                'real_ip': real_ip_addresses,
                'org': org_name,
                'opened_ports': opened_ports,
            })
        else:
            print(res.get('message', 'An unknown error occurred'))
            break

    return results


def print_result(results):
    table = PrettyTable(['IP Addr', 'Real IP Addr', 'Organization', 'Opened Ports'])

    for r in results:
        real_ip = '\n'.join(r['real_ip'])
        table.add_row([r['ip'], real_ip, r['org'], r['opened_ports']])

    print(table)


def main():
    domain = input("Enter domain : ")
    ip_list = nslookup(domain)

    results = find_real_ip(ip_list, HEADERS)

    print_result(results)


if __name__ == '__main__':
    banner()

    api_key = getpass.getpass("Enter Criminal IP API KEY : ")
    HEADERS = {
        "x-api-key": api_key,
        "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    }

    main()

