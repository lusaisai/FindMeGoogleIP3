import urllib.request
import concurrent.futures
import dns.resolver
import dns.exception
import socket
import ssl
import json


def download_dns_servers(domain):
    dns_servers = set()
    url = 'https://public-dns.info/nameserver/%s.txt' % domain

    print("downloading dns server list from %s" % url)
    with urllib.request.urlopen(url) as f:
        for server in f:
            dns_servers.add(server.strip())

    return dns_servers


def download_all_dns_servers(domains):
    dns_servers = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        download_futures = [executor.submit(download_dns_servers, domain) for domain in domains]
        for download_future in concurrent.futures.as_completed(download_futures):
            for dns_server in download_future.result():
                dns_servers.add(dns_server)

    return dns_servers


def make_dns_query(dns_server):
    dns_client = dns.resolver.Resolver()
    dns_client.nameservers = [dns_server]
    dns_client.lifetime = 5
    try:
        print('making dns query to %s' % dns_server)
        result = dns_client.query('www.google.com')
        if len(result) > 0:
            return [str(ip) for ip in result]
        else:
            return None
    except (dns.exception.DNSException, ValueError, TypeError):
        return None


def make_all_dns_query(dns_servers):
    ips = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        dns_futures = [executor.submit(make_dns_query, dns_server) for dns_server in dns_servers]
        for dns_future in concurrent.futures.as_completed(dns_futures):
            if dns_future.result():
                for ip in dns_future.result():
                    ips.add(ip)

    return ips


def ssl_check(ip):
    socket.setdefaulttimeout(2)
    s = ssl.SSLContext().wrap_socket(socket.socket(), server_hostname='google.com')
    try:
        print('ssl check for ip %s' % ip)
        s.connect((ip, 443))
        return ip
    except (ssl.CertificateError, ssl.SSLError, socket.timeout, OSError):
        return None


def ssl_check_all(ips):
    verified_ips = set()
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        ip_futures = [executor.submit(ssl_check, ip) for ip in ips]
        for ip_future in concurrent.futures.as_completed(ip_futures):
            if ip_future.result():
                verified_ips.add(ip_future.result())

    return verified_ips


if __name__ == '__main__':
    domains = ['kr', 'tw']
    dns_servers = download_all_dns_servers(domains)
    ips = make_all_dns_query(dns_servers)
    verified_ips = ssl_check_all(ips)
    print('+' * 88)
    print(json.dumps(list(verified_ips)))
