from dnslib import DNSRecord, DNSHeader, DNSBuffer, DNSQuestion, RR, QTYPE, RCODE
from socket import socket, SOCK_DGRAM, AF_INET
import time

"""
There are 13 root servers defined at https://www.iana.org/domains/root/servers
"""

ROOT_SERVER = "199.7.83.42"    # ICANN Root Server
DNS_PORT = 53
def get_dns_record(udp_socket, domain:str, parent_server: str, record_type):
  q = DNSRecord.question(domain, qtype = record_type)
  q.header.rd = 0   # Recursion Desired?  NO
  udp_socket.sendto(q.pack(), (parent_server, DNS_PORT))
  pkt, _ = udp_socket.recvfrom(8192)
  buff = DNSBuffer(pkt)
  
  """
  RFC1035 Section 4.1 Format
  
  The top level format of DNS message is divided into five sections:
  1. Header
  2. Question
  3. Answer
  4. Authority
  5. Additional
  """
  
  header = DNSHeader.parse(buff)
  if q.header.id != header.id:
    print("Unmatched transaction")
    return None
  if header.rcode != RCODE.NOERROR:
    print("name server could not answer query")
    print(f"the domain '{domain}' may not exist")
    return None
  
  records = []

  # Parse the question section #2
  for k in range(header.q):
    q = DNSQuestion.parse(buff)
    
  # Parse the answer section #3
  for k in range(header.a):
    a = RR.parse(buff)
    records.append(a)
      
  # Parse the authority section #4
  for k in range(header.auth):
    auth = RR.parse(buff)
    records.append(auth)

  # Parse the additional section #5
  for k in range(header.ar):
    adr = RR.parse(buff)
    records.append(adr)

  return records


def cache_records(cache: dict, records: list):
    ns = None
    for record in records:
        name = str(record.rname)
        type = record.rtype
        expires = time.time() + record.ttl
        data = str(record.rdata)

        # print(record)

        if name not in cache:
            cache[name] = {}

        if type == QTYPE.CNAME:
            cache[name]['CNAME'] = {
                'expires': expires,
                'data': data
            }
            return ('CNAME', data)
        
        if type == QTYPE.A:
            cache[name]['A'] = {
                'expires': expires,
                'data': data
            }

        # only replace an existing NS record if this one comes with a corresponding A record
        elif type == QTYPE.NS and ('NS' not in cache[name] or (data in cache and 'A' in cache[data])):
            cache[name]['NS'] = {
                'expires': expires,
                'data': data
            }
            ns = cache[name]['NS']['data']

    if ns is not None:
       return ('NS', ns)
    return ('A', None)


def query_cache(cache: dict, domain: str, rtype: str):
  if domain == '' and rtype == 'NS':
     return ROOT_SERVER
  if domain in cache and rtype in cache[domain] and cache[domain][rtype]['expires'] > time.time():
    return cache[domain][rtype]['data']
  return None


def query_server(sock, cache: dict, label: str, ns: str, rtype: str):
    records = get_dns_record(sock, label, ns, rtype)
    if records is None:
       return (None, None)
    return cache_records(cache, records)


def ip_addr(sock, cache, label):
    ns_domain = None
    ns = ROOT_SERVER

    ip = query_cache(cache, label, 'A')
    if ip is not None:
        print(f"found cached A record for {label}")
        return ip
    
    while True:
        print(f"asking for records from {ns if ns_domain is None else ns_domain} ({ns})")
        (type, ns_domain) = query_server(sock, cache, label, ns, 'A')

        if type is None:
           return
        
        if type == 'CNAME':
           label = ns_domain
           ns = ROOT_SERVER
           continue

        ip = query_cache(cache, label, 'A')
        if ip is not None:
            return ip

        if ns_domain is None:
           print("no namserver")
           break
        
        ns = query_cache(cache, ns_domain, 'A')
        if ns is None:
            ns = ip_addr(sock, cache, ns_domain)


def commands(cmd: str):
    if cmd == '.clear':
        cache.clear()
    elif cmd == '.list':
        i = 0
        for key in list(cache.keys()):
            i += 1
            print(f"{i} {key}: {cache[key]}")
    elif cmd.startswith('.remove'):
        split = cmd.split(' ')
        if len(split) != 2:
            print("usage: .remove N")
        index = int(split[1])
        i = 0
        for key in list(cache.keys()):
            i += 1
            if i == index:
                del cache[key]


if __name__ == '__main__':
    sock = socket(AF_INET, SOCK_DGRAM)
    sock.settimeout(2)


    cache = dict()

    while True:
        domain_name = input("Enter a domain name or .exit > ")

        if domain_name == '.exit':
            break
        if domain_name.startswith('.'):
           commands(domain_name)
           continue

        if not domain_name.endswith('.'):
            domain_name += '.'

        ip = ip_addr(sock, cache, domain_name)
        if ip is not None:
           print(ip)

    sock.close()