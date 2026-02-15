from classes import *
import socket
ROOT_SERVERS = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']

def main():
    dns_server = DNServer('localhost', 53, socket.socket(socket.AF_INET, socket.SOCK_DGRAM), ROOT_SERVERS)
    dns_server.sock.bind((dns_server.ip, dns_server.port))
    while True:
        try:
            data, original_ip_port = dns_server.start_server()
            dns_translator = DNSPacket(data)
            domain = dns_translator.extract_domain()
            if b'arpa' in domain:
                continue
            qry_type = dns_translator.extract_qry_type()
            data = dns_server.resolve_query(domain, qry_type)
            dns_server.send_response(data, original_ip_port)
        except Exception as e:
            print(f'err: {e}')

if __name__ == '__main__':
    main()
