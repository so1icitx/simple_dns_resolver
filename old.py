import socket, random, struct
ROOT_SERVERS = ['198.41.0.4', '199.9.14.201', '192.33.4.12', '199.7.91.13', '192.203.230.10', '192.5.5.241', '192.112.36.4', '198.97.190.53', '192.36.148.17', '192.58.128.30', '193.0.14.129', '199.7.83.42', '202.12.27.33']
def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(('127.0.0.1', 53))
    print("Listening for DNS queries on 127.0.0.1:53...")

    try:
        while True:   
            data, original_ip_port = sock.recvfrom(512)
            dns_return_id = data[:2]
            tmp_pointer = 12
            while data[tmp_pointer] != 0: tmp_pointer = (tmp_pointer + data[tmp_pointer]) + 1
            dns_request_type = struct.unpack('!H', data[tmp_pointer +1 :tmp_pointer+ 3])[0]
            full_domain = ""
            char = ''
            p = 12

            # Parse Domain from raw bytes
            while data[p] != 0:
                full_domain = full_domain + (data[p + 1 :p + data[p] + 1]).decode()
                full_domain = full_domain + '.'
                p = p + data[p] + 1
                char = p
            full_domain = full_domain.strip('.')
            domain_encoded = [part.encode() for part in full_domain.split('.')]
            if b'arpa' in domain_encoded:
                continue
            
            try :
                new_data = connect_to_server(domain_encoded, dns_request_type)
                
                if new_data:
                    final_response = dns_return_id + new_data[2:]
                    sock.sendto(final_response, original_ip_port)
            except Exception as e:
                print(f'err: {e}')
                continue
            
    except KeyboardInterrupt:
        print("exiting..\n")
    finally:
        sock.close()

def connect_to_server(domain, query_type):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

            # Request NS for tld (ex .com)
            tld = bytes([len(domain[-1])])
            tld = tld + domain[-1] + b'\x00'
            tmp_id = random.randint(0, 0xFFFF)
            header = struct.pack('!HHHHHH', tmp_id, 0, 1, 0, 0, 0)
            question = tld + struct.pack('!HH', 2, 1)
            full_dns_query = header + question
            s.settimeout(2.0)
            s.sendto(full_dns_query, (ROOT_SERVERS[random.randint(0, len(ROOT_SERVERS))], 53))
            data, addr = s.recvfrom(512)


            # Unpack and get the IP of the NS
            total_questions = struct.unpack("!H", data[4:6])[0]
            total_answers = struct.unpack("!H", data[6:8])[0]
            total_auth_res_records = struct.unpack("!H", data[8:10])[0]
            total_add_res_records =  struct.unpack("!H", data[10:12])[0]
            len_offset = 12 + data[12] + 1 + 16 
            pointer = len_offset + data[len_offset]
            for i in range(total_auth_res_records - 1):
                pointer += 12
                pointer = pointer + data[pointer] 
            pointer += 11
            tld_ip = str(data[pointer+2]) + '.' + str(data[pointer+3]) + '.' + str(data[pointer+4]) + '.' + str(data[pointer+5]) 

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

            # Request NS for Auth Server (ex ns1.google.com)
            tld_tmp = b''
            for part in range(len(domain)):
                tld_tmp = tld_tmp + bytes([len(domain[part])]) + domain[part] 
            tld = tld_tmp + b'\x00'
            tmp_id = random.randint(0, 0xFFFF)
            header = struct.pack('!HHHHHH', tmp_id, 0, 1, 0, 0, 0)
            question = tld + struct.pack('!HH', 2, 1)
            full_dns_query = header + question
            s.settimeout(5.0)
            s.sendto(full_dns_query, (tld_ip, 53))
            data, addr = s.recvfrom(512)

            #Unpack and get the IP for the NS (ex ns1.google.com)
            total_auth_res_records = struct.unpack("!H", data[8:10])[0]
            total_add_res_records = struct.unpack("!H", data[10:12])[0] 
            
            # Skip the Question safely
            pointer = 12
            while data[pointer] != 0: pointer += 1 + data[pointer]
            pointer += 5
            
            # Skip the Authority records dynamically
            for i in range(total_auth_res_records):
                if data[pointer] == 0xC0: pointer += 2
                else:
                    while data[pointer] != 0: pointer += 1 + data[pointer]
                    pointer += 1
                rdlength = struct.unpack("!H", data[pointer+8 : pointer+10])[0]
                pointer += 10 + rdlength
                
            # Search the Additional Section for the IPv4 Address
            ns_ip = None
            for i in range(total_add_res_records):
                if data[pointer] == 0xC0: pointer += 2
                else:
                    while data[pointer] != 0: pointer += 1 + data[pointer]
                    pointer += 1
                rtype = struct.unpack("!H", data[pointer : pointer+2])[0]
                rdlength = struct.unpack("!H", data[pointer+8 : pointer+10])[0]
                pointer += 10 
                if rtype == 1 and rdlength == 4:
                    ns_ip = str(data[pointer]) + '.' + str(data[pointer+1]) + '.' + str(data[pointer+2]) + '.' + str(data[pointer+3])
                    break 
                else:
                    pointer += rdlength

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:

            #Request to Authoritive NS to get the final IP
            tmp_id = random.randint(0, 0xFFFF)
            header = struct.pack('!HHHHHH', tmp_id, 0, 1, 0, 0, 0)
            question = tld + struct.pack('!HH', query_type, 1)
            full_dns_query = header + question
            s.settimeout(5.0)
            s.sendto(full_dns_query, (ns_ip, 53))
            data, addr = s.recvfrom(512)
            return data  

    except TypeError:
        print(f'err: no glue records found in response')
        return None
    except Exception as e:
        print(f'err: {e}')
        return None
        
if __name__ == "__main__":
    main()
