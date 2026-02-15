import socket, random, struct

class DNSPacket:
    
    def __init__(self, raw_data):
        self.raw_data = raw_data
        self.pointer = 12
        self.domain = ''
        self.domain_lst = []
        self.query_type = None

    def extract_domain(self):
        p = self.pointer
        while self.raw_data[p] != 0:
                self.domain = self.domain + (self.raw_data[p + 1 :p + self.raw_data[p] + 1]).decode()
                self.domain = self.domain + '.'
                p = p + self.raw_data[p] + 1
        self.domain = self.domain.strip('.')
        self.domain_lst = [part.encode() for part in self.domain.split('.')]
        return self.domain_lst
        
    def extract_qry_type(self):
        p = self.pointer
        while self.raw_data[p] != 0: p = (p + self.raw_data[p]) + 1
        self.query_type = struct.unpack('!H', self.raw_data[p + 1:p + 3])[0]
        return self.query_type

class DNServer:
    def __init__(self, ip, port, sock, r_servers):
        self.ip = ip
        self.port = port
        self.sock = sock
        self.r_servers = r_servers
        self.client_id = None
    
    def start_server(self):
        data, addr = self.sock.recvfrom(512)
        self.client_id = data[:2]
        return data, addr

    def send_response(self, data, ip_port):
        response = self.client_id + data[2:]
        self.sock.sendto(response, ip_port)

    def resolve_query(self, domain, query_type):
        
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
                s.sendto(full_dns_query, (self.r_servers[random.randint(0, len(self.r_servers))], 53))
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

                # Request NS for tld (ex .com)
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
                
        except TimeoutError:
            print("err: Connection timed out due to network attrition.")
            return None
        except Exception as e:
            print(f"err: {e}")
            return None
    
