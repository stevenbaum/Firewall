#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING
from re import *
import socket
import struct

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.

class Firewall:
    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # Sets of valid rules (based on protocol) parsed from config
        self.tcp_rules = []
        self.icmp_rules = []
        self.udp_dns_rules = []
        self.http_rules = []

        # Pairs of HTTP requests & respsonses for HTTP logging
        self.http_list = []
        # Obnoxiously large list containing geoip ranges & corresponding countries
        #self.geoip_list = []

        # Load the firewall rules (from rule_filename) here.
        lines = open(config['rule']).readlines()
        self.parse_config(lines)
        
        self.http_file = open('http.log', 'a')
        # Load the GeoIP DB ('geoipdb.txt') as well. NOT FOR PART B
        # geo_lines = open('geoipdb.txt').readlines()
        # self.parse_geo(geo_lines)


    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):

        if pkt_dir == PKT_DIR_INCOMING:
            direction = 'incoming'
        else:
            direction = 'outgoing'
        # Pick apart contents of pkt: nw_<foo> means network-parsed,
        # I.E. it needs to be converted to little-endian before use.
        # h_<foo> means host-parsed, i.e. converted little-endian
        nw_header_length = struct.unpack('!B', pkt[0:1])[0]
        h_header_length = nw_header_length & 15
        ip_end = h_header_length * 4
        # Packet length must equal # of bytes specified by length field
        # If not, terminate function
        if h_header_length < 5:
            return None

        # Single byte for protocol field; endianness irrelevant
        nw_protocol = struct.unpack('!B', pkt[9:10])[0]
        if nw_protocol == 1:
            protocol = 'icmp'
        elif nw_protocol == 6:
            protocol = 'tcp'
        elif nw_protocol == 17:
            protocol = 'udp'
        else:
            protocol = 'other'

        # Determine external ip and port based on direction packet's coming from
        if direction == 'incoming':
            ext_ip_str = pkt[12:16]
            int_ip_str = pkt[16:20]
            h_external_ip = struct.unpack('!L', pkt[12:16])[0]
            h_internal_ip = struct.unpack('!L', pkt[16:20])[0]
        else:
            ext_ip_str = pkt[16:20]
            int_ip_str = pkt[12:16]
            h_external_ip = struct.unpack('!L', pkt[16:20])[0]
            h_internal_ip = struct.unpack('!L', pkt[12:16])[0]

        # If protocol is tcp or udp, get external port number
        # Else (if icmp), get type number
        if protocol == 'tcp' or protocol == 'udp':
            if direction == 'incoming':
                ext_port_str = pkt[ip_end:ip_end+2]
                int_port_str = pkt[ip_end+2:ip_end+4]
                h_external_port = struct.unpack('!H', pkt[ip_end:ip_end+2])[0]
                h_internal_port = struct.unpack('!H', pkt[ip_end+2:ip_end+4])[0]
            else:
                ext_port_str = pkt[ip_end+2:ip_end+4]
                int_port_str = pkt[ip_end:ip_end+2]
                h_external_port = struct.unpack('!H', pkt[ip_end+2:ip_end+4])[0]
                h_internal_port = struct.unpack('!H', pkt[ip_end:ip_end+2])[0]
        elif protocol == 'icmp':
            h_external_port = struct.unpack('!B', pkt[ip_end:ip_end+1])[0]

        # Grab 2-character geoip code NOT FOR PART B, use dummy code "@@"
        # country_code = self.binary_search(h_external_ip, self.geoip_list, 0, len(self.geoip_list))
        country_code = "@@"

        # If packet is tcp, grab its sequence & ack
        if protocol == "tcp":
            seq_no = pkt[24:28]
            ack_no = pkt[28:32]

        # Check to see if tcp packet is HTTP
        is_http = False
        if protocol == "tcp" and direction == "incoming" and h_external_port == 80:
            is_http = True
        elif protocol == "tcp" and direction == "outgoing" and h_internal_port == 80:
            is_http = True                

        # Check to see if UDP packet is also DNS packet
        # Requires: Direction is outgoing, socket # = 53, QDCOUNT = 1, QTYPE = 1 or 28, QCLASS = 1
        # DNS starts after the 8 bytes of the udp header
        dns_start = ip_end + 8
        # Question segment begins 12 bytes after dns header
        is_dns = False
        question_start = dns_start + 12
        domain = ""
        qname_total = ""
        dns_packet = ""
        if h_external_port == 53 and direction == 'outgoing':
            dns_id = pkt[dns_start:dns_start+2]
            h_qdcount = struct.unpack('!H', pkt[dns_start + 4:dns_start + 6])[0]

            # Store complete qname field for packet generation
            current = "cats"
            qname_cursor = question_start
            while current is not chr(0x00):
                current = pkt[qname_cursor:qname_cursor+1]
                qname_total += current
                qname_cursor += 1
           
            # Parse QNAME portion to assemble domain name and reach qtype, qclass fields
            distance = struct.unpack('!B', pkt[question_start:question_start+1])[0]
            cursor = question_start + 1
            done = False
            domain = ""
            while not done:
                distance -= 1
                letterhex = struct.unpack('!B', pkt[cursor:cursor+1])[0]
                letter = chr(letterhex)
                domain += letter

                cursor += 1
                next_letter = struct.unpack('!B', pkt[cursor:cursor+1])[0]
                # Reached end of a byte distance; either signals a new '.'
                # Or QNAME field has ended with \x00 signal
                if distance == 0:
                    if next_letter == 0:
                        done = True
                        qtype_start = cursor + 1
                    else:
                        domain += "."
                        distance = next_letter
                        cursor += 1

            h_qtype = struct.unpack('!H', pkt[qtype_start:qtype_start+2])[0]

            h_qclass = struct.unpack('!H', pkt[qtype_start+2:qtype_start+4])[0]

            if h_qdcount == 1 and (h_qtype == 1 or h_qtype == 28) and h_qclass == 1:
                is_dns = True

            # Make DNS denial packet
            denial_ip_header = self.create_ip_header(int_ip_str, ext_ip_str, "udp", qname_total)
            denial_udp = self.create_dns_packet(int_port_str, ext_port_str, dns_id, qname_total)
            dns_packet = denial_ip_header + denial_udp

        verdict = "pass"
        if protocol == 'udp':
            verdict = self.check_udp(is_dns, h_external_ip, country_code, domain, h_external_port, dns_packet)
        else:
            tcp_pkt = ""
            if protocol == "tcp":
                rst_ip_header = self.create_ip_header(int_ip_str, ext_ip_str, "tcp")
                rst_tcp_header = self.create_tcp_header(int_port_str, ext_port_str, seq_no, ack_no, int_ip_str, ext_ip_str)
                tcp_pkt = rst_ip_header + rst_tcp_header
            verdict = self.list_check(protocol, h_external_ip, country_code, h_external_port, tcp_pkt)

        # Project Part A: pass/no pass rules
        if verdict == "pass" and direction == "outgoing":
            self.iface_ext.send_ip_packet(pkt)
        elif verdict == "pass" and direction == "incoming":
            self.iface_int.send_ip_packet(pkt)


    # Create an IP header (In this case, tcp or udp depending on protocol)
    # @pkt_src_ip: The pkt's original source address
    # @pkt_dst_ip: The pkt's original destination address
    def create_ip_header(self, pkt_src_ip, pkt_dst_ip, protocol, qname=""):
        # Create IP header in two portions: pre and post checksum
        # Then calculate checksum and sandwich it in between these two parts
        before_checksum = ""
        after_checksum = ""
        checksum = ""
        # First, create an IP Header w/ protocol set to TCP (Protocol field = 6 for TCP)
        # First Byte: Set version to 4, length to 5 (hex val: 45)
        before_checksum += chr(0x45)
        # Second Byte: TOS, which is apparently just 0
        before_checksum += chr(0x00)
        # Third/Fourth Bytes: Total length: Since denial packet is just IP Header (20B)
        # and TCP header (20B) w/o any actual data, the total length is just 40B (hex val: 28)
        # if protocol is UDP, total length is just 20B + 38B + 2*qname len 
        before_checksum += chr(0x00)
        if protocol == "tcp":
            before_checksum += chr(0x28)
        elif protocol == "udp":
            udp_total_length = 58 + 2*len(qname)
            before_checksum += chr(udp_total_length)
        # 5th/6th/7th/8th Bytes: ID, Fragment flags & Offset: Irrelevant for project, all 0
        # Except set fragment flag to do not fragment
        x = 0
        while x < 4:
            if x == 2:
                before_checksum += chr(0x40)
            else:
                before_checksum += chr(0x00)
            x += 1
        # 9th Byte: TTL: Apparently 64 is an okay TTL (Hex val: 0x40)
        before_checksum += chr(0x40)
        # 10th Byte: Protocol Set to 6 for TCP, 17 for UDP (DNS)
        if protocol == "tcp":
            before_checksum += chr(0x06)
        elif protocol == "udp":
            before_checksum += chr(0x11)
        # 11th/12th Bytes are checksum: calculate later

        # 13th - 16th Bytes are Source Address: Since we're sending the packet back
        # From where it came, the desination of pkt is now OUR source
        after_checksum += pkt_dst_ip
        # 17th - 20th Bytes are Destination Address, which is the source of the packet we received
        after_checksum += pkt_src_ip

        # GENERATING CHECKSUM: Splice header into 2B chunks (16b) and sum them
        # (Because Checksum is assumed to be 0 before it's calculated, we ignore it) 
        # Sum 1st & 2nd 16-bit chunks
        checksum_sum = 0x4500
        # Concatenate TTL and protocol fields, add them to ongoing checksum
        if protocol == "tcp":
            checksum_sum += 0x0028
            ttl_protocol_str = chr(0x40) + chr(0x06)
            ttl_protocol_chunk = struct.unpack('!H', ttl_protocol_str)[0]
        elif protocol == "udp":
            checksum_sum += udp_total_length
            ttl_protocol_str = chr(0x40) + chr(0x11)
            ttl_protocol_chunk = struct.unpack('!H', ttl_protocol_str)[0]
        checksum_sum += ttl_protocol_chunk
        # Add chunk for fragment flag
        checksum_sum += 0x4000
        # Because ID, Flags, Offset & Checksum fields are all 0, we need only worry about
        # The src/dest fields, which are a word long each and must be split into 2B chunks
        src_chunk_1 = struct.unpack('!H', pkt_src_ip[0:2])[0]
        src_chunk_2 = struct.unpack('!H', pkt_src_ip[2:4])[0]

        dst_chunk_1 = struct.unpack('!H', pkt_dst_ip[0:2])[0]
        dst_chunk_2 = struct.unpack('!H', pkt_dst_ip[2:4])[0]

        # Add split chunks of src/ip addresses to checksum
        checksum_sum += src_chunk_1
        checksum_sum += src_chunk_2
        checksum_sum += dst_chunk_1
        checksum_sum += dst_chunk_2

        # Checksum has been totaled; now take 1's complement of this to get actual checksum
        # HOWEVER: First, to account for any wraparound in the 16 bits, cut off all bits past 16
        # and add them back into the lower 16; repeat until there's no more wraparound
        wraparound = 10
        while wraparound > 0:
            wraparound = checksum_sum >> 16
            checksum_sum = checksum_sum & 0xFFFF
            checksum_sum += wraparound
        # Take one's compelement of final checksum and turn it into a string
        checksum = struct.pack('!H', checksum_sum ^ 0xFFFF)

        # Concatenate pre-checksum, checksum & post-checksum parts; IP header is complete
        final_header = before_checksum + checksum + after_checksum
        return final_header
    
    # Assemble TCP bytestream for http logs
    def assemble_bytestream(self, pkt, ip_header_length, tcp_header_length, total_length):
        str_array = []
        num_linejumps = 0
        # Start immediately after tcp header
        tcp_l = ord(tcp_header_length)
        h_l = 5 * ord(ip_header_length)
        cursor = h_l + tcp_l
        ongoing = ""
        # If there have been two 0x0d 0x0a in a row, that's one linejump
        while num_linejumps < 2:
            # In event that http message is too big and in multiple messages, break to avoid infinite loop
            if cursor >= total_length:
                break
            current_letter = chr(pkt[cursor:cursor+1])
            next_letter = chr(pkt[cursor+1:cursor+2])
            if current_letter is chr(0x0d) and next_letter is chr(0x0a):
                str_array.append(ongoing)
                cursor += 2
                if ongoing == "":
                    num_linejumps += 1
                    str_array.append("")
                ongoing == ""
                continue
            else:
                ongoing += current_letter
            cursor += 1
            
        self.http_list.append(str_array)

    # Generates the TCP header used in tcp denial packets
    # The pkt_src/dst are the src/dst ports used from the packet SENT to us:
    # We flip these because we're sending a new packet back
    # Same goes for syn/ack
    def create_tcp_header(self, pkt_src, pkt_dst, pkt_syn, pkt_ack, src_ip, dst_ip):
        header = ""
        # 1st/2nd Bytes: Source Port: I.E. the destination port of the pkt we received
        header += pkt_dst
        # 3rd/4th Bytes: Destination Port: I.E. the source port of the pkt we received
        header += pkt_src
        # 5th-8th Bytes: Sequence #: Apparently, just the ACK of the sent pkt
        header += pkt_ack
        # 9th-12th Bytes: Ack #: The SYN of the sent pkt, + 1
        # Unpack pkt's syn, add 1 and add to our tcp header
        num = struct.unpack('!L', pkt_syn)[0]
        num += 1
        string = struct.pack('!L', num)
        header += string
        # 13th Byte: Offset & Reserved; 5 for offset (5*4 = 20B), reserved is 0: 0x50
        header += chr(0x50)
        # 14th Byte: Flags: Set ACK & R FLags
        header += chr(0x14)
        # 15th/16th Bytes: Window: Set to 0 (??)
        header += chr(0x00)
        header += chr(0x00)
        # CALCULATING TCP CHECKSUM: Make pseudoheader (split pkt src/dst in half, sum them,
        # add protocol etc.)
        src_val = struct.unpack('!L', src_ip)[0]
        src_top = src_val >> 16
        src_bot = src_val & 0xFF
        src_sum = src_top + src_bot

        dst_val = struct.unpack('!L', dst_ip)[0]
        dst_top = dst_val >> 16
        dst_bot = dst_val & 0xFF
        dst_sum = dst_top + dst_bot
        # 16b reserved(0's) & protocol; 0x06
        res_prot = 0x06
        # Last 16b: TCP length; since there's no data and the pseudoheader isn't real, it's just
        # The header length: 20
        tcp_len = 0x0014
        checksum = src_sum + dst_sum + res_prot + tcp_len
        checksum = checksum ^ 0xFF
        checksum_str = struct.pack('!H', checksum)
        header += checksum_str
        # Final 2 Bytes: Urgent Pointer; Set to 0
        header += chr(0x00)
        header += chr(0x00)
        return header

    # Creates a UDP header & packet for injecting DNS packets.
    # All fields are taken from the given dns packet sent to us
    def create_dns_packet(self, pkt_src, pkt_dst, pkt_id, qname):
        udp_header = ""
        # 1st/2nd Bytes: Source Port: I.E. the sent packet's destination
        udp_header += pkt_dst
        # 3rd/4th Bytes: Destination Port: I.E. the sent packet's source
        udp_header += pkt_src
        # 5th/6th Bytes: Length of UDP header & payload - 36 + 2*qname length 70 (hex:0x46)
        udp_header += chr(0x00)
        udp_header += chr(38 + 2*len(qname))
        #udp_header += chr(0x24 + 2*len(qname))
        # 7th/8th Bytes: Checksum: 0, apparently
        udp_header += chr(0x00)
        udp_header += chr(0x00)

        # Actual DNS payload junk:
        # First: Header
        # First of header: ID: Just copy it
        dns_header = ""
        dns_header += pkt_id
        # Set QR to one b/c this is a response
        dns_header += chr(0x81)
        # Rest of that line is 0 except for recursive query flag
        dns_header += chr(0x00)
        # There's only 1 question and 1 answer, 0 authoritative & additional
        x = 0
        while x < 2:
            dns_header += chr(0x00)
            dns_header += chr(0x01)
            x += 1
        x = 0
        while x < 4:
            dns_header += chr(0x00)
            x += 1
        # DONE WITH DNS HEADER: Now do question section: Qname, Qtype(1) & Qclass(1)
        question = ""
        question += qname
        x = 0
        while x < 2:
            question += chr(0x00)
            question += chr(0x01)
            x += 1
        # DONE WITH DNS QUESTION: Now do answer section: Name
        answer = ""
        # Name is the same as qname
        answer += qname
        # Type and class are both (1), as is TTL
        x = 0
        while x < 2:
            answer += chr(0x00)
            answer += chr(0x01)
            x += 1
        # TTL is 4B
        answer += chr(0x00)
        answer += chr(0x00)
        answer += chr(0x00)
        answer += chr(0x01)
        # RDLength: 4
        answer += chr(0x00)
        answer += chr(0x04)
        # RData: The IP address we're reaching (cat website)
        answer += socket.inet_aton("169.229.49.109")
        final_dns = udp_header + dns_header + question + answer
        return final_dns

        
    # Updated for part b: In the event of matching rule, will send out dns denial pkt
    # Check packet against set of udp/dns rules to determine pass/no pass
    def check_udp(self, isdns, ip, country, domain_name, portnum, pkt=""):
        p_np = "pass"
        # Rule broken into [<verdict>, 'dns', <domain name>]
        for rule in self.udp_dns_rules:
            if rule[1] == 'dns' and not isdns:
                continue
            elif rule[1] == 'dns' and isdns:
                #Check for wildcard vs. non-wildcard dns
                if "*" in rule[2] and (rule[2][1:len(rule[2])] in domain_name):
                    if rule[0] == "deny":
                        self.iface_int.send_ip_packet(pkt)
                        return "denied"
                    p_np = rule[0]
                elif rule[2] == domain_name:
                    if rule[0] == "deny":
                        self.iface_int.send_ip_packet(pkt)
                        return "denied"
                    p_np = rule[0]

            # Examine udp cases now; if ip and port cases match rule, use its verdict
            else:
                p_np = self.generic_rulecheck(rule, ip, country, portnum)
        if p_np == None:
            p_np = "pass"
        return p_np

    # All-purpose rule-checker
    # Rule is considered matched if ip and port fields both match rule
    # @rule is [<verdict>, <protocol>, <external IP>, <external port>]
    # Updated for part b: If tcp rule matches, sends rst packet
    def generic_rulecheck(self, rule, ip, country, portnum, pkt=""):
        p_np = ""
        ipmatch, portmatch = False, False
        if rule[2] == "any":
            ipmatch = True
            # Only country codes have length 2
        elif len(rule[2]) == 2:
            if country is None:
                ipmatch = False
            elif country.lower() == rule[2].lower():
                ipmatch = True
        #<external IP> of slash notation 0.0.0.0/32
        elif "/" in rule[2]:
            split = rule[2].split("/")
            mask_num = (int)(split[1])
            mask_str = ""
            while mask_num != 0:
                mask_str += "1"
                mask_num -= 1
            while len(mask_str) != 32:
                mask_str += "0"
            rule_ip = socket.ntohl(split[0])
            final_mask = int(mask_str, 2)
            if (ip & final_mask) == rule_ip:
                ipmatch = True
        # <external IP> is of generic ip form w/o slash
        else:
            rule_ip1 = socket.inet_aton(rule[2])
            if ip == rule_ip1:
                ipmatch = True
        # Now check the matching-ness of the <external port> field
        if rule[3] == "any":
            portmatch = True
        # If field contains a dash, field uses range of port values "xxxx-yyyy"
        elif "-" in rule[3]:
            portsplit = rule[3].split("-")
            lowerbound = portsplit[0]
            upperbound = portsplit[1]
            if portnum >= lowerbound or portnum <= upperbound:
                portmatch = True
        # Else port field is just a single value
        elif int(portnum) == int(rule[3]):
            portmatch = True
        # If both the port field and ip fields pass (protocol already passed), rule applies
        if portmatch is True and ipmatch is True:
            if rule[0] == "deny":
                self.iface_int.send_ip_packet(pkt)
                return "denied"
            else:
                p_np = rule[0]
                return p_np

    # Apply rulecheck to icmp/tcp rules (In case of icmp, portnum = type field)
    def list_check(self, protocol, ip, country, portnum, pkt=""):
        verdict = "pass"
        if protocol == "tcp":
            for rule in self.tcp_rules:
                verdict = self.generic_rulecheck(rule, ip, country, portnum, pkt)
                if verdict == None:
                    verdict = "pass"
            return verdict
        elif protocol == "icmp":
            for rule in self.icmp_rules:
                verdict = self.generic_rulecheck(rule, ip, country, portnum)
                if verdict == None:
                    verdict = "pass"
            return verdict
        # protocol isn't tcp/icmp/udp/dns: just pass it
        else:
            return "pass"


    # Parse config lines to populate list of actual rules
    # @lines: list of lines created via open(config['rule']).readlines() 
    def parse_config(self, lines):
        for line in lines:
            # Ignore comments (%) or blank lines (\n)
            if line[0] == "%" or line[0] == "\n":
                continue
            # Line is (presumably) a legal rule: Make lowercase & check
            line = line.lower()
            tokenized = line.split()
            if tokenized[1] == "tcp" and tokenized[0] != "deny":
                self.tcp_rules.append(tokenized)
            elif tokenized[1] == "icmp":
                self.icmp_rules.append(tokenized)
            elif (tokenized[1] == "udp" or tokenized[1] == "dns") and tokenized[0] != "deny":
                self.udp_dns_rules.append(tokenized)

            # Rules for Part B of project    
            elif tokenized[0] == "deny" and tokenized[1] == "tcp":
                self.tcp_rules.append(tokenized)
            elif tokenized[0] == "deny" and tokenized[1] == "dns":
                self.udp_dns_rules.append(tokenized)
            elif tokenized[0] == "log" and tokenized[1] == "http":
                self.http_rules.append(tokenized)
     
    # Parse the geoipdb.txt file to populate geoip_list
    # Split each line into 
    def parse_geo(self, lines):
        for line in lines:
            # Make country letters lowercase to standardize
            line = line.lower()
            tokens = line.split()
            # Convert IP Ranges
            tokens[0] = socket.inet_aton(tokens[0])
            tokens[1] = socket.inet_aton(tokens[1])
            # Add modified IPs w/ respective country code to list
            self.geoip_list.append(tokens)

    # Given a certain IP address, obtain its respective country
    # via a binary search on the sorted list of addresses, geoip_list
    # @ip_address is the address parsed from the IPv4 packet
    # @return the two-character country code corresponding to that packet
    # If no match is found, return None
    def binary_search(self, ip_address, rule_list, floor, ceiling):
        index = (floor + ceiling)/2
        lower_bound = self.geoip_list[index][0]
        lower_bound = struct.unpack('!L', lower_bound)[0]
        upper_bound = self.geoip_list[index][1]
        upper_bound = struct.unpack('!L', upper_bound)[0]

        # If IP address is within bounds of given entry,
        # It corresponds to the country code for that line
        if ip_address >= lower_bound and ip_address <= upper_bound:
            return rule_list[index][2]
        # IP Wasn't in this iteration's range and binary search reached edge of list;
        if (ceiling - floor) <= 2:
            return None
        # IP was lower than lower bound; cut index in half
        # Else look in the upper half
        if ip_address > upper_bound:
            floor = index
            return self.binary_search(ip_address, rule_list, floor, ceiling)
        else:
            ceiling = index
            return self.binary_search(ip_address, rule_list, floor, ceiling)


