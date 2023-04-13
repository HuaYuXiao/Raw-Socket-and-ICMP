import random
import struct
import socket
import sys
import os
import time
import select
import argparse


PING_COUNT = 3  #the number of ICMP echo packet tobe sent whose initial TTL value are same  
PING_INTERVAL = 0.05
PING_TIMEOUT = 2
MAX_HOP = 30
ICMP_ECHO_REQUEST = 8


class Response:
    def __init__(self, address, packet, rtt, pid, seq):
        self.address = address
        self.packet = packet
        self.rtt = float(rtt)
        self.id = pid
        self.sequence = seq
    def __repr__(self):
        return f"{self.sequence} and {self.rtt}"


class Request:
    def __init__(self, address, packet, send_time, pid, seq):
        self.address = address
        self.packet = packet
        self.sendTime = send_time
        self.id = pid
        self.sequence = seq
    def __repr__(self):
        return f"{self.sequence}"


# crate ICMP packet with this function
# default packet size is 60 byte.
def crate_icmp_packet(identifier, sequence_number=1, packet_size=18):  # default packet size is 18 byte.
    # Maximum for an unsigned short int c object counts to 65535(0xFFFF). we have to sure that our packet id is not
    # greater than that.
    identifier = identifier & 0xFFFF

    # cod is 0 for icmp echo request
    code = 0
    # checksum is 0 for now
    checksum = 0
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, code, checksum, identifier, sequence_number)
    # Payload Generation
    payload_byte = []
    if packet_size > 0:
        for i in range(0x42, 0x42 + packet_size):  # 0x42 = 66 decimal
            payload_byte += [(i & 0xff)]  # Keep chars in the 0-255 range
    data = bytes(payload_byte)
    checksum = calculate_checksum(header + data)
    header = struct.pack('!BBHHH', ICMP_ECHO_REQUEST, code, checksum, identifier, sequence_number)
    packet = header + data
    return packet


# this function is only calculate checksum of packet.
def calculate_checksum(source_string):
    countTo = (int(len(source_string) / 2)) * 2
    sum = 0
    count = 0

    # Handle bytes in pairs (decoding as short ints)
    loByte = 0
    hiByte = 0
    while count < countTo:
        if (sys.byteorder == "little"):
            loByte = source_string[count]
            hiByte = source_string[count + 1]
        else:
            loByte = source_string[count + 1]
            hiByte = source_string[count]
        sum = sum + (hiByte * 256 + loByte)
        count += 2

    # Handle last byte if applicable (odd-number of bytes)
    # Endianness should be irrelevant in this case
    if countTo < len(source_string):  # Check for odd length
        loByte = source_string[len(source_string) - 1]
        sum += loByte

    sum &= 0xffffffff  # Truncate sum to 32 bits (a variance from ping.c, which
    # uses signed ints, but overflow is unlikely in ping)

    sum = (sum >> 16) + (sum & 0xffff)  # Add high 16 bits to low 16 bits
    sum += (sum >> 16)  # Add carry from above (if any)
    answer = ~sum & 0xffff  # Invert and truncate to 16 bits
    answer = socket.htons(answer)
    return answer


def send_one_icmp_packet(destination, request_packet, my_socket, port_number=0):
    send_time = time.time()
    try:
        my_socket.sendto(request_packet, (destination, port_number))
    except socket.error as e:
        print(e)
        return
    return send_time


def receive_one_icmp_packet(my_socket, send_time, timeout):
    while True:
        r_list, w_list, x_list = select.select([my_socket], [], [], timeout)
        start_time_for_receive = time.time()
        total_time = start_time_for_receive - send_time
        timeout = timeout - total_time
        if not r_list:
            return None
        if timeout <= 0:
            return None
        reply_packet, address = my_socket.recvfrom(2048)
        total_time *= 1000
        total_time = "{:.3f}".format(total_time)
        return reply_packet, address, total_time


def open_packet(reply_packet, identifier, sequence_number, rtt, address):
    type_of_message, code, checksum, pid, sequence = struct.unpack('!BBHHH', reply_packet[20:28])
    reply_header = struct.pack('!BBHHH', type_of_message, code, 0, pid, sequence)
    response = Response(address, reply_packet, rtt, pid, sequence)
    return response


def calculate_statistics(ARRAY_OF_RESPONSE):
    loss = 0
    sum_rtt = 0.0
    # print(f"ARRAY_OF_RESPONSE={ARRAY_OF_RESPONSE}")
    for each_rtt in ARRAY_OF_RESPONSE:
        # print(f"each_rtt={each_rtt}")
        if each_rtt is not None:
            sum_rtt+=float(each_rtt)
        else:
            loss+=1
    # print(f"sum_rtt={sum_rtt}")
    # print(f"loss={loss}")
    return sum_rtt, loss


def print_info(ttl,this_address,ARRAY_OF_RESPONSE):
    print(f"#{ttl}\t{this_address}")
    print("------------------------------------------------------------")
    sum_rtt, loss = calculate_statistics(ARRAY_OF_RESPONSE)
    receive =PING_COUNT-loss
    per_loss = (loss /PING_COUNT) * 100
    per_loss = "{:.1f}".format(per_loss)
    print(f"Packets sent:\t\t{PING_COUNT}")
    print(f"Packets received:\t{receive}")
    print(f"Packet loss:\t\t{per_loss}%")
    avg_rtt=sum_rtt/PING_COUNT
    avg_rtt=round(avg_rtt,3)
    var_rtt=0.0
    for each in ARRAY_OF_RESPONSE:

        var_rtt+=pow(avg_rtt-float(each),2)
    var_rtt/=PING_COUNT
    var_rtt=round(var_rtt,3)
    min_rtt= min(ARRAY_OF_RESPONSE)
    max_rtt= max(ARRAY_OF_RESPONSE)
    print(f"Round-trip times:\t{min_rtt}ms / {avg_rtt}ms / {max_rtt}ms")
    print(f"Jitter:\t\t\t{var_rtt}ms")
    print("------------------------------------------------------------")


# function that send one icmp packet each time.
# try to send 3 icmp pakcet each time.
def traceroute_use_icmp(dst, timeout=PING_TIMEOUT, port_number=0, start_ttl=1, max_ttl=MAX_HOP, max_tries=PING_COUNT,packet_size=18):
    address =()
    prv_address = ("0.0.0.0", port_number)
    reply_icmp_packet= None
    total_time = -float('inf')
    ip_of_host = socket.gethostbyname(dst)
    # print(f"traceroute <{ip_of_host}> use ICMP:")
    for ttl in range(start_ttl, max_ttl):
        ARRAY_OF_REQUEST = []
        ARRAY_OF_RESPONSE = []
        seq_number = 1
        while seq_number<=PING_COUNT:
            # print(f"seq_number={seq_number}")
            reply_icmp_packet= None
            pid = os.getpid() + int(random.randint(1, 1000))
            request_icmp_packet = crate_icmp_packet(pid, packet_size=packet_size)
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
            try:
                my_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
                send_time = send_one_icmp_packet(ip_of_host, request_icmp_packet, my_socket, port_number)
                req = Request(ip_of_host, request_icmp_packet, send_time, pid, seq_number)
                ARRAY_OF_REQUEST.append(req)
                reply_icmp_packet, address, rtt = receive_one_icmp_packet(my_socket, send_time, timeout)
                # print(f"rtt={rtt}")
                # print(reply_icmp_packet)
                this_address=address[0]
                # print(f"address[0]={address[0]}")
                # if reply_icmp_packet is not None:
                #     result=open_packet(reply_icmp_packet, pid, seq_number, rtt, this_address)
                #     # result=open_packet(reply_icmp_packet, pid, seq_number, rtt, ip_of_host)
                #     print(f"result={result}")
                #     ARRAY_OF_RESPONSE.append(result)
                if reply_icmp_packet is not None:
                    ARRAY_OF_RESPONSE.append(rtt)
                # if address[0]:
                #     break
                # my_socket.close()
            except socket.error as e:
                print(e)
            except TypeError:
                continue        
            seq_number+=1
                

        if reply_icmp_packet is not None:
            type_of_message, code, checksum, pid, sequence = struct.unpack('!BBHHH', reply_icmp_packet[20:28])

        # if prv_address[0] != "0.0.0.0":
        #     if seq_number == max_tries and prv_address[0] == address[0]:
        #         print(f"HOP<{ttl}> NO REPLY after {seq_number} tries.")
        #         continue
        # prv_address = address
        # if ttl == 1:
        #     print(f"HOP<{ttl}> <{address[0]}> in {total_time} after {seq_number} tries.")
        #     continue
        # if type_of_message == 0 or address[0] ==ip_of_host:
        #     print(f"HOP<{ttl}> <{address[0]}> in {total_time} after {seq_number} tries.")
        #     return
        # elif type_of_message == 11 or type_of_message == 3:
        #     print(f"HOP<{ttl}> <{address[0]}> in {total_time} after {seq_number} tries.")

        # print(f"ARRAY_OF_RESPONSE={ARRAY_OF_RESPONSE}")

        print_info(ttl,this_address,ARRAY_OF_RESPONSE)

    if address[0] ==ip_of_host:
        sys.exit(0)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="tracert")
    parser.add_argument("host", help="The host that you want trace.", type=str)
    parser.add_argument("-t", "--timeout", help="timeout for each ping reply (default is 1 second).", type=float)
    parser.add_argument("-s", "--size",
                        help="size of payload part of each ICMP request packet (default payload is 18).",
                        type=int)
    parser.add_argument("-l", "--maxHop", help="the max hop or max TTL.", type=int)
    parser.add_argument("-f", "--startTTL", help="the number of TTL that we start trace with it.", type=int)
    parser.add_argument("-e", "--tries", help="the number of tries for each TTL.", type=int)
    parser.add_argument("-p", "--port", help="the port number that send packet.", type=int)
    args = parser.parse_args()
    host = args.host
    timeout = args.timeout
    packet_size = args.size
    max_hop = args.maxHop
    start_TTL = args.startTTL
    tries_for_each_TTL = args.tries
    send_port = args.port
    if timeout is None:
        timeout = 1
    if packet_size is None:
        packet_size = 18
    if max_hop is None:
        max_hop = MAX_HOP
    if start_TTL is None:
        start_TTL = 1
    if tries_for_each_TTL is None:
        tries_for_each_TTL =PING_COUNT
    if send_port is None:
        send_port = 0

    traceroute_use_icmp(host, timeout, send_port, start_TTL, max_hop, tries_for_each_TTL, packet_size)

    print_info()
