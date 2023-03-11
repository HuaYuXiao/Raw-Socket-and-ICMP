import socket
import struct
import select
import os
import sys
import time
import asyncio
import argparse
from operator import attrgetter
import random


ICMP_ECHO_REQUEST = 8
ARRAY_OF_REQUEST = []
ARRAY_OF_RESPONSE = []
ARRAY_OF_HOSTS = []
PING_INTERVAL = 0.05
PING_TIMEOUT = 3


# set information of each icmp reply in this class
class Response:
    def __init__(self, address, packet, rtt, pid, seq):
        self.address = address
        self.packet = packet
        self.rtt = float(rtt)
        self.id = pid
        self.sequence = seq
    def __repr__(self):
        return f"{self.sequence} and {self.rtt}"
        # return f"IP={self.address} RTT={self.rtt} seq={self.sequence}"


# set information of each icmp request in this class
class Request:
    def __init__(self, address, packet, send_time, pid, seq):
        self.address = address
        self.packet = packet
        self.sendTime = send_time
        self.id = pid
        self.sequence = seq
    def __repr__(self):
        return f"{self.sequence}"
        # return f"IP={self.address} RTT={self.sendTime} seq={self.sequence}"


def crate_packet(identifier, sequence_number=1, packet_size=10):  # default packet size is 10 byte.
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


def send_one_icmp_packet(destination, request_packet, udp_socket):
    send_time = time.time()
    try:
        udp_socket.sendto(request_packet, (destination, 1))
    except socket.error as e:
        print(e)
        return
    return send_time


def receive_one_icmp_packet(udp_socket, send_time, timeout):
    while True:
        r_list, w_list, x_list = select.select([udp_socket], [], [], timeout)
        start_time_for_receive = time.time()
        total_time = start_time_for_receive - send_time
        timeout = timeout - total_time
        if not r_list:
            return None
        if timeout <= 0:
            return None
        reply_packet, address = udp_socket.recvfrom(2048)
        total_time *= 1000  # change it to ms
        # total_time = int(total_time)
        total_time = "{:.3f}".format(total_time)  # for floating point
        return reply_packet, address, total_time


def open_packet(reply_packet, identifier, sequence_number, rtt, address):
    type_of_message, code, checksum, pid, sequence = struct.unpack('!BBHHH', reply_packet[20:28])
    # first we have to check the checksum:
    reply_header = struct.pack('!BBHHH', type_of_message, code, 0, pid, sequence)
    if address == '127.0.0.1':
        response = Response(address, reply_packet, rtt, pid, sequence)
        return response
    # if calculate_checksum(reply_header + reply_packet[:20]) == checksum:
    # second we check the header of reply packet:
    if type_of_message == 0 and code == 0 and pid == identifier and sequence == sequence_number:
        response = Response(address, reply_packet, rtt, pid, sequence)
        return response


def calculate_statistics():
    hosts_dict_rtt = {}
    hosts_dict_loss = {}
    hosts_dict_req_packets = {}

    for host in ARRAY_OF_HOSTS:
        loss = 0
        sum_rtt = 0
        req_packets = 0
        for req in ARRAY_OF_REQUEST:
            if req.address == host:
                req_packets += 1
                find = False
                for res in ARRAY_OF_RESPONSE:
                    if req.id == res.id and req.sequence == res.sequence and req.address == res.address:
                        sum_rtt += float(res.rtt)
                        find = True
                        break
                if not find:
                    loss += 1
        hosts_dict_rtt[host] = sum_rtt
        hosts_dict_loss[host] = loss
        hosts_dict_req_packets[host] = req_packets
    return hosts_dict_req_packets, hosts_dict_rtt, hosts_dict_loss


# handle sigint
def print_info():
    print("------------------------------------------------------------")
    req_packet, host_rtt, host_loss = calculate_statistics()
    for host in ARRAY_OF_HOSTS:
        send = req_packet[host]
        loss = host_loss[host]
        receive = send - loss
        if send != 0:
            per_loss = (loss / send) * 100
            per_loss = "{:.1f}".format(per_loss)
        else:
            per_loss = 0.0
    print(f"Packets sent:\t\t{send}")
    print(f"Packets received:\t{receive}")
    print(f"Packet loss:\t\t{per_loss}%")
    avg_rtt=0.0
    for each in ARRAY_OF_HOSTS:
        send=req_packet[each]
        rtt=host_rtt[each]
        avg_rtt=rtt/send
    avg_rtt=round(avg_rtt,3)
    var_rtt=0.0
    for each in ARRAY_OF_RESPONSE:
        each_rtt=each.rtt
        var_rtt+=pow(avg_rtt-each_rtt,2)
    var_rtt/=send
    var_rtt=round(var_rtt,3)
    min_rtt_obj = min(ARRAY_OF_RESPONSE, key=attrgetter('rtt'))
    max_rtt_obj = max(ARRAY_OF_RESPONSE, key=attrgetter('rtt'))
    print(f"Round-trip times:\t{min_rtt_obj.rtt}ms / {avg_rtt}ms / {max_rtt_obj.rtt}ms")
    print(f"Jitter:\t\t\t{var_rtt}ms")
    print("------------------------------------------------------------")
    sys.exit(0)


async def ping_one_host(host_name, timeout=PING_TIMEOUT, icmp_packet_size=0):
    ip_of_host =socket.gethostbyname(host_name)
    pid = os.getpid() + int(random.randint(1, 1000))
    seq_number = 1
    while seq_number<=4:
        request_icmp_packet = crate_packet(pid, seq_number, icmp_packet_size)
        try:
            my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
            send_time = send_one_icmp_packet(ip_of_host, request_icmp_packet, my_socket)
            # print(f"send_time={send_time}")
            req = Request(ip_of_host, request_icmp_packet, send_time, pid, seq_number)
            ARRAY_OF_REQUEST.append(req)
            reply_icmp_packet, address, rtt = receive_one_icmp_packet(my_socket, req.sendTime, timeout)
            if reply_icmp_packet is not None and address[0] == ip_of_host:
                result = open_packet(reply_icmp_packet, pid, seq_number, rtt, ip_of_host)
                ARRAY_OF_RESPONSE.append(result)
                # print(f"Reply form IP {result.address} in {result.rtt}ms seq={result.sequence}.")
            my_socket.close()
        except socket.error as e:
            print(e)
        except TypeError:
            print(f"Reply Timeout.")
        seq_number+=1
        await asyncio.sleep(1)
        # time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ping")
    parser.add_argument("host", help="The host or hosts that you want ping.", type=str)
    parser.add_argument('--n', type=int, default=4)
    parser.add_argument('--p', type=str, default=None)
    parser.add_argument('--i', type=int, default=None)
    parser.add_argument("-t", "--timeout", help="timeout for each ping reply (default is 3 second).", type=float)
    parser.add_argument("-s", "--size",type=int) 
    args = parser.parse_args()
    hosts = args.host
    timeout_for_response = args.timeout
    payload_size = args.size
    if timeout_for_response is None:
        timeout_for_response = PING_TIMEOUT
    if payload_size is None:
        payload_size = 0
    hosts = hosts.split(" ")

    for text in hosts:
        ip_of_text =socket.gethostbyname(text)
        if ip_of_text == '0.0.0.0':
            continue
        if ip_of_text is not None:
            if ip_of_text not in ARRAY_OF_HOSTS:
                ARRAY_OF_HOSTS.append(ip_of_text)
                # if str(ip_of_text) == text:
                #     print(f"ping IP<{text}>")
                # else:
                #     print(f"ping Host <{text}><{ip_of_text}>")
    for host in ARRAY_OF_HOSTS:
        asyncio.run(ping_one_host(host, timeout_for_response, payload_size))
    print_info()
