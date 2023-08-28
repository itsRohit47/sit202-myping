#import all the required libraries
from asyncio.windows_events import NULL
import os
import socket
import sys
import time
import struct
import select

#this function checks weather the IP address supplied is a valid 4 byte IP or not
def is_valid_ip(hostname_ip):
	ip_parts = hostname_ip.strip().split('.')
	if ip_parts != 4:
		return False
	for part in ip_parts:
		try:
			if int(part) < 0 or int(part) > 255:
				return False

		except ValueError:
			return False

	return True

#converts the given host name to its IP address
def to_ip(hostname):
    try:
        if is_valid_ip(hostname):
            return hostname
        return socket.gethostbyname(hostname)
    except Exception:
        return NULL

#the chceksum calculator
def calculate_checksum(packet):
	countTo = (len(packet) // 2) * 2

	count = 0
	sum = 0

	while count < countTo:
		if sys.byteorder == "little":
			loByte = packet[count]
			hiByte = packet[count + 1]
		else:
			loByte = packet[count + 1]
			hiByte = packet[count]
		sum = sum + (hiByte * 256 + loByte)
		count += 2

	if countTo < len(packet):
		sum += packet[count]

	# sum &= 0xffffffff

	sum = (sum >> 16) + (sum & 0xffff)  # adding the higher order 16 bits and lower order 16 bits
	sum += (sum >> 16)
	answer = ~sum & 0xffff
	answer = socket.htons(answer)
	return answer

@staticmethod
def header_to_dict(keys, header, struct_format):
	values = struct.unpack(struct_format, header)
	return dict(zip(keys, values))

# this function builds the icmp packet and pushes it to the destination server's socket
def send_icmp_request(icmp_socket):
    global timer
    checksum = 0
    startvalue = 65
    
    header = struct.pack("!BBHHH", ICMP_ECHO, CODE, checksum, identifier, seq_no)
    payload = []
    for i in range(startvalue, startvalue + packet_size):
        payload.append(i & 0xff)
        
    data = bytes(payload)
    checksum = calculate_checksum(header + data)
    header = struct.pack("!BBHHH", ICMP_ECHO, CODE, checksum, identifier, seq_no)
    packet = header + data
    send_time = time.time()
    try:
        icmp_socket.sendto(packet, (destination_host, 1))
        start_of_wait = time.time()
    except socket.error as err:
        print("General error: %s", err)
        icmp_socket.close()
        return
    return send_time, start_of_wait

# this function captures the response from the icmp socket   
def receive_icmp_reply(icmp_socket):
    global seq_no
    global wait_time
    timeout = wait_time / 1000  # converting timeout to s
    while True:
        inputready, _, _ = select.select([icmp_socket], [], [], timeout)
        receive_time = time.time()

        if not inputready:  # timeout
            print("Request timeout for icmp_seq {}".format(seq_no))
            return None, 0, 0, 0
            
        packet_data, address = icmp_socket.recvfrom(2048)
        icmp_keys = ['type', 'code', 'checksum', 'identifier', 'sequence number']
        icmp_header = header_to_dict(icmp_keys, packet_data[20:28], "!BBHHH")
        if icmp_header['identifier'] == identifier and icmp_header['sequence number'] == seq_no:
            ip_keys = ['VersionIHL', 'Type_of_Service', 'Total_Length', 'Identification', 
            'Flags_FragOffset', 'TTL', 'Protocol','Header_Checksum', 'Source_IP', 'Destination_IP']
            ip_header = header_to_dict(ip_keys, packet_data[:20], "!BBHHHBBHII")
            data_len = len(packet_data) - 28
            return receive_time, ip_header['TTL'], data_len, address[0]


#the required fields for a ping request
ICMP_ECHO = 8
ICMP_ECHOREPLY = 0
CODE = 0
MIN_SLEEP = 1000.00
destination_host = input("Destination host: ")
wait_time = int(input("Timeout in ms: "))
count = int(input("Number of packets: "))
packet_size = int(input("Packet size in bytes: "))
identifier = os.getpid() & 0xffff
seq_no = -1
packets_sent = 0
received_packets = 0
min_delay = 999999999.0
max_delay = 0.0
total_delay = 0.0

#exits if packet size is not valid
if packet_size > 65507:
		print("ping: packet size too large: {} > 65507".format(packet_size))
		sys.exit()

destination_ip = to_ip(destination_host)
if destination_ip == NULL:
    print("cannot resolve {}: Unknown host".format(destination_host))

# the main procedure that brings all the bits and pieces together 
def ping():
    global seq_no
    global packets_sent
    global received_packets
    global min_delay
    global max_delay
    global total_delay
    global delay
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname("ICMP"))
    if seq_no == -1:
        print("ping {} ({}) in python with {} bytes of data".format(destination_host, destination_ip, packet_size))
    seq_no += 1
    time_values = send_icmp_request(icmp_socket)
    
    if time_values is None:
        time.sleep(MIN_SLEEP / 1000.00)
        return
    send_time, start_of_wait = map(float, time_values)
    packets_sent += 1
    receive_time, ttl, data_len, from_address = receive_icmp_reply(icmp_socket)

    icmp_socket.close()
    if receive_time:
        received_packets += 1
        delay = (receive_time - send_time) * 1000.00

    if min_delay > delay:
        min_delay = delay
    if max_delay < delay:
        max_delay = delay
    total_delay += delay
    print("{} bytes from {}: icmp_seq={} ttl={} time={:.3f} ms".format(data_len, from_address, seq_no, ttl, delay))
    if MIN_SLEEP > delay:
        time.sleep((MIN_SLEEP - delay) / 1000.00)

try:
    #loop until number of remaining packets are 0
    while count>0:
        ping()
        count-=1
    print()
    #print the ping statistics
    print("Ping statistics for {}".format(destination_ip))
    if packets_sent != 0:
        packet_loss = ((packets_sent - received_packets) * 100) / packets_sent
        print("     Packets: Sent = {}, Received =  {} , Lost = {} ({:.1f}%)".format(packets_sent, received_packets,(packets_sent - received_packets), packet_loss))
        avg = total_delay/packets_sent
        print("Approximate round trip times in milli-seconds:")
        if received_packets > 0:
            print("Minimum = {:.3f}ms , Maximum = {:.3f}ms, Average = {:.3f}ms".format(min_delay, max_delay, avg))
    else:
        print("{} packets transmitted, {} packets received".format(packets_sent, received_packets))

# handle Ctrl+C
except KeyboardInterrupt:  
    print()
# restricts the user to be in administrator mode
except socket.error as err:
    if err.errno == 1:
        print("Operation not permitted: ICMP messages can only be sent from a process running as root")
    else:
        print("Error: {}".format(err))
    sys.exit()