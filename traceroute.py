#!/usr/bin/env python
import sys
import socket

def traceroute(dest_name, port, max_hops):
    dest_addr = socket.gethostbyname(dest_name)
    print("target ==> %s (%s)" % (dest_name, dest_addr))

    socket.setdefaulttimeout(10)
    icmp = socket.getprotobyname('icmp')
    udp = socket.getprotobyname('udp')
    ttl = 1

    while True:
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, udp)
        send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        recv_socket.bind(("", port))
        send_socket.sendto(bytes(512), (dest_addr, port))
        curr_addr = None
        curr_name = None
        try:
            curr_name, curr_addr = recv_socket.recvfrom(512)
            curr_addr = curr_addr[0]
            try:
                curr_name = socket.gethostbyaddr(curr_addr)[0]
            except socket.error:
                curr_name = curr_addr
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            curr_host = "%s (%s)" % (curr_name, curr_addr)
        else:
            curr_host = "*"
        print("%d  %s" % (ttl, curr_host))

        ttl += 1
        if curr_name == dest_name or curr_addr == dest_addr:
            break

if __name__ == "__main__":
    traceroute(str(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]))
