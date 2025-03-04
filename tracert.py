import socket
import struct
import time
import select
import sys


def checksum(source_string):
    sum = 0
    count_to = (len(source_string) // 2) * 2
    count = 0
    while count < count_to:
        this_val = source_string[count + 1] * 256 + source_string[count]
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2

    if count_to < len(source_string):
        sum = sum + source_string[-1]
        sum = sum & 0xffffffff

    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def create_icmp_packet(seq):
    icmp_type = 8  # ICMP Echo Request
    icmp_code = 0
    checksum_value = 0
    identifier = 12345
    header = struct.pack("bbHHh", icmp_type, icmp_code, checksum_value, identifier, seq)
    data = struct.pack("d", time.time())
    checksum_value = checksum(header + data)
    header = struct.pack("bbHHh", icmp_type, icmp_code, socket.htons(checksum_value), identifier, seq)
    return header + data


def tracert(dest_addr, max_hops=30, timeout=1, packets_per_hop=3):
    dest_ip = socket.gethostbyname(dest_addr)
    print(f"Tracing route to {dest_addr} [{dest_ip}] with maximum {max_hops} hops:")

    for ttl in range(1, max_hops + 1):
        # Создаем сокеты
        recv_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        send_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        # Устанавливаем TTL
        send_socket.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, ttl)
        recv_socket.settimeout(timeout)
        recv_socket.bind(("", 0))

        times = []
        addr = None

        for seq in range(packets_per_hop):
            packet = create_icmp_packet(seq)
            send_time = time.time()
            send_socket.sendto(packet, (dest_ip, 1))

            ready = select.select([recv_socket], [], [], timeout)
            if ready[0]:
                recv_packet, addr = recv_socket.recvfrom(512)
                recv_time = time.time()
                times.append((recv_time - send_time) * 1000)
            else:
                times.append(None)

        # Закрываем сокеты
        send_socket.close()
        recv_socket.close()

        if addr:
            addr = addr[0]
            times_str = "  ".join(f"{t:.2f} ms" if t else "*" for t in times)
            print(f"{ttl:2} {times_str} {addr}")
        else:
            print(f"{ttl:2} *  *  * Request timed out.")

        if addr == dest_ip:
            break


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python tracert.py <hostname>")
        sys.exit(1)
    tracert(sys.argv[1])