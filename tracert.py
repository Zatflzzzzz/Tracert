import socket
import struct
import time
import select
import sys

def calculate_checksum(data):
    total = 0
    length = len(data)
    index = 0
    while index < length - 1:
        value = (data[index + 1] << 8) + data[index]
        total += value
        total &= 0xffffffff
        index += 2

    if index < length:
        total += data[-1]
        total &= 0xffffffff

    total = (total >> 16) + (total & 0xffff)
    total += (total >> 16)
    checksum = ~total & 0xffff
    checksum = (checksum >> 8) | ((checksum << 8) & 0xff00)
    return checksum

def build_icmp_message(sequence):
    message_type = 8  # ICMP Echo Request
    message_code = 0
    checksum_value = 0
    identifier = 54321
    header = struct.pack("bbHHh", message_type, message_code, checksum_value, identifier, sequence)
    payload = struct.pack("d", time.time())
    checksum_value = calculate_checksum(header + payload)
    header = struct.pack("bbHHh", message_type, message_code, socket.htons(checksum_value), identifier, sequence)
    return header + payload

def trace_route(target_ip, max_hops=30, timeout=1, attempts_per_hop=3):
    print(f"Tracing route to {target_ip} with a maximum of {max_hops} hops:")

    for hop in range(1, max_hops + 1):
        receiver = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sender = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

        sender.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop)
        receiver.settimeout(timeout)
        receiver.bind(("", 0))

        response_times = []
        response_address = None

        for attempt in range(attempts_per_hop):
            message = build_icmp_message(attempt)
            send_time = time.time()
            sender.sendto(message, (target_ip, 1))

            ready = select.select([receiver], [], [], timeout)
            if ready[0]:
                received_message, response_address = receiver.recvfrom(512)
                receive_time = time.time()
                response_times.append((receive_time - send_time) * 1000)
            else:
                response_times.append(None)

        sender.close()
        receiver.close()

        if response_address:
            response_address = response_address[0]
            times_str = "  ".join(f"{t:.2f} ms" if t else "*" for t in response_times)
            print(f"{hop:2} {times_str} {response_address}")
        else:
            print(f"{hop:2} *  *  * Request timed out.")

        if response_address == target_ip:
            break

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python trace_route.py <IP address>")
        sys.exit(1)

    target_ip = sys.argv[1]

    trace_route(target_ip)
