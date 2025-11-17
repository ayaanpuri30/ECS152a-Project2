import socket
import struct
import time

# config
HOSTNAME = "tmz.com"
RESOLVER = "1.1.1.1" # or 8.8.8.8
DNS_PORT = 53
TIMEOUT = 5.0
QTYPE_A = 1
DO_HTTP_TEST = True

# binary label for DNS: "tmz.com" -> b'\x03tmz\x03com\x00'
def encode_qname(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        b_label = label.encode("ascii")
        out += struct.pack("!B", len(b_label)) + b_label 
    return out + b"\x00"


def build_query(tid: int, hostname: str) -> bytes:
    flags = 0x0100 # query
    header = struct.pack("!HHHHHH",
                         tid, flags,
                         1, # QDCOUNT: 1 question
                         0, # ANCOUNT
                         0, # NSCOUNT
                         0) # ARCOUNT
    question = encode_qname(hostname) + struct.pack("!HH", QTYPE_A, 1)
    return header + question


def read_name(msg: bytes, offset: int):
    labels = []
    jumped = False
    origin = offset
    while True:
        length = msg[offset]
        # compression pointer: 11xxxxxx xxxxxxxx
        if (length & 0xC0) == 0xC0:
            pointer = ((length & 0x3F) << 8) | msg[offset + 1]
            if not jumped:
                origin = offset + 2  # past the pointer
                jumped = True
            offset = pointer
            continue
        if length == 0:
            offset += 1
            break
        offset += 1
        labels.append(msg[offset:offset + length].decode("ascii", errors="ignore"))
        offset += length
    name = ".".join(labels)
    return name, (origin if jumped else offset)


def parse_response(resp: bytes):
    if len(resp) < 12:
        raise ValueError("DNS response too short")

    tid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", resp[:12])
    rcode = flags & 0x000F  # 0 = NoError
    offset = 12

    # skip the question
    for _ in range(qd):
        _, offset = read_name(resp, offset)
        offset += 4  # QTYPE and QCLASS

    answers = []
    for _ in range(an):
        _, offset_name = read_name(resp, offset)
        offset = offset_name
        rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", resp[offset:offset + 10])
        offset += 10
        rdata = resp[offset:offset + rdlength]
        offset += rdlength

        if rtype == 1 and rdlength == 4:  # A record
            ip = ".".join(str(b) for b in rdata)
            answers.append({"type": "A", "ip": ip, "ttl": ttl})

    return {"id": tid, "rcode": rcode, "answers": answers}


def resolve_once(hostname: str, resolver_ip: str):
    tid = int(time.time() * 1000) & 0xFFFF
    query = build_query(tid, hostname)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIMEOUT)

    start = time.perf_counter()
    sock.sendto(query, (resolver_ip, DNS_PORT))
    resp, _ = sock.recvfrom(2048)
    end = time.perf_counter()
    sock.close()

    rtt_ms = (end - start) * 1000.0
    parsed = parse_response(resp)
    return rtt_ms, parsed


def http_connect_rtt(ip: str, host_header: str = "tmz.com"):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(TIMEOUT)
    start = time.perf_counter()
    s.connect((ip, 80))
    end = time.perf_counter()
    s.close()
    return (end - start) * 1000.0


def main():
    print(f"DNS: Resolving {HOSTNAME} via {RESOLVER}")
    try:
        rtt, result = resolve_once(HOSTNAME, RESOLVER)
    except socket.timeout:
        print("DNS: Timeout")
        return
    except Exception as e:
        print("DNS: Error:", e)
        return

    rcode_names = {0: "NoError", 1: "FormErr", 2: "ServFail", 3: "NXDomain", 5: "Refused"}
    print(f"DNS RTT: {rtt:.2f} ms | RCODE: {rcode_names.get(result['rcode'], result['rcode'])}")

    if not result["answers"]:
        print("DNS - No A records in Answer section (resolver may have returned a referral).")
        return

    # answers and measure TCP connect RTT for the first IP
    for a in result["answers"]:
        print(f"DNS : A {HOSTNAME} = {a['ip']} (TTL {a['ttl']})")

    if DO_HTTP_TEST:
        ip0 = result["answers"][0]["ip"]
        try:
            http_rtt = http_connect_rtt(ip0, HOSTNAME)
            print(f"HTTP - TCP connect RTT to {ip0}:80 = {http_rtt:.2f} ms")
        except Exception as e:
            print("HTTP - Connect error:", e)


if __name__ == "__main__":
    main()