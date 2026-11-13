import sys
from netfilterqueue import NetfilterQueue
from scapy.all import IP, TCP, Raw, send

seen_flows = set()

def extract_sni(data):
    try:
        if len(data) < 6 or data[0] != 0x16 or data[5] != 0x01:
            return None

        pos = 5 + 4          
        pos += 2 + 32        

        sid_len = data[pos]  
        pos += 1 + sid_len

        cs_len = int.from_bytes(data[pos:pos + 2], "big")  
        pos += 2 + cs_len

        cm_len = data[pos]   
        pos += 1 + cm_len

        ext_total = int.from_bytes(data[pos:pos + 2], "big")  
        pos += 2
        end = min(pos + ext_total, len(data))

        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos + 2], "big")
            ext_len = int.from_bytes(data[pos + 2:pos + 4], "big")
            pos += 4

            if ext_type == 0:  
                name_len = int.from_bytes(data[pos + 3:pos + 5], "big")
                return data[pos + 5:pos + 5 + name_len].decode("ascii", errors="ignore")

            pos += ext_len
    except Exception:
        return None

    return None

def packet_callback(nf_packet):
    pkt = IP(nf_packet.get_payload())

    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = bytes(pkt[TCP].payload)

        if pkt[TCP].dport == 443:
            flow_key = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)

            sni = extract_sni(payload)
            if sni:
                if flow_key in seen_flows:
                    nf_packet.accept()
                    return

                print(f"[VoolDpi] [BYPASS] Segment Splitting Applied: {sni}")
                seen_flows.add(flow_key)

                split_pos = int(len(payload) * 0.3)
                part1 = payload[:split_pos]
                part2 = payload[split_pos:]

                pkt_part1 = pkt.copy()
                pkt_part1[TCP].payload = Raw(load=part1)
                del pkt_part1[IP].len
                del pkt_part1[IP].chksum
                del pkt_part1[TCP].chksum

                pkt_part2 = pkt.copy()
                pkt_part2[TCP].payload = Raw(load=part2)
                pkt_part2[TCP].seq = pkt[TCP].seq + len(part1)
                del pkt_part2[IP].len
                del pkt_part2[IP].chksum
                del pkt_part2[TCP].chksum

                send(pkt_part1, verbose=False)
                send(pkt_part2, verbose=False)

                nf_packet.drop()
                return

    nf_packet.accept()

if __name__ == "__main__":
    print("VoolDpi Engine v0.2 (Fragmentation)")
    print("Status: Active DPI Bypass Mode\n")

    queue = NetfilterQueue()
    queue.bind(1, packet_callback)
    try:
        queue.run()
    except KeyboardInterrupt:
        print("\n[VoolDpi] Shutting down...")
    finally:
        queue.unbind()
