import dpkt

def average_latency(path: str) -> float:
    requests = {}
    rtts = []
    average = 0

    with open(path, "rb") as pcap_file:
        pcap = dpkt.pcap.Reader(pcap_file)

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)

            if not isinstance(eth.data, dpkt.ip.IP):
                continue

            ip = eth.data

            if isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                
                if icmp.type == 8: #Request
                    requests[icmp.data.seq] = timestamp
                    
                # ICMP Echo reply 
                elif icmp.type == 0:
                    if icmp.data.seq in requests:
                        rrt = timestamp - requests[icmp.data.seq]
                        rtts.append(rrt)
                        
        # Calculate average latency
        if rtts:
            average = sum(rtts) / len(rtts) * 1000
            return average

if __name__ == "__main__":
    phone = average_latency("./iphone.pcap")
    board = average_latency("./rw612-board.pcap")

    print(f"phone avg latency: {phone:.2f}ms\nboard avg latency: {board:.2f}ms")
        