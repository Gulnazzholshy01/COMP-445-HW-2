import dpkt

def calculate_average_throughput(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        total_bytes = 0
        start_time = None
        end_time = None
        
        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                icmp_type = icmp.type
                icmp_data = icmp.data
                
                # Consider ICMP Echo request and reply 
                if icmp_type in (8, 0) and isinstance(icmp_data, dpkt.icmp.ICMP.Echo):
                    if start_time is None:
                        start_time = timestamp
                    end_time = timestamp
                    total_bytes += len(buf)
        
        # Calculate total duration
        if start_time is not None and end_time is not None:
            total_duration = end_time - start_time
            average_throughput = (total_bytes * 8) / total_duration  # Bits per second (bps)
            return average_throughput


average_throughput_board = calculate_average_throughput('rw612-board.pcap')
average_throughput_phone = calculate_average_throughput('iphone.pcap')

print(f'Average throughput: {average_throughput_phone:.6f} bps')
print(f'Average throughput: {average_throughput_board:.6f} bps')
