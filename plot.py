import dpkt
import matplotlib.pyplot as plt

def plot_data_rate(pcap_file):

    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
  
        time_intervals = []
        byte_counts = []
        interval_duration = 1  
        
        current_interval_start = None
        current_interval_bytes = 0
        
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
                    if current_interval_start is None:
                        current_interval_start = timestamp
                    while timestamp - current_interval_start >= interval_duration:
                        time_intervals.append(current_interval_start)
                        byte_counts.append(current_interval_bytes)
                        current_interval_start += interval_duration
                        current_interval_bytes = 0
                    current_interval_bytes += len(buf)
        
        # Append the last interval
        if current_interval_start is not None:
            time_intervals.append(current_interval_start)
            byte_counts.append(current_interval_bytes)
        
        # Convert to data rate (bytes per second)
        data_rate = [bytes / interval_duration for bytes in byte_counts]
        
        # Plot data rate vs time
        plt.figure(figsize=(10, 6))
        plt.plot(time_intervals, data_rate, marker='o', linestyle='-', color='b')
        plt.xlabel('Time (seconds)')
        plt.ylabel('Data Rate (bytes per second)')
        plt.title('Data Rate vs Time for ICMP Packet Flow')
        plt.grid(True)
        plt.show()

plot_data_rate('rw612-board.pcap')
plot_data_rate('iphone.pcap')