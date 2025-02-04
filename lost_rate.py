import dpkt

def calculate_loss_rate(pcap_file):
    with open(pcap_file, 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        
        sent_requests = {}
        received_replies = 0
        total_requests = 0

        for timestamp, buf in pcap:
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                continue
            ip = eth.data
            if isinstance(ip.data, dpkt.icmp.ICMP):
                icmp = ip.data
                icmp_type = icmp.type
                icmp_data = icmp.data
                
                # ICMP Echo request 
                if icmp_type == 8 and isinstance(icmp_data, dpkt.icmp.ICMP.Echo):
                    icmp_id = icmp_data.id
                    icmp_seq = icmp_data.seq
                    sent_requests[(icmp_id, icmp_seq)] = timestamp
                    total_requests += 1

                # ICMP Echo reply 
                elif icmp_type == 0 and isinstance(icmp_data, dpkt.icmp.ICMP.Echo):
                    icmp_id = icmp_data.id
                    icmp_seq = icmp_data.seq
                    if (icmp_id, icmp_seq) in sent_requests:
                        received_replies += 1
                        del sent_requests[(icmp_id, icmp_seq)]
        
        # Calculate loss rate
        if total_requests > 0:
            lost_packets = total_requests - received_replies
            loss_rate = (lost_packets / total_requests) * 100
            return loss_rate
        else:
            return None

loss_rate_phone = calculate_loss_rate('iphone.pcap')
loss_rate_board = calculate_loss_rate('rw612-board.pcap')

print(f'Loss rate for Iphone: {loss_rate_phone:.3f}%')
print(f'Loss rate for Iphone: {loss_rate_board:.3f}%')
