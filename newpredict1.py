import csv
import time
from scapy.all import sniff
from collections import defaultdict
from datetime import datetime

import pickle
from sklearn.ensemble import ExtraTreesClassifier
import os

# Load the pre-trained ExtraTreesClassifier model (assuming the model is saved as 'ExtraTreeClassifier.pkl')
with open('etcUdhya.pkl', 'rb') as model_file:
    model = pickle.load(model_file)

# Initialize flow data storage
flows = defaultdict(lambda: {
    'src_ip': '',
    'dst_ip': '',
    'protocol': '',
    'duration': 0,
    'fwd_packets': 0,
    'bwd_packets': 0,
    'flow_iat': [],
    'packet_lengths': [],
    'fin_count': 0,
    'syn_count': 0,
    'psh_count': 0,
    'ack_count': 0
})

# Function to capture and process packets
def process_packet(packet):
    if packet.haslayer('IP') and packet.haslayer('TCP'):
        # Capture relevant fields
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet.proto
        packet_len = len(packet)

        # Flow Key based on src_ip, dst_ip, and protocol (to identify the flow)
        flow_key = (src_ip, dst_ip, protocol)

        # Extract flags
        flags = packet.sprintf('%TCP.flags%')
        fin_flag = 1 if 'F' in flags else 0
        syn_flag = 1 if 'S' in flags else 0
        psh_flag = 1 if 'P' in flags else 0
        ack_flag = 1 if 'A' in flags else 0

        # Update flow data
        flow_data = flows[flow_key]
        flow_data['src_ip'] = src_ip
        flow_data['dst_ip'] = dst_ip
        flow_data['protocol'] = protocol
        flow_data['packet_lengths'].append(packet_len)
        flow_data['fin_count'] += fin_flag
        flow_data['syn_count'] += syn_flag
        flow_data['psh_count'] += psh_flag
        flow_data['ack_count'] += ack_flag

        # For IAT (Inter-arrival time), calculate based on timestamp difference
        if flow_data['duration'] > 0:
            flow_iat = (packet.time - flow_data['duration']) * 1000  # Convert to milliseconds
            flow_data['flow_iat'].append(flow_iat)

        # Update packet count and flow duration
        flow_data['fwd_packets'] += 1 if packet['IP'].src == src_ip else 0
        flow_data['bwd_packets'] += 1 if packet['IP'].dst == dst_ip else 0
        flow_data['duration'] = packet.time

# Function to block an IP address using iptables
def block_ip(ip):
    print(f"Blocking IP address {ip} using iptables...")
    os.system(f"iptables -A INPUT -s {ip} -j DROP")  # Block incoming traffic from this IP

# Function to save captured data to a CSV file
def save_to_csv():
    # Prepare CSV header and row data
    fieldnames = [
        'Source IP', 'Destination IP', 'Protocol', 'Flow Duration', 'Total Length of Fwd Packets',
        'Total Length of Bwd Packets', 'Flow IAT Mean', 'Flow IAT Max', 'Flow IAT Min',
        'Packet Length Mean', 'FIN Flag Count', 'SYN Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'Predicted Label'
    ]

    with open('flow_data_with_predictions.csv', 'w', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        # Process each flow and make predictions
        for flow_key, flow_data in flows.items():
            # Compute Flow IAT Mean, Max, Min
            if flow_data['flow_iat']:
                flow_iat_mean = sum(flow_data['flow_iat']) / len(flow_data['flow_iat'])
                flow_iat_max = max(flow_data['flow_iat'])
                flow_iat_min = min(flow_data['flow_iat'])
            else:
                flow_iat_mean = flow_iat_max = flow_iat_min = 0

            # Compute Packet Length Mean
            if flow_data['packet_lengths']:
                packet_len_mean = sum(flow_data['packet_lengths']) / len(flow_data['packet_lengths'])
            else:
                packet_len_mean = 0

            # Create feature array for prediction
            feature_array = [
                flow_data['duration'],
                flow_data['fwd_packets'],
                flow_data['bwd_packets'],
                flow_iat_mean,
                flow_iat_max,
                flow_iat_min,
                packet_len_mean,
                flow_data['fin_count'],
                flow_data['syn_count'],
                flow_data['psh_count'],
                flow_data['ack_count']
            ]

            # Ensure the feature array has the correct number of features (14 in this case)
            while len(feature_array) < 14:
                feature_array.append(0)  # Fill with zeros if there are missing features

            # Make prediction
            predicted_label = model.predict([feature_array])[0]

            # Log the packet info and prediction to CSV
            writer.writerow({
                'Source IP': flow_data['src_ip'],
                'Destination IP': flow_data['dst_ip'],
                'Protocol': flow_data['protocol'],
                'Flow Duration': flow_data['duration'],
                'Total Length of Fwd Packets': flow_data['fwd_packets'],
                'Total Length of Bwd Packets': flow_data['bwd_packets'],
                'Flow IAT Mean': flow_iat_mean,
                'Flow IAT Max': flow_iat_max,
                'Flow IAT Min': flow_iat_min,
                'Packet Length Mean': packet_len_mean,
                'FIN Flag Count': flow_data['fin_count'],
                'SYN Flag Count': flow_data['syn_count'],
                'PSH Flag Count': flow_data['psh_count'],
                'ACK Flag Count': flow_data['ack_count'],
                'Predicted Label': predicted_label
            })

            # Print packet details and prediction
            print(
                f"Timestamp: {datetime.now()}, Src IP: {flow_data['src_ip']}, Dst IP: {flow_data['dst_ip']}, Protocol: {flow_data['protocol']}, Prediction: {predicted_label}"
            )

            # Block the IP if the prediction is DDoS (1)
            if predicted_label == 1:
                block_ip(flow_data['src_ip'])

# Start sniffing packets on port 80 (HTTP) on interface 'enp0s3'
# Start sniffing packets on port 80 (HTTP) on interface 'enp0s3' in a non-blocking manner
sniff(filter="tcp port 80", iface="enp0s3", prn=process_packet, store=0, count=0)

# After sniffing, save the collected flow data with predictions to CSV
save_to_csv()

print("Flow data with predictions saved to flow_data_with_predictions.csv")

