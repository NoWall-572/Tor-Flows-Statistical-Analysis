import pandas as pd
from scapy.all import rdpcap
from collections import defaultdict
import glob
import os
from datetime import datetime
import pytz
import numpy as np
from scipy import stats

# 添加一个函数来映射协议编号为协议名称
def get_protocol_name(proto_number):
    if proto_number == 6:
        return "TCP"
    elif proto_number == 17:
        return "UDP"
    elif proto_number == 1:
        return "ICMP"
    else:
        return f"Other ({proto_number})"

# 完善协议检测：源端口或目的端口为 80 时为 HTTP，源端口或目的端口为 443 时为 HTTPS
def get_tcp_protocol_name(src_port, dst_port):
    if src_port == 80 or dst_port == 80:
        return "HTTP"
    elif src_port == 443 or dst_port == 443:
        return "HTTPS"
    else:
        return "TCP"

# 新增功能：根据源或目的 IP 修改流的名称并交换包数
def adjust_ip_and_ports(src_ip, src_port, dst_ip, dst_port):
    if src_ip == "209.141.46.203":
        # 如果源 IP 为 Tor_IP
        return {
            'Tor_IP': src_ip, 'Tor_Port': src_port,
            'Server_IP': dst_ip, 'Server_Port': dst_port,
            'swap_counts': False  # 不需要交换包数
        }
    elif dst_ip == "209.141.46.203":
        # 如果目的 IP 为 Tor_IP
        return {
            'Tor_IP': dst_ip, 'Tor_Port': dst_port,
            'Server_IP': src_ip, 'Server_Port': src_port,
            'swap_counts': True  # 需要交换包数
        }
    else:
        return {
            'Tor_IP': None, 'Tor_Port': None,
            'Server_IP': None, 'Server_Port': None,
            'swap_counts': False  # 默认不交换
        }

# 转换时间戳为北京时间
def timestamp_to_beijing(timestamp):
    timestamp = int(timestamp)
    utc_time = datetime.utcfromtimestamp(timestamp)
    beijing_tz = pytz.timezone('Asia/Shanghai')
    utc_time = pytz.utc.localize(utc_time)
    beijing_time = utc_time.astimezone(beijing_tz)
    return beijing_time.strftime('%Y-%m-%d %H:%M:%S')

def extract_time_features(times):
    if not times:
        return {}
    times = np.array(times)
    intervals = np.diff(times).astype(float)  # Ensure intervals are of float type
    return {
        'First Arrival Time': float(times[0]),
        'Last Arrival Time': float(times[-1]),
        'Duration': float(times[-1] - times[0]),
        'Average Interval': np.mean(intervals) if len(intervals) > 0 else 0,
        'Standard Deviation of Intervals': np.std(intervals) if len(intervals) > 0 else 0,
        'Variance of Intervals': np.var(intervals) if len(intervals) > 0 else 0,
        'Median Interval': np.median(intervals) if len(intervals) > 0 else 0,
        'Mode Interval': float(stats.mode(intervals, keepdims=False)[0]) if len(intervals) > 0 else 0,  # Set keepdims=False
        'Skewness of Intervals': stats.skew(intervals) if len(intervals) > 0 and len(np.unique(intervals)) > 1 else 0  # Check if intervals are identical
    }

def extract_tcp_flows(pcap_files, output_file, time_threshold=10):
    all_flow_records = []  # 用于存储所有文件的流记录

    for pcap_file in pcap_files:
        print(f"Processing file: {pcap_file}")
        packets = rdpcap(pcap_file)
        flows = defaultdict(lambda: {'forward': [], 'reverse': []})  # 用字典存储正向和反向流

        # 添加字典来存储每个流的开始时间和结束时间
        flow_timestamps = {}

        # 添加字节数的记录
        flow_bytes = defaultdict(lambda: {'forward': 0, 'reverse': 0})  # 用字典存储字节数

        # 存储每个流的时间戳
        flow_times = defaultdict(list)

        for packet in packets:
            if packet.haslayer('IP') and packet.haslayer('TCP'):
                ip_layer = packet['IP']
                tcp_layer = packet['TCP']
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport
                protocol = ip_layer.proto
                timestamp = packet.time  # 获取数据包的时间戳
                packet_size = len(packet)  # 包的字节数

                # 过滤掉端口 9001 的流量
                if src_port == 9001 or dst_port == 9001:
                    continue

                # 获取协议名称
                protocol_name = get_protocol_name(protocol)

                # 如果是 TCP，进一步判断是否为 HTTP 或 HTTPS
                if protocol_name == "TCP":
                    protocol_name = get_tcp_protocol_name(src_port, dst_port)

                # 用一个元组表示 TCP 连接
                flow_key = (src_ip, src_port, dst_ip, dst_port, protocol_name)

                # 也考虑反向流作为同一个连接
                reverse_flow_key = (dst_ip, dst_port, src_ip, src_port, protocol_name)

                # 更新流的开始时间和结束时间
                if flow_key not in flow_timestamps:
                    flow_timestamps[flow_key] = {"start": timestamp, "end": timestamp}
                else:
                    flow_timestamps[flow_key]["end"] = timestamp

                # 记录正向流和反向流
                if reverse_flow_key in flows:
                    flows[reverse_flow_key]['reverse'].append(packet)
                    flow_bytes[reverse_flow_key]['reverse'] += packet_size  # 累加反向流字节数
                    flow_times[reverse_flow_key].append(timestamp)  # 记录反向流的时间戳
                else:
                    flows[flow_key]['forward'].append(packet)
                    flow_bytes[flow_key]['forward'] += packet_size  # 累加正向流字节数
                    flow_times[flow_key].append(timestamp)  # 记录正向流的时间戳

        # 汇总每个文件的数据
        for flow_key, packets in flows.items():
            src_ip, src_port, dst_ip, dst_port, protocol_name = flow_key
            start_time = flow_timestamps[flow_key]["start"]
            end_time = flow_timestamps[flow_key]["end"]
            duration = float(end_time - start_time)  # 强制转换为浮动数值

            forward_packet_count = len(packets['forward'])
            reverse_packet_count = len(packets['reverse'])
            forward_bytes = flow_bytes[flow_key]['forward']
            reverse_bytes = flow_bytes[flow_key]['reverse']

            # 计算总字节数
            total_bytes = forward_bytes + reverse_bytes

            # 判断持续时间是否为零
            if duration > 0:
                # 计算传输速率（字节数 / 持续时间）
                transfer_rate = total_bytes / duration  # 传输速率，单位：字节/秒
            else:
                # 如果持续时间为零，设定传输速率为零
                transfer_rate = 0

            # 调整 IP 地址和端口，并决定是否交换包数
            ip_adjustment = adjust_ip_and_ports(src_ip, src_port, dst_ip, dst_port)
            Tor_IP = ip_adjustment['Tor_IP']
            Tor_Port = ip_adjustment['Tor_Port']
            Server_IP = ip_adjustment['Server_IP']
            Server_Port = ip_adjustment['Server_Port']
            swap_counts = ip_adjustment['swap_counts']

            # 如果需要交换包数，则交换
            if swap_counts:
                forward_packet_count, reverse_packet_count = reverse_packet_count, forward_packet_count
                forward_bytes, reverse_bytes = reverse_bytes, forward_bytes

            # 提取时间特征
            time_features = extract_time_features(flow_times[flow_key])

            # 汇总流数据并标记来源文件
            all_flow_records.append({
                'Tor_IP': Tor_IP,
                'Tor_Port': Tor_Port,
                'Server_IP': Server_IP,
                'Server_Port': Server_Port,
                'Protocol': protocol_name,
                'Forward Packet Count': forward_packet_count,  # 正向流包数
                'Reverse Packet Count': reverse_packet_count,  # 反向流包数
                'Total Packet Count': forward_packet_count + reverse_packet_count,  # 总包数
                'Forward Bytes': forward_bytes,  # 正向流字节数
                'Reverse Bytes': reverse_bytes,  # 反向流字节数
                'Total Bytes': total_bytes,  # 总字节数
                'Transfer Rate (B/s)': transfer_rate,  # 传输速率（字节/秒）
                'Start Time': start_time,
                'End Time': end_time,
                'Duration (s)': duration,  # 添加持续时间（单位：秒）
                'Source File': os.path.basename(pcap_file),  # 添加来源文件名
                **time_features  # 添加时间特征
            })

        # 合并重复流（前五列数据相同）并合并它们的包数和持续时间
        merged_records = []
        seen_flows = {}

        for record in all_flow_records:
            flow_key = tuple(record[col] for col in ['Tor_IP', 'Tor_Port', 'Server_IP', 'Server_Port', 'Protocol'])
            if flow_key not in seen_flows:
                seen_flows[flow_key] = record
            else:
                # 合并包数和持续时间
                existing_record = seen_flows[flow_key]
                if 'End Time' in record and 'End Time' in existing_record:
                    time_diff = record['Start Time'] - existing_record['End Time']
                    if abs(time_diff) <= time_threshold:
                        # 合并包数
                        existing_record['Forward Packet Count'] += record['Forward Packet Count']
                        existing_record['Reverse Packet Count'] += record['Reverse Packet Count']
                        existing_record['Total Packet Count'] += record['Total Packet Count']
                        existing_record['Forward Bytes'] += record['Forward Bytes']
                        existing_record['Reverse Bytes'] += record['Reverse Bytes']
                        existing_record['Total Bytes'] += record['Total Bytes']

                        # 计算新的持续时间
                        new_duration = existing_record['Duration (s)'] + (
                                    record['End Time'] - existing_record['Start Time'])
                        existing_record['Duration (s)'] = new_duration

                        # 计算传输速率
                        if new_duration > 0:
                            existing_record['Transfer Rate (B/s)'] = float(existing_record['Total Bytes'] / new_duration)
                        else:
                            existing_record['Transfer Rate (B/s)'] = 0.0

                        # 合并源文件
                        existing_record['Source File'] += f", {record['Source File']}"
                        # 更新结束时间
                        existing_record['End Time'] = max(record['End Time'], existing_record['End Time'])
                    else:
                        seen_flows[flow_key] = record
                else:
                    seen_flows[flow_key] = record

        # 将合并后的流记录保存到 Excel 文件
        final_records = list(seen_flows.values())

        # 转换时间戳为北京时间
        for record in final_records:
            if 'Start Time' in record and 'End Time' in record:
                record['Start Time (Beijing)'] = timestamp_to_beijing(record['Start Time'])
                record['End Time (Beijing)'] = timestamp_to_beijing(record['End Time'])

        # 删除原始的时间戳列
        for record in final_records:
            if 'Start Time' in record and 'End Time' in record:
                del record['Start Time']
                del record['End Time']

        # 将数据写入 Excel
        df = pd.DataFrame(final_records)
        df.to_excel(output_file, index=False)

if __name__ == "__main__":
    folder_path = 'E:/Tor网络流量检测内容/MyFlowProject/testflows'
    pcap_files = glob.glob(f'{folder_path}/**/log.pcap.*', recursive=True)
    output_file = 'E:/Tor网络流量检测内容/MyFlowProject/output.xlsx'  # Specify full path
    extract_tcp_flows(pcap_files, output_file)