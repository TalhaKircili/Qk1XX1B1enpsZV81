from scapy.all import rdpcap, IP, TCP, ICMP, Raw
from re import search

def get_payload(packet):
    """Extract packet payload as UTF-8 text."""
    if Raw not in packet:
        return ""

    return bytes(packet[Raw].load).decode(errors="ignore")


def extract_tcp_config(packets):
    """
    Extract decoding parameters from TCP traffic:
    - alphabet used for decoding
    - interval for selecting ICMP packets
    - source/destination pair to monitor
    - packet index after which extraction starts
    """
    alphabet = None
    interval = None
    source_ip = None
    destination_ip = None
    start_index = None

    for packet_index, packet in enumerate(packets):
        payload = get_payload(packet)

        alphabet_match = search(r"alphabet=.*?:\s*(\S+)", payload)
        if alphabet_match:
            alphabet = alphabet_match.group(1)
            continue

        interval_match = search(r"interval:\s*(\d+)", payload)
        if interval_match:
            interval = int(interval_match.group(1))
            source_ip = packet[IP].src
            destination_ip = packet[IP].dst
            start_index = packet_index
            break

    return alphabet, interval, source_ip, destination_ip, start_index


def extract_relevant_icmp_indexes(packets, start_index, source_ip, destination_ip, interval):
    """
    Extract ICMP indexes from packets matching the TCP-configured
    source/destination pair.

    Only every n-th matching packet is considered relevant,
    where n is the configured interval.
    """
    relevant_indexes = []
    counter = 0

    for packet in packets[start_index + 1:]:
        if IP not in packet or ICMP not in packet or Raw not in packet:
            continue

        if packet[IP].src != source_ip:
            continue

        if packet[IP].dst != destination_ip:
            continue

        match = search(r"index=(\d+)", get_payload(packet))
        if not match:
            continue

        if counter % interval == 0:
            relevant_indexes.append(int(match.group(1)))

        counter += 1

    return relevant_indexes


def decode_indexes(indexes, alphabet):
    """Convert numeric indexes into characters using the extracted alphabet."""
    return "".join(
        alphabet[index]
        for index in indexes
        if 0 <= index < len(alphabet)
    )


def analyze_pcap(pcap_file):
    """Analyze a PCAP file and attempt to recover the embedded flag."""
    packets = rdpcap(pcap_file)

    alphabet, interval, source_ip, destination_ip, start_index = extract_tcp_config(packets)

    indexes = extract_relevant_icmp_indexes(
        packets,
        start_index,
        source_ip,
        destination_ip,
        interval,
    )

    flag = decode_indexes(indexes, alphabet)

    print(f"\n--- {pcap_file} ---")
    print(f"Alphabet:       {alphabet}")
    print(f"Interval:       {interval}")
    print(f"Source IP:      {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"Flag: {flag}")


if __name__ == "__main__":
    for pcap_file in ["sample_1.pcap", "sample_2.pcap"]:
        analyze_pcap(pcap_file)