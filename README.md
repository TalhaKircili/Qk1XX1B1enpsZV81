# Puzzle 5 - Network Traffic Inspection

## Challenge Description

> Here at Fabulous Mobility, we understand that collaboration with our partners is crucial in delivering awesome cars. It therefore comes with no surprise that the availability of our offered services are continously tested to ensure they are running.
> We really keep things simple and just send ping packets. Therefore, we don't recommend you waste time inspecting the traffic. However, in case you insist, we provide two .pcap sample files to show how this availability testing is achieved:
>
> * `sample_1.pcap`
> * `sample_2.pcap`

---

# Initial Analysis

Opening the PCAPs in Wireshark immediately revealed two types of traffic:

* ICMP Echo Requests (`ping`)
* A small amount of TCP traffic

The ICMP packets contained payloads like:

```text
index=17
```

---

# TCP Configuration Messages

The first TCP packet contained a message similar to:

```text
alphabet=This is the alphabet we shall use to encode the secret flag: abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890-+
```

The second TCP packet contained:

```text
ping_interval=After the next ping, consider the indexes that I only send to *you* at this interval: 3
```

This immediately suggested:

* the `index` values represent indexes from the custom alphabet
* only every `n-th` relevant ping packet matters

Additionally, the source and destination IPs of the second TCP packet determine which ICMP stream should be analyzed.

---

# Solution Logic

The extraction process became:

1. Read the PCAP.
2. Find the TCP packet containing the alphabet.
3. Find the TCP packet containing the interval.
4. Extract:
   * alphabet
   * interval
   * source IP
   * destination IP
5. Process ICMP packets occurring after the interval TCP packet.
6. Only consider ICMP packets matching the extracted source/destination pair.
7. Select every `n-th` matching ICMP packet.
8. Extract the numeric `index=...` value.
9. Convert indexes into characters using the custom alphabet.

---

# Flags

## sample_1.pcap

```text
CIT-16e5e944f6c08b6cee039555c5f23cf893d47470ad+e93a6ba94777db82c43a6
```

## sample_2.pcap

```text
CIT-9f544c9cbb1dc19bbd262a313b5bcaa7f6cf1e6c35c2114a02338dec01cacdd6
```
