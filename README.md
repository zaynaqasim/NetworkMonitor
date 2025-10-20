# Network Packet Analyzer

CS250 Assignment 2  
Zayna Qasim, BSDS-2A

## About

This program captures network packets and analyzes them using custom Queue and Stack data structures. No STL libraries used, everything is implemented from scratch.

## What it does

- Captures packets continuously from network interface
- Manages packets with custom Queue (FIFO)
- Parses protocol layers with custom Stack (LIFO)
- Supports Ethernet, IPv4, IPv6, TCP, and UDP
- Filters packets by source/destination IP
- Replays packets with retry on failure (max 2 retries)

## Requirements

- Linux system
- Root privileges (for raw sockets)
- g++ compiler

## Compilation
```bash
g++ -o network_monitor main.cpp -std=c++11
```

## Running
```bash
sudo ./network_monitor
```

The program captures for 60 seconds then shows results.

## Configuration

Default interface is `lo` (loopback). To change it, edit main.cpp line 450:
```cpp
const char* interface = "lo";  
```

Find your interfaces with: `ip link show`

## Testing

Generate traffic while program runs:
```bash
ping 127.0.0.1 -c 100
```

## Key Features

**Custom Queue:**
- Linked list implementation
- enqueue(), dequeue(), isEmpty(), size()
- Used for: packet queue, filtered queue, backup queue

**Custom Stack:**
- Linked list implementation  
- push(), pop(), peek(), isEmpty()
- Used for: parsing protocol layers

**Packet Structure:**
- ID, timestamp, raw data, IPs, retry count

**Protocol Dissection:**
- Ethernet: MAC addresses, EtherType
- IPv4/IPv6: IP addresses, protocol field
- TCP: ports, sequence numbers, flags
- UDP: ports, length

**Filtering:**
- By source/destination IP
- Skips oversized packets (>1500 bytes) if count exceeds threshold
- Delay calculation: packet_size / 1000 ms

**Replay with Error Handling:**
- Sends filtered packets
- Retry up to 2 times on failure
- Backup queue for failed packets

## Assumptions

- Single network interface used
- Root privileges available
- Linux environment
- Some network traffic present during capture
- Max 2 retries per packet as specified

## Files

- main.cpp - source code
- README.md - this file
- Report.pdf - documentation

## Notes

The trickiest part was getting protocol parsing right especially for IPv6. Memory management was also important since we're copying raw packet data. Using Queue for packet management and Stack for layer parsing made sense because of how network protocols work.

GitHub: https://github.com/zaynaqasim24/NetworkMonitor
