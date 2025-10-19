#include <iostream>
#include <cstring>
#include <ctime>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

using namespace std;


// Node structure for linked lists
template <typename T>
class Node {
public:
    T data;
    Node* next;
    Node(T val) {
        data = val;
        next = nullptr;
    }
};

// Queue - FIFO structure for managing packets
template <typename T>
class Queue {
private:
    Node<T>* front;
    Node<T>* rear;
    int count;

public:
    Queue() {
        front = nullptr;
        rear = nullptr;
        count = 0;
    }
    
    ~Queue() {
        while (!isEmpty()) {
            dequeue();
        }
    }
    
    void enqueue(T data) {
        Node<T>* newNode = new Node<T>(data);
        if (rear == nullptr) {
            front = rear = newNode;
        } else {
            rear->next = newNode;
            rear = newNode;
        }
        count++;
    }
    
    T dequeue() {
        if (isEmpty()) {
            throw runtime_error("Queue is empty!");
        }
        Node<T>* temp = front;
        T data = front->data;
        front = front->next;
        if (front == nullptr) {
            rear = nullptr;
        }
        delete temp;
        count--;
        return data;
    }
    
    T peek() {
        if (isEmpty()) {
            throw runtime_error("Queue is empty!");
        }
        return front->data;
    }
    
    bool isEmpty() {
        return front == nullptr;
    }
    
    int size() {
        return count;
    }
    
    Node<T>* getFront() { 
        return front; 
    }
};

// Stack - LIFO structure for parsing packet layers
template <typename T>
class Stack {
private:
    Node<T>* top;
    int count;

public:
    Stack() {
        top = nullptr;
        count = 0;
    }
    
    ~Stack() {
        while (!isEmpty()) {
            pop();
        }
    }
    
    void push(T data) {
        Node<T>* newNode = new Node<T>(data);
        newNode->next = top;
        top = newNode;
        count++;
    }
    
    T pop() {
        if (isEmpty()) {
            throw runtime_error("Stack is empty!");
        }
        Node<T>* temp = top;
        T data = top->data;
        top = top->next;
        delete temp;
        count--;
        return data;
    }
    
    T peek() {
        if (isEmpty()) {
            throw runtime_error("Stack is empty!");
        }
        return top->data;
    }
    
    bool isEmpty() {
        return top == nullptr;
    }
    
    int size() {
        return count;
    }
};

// Packet structure to store captured packet info
struct Packet {
    int id;
    time_t timestamp;
    unsigned char* rawData;
    int dataSize;
    string sourceIP;
    string destIP;
    int retryCount;
    
    Packet() {
        id = 0;
        timestamp = 0;
        rawData = nullptr;
        dataSize = 0;
        retryCount = 0;
    }
    
    Packet(int _id, unsigned char* data, int size) {
        id = _id;
        timestamp = time(nullptr);
        dataSize = size;
        rawData = new unsigned char[size];
        memcpy(rawData, data, size);
        retryCount = 0;
    }
    
    ~Packet() {

    }
    
    // copy constructor because we need deep copy for the raw data
    Packet(const Packet& other) {
        id = other.id;
        timestamp = other.timestamp;
        dataSize = other.dataSize;
        sourceIP = other.sourceIP;
        destIP = other.destIP;
        retryCount = other.retryCount;
        if (other.rawData != nullptr) {
            rawData = new unsigned char[dataSize];
            memcpy(rawData, other.rawData, dataSize);
        } else {
            rawData = nullptr;
        }
    }
};

// For storing info about each layer we parse
struct LayerInfo {
    string layerName;
    string details;
    
    LayerInfo(string name = "", string det = "") {
        layerName = name;
        details = det;
    }
};

// global queues and counter
Queue<Packet> packetQueue;
Queue<Packet> filteredQueue;
Queue<Packet> backupQueue;
int packetCounter = 0;

// function to open raw socket on specified interface
int openRawSocket(const char* interface) {
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    // get interface index
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    
    if (ioctl(sockfd, SIOCGIFINDEX, &ifr) < 0) {
        perror("Interface not found");
        close(sockfd);
        return -1;
    }
    
    // bind socket to interface
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifr.ifr_ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    
    if (bind(sockfd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("Bind failed");
        close(sockfd);
        return -1;
    }
    
    cout << "Raw socket opened successfully on " << interface << endl;
    return sockfd;
}

// capture packets continuously for given duration
void capturePackets(int sockfd, int duration) {
    unsigned char buffer[65536];
    time_t startTime = time(nullptr);
    
    cout << "\nStarting packet capture for " << duration << " seconds...\n" << endl;
    
    while (time(nullptr) - startTime < duration) {
        int dataSize = recvfrom(sockfd, buffer, 65536, 0, nullptr, nullptr);
        
        if (dataSize < 0) {
            perror("Receive failed");
            continue;
        }
        
        // create new packet
        Packet pkt(++packetCounter, buffer, dataSize);
        
        // try to extract IP addresses from the packet
        struct ethhdr* eth = (struct ethhdr*)buffer;
        unsigned short ethType = ntohs(eth->h_proto);
        
        if (ethType == ETH_P_IP) {
            // IPv4 packet
            struct iphdr* iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
            struct in_addr src, dst;
            src.s_addr = iph->saddr;
            dst.s_addr = iph->daddr;
            pkt.sourceIP = inet_ntoa(src);
            src.s_addr = iph->daddr;
            pkt.destIP = inet_ntoa(src);
        } else if (ethType == ETH_P_IPV6) {
            // IPv6 packet
            struct ip6_hdr* ip6h = (struct ip6_hdr*)(buffer + sizeof(struct ethhdr));
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6h->ip6_src), src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst, INET6_ADDRSTRLEN);
            pkt.sourceIP = src;
            pkt.destIP = dst;
        }
        
        packetQueue.enqueue(pkt);
        
        // print progress every 10 packets
        if (packetCounter % 10 == 0) {
            cout << "Captured " << packetCounter << " packets so far..." << endl;
        }
    }
    
    cout << "\nCapture complete! Total packets captured: " << packetCounter << endl;
}

// parse packet layers using stack
void dissectPacket(Packet& pkt, Stack<LayerInfo>& layers) {
    unsigned char* data = pkt.rawData;
    int size = pkt.dataSize;
    
    // first parse ethernet layer
    if (size >= (int)sizeof(struct ethhdr)) {
        struct ethhdr* eth = (struct ethhdr*)data;
        char details[256];
        snprintf(details, sizeof(details), "Src MAC: %02x:%02x:%02x:%02x:%02x:%02x, Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x, Type: 0x%04x",
                 eth->h_source[0], eth->h_source[1], eth->h_source[2], eth->h_source[3], eth->h_source[4], eth->h_source[5],
                 eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3], eth->h_dest[4], eth->h_dest[5],
                 ntohs(eth->h_proto));
        layers.push(LayerInfo("Ethernet", details));
        
        unsigned short ethType = ntohs(eth->h_proto);
        data += sizeof(struct ethhdr);
        size -= sizeof(struct ethhdr);
        
        // check what comes after ethernet
        if (ethType == ETH_P_IP && size >= (int)sizeof(struct iphdr)) {
            // its IPv4
            struct iphdr* iph = (struct iphdr*)data;
            struct in_addr src, dst;
            src.s_addr = iph->saddr;
            dst.s_addr = iph->daddr;
            char ipDetails[256];
            snprintf(ipDetails, sizeof(ipDetails), "Src IP: %s, Dst IP: %s, Protocol: %d, TTL: %d",
                     inet_ntoa(src), inet_ntoa(dst), iph->protocol, iph->ttl);
            src.s_addr = iph->daddr;
            layers.push(LayerInfo("IPv4", ipDetails));
            
            int ipHeaderLen = iph->ihl * 4;
            data += ipHeaderLen;
            size -= ipHeaderLen;
            
            // now check transport layer
            if (iph->protocol == IPPROTO_TCP && size >= (int)sizeof(struct tcphdr)) {
                struct tcphdr* tcph = (struct tcphdr*)data;
                char tcpDetails[256];
                snprintf(tcpDetails, sizeof(tcpDetails), "Src Port: %d, Dst Port: %d, Seq: %u, Ack: %u, Flags: %s%s%s%s%s%s",
                         ntohs(tcph->source), ntohs(tcph->dest), ntohl(tcph->seq), ntohl(tcph->ack_seq),
                         tcph->syn ? "SYN " : "", tcph->ack ? "ACK " : "", tcph->fin ? "FIN " : "",
                         tcph->rst ? "RST " : "", tcph->psh ? "PSH " : "", tcph->urg ? "URG " : "");
                layers.push(LayerInfo("TCP", tcpDetails));
            } else if (iph->protocol == IPPROTO_UDP && size >= (int)sizeof(struct udphdr)) {
                struct udphdr* udph = (struct udphdr*)data;
                char udpDetails[256];
                snprintf(udpDetails, sizeof(udpDetails), "Src Port: %d, Dst Port: %d, Length: %d",
                         ntohs(udph->source), ntohs(udph->dest), ntohs(udph->len));
                layers.push(LayerInfo("UDP", udpDetails));
            }
        } else if (ethType == ETH_P_IPV6 && size >= (int)sizeof(struct ip6_hdr)) {
            // its IPv6
            struct ip6_hdr* ip6h = (struct ip6_hdr*)data;
            char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &(ip6h->ip6_src), src, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(ip6h->ip6_dst), dst, INET6_ADDRSTRLEN);
            char ip6Details[512];
            snprintf(ip6Details, sizeof(ip6Details), "Src IP: %s, Dst IP: %s, Next Header: %d",
                     src, dst, ip6h->ip6_nxt);
            layers.push(LayerInfo("IPv6", ip6Details));
            
            data += sizeof(struct ip6_hdr);
            size -= sizeof(struct ip6_hdr);
            
            if (ip6h->ip6_nxt == IPPROTO_TCP && size >= (int)sizeof(struct tcphdr)) {
                struct tcphdr* tcph = (struct tcphdr*)data;
                char tcpDetails[256];
                snprintf(tcpDetails, sizeof(tcpDetails), "Src Port: %d, Dst Port: %d, Seq: %u",
                         ntohs(tcph->source), ntohs(tcph->dest), ntohl(tcph->seq));
                layers.push(LayerInfo("TCP", tcpDetails));
            } else if (ip6h->ip6_nxt == IPPROTO_UDP && size >= (int)sizeof(struct udphdr)) {
                struct udphdr* udph = (struct udphdr*)data;
                char udpDetails[256];
                snprintf(udpDetails, sizeof(udpDetails), "Src Port: %d, Dst Port: %d",
                         ntohs(udph->source), ntohs(udph->dest));
                layers.push(LayerInfo("UDP", udpDetails));
            }
        }
    }
}

// filter packets based on source and destination IPs
void filterPackets(const string& srcIP, const string& dstIP) {
    cout << "\nFiltering packets..." << endl;
    if (!srcIP.empty()) cout << "Source IP filter: " << srcIP << endl;
    if (!dstIP.empty()) cout << "Destination IP filter: " << dstIP << endl;
    
    Node<Packet>* current = packetQueue.getFront();
    int oversizedCount = 0;
    int filteredCount = 0;
    
    while (current != nullptr) {
        Packet& pkt = current->data;
        
        // skip really big packets if we already have too many
        if (pkt.dataSize > 1500) {
            oversizedCount++;
            if (oversizedCount > 5) {
                current = current->next;
                continue;
            }
        }
        
        // check if packet matches our filter
        bool matchSrc = srcIP.empty() || pkt.sourceIP == srcIP;
        bool matchDst = dstIP.empty() || pkt.destIP == dstIP;
        
        if (matchSrc && matchDst) {
            filteredQueue.enqueue(pkt);
            filteredCount++;
        }
        
        current = current->next;
    }
    
    cout << "Found " << filteredCount << " matching packets" << endl;
}

// replay filtered packets with error handling
void replayPackets(int sockfd) {
    cout << "\nReplaying filtered packets..." << endl;
    
    int replayedCount = 0;
    int failedCount = 0;
    
    while (!filteredQueue.isEmpty()) {
        Packet pkt = filteredQueue.dequeue();
        
        // calculate delay based on packet size
        int delay = pkt.dataSize / 1000;
        if (delay > 0) {
            usleep(delay * 1000);
        }
        
        // try to send the packet
        ssize_t sent = send(sockfd, pkt.rawData, pkt.dataSize, 0);
        
        if (sent < 0) {
            // sending failed
            pkt.retryCount++;
            if (pkt.retryCount <= 2) {
                backupQueue.enqueue(pkt);
                cout << "Packet " << pkt.id << " failed, will retry (attempt " << pkt.retryCount << ")" << endl;
            } else {
                failedCount++;
                cout << "Packet " << pkt.id << " failed after max retries" << endl;
            }
        } else {
            replayedCount++;
            if (replayedCount % 5 == 0) {
                cout << "Replayed " << replayedCount << " packets..." << endl;
            }
        }
    }
    
    // now try the backup packets
    cout << "\nRetrying failed packets from backup..." << endl;
    while (!backupQueue.isEmpty()) {
        Packet pkt = backupQueue.dequeue();
        ssize_t sent = send(sockfd, pkt.rawData, pkt.dataSize, 0);
        if (sent >= 0) {
            replayedCount++;
            cout << "Retry successful for packet " << pkt.id << endl;
        } else {
            failedCount++;
        }
    }
    
    cout << "\nReplay complete: " << replayedCount << " successful, " << failedCount << " failed" << endl;
}

// display list of captured packets
void showPacketList() {
    cout << "\nCaptured Packets:" << endl;
    cout << "ID  Timestamp                 Source IP          Dest IP            Size" << endl;
    
    Node<Packet>* current = packetQueue.getFront();
    int count = 0;
    while (current != nullptr && count < 20) {
        Packet& pkt = current->data;
        char timeStr[26];
        ctime_r(&pkt.timestamp, timeStr);
        timeStr[24] = '\0';
        printf("%d\t%s\t%s\t\t%s\t%d\n", pkt.id, timeStr, pkt.sourceIP.c_str(), pkt.destIP.c_str(), pkt.dataSize);
        current = current->next;
        count++;
    }
    
    if (packetQueue.size() > 20) {
        cout << "... (" << (packetQueue.size() - 20) << " more packets not shown)" << endl;
    }
}

// show dissected layers for a specific packet
void showDissectedLayers(int packetId) {
    cout << "\nDissected Layers for Packet " << packetId << ":" << endl;
    
    Node<Packet>* current = packetQueue.getFront();
    while (current != nullptr) {
        if (current->data.id == packetId) {
            Stack<LayerInfo> layers;
            dissectPacket(current->data, layers);
            
            int layerNum = 1;
            while (!layers.isEmpty()) {
                LayerInfo layer = layers.pop();
                cout << "Layer " << layerNum++ << " - " << layer.layerName << ":" << endl;
                cout << "  " << layer.details << endl;
            }
            return;
        }
        current = current->next;
    }
    
    cout << "Packet " << packetId << " not found" << endl;
}

// display filtered packets with their delays
void showFilteredPackets() {
    cout << "\nFiltered Packets:" << endl;
    cout << "ID  Source IP          Dest IP            Size    Delay (ms)" << endl;
    
    Node<Packet>* current = filteredQueue.getFront();
    while (current != nullptr) {
        Packet& pkt = current->data;
        int delay = pkt.dataSize / 1000;
        printf("%d\t%s\t\t%s\t%d\t%d\n", pkt.id, pkt.sourceIP.c_str(), pkt.destIP.c_str(), pkt.dataSize, delay);
        current = current->next;
    }
}

int main() {
    cout << "\nNetwork Packet Analyzer" << endl;
    
    // Note: need root privileges to run this
    // using loopback interface for testing
    const char* interface = "lo";
    
    // open raw socket
    int sockfd = openRawSocket(interface);
    if (sockfd < 0) {
        cout << "Error: Could not open socket. Make sure you run with sudo!" << endl;
        cout << "Also check if interface name is correct (try: wlan0, eth0, enp0s3)" << endl;
        return 1;
    }
    
    // test case 1: capture packets for 60 seconds
    capturePackets(sockfd, 60);
    
    // test case 2: dissect first few packets
    cout << "\nDissecting captured packets..." << endl;
    for (int i = 1; i <= min(5, packetCounter); i++) {
        showDissectedLayers(i);
    }
    
    // test case 3: display packet list
    showPacketList();
    
    // test case 4: filter packets
    // empty strings mean show all packets
    filterPackets("", "");
    showFilteredPackets();
    
    // test case 5: replay filtered packets
    replayPackets(sockfd);
    
    // summary
    cout << "\n\nSummary:" << endl;
    cout << "Total packets captured: " << packetCounter << endl;
    cout << "Packets in queue: " << packetQueue.size() << endl;
    cout << "Filtered packets: " << filteredQueue.size() << endl;
    cout << "Backup packets: " << backupQueue.size() << endl;
    cout << "\nProgram finished.\n" << endl;
    
    close(sockfd);
    return 0;
}
