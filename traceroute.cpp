#include "traceroute.h"

uint16_t checksum(unsigned short *buffer, int size) {
    unsigned long sum = 0;
    while (size > 1) {
        sum += *buffer++;
        size -= 2;
    }
    if (size == 1) {
        sum += *(unsigned char *) buffer;
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short) (~sum);
}

int main(int argc, char *argv[]) {
    std::string destIP;

    // ********************************************************************
    // * Process the command line arguments
    // ********************************************************************
    int opt = 0;
    while ((opt = getopt(argc, argv, "d:v:")) != -1) {
        switch (opt) {
            case 'd':
                destIP = optarg;
                break;
            case 'v':
                LOG_LEVEL = atoi(optarg);
                break;
            case ':':
            case '?':
            default:
                FATAL << "usage: " << argv[0] << " -d [destination ip] -v [Log Level]" << ENDL;
                exit(-1);
        }
    }

    if (destIP.empty()) {
        FATAL << "Destination IP is required." << ENDL;
        FATAL << "usage: " << argv[0] << " -d [destination ip] -v [Log Level]" << ENDL;
        exit(-1);
    }

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        FATAL << "Socket creation failed. Need root privileges." << ENDL;
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    INFO << "Raw socket created successfully." << ENDL;

    // Set destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, destIP.c_str(), &dest_addr.sin_addr) != 1) {
        FATAL << "Invalid destination IP address: " << destIP << ENDL;
        exit(EXIT_FAILURE);
    }

    INFO << "Destination IP set to " << destIP << ENDL;

    int max_ttl = 30;
    int sequence_number = 0;
    int datagrams_sent = 0;
    bool reached = false;

    for (int ttl = 2; ttl <= max_ttl; ++ttl) {
        // Set the TTL option on the socket
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            ERROR << "Failed to set TTL option for TTL = " << ttl << ENDL;
            perror("Failed to set socket option");
            continue;
        }

        DEBUG << "TTL set to " << ttl << ENDL;

        // Build ICMP Echo Request packet
        char sendbuf[64];
        memset(sendbuf, 0, sizeof(sendbuf));
        struct icmp *icmp_hdr = (struct icmp *) sendbuf;
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = htons(getpid() & 0xFFFF);
        icmp_hdr->icmp_seq = htons(sequence_number++);
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = checksum((unsigned short *)icmp_hdr, sizeof(struct icmp));

        // Send the packet
        ssize_t bytes_sent = sendto(sockfd, sendbuf, sizeof(struct icmp), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent <= 0) {
            WARNING << "Failed to send datagram for TTL = " << ttl << ENDL;
            perror("Failed to send packet");
            continue;
        }

        datagrams_sent++;
        INFO << "Datagram sent: TTL = " << ttl << ", Bytes = " << bytes_sent << ENDL;

        // Set up select for timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval tv;
        tv.tv_sec = 15; // 15-second timeout
        tv.tv_usec = 0;

        int retval = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (retval == -1) {
            ERROR << "Select() failed." << ENDL;
            perror("select()");
            exit(EXIT_FAILURE);
        } else if (retval == 0) {
            // Timeout occurred
            WARNING << "No response with TTL = " << ttl << ENDL;
            std::cout << "No response with TTL = " << ttl << std::endl;
            continue;
        } else {
            // Data is available, receive it
            char recvbuf[1024];
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);

            ssize_t len = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&recv_addr, &addr_len);
            if (len <= 0) {
                ERROR << "Failed to receive packet for TTL = " << ttl << ENDL;
                perror("Failed to receive packet");
                continue;
            }

            DEBUG << "Received " << len << " bytes from " << inet_ntoa(recv_addr.sin_addr) << ENDL;

            // Process the received packet
            struct ip *ip_hdr = (struct ip *)recvbuf;
            int ip_hdr_len = ip_hdr->ip_hl * 4;

            struct icmp *icmp_hdr_recv = (struct icmp *)(recvbuf + ip_hdr_len);

            if (icmp_hdr_recv->icmp_type == ICMP_ECHOREPLY && icmp_hdr_recv->icmp_id == htons(getpid() & 0xFFFF)) {
                // Echo Reply received
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(recv_addr.sin_addr), addr_str, INET_ADDRSTRLEN);
                std::cout << "Reached destination: " << addr_str << std::endl;
                INFO << "Reached destination: " << addr_str << ENDL;
                reached = true;
                break;
            } else if (icmp_hdr_recv->icmp_type == ICMP_TIME_EXCEEDED) {
                // Time Exceeded message received
                char addr_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(recv_addr.sin_addr), addr_str, INET_ADDRSTRLEN);
                std::cout << "TTL " << ttl << ": " << addr_str << std::endl;
                INFO << "TTL " << ttl << ": " << addr_str << ENDL;
            } else {
                // Other ICMP message
                TRACE << "Received ICMP type " << (int)icmp_hdr_recv->icmp_type
                      << " from " << inet_ntoa(recv_addr.sin_addr) << ENDL;
            }
        }
    }

    // Print the total datagrams sent
    std::cout << "Total datagrams sent: " << datagrams_sent << std::endl;

    if (!reached) {
        WARNING << "Did not reach destination within " << max_ttl << " hops." << ENDL;
    }

    close(sockfd);
    INFO << "Socket closed. Program finished." << ENDL;
    return 0;
}
