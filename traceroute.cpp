// traceroute.cpp

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
                std::cout << "usage: " << argv[0] << " -d [destination ip] -v [Log Level]" << std::endl;
                exit(-1);
        }
    }

    if (destIP.empty()) {
        std::cout << "Destination IP is required." << std::endl;
        std::cout << "usage: " << argv[0] << " -d [destination ip] -v [Log Level]" << std::endl;
        exit(-1);
    }

    // Create raw socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed. Need root privileges.");
        exit(EXIT_FAILURE);
    }

    // Set destination address
    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    if (inet_pton(AF_INET, destIP.c_str(), &dest_addr.sin_addr) != 1) {
        perror("Invalid destination IP address");
        exit(EXIT_FAILURE);
    }

    int max_ttl = 30;
    int sequence_number = 0;
    bool reached = false;

    for (int ttl = 2; ttl <= max_ttl; ++ttl) {
        // Set the TTL option on the socket
        if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            perror("Failed to set socket option");
            exit(EXIT_FAILURE);
        }

        // Build ICMP Echo Request packet
        char sendbuf[64];
        memset(sendbuf, 0, sizeof(sendbuf));
        struct icmp *icmp_hdr = (struct icmp *) sendbuf;
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = htons(getpid() & 0xFFFF);
        icmp_hdr->icmp_seq = htons(sequence_number++);
        // Compute ICMP checksum
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = checksum((unsigned short *)icmp_hdr, sizeof(struct icmp));

        // Send the packet
        ssize_t bytes_sent = sendto(sockfd, sendbuf, sizeof(struct icmp), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
        if (bytes_sent <= 0) {
            perror("Failed to send packet");
            continue;
        }

        DEBUG << "Sent " << bytes_sent << " bytes to " << destIP << ENDL;

        // Set up select for timeout
        fd_set readfds;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);

        struct timeval tv;
        tv.tv_sec = 15; // 15-second timeout
        tv.tv_usec = 0;

        int retval = select(sockfd + 1, &readfds, NULL, NULL, &tv);
        if (retval == -1) {
            perror("select()");
            exit(EXIT_FAILURE);
        } else if (retval == 0) {
            // Timeout occurred
            std::cout << "No response with TTL of " << ttl << std::endl;
            continue;
        } else {
            // Data is available, receive it
            char recvbuf[1024];
            struct sockaddr_in recv_addr;
            socklen_t addr_len = sizeof(recv_addr);

            ssize_t len = recvfrom(sockfd, recvbuf, sizeof(recvbuf), 0, (struct sockaddr *)&recv_addr, &addr_len);
            if (len <= 0) {
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
                reached = true;
                break;
            } else if (icmp_hdr_recv->icmp_type == ICMP_TIME_EXCEEDED) {
                // Time Exceeded message received
                // Extract the original IP header and ICMP header from the data section
                struct ip *orig_ip_hdr = (struct ip *)(recvbuf + ip_hdr_len + sizeof(struct icmp));
                int orig_ip_hdr_len = orig_ip_hdr->ip_hl * 4;
                struct icmp *orig_icmp_hdr = (struct icmp *)((char *)orig_ip_hdr + orig_ip_hdr_len);

                if (orig_icmp_hdr->icmp_id == htons(getpid() & 0xFFFF)) {
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(recv_addr.sin_addr), addr_str, INET_ADDRSTRLEN);
                    std::cout << "TTL " << ttl << ": " << addr_str << std::endl;
                }
            } else {
                // Other ICMP message
                if (LOG_LEVEL > 0) {
                    char addr_str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(recv_addr.sin_addr), addr_str, INET_ADDRSTRLEN);
                    std::cout << "Received ICMP type " << (int)icmp_hdr_recv->icmp_type
                              << " from " << addr_str << std::endl;
                }
            }
        }
    }

    if (!reached) {
        std::cout << "Did not reach destination within " << max_ttl << " hops." << std::endl;
    }

    close(sockfd);
    return 0;
}
