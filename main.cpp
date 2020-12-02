#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <libnet.h>
#include <netinet/in.h>
#include <iostream>

#pragma pack(push, 1)

struct atk_pkt {
    struct libnet_ethernet_hdr ether;
    struct libnet_ipv4_hdr ip;
    struct libnet_tcp_hdr tcp;
};

struct tcp_hdr {
    struct in_addr ip_src, ip_dst;
    uint8_t reserved;
    uint8_t ip_p;
    uint16_t tcp_len;
};

#pragma pack(pop)

char *https[] = {"GET", "POST"};

void checksum(struct atk_pkt *packet) {
    
    uint32_t th_sum = 0;
    packet->tcp.th_sum = 0;

    struct tcp_hdr pseudo_hdr;
    pseudo_hdr.ip_src = packet->ip.ip_src;
    pseudo_hdr.ip_dst = packet->ip.ip_dst;
    pseudo_hdr.reserved = 0;
    pseudo_hdr.ip_p = packet->ip.ip_p;
    pseudo_hdr.tcp_len = htons(sizeof(struct libnet_tcp_hdr));

    uint16_t *short_view = (uint16_t *) &pseudo_hdr;    
    for (int i = 0; i < sizeof(pseudo_hdr) / sizeof(uint16_t); i++) {
        th_sum += ntohs(short_view[i]);
    }
    short_view = (uint16_t *) &packet->tcp;    
    for (int i = 0; i < packet->tcp.th_off * sizeof(uint32_t) / sizeof(uint16_t); i++) {
        th_sum += ntohs(short_view[i]);
    }
    while (th_sum >> 16)
        th_sum = (th_sum & 0xFFFF) + (th_sum >> 16);
    packet->tcp.th_sum = ~htons(th_sum);

    uint32_t ip_sum = 0;
    packet->ip.ip_sum = 0;
    
    short_view = (uint16_t *) &packet->ip; 
    for (int i = 0; i < packet->ip.ip_hl * sizeof(uint32_t) / sizeof(uint16_t); i++) {
        ip_sum += ntohs(short_view[i]);
    }
    while (ip_sum >> 16)
        ip_sum = (ip_sum & 0xFFFF) + (ip_sum >> 16);
    
    packet->ip.ip_sum = ~htons(ip_sum);
}

void packet_builder(struct atk_pkt *new_pkt, struct atk_pkt *old_pkt, bool forward, uint8_t th_flags) {

    if (forward) {
        memcpy(new_pkt->ether.ether_dhost, old_pkt->ether.ether_dhost, ETHER_ADDR_LEN);
        memcpy(new_pkt->ether.ether_shost, old_pkt->ether.ether_shost, ETHER_ADDR_LEN);
    }
    else {
        memcpy(new_pkt->ether.ether_dhost, old_pkt->ether.ether_shost, ETHER_ADDR_LEN);
        memcpy(new_pkt->ether.ether_shost, old_pkt->ether.ether_dhost, ETHER_ADDR_LEN);
    }
    new_pkt->ether.ether_type = old_pkt->ether.ether_type;

    new_pkt->ip.ip_v = old_pkt->ip.ip_v;
    new_pkt->ip.ip_hl = sizeof(struct libnet_ipv4_hdr) / sizeof(uint32_t);
    new_pkt->ip.ip_tos = old_pkt->ip.ip_tos;
    new_pkt->ip.ip_len = htons(sizeof(struct libnet_ipv4_hdr) + sizeof(struct libnet_tcp_hdr));
    new_pkt->ip.ip_id = old_pkt->ip.ip_id;
    new_pkt->ip.ip_off = old_pkt->ip.ip_off;
    new_pkt->ip.ip_ttl = old_pkt->ip.ip_ttl;
    new_pkt->ip.ip_p = old_pkt->ip.ip_p;
    new_pkt->ip.ip_sum = 0;

    if (forward) {
        new_pkt->ip.ip_src = old_pkt->ip.ip_src;
        new_pkt->ip.ip_dst = old_pkt->ip.ip_dst;
    }
    else {
        new_pkt->ip.ip_src = old_pkt->ip.ip_dst;
        new_pkt->ip.ip_dst = old_pkt->ip.ip_src;
    }
    uint32_t old_data_length = ntohs(old_pkt->ip.ip_len) - (old_pkt->ip.ip_hl * sizeof(uint32_t)) - (old_pkt->tcp.th_off * sizeof(uint32_t));

    if (forward) {
        new_pkt->tcp.th_sport = old_pkt->tcp.th_sport;
        new_pkt->tcp.th_dport = old_pkt->tcp.th_dport;
        new_pkt->tcp.th_seq = htonl(ntohl(old_pkt->tcp.th_seq) + old_data_length);
        new_pkt->tcp.th_ack = old_pkt->tcp.th_ack;
    }
    else {
        new_pkt->tcp.th_sport = old_pkt->tcp.th_dport;
        new_pkt->tcp.th_dport = old_pkt->tcp.th_sport;
        new_pkt->tcp.th_seq = old_pkt->tcp.th_ack;
        new_pkt->tcp.th_ack = htonl(ntohl(old_pkt->tcp.th_seq) + old_data_length);
    }
    new_pkt->tcp.th_off = sizeof(struct libnet_tcp_hdr) / sizeof(uint32_t);
    new_pkt->tcp.th_flags = th_flags;
    new_pkt->tcp.th_win = old_pkt->tcp.th_win;
    new_pkt->tcp.th_sum = 0;
    new_pkt->tcp.th_urp = old_pkt->tcp.th_urp;

    checksum(new_pkt);
}

bool handler(struct atk_pkt *new_pkt, struct pcap_pkthdr *header, const u_char *packet, char *block_address) {
    const int32_t total_length = header->caplen;
    int32_t parsed_length = 0;

    if(total_length - parsed_length < sizeof(struct libnet_ethernet_hdr)) 
        return false;

    struct libnet_ethernet_hdr *view_ethernet = (struct libnet_ethernet_hdr *) packet;
    if (ntohs(view_ethernet->ether_type) != ETHERTYPE_IP)
        return false;

    parsed_length += sizeof(struct libnet_ethernet_hdr);
    if (total_length - parsed_length < sizeof(struct libnet_ipv4_hdr))
        return false;

    struct libnet_ipv4_hdr *view_ip = (struct libnet_ipv4_hdr *) (packet + parsed_length);

    if (view_ip->ip_p != IPPROTO_TCP)
        return false;
    
    if (total_length - parsed_length < ntohs(view_ip->ip_len) || total_length - parsed_length < ((view_ip->ip_hl) * sizeof(uint32_t)))
        return false;

    parsed_length += (view_ip->ip_hl) * sizeof(uint32_t);

    if (total_length - parsed_length < sizeof(struct libnet_tcp_hdr))
        return false;
    
    struct libnet_tcp_hdr *view_tcp = (struct libnet_tcp_hdr *) (packet + parsed_length);
    if (view_tcp->th_dport != htons(80))
        return false;
    
    if (total_length - parsed_length < (view_tcp->th_off * sizeof(uint32_t))) 
        return false;
    
    parsed_length += view_tcp->th_off * sizeof(uint32_t);
    char *http_req = (char *) (packet + parsed_length);

    bool found = false;
    if(total_length - parsed_length < 24)
        return false;
    
    for(int i = 0; i < sizeof(https); i++) {
        if(memcmp(http_req, https[i], strlen(https[i])) == 0) {
            found = true;
            break;
        }
    }

    if(!found)
        return false;
    
    char * pos = http_req;
    size_t length = total_length - parsed_length;
    found = false;
    
    for(int i = 0; i < 20; i++) {
        char *end =  (char *)memchr(pos, '\n', length);
        if(end == NULL)
            break;
        if(end - pos < 5)
            break;
        if(strncasecmp((const char *)pos, "Host", 4) == 0) {
            char *cur = pos +4;
            if (*cur == ':') {
                cur++;
                while(*cur == ' ' && cur < end) cur++;
                if(cur < end) {
                    char *address = cur;
                    address[end - cur] = '\x00';
                    size_t idx = end - cur - 1;
                    while(idx != 0 && (address[idx] == ' ' || address[idx] == '\n' || address[idx] == '\r'))
                        idx--;
                    address[idx + 1] = '\x00';
                    for(int j = 0; j < strlen(address); j++){
                        if (strncmp(block_address, address + j, strlen(block_address)) == 0) {
                            printf("i am blocking : %s\n", address);
                            memcpy(&new_pkt->ether, view_ethernet, sizeof(new_pkt->ether));
                            memcpy(&new_pkt->ip, view_ip, sizeof(new_pkt->ip));
                            memcpy(&new_pkt->tcp, view_tcp, sizeof(new_pkt->tcp));
                            return true;
                        }
                    }
                }
            }
        }
        length -= end - pos + 1;
        pos = end + 1;
    }
    return false;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("syntax : tcp-block <interface> <pattern>\n", argv[0]);
        printf("Sample: %s ens33 test.gilgil.net\n", argv[0]);
        return 1;
    }

    char *dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);

    while (true) {
        struct pcap_pkthdr *header;
        struct atk_pkt parsed_pkt;
        struct atk_pkt new_pkt;
        const u_char *packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;

        if(handler(&parsed_pkt, header, packet, argv[2])) {
            packet_builder(&new_pkt, &parsed_pkt, false, TH_RST | TH_ACK);
            pcap_inject(handle, &new_pkt, sizeof(new_pkt));
            packet_builder(&new_pkt, &parsed_pkt, true, TH_RST | TH_ACK);
            pcap_inject(handle, &new_pkt, sizeof(new_pkt));
        }
    }

    return 0;
}