#include <pcap.h>
#include <stdio.h>
#include <headers.h>
#define ETHERNET_SIZE 14
#define IP_SIZE 20
#define TCP_SIZE 20

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

void print_ethernet(uint8_t const ethernet_mac[6]) {
    for(int i=0; i<6; i++) {
    printf("%02x", ethernet_mac[i]);
        if(i != 5) {
            printf(":");
        }
    }
}

void print_ip(uint8_t const ip_address[4]) {
    for (int j=0; j<4; j++) {
        printf("%d", ip_address[j]);
        if(j != 3) {
            printf(".");
        }
    }
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0)
            continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }

        const struct ethernet_header* ethernet = (struct ethernet_header*)(packet);
        const struct ip_header* ip = (struct ip_header*)(packet + ETHERNET_SIZE);
        const struct tcp_header* tcp = (struct tcp_header*)(packet + ETHERNET_SIZE + IP_SIZE);
        const u_char *payload = packet + ETHERNET_SIZE + IP_SIZE + TCP_SIZE;
        printf("%u bytes captured\n", header->caplen);

        if (ntohs(ethernet->ethernet_type) == 0x0800 && ip->ip_pi == 6) {
            printf("src mac: ");
            print_ethernet(ethernet->ethernet_smac);
            printf(", dst mac: ");
            print_ethernet(ethernet->ethernet_dmac);
            printf("\n\n");

            printf("src ip address: ");
            print_ip(ip->ip_src);
            printf(", dst ip address: ");
            print_ip(ip->ip_dst);
            printf("\n\n");

            printf("src port: %d, dst port: %d\n\n", htons(tcp->tcp_sport), htons(tcp->tcp_dport));

            for(int i=0; i<16; i++) {
                printf("%02x ", *payload);
                payload++;
            }
            printf("\n\n");
        }
    }

    pcap_close(handle);
}
