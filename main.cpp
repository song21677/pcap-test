#include <pcap.h>
#include <stdio.h>
#include <headers.h>

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
    for (int i=0; i<4; i++) {
        printf("%d", ip_address[i]);
        if(i != 3) {
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
        printf("%u bytes captured\n", header->caplen);

        const struct ethernet_header* ethernet = (struct ethernet_header*)(packet);
        if (ntohs(ethernet->ethernet_type) == 0x0800) {
            const struct ip_header* ip = (struct ip_header*)(packet + sizeof(ethernet_header));
            int ip_hl = (ip->ip_vhl & 0x0F)*4;
            if (ip->ip_pi == 6) {
                const struct tcp_header* tcp = (struct tcp_header*)(packet + sizeof(ethernet_header) + ip_hl);
                int tcp_hl = (((tcp->tcp_or & 0xF0)>>4)*4);
                const u_char *payload = packet + sizeof(ethernet_header) + ip_hl + tcp_hl;
                int payload_length = ntohs(ip->ip_tpl)-ip_hl-tcp_hl;

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

                for (int i=1; i<=payload_length; i++) {
                    printf("%02x ", *payload);
                    payload++;
                    if (i>15) break;
                }
            printf("\n\n");
            }
        }
    }

    pcap_close(handle);
}
