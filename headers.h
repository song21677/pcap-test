#include <stdint.h>

struct ethernet_header
{
    uint8_t ethernet_dmac[6];
    uint8_t ethernet_smac[6];
    uint16_t ethernet_type;
};

struct ip_header
{
    uint8_t ip_vhl;
    uint8_t ip_tos;
    uint16_t ip_tpl;
    uint16_t ip_id;
    uint16_t ip_fo;
    uint8_t ip_ttl;
    uint8_t ip_pi;
    uint16_t ip_checksum;
    uint8_t ip_src[4];
    uint8_t ip_dst[4];
};

struct tcp_header
{
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seqnum;
    uint32_t tcp_acknum;
    uint8_t tcp_or;
    uint8_t tcp_flags;
    uint16_t tcp_window;
    uint16_t tcp_checksum;
    uint16_t tcp_up;
};

