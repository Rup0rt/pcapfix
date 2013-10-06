#ifndef PF_PCAPNG
#define PF_PCAPNG

#define BYTE_ORDER_MAGIC 0x1a2b3c4d

#define TYPE_SHB 0x0A0D0D0A
#define TYPE_IDB 0x00000001
#define TYPE_PB  0x00000002
#define TYPE_SPB 0x00000003
#define TYPE_NRB 0x00000004
#define TYPE_ISB 0x00000005
#define TYPE_EPB 0x00000006

int fix_pcapng(FILE *pcap, FILE *pcap_fix);

#endif
