#ifndef PF_PCAPNG
#define PF_PCAPNG

/* http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html */
/* http://wiki.wireshark.org/Development/PcapNg */

#define BYTE_ORDER_MAGIC 0x1a2b3c4d /* pcapng default byte order magic - non swapped */

#define TYPE_SHB 0x0A0D0D0A /* Section Header Block */
#define TYPE_IDB 0x00000001 /* Interface Description Block */
#define TYPE_PB  0x00000002 /* Packet Block */
#define TYPE_SPB 0x00000003 /* Simple Packet Block */
#define TYPE_NRB 0x00000004 /* Name Resolution Block */
#define TYPE_ISB 0x00000005 /* Interface Statistics Block */
#define TYPE_EPB 0x00000006 /* Enhanced Packet Block */

/*
 * Function:  fix_pcapng
 * ---------------------
 * tries to fix a pcapng file
 *
 * pcap:      file pointer to input file
 * pcap_fix:  file pointer to output file
 *
 * returns: 0   success (file was corrupted and has been successfully repaired)
 *          !=0 otherwise
 *
 */
int fix_pcapng(FILE *pcap, FILE *pcap_fix);

int find_valid_block(FILE *pcap, unsigned long filesize);

int write_shb(FILE *pcap_fix);

int write_idb(FILE *pcap_fix);

#endif
