#ifndef PF_PCAPNG
#define PF_PCAPNG

/* http://www.winpcap.org/ntar/draft/PCAP-DumpFileFormat.html */
/* http://wiki.wireshark.org/Development/PcapNg */

#define BYTE_ORDER_MAGIC 0x1a2b3c4d /* pcapng default byte order magic - non swapped */

#define TYPE_SHB 0x0A0D0D0A         /* Section Header Block */
#define TYPE_IDB 0x00000001         /* Interface Description Block */
#define TYPE_PB  0x00000002         /* Packet Block */
#define TYPE_SPB 0x00000003         /* Simple Packet Block */
#define TYPE_NRB 0x00000004         /* Name Resolution Block */
#define TYPE_ISB 0x00000005         /* Interface Statistics Block */
#define TYPE_EPB 0x00000006         /* Enhanced Packet Block */

/*
 * Function:  fix_pcapng
 * ---------------------
 * tries to fix a pcapng file
 *
 * pcap:      file pointer to input file
 * pcap_fix:  file pointer to output file
 *
 * returns: >0   success (number of corruptions fixed)
 *           0   success (nothing to fix)
 *          -1   error (not a pcap file)
 *          -2   error (unable to repair)
 *          -3   error (EOF while reading input file)
 *
 */
int fix_pcapng(FILE *pcap, FILE *pcap_fix);

/*
 * Function:  find_valid_block
 * ---------------------------
 * searches for the next valid block beginning at current file pointer position
 *
 * pcap:      file pointer to input file
 * filesize:  size of input file in bytes
 *
 * returns:  0   success (next block header has been found, file pointer is set to start of block)
 *          -1   error (reached EOF without finding a valid block)
 *
 */
int find_valid_block(FILE *pcap, unsigned long filesize);

/*
 * Function:  write_shb
 * --------------------
 * creates a raw section header block (SHB) and writes it into output file
 * (there will be no information inside except that it has been added by pcapfix)
 *
 * pcap_fix:  file pointer to output file
 *
 * returns:  0   success (new shb has been written to output file)
 *          -1   error (cannot write to output file)
 *
 */
int write_shb(FILE *pcap_fix);

/*
 * Function:  write_idb
 * --------------------
 * creates a raw interface description block (IDB) and writes it into output file
 * (there will be no information inside except that it has been added by pcapfix)
 *
 * pcap_fix:  file pointer to output file
 *
 * returns:  0   success (new shb has been written to output file)
 *          -1   error (cannot write to output file)
 *
 */
int write_idb(FILE *pcap_fix);

#endif
