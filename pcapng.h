/*******************************************************************************
 *
 * Copyright (c) 2012-2019 Robert Krause (ruport@f00l.de)
 *
 * This file is part of Pcapfix.
 *
 * Pcapfix is free software: you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or any later version.
 *
 * Pcapfix is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * Pcapfix. If not, see http://www.gnu.org/licenses/.
 *
 ******************************************************************************/

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

#define PCAPNG_MAX_SNAPLEN 262144   /* maximum snap length */

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
int find_valid_block(FILE *pcap, uint64_t filesize);

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
int write_shb(FILE *pcap_fix, char* writebuffer, uint64_t* writepos);

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
int write_idb(FILE *pcap_fix, char* writebuffer, uint64_t* writepos);

#endif
