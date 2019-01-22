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

#ifndef PF_PCAP_KUZNET
#define PF_PCAP_KUZNET

#define PCAP_EXT_MAGIC 0xa1b2cd34               /* the magic of the extended pcap global header (non swapped) */
#define PCAP_EXT_MAGIC_SWAPPED 0x34cdb2a1	/* the magic of the extended pcap global header (swapped) */

#include "pcap.h"

/* KUZNETZOV Packet Header
   http://tcpreplay.synfin.net/doxygen_yhsiam/tcpcapinfo_8c-source.html - is there an official documentation? */
struct packet_hdr_kuznet_s {
  u_int32_t ts_sec;         /* timestamp seconds */
  u_int32_t ts_usec;        /* timestamp microseconds */
  u_int32_t incl_len;       /* number of octets of packet saved in file */
  u_int32_t orig_len;       /* actual length of packet */
  int32_t index;
  u_int16_t protocol;
  u_int8_t pkt_type;
};

/*
 * Function:  is_plausible
 * -----------------------
 * check if the pcap packet header could be a plausible one by satisfying those conditions:
 * - packet size >= 16 bytes AND <= MAX_SNAPLEN bytes (included length AND original length) (conditions 1,2,3,4)
 * - included length <= original lenth (condition 5)
 * - packet timestamp is NOT older OR younger than the prior packets timestamp -+ one day (conditions 6,7)
 * - usec (microseconds) field <= 1000000 (conditions 8)
 * - usec (nanoseconds) field <= 1000000000 (conditions 9)
 *
 * global_hdr: the filled pcap header to check for snaplen
 * hdr:        the filled packet header struct to check for plausibility
 * prior_ts:   the prior packets timestamp (seconds) to check for time relation (condition 6,7)
 *
 * returns:  0   success
 *          -X   error (condition X failed)
 *
 */
int is_plausible_kuznet(struct global_hdr_s global_hdr, struct packet_hdr_s hdr, unsigned int prior_ts);

/*
 * Function:  check_header
 * -----------------------
 * this function takes a buffer and brute forces some possible ascii-corrupted bytes versus plausibility checks
 *
 * buffer:     the buffer that might contain the possible pcap packet header
 * size:       the size of the buffer (double pcap packet header size is a good choice)
 * priot_ts:   the prior packets timestamp (to check for plausibility)
 * global_hdr: the pointer to the pcap buffer
 * hdr:        the pointer to the packet header buffer (we use this to return the repaired header)
 *
 * returns: >=0   success (return value contains number of ascii corrupted bytes in hdr (we need this data to align the beginning of the packet body later)
 *           -1   error (no valid pcap header found inside buffer)
 *
 */
int check_header_kuznetzov(char *buffer, unsigned int size, unsigned int prior_ts, struct global_hdr_s *global_hdr, struct packet_hdr_kuznet_s *hdr);

/*
 * Function:  fix_pcap
 * -------------------
 * tries to fix a classic pcap file
 *
 * pcap:      file pointer to input file
 * pcap_fix:  file pointer to output file
 *
 * returns: >0   success (number of corruptions fixed)
 *           0   success (nothing to fix)
 *          -1   error (not a pcap file)
 *          -2   error (unable to repair)
 *          -3   error (EOF reached while reading input file)
 *
 */
int fix_pcap_kuznetzov(FILE *pcap, FILE *pcap_fix);

/*
 * Function:  fix_pcap_packets
 * ---------------------------
 * tries to fix pcap packets inside a pcap file
 *
 * pcap:        file pointer to input file
 * pcap_fix:    file pointer to output file
 * filesize:    input file size in bytes
 * global_hdr:  global header struct
 * hdr_integ:   global header integrity counter
 * writebuffer: buffer to write pcap packets into
 * writepos:    position in buffer to write next packet to
 *
 * returns: >0   success (number of corruptions fixed)
 *           0   success (nothing to fix)
 *          -1   error (not a pcap file)
 *          -2   error (unable to repair)
 *          -3   error (EOF reached while reading input file)
 *
 */
int fix_pcap_packets_kuznetzov(FILE *pcap, FILE *pcap_fix, uint64_t filesize, struct global_hdr_s global_hdr, unsigned short hdr_integ, char *writebuffer, uint64_t writepos);

#endif
