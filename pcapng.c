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

#include "pcapfix.h"
#include "pcapng.h"

/* Header of all pcapng blocks */
struct block_header {
	u_int32_t	block_type;    /* block type */
	u_int32_t	total_length;  /* block length */
};

/* Header of all pcapng options */
struct option_header {
	u_int16_t		option_code;    /* option code - depending of block (0 - end of opts, 1 - comment are in common) */
	u_int16_t		option_length;  /* option length - length of option in bytes (will be padded to 32bit) */
};

/* Section Header Block (SHB) - ID 0x0A0D0D0A */
struct section_header_block {
	u_int32_t	byte_order_magic;   /* byte order magic - indicates swapped data */
	u_int16_t		major_version;  /* major version of pcapng (1 atm) */
	u_int16_t		minor_version;  /* minor version of pcapng (0 atm) */
	int64_t	section_length;         /* length of section - can be -1 (parsing necessary) */
};

/* Interface Description Block (IDB) - ID 0x00000001 */
struct interface_description_block {
	u_int16_t		linktype;   /* the link layer type (was -network- in classic pcap global header) */
	u_int16_t		reserved;   /* 2 bytes of reserved data */
	u_int32_t	snaplen;        /* maximum number of bytes dumped from each packet (was -snaplen- in classic pcap global header */
};

/* Packet Block (PB) - ID 0x00000002 (OBSOLETE - EPB should be used instead) */
struct packet_block {
	u_int16_t		interface_id;   /* the interface the packet was captured from - identified by interface description block in current section */
	u_int16_t		drops_count;    /* packet dropped by IF and OS since prior packet */
	u_int32_t	timestamp_high;     /* high bytes of timestamp */
	u_int32_t	timestamp_low;      /* low bytes of timestamp */
	u_int32_t	caplen;             /* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
	u_int32_t	len;                /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
};

/* Simple Packet Block (SPB) - ID 0x00000003 */
struct simple_packet_block {
	u_int32_t	len;  /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
};

/* Name Resolution Block (NRB) - ID 0x00000004 */
struct name_resolution_block {
	u_int16_t		record_type;    /* type of record (ipv4 / ipv6) */
	u_int16_t		record_length;  /* length of record value */
};

/* Interface Statistics Block - ID 0x00000005 */
struct interface_statistics_block {
	u_int32_t	interface_id;     /* the interface the stats refer to - identified by interface description block in current section */
	u_int32_t	timestamp_high;   /* high bytes of timestamp */
	u_int32_t	timestamp_low;    /* low bytes of timestamp */
};

/* Enhanced Packet Block (EPB) - ID 0x00000006 */
struct enhanced_packet_block {
	u_int32_t	interface_id;     /* the interface the packet was captured from - identified by interface description block in current section */
	u_int32_t	timestamp_high;   /* high bytes of timestamp */
	u_int32_t	timestamp_low;    /* low bytes of timestamp */
	u_int32_t	caplen;           /* length of packet in the capture file (was -incl_len- in classic pcap packet header) */
	u_int32_t	len;              /* length of packet when transmitted (was -orig_len- in classic pcap packet header) */
};

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
int fix_pcapng(FILE *pcap, FILE *pcap_fix) {
  struct block_header bh;                   /* Block Header */
  struct option_header oh;                  /* Option Header */
  struct section_header_block shb;          /* Section Header Block */
  struct interface_description_block idb;   /* Interface Description Block */
  struct packet_block pb;                   /* Packet Block */
  struct simple_packet_block spb;           /* Simple Packet Block */
  struct name_resolution_block nrb;         /* Name Resolution Block */
  struct interface_statistics_block isb;    /* Interface Statistics Block */
  struct enhanced_packet_block epb;         /* Enhanced Packet Block */

  char *data;                               /* Storage for packet data */
  char *new_block;                          /* Storage for new (maybe repaired) block to finally write into ouput file */

  // we use a buffer to cache 1mb of writing... this way writing is faster and
  // we can read and write the file at the same time
  char *writebuffer;
  uint64_t writepos = 0;

  uint64_t bytes;                           /* written bytes/blocks counter */
  uint64_t padding;                         /* calculation for padding bytes */
  uint64_t pos;                             /* current block position in input file */
  uint64_t filesize;                        /* size of input file */
  unsigned int block_pos;                   /* current position inside -new_block- to write further data to */
  unsigned int check;                       /* variable to check end of blocks sizes */
  unsigned int count;                       /* option / record counter to create EOO/EOR if necessary */
  unsigned int shb_num;                     /* number of SHB counter */
  unsigned int idb_num;                     /* number of IDB counter */
  unsigned int step;                        /* step counter for progress bar */
  unsigned int packets;

  int64_t left;                             /* bytes left to proceed until current blocks end is reached */
  int fixes;                                /* corruptions counter */
  int res;                                  /* return values */

  /* init write buffer */
  writebuffer = malloc(1024000);

  /* get file size of input file */
  fseeko(pcap, 0, SEEK_END);
  filesize = ftello(pcap);
  fseeko(pcap, 0, SEEK_SET);

  /* init variables */
  pos = 0;            /* begin file check at position 0 */
  packets = 0;
  fixes = 0;          /* no corruptions fixed yet */
  shb_num = 0;        /* no SHBs progressed yet */
  idb_num = 0;        /* no IDBs progressed yet */
  step = 1;           /* progress bar starts at 0 steps */

  /* loop every block inside pcapng file until end of file is reached */

  while (pos < filesize-sizeof(bh)) {

    /* print out progress bar if in non-verbose mode */
    if ((verbose == 0) && (5*(float)pos/(float)filesize > step)) {
      print_progress(pos, filesize);
      step++;
    }

    /* read the header of the current block */
    bytes = fread(&bh, sizeof(bh), 1, pcap);
    if (bytes != 1) return -3;

    /* check for invalid block length / file cut off */
    if (bh.total_length > filesize-pos) {
      /* block size is larger than bytes in input file */

      if (verbose >= 1) printf("[-] Block Length (%u) exceeds file size (%" PRIu64 ").\n", bh.total_length, filesize);

      /* search for next valid block */
      if (verbose >= 1) printf("[*] Trying to align next block...\n");
      res = find_valid_block(pcap, filesize);

      /* block found? */
      if (res == 0) {
        /* another valid block has been found in the file */

        if (verbose >= 1) printf("[+] GOT Next Block at Position %" PRIu64 "\n", ftello(pcap));

        /* adjust total blocks length to match next block */
        bh.total_length = ftello(pcap)-pos;

      } else {
        /* there are no more blocks inside the file */

        if (verbose >= 1) printf("[*] No more valid Blocks found inside file! (maybe it was the last one)\n");

        /* adjust total blocks length to end of file */
        bh.total_length = filesize-pos;

      }

      if (verbose >= 1) printf("[*] Assuming this blocks size as %u bytes.\n", bh.total_length);
      else printf("[-] Invalid Block size => CORRECTED.\n");

      /* reset input file pointer behind block header */
      fseeko(pcap, pos+sizeof(struct block_header), SEEK_SET);

      /* increase corruptions counter */
      fixes++;
    }

    /* how many bytes are left until the final block size (end of block) is reached */
    left = bh.total_length-sizeof(bh)-sizeof(check);

    /* allocate memory for the new block - that will be written to repaired output file finally */
    new_block = malloc(bh.total_length);

    /* copy the current blocks header into repaired block */
    memcpy(new_block, &bh, 8);
    block_pos = 8;

    /* what is the type of block at current position ? */
    switch (bh.block_type) {

      /* Section Header Block */
      case TYPE_SHB:
        if (verbose >= 1) printf("[*] FOUND: Section Header Block at position %" PRIu64 " (%u bytes)\n", pos, bh.total_length);

        /* read section header block into struct */
        bytes = fread(&shb, sizeof(shb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(shb);

        /* check for pcap's magic bytes () */
        if (shb.byte_order_magic == BYTE_ORDER_MAGIC) {
          if (verbose >= 1) printf("[+] Byte Order Magic: 0x%x\n", shb.byte_order_magic);
        } else if (shb.byte_order_magic == htonl(BYTE_ORDER_MAGIC)) {
          if (verbose >= 1) printf("[+] Byte Order Magic: 0x%x (SWAPPED)\n", shb.byte_order_magic);
          swapped = 1;
        } else {
          printf("[-] Unknown Byte Order Magic: 0x%x ==> CORRECTED.\n", shb.byte_order_magic);
          shb.byte_order_magic = BYTE_ORDER_MAGIC;
          fixes++;
        }

        /* check for major version number (2) */
        if (conshort(shb.major_version) == 1) {	/* current major version is 2 */
          if (verbose >= 1) printf("[+] Major version number: %hu\n", conshort(shb.major_version));
        } else {
          printf("[-] Major version number: %hu ==> CORRECTED.\n", conshort(shb.major_version));
          shb.major_version = conshort(1);
          fixes++;
        }

        /* check for minor version number */
        if (conshort(shb.minor_version) == 0) {	/* current minor version is 4 */
          if (verbose >= 1) printf("[+] Minor version number: %hu\n", conshort(shb.minor_version));
        } else {
          printf("[-] Minor version number: %hu ==> CORRECTED.\n", conshort(shb.minor_version));
          shb.minor_version = conshort(0);
          fixes++;
        }

        /* section length */
        if (shb.section_length == -1) {
          if (verbose >= 1) printf("[*] Section length: %" PRId64 "\n", shb.section_length);

        } else {
          if (verbose >= 1) printf("[*] Section length: %" PRId64 " ==> SETTING TO -1\n", shb.section_length);
          shb.section_length = -1;
        }

        /* copy section header block into repaired block */
        memcpy(new_block+block_pos, &shb, sizeof(shb));
        block_pos += sizeof(shb);

        /* options */
        count = 0 ;
        while (left > 0) {
          /* read option header into struct */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get ? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Hardware Information */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Hardware... (%u bytes)\n", oh.option_length);
              break;
            /* Operating System Information */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Operating System... (%u bytes)\n", oh.option_length);
              break;
            /* User Application Information */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: Userappl... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x04) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* check oversize */
          if (padding > (unsigned)left) {
            printf("[-] Option size (%" PRIu64 ") exceeds remaining block space (%" PRId64 "). ==> SKIPPING OPTION.\n", padding, left);
            fixes++;

            /* because this block oversizes, there should not be any further option */

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* copy option header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* read data of current option */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* write option data to repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;

        }
        break;

      /* Packet Block */
      case TYPE_PB:
	packets++;

        /* check oversize */
        if (sizeof(pb) > (unsigned)left) {
          printf("[-] Packet #%u exceeds size of block header (%" PRIu64 " > %" PRId64 ") ==> SKIPPING.\n", packets, sizeof(pb), left);
          /* set to "invalid block" */
          bh.block_type = -1;
          break;
        }

        /* check for the mandatory SBH that MUST be before any packet! */
        if (shb_num == 0) {
          /* no SBH before this packet, we NEED to create one */
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          shb_num++;
          fixes++;
        }

        if (verbose >= 1) printf("[*] FOUND Packet #%u: Packet Block at position %" PRIu64 " (%u bytes)\n", packets, pos, bh.total_length);

        /* read packet block into struct */
        bytes = fread(&pb, sizeof(pb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(pb);

        /* pre-check too large interface number (1024) */
        if (pb.interface_id > 1024) {
          /* interface id is unusal high --> this field is probably corrupted */
          printf("[-] Probably corrupted Interface ID #%u (too high?) ==> CORRECTED.\n", pb.interface_id);
          pb.interface_id = 1;
          fixes++;
        }

        /* check for the mandatory IDB that MUST identify every packets interface_id */
        while (pb.interface_id >= idb_num) {
          /* no IDB is identifying this packet, we need to create one - until the ID has been reached */
          printf("[-] Missing IDB for Interface #%u ==> CREATING (#%u).\n", pb.interface_id, idb_num);
          write_idb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          idb_num++;
          fixes++;
        }

        /* copy packet block into repaired block */
        memcpy(new_block+block_pos, &pb, sizeof(pb));
        block_pos += sizeof(pb);

        /* check for oversized caplen */
        if (pb.caplen > (unsigned)left) {
          printf("[-] Capture length (%u) exceeds block size (%" PRId64 ") ==> CORRECTED.\n", pb.caplen, left);
          pb.caplen = left;
        }

        /* calculate padding for packet data */
        padding = pb.caplen;
        if (pb.caplen % 4 != 0) padding += (4 - pb.caplen % 4);

        /* read packet data from input file */
        data = malloc(padding);
        bytes = fread(data, padding, 1, pcap);
        left -= padding;

        /* copy packet data into repaired block */
        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        /* clean up memory */
        free(data);

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get ? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Link Layer Flags */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Link Layer Flags... (%u bytes)\n", oh.option_length);
              break;
            /* Packet Hash */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Packet Hash... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x03) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* check oversize */
          if (padding > (unsigned)left) {
            printf("[-] Option size (%" PRIu64 ") exceeds remaining block space (%" PRId64 "). ==> SKIPPING OPTION.\n", padding, left);
            fixes++;

            /* because this block oversizes, there should not be any further option */

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* copy options header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* read data of current option */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option data to repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

      /* Simple Packet Block */
      case TYPE_SPB:
	packets++;

        /* check for the mandatory SBH that MUST be before any packet! */
        if (shb_num == 0) {
          /* no SBH before this packet, we NEED to create one */
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          shb_num++;
          fixes++;
        }

        if (verbose >= 1) printf("[*] FOUND Packet #%u: Simple Packet Block at position %" PRIu64 " (%u bytes)\n", packets, pos, bh.total_length);

        /* read simple packet block */
        bytes = fread(&spb, sizeof(spb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(spb);

        /* output data */
        if (verbose >= 1) printf("[*] SPB original packet length: %u bytes\n", spb.len);

        /* copy simple packet block into repaired file */
        memcpy(new_block+block_pos, &spb, sizeof(spb));
        block_pos += sizeof(spb);

        /* calculate padding for packet data */
        /* spb.len is NOT the length of packet inside file (origlen != caplen); we need to calculate caplen using block length (left) */
        /* decrease by two to avoid oversize padding */
        padding = left-2;
        if (padding % 4 != 0) padding += (4 - left % 4);

        /* read packet data from input file */
        data = malloc(padding);
        bytes = fread(data, padding, 1, pcap);
        left -= padding;

        /* copy packet data into repaired block */
        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        /* clean up memory */
        free(data);

        break;

      /* Interface Description Block */
      case TYPE_IDB:

        /* check for the mandatory SBH that MUST be before any packet! */
        if (shb_num == 0) {
          /* no SBH before this packet, we NEED to create one */
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          shb_num++;
          fixes++;
        }

        if (verbose >= 1) printf("[*] FOUND: Interface Description Block (%u bytes)\n", bh.total_length);

        /* read interface description block */
        bytes = fread(&idb, sizeof(idb), 1, pcap);	/* read first bytes of input file into struct */
        if (bytes != 1) return -3;
        left -= sizeof(idb);

        /* copy interface description block into repaired block */
        memcpy(new_block+block_pos, &idb, sizeof(idb));
        block_pos += sizeof(idb);

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Interface Name */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Interface Name... (%u bytes)\n", oh.option_length);
              break;
            /* Interface Description */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Interface Description... (%u bytes)\n", oh.option_length);
              break;
            /* IPv4 Address of Interface */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: IPv4 Address... (%u bytes)\n", oh.option_length);
              break;
            /* IPv6 Address of Interface */
            case 0x05:
              if (verbose >= 2) printf("[+] OPTION: IPv6 Address... (%u bytes)\n", oh.option_length);
              break;
            /* MAC Address of Interface */
            case 0x06:
              if (verbose >= 2) printf("[+] OPTION: MAC Address... (%u bytes)\n", oh.option_length);
              break;
            /* EUI Address of Interface */
            case 0x07:
              if (verbose >= 2) printf("[+] OPTION: EUI Address... (%u bytes)\n", oh.option_length);
              break;
            /* Interface Speed */
            case 0x08:
              if (verbose >= 2) printf("[+] OPTION: Interface Speed... (%u bytes)\n", oh.option_length);
              break;
            /* Resolution of Timestamps */
            case 0x09:
              if (verbose >= 2) printf("[+] OPTION: Resolution of Timestamps... (%u bytes)\n", oh.option_length);
              break;
            /* Timezone */
            case 0x0a:
              if (verbose >= 2) printf("[+] OPTION: Timezone... (%u bytes)\n", oh.option_length);
              break;
            /* Filter expression used */
            case 0x0b:
              if (verbose >= 2) printf("[+] OPTION: Filter expression... (%u bytes)\n",  oh.option_length);
              break;
            /* Operating System */
            case 0x0c:
              if (verbose >= 2) printf("[+] OPTION: Operating System... (%u bytes)\n",  oh.option_length);
              break;
            /* Frame Check Sequence Length */
            case 0x0d:
              if (verbose >= 2) printf("[+] OPTION: Frame Check Sequence Length... (%u bytes)\n",  oh.option_length);
              break;
            /* Timestamp Offset */
            case 0x0e:
              if (verbose >= 2) printf("[+] OPTION: Timestamp Offset... (%u bytes)\n",  oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x0e) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* check oversize */
          if (padding > (unsigned)left) {
            printf("[-] Option size (%" PRIu64 ") exceeds remaining block space (%" PRId64 "). ==> SKIPPING OPTION.\n", padding, left);
            fixes++;

            /* because this block oversizes, there should not be any further option */

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* copy options header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further*/
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* read option data */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* write option data into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

      /* Name Resolution Block */
      case TYPE_NRB:

        /* check for the mandatory SBH that MUST be before any packet! */
        if (shb_num == 0) {
          /* no SBH before this packet, we NEED to create one */
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          shb_num++;
          fixes++;
        }

        if (verbose >= 1) printf("[*] FOUND: Name Resolution Block at position %" PRIu64 " (%u bytes)\n", pos, bh.total_length);

        /* process records */
        count = 0;
        while (left > 0) {

          /* read name resolution block */
          bytes = fread(&nrb, sizeof(nrb), 1, pcap);	/* read first bytes of input file into struct */
          if (bytes != 1) return -3;
          left -= sizeof(nrb);

          /* which type of record did we get? */
          switch (nrb.record_type) {
            /* End of Records */
            case 0x00:
              if (verbose >= 2) printf("[+] RECORD: End of Records... (%u bytes)\n", nrb.record_length);
              break;
            /* IPv4 Record */
            case 0x01:
              if (verbose >= 2) printf("[+] RECORD: IPv4 Record... (%u bytes)\n", nrb.record_length);
              break;
            /* IPv6 Record */
            case 0x02:
              if (verbose >= 2) printf("[+] RECORD: IPv6 Record... (%u bytes)\n", nrb.record_length);
              break;
          }

          /* Invalid Record? */
          if (nrb.record_type > 0x02) {
            printf("[-] Unknown record type: 0x%04x (%u bytes) ==> SKIPPING.\n", nrb.record_type, nrb.record_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first record we check? */
            if (count == 0) {
              /* there are NO records inside this block; skipping EOR record */
              if (verbose >= 1) printf("[*] No Records inside -> no need for End of Records...\n");
              break;
            }

            /* there have been other records before this corruption, we need EOR record */

            if (verbose >= 1) printf("[*] %u Records inside -> Finishing with End of Records...\n", count);

            /* adjust option header to end of options */
            nrb.record_type = 0x00;
            nrb.record_length = 0x00;
          }

          /* record is valid */

          /* write name resolution block into repaired block */
          memcpy(new_block+block_pos, &nrb, sizeof(nrb));
          block_pos += sizeof(nrb);

          /* end of records? -> do not write any further */
          if (nrb.record_type == 0x00 && nrb.record_length == 0x00) break;

          /* calculate padding for current record value */
          padding = nrb.record_length;
          if (nrb.record_length % 4 != 0) padding += (4 - nrb.record_length % 4);

          /* read record value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy record value into repaired buffer */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;

        }

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* DNS Server Name */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: DNS Server... (%u bytes)\n", oh.option_length);
              break;
            /* DNS Server IPv4 Address */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: IPv4 Address of DNS Server... (%u bytes)\n", oh.option_length);
              break;
            /* DNS Server IPv6 Address */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: IPv6 Address of DNS Server... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x04) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* check oversize */
          if (padding > (unsigned)left) {
            printf("[-] Option size (%" PRIu64 ") exceeds remaining block space (%" PRId64 "). ==> SKIPPING OPTION.\n", padding, left);
            fixes++;

            /* because this block oversizes, there should not be any further option */

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* copy option header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* read option value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option value into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;

        }
        break;

      /* Interface Statistics Block */
      case TYPE_ISB:

        /* check for the mandatory SBH that MUST be before any packet! */
        if (shb_num == 0) {
          /* no SBH before this packet, we NEED to create one */
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          shb_num++;
          fixes++;
        }

        if (verbose >= 1) printf("[*] FOUND: Interface Statistics Block at position %" PRIu64 " (%u bytes)\n", pos, bh.total_length);

        /* read interface statistics block */
        bytes = fread(&isb, sizeof(isb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(isb);

        /* copy interface statistics block into repaired block */
        memcpy(new_block+block_pos, &isb, sizeof(isb));
        block_pos += sizeof(isb);

        /* options */
        count = 0;
        while (left > 0) {

          /* read options header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Capture Start Time */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Capture Start Time... (%u bytes)\n", oh.option_length);
              break;
            /* Capture End Time */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Capture End Time... (%u bytes)\n", oh.option_length);
              break;
            /* Packets received */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: Packets received... (%u bytes)\n", oh.option_length);
              break;
            /* Packets dropped */
            case 0x05:
              if (verbose >= 2) printf("[+] OPTION: Packets dropped... (%u bytes)\n", oh.option_length);
              break;
            /* Packets accepted by Filter */
            case 0x06:
              if (verbose >= 2) printf("[+] OPTION: Filter packets accepted... (%u bytes)\n", oh.option_length);
              break;
            /* Packets dropped by Operating System */
            case 0x07:
              if (verbose >= 2) printf("[+] OPTION: Packets dropped by OS... (%u bytes)\n", oh.option_length);
              break;
            /* Packets delivered to user */
            case 0x08:
              if (verbose >= 2) printf("[+] OPTION: Packets delivered to user... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x08) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* check oversize */
          if (padding > (unsigned)left) {
            printf("[-] Option size (%" PRIu64 ") exceeds remaining block space (%" PRId64 "). ==> SKIPPING OPTION.\n", padding, left);
            fixes++;

            /* because this block oversizes, there should not be any further option */

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* copy options header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* read option value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option value into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

      /* Enhanced Packet Block */
      case TYPE_EPB:
	packets++;

        /* check for the mandatory SBH that MUST be before any packet! */
        if (shb_num == 0) {
          /* no SBH before this packet, we NEED to create one */
          printf("[-] No Section Block header found ==> CREATING.\n");
          write_shb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          shb_num++;
          fixes++;
        }

        if (verbose >= 1) printf("[*] FOUND Packet #%u: Enhanced Packet Block at position %" PRIu64 " (%u bytes)\n", packets, pos, bh.total_length);

        /* read enhanced packet block */
        bytes = fread(&epb, sizeof(epb), 1, pcap);
        if (bytes != 1) return -3;
        left -= sizeof(epb);

        /* pre-check too large interface number (1024) */
        if (epb.interface_id > 1024) {
          /* interface id is unusal high --> this field is probably corrupted */
          printf("[-] Probably corrupted Interface ID #%u (too high?) ==> CORRECTED.\n", epb.interface_id);
          epb.interface_id = 1;
          fixes++;
        }

        /* check for the mandatory IDB that MUST identify every packets interface_id */
        while (epb.interface_id >= idb_num) {
          /* no IDB identifying this packet, we need to create one - until the ID is reached */
          printf("[-] Missing IDB for Interface #%u ==> CREATING (#%u).\n", epb.interface_id, idb_num);
          write_idb(pcap_fix, writebuffer, &writepos);

          /* increase counters */
          idb_num++;
          fixes++;
        }

        /* check if packet capture size exceeds packet length */
        if (epb.caplen > epb.len) {
          printf("[-] Enhanced packet data exceeds packet capture length (%u > %u) ==> CORRECTED.\n", epb.caplen, epb.len);
          epb.caplen = epb.len;

          fixes++;
        }

        /* check if packet capture size exceeds packet length */
        if (epb.caplen > left) {
          printf("[-] Enhanced packet data exceeds total packet size (%u > %" PRIu64 ") ==> CORRECTED.\n", epb.caplen, left);
          epb.caplen = left;

          fixes++;
        }

        /* copy enhanced packet block into repaired buffer */
        memcpy(new_block+block_pos, &epb, sizeof(epb));
        block_pos += sizeof(epb);

        /* check for zero capture length */
        if (epb.caplen != 0) {

          /* calculate padding for packet data */
          padding = epb.caplen;
          if (epb.caplen % 4 != 0) padding += (4 - epb.caplen % 4);

          /* read packet data from input file */
          data = malloc(padding);

          bytes = fread(data, padding, 1, pcap);
          if (bytes != 1) return -3;
          left -= padding;

          /* copy packet data into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);
        }

        /* options */
        count = 0;
        while (left > 0) {

          /* read option header */
          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -3;
          left -= sizeof(oh);

          /* which option did we get? */
          switch (oh.option_code) {
            /* End of Options */
            case 0x00:
              if (verbose >= 2) printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            /* Comment Option */
            case 0x01:
              if (verbose >= 2) printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            /* Link Layer Flags */
            case 0x02:
              if (verbose >= 2) printf("[+] OPTION: Link Layer Flags... (%u bytes)\n", oh.option_length);
              break;
            /* Packet Hash */
            case 0x03:
              if (verbose >= 2) printf("[+] OPTION: Packet Hash... (%u bytes)\n", oh.option_length);
              break;
            /* Dropped Packets */
            case 0x04:
              if (verbose >= 2) printf("[+] OPTION: Dropped Packets Counter... (%u bytes)\n", oh.option_length);
              break;
          }

          /* Invalid Option? */
          if (oh.option_code > 0x04) {
            printf("[-] Unknown option code: 0x%04x (%u bytes) ==> SKIPPING.\n", oh.option_code, oh.option_length);

            /* increase corruptions counter */
            fixes++;

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* option is valid */

          /* calculate padding for current option value */
          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);

          /* check oversize */
          if (padding > (unsigned)left) {
            printf("[-] Option size (%" PRIu64 ") exceeds remaining block space (%" PRId64 "). ==> SKIPPING OPTION.\n", padding, left);
            fixes++;

            /* because this block oversizes, there should not be any further option */

            /* is this the first option we check? */
            if (count == 0) {
              /* there are NO options inside this block; skipping EOO option */
              if (verbose >= 1) printf("[*] No Options inside -> no need for End of Options...\n");
              break;
            }

            /* there have been other options before this corruption, we need EOO option */

            if (verbose >= 1) printf("[*] %u Options inside -> Finishing with End of Options...\n", count);

            /* adjust option header to end of options */
            oh.option_code = 0x00;
            oh.option_length = 0x00;
          }

          /* copy option header into repaired block */
          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          /* end of options? -> do not write any further */
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          /* read option value from input file */
          data = malloc(padding);
          bytes = fread(data, padding, 1, pcap);
          left -= padding;

          /* copy option value into repaired block */
          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          /* clean up memory */
          free(data);

          count++;
        }
        break;

    } /* end of switch - block header */

    /* check for invalid block header type */
    if ((bh.block_type != TYPE_SHB && bh.block_type > TYPE_EPB) || bh.block_type == 0x00000000) {
      /* this block type is ńot know */

      printf("[-] Unknown block type!: 0x%08x ==> SKIPPING.\n", bh.block_type);

      /* increase corruption counter */
      fixes++;

    } else {
      /* this block type is valid */

      /* write sizes of block header to correct positions */
      block_pos += sizeof(bh.total_length);
      memcpy(new_block+4, &block_pos, sizeof(bh.total_length));
      memcpy(new_block+block_pos-4, &block_pos, sizeof(bh.total_length));

      /* check wether the real size matches the size formerly specified in block header */
      if (block_pos != bh.total_length) {

        /* specified size in block header does NOT match the real block size (maybe due to fixed corruptions) */
        if (verbose >= 1) printf("[*] Block size adjusted (%u --> %u).\n", bh.total_length, block_pos);

        /* increase corruption counter */
        fixes++;
      }

      /* write repaired block into output file */
      if (verbose >= 2) printf("[*] Writing block to buffer (%u bytes).\n", block_pos);

      // do we need to write the buffer to the file?
      if (writepos + block_pos > 1024000) {
        bytes = fwrite(writebuffer, writepos, 1, pcap_fix);
        writepos = 0;
      }

      // put new bytes into write buffer
      memcpy(writebuffer+writepos, new_block, block_pos);
      writepos += block_pos;

      free(new_block);

      /* increate SHB / IDB counters */
      if (bh.block_type == TYPE_SHB) shb_num++;
      if (bh.block_type == TYPE_IDB) idb_num++;
    }

    /* did we process all bytes of the block - given by block length */
    if (left == 0) {
      /* all bytes processed */
      if (verbose >= 2) printf("[+] End of Block reached... byte counter is correct!\n");
    } else {
      /* we did not read until end of block - maybe due to option skipping */
      if (verbose >= 1) printf("[-] Did not hit the end of the block! (%" PRId64 " bytes left)\n", left);
    }

    /* check for correct block end (block size) */
    bytes = fread(&check, sizeof(check), 1, pcap);

    /* read the second block length field and check first block size field */
    if (check == bh.total_length) {
      /* first and second block header size do match */
      if (verbose >= 2) printf("[+] Block size matches (%u)!\n", check);
    } else {
      /* block header sizes do not match! */

      printf("[-] Block size mismatch (0x%08x != 0x%08x) ==> CORRECTED.\n", check, bh.total_length);
      fixes++;

      /* we did not hit the end of block - need to search for next one */

      /* remeber current position to know how much bytes have been skipped */
      bytes = ftello(pcap);

      if (bytes != filesize) {

        /* search for next valid block */
        if (verbose >= 1) printf("[*] Trying to align next block...\n");
        res = find_valid_block(pcap, filesize);

        /* output information about overlapped/skipped bytes */
        if (ftello(pcap) > (unsigned)bytes) printf("[-] Found %" PRId64 " bytes of unknown data ==> SKIPPING.\n", ftello(pcap)-bytes);
        else printf("[-] Packet overlapps with %" PRId64 " bytes ==> CORRECTED.\n", bytes-ftello(pcap));

        /* increase corruption counter */
        fixes++;

        /* did we find a next block at all? */
        if (res == -1) {
          /* EOF reached while searching --> no more blocks */
          if (verbose >= 1) printf("[*] No more valid blocks found inside file! (maybe it was the last one)\n");
          break;
        }

      }

    }

    /* set positon of next block */
    pos = ftello(pcap);

  }

  // write remaining data into buffer
  bytes = fwrite(writebuffer, writepos, 1, pcap_fix);
  writepos = 0;

  /* FILE HAS BEEN COMPLETELY CHECKED */

  /* did we write any SHB blocks at all?
   * if not this seems to be no pcapng file! */
  if (shb_num == 0) return(-1);

  /* everything successfull - return number of fixes */
  return(fixes);
}

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
int find_valid_block(FILE *pcap, uint64_t filesize) {
  uint64_t i;
  unsigned int bytes;
  unsigned int check;                       /* variable to check end of blocks sizes */
  struct block_header bh;                   /* block header */
  struct packet_block pb;                   /* Packet Block */
  struct name_resolution_block nrb;         /* Name Resolution Block */
  struct simple_packet_block spb;           /* Simple Packet Block */

  /* bytewise processing of input file */
  for (i=ftello(pcap)-4; i<filesize; i++) {
    /* set file pointer to loop position */
    fseeko(pcap, i, SEEK_SET);

    /* read possbile block header */
    bytes = fread(&bh, sizeof(bh), 1, pcap);
    if (bytes != 1) return(-1);

    /* check if:
     * - block header is greater than minimal size (12)
     * - block header type has a valid ID */
    if (bh.total_length >= 12 && bh.block_type >= TYPE_IDB && bh.block_type <= TYPE_EPB) {
      /* block header might be valid */

      /* perform some block specific checks */

      /* Packet Block Checks:
       * - interface id <= 1024 */
      if (bh.block_type == TYPE_PB) {
        bytes = fread(&pb, sizeof(pb), 1, pcap);
        if (bytes != 1) return(-1);

        /* interface id check */
        if (pb.interface_id > 1024) continue;
      }

      /* Simple Packet Block Checks:
       * - max size <= MAX_SNAPLEN */
      if (bh.block_type == TYPE_SPB) {
        /* max size check */
        if (bh.total_length > PCAPNG_MAX_SNAPLEN) continue;

        bytes = fread(&spb, sizeof(spb), 1, pcap);
        if (bytes != 1) return(-1);

        /* check original packet lengths <= MAX_SNAPLEN */
        if (spb.len > PCAPNG_MAX_SNAPLEN) continue;
      }

      /* Name Resolution Block Checks:
       * - min size >= 16
         - record size < block length
         - record type ipv4,ipv6 or eeo */
      if (bh.block_type == TYPE_NRB) {
        bytes = fread(&nrb, sizeof(nrb), 1, pcap);
        if (bytes != 1) return(-1);

        /* max length check */
        if (bh.total_length < 16) continue;

        /* record length check */
        if (nrb.record_length > bh.total_length) continue;

        /* record type check (max is 0x02) */
        if (nrb.record_type > 0x02) continue;
      }

      /* check if the second size value is valid too */
      fseeko(pcap, i+bh.total_length-4, SEEK_SET);
      bytes = fread(&check, sizeof(check), 1, pcap);
      if (check == bh.total_length) {
        /* also the second block size value is correct! */

        if (verbose >= 1) printf("[+] FOUND: Block (Type: 0x%08x) at Position %" PRIu64 "\n", bh.block_type, i);

        /* set pointer to next block position */
        fseeko(pcap, i, SEEK_SET);
        return(0);
      }
    }
  }

  /* finished loop without success -> no more blocks inside file */
  return(-1);
}

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
int write_shb(FILE *pcap_fix, char* writebuffer, uint64_t* writepos) {
  struct block_header bh;           /* block header */
  struct section_header_block shb;  /* section header block */
  struct option_header oh;          /* options header */

  uint64_t bytes;              /* written bytes/blocks counter */
  unsigned int size = 0;            /* size of whole block */
  unsigned int padding;             /* padding of data */
  unsigned char *data;              /* data buffer */

  /* this comment will be added to options to indicate that block has been arbitrary added
   * we pad string with max of 4 zero bytes to ahjust memory alignment */
  char comment[] = "Added by pcapfix.\x00\x00\x00\x00";

  /* set block type to section header block */
  bh.block_type = TYPE_SHB;

  /* increase total size by block header size */
  size += sizeof(struct block_header);

  /* fill section header block with valid values */
  shb.byte_order_magic = BYTE_ORDER_MAGIC;    /* we use a non-swapped BYTE_ORDER */
  shb.major_version = 1;                      /* major pcapng version is 1 */
  shb.minor_version = 0;                      /* minor pcapng version is 0 */

  /* increase total size by section header block size */
  size += sizeof(struct section_header_block);

  /* prepare options header */
  oh.option_code = 0x01;                /* this is a comment option */
  oh.option_length = strlen(comment);   /* size equals the definied comment */

  /* increase total size by options header size */
  size += sizeof(struct option_header);

  /* calculate padding for this options data */
  padding = oh.option_length;
  if (oh.option_length % 4 != 0) padding += (4 - oh.option_length % 4);

  /* increase total size by options data size (including padding) */
  size += padding;

  /* increase size by 4 (end of options) */
  size += 4;

  /* increase size by 4 (second block_length field) */
  size += 4;

  /* set final size into block header field */
  bh.total_length = size;

  /* reserve memory for whole section header block (including block header) */
  data = malloc(size);

  /* store block header into buffer */
  memcpy(data, &bh, sizeof(bh));
  /* store section header block (header) into buffer */
  memcpy(data+sizeof(bh), &shb, sizeof(shb));
  /* store options header into buffer */
  memcpy(data+sizeof(bh)+sizeof(shb), &oh, sizeof(oh));
  /* store option data into buffer */
  memcpy(data+sizeof(bh)+sizeof(shb)+sizeof(oh), comment, padding);
  /* store end of options into buffer */
  memset(data+sizeof(bh)+sizeof(shb)+sizeof(oh)+padding, 0, 4);
  /* store second block_length field into buffer */
  memcpy(data+sizeof(bh)+sizeof(shb)+sizeof(oh)+padding+4, &size, sizeof(size));

  /* write whole buffer (new SHB) into buffer */

  // check if there is enough space in buffer
  if (*writepos + size > 1024000) {
    bytes = fwrite(writebuffer, *writepos, 1, pcap_fix);
    if (bytes != 1) return(-1);
    *writepos = 0;
  }

  // put new bytes into write buffer
  memcpy(writebuffer+(*writepos), data, size);
  *writepos += size;

  /* clean up memory */
  free(data);

  /* success */
  return(0);
}

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
int write_idb(FILE *pcap_fix, char* writebuffer, uint64_t* writepos) {
  struct block_header bh;                   /* block header */
  struct interface_description_block idb;   /* interface description block */
  struct option_header oh;                  /* options header */

  uint64_t bytes;              /* written bytes/blocks counter */
  unsigned int size = 0;            /* size of whole block */
  unsigned int padding;             /* padding of data */
  unsigned char *data;              /* data buffer */

  /* this comment will be added to options to indicate that block has been arbitrary added
   * we pad string with max of 4 zero bytes to ahjust memory alignment */
  char comment[] = "Added by pcapfix.\x00\x00\x00\x00";

  /* set block type to interface description block */
  bh.block_type = TYPE_IDB;

  /* increase total size by block header size */
  size += sizeof(struct block_header);

  /* fill interface description block with valid values */

  /* data link type */
  if (data_link_type != -1) {
    idb.linktype = data_link_type;  /* link layter type as set by user */
  } else {
    idb.linktype = 1;               /* link layter type to default (1 == ETHERNET) */
  }

  /* reserved is always zero */
  idb.reserved = 0;

  /* we set snaplen to maximum */
  idb.snaplen = PCAPNG_MAX_SNAPLEN;

  /* increase total size by interface desciption block (header) */
  size += sizeof(struct interface_description_block);

  /* prepare options header */
  oh.option_code = 0x01;                /* this is a comment option */
  oh.option_length = strlen(comment);   /* size equals the definied comment */

  /* increase total size by options header size */
  size += sizeof(struct option_header);

  /* calculate padding for this options data */
  padding = oh.option_length;
  if (oh.option_length % 4 != 0) padding += (4 - oh.option_length % 4);

  /* increase total size by options data size (including padding) */
  size += padding;

  /* increase size by 4 (end of options) */
  size += 4;

  /* increase size by 4 (second block_length field) */
  size += 4;

  /* set final size into block header field */
  bh.total_length = size;

  /* reserve memory for whole section header block (including block header) */
  data = malloc(size);

  /* store block header into buffer */
  memcpy(data, &bh, sizeof(bh));
  /* store interface description block (header) into buffer */
  memcpy(data+sizeof(bh), &idb, sizeof(idb));
  /* store options header into buffer */
  memcpy(data+sizeof(bh)+sizeof(idb), &oh, sizeof(oh));
  /* store option data into buffer */
  memcpy(data+sizeof(bh)+sizeof(idb)+sizeof(oh), comment, padding);
  /* store end of options into buffer */
  memset(data+sizeof(bh)+sizeof(idb)+sizeof(oh)+padding, 0, 4);
  /* store second block_length field into buffer */
  memcpy(data+sizeof(bh)+sizeof(idb)+sizeof(oh)+padding+4, &size, sizeof(size));

  /* write whole buffer (new SHB) into output file */

  // check if there is enough space in buffer
  if (*writepos + size > 1024000) {
    bytes = fwrite(writebuffer, *writepos, 1, pcap_fix);
    if (bytes != 1) return(-1);
    *writepos = 0;
  }

  // put new bytes into write buffer
  memcpy(writebuffer+(*writepos), data, size);
  *writepos += size;

  /* clean up memory */
  free(data);

  /* success */
  return(0);
}
