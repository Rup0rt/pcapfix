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
#include "pcap_kuznet.h"

/*
 * Function:  is_plausible
 * -----------------------
 * check if the pcap packet header could be a plausible one by satisfying those conditions:
 * - packet size >= 16 bytes AND <= MAX_SNAPLEN bytes (included length AND original length) (conditions 1,2,3,4,5)
 * - included length <= original lenth (conditions 6,7,8,9)
 * - packet timestamp is NOT older OR younger than the prior packets timestamp -+ one day (conditions 10,11,12)
 * - usec (microseconds) field <= 1000000 (conditions 13)
 * - usec (nanoseconds) field <= 1000000000 (conditions 14)
 *
 * global_hdr: the filled pcap header struct to check for snaplen
 * hdr:        the filled packet header struct to check for plausibility
 * prior_ts:   the prior packets timestamp (seconds) to check for time relation (condition 6,7)
 *
 * returns:  0   success
 *          -X   error (condition X failed)
 *
 */
int is_plausible_kuznetzov(struct global_hdr_s global_hdr, struct packet_hdr_kuznet_s hdr, unsigned int prior_ts) {
  /* check for minimum packet size
   * minimum packet size should be 16, but in some cases, e.g. local wlan capture, packet might
   * even be smaller --> decreased minimum size to 10 */
  if (conint(hdr.incl_len) < 10) return(-1);
  if (conint(hdr.orig_len) < 10) return(-2);

  /* check packet limit with header field and max snaplen
     in soft mode (and dlt 119) the packet detection accepts a wider range */
  if (soft_mode || global_hdr.network == 119) {
    /* in soft mode, global pcap snap length is ignored, instead MAX snaplen is used */

    /* strange behavior for wlan: in some cases incl length seems to differ
       not following the configured max snap length; this leads to dropping
       valid wlan packets -> use soft mode for DLT 119 */
    if (conint(hdr.incl_len) > PCAP_MAX_SNAPLEN) return(-3);
  } else {
    /* in hard mode (and not dlt 119), global pcap snap length is the limit in plausibility checks */
    if (conint(hdr.incl_len) > conint(global_hdr.snaplen)) return(-4);
  }
  /* orig length should not be greater than pcap max snaplen */
  if (conint(hdr.orig_len) > PCAP_MAX_SNAPLEN) return(-5);

  /* if the packet original size is larger than the included length, then
     the included length should be limited by the files snap length */
  if (conint(hdr.orig_len) > conint(hdr.incl_len)) {
    /* check for dlt 119 == wlan */
    if (global_hdr.network == 119) {
      /* strange behavior for wlan: in some cases incl length seems to differ
         not following the configured max snap length; this leads to dropping
         valid wlan packets -> ignore this check for DLT 119 */
    } else {
      if (conint(hdr.incl_len) != conint(global_hdr.snaplen)) return(-7);
    }
  }

  /* the included length CAN NOT be larger than the original length */
  /* check for LINKTYPE_LINUX_SLL (linux cooked) */
  if (global_hdr.network == 113) {
    /* linux cooked headers are appended to packet length, but not to orig length
       so we need to remove it from incl_len before checking */
    if (conint(hdr.incl_len)-16 > conint(hdr.orig_len)) return(-8);
  } else if (conint(hdr.incl_len) > conint(hdr.orig_len)) return(-9);

  /* check packet times (older) */
  if (soft_mode) {
    /* in soft mode, there is no limit for older packets */
  } else {
    /* in hard mode, packet must not be older than one day (related to prior packet) */
    if ((prior_ts != 0) && (conint(hdr.ts_sec) > (prior_ts+86400))) return(-10);
  }

  /* check packet times (younger) */
  if (soft_mode) {
    /* in soft mode, packet must not be younger than one day (related to prior packet) */
    if ((prior_ts >= 86400) && (conint(hdr.ts_sec) < (prior_ts-86400))) return(-11);
  } else {
    /* in hard mode, packets must not be younger than prior packet */
    if ((prior_ts != 0) && (conint(hdr.ts_sec) < prior_ts)) return(-12);
  }

  /* check for nano/microseconds (hard mode only) */
  if (!soft_mode) {
    /* in hard mode */
    /* usec (microseconds) must <= 1000000 */
    /* kuznetzov never uses nanoseconds */
    if (conint(hdr.ts_usec) > 1000000) return(-13);
  }

  /* all conditions fullfilled ==> everything fine! */
  return(0);
}

/*
 * Function:  check_header
 * -----------------------
 * this function takes a buffer and brute forces some possible ascii-corrupted bytes versus plausibility checks
 *
 * buffer:     the buffer that might contain the possible pcap packet header
 * size:       the size of the buffer (double pcap packet header size is a good choice)
 * priot_ts:   the prior packets timestamp (to check for plausibility)
 * global_hdr: the pointer to the pcap header
 * hdr:        the pointer to the packet header buffer (we use this to return the repaired header)
 *
 * returns: >=0   success (return value contains number of ascii corrupted bytes in hdr (we need this data to align the beginning of the packet body later)
 *           -1   error (no valid pcap header found inside buffer)
 *
 */
int check_header_kuznetzov(char *buffer, unsigned int size, unsigned int prior_ts, struct global_hdr_s *global_hdr, struct packet_hdr_kuznet_s *hdr) {
  unsigned int i; /* loop variable - first byte in buffer that could be beginning of packet */
  int res;        /* return value */
  char *tmp;      /* the temporary buffer that will be used for recursion */

  /* does the buffer already contain a valid packet header (without any correction) ?? */
  memcpy(hdr, buffer, sizeof(struct packet_hdr_kuznet_s));
  res = is_plausible_kuznetzov(*global_hdr, *hdr, prior_ts);
  if (res == 0) return(0);

  if (verbose >= 2) printf("[-] Header plausibility check failed with error code %d\n", res);

  /* we need to abort the recursion of there are too many possible ascii corrupted bytes at ones */
  /* 32-25 = 7 bytes maximum in 32bytes of data! */
  if (size <= 25) return(-1);

  /* this loop will check the the buffer for occurence of 0x0D + 0x0A (UNIX to WINDOWS ascii corruption) */
  for(i=0; i<sizeof(struct packet_hdr_kuznet_s); i++) {
    /* is there a 0x0D 0X0A combination at this position? */
    if (buffer[i] == 0x0D && buffer[i+1] == 0x0A) {

      /* allocate memory for recursion buffer */
      tmp = malloc(size);

      /* we cut out 0x0D because this byte could have been added due to ftp ascii transfer eg */
      memcpy(tmp, buffer, i);
      memcpy(tmp+i, buffer+i+1, size-i-1);

      /* and invoke the header again without this 0x0D byte */
      res = check_header_kuznetzov(tmp, size-1, prior_ts, global_hdr, hdr);

      /* free recursion buffer */
      free(tmp);

      /* if the check was successfull (maybe with multiple recursions) return the value added by one (body shift offset) */
      if (res != -1) return(res+1);
    }
  }

  /* the buffer (even after ascii corruption brute force) does not contain any valid pcap packet header */
  return(-1);
}

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
int fix_pcap_kuznetzov(FILE *pcap, FILE *pcap_fix) {
  struct global_hdr_s global_hdr;		/* global header data */

  /* we use a buffer to cache 1mb of writing... this way writing is faster and
     we can read and write the file at the same time */
  char *writebuffer;
  uint64_t writepos = 0;

  uint64_t bytes;				/* read/written bytes counter */
  uint64_t filesize;				/* filesize of input file in bytes */
  unsigned short hdr_integ;			/* integrity counter of global header */

  /* init write buffer */
  writebuffer = malloc(1024000);

  /* get size of input file */
  fseeko(pcap, 0, SEEK_END);
  filesize = ftello(pcap);
  fseeko(pcap, 0, SEEK_SET);

  /* BEGIN GLOBAL HEADER CHECK */

  /* check space of pcap global header */
  if (filesize < sizeof(global_hdr)) {
    printf("[-] File is too small to read pcap global header.\n");
    return(-2);
  }

  printf("[*] Analyzing Global Header...\n");
  bytes = fread(&global_hdr, sizeof(global_hdr), 1, pcap);	/* read first bytes of input file into struct */
  if (bytes != 1) return -3;

  /* init integrity counter */
  hdr_integ = 0;

  /* check for pcap's magic bytes () */
  if (global_hdr.magic_number == PCAP_EXT_MAGIC) {
    /* we got a KUZNETZOV extended tcpdump magic (non swapped) */
    if (verbose) printf("[+] Magic number: 0x%x (KUZNETZOV)\n", global_hdr.magic_number);
  } else if (global_hdr.magic_number == htonl(PCAP_EXT_MAGIC)) {
    /* we got a KUZNETZOV extended tcpdump magic (swapped) */
    if (verbose) printf("[+] Magic number: 0x%x (KUZNETZOV - SWAPPED)\n", global_hdr.magic_number);
    swapped = 1;
  } else {
    /* we are not able to determine the pcap magic */
    hdr_integ++;
    if (verbose) printf("[-] Magic number: 0x%x\n", global_hdr.magic_number);

    /* in this special case of kuznetzov, we do not try to assume it is a pcap file */
    return(-1);
  }

  /* check for major version number (2) */
  if (conshort(global_hdr.version_major) == 2) {	/* current major version is 2 */
    if (verbose) printf("[+] Major version number: %hu\n", conshort(global_hdr.version_major));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Major version number: %hu\n", conshort(global_hdr.version_major));
    global_hdr.version_major = conshort(2);
  }

  /* check for minor version number */
  if (conshort(global_hdr.version_minor) == 4) {	/* current minor version is 4 */
    if (verbose) printf("[+] Minor version number: %hu\n", conshort(global_hdr.version_minor));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Minor version number: %hu\n", conshort(global_hdr.version_minor));
    global_hdr.version_minor = conshort(4);
  }

  /* check for GTM to local correction */
  if (conshort(global_hdr.thiszone) == 0) {	/* in practise time stamps are always in GTM, so the correction is always zero */
    if (verbose) printf("[+] GTM to local correction: %d\n", conint(global_hdr.thiszone));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] GTM to local correction: %d\n", conint(global_hdr.thiszone));
    global_hdr.thiszone = conint(0);
  }

  /* check for accuracy of timestamps */
  if (conint(global_hdr.sigfigs) == 0) {	/* all capture tools set this to zero */
    if (verbose) printf("[+] Accuracy of timestamps: %u\n", conint(global_hdr.sigfigs));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Accuracy of timestamps: %u\n", conint(global_hdr.sigfigs));
    global_hdr.sigfigs = conint(0);
  }

  /* check for max packet length */
  if ((conint(global_hdr.snaplen) > 0) && (conint(global_hdr.snaplen) <= PCAP_MAX_SNAPLEN)) {	/* typically 262144 nowadays */
    if (verbose) printf("[+] Max packet length: %u\n", conint(global_hdr.snaplen));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Max packet length: %u\n", conint(global_hdr.snaplen));
    global_hdr.snaplen = conint(PCAP_MAX_SNAPLEN);
  }

  /* check for data link type (http://www.tcpdump.org/linktypes.html) */
  if (conint(global_hdr.network) <= 251) {	/* data link types are <= 251 */
    if (verbose) printf("[+] Data link type: %u\n", conint(global_hdr.network));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Data link type: %u\n", conint(global_hdr.network));
    /* if data link type is corrupt, we set it to ethernet (user supplied param will be processed afterwards) */
    global_hdr.network = conint(1);
  }

  /* does the user provides a self-supplied data link type? if yes... change global header */
  if (data_link_type != -1) {
    printf("[+] Changing data link type to %d.\n", data_link_type);
    global_hdr.network = conint(data_link_type);
    hdr_integ++;
  }

  /* evaluate the integrity of the global header */
  if (hdr_integ == 0) { /* no field has been corrupted? --> header is intact */
    printf("[+] The global pcap header seems to be fine!\n");
  } else if (hdr_integ >= 4) { /* there have been five or more (of seven) corrupted fields? --> header is missing */
    printf("[-] The global pcap header seems to be missing ==> CORRECTED!\n");
    /* we need to set the file pointer to the beginning of the file, because
     * further packet search depends on this position and without a global
     * header the first packet might begin there */
    fseeko(pcap, 0, SEEK_SET);

    /* set important header values to defaults */
    global_hdr.snaplen = conint(PCAP_MAX_SNAPLEN);

    if (data_link_type != -1) {
      global_hdr.network = conint(data_link_type);
    } else {
      global_hdr.network = conint(1);
    }
  } else { /* there have been corrupted fields (less than five) --> header is corrupted */
    printf("[-] The global pcap header seems to be corrupt! ==> CORRECTED\n");
  }

  /* write the (maybe changed) global header to output file */
  memcpy(writebuffer, &global_hdr, sizeof(global_hdr));
  writepos += sizeof(global_hdr);

  /* END OF GLOBAL HEADER CHECK */

  /* start handling packets */
  return(fix_pcap_packets_kuznetzov(pcap, pcap_fix, filesize, global_hdr, hdr_integ, writebuffer, writepos));
}

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
int fix_pcap_packets_kuznetzov(FILE *pcap, FILE *pcap_fix, uint64_t filesize, struct global_hdr_s global_hdr, unsigned short hdr_integ, char *writebuffer, uint64_t writepos) {
  struct packet_hdr_kuznet_s packet_hdr;	/* packet header data */
  struct packet_hdr_kuznet_s next_packet_hdr;	/* next packet header data to look forward */
  char hdrbuffer[sizeof(packet_hdr)*2];		/* the buffer that will be used to find a proper packet */

  char buffer[PCAP_MAX_SNAPLEN];		/* the packet body */
  uint64_t bytes;				/* read/written bytes counter */

  unsigned int count;				/* packet counter */
  unsigned int step = 1;			/* step counter for progress bar */

  uint64_t pos = 0;				/* position of current packet header */
  uint64_t nextpos = 0;			        /* possible position of next packets header */

  unsigned int last_correct_ts_sec = 0;		/* timestamp of the last proper packet found (seconds) */
  unsigned int last_correct_ts_usec = 0;	/* timestamp of the last proper packet found (microseconds or nanoseconds) */

  int ascii = 0;				/* ascii counter for possible ascii-corrupted packets */
  int corrupted = 0;				/* corrupted packet counter for final output */

  int res;					/* the result of the header check == the offset of body shifting */

  /* BEGIN PACKET CHECK */

  printf("[*] Analyzing packets...\n");

  /* this loop iterates the packets from top till down by checking the
   * pcap packet headers on plausibility. if any packet header has got
   * implausible information the packet will be handled as corrupted
   * and pcapfix will brute force the next packet. if the packet header
   * look plausible, pcapfix will check if the next packet is aligned and
   * if not check for overlapping packets.
   */

  /* get current file pointer position */
  pos = ftello(pcap);

  /* loop the pcap files packets until pos has reacher end of file */
  for (count=1; pos < filesize; count++) {

    /* we only want the progress bar to be printed in non-verbose mode */
    if ((verbose == 0) && (5*(float)pos/(float)filesize > step)) {
      print_progress(pos, filesize);
      step++;
    }

    /* check if a pcap packet header would fit into the file */
    if (pos + sizeof(hdrbuffer) > filesize) {
      printf("[-] Not enough bytes left in file ==> SKIPPING %" PRIu64 " bytes.\n", filesize-pos);
      corrupted++;

      /* at least one packet has been found?? */
      if (count == 1) {
        printf("[-] No packet has been found!\n");
        return(-2);
      }

      /* end of file reached */
      pos = filesize;
      break;
    }

    /* read the next packet header */
    bytes = fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap);
    if (bytes != 1) return -3;

    /* check if the packet header looks proper */
    res = check_header_kuznetzov(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &global_hdr, &packet_hdr);
    if (res != -1) {

      /* realign packet body (based on possible-ascii corrupted pcap header) */
      pos += res;
      fseeko(pcap, pos+sizeof(packet_hdr), SEEK_SET);

      /* try to read the packet body AND check if there are still at least 24 bytes left for the next pcap packet header */
      if ((fread(&buffer, conint(packet_hdr.incl_len), 1, pcap) == 0) || ((filesize-(pos+sizeof(packet_hdr)+conint(packet_hdr.incl_len)) > 0) && (filesize-(pos+sizeof(packet_hdr)+conint(packet_hdr.incl_len)) < sizeof(packet_hdr)))) {
        /* fread returned an error (EOL while read the body) or the file is not large enough for the next pcap packet header (24bytes) */
        /* thou the last packet has been cut of */

        if (verbose >= 1) printf("[-] LAST PACKET MISMATCH (%u | %u | %u | %u)\n", conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

        /* correct the packets included length field to match the end of file */
        packet_hdr.incl_len = conint(filesize-pos-sizeof(packet_hdr));

        /* the original length must not be smaller than the included length */
        if (conint(packet_hdr.incl_len) > conint(packet_hdr.orig_len)) packet_hdr.orig_len = packet_hdr.incl_len;

        /* print out information */
        printf("[+] CORRECTED Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));
        corrupted++;
      }

      /* OVERLAPPING DETECTION */
      /* we do ONLY scan for overlapping if next packet is NOT aligned */

      /* read next packet header */
      bytes = fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap);

      /* check if next packets header looks proper */
      if (check_header_kuznetzov(hdrbuffer, sizeof(hdrbuffer), conint(packet_hdr.ts_sec), &global_hdr, &next_packet_hdr) == -1) {

        /* the next packets header is corrupted thou we are going to scan through the prior packets body to look for an overlapped packet header
         * also look inside the next packets header + 24bytes of packet body, because we need to know HERE
         * do not leave the loop if the first packet has not been found yet AND deep scan mode is activated */
        for (nextpos=pos+sizeof(packet_hdr)+1; (nextpos < pos+sizeof(packet_hdr)+conint(packet_hdr.incl_len)+2*sizeof(packet_hdr)) || (count == 1 && deep_scan == 1); nextpos++) {

          /* read the possible next packets header */
          fseeko(pcap, nextpos, SEEK_SET);
          bytes = fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap);

          /* check read success */
          if (bytes == 0) break;

          /* heavy verbose output :-) */
          if (verbose >= 2) printf("[*] Trying Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

          /* check the header for plausibility */
          res = check_header_kuznetzov(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &global_hdr, &next_packet_hdr);
          if (res != -1) {

            /* we found a proper header inside the packets body! */
            if (verbose >= 1) printf("[-] FOUND OVERLAPPING data of Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

            /* correct the prior packets length information fields to align the overlapped packet */
            packet_hdr.incl_len = conint(nextpos-(pos+sizeof(packet_hdr))+res);	/* also include ascii corruption offset (res) */
            packet_hdr.orig_len = packet_hdr.incl_len;

            /* time correction for the FIRST packet only */
            if (count == 1) {
              if (conint(next_packet_hdr.ts_usec) > 0) {
                /* next packets usec is > 0 ===> first packet will get same timestamp and usec - 1 */
                packet_hdr.ts_sec = next_packet_hdr.ts_sec;
                packet_hdr.ts_usec = conint(conint(next_packet_hdr.ts_usec)-1);
              } else if(conint(next_packet_hdr.ts_sec) > 0) {
                /* else: next packets timestamp i > 0 ===> firt packet will get timestamp -1 and maximum usec */
                packet_hdr.ts_sec = conint(conint(next_packet_hdr.ts_sec)-1);
                packet_hdr.ts_usec = conint(999999);
              } else {
                /* else: (next packets sec and usec are zero), this packet will get zero times as well */
                packet_hdr.ts_sec = conint(0);
                packet_hdr.ts_usec = conint(0);
              }
            }

            /* print out information */
            printf("[+] CORRECTED Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));
            corrupted++;

            /* overlapping seems to be a result of ascii-transferred pcap files via FTP */
            ascii++;

            break;
          }
        }
      }

      /* reset file fointer to next packet */
      fseeko(pcap, pos+sizeof(packet_hdr)+conint(packet_hdr.incl_len), SEEK_SET);

      /* we found a correct packet (and aligned it maybe) */
      if (verbose >= 1) printf("[+] Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

      /* write this packet */

      // check if there is enough space in buffer
      int totalsize = sizeof(packet_hdr) + conint(packet_hdr.incl_len);
      if (writepos+totalsize > 1024000) {
        bytes = fwrite(writebuffer, writepos, 1, pcap_fix);
        writepos = 0;
      }

      // put new bytes into write buffer
      memcpy(writebuffer+writepos, &packet_hdr, sizeof(packet_hdr));
      writepos += sizeof(packet_hdr);
      memcpy(writebuffer+writepos, buffer, conint(packet_hdr.incl_len));
      writepos += conint(packet_hdr.incl_len);

      /* remember that this packets timestamp to evaluate futher timestamps */
      last_correct_ts_sec = conint(packet_hdr.ts_sec);
      last_correct_ts_usec = conint(packet_hdr.ts_usec);

    } else {

      /* PACKET IS CORRUPT */

      if (verbose >= 1) printf("[-] CORRUPTED Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

      /* scan from the current position to the maximum packet size and look for a next proper packet header to align the corrupted packet
       * also do not leave the loop if the first packet has not been found yet AND deep scan mode is activated */
      for (nextpos=pos+sizeof(packet_hdr)+1; (nextpos <= pos+sizeof(packet_hdr)+PCAP_MAX_SNAPLEN) || (count == 1 && deep_scan == 1); nextpos++) {

        /* read the possible next packets header */
        fseeko(pcap, nextpos, SEEK_SET);
        if (fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap) == 0) {

          /* did we read over EOF AND havent found the first packet yet? then we need to abort! */
          if ((count == 1) && (deep_scan == 1)) {

            /* abort scan */
            pos = 0;
            corrupted = -1;
            break;
          }

          printf("[*] End of file reached. Aligning last packet.\n");

          /* check last packet for plausiblilty */
          res = check_header_kuznetzov(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &global_hdr, &packet_hdr);
          if (res != 0) {
            printf("[-] Cannot align last packet, because it is broken.\n");
            corrupted++;
            count--;
            break;
          }

          /* check passed */

          /* align the last packet to match EOF */
          packet_hdr.incl_len = conint(filesize-(pos+sizeof(packet_hdr)));
          packet_hdr.orig_len = packet_hdr.incl_len;

          /* if the is the first packet, we need to set timestamps to zero */
          if (count == 1) {
            packet_hdr.ts_sec = conint(0);
            packet_hdr.ts_usec = conint(0);
          } else {	/* else take the last correct timestamp and usec plus one */
            packet_hdr.ts_sec = conint(last_correct_ts_sec);
            packet_hdr.ts_usec = conint(last_correct_ts_usec+1);
          }

          /* read the packets body (size based on the just found next packets position) */
          fseeko(pcap, pos+sizeof(packet_hdr), SEEK_SET);
          bytes = fread(&buffer, conint(packet_hdr.incl_len), 1, pcap);

          // check if there is enough space in buffer
          int totalsize = sizeof(packet_hdr) + conint(packet_hdr.incl_len);
          if (writepos+totalsize > 1024000) {
            bytes = fwrite(writebuffer, writepos, 1, pcap_fix);
            writepos = 0;
          }

          // put new bytes into write buffer
          memcpy(writebuffer+writepos, &packet_hdr, sizeof(packet_hdr));
          writepos += sizeof(packet_hdr);
          memcpy(writebuffer+writepos, buffer, conint(packet_hdr.incl_len));
          writepos += conint(packet_hdr.incl_len);

          /* remember that this packets timestamp to evaluate futher timestamps */
          last_correct_ts_sec = packet_hdr.ts_sec;
          last_correct_ts_usec = packet_hdr.ts_usec;

          /* print out information */
          printf("[+] CORRECTED LAST Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));
          corrupted++;

          break;
        }

        /* shall we abort the whole scan?? */
        if (corrupted == -1) break;

        /* heavy verbose output :-) */
        if (verbose >= 2) printf("[*] Trying Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

        /* check if next packets header looks proper */
        res = check_header_kuznetzov(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &global_hdr, &next_packet_hdr);
        if (res != -1) {

          /* if we found a packet that is below the top MAX_SNAPLEN bytes (deep scan) we cut it off and take the second packet as first one */
          if ((nextpos-(pos+sizeof(packet_hdr)) > PCAP_MAX_SNAPLEN) && (count == 1) && (deep_scan == 1)) {

            if (verbose >= 1) printf("[+] (DEEP SCAN) FOUND FIRST Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

            /* set the filepoint to the top of the first packet to be read in next loop iteration */
            fseeko(pcap, nextpos, SEEK_SET);

            /* correct counter due to deep scan */
            count--;

          } else { /* found next packet (NO deep scan mode) */

            /* we found the NEXT packets header, now we are able to align the corrupted packet */
            if (verbose >= 1) printf("[+] FOUND NEXT Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

            /* correct the corrupted pcap packet header to match the just found next packet header */
            packet_hdr.incl_len = conint(nextpos-(pos+sizeof(packet_hdr)));
            packet_hdr.orig_len = packet_hdr.incl_len;

            if (count == 1) { /* time correction for the FIRST packet */
              if (conint(next_packet_hdr.ts_usec) > 0) {
                /* next packets usec is > 0 ===> first packet will get same timestamp and usec - 1 */
                packet_hdr.ts_sec = next_packet_hdr.ts_sec;
                packet_hdr.ts_usec = conint(conint(next_packet_hdr.ts_usec)-1);
              } else if(conint(next_packet_hdr.ts_sec) > 0) {
                /* else: next packets timestamp i > 0 ===> firt packet will get timestamp -1 and maximum usec */
                packet_hdr.ts_sec = conint(conint(next_packet_hdr.ts_sec)-1);
                packet_hdr.ts_usec = conint(999999);
              } else {
                /* else: (next packets sec and usec are zero), this packet will get zero times as well */
                packet_hdr.ts_sec = conint(0);
                packet_hdr.ts_usec = conint(0);
              }
            } else { /* ALL packets except the first one will use the last correct packets timestamps */
              packet_hdr.ts_sec = conint(last_correct_ts_sec);
              packet_hdr.ts_usec = conint(last_correct_ts_usec+1);
            }

            /* read the packets body (size based on the just found next packets position) */
            fseeko(pcap, pos+sizeof(packet_hdr), SEEK_SET);
            bytes = fread(&buffer, conint(packet_hdr.incl_len), 1, pcap);

            /* final check resulting packet for plausibility */
            res = is_plausible_kuznetzov(global_hdr, packet_hdr, last_correct_ts_sec);
            if (res == 0) {

              // check if there is enough space in buffer
              int totalsize = sizeof(packet_hdr) + conint(packet_hdr.incl_len);
              if (writepos+totalsize > 1024000) {
                bytes = fwrite(writebuffer, writepos, 1, pcap_fix);
                writepos = 0;
              }

              // put new bytes into write buffer
              memcpy(writebuffer+writepos, &packet_hdr, sizeof(packet_hdr));
              writepos += sizeof(packet_hdr);
              memcpy(writebuffer+writepos, buffer, conint(packet_hdr.incl_len));
              writepos += conint(packet_hdr.incl_len);

              /* remember that this packets timestamp to evaluate futher timestamps */
              last_correct_ts_sec = conint(packet_hdr.ts_sec);
              last_correct_ts_usec = conint(packet_hdr.ts_usec);

              /* print out information */
              printf("[+] CORRECTED Packet #%u at position %" PRIu64 " (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

            } else {
              /* prior packet is invalid */
              printf("[-] Packet #%u at position %" PRIu64 " is invalid ==> SKIPPING.\n", count, pos);
            }

          }

          /* increase corruption counter */
          corrupted++;

          /* leave the next packet search loop */
          break;
        }

      }

      /* shall we abort the whole scan (due to deep scan did not succeed at all) */
      if (corrupted == -1) break;

      /* did the counter exceed the maximum packet size? */
      if ((count == 1 && deep_scan == 0) && (nextpos > pos+sizeof(packet_hdr)+PCAP_MAX_SNAPLEN)) {

        /* PACKET COULD NOT BE REPAIRED! */

        if (verbose >= 1) printf("[-] Cannot align corrupted packet! \n");
        break;
      }

      /* maximum search range reached? -> skip packet and keep on searching */
      if (deep_scan == 0 && (nextpos > pos+sizeof(packet_hdr)+PCAP_MAX_SNAPLEN)) {
        if (verbose >= 1) printf("[-] No next packet found within max packet range --> SKIPPING!\n");

        /* reset counter because no packet found */
        count--;
      }

    }

    /* get current file pointer position to start next loop iteration */
    pos = ftello(pcap);

  }

  // write remaining data into buffer
  bytes = fwrite(writebuffer, writepos, 1, pcap_fix);
  writepos = 0;

  if (verbose == 0) { print_progress(pos, filesize); }

  /* did we reach the end of pcap file? */
  if (pos != filesize) { /* no ==> data missing == FAILED */
    printf("[-] Reached EOF without finding more packets!\n");
    corrupted = -1;	/* the file could not be repaired */
  }

  /* END PACKET CHECK */

  /* EVALUATE RESULT */

  if ((hdr_integ == 0) && (corrupted == 0)) { /* check allover failure / integrity count and corrupted counter */

   /* no errors (header + packets correct) */
   return(0);

  } else if (corrupted == -1) {	/* check vor very high packet failure value ==> no recovery possible */

    /* file could NOT be repaired */

    if (count == 1) {

      /* even the first packet was corrupted and no other packet could be found */
      return(-1);

    } else {

      /* the first packet was intact, but recovery is not possible nevertheless */
      return(-2);

    }

  } else {
    /* check if we found at least one packet */
    if (count == 1) {
      /* even the first packet was corrupted and no other packet could be found */
      return(-1);
    }

    /* file has been successfully repaired (corruption fixed) */

    printf("[*] Wrote %u packets to file.\n", count-1);

    /* are there any packets that might have been transferred in ascii mode? */
    if (ascii) {
      printf("[!] This corruption seems to be a result of an ascii-mode transferred pcap file via FTP.\n");
      printf("[!] The pcap structure of those files can be repaired, but the data inside might still be corrupted!\n");
    }

    return(hdr_integ+corrupted);

  }

}
