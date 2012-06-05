/*******************************************************************************
 *
 * pcapfix.c - pcap file repair tool
 * Copyright (c) 2012 Robert Krause (ruport@f00l.de)
 * License: GPLv3
 *
 * Last Modified: 31.03.2012
 *
 * Command line: pcapfix [-v] <pcap_file>
 *
 * Description:
 *
 * pcapfix is a repair tool for corrupted pcap files. It checks for an intact
 * pcap global header and repairs it if there are any corrupted bytes. If one
 * is not present, one is created and added to the beginning of the file. It
 * then tries to find pcap packet headers, and checks and repairs them.
 *
 ******************************************************************************/

#ifdef __linux__
  #define _GNU_SOURCE     // we need this line to get the correct basename function on linux systems
#endif

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#define VERSION "0.3"		// pcapfix version
#define PCAP_MAGIC 0xa1b2c3d4	// the magic of the pcap global header (non swapped)

// Global header (http://v2.nat32.com/pcap.htm)
struct global_hdr_s {
        unsigned int magic_number;   	/* magic number */
        unsigned short version_major;  	/* major version number */
        unsigned short version_minor;  	/* minor version number */
        signed int thiszone;       	/* GMT to local correction */
        unsigned int sigfigs;        	/* accuracy of timestamps */
        unsigned int snaplen;        	/* max length of captured packets, in octets */
        unsigned int network;        	/* data link type */
};

// Packet header (http://v2.nat32.com/pcap.htm)
struct packet_hdr_s {
        unsigned int ts_sec;         /* timestamp seconds */
        unsigned int ts_usec;        /* timestamp microseconds */
        unsigned int incl_len;       /* number of octets of packet saved in file */
        unsigned int orig_len;       /* actual length of packet */
};

// print out the usage information
// IN: progname - the program name
void usage(char *progname) {
  printf("Usage: %s [OPTIONS] filename\n", progname);
  printf("OPTIONS:");
  printf(  "\t-t <nr>, --data-link-type <nr>\tData link type\n");
  printf("\t\t-v     , --verbose            \tVerbose output\n");
  printf("\n");
}

int main(int argc, char *argv[]) {
  FILE *pcap, *pcap_fix;			// input and output file
  struct global_hdr_s global_hdr;		// global header data
  struct packet_hdr_s packet_hdr;		// packet header data
  char buffer[65535];				// the packet body

  unsigned long pos;				// position of file pointer
  unsigned int count;				// packet counter
  unsigned int last_correct_ts_sec = 0;		// timestamp of the last proper packet found (seconds)
  unsigned int last_correct_ts_usec = 0;	// timestamp of the last proper packet found (microseconds)
  unsigned long last_correct_upper_pos = 0;	// lower file pointer position of proper packet
  unsigned long last_correct_lower_pos;		// upper file pointer position of proper packet
  unsigned short hdr_integ, pkt_integ;		// integrity counter of global header of packet header
  int size;					// size counter to guess packet length
  int c;					// loop counter
  int option_index = 0;				// getopt_long option index

  int data_link_type = 1;			// data link type (default: LINKTYPE_ETHERNET)
  int verbose = 0;				// verbose output option (default: dont be verbose)

  // init getopt_long options struct
  struct option long_options[] = {
    {"data-link-type", required_argument, 0, 't'},		// --data-link-type == -t
    {"verbose", no_argument, 0, 'v'},				// --verbose == -v
    {0, 0, 0, 0}
  };

  // print out pcapfix header information
  printf("pcapfix %s (c) 2012 Robert Krause\n\n", VERSION);

  // scan for options and arguments
  while ((c = getopt_long(argc, argv, ":t:v::", long_options, &option_index)) != -1) {
    switch (c) {
      case 0:	// getopt_long options evaluation
        long_options[option_index].flag;
        break;
      case 'v':	// verbose
        verbose++;
        break;
      case 't':	// data link type
        data_link_type = atoi(optarg);
        break;
      case '?': // unknown option
        usage(argv[0]);
        return 1;
      default:
        abort();
    }
  }

  // filename is first argument
  char *filename = argv[optind++];

  // if filename is not set, output usage information
  if (filename == NULL) {
    usage(argv[0]);
    return(1);
  }

  // open input file
  printf("[*] Reading from file: %s\n", filename);
  pcap = fopen(filename, "r");
  if (!pcap) {
    perror("[-] Cannot open input file");
    return(1);
  }

  // open output file
  // we need to extract the basename first (windows and linux use different functions)
  char filebname[strlen(filename)];
  #ifdef __WIN32__
    _splitpath(filename, NULL, NULL, filebname, NULL);
  # else
    strcpy(filebname, basename(filename));
  #endif
  char filename_fix[strlen(filebname)+6];	// size of outputfile depends on inputfile's length
  strcpy(filename_fix, "fixed_");		// outputfile = fixed_ + inputfile
  strcat(filename_fix, filebname);
  printf("[*] Writing to file: %s\n", filename_fix);
  pcap_fix = fopen(filename_fix, "w");
  if (!pcap_fix) {
    perror("[-] Cannot open output file");
    return(1);
  }

  // BEGIN OF GLOBAL HEADER CHECK

  printf("[*] Analyzing global header...\n");
  fread(&global_hdr, sizeof(global_hdr), 1, pcap);	// read first bytes of input file into struct

  hdr_integ = 0;
  // check for file's magic bytes ()
  if (global_hdr.magic_number == PCAP_MAGIC) {
    if (verbose) printf("[+] Magic number: 0x%x\n", global_hdr.magic_number);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Magic number: 0x%x\n", global_hdr.magic_number);
    global_hdr.magic_number = PCAP_MAGIC;
  }

  // check for major version number
  if (global_hdr.version_major == 2) {	// current major version is 2
    if (verbose) printf("[+] Major version number: %hu\n", global_hdr.version_major);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Major version number: %hu\n", global_hdr.version_major);
    global_hdr.version_major = 2;
  }

  // check for minor version number
  if (global_hdr.version_minor == 4) {	// current minor version is 4
    if (verbose) printf("[+] Minor version number: %hu\n", global_hdr.version_minor);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Minor version number: %hu\n", global_hdr.version_minor);
    global_hdr.version_minor = 4;
  }

  // check for GTM to local correction
  if (global_hdr.thiszone == 0) {	// in practise time stamps are always in GTM, so the correction is always zero
    if (verbose) printf("[+] GTM to local correction: %d\n", global_hdr.thiszone);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] GTM to local correction: %d\n", global_hdr.thiszone);
    global_hdr.thiszone = 0;
  }

  // check for accuracy of timestamps
  if (global_hdr.sigfigs == 0) {	// all capture tools set this to zero
    if (verbose) printf("[+] Accuracy of timestamps: %u\n", global_hdr.sigfigs);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Accuracy of timestamps: %u\n", global_hdr.sigfigs);
    global_hdr.sigfigs = 0;
  }

  // check for max packet length
  if (global_hdr.snaplen <= 65535) {	// typically 65535 (no support for huge packets yet)
    if (verbose) printf("[+] Max packet length: %u\n", global_hdr.snaplen);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Max packet length: %u\n", global_hdr.snaplen);
    global_hdr.snaplen = 65535;
  }

  // check for data link type (http://www.tcpdump.org/linktypes.html)
  if (global_hdr.network <= 245) {	// data link types are smaller than 245
    if (verbose) printf("[+] Data link type: %u\n", global_hdr.network);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Data link type: %u\n", global_hdr.network);
    // if data link type is corrupt, we set it to ethernet (user supplied param will be processed later)
    global_hdr.network = 1;
  }

  // does the user forces a self-supplied data link type? if yes... change global header
  if (data_link_type != 1) {
    printf("[+] Changing data link type to %d.\n", data_link_type);
    global_hdr.network = data_link_type;
  }

  // evaluate the integrity of the global header
  if (hdr_integ == 0) { // no field has been corrupted? --> header is intact
    printf("[+] The global pcap header seems to be fine!\n");
  } else if (hdr_integ >= 6) { // there have been six or more corrupted fields? --> header is missing
    printf("[-] The global pcap header seems to be missing ==> CORRECTED!\n");
    /* we need to set the file pointer to the beginning of the file, because
       further packet search depends on this position and without a global
       header the first packet might begin there */
    fseek(pcap, 0, SEEK_SET);
  } else { // there have been corrupted fields (less than six) --> header is corrupted
    printf("[-] The global pcap header seems to corrupt! ==> CORRECTED\n");
  }

  // write the (maybe fixed) global header to output file
  fwrite(&global_hdr, sizeof(global_hdr), 1, pcap_fix);

  // END OF GLOBAL HEADER CHECK

  // BEGIN PACKET CHECK

  printf("[*] Analyzing packets...\n");

  pkt_integ = 0;	// reset packet integrity counter
  pos = ftell(pcap);	// get current file pointer position

  /* this loop iterates the packets from top till down by checking the
     pcap packet headers on plausibility. if any packet header has got
     implausible information the packet will be handled as corrupted.
  */

  for (count=1; fread(&packet_hdr, sizeof(packet_hdr), 1, pcap) > 0; count++) {	// read the next packet header based on current file pointer

    /* which data is not plausible for packet headers?
         ==> packet capture size (incl_len) is larger than 65535 bytes (no huge packet support yet!)
         ==> packet timestamp is smaller than the previous packet's one (packets must build an conclusive time line)
         ==> packet capture size is larger than original packet size
    */

    if ((packet_hdr.incl_len <= 65535) && (packet_hdr.ts_sec >= last_correct_ts_sec) && (packet_hdr.incl_len <= packet_hdr.orig_len)) {	// packet header seems to be fine

      if (verbose) printf("[+] Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
      fread(&buffer, packet_hdr.incl_len, 1, pcap);		// read packet body
      fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
      fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);	// write packet body to output file

      // remember that this packet (timestamp + position) was the last found correct one
      last_correct_ts_sec = packet_hdr.ts_sec;
      last_correct_ts_usec = packet_hdr.ts_usec;
      last_correct_upper_pos = pos+packet_hdr.incl_len+16;

    } else {	// packet header is corrupted

      pkt_integ++;
      if (verbose) printf("[-] Corrupted packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
      else printf("[-] Corrupted packet found ==> TRYING TO RECOVER\n");

      // break the top till down iteration and try to recover the packets from bottom up
      break;

    }

    // get current file pointer position
    pos = ftell(pcap);
  }

  // BEGIN BOTTOM UP RECOVERY

  // only start bottum up recovery if there has been any corrupted packet
  if (pkt_integ > 0) {
    if (verbose) printf("[*] Recovering");

    // set file pointer to end of file
    fseek(pcap, 0, SEEK_END);
    pos = ftell(pcap);

    /* now we have to look for pcap headers by brute force. we are going to interpret every
       header sized block as packet header and check for plausebility. the last packet must
       conclude the pcap file. so the packet capture size must be file length minus packet
       header position. if a correct packet header has been found. try to find the upper
       packet using the same algorithm.
    */

    size = 0;	// this is the value, the packet capture size MUST be, if the packet header would be at the current position
    for(pos -= sizeof(packet_hdr); pos > last_correct_upper_pos; pos--) {	// iterate through the last known correct upper position has been reached
      fseek(pcap, pos, SEEK_SET);			// set the file pointer
      fread(&packet_hdr, sizeof(packet_hdr), 1, pcap);	// read in the possible packet header
      if (verbose >= 2) printf("[*] Trying position %ld (%u | %u | %u | %u) - size MUST be %d.\n", pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len, size);

      /* check the possible packet header for plausibility here!
         which values should qualify a correct packet header?
           ==> packet capture size points to the position of the packet below (or the end of file) (this is the MOST IMPORTANT condition)
           ==> packet capture size must be larger than 53 and smaller than 65536 (no huge packet support yet)
           ==> packet timestamp must be larger than the last known correct packet ones
      */

      if ((packet_hdr.incl_len == size) && (packet_hdr.incl_len >= 54) && (packet_hdr.incl_len <= 65535) && (packet_hdr.ts_sec >= last_correct_ts_sec)) {	// seems to be a correct packet header

        if (verbose >= 2) printf("[+] Found packet at position %ld (%u | %u | %u | %u).\n", pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
        else if (verbose) printf(".");

	last_correct_lower_pos = pos;	// remember this position as the last known correct lower packet
        pos -= sizeof(packet_hdr)-1;	// skip next packet header (+1 is done by loop head)
        size = 0;			// reset size (points to lower packet now)

      } else { size++; }	// no correct packet header (so in the next interation capture size must satisfy size + 1)

    }  // last known correct upper packet reached

    if (verbose) printf("\n");

    // check if a correct lower packet has been found
    if (last_correct_lower_pos-last_correct_upper_pos <= 65535) { // packet found
      if (!verbose) printf("[+] SUCCESS!\n");

      // REBUILD DAMAGED PACKET HERE

      /* at this position we know the last correct upper packets postion and the
         last correct lower packets position. the data between these two packets
         MUST be a corrupted one. to not override any packet data we will fill in
         a new pcap packet header with correct data and keep on writing the proper
         packets
      */

      // build the new header of the corrupted packet
      packet_hdr.ts_sec = last_correct_ts_sec;					// timestamp is equal to the upper packet
      packet_hdr.ts_usec = last_correct_ts_usec+1;				// microseconds + 1, just to show the packet has been captured later
      packet_hdr.incl_len = last_correct_lower_pos-last_correct_upper_pos;	// capture size is the size between the last correct upper and lower packets position
      packet_hdr.orig_len = last_correct_lower_pos-last_correct_upper_pos;	// we do not know the original size, we set it to capture size thou
      if (verbose) printf("[+] RECOVERED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, last_correct_upper_pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
      count++;	// count the corrupted packet too

      // write repaired packet to output file
      fseek(pcap, last_correct_upper_pos, SEEK_SET);		// set input file pointer to the beginning of the corrupted data
      fread(&buffer, packet_hdr.incl_len, 1, pcap);		// read the corrupted data as packet body as a whole
      fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write self-builded packet header to output file
      fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);		// write corrupted packet data as new repaired packet body to output file

      // continue writing the proper packets from below to output file
      pos = ftell(pcap);	// get current file pointer position
      for (; fread(&packet_hdr, sizeof(packet_hdr), 1, pcap) > 0; count++) {	// just keep on reading the packets from input file
        if (verbose) printf("[+] Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);

        // we do not need any further checks here ( hopefully ;-) ) because the bottom-up-check already did it
        fread(&buffer, packet_hdr.incl_len, 1, pcap);		// read packet body from input file
        fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
        fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);	// write packet body to output file

        // get current file pointer position
        pos = ftell(pcap);
      }

    } else { // no lower correct packet found
      printf("[-] FAILED!\n");
      pkt_integ = 9999;	// set packet failure value very high
    }

  } // END BOTTOM UP RECOVERY

  // END PACKET CHECK

  // close files
  fclose(pcap);
  fclose(pcap_fix);

  // evaluate result
  if ((hdr_integ+pkt_integ) == 0) {	// check allover failure / integrity count ( 0 == no corruption )
    if (data_link_type == 1) { // data link type has not been changed
      printf("\nYour pcap file looks proper. Nothing to fix!\n\n");
      remove(filename_fix);	// delete output file due to nothing changed
    } else { // the user forces a new data link type, then we dont remove the file even if no corruption was detected
      printf("\nYour pcap file looks proper. Only data link type has been changed.\n\n");
    }
  } else if (pkt_integ == 9999) {	// check vor very high packet failure value ==> no recovery possible
    if (count == 1) {	// if count == 1 then even the first packet was corrupted and no other packet could be found
      printf("\nThis file does not seem to be a pcap file!\n\n");
    } else {	// the first packet was intact, but recovery is not possible nevertheless
      printf("\nUnable to recover pcap file.\n\n");
    }
    remove(filename_fix);	// delete output file due to repair impossible
  } else {	// if anything had to be corrected
    printf("\nYour pcap file has been successfully repaired.\n");
    printf("Wrote %u packets to file %s.\n\n", count-1, filename_fix);
  }

  return(0);
}
