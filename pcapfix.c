/*******************************************************************************
 *
 * pcapfix.c - pcap file repair tool
 * Copyright (c) 2012 Robert Krause (ruport@f00l.de)
 * License: GPLv3
 *
 * Last Modified: 05.05.2012
 *
 * Command line: pcapfix [-v] [-t link_type] <pcap_file>
 *
 * Description:
 *
 * pcapfix is a repair tool for corrupted pcap files. It checks for an intact
 * pcap global header and repairs it if there are any corrupted bytes. If one
 * is not present, one is created and added to the beginning of the file. It
 * then tries to find pcap packet headers, and checks and repairs them.
 *
 * Algorithm:
 *
 * pcapfix will first step through the packets top down until it recognizes a
 * corrupted one by using plausibility checks. After that the tool will brute
 * force further pcap packet headers by reading the file byte by byte. If another
 * proper packet is found, pcapfix restores the data in between by adding a
 * well-formed pcap packet header.
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

#define VERSION "0.5"		// pcapfix version
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

// usage()
// print out the usage information
// IN: progname - the program name
void usage(char *progname) {
  printf("Usage: %s [OPTIONS] filename\n", progname);
  printf("OPTIONS:");
  printf(  "\t-t <nr>, --data-link-type <nr>\tData link type\n");
  printf("\t\t-v     , --verbose            \tVerbose output\n");
  printf("\n");
}

/* check_header()
   check if the pcap packet header could be a plausible one by satisfying those conditions:
   ==> packet size >= 16 bytes AND <= 65535 bytes (included length AND original length)
   ==> included length <= original lenth
   ==> packet timestamp is NOT older OR younger than the prior packets timestamp -+ one day
   IN: hdr - packet to check
   IN: priot_ts - the prior packets timestamp
   OUT: 0 - if packet is correct
   OUT: >0 - the plausability check that failed
*/
int check_header(struct packet_hdr_s hdr, unsigned int prior_ts) {
  // check for minimal packet size
  if (hdr.incl_len < 16) return(1);
  if (hdr.orig_len < 16) return(2);

  // check max maximal packet size
  if (hdr.incl_len > 65535) return(3);
  if (hdr.orig_len > 65535) return(4);

  // the included lenth CAN NOT be larger than the original length
  if (hdr.incl_len > hdr.orig_len) return(5);

  // packet is not older than one day
  if ((prior_ts != 0) && (hdr.ts_sec > prior_ts+86400)) return(6);

  // packet is not younger than one day
  if ((prior_ts >= 86400) && (hdr.ts_sec < prior_ts-86400)) return(7);

  // everything fine!
  return(0);
}

// print_progress()
// prints the progess bar
// IN: pos - the current filepointer position
// IN: filesize - the size of the file
void print_progress(unsigned long pos, unsigned long filesize) {
  int i;		// loop counter
  float percentage;	// pencentage variable

  // calculate the current percentage of file analyzing progress
  percentage = (float)pos/(float)filesize;

  // print the first part of the line including percentage output
  printf("[*] Progress: %5.2f %% [", percentage*100);

  // output progress bar (width = 50 chars)
  for (i=1; i<=percentage*50 ;i++) printf("=");	// calculate and output "="-signs
  printf(">");					// output arrow peak
  for (i=percentage*50; i<50; i++) printf(" ");	// calculate and output spaces

  // clear the line and carriage return
  printf("]\n\033[F\033[J");
}

// main()
// IN: argc - number of cmd line args
// IN: argv - array of cmd line args
// OUT: always zero
int main(int argc, char *argv[]) {
  FILE *pcap, *pcap_fix;			// input and output file
  struct global_hdr_s global_hdr;		// global header data
  struct packet_hdr_s packet_hdr;		// packet header data
  struct packet_hdr_s next_packet_hdr;		// next packet header data to look forward
  char buffer[65535];				// the packet body

  unsigned long pos = 0;			// position of current packet header
  unsigned long nextpos = 0;			// possible position of next packets header
  unsigned long filesize;			// file size
  unsigned int count;				// packet counter
  unsigned int last_correct_ts_sec = 0;		// timestamp of the last proper packet found (seconds)
  unsigned int last_correct_ts_usec = 0;	// timestamp of the last proper packet found (microseconds)
  unsigned short hdr_integ;			// integrity counter of global header
  int c;					// loop counter
  int option_index = 0;				// getopt_long option index
  int ascii = 0;				// ascii counter for possible ascii-corrupted packets
  int corrupted = 0;			// corrupted packet counter for final output

  // configuration variables
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
    _splitpath(filename, NULL, NULL, filebname, NULL);	// windown method (_splitpath)
  # else
    strcpy(filebname, basename(filename));		// unix method (basename)
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

  // get file size
  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);

  fseek(pcap, 0, SEEK_SET);

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

  // does the user provides a self-supplied data link type? if yes... change global header
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

  /* this loop iterates the packets from top till down by checking the
     pcap packet headers on plausibility. if any packet header has got
     implausible information the packet will be handled as corrupted
     and pcapfix will brute force the next packet. if the packet header
     look plausible, pcapfix will check if the next packet is aligned and
     if not check for overlapping packets.
  */

  pos = ftell(pcap);	// get current file pointer position

  // loop the pcap files packets until pos has reacher end of file
  for (count=1; pos < filesize; count++) {

    // we only want the progress bar to be printed in non-verbose mode
    if (verbose == 0) print_progress(pos, filesize);

    // read the next packet header
    fread(&packet_hdr, sizeof(packet_hdr), 1, pcap);

    // check if the packet header looks proper
    if (check_header(packet_hdr, last_correct_ts_sec) == 0) {

      // CUT OF LAST PACKET DETECTION

      // try to read the whole packet body
      if (fread(&buffer, packet_hdr.incl_len, 1, pcap) == 0) {
	// fread returned an error ==> we requested more data than the file has
	// thou the last packet has been cut of
        if (verbose >= 1) printf("[-] File has been cut off! ==> CORRECTING LAST PACKET\n");

	// correct the packets included length field to match the end of file
        packet_hdr.incl_len = filesize-pos-16;

	// print out information
        printf("[+] CORRECTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
	corrupted++;
      }

      // OVERLAPPING DETECTION
      // we do ONLY scan for overlapping if next packet is NOT aligned

      // read next packet header
      fread(&next_packet_hdr, sizeof(next_packet_hdr), 1, pcap);

      // check if next packets header looks proper
      if (check_header(next_packet_hdr, packet_hdr.ts_sec) != 0) {

        // the next packets header is corrupted thou we are going to scan through the prior packets body to look for an overlapped packet header
        for (nextpos=pos+16+1; nextpos < pos+16+packet_hdr.incl_len+32; nextpos++) {	// also look inside the next packets header + 16bytes of packet body, because we need to know HERE

          // read the possible next packets header
          fseek(pcap, nextpos, SEEK_SET);
          fread(&next_packet_hdr, sizeof(next_packet_hdr), 1, pcap);

          // heavy verbose output :-)
          if (verbose >= 2) printf("[*] Trying Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, next_packet_hdr.ts_sec, next_packet_hdr.ts_usec, next_packet_hdr.incl_len, next_packet_hdr.orig_len);

          // check the header for plausibility
          if (check_header(next_packet_hdr, last_correct_ts_sec) == 0) {

            // we found a proper header inside the packets body!
            if (verbose >= 1) printf("[-] FOUND OVERLAPPING data of Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, next_packet_hdr.ts_sec, next_packet_hdr.ts_usec, next_packet_hdr.incl_len, next_packet_hdr.orig_len);

            // correct the prior packets length information fields to align the overlapped packet
            packet_hdr.incl_len = nextpos-(pos+16);
            packet_hdr.orig_len = packet_hdr.incl_len;

            // print out information
            printf("[+] CORRECTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
            corrupted++;

            // overlapping seems to be a result of ascii-transfered pcap files via FTP
            ascii++;

            break;
          }
        }
      }

      // reset file fointer to next packet
      fseek(pcap, pos+16+packet_hdr.incl_len, SEEK_SET);

      // we found a correct packet (and aligned it maybe)
      if (verbose >= 1) printf("[+] Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);

      // write last packet
      fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
      fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);	// write packet body to output file

      // remember that this packets timestamp to evaluate futher timestamps
      last_correct_ts_sec = packet_hdr.ts_sec;
      last_correct_ts_usec = packet_hdr.ts_usec;

    } else {

      // PACKET IS CORRUPT

      if (verbose >= 1) printf("[-] CORRUPTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);

      // scan from the current position to the maximum packet size and look for a next proper packet header to align the corrupted packet
      for (nextpos=pos+16+1; nextpos < pos+16+65535; nextpos++) {

        // read the possible next packets header
	fseek(pcap, nextpos, SEEK_SET);
        fread(&next_packet_hdr, sizeof(next_packet_hdr), 1, pcap);

        // heavy verbose output :-)
        if (verbose >= 2) printf("[*] Trying Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, next_packet_hdr.ts_sec, next_packet_hdr.ts_usec, next_packet_hdr.incl_len, next_packet_hdr.orig_len);

        // check if next packets header looks proper
        if (check_header(next_packet_hdr, last_correct_ts_sec) == 0) {

          // we found the NEXT packets header, now we are able to align the corrupted packet
          if (verbose >= 1) printf("[+] FOUND NEXT Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, next_packet_hdr.ts_sec, next_packet_hdr.ts_usec, next_packet_hdr.incl_len, next_packet_hdr.orig_len);

          // correct the corrupted pcap packet header to match the just found next packet header
	  packet_hdr.incl_len = nextpos-(pos+16);
	  packet_hdr.orig_len = packet_hdr.incl_len;
	  packet_hdr.ts_sec = last_correct_ts_sec;
	  packet_hdr.ts_usec = last_correct_ts_usec+1;

          // read the packets body (size based on the just found next packets position)
          fseek(pcap, pos+16, SEEK_SET);
          fread(&buffer, packet_hdr.incl_len, 1, pcap);

          // write repaired packet header and packet body
          fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
          fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);	// write packet body to output file

          // remember that this packets timestamp to evaluate futher timestamps
          last_correct_ts_sec = packet_hdr.ts_sec;
          last_correct_ts_usec = packet_hdr.ts_usec;

          // print out information
          printf("[+] CORRECTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
	  corrupted++;

          break;
        }

      }

      // did the counter exceed the maximum packet size?
      if (nextpos >= pos+16+65535) {

        // PACKET COULD NOT BE REPAIRED!

        if (verbose >= 1) printf("[-] Cannot align corrupted packet! \n");
        break;
      }

    }

    pos = ftell(pcap);	// get current file pointer position

  }

  // did we reach the end of pcap file?
  if (pos == filesize) { // yes ==> all data processed == SUCCESS
    printf("[+] Success!\n\n");
  } else { // no ==> data missing == FAILED
    printf("[-] Failed!\n\n");
    corrupted = -1;	// the file could not be repaired
  }

  // END PACKET CHECK

  // close files
  fclose(pcap);
  fclose(pcap_fix);

  // evaluate result
  if ((hdr_integ == 0) && (corrupted == 0)) {	// check allover failure / integrity count and corrupted counter
    if (data_link_type == 1) { 	// data link type has not been changed
      printf("Your pcap file looks proper. Nothing to fix!\n\n");
      remove(filename_fix);	// delete output file due to nothing changed
    } else { // the user forces a new data link type, then we dont remove the file even if no corruption was detected
      printf("Your pcap file looks proper. Only data link type has been changed.\n\n");
    }
  } else if (corrupted == -1) {	// check vor very high packet failure value ==> no recovery possible
    if (count == 1) {	// if count == 1 then even the first packet was corrupted and no other packet could be found
      printf("This file does not seem to be a pcap file!\n\n");
    } else {	// the first packet was intact, but recovery is not possible nevertheless
      printf("Unable to recover pcap file.\n\n");
      if (!verbose) printf("Try executing pcapfix with -v option to trace the corruption!\n");
      printf("You may help improving pcapfix by sending your pcap file to ruport@f00l.de\n\n");
    }
    remove(filename_fix);	// delete output file due to repair impossible
  } else {	// if anything had to be corrected
    printf("Your pcap file has been successfully repaired (%d corrupted packet(s)).\n", corrupted);
    printf("Wrote %u packets to file %s.\n\n", count-1, filename_fix);

    // are there any packets that might have been transfered in ascii mode?
    if (ascii) {
      printf("This corruption seems to be a result of an ascii-mode transfered pcap file via FTP.\n");
      printf("The pcap structure of those files can be repaired, but the data inside might still be corrupted!!!\n\n");
    }

  }

  return(0);
}

