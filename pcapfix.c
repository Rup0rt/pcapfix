/*******************************************************************************
 *
 * pcapfix.c - pcap file repair tool
 * Copyright (c) 2012-2013 Robert Krause (ruport@f00l.de)
 * License: GPLv3
 *
 * Last Modified: 09.09.2013
 *
 * Command line: pcapfix [-v] [-d] [-t link_type] <pcap_file>
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#ifdef __WIN32__
  #include <Winsock.h>   		// needed for htons,htonl on windows systems
#else
  #include <libgen.h>    		// needed for basename
  #include <arpa/inet.h>		// htons, htonl
#endif

#define VERSION "1.0.0"			// pcapfix version

#define PCAP_MAGIC 0xa1b2c3d4			// the magic of the pcap global header (non swapped)
#define PCAPNG_MAGIC 0x0a0d0d0a			// the magic of the pcap global header (non swapped)
#define PCAP_NSEC_MAGIC 0xa1b23c4d		// the magic of the pcap global header (nanoseconds - non swapped)
#define SNOOP_MAGIC 0x6f6f6e73ULL	// snoop packet magic (first 4 bytes)

#define BYTE_ORDER_MAGIC 0x1a2b3c4d

#define TYPE_SHB 0x0A0D0D0A
#define TYPE_IDB 0x00000001
#define TYPE_PB  0x00000002
#define TYPE_SPB 0x00000003
#define TYPE_NRB 0x00000004
#define TYPE_ISB 0x00000005
#define TYPE_EPB 0x00000006

int fix_pcap(FILE *pcap, FILE *pcap_fix);
int fix_pcapng(FILE *pcap, FILE *pcap_fix);

int swapped = 0;			// pcap file is swapped (big endian)
int nanoseconds = 0;			// pcap file uses nanoseconds (instead of microseconds)

// configuration variables
int data_link_type = 1;			// data link type (default: LINKTYPE_ETHERNET)
int verbose = 0;				// verbose output option (default: dont be verbose)
int deep_scan = 0;				// deep scan option (default: no depp scan)

// header placeholder
unsigned int header_magic;

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

struct block_header {
	u_int32_t	block_type;
	u_int32_t	total_length;
};

struct section_header_block {
	u_int32_t	byte_order_magic;
	u_short		major_version;
	u_short		minor_version;
	u_int64_t	section_length;
};

struct option_header {
	u_short		option_code;
	u_short		option_length;
};

struct interface_description_block {
	u_short		linktype;
	u_short		reserved;
	u_int32_t	snaplen;
};

struct name_resolution_block {
	u_short		record_type;
	u_short		record_length;
};

struct enhanced_packet_block {
	u_int32_t	interface_id;
	u_int32_t	timestamp_high;
	u_int32_t	timestamp_low;
	u_int32_t	caplen;
	u_int32_t	len;
};

struct interface_statistics_block {
	u_int32_t	interface_id;
	u_int32_t	timestamp_high;
	u_int32_t	timestamp_low;
};

struct simple_packet_block {
	u_int32_t	len;
};

struct packet_block {
	u_short		interface_id;
	u_short		drops_count;
	u_int32_t	timestamp_high;
	u_int32_t	timestamp_low;
	u_int32_t	caplen;
	u_int32_t	len;
};

// usage()
// print out the usage information
// IN: progname - the program name
void usage(char *progname) {
  printf("Usage: %s [OPTIONS] filename\n", progname);
  printf("OPTIONS:");
  printf(  "\t-t <nr>, --data-link-type <nr>\tData link type\n");
  printf("\t\t-d     , --deep-scan          \tDeep scan\n");
  printf("\t\t-v     , --verbose            \tVerbose output\n");
  printf("\n");
}

/* conshort()
   converts a short variable to network byte order in case of swapped pcap file
   IN: var - variable to convert
   OUT: var in correct notation (swapped / non-swapped)
*/
unsigned short conshort(unsigned short var) {
  if (swapped == 0) return(var);
  return(htons(var));
}

/* conint()
   converts an integer variable to network byte order in case of swapped pcap file
   IN: var - variable to convert
   OUT: var in correct notation (swapped / non-swapped)
*/
unsigned int conint(unsigned int var) {
  if (swapped == 0) return(var);
  return(htonl(var));
}

/* is_plausible()
   check if the pcap packet header could be a plausible one by satisfying those conditions:
   ==> packet size >= 16 bytes AND <= 65535 bytes (included length AND original length) (conditions 1,2,3,4)
   ==> included length <= original lenth (condition 5)
   ==> packet timestamp is NOT older OR younger than the prior packets timestamp -+ one day (conditions 6,7)
   ==> usec (microseconds) field >= 0 AND <= 1000000 (conditions 8,9)
   IN: hdr - packet to check
   IN: priot_ts - the prior packets timestamp
   OUT: 0 - if packet is correct
   OUT: >0 - the condition that failed
*/
int is_plausible(struct packet_hdr_s hdr, unsigned int prior_ts) {
  // check for minimum packet size
  // minimum packet size should be 16, but in some cases, e.g. local wlan capture, packet might
  // even be smaller --> decreased minimum size to 10
  if (conint(hdr.incl_len) < 10) return(1);
  if (conint(hdr.orig_len) < 10) return(2);

  // check max maximum packet size
  if (conint(hdr.incl_len) > 65535) return(3);
  if (conint(hdr.orig_len) > 65535) return(4);

  // the included length CAN NOT be larger than the original length
  if (conint(hdr.incl_len) > conint(hdr.orig_len)) return(5);

  // packet is not older than one day (related to prior packet)
  if ((prior_ts != 0) && (conint(hdr.ts_sec) > (prior_ts+86400))) return(6);

  // packet is not younger than one day (related to prior packet)
  if ((prior_ts >= 86400) && (conint(hdr.ts_sec) < (prior_ts-86400))) return(7);

  // check for nano/microseconds
  if (nanoseconds == 0) {
    // usec (microseconds) must be > 0 AND <= 1000000
    if (conint(hdr.ts_usec) < 0) return(8);
    if (conint(hdr.ts_usec) > 1000000) return(9);
  } else {
    // usec (nanoseconds) must be > 0 AND <= 1000000000
    if (conint(hdr.ts_usec) < 0) return(8);
    if (conint(hdr.ts_usec) > 1000000000) return(9);
  }

  // all conditions fullfilled ==> everything fine!
  return(0);
}

/* check_header()
   this function takes a buffer and brute forces some possible ascii-corrupted bytes versus plausibility checks
   IN: *buffer - the buffer that might contain the possible pcap packet header
   IN: size - the size of the buffer (i choose double pcap packet header size)
   IN: priot_ts - the prior packets timestamp (to check for plausibility)
   IN: *hdr - the pointer to the packet header buffer (we use this to return the repaired header)
   OUT: -1 - if there is NO pcap packet header inside the buffer (after ascii-corrution brute force)
   OUT: >=0 - the number of ascii-corrupted bytes inside the *hdr (we need this data to align the beginning of the packet body later)
*/
int check_header(char *buffer, unsigned int size, unsigned int prior_ts, struct packet_hdr_s *hdr) {
  int i, res;
  char tmp[size];	// the temporary buffer that will be used for recursion

  // does the buffer already contain a valid packet header (without any correction) ??
  memcpy(hdr, buffer, sizeof(struct packet_hdr_s));
  if (is_plausible(*hdr, prior_ts) == 0) return(0);

  // we need to abort the recursion of there are too many possible ascii corrupted bytes at ones
  // 32-25 = 7 bytes maximum in 32bytes of data!
  if (size <= 25) return(-1);

  // this loop will the the buffer for occurence of 0x0D + 0x0A (UNIX to WINDOWS ascii corruption)
  for(i=0; i<sizeof(struct packet_hdr_s); i++) {
    // is there a 0x0D 0X0A combination at this position?
    if (buffer[i] == 0x0D && buffer[i+1] == 0x0A) {

      // we cut out 0x0D because this byte could have been added due to ftp ascii transfer eg
      memcpy(tmp, buffer, i);
      memcpy(tmp+i, buffer+i+1, size-i-1);

      // and invoke the header again without this 0x0D byte
      res = check_header(tmp, size-1, prior_ts, hdr);

      // if the check was successfull (maybe with multiple recursions) return the value added by one (body shift offset)
      if (res != -1) return(res+1);
    }
  }

  // the buffer (even after ascii corruption brute force) does not contain any valid pcap packet header
  return(-1);
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
  int option_index = 0;				// getopt_long option index
  unsigned long filesize;			// file size
  int c;
  int res;
  char *filename;
  char *filebname;
  char *filename_fix;
  unsigned long bytes;				// read/written bytes counter (unused yet)

  // init getopt_long options struct
  struct option long_options[] = {
    {"data-link-type", required_argument, 0, 't'},		// --data-link-type == -t
    {"deep-scan", no_argument, 0, 'd'},				// --deep-scan == -d
    {"verbose", no_argument, 0, 'v'},				// --verbose == -v
    {0, 0, 0, 0}
  };

  // print out pcapfix header information
  printf("pcapfix %s (c) 2012-2013 Robert Krause\n\n", VERSION);

  // scan for options and arguments
  while ((c = getopt_long(argc, argv, ":t:v::d::", long_options, &option_index)) != -1) {
    switch (c) {
      case 0:	// getopt_long options evaluation
        break;
      case 'd':	// deep scan
        deep_scan++;
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
  filename = argv[optind++];

  // if filename is not set, output usage information
  if (filename == NULL) {
    usage(argv[0]);
    return(1);
  }

  // open input file
  printf("[*] Reading from file: %s\n", filename);
  pcap = fopen(filename, "rb");
  if (!pcap) {
    perror("[-] Cannot open input file");
    return(1);
  }

  // open output file
  // we need to extract the basename first (windows and linux use different functions)
  filebname = malloc(strlen(filename));
  #ifdef __WIN32__
    _splitpath(filename, NULL, NULL, filebname, NULL);	// windown method (_splitpath)
  # else
    strcpy(filebname, basename(filename));		// unix method (basename)
  #endif
  filename_fix = malloc(strlen(filebname)+6);	// size of outputfile depends on inputfile's length

  strcpy(filename_fix, "fixed_");		// outputfile = fixed_ + inputfile
  strcat(filename_fix, filebname);
  free(filebname);
  printf("[*] Writing to file: %s\n", filename_fix);
  pcap_fix = fopen(filename_fix, "wb");
  if (!pcap_fix) {
    perror("[-] Cannot open output file");
    return(1);
  }

  // BEGIN OF GLOBAL HEADER CHECK

  // get file size
  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);

  // check for empty file
  if (filesize == 0) {
    printf("[-] The source file is empty.\n\n");
    fclose(pcap);
    fclose(pcap_fix);
    remove(filename_fix);
    return(1);
  }

  fseek(pcap, 0, SEEK_SET);

  // read header to header magic for further inspection
  bytes = fread(&header_magic, sizeof(header_magic), 1, pcap);
  if (bytes == 0) {
    printf("[-] Cannot read file header (file too small?).\n\n");
    fclose(pcap);
    fclose(pcap_fix);
    remove(filename_fix);
    return(1);
  }
  fseek(pcap, 0, SEEK_SET);

  // check for known but not supported file types
  switch (header_magic) {
    case SNOOP_MAGIC:
      printf("[-] This is a SNOOP file, which is not supported yet.\n\n");
      fclose(pcap);
      fclose(pcap_fix);
      remove(filename_fix);
      return(-1);
    case PCAPNG_MAGIC:
      printf("[+] This is a PCAPNG file.\n");
      res = fix_pcapng(pcap, pcap_fix);
      break;
    case PCAP_MAGIC:
      printf("[+] This is a PCAP file.\n");
      res = fix_pcap(pcap, pcap_fix);
      break;
    default:
      printf("[*] Unknown filetype. Assuming PCAP format.\n");
      res = fix_pcap(pcap, pcap_fix);
      break;
  }

  switch (res) {
    case 0:
      // nothing to fix
      remove(filename_fix);	// delete output file due to nothing changed
      break;
    case -1:
      // reparation impossible
      remove(filename_fix);
      break;
    case 1:
      // fixed
      break;
  }

  // always return zero (might be changed later)
  return(0);
}

int fix_pcap(FILE *pcap, FILE *pcap_fix) {
  struct global_hdr_s global_hdr;		// global header data
  struct packet_hdr_s packet_hdr;		// packet header data
  struct packet_hdr_s next_packet_hdr;		// next packet header data to look forward

  char hdrbuffer[sizeof(packet_hdr)*2];		// the buffer that will be used to find a proper packet
  char buffer[65535];				// the packet body

  unsigned long pos = 0;			// position of current packet header
  unsigned long nextpos = 0;			// possible position of next packets header
  unsigned long bytes;				// read/written bytes counter (unused yet)
  unsigned int count;				// packet counter
  unsigned long filesize;
  unsigned int last_correct_ts_sec = 0;		// timestamp of the last proper packet found (seconds)
  unsigned int last_correct_ts_usec = 0;	// timestamp of the last proper packet found (microseconds or nanoseconds)
  unsigned short hdr_integ;			// integrity counter of global header
  int ascii = 0;				// ascii counter for possible ascii-corrupted packets
  int corrupted = 0;				// corrupted packet counter for final output
  int res;					// the result of the header check == the offset of body shifting

  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);
  fseek(pcap, 0, SEEK_SET);

  printf("[*] Analyzing Global Header...\n");
  bytes = fread(&global_hdr, sizeof(global_hdr), 1, pcap);	// read first bytes of input file into struct
  if (bytes != 1) return -1;

  hdr_integ = 0;

  // check for pcap's magic bytes ()
  if (global_hdr.magic_number == PCAP_MAGIC) {
    if (verbose) printf("[+] Magic number: 0x%x\n", global_hdr.magic_number);
  } else if (global_hdr.magic_number == htonl(PCAP_MAGIC)) {
    if (verbose) printf("[+] Magic number: 0x%x (SWAPPED)\n", global_hdr.magic_number);
    swapped = 1;
  } else if (global_hdr.magic_number == PCAP_NSEC_MAGIC) {
    if (verbose) printf("[+] Magic number: 0x%x (NANOSECONDS)\n", global_hdr.magic_number);
    nanoseconds = 1;
  } else if (global_hdr.magic_number == htonl(PCAP_NSEC_MAGIC)) {
    if (verbose) printf("[+] Magic number: 0x%x (SWAPPED - NANOSECONDS)\n", global_hdr.magic_number);
    swapped = 1;
    nanoseconds = 1;
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Magic number: 0x%x\n", global_hdr.magic_number);
    global_hdr.magic_number = PCAP_MAGIC;
  }

  // check for major version number (2)
  if (conshort(global_hdr.version_major) == 2) {	// current major version is 2
    if (verbose) printf("[+] Major version number: %hu\n", conshort(global_hdr.version_major));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Major version number: %hu\n", conshort(global_hdr.version_major));
    global_hdr.version_major = conshort(2);
  }

  // check for minor version number
  if (conshort(global_hdr.version_minor) == 4) {	// current minor version is 4
    if (verbose) printf("[+] Minor version number: %hu\n", conshort(global_hdr.version_minor));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Minor version number: %hu\n", conshort(global_hdr.version_minor));
    global_hdr.version_minor = conshort(4);
  }

  // check for GTM to local correction
  if (conshort(global_hdr.thiszone) == 0) {	// in practise time stamps are always in GTM, so the correction is always zero
    if (verbose) printf("[+] GTM to local correction: %d\n", conint(global_hdr.thiszone));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] GTM to local correction: %d\n", conint(global_hdr.thiszone));
    global_hdr.thiszone = conint(0);
  }

  // check for accuracy of timestamps
  if (conint(global_hdr.sigfigs) == 0) {	// all capture tools set this to zero
    if (verbose) printf("[+] Accuracy of timestamps: %u\n", conint(global_hdr.sigfigs));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Accuracy of timestamps: %u\n", conint(global_hdr.sigfigs));
    global_hdr.sigfigs = conint(0);
  }

  // check for max packet length
  if ((conint(global_hdr.snaplen) >= 0) && (conint(global_hdr.snaplen) <= 65535)) {	// typically 65535 (no support for huge packets yet)
    if (verbose) printf("[+] Max packet length: %u\n", conint(global_hdr.snaplen));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Max packet length: %u\n", conint(global_hdr.snaplen));
    global_hdr.snaplen = conint(65535);
  }

  // check for data link type (http://www.tcpdump.org/linktypes.html)
  if ((conint(global_hdr.network) >= 0) && (conint(global_hdr.network) <= 245)) {	// data link types are >= 0 and <= 245
    if (verbose) printf("[+] Data link type: %u\n", conint(global_hdr.network));
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Data link type: %u\n", conint(global_hdr.network));
    // if data link type is corrupt, we set it to ethernet (user supplied param will be processed later)
    global_hdr.network = conint(1);
  }

  // does the user provides a self-supplied data link type? if yes... change global header
  if (data_link_type != 1) {
    printf("[+] Changing data link type to %d.\n", data_link_type);
    global_hdr.network = conint(data_link_type);
  }

  // evaluate the integrity of the global header
  if (hdr_integ == 0) { // no field has been corrupted? --> header is intact
    printf("[+] The global pcap header seems to be fine!\n");
  } else if (hdr_integ >= 5) { // there have been five or more (of seven) corrupted fields? --> header is missing
    printf("[-] The global pcap header seems to be missing ==> CORRECTED!\n");
    /* we need to set the file pointer to the beginning of the file, because
       further packet search depends on this position and without a global
       header the first packet might begin there */
    fseek(pcap, 0, SEEK_SET);
  } else { // there have been corrupted fields (less than six) --> header is corrupted
    printf("[-] The global pcap header seems to corrupt! ==> CORRECTED\n");
  }

  // write the (maybe fixed) global header to output file
  bytes = fwrite(&global_hdr, sizeof(global_hdr), 1, pcap_fix);

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
    bytes = fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap);

    // check if the packet header looks proper
    res = check_header(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &packet_hdr);
    if (res != -1) {

      // realign packet body (based on possible-ascii corrupted pcap header)
      pos += res;
      fseek(pcap, pos+16, SEEK_SET);

      // try to read the packet body AND check if there are still at least 16 bytes left for the next pcap packet header
      if ((fread(&buffer, conint(packet_hdr.incl_len), 1, pcap) == 0) || ((filesize-(pos+16+res+conint(packet_hdr.incl_len)) > 0) && (filesize-(pos+16+res+conint(packet_hdr.incl_len)) < 16))) {
	// fread returned an error (EOL while read the body) or the file is not large enough for the next pcap packet header (16bytes)
	// thou the last packet has been cut of

        if (verbose >= 1) printf("[-] LAST PACKET MISMATCH (%u | %u | %u | %u)\n", conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

	// correct the packets included length field to match the end of file
        packet_hdr.incl_len = conint(filesize-pos-16);

        // the original length must not be smaller than the included length
        if (conint(packet_hdr.incl_len) > conint(packet_hdr.orig_len)) packet_hdr.orig_len = packet_hdr.incl_len;

	// print out information
        printf("[+] CORRECTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));
	corrupted++;
      }

      // OVERLAPPING DETECTION
      // we do ONLY scan for overlapping if next packet is NOT aligned

      // read next packet header
      bytes = fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap);

      // check if next packets header looks proper
      if (check_header(hdrbuffer, sizeof(hdrbuffer), conint(packet_hdr.ts_sec), &next_packet_hdr) == -1) {

        // the next packets header is corrupted thou we are going to scan through the prior packets body to look for an overlapped packet header
	// also look inside the next packets header + 16bytes of packet body, because we need to know HERE
	// do not leave the loop if the first packet has not been found yet AND deep scan mode is activated
        for (nextpos=pos+16+1; (nextpos < pos+16+conint(packet_hdr.incl_len)+32) || (count == 1 && deep_scan == 1); nextpos++) {

          // read the possible next packets header
          fseek(pcap, nextpos, SEEK_SET);
          bytes = fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap);

          // heavy verbose output :-)
          if (verbose >= 2) printf("[*] Trying Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

          // check the header for plausibility
	  res = check_header(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &next_packet_hdr);
          if (res != -1) {

            // we found a proper header inside the packets body!
            if (verbose >= 1) printf("[-] FOUND OVERLAPPING data of Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

            // correct the prior packets length information fields to align the overlapped packet
            packet_hdr.incl_len = conint(nextpos-(pos+16)+res);	// also include ascii corruption offset (res)
            packet_hdr.orig_len = packet_hdr.incl_len;

	    // time correction for the FIRST packet only
	    if (count == 1) {
	      if (conint(next_packet_hdr.ts_usec) > 0) {
		// next packets usec is > 0 ===> first packet will get same timestamp and usec - 1
		packet_hdr.ts_sec = next_packet_hdr.ts_sec;
		packet_hdr.ts_usec = conint(conint(next_packet_hdr.ts_usec)-1);
	      } else if(conint(next_packet_hdr.ts_sec) > 0) {
		// else: next packets timestamp i > 0 ===> firt packet will get timestamp -1 and maximum usec
		packet_hdr.ts_sec = conint(conint(next_packet_hdr.ts_sec)-1);
		packet_hdr.ts_usec = conint(999999);
  	      } else {
		// else: (next packets sec and usec are zero), this packet will get zero times as well
		packet_hdr.ts_sec = conint(0);
		packet_hdr.ts_usec = conint(0);
	      }
	    }

            // print out information
            printf("[+] CORRECTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));
            corrupted++;

            // overlapping seems to be a result of ascii-transferred pcap files via FTP
            ascii++;

            break;
          }
        }
      }

      // reset file fointer to next packet
      fseek(pcap, pos+16+conint(packet_hdr.incl_len), SEEK_SET);

      // we found a correct packet (and aligned it maybe)
      if (verbose >= 1) printf("[+] Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

      // write last packet
      bytes = fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
      bytes = fwrite(&buffer, conint(packet_hdr.incl_len), 1, pcap_fix);	// write packet body to output file

      // remember that this packets timestamp to evaluate futher timestamps
      last_correct_ts_sec = conint(packet_hdr.ts_sec);
      last_correct_ts_usec = conint(packet_hdr.ts_usec);

    } else {

      // PACKET IS CORRUPT

      if (verbose >= 1) printf("[-] CORRUPTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

      // scan from the current position to the maximum packet size and look for a next proper packet header to align the corrupted packet
      // also do not leave the loop if the first packet has not been found yet AND deep scan mode is activated
      for (nextpos=pos+16+1; (nextpos <= pos+16+65535) || (count == 1 && deep_scan == 1); nextpos++) {

        // read the possible next packets header
	fseek(pcap, nextpos, SEEK_SET);
        if (fread(hdrbuffer, sizeof(hdrbuffer), 1, pcap) == 0) {

	  // did we read over EOF AND havent found the first packet yet? then we need to abort!
          if ((count == 1) && (deep_scan == 1)) {

	    // abort scan
            pos = 0;
            corrupted = -1;
            break;
          }

          printf("[*] End of file reached. Aligning last packet.\n");

	  // align the last packet to match EOF
	  packet_hdr.incl_len = conint(filesize-(pos+16));
	  packet_hdr.orig_len = packet_hdr.incl_len;

	  // if the is the first packet, we need to set timestamps to zero
	  if (count == 1) {
	    packet_hdr.ts_sec = conint(0);
	    packet_hdr.ts_usec = conint(0);
	  } else {	// else take the last correct timestamp and usec plus one
	    packet_hdr.ts_sec = conint(last_correct_ts_sec);
	    packet_hdr.ts_usec = conint(last_correct_ts_usec+1);
	  }

          // read the packets body (size based on the just found next packets position)
          fseek(pcap, pos+16, SEEK_SET);
          bytes = fread(&buffer, conint(packet_hdr.incl_len), 1, pcap);

          // write repaired packet header and packet body
          bytes = fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
          bytes = fwrite(&buffer, conint(packet_hdr.incl_len), 1, pcap_fix);	// write packet body to output file

          // remember that this packets timestamp to evaluate futher timestamps
          last_correct_ts_sec = packet_hdr.ts_sec;
          last_correct_ts_usec = packet_hdr.ts_usec;

          // print out information
          printf("[+] CORRECTED LAST Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));
	  corrupted++;

	  break;
	}

	// shall we abord the whole scan??
	if (corrupted == -1) break;

        // heavy verbose output :-)
        if (verbose >= 2) printf("[*] Trying Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

        // check if next packets header looks proper
        res = check_header(hdrbuffer, sizeof(hdrbuffer), last_correct_ts_sec, &next_packet_hdr);
        if (res != -1) {

	  // if we found a packet that is below the top 65535 bytes (deep scan) we cut it off and take the second packet as first one
	  if ((nextpos-(pos+16) > 65535) && (count == 1) && (deep_scan == 1)) {

            if (verbose >= 1) printf("[+] (DEEP SCAN) FOUND FIRST Packet #%u at position %ld (%u | %u | %u | %u).\n", count, nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

	    // set the filepoint to the top of the first packet to be read in next loop iteration
	    fseek(pcap, nextpos, SEEK_SET);

	    // correct counter due to deep scan
	    count--;

	  } else { // found next packet (NO deep scan mode)
            // we found the NEXT packets header, now we are able to align the corrupted packet
            if (verbose >= 1) printf("[+] FOUND NEXT Packet #%u at position %ld (%u | %u | %u | %u).\n", (count+1), nextpos, conint(next_packet_hdr.ts_sec), conint(next_packet_hdr.ts_usec), conint(next_packet_hdr.incl_len), conint(next_packet_hdr.orig_len));

            // correct the corrupted pcap packet header to match the just found next packet header
	    packet_hdr.incl_len = conint(nextpos-(pos+16));
	    packet_hdr.orig_len = packet_hdr.incl_len;

	    if (count == 1) { // time correction for the FIRST packet
	      if (conint(next_packet_hdr.ts_usec) > 0) {
		// next packets usec is > 0 ===> first packet will get same timestamp and usec - 1
		packet_hdr.ts_sec = next_packet_hdr.ts_sec;
		packet_hdr.ts_usec = conint(conint(next_packet_hdr.ts_usec)-1);
	      } else if(conint(next_packet_hdr.ts_sec) > 0) {
		// else: next packets timestamp i > 0 ===> firt packet will get timestamp -1 and maximum usec
		packet_hdr.ts_sec = conint(conint(next_packet_hdr.ts_sec)-1);
		packet_hdr.ts_usec = conint(999999);
  	      } else {
		// else: (next packets sec and usec are zero), this packet will get zero times as well
		packet_hdr.ts_sec = conint(0);
		packet_hdr.ts_usec = conint(0);
	      }
	    } else { // ALL packets except the first one will use the last correct packets timestamps
	      packet_hdr.ts_sec = last_correct_ts_sec;
	      packet_hdr.ts_usec = conint(last_correct_ts_usec+1);
	    }

            // read the packets body (size based on the just found next packets position)
            fseek(pcap, pos+16, SEEK_SET);
            bytes = fread(&buffer, packet_hdr.incl_len, 1, pcap);

            // write repaired packet header and packet body
            bytes = fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);	// write packet header to output file
            bytes = fwrite(&buffer, conint(packet_hdr.incl_len), 1, pcap_fix);	// write packet body to output file

            // remember that this packets timestamp to evaluate futher timestamps
            last_correct_ts_sec = packet_hdr.ts_sec;
            last_correct_ts_usec = packet_hdr.ts_usec;

            // print out information
            printf("[+] CORRECTED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, conint(packet_hdr.ts_sec), conint(packet_hdr.ts_usec), conint(packet_hdr.incl_len), conint(packet_hdr.orig_len));

	  }

	  // increase corruption counter
	  corrupted++;

	  // leave the next packet search loop
          break;
        }

      }

      // shall we abort the whole scan (due to deep scan did not succeed at all)
      if (corrupted == -1) break;

      // did the counter exceed the maximum packet size?
      if ((count == 1 && deep_scan == 0) && (nextpos > pos+16+65535)) {

        // PACKET COULD NOT BE REPAIRED!

        if (verbose >= 1) printf("[-] Cannot align corrupted packet! \n");
        break;
      }

    }

    // get current file pointer position to start next loop iteration
    pos = ftell(pcap);

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

  // EVALUATE RESULT

  // no errors (header + packets correct)
  if ((hdr_integ == 0) && (corrupted == 0)) {	// check allover failure / integrity count and corrupted counter

    if (data_link_type == 1) { 	// data link type has not been changed
      printf("Your pcap file looks proper. Nothing to fix!\n\n");
      return(0);
    } else { // the user forces a new data link type, then we dont remove the file even if no corruption was detected
      printf("Your pcap file looks proper. Only data link type has been changed.\n\n");
    }

  // anything was corrupted

  // file could NOT be repaired
  } else if (corrupted == -1) {	// check vor very high packet failure value ==> no recovery possible

    // if count == 1 then even the first packet was corrupted and no other packet could be found
    if (count == 1) {
      printf("This file does not seem to be a pcap file!\n\n");

      // deep scan dependent output
      if (deep_scan == 0) printf("If you are SURE that there are pcap packets inside, try with deep scan option (-d) to find them!\n\n");
      else printf("There is REALLY no pcap packet inside this file!!!\n\n");

    // the first packet was intact, but recovery is not possible nevertheless
    } else {
      printf("Unable to recover pcap file.\n\n");
      if (!verbose) printf("Try executing pcapfix with -v option to trace the corruption!\n");
      printf("You may help improving pcapfix by sending your pcap file to ruport@f00l.de\n\n");
    }

    // delete output file due to repair impossible
    return(-1);

  // file has been successfully repaired (corruption fixed)
  } else {
    printf("Your pcap file has been successfully repaired (%d corrupted packet(s)).\n", corrupted);
// TODO: printf("Wrote %u packets to file %s.\n\n", count-1, filename_fix);

    // are there any packets that might have been transferred in ascii mode?
    if (ascii) {
      printf("This corruption seems to be a result of an ascii-mode transferred pcap file via FTP.\n");
      printf("The pcap structure of those files can be repaired, but the data inside might still be corrupted!!!\n\n");
    }

  }
  return(1);
}

int fix_pcapng(FILE *pcap, FILE *pcap_fix) {
  struct block_header bh;
  struct section_header_block shb;
  struct option_header oh;
  struct interface_description_block idb;
  struct name_resolution_block nrb;
  struct enhanced_packet_block epb;
  struct interface_statistics_block isb;
  struct packet_block pb;
  struct simple_packet_block spb;

  char *data;

  char *new_block;
  unsigned long block_pos;

  unsigned long bytes;
  unsigned int check;
  unsigned long padding;
  unsigned long pos;
  unsigned long filesize;
  signed long left;

  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);
  fseek(pcap, 0, SEEK_SET);

  pos = 0;

  // check block header ()
  while (pos < filesize) {
    printf("%ld / %ld\n", pos, filesize);

    bytes = fread(&bh, sizeof(bh), 1, pcap);	// read first bytes of input file into struct
    if (bytes != 1) return -1;

    printf("[*] Total Block Length: %u bytes\n", bh.total_length);
    left = bh.total_length-sizeof(bh)-sizeof(check);

    new_block = malloc(bh.total_length);
    memcpy(new_block, &bh, 8);
    block_pos = 8;

    switch (bh.block_type) {
      case TYPE_SHB:
        printf("[+] Section Header Block: 0x%08x\n", bh.block_type);
        bytes = fread(&shb, sizeof(shb), 1, pcap);	// read first bytes of input file into struct
        if (bytes != 1) return -1;

        left -= sizeof(shb);

        // check for pcap's magic bytes ()
        if (shb.byte_order_magic == BYTE_ORDER_MAGIC) {
          if (verbose) printf("[+] Byte Order Magic: 0x%x\n", shb.byte_order_magic);
        } else if (shb.byte_order_magic == htonl(BYTE_ORDER_MAGIC)) {
          if (verbose) printf("[+] Byte Order Magic: 0x%x (SWAPPED)\n", shb.byte_order_magic);
          swapped = 1;
        } else {
          if (verbose) printf("[-] Unknown Byte Order Magic: 0x%x\n", shb.byte_order_magic);
          shb.byte_order_magic = BYTE_ORDER_MAGIC;
        }

        // check for major version number (2)
        if (conshort(shb.major_version) == 1) {	// current major version is 2
          if (verbose) printf("[+] Major version number: %hu\n", conshort(shb.major_version));
        } else {
          if (verbose) printf("[-] Major version number: %hu\n", conshort(shb.major_version));
          shb.major_version = conshort(1);
        }

        // check for minor version number
        if (conshort(shb.minor_version) == 0) {	// current minor version is 4
          if (verbose) printf("[+] Minor version number: %hu\n", conshort(shb.minor_version));
        } else {
          if (verbose) printf("[-] Minor version number: %hu\n", conshort(shb.minor_version));
          shb.minor_version = conshort(0);
        }

        // section length
        printf("[*] Section length (we do not care): %ld\n", shb.section_length);

        memcpy(new_block+block_pos, &shb, sizeof(shb));
        block_pos += sizeof(shb);

        // options
        while (left > 0) {

          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -1;

          left -= sizeof(oh);

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          switch (oh.option_code) {
            case 0x00:
              printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            case 0x01:
              printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            case 0x02:
              printf("[+] OPTION: Hardware... (%u bytes)\n", oh.option_length);
              break;
            case 0x03:
              printf("[+] OPTION: Operation System... (%u bytes)\n", oh.option_length);
              break;
            case 0x04:
              printf("[+] OPTION: Userappl... (%u bytes)\n", oh.option_length);
              break;
            default:
              printf("[-] OPTION: Unknown option code: 0x%04x\n", oh.option_code);
              break;
          }

          // end of options
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }
        break;
      case TYPE_PB:
        printf("[+] Packet Block: 0x%08x\n", bh.block_type);
        bytes = fread(&pb, sizeof(pb), 1, pcap);	// read first bytes of input file into struct
        if (bytes != 1) return -1;

        left -= sizeof(pb);

        memcpy(new_block+block_pos, &pb, sizeof(pb));
        block_pos += sizeof(pb);

        padding = pb.caplen;
        if (pb.caplen % 4 != 0) padding += (4 - pb.caplen % 4);
        data = malloc(padding);
        fread(data, padding, 1, pcap);
        left -= padding;

        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        free(data);

        // options
        while (left > 0) {

          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -1;

          left -= sizeof(oh);

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          switch (oh.option_code) {
            case 0x00:
              printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            case 0x01:
              printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            case 0x02:
              printf("[+] OPTION: Link Layer Flags... (%u bytes)\n", oh.option_length);
              break;
            case 0x03:
              printf("[+] OPTION: Packet Hash... (%u bytes)\n", oh.option_length);
              break;
            default:
              printf("[-] OPTION: Unknown option code: 0x%04x\n", oh.option_code);
              break;
          }

          // end of options
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }

        break;
      case TYPE_SPB:
        printf("[+] Simple Packet Block: 0x%08x\n", bh.block_type);
        bytes = fread(&spb, sizeof(spb), 1, pcap);	// read first bytes of input file into struct
        if (bytes != 1) return -1;

        left -= sizeof(spb);

        memcpy(new_block+block_pos, &spb, sizeof(spb));
        block_pos += sizeof(spb);

        padding = spb.len;
        if (spb.len % 4 != 0) padding += (4 - spb.len % 4);
        data = malloc(padding);
        fread(data, padding, 1, pcap);
        left -= padding;

        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        free(data);

        break;
      case TYPE_IDB:
        printf("[+] Interface Description Block: 0x%08x\n", bh.block_type);
        bytes = fread(&idb, sizeof(idb), 1, pcap);	// read first bytes of input file into struct
        if (bytes != 1) return -1;

        left -= sizeof(idb);

        memcpy(new_block+block_pos, &idb, sizeof(idb));
        block_pos += sizeof(idb);

        while (left > 0) {

          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -1;

          left -= sizeof(oh);

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          switch (oh.option_code) {
            case 0x00:
              printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            case 0x01:
              printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            case 0x02:
              printf("[+] OPTION: Interface Name... (%u bytes)\n", oh.option_length);
              break;
            case 0x03:
              printf("[+] OPTION: Interface Description... (%u bytes)\n", oh.option_length);
              break;
            case 0x04:
              printf("[+] OPTION: IPv4 Address... (%u bytes)\n", oh.option_length);
              break;
            case 0x05:
              printf("[+] OPTION: IPv6 Address... (%u bytes)\n", oh.option_length);
              break;
            case 0x06:
              printf("[+] OPTION: MAC Address... (%u bytes)\n", oh.option_length);
              break;
            case 0x07:
              printf("[+] OPTION: EUI Address... (%u bytes)\n", oh.option_length);
              break;
            case 0x08:
              printf("[+] OPTION: Interface Speed... (%u bytes)\n", oh.option_length);
              break;
            case 0x09:
              printf("[+] OPTION: Resolution of Timestamps... (%u bytes)\n", oh.option_length);
              break;
            case 0x0a:
              printf("[+] OPTION: Timezone... (%u bytes)\n", oh.option_length);
              break;
            case 0x0b:
              printf("[+] OPTION: Filter expression... (%u bytes)\n",  oh.option_length);
              break;
            case 0x0c:
              printf("[+] OPTION: Operation System... (%u bytes)\n",  oh.option_length);
              break;
            case 0x0d:
              printf("[+] OPTION: Frame Check Sequence Length... (%u bytes)\n",  oh.option_length);
              break;
            case 0x0e:
              printf("[+] OPTION: Timestamp Offset... (%u bytes)\n",  oh.option_length);
              break;
            default:
              printf("[-] Unknown option code: 0x%04x\n", oh.option_code);
              break;
          }

          // end of options
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }

        break;
      case TYPE_NRB:
        printf("[+] Name Resolution Block: 0x%08x\n", bh.block_type);

        while(1) {
          bytes = fread(&nrb, sizeof(nrb), 1, pcap);	// read first bytes of input file into struct
          if (bytes != 1) return -1;

          left -= sizeof(nrb);

          memcpy(new_block+block_pos, &nrb, sizeof(nrb));
          block_pos += sizeof(nrb);

          switch (nrb.record_type) {
            case 0x00:
              printf("[+] RECORD: End of Records... (%u bytes)\n", nrb.record_length);
              break;
            case 0x01:
              printf("[+] RECORD: IPv4 Record... (%u bytes)\n", nrb.record_length);
              break;
            case 0x02:
              printf("[+] RECORD: IPv6 Record... (%u bytes)\n", nrb.record_length);
              break;
            default:
              printf("[-] RECORD: Unknown record type: 0x%04x\n", nrb.record_type);
              break;
          }

          // end of options
          if (nrb.record_type == 0x00 && nrb.record_length == 0x00) break;

          padding = nrb.record_length;
          if (nrb.record_length % 4 != 0) padding += (4 - nrb.record_length % 4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }

        // options
        while (left > 0) {

          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -1;

          left -= sizeof(oh);

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          switch (oh.option_code) {
            case 0x00:
              printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            case 0x01:
              printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            case 0x02:
              printf("[+] OPTION: DNS Server... (%u bytes)\n", oh.option_length);
              break;
            case 0x03:
              printf("[+] OPTION: IPv4 Address of DNS Server... (%u bytes)\n", oh.option_length);
              break;
            case 0x04:
              printf("[+] OPTION: IPv6 Address of DNS Server... (%u bytes)\n", oh.option_length);
              break;
            default:
              printf("[-] OPTION: Unknown option code: 0x%04x\n", oh.option_code);
              break;
          }

          // end of options
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }

        break;
      case TYPE_ISB:
        printf("[+] Interface Statistics Block: 0x%08x\n", bh.block_type);

        bytes = fread(&isb, sizeof(isb), 1, pcap);
        if (bytes != 1) return -1;

        left -= sizeof(isb);

        memcpy(new_block+block_pos, &isb, sizeof(isb));
        block_pos += sizeof(isb);

        // options
        while (left > 0) {

          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -1;

          left -= sizeof(oh);

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          switch (oh.option_code) {
            case 0x00:
              printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            case 0x01:
              printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            case 0x02:
              printf("[+] OPTION: Capture Start Time... (%u bytes)\n", oh.option_length);
              break;
            case 0x03:
              printf("[+] OPTION: Capture End Time... (%u bytes)\n", oh.option_length);
              break;
            case 0x04:
              printf("[+] OPTION: Packets recieved... (%u bytes)\n", oh.option_length);
              break;
            case 0x05:
              printf("[+] OPTION: Packets dropped... (%u bytes)\n", oh.option_length);
              break;
            case 0x06:
              printf("[+] OPTION: Filter packets accepted... (%u bytes)\n", oh.option_length);
              break;
            case 0x07:
              printf("[+] OPTION: Packets dropped by OS... (%u bytes)\n", oh.option_length);
              break;
            case 0x08:
              printf("[+] OPTION: Packets delivered to user... (%u bytes)\n", oh.option_length);
              break;
            default:
              printf("[-] OPTION: Unknown option code: 0x%04x\n", oh.option_code);
              break;
          }

          // end of options
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }

        break;
      case TYPE_EPB:
        printf("[+] Enhanced Packet Block: 0x%08x\n", bh.block_type);

        bytes = fread(&epb, sizeof(epb), 1, pcap);
        if (bytes != 1) return -1;

        left -= sizeof(epb);

        memcpy(new_block+block_pos, &epb, sizeof(epb));
        block_pos += sizeof(epb);

        padding = epb.caplen;
        if (epb.caplen % 4 != 0) padding += (4 - epb.caplen % 4);
        data = malloc(padding);
        fread(data, padding, 1, pcap);
        left -= padding;

        memcpy(new_block+block_pos, data, padding);
        block_pos += padding;

        free(data);

        // options
        while (left > 0) {

          bytes = fread(&oh, sizeof(oh), 1, pcap);
          if (bytes != 1) return -1;

          left -= sizeof(oh);

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

          switch (oh.option_code) {
            case 0x00:
              printf("[+] OPTION: End of Options... (%u bytes)\n", oh.option_length);
              break;
            case 0x01:
              printf("[+] OPTION: Comment... (%u bytes)\n", oh.option_length);
              break;
            case 0x02:
              printf("[+] OPTION: Link Layer Flags... (%u bytes)\n", oh.option_length);
              break;
            case 0x03:
              printf("[+] OPTION: Packet Hash... (%u bytes)\n", oh.option_length);
              break;
            case 0x04:
              printf("[+] OPTION: Dropped Packets Counter... (%u bytes)\n", oh.option_length);
              break;
            default:
              printf("[-] OPTION: Unknown option code: 0x%04x\n", oh.option_code);
              break;
          }

          // end of options
          if (oh.option_code == 0x00 && oh.option_length == 0x00) break;

          padding = oh.option_length;
          if (oh.option_length%4 != 0) padding += (4-oh.option_length%4);
          data = malloc(padding);
          fread(data, padding, 1, pcap);
          left -= padding;

          memcpy(new_block+block_pos, data, padding);
          block_pos += padding;

          free(data);

        }

        break;
      default:
        printf("[-] Unknown block type!: 0x%08x\n", bh.block_type);
        break;
    }

    if (left == 0) {
      printf("[+] End of Block reached... byte counter is correct!\n");
    } else {
      printf("[-] Something went wrong! This should not be the end of the block! (%ld bytes left)\n", left);
    }

    // check for correct block end (block size)
    bytes = fread(&check, sizeof(check), 1, pcap);
    if (bytes != 1) return -1;

    if (check == bh.total_length) {
      printf("[+] Block size matches (%u)!\n", check);
    } else {
      printf("[-] Block size mismatch (%u != %u)!\n", check, oh.option_length);
    }

    block_pos += 4;
    memcpy(new_block+4, &block_pos, 4);
    memcpy(new_block+block_pos-4, &block_pos, 4);

    printf("Writing %ld bytes...\n", block_pos);
    fwrite(new_block, block_pos, 1, pcap_fix);
    free(new_block);

    pos = ftell(pcap);
  }

  printf("SUCCESS\n");

  return(1);
}
