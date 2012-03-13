// see: http://v2.nat32.com/pcap.htm
// TODO: recover / detect swapped data
// TODO: thiszone MUST be zero? if not implement it...
// TODO: detect multiple network types
// TODO: more than 0xffff snaplen

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#define VERSION "0.1"
#define PCAP_MAGIC 0xa1b2c3d4

// GLOBAL HEADER
struct global_hdr_s {
        unsigned int magic_number;   	/* magic number */
        unsigned short version_major;  	/* major version number */
        unsigned short version_minor;  	/* minor version number */
        signed int thiszone;       	/* GMT to local correction */
        unsigned int sigfigs;        	/* accuracy of timestamps */
        unsigned int snaplen;        	/* max length of captured packets, in octets */
        unsigned int network;        	/* data link type */
};

// PACKET HEADER
struct packet_hdr_s {
        unsigned int ts_sec;         /* timestamp seconds */
        unsigned int ts_usec;        /* timestamp microseconds */
        unsigned int incl_len;       /* number of octets of packet saved in file */
        unsigned int orig_len;       /* actual length of packet */
};

void usage(char *progname) {
  printf("Usage: %s [OPTIONS] filename\n", progname);
  printf("OPTIONS:", progname);
  printf("\t-v, --verbose\tVerbose output\n", progname);
  printf("\n");
}

int main(int argc, char *argv[]) {

  FILE *pcap, *pcap_fix;
  unsigned long pos;
  unsigned int count;
  unsigned int last_correct_ts_sec = 0;
  unsigned int last_correct_ts_usec = 0;
  unsigned long last_correct_lower_pos;
  unsigned long last_correct_upper_pos;
  int size;
  int ret;
  int c;
  int verbose = 0;
  unsigned short hdr_integ, pkt_integ;
  struct global_hdr_s global_hdr;
  struct packet_hdr_s packet_hdr;
  char buffer[65535];

  struct option long_options[] = {
    {"verbose", no_argument,       &verbose, 1},
    {0, 0, 0, 0}
  };

  /* getopt_long stores the option index here. */
  int option_index = 0;

  // HEADER + OPTIONS

  printf("pcapfix %s (c) 2012 Robert Krause\n\n", VERSION);

  while ((c = getopt_long(argc, argv, ":v::", long_options, &option_index)) != -1) {
    switch (c) {
      case 0:
        long_options[option_index].flag;
        break;
      case 'v':
        verbose = 1;
        break;
      case '?':
        usage(argv[0]);
        return 1;
      default:
        abort();
    }
  }

  char *filename = (char*)basename(argv[optind]);

  if (filename == NULL) {
    usage(argv[0]);
    return(1);
  }

  char filename_fix[strlen(filename)+6];

  // BEGIN INIT

  // OPEN INPUT FILE
  printf("[*] Reading from file: %s\n", filename);
  pcap = fopen(filename, "r");
  if (!pcap) {
    perror("[-] Cannot open input file");
    return(1);
  }

  // OPEN OUTPUT FILE
  strcpy(filename_fix, "fixed_");
  strcat(filename_fix, filename);
  printf("[*] Writing to file: %s\n", filename_fix);
  pcap_fix = fopen(filename_fix, "w");
  if (!pcap_fix) {
    perror("[-] Cannot open output file");
    return(1);
  }

  // CHECK GLOBAL HEADER
  printf("[*] Analyzing global header...\n");
  fread(&global_hdr, sizeof(global_hdr), 1, pcap);

  hdr_integ = 0;
  if (global_hdr.magic_number == PCAP_MAGIC) {
    if (verbose) printf("[+] Magic number: 0x%x\n", global_hdr.magic_number);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Magic number: 0x%x\n", global_hdr.magic_number);
    global_hdr.magic_number = PCAP_MAGIC;
  }
  if (global_hdr.version_major == 2) {
    if (verbose) printf("[+] Major version number: %hu\n", global_hdr.version_major);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Major version number: %hu\n", global_hdr.version_major);
    global_hdr.version_major = 2;
  }
  if (global_hdr.version_minor == 4) {
    if (verbose) printf("[+] Minor version number: %hu\n", global_hdr.version_minor);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Minor version number: %hu\n", global_hdr.version_minor);
    global_hdr.version_minor = 4;
  }
  if (global_hdr.thiszone == 0) {
    if (verbose) printf("[+] GTM to local correction: %d\n", global_hdr.thiszone);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] GTM to local correction: %d\n", global_hdr.thiszone);
    global_hdr.thiszone = 0;
  }
  if (global_hdr.sigfigs == 0) {
    if (verbose) printf("[+] Accuracy of timestamps: %u\n", global_hdr.sigfigs);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Accuracy of timestamps: %u\n", global_hdr.sigfigs);
    global_hdr.sigfigs = 0;
  }
  if (global_hdr.snaplen <= 0xffff) {
    if (verbose) printf("[+] Max packet length: %u\n", global_hdr.snaplen);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Max packet length: %u\n", global_hdr.snaplen);
    global_hdr.snaplen = 0xffff;
  }
  if (global_hdr.network == 1) {
    if (verbose) printf("[+] Data link type: %u\n", global_hdr.network);
  } else {
    hdr_integ++;
    if (verbose) printf("[-] Data link type: %u\n", global_hdr.network);
    global_hdr.network = 1;
  }
  if (hdr_integ == 0) {
    printf("[+] The global pcap header seems to be fine!\n");
  } else if (hdr_integ >= 6) {
    printf("[-] The global pcap header seems to be missing ==> CORRECTED!\n");
    fseek(pcap, 0, SEEK_SET);
  } else {
    printf("[-] The global pcap header seems to corrupt! ==> CORRECTED\n");
  }
  fwrite(&global_hdr, sizeof(global_hdr), 1, pcap_fix);

  // CHECK PACKETS
  printf("[*] Analyzing packets...\n");

  pkt_integ = 0;
  pos = ftell(pcap);
  for (count=1; fread(&packet_hdr, sizeof(packet_hdr), 1, pcap) > 0; count++) {
    if (packet_hdr.incl_len <= 0xffff) {
      if (verbose) printf("[+] Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
      fread(&buffer, packet_hdr.incl_len, 1, pcap);
      fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);
      fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);
      last_correct_ts_sec = packet_hdr.ts_sec;
      last_correct_ts_usec = packet_hdr.ts_usec;
      last_correct_upper_pos = pos+packet_hdr.incl_len+16;
    } else {
      pkt_integ++;
      if (verbose) printf("[-] Corrupted packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
      else printf("[-] Corrupted packet found ==> TRYING TO RECOVER\n");
      break;
    }
    pos = ftell(pcap);
  };


  // BOTTOM UP RECOVERY

  if (pkt_integ > 0) {
    if (verbose) printf("[*] Recovering");

    fseek(pcap, 0, SEEK_END);
    pos = ftell(pcap);

    size = 0;
    for(pos -= 16; pos > 0; pos--) {
      fseek(pcap, pos, SEEK_SET);
      fread(&packet_hdr, sizeof(packet_hdr), 1, pcap);
//      printf("[*] Trying position %ld (%u | %u | %u | %u)).\n", pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
//      printf("    Size MUST be %d\n", size);
      if ((packet_hdr.incl_len == size) && (packet_hdr.incl_len >= 54) && (packet_hdr.incl_len <= 0xffff) && (packet_hdr.ts_sec >= last_correct_ts_sec)) {
//        printf("[+] Found packet at position %ld (%u | %u | %u | %u).\n", pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
        if (verbose) printf(".");
	last_correct_lower_pos = pos;
        pos -= 15;	// skip packet header (plus -1 by loop)
        size = 0;
      } else { size++; }
    }
    if (verbose) printf("\n");
    else printf("[+] SUCCESS!\n");

    // REBUILD DAMAGED PACKET HERE
//    printf("\nRebuilding damaged packet\n");
    packet_hdr.ts_sec = last_correct_ts_sec;
    packet_hdr.ts_usec = last_correct_ts_usec+1;
    packet_hdr.incl_len = last_correct_lower_pos-last_correct_upper_pos;
    packet_hdr.orig_len = last_correct_lower_pos-last_correct_upper_pos;
    if (verbose) printf("[+] RECOVERED Packet #%u at position %ld (%u | %u | %u | %u).\n", count, last_correct_upper_pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
    count++;

    // WRITE NEW HEADER
    fseek(pcap, last_correct_upper_pos, SEEK_SET);
    fread(&buffer, packet_hdr.incl_len, 1, pcap);
    fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);
    fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);

    // CONTINUE WRITING PACKETS TO FILE
    pos = ftell(pcap);
    for (; fread(&packet_hdr, sizeof(packet_hdr), 1, pcap) > 0; count++) {
      if (verbose) printf("[+] Packet #%u at position %ld (%u | %u | %u | %u).\n", count, pos, packet_hdr.ts_sec, packet_hdr.ts_usec, packet_hdr.incl_len, packet_hdr.orig_len);
      fread(&buffer, packet_hdr.incl_len, 1, pcap);
      fwrite(&packet_hdr, sizeof(packet_hdr), 1, pcap_fix);
      fwrite(&buffer, packet_hdr.incl_len, 1, pcap_fix);
      pos = ftell(pcap);
    };

  }

  // CLOSE FILES
  fclose(pcap);
  fclose(pcap_fix);

  // RESULT
  if ((hdr_integ+pkt_integ) == 0) {
    printf("\nYour pcap file looks proper. Nothing to fix!\n\n");
    remove(filename_fix);
  } else {
    printf("\nYour pcap file has been successfully repaired.\n");
    printf("Wrote %u packets to file %s.\n\n", count-1, filename_fix);
  }

  return(0);
}
