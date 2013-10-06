/*******************************************************************************
 *
 * pcapfix.c - pcap file repair tool
 * Copyright (c) 2012-2013 Robert Krause (ruport@f00l.de)
 * License: GPLv3
 *
 * Last Modified: 06.10.2013
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

#include "pcapfix.h"
#include "pcap.h"
#include "pcapng.h"

#define VERSION "1.0.0"			    /* pcapfix version */

#define SNOOP_MAGIC 0x6f6f6e73	/* snoop packet magic (first 4 bytes) */

/* configuration variables */
int deep_scan = 0;				      /* deep scan option (default: no deep scan) */
int verbose = 0;				        /* verbose output option (default: dont be verbose) */
int swapped = 0;			          /* pcap file is swapped (big endian) */
int data_link_type = 1;		      /* data link type (default: LINKTYPE_ETHERNET) */

/* header placeholder */
unsigned int header_magic;

/*
 * Function:  usage
 * ----------------
 * prints out the usage information of pcapfix
 * invoked when running without / with too less parameters
 *
 * in:  the name of pcapfix' binary file
 *
 */
void usage(char *progname) {
  printf("Usage: %s [OPTIONS] filename\n", progname);
  printf("OPTIONS:");
  printf(  "\t-t <nr>, --data-link-type <nr>\tData link type (pcap only)\n");
  printf("\t\t-d     , --deep-scan          \tDeep scan (pcap only)\n");
  printf("\t\t-v     , --verbose            \tVerbose output\n");
  printf("\n");
}

/*
 * Function:  conshort
 * -------------------
 * Convertes a short variable into correct byte order (if necessary)
 * depending on the global -swapped- settings of pcap data.
 *
 * This function MUST encapsulate all variables that might be swapped!
 *
 * var: the variable that shall be converted into correct byte order
 *
 * returns: the variable in correct byte order
 *
 */
unsigned short conshort(unsigned short var) {
  if (swapped == 0) return(var);
  return(htons(var));
}

/*
 * Function:  conint
 * -----------------
 * Convertes an integer variable into correct byte order (if necessary)
 * depending on the global -swapped- settings of pcap data.
 *
 * This function MUST encapsulate all variables that might be swapped!
 *
 * var: the variable that shall be converted into correct byte order
 *
 * returns: the variable in correct byte order
 *
 */
unsigned int conint(unsigned int var) {
  if (swapped == 0) return(var);
  return(htonl(var));
}

/*
 * Function:  print_progress
 * -------------------------
 * prints the progess bar when using pcapfix in non-verbose mode
 *
 * pos:       the current filepointer position
 * filesize:  the size of the input pcap file in bytes
 *
 */
void print_progress(unsigned long pos, unsigned long filesize) {
  int i;		        /* loop counter */
  float percentage;	/* pencentage variable */

  /* calculate the current percentage of file analyzing progress */
  percentage = (float)pos/(float)filesize;

  /* print the first part of the line including percentage output */
  printf("[*] Progress: %5.2f %% [", percentage*100);

  /* output progress bar (width = 50 chars) */
  for (i=1; i<=percentage*50 ;i++) printf("=");	/* calculate and output "="-signs */
  printf(">");					/* output arrow peak */
  for (i=percentage*50; i<50; i++) printf(" ");	/* calculate and output spaces */

  /* clear the line and carriage return */
  printf("]\n\033[F\033[J");
}

/*
 * Function:  main
 * ---------------
 * - takes arguments from command line
 * - opens input and output files
 * - checks for file format (pcap, pcapng, snoop, ...)
 * - runs fixing function depending on format
 * - evaluates result
 *
 * argc:  number of cmd line args
 * argv:  array of pointers to cmd line args
 *
 * returns:  0  success
 *          -1  error (parameters)
 *          -2  error (cannot open input file)
 *          -3  error (cannot open output file for writing)
 *          -4  error (input file is empty)
 *          -5  error (input file is too small)
 *          -6  error (filetype is known but not supported)
 *
 */
int main(int argc, char *argv[]) {
  FILE *pcap, *pcap_fix;			/* input and output file */
  int option_index = 0;				/* getopt_long option index */
  int c;                      /* getopts loop counter */
  int res;                    /* return values */
  char *filename;             /* filename of input file */
  char *filebname;            /* filebasename of input file (without path) */
  char *filename_fix;         /* filename of output file */
  unsigned long bytes;				/* read/written blocks counter */
  unsigned long filesize;			/* file size of input pcap file in bytes */

  /* init getopt_long options struct */
  struct option long_options[] = {
    {"data-link-type", required_argument, 0, 't'},		/* --data-link-type == -t */
    {"deep-scan", no_argument, 0, 'd'},				        /* --deep-scan == -d */
    {"verbose", no_argument, 0, 'v'},				          /* --verbose == -v */
    {0, 0, 0, 0}
  };

  /* print out pcapfix header information */
  printf("pcapfix %s (c) 2012-2013 Robert Krause\n\n", VERSION);

  /* scan for options and arguments */
  while ((c = getopt_long(argc, argv, ":t:v::d::", long_options, &option_index)) != -1) {
    switch (c) {
      case 0:	/* getopt_long options evaluation */
        break;
      case 'd':	/* deep scan */
        deep_scan++;
        break;
      case 'v':	/* verbose */
        verbose++;
        break;
      case 't':	/* data link type */
        data_link_type = atoi(optarg);
        break;
      case '?': /* unknown option */
        usage(argv[0]);
        return -1;
      default:
        abort();
    }
  }

  /* filename is first argument */
  filename = argv[optind++];

  /* if filename is not set, output usage information */
  if (filename == NULL) {
    usage(argv[0]);
    return(-1);
  }

  /* open input file */
  printf("[*] Reading from file: %s\n", filename);
  pcap = fopen(filename, "rb");
  if (!pcap) {
    perror("[-] Cannot open input file");
    return(-2);
  }

  /* open output file */
  /* we need to extract the basename first (windows and linux use different functions) */
  filebname = malloc(strlen(filename));
  #ifdef __WIN32__
    _splitpath(filename, NULL, NULL, filebname, NULL);	/* windown method (_splitpath) */
  # else
    strcpy(filebname, basename(filename));		/* unix method (basename) */
  #endif
  filename_fix = malloc(strlen(filebname)+6);	/* size of outputfile depends on inputfile's length */

  /* prepare output file name: "fixed_" + inputfilename */
  strcpy(filename_fix, "fixed_");
  strcat(filename_fix, filebname);
  free(filebname);

  /* open the file for writing */
  pcap_fix = fopen(filename_fix, "wb");
  if (!pcap_fix) {
    perror("[-] Cannot open output file for writing");
    return(-3);
  }
  printf("[*] Writing to file: %s\n", filename_fix);

  /* basic checks of input file */

  /* get file size */
  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);

  /* check for empty file */
  if (filesize == 0) {
    printf("[-] The source file is empty.\n\n");
    fclose(pcap);
    fclose(pcap_fix);
    remove(filename_fix);
    return(-4);
  }

  /* reset file pointer to file begin */
  fseek(pcap, 0, SEEK_SET);

  /* read header to header magic for further inspection */
  bytes = fread(&header_magic, sizeof(header_magic), 1, pcap);
  if (bytes == 0) {
    printf("[-] Cannot read file header (file too small?).\n\n");
    fclose(pcap);
    fclose(pcap_fix);
    remove(filename_fix);
    return(-5);
  }
  fseek(pcap, 0, SEEK_SET);

  /* check for file type */
  switch (header_magic) {
    case SNOOP_MAGIC:
      printf("[-] This is a SNOOP file, which is not supported yet.\n\n");
      fclose(pcap);
      fclose(pcap_fix);
      remove(filename_fix);
      return(-6);
    case PCAPNG_MAGIC:
      printf("[+] This is a PCAPNG file.\n");
      res = fix_pcapng(pcap, pcap_fix);
      break;
    case PCAP_MAGIC:
      printf("[+] This is a PCAP file.\n");
      res = fix_pcap(pcap, pcap_fix);
      break;
    default:
      /* if the file type is unknown (header corrupted) assume classic PCAP format */
      printf("[*] Unknown filetype. Assuming PCAP format.\n");
      res = fix_pcap(pcap, pcap_fix);
      break;
  }

  /* evaluate result of fixing function */
  if (res != 0) {
    printf("[-] ERROR (%d)\n", res);

    fclose(pcap);
    fclose(pcap_fix);

    /* delete output file due to failure */
    remove(filename_fix);
    return(10 + res);
  }

  /* Successful! */
  printf("[+] SUCCESS\n");

  /* always return zero (might be changed later) */
  return(0);
}
