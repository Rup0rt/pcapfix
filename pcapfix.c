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
 * Last Modified: 22.01.2019
 *
 *******************************************************************************
 *
 * Description:
 *
 * Pcapfix is a tool to repair your damaged or corrupted pcap and pcapng files.
 * It is written in C and released under the GNU General Public License.
 *
 * To fix your pcap files the tool first checks for an intact pcap global header
 * and repairs it if there are some corrupted bytes. It there seems to be no
 * global header at all, pcapfix adds a self-created one at the beginning of the
 * file. In a second step the tool tries to find pcap packet headers inside the
 * file, below the global header. It checks if the values are correct (or seem
 * to be correct) and tries to repair a packet if there is something wrong. 
 *
 * To fix your pcapng files the tool loops through all packet headers that can
 * be found in the file. It checks for mandatory Section Header Block and
 * Interface Description Block and creates them if missing. Pcapfix checks for
 * correct block sizes and valid option fields. If something is wrong, invalid
 * fields are repaired (if possible) or skipped and adjusted to finally get a
 * proper pcapng file.
 *
 ******************************************************************************/

#include "pcapfix.h"
#include "pcap.h"
#include "pcap_kuznet.h"
#include "pcapng.h"

#define VERSION "1.1.4"			    /* pcapfix version */

#define BTSNOOP_MAGIC 0x6E737462    /* btsnoop file magic (first 4 bytes) */
#define SNOOP_MAGIC 0x6f6f6e73	    /* snoop file magic (first 4 bytes) */
#define NETMON_MAGIC 0x55424d47     /* netmon file magic */
#define NETMON11_MAGIC 0x53535452   /* netmon 1.1 file magic */
#define ETHERPEEK_MAGIC 0x7265767f  /* EtherPeek/AiroPeek/OmniPeek file magic */

/* configuration variables */
int deep_scan = 0;		/* deep scan option (default: no deep scan) */
int soft_mode = 0;		/* soft mode option (default: no soft mode) */
int keep_outfile = 0;		/* keep output file even if nothing needed fixing (default: don't) */
int verbose = 0;		/* verbose output option (default: dont be verbose) */
int swapped = 0;		/* pcap file is swapped (big endian) */
int data_link_type = -1;	/* data link type (default: LINKTYPE_ETHERNET) */
int pcapng = 0;			/* file format to assume */

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
  printf(  "\t-d        , --deep-scan          \tDeep scan (pcap only)\n");
  printf("\t\t-s        , --soft-mode          \tSoft mode (packet detection)\n");
  printf("\t\t-n        , --pcapng             \tforce pcapng format\n");
  printf("\t\t-o <file> , --outfile <file>     \tset output file name\n");
  printf("\t\t-k        , --keep-outfile       \tdon't delete the output file if nothing needed to be fixed\n");
  printf("\t\t-t <nr>   , --data-link-type <nr>\tData link type\n");
  printf("\t\t-v        , --verbose            \tVerbose output\n");
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
 * prints the progess line when using pcapfix in non-verbose mode
 *
 * pos:       the current filepointer position
 * filesize:  the size of the input pcap file in bytes
 *
 */
void print_progress(uint64_t pos, uint64_t filesize) {
  float percentage;	/* pencentage variable */

  /* calculate the current percentage of file analyzing progress */
  percentage = (float)pos/(float)filesize;

  /* print the first part of the line including percentage output */
  printf("[*] Progress: %6.02f %%\n", percentage*100);
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
 * returns:  1    success (filed repaired)
 *           0    success (nothing to fix)
 *          -1    error (parameters)
 *          -2    error (cannot open input file)
 *          -3    error (cannot open output file for writing)
 *          -4    error (input file is empty)
 *          -5    error (input file is too small)
 *          -6    error (filetype is known but not supported)
 *          -11   error (not a pcap file)
 *          -12   error (unable to recover pcap file)
 *          -13   error (EOF while reading input file)
 *          -255  error (unkown)
 *
 */
int main(int argc, char *argv[]) {
  FILE *pcap, *pcap_fix;		/* input and output file */
  int option_index = 0;			/* getopt_long option index */
  int c;                        /* getopts loop counter */
  int res;                      /* return values */
  char *filename;               /* filename of input file */
  char *filebname;              /* filebasename of input file (without path) */
  char *filename_fix = NULL;    /* filename of output file */
  uint64_t bytes;		        /* read/written blocks counter */
  uint64_t filesize;	        /* file size of input pcap file in bytes */

  /* init getopt_long options struct */
  struct option long_options[] = {
    {"deep-scan", no_argument, 0, 'd'},            /* --deep-scan == -d */
    {"soft-mode", no_argument, 0, 's'},            /* --soft-mode == -s */
    {"pcapng", no_argument, 0, 'n'},               /* --pcapng == -n */
    {"outfile", required_argument, 0, 'o'},        /* --outfile == -o */
    {"keep-outfile", no_argument, 0, 'k'},         /* --keep-outfile == -k */
    {"data-link-type", required_argument, 0, 't'}, /* --data-link-type == -t */
    {"verbose", no_argument, 0, 'v'},              /* --verbose == -v */
    {0, 0, 0, 0}
  };

  /* print out pcapfix header information */
  printf("pcapfix %s (c) 2012-2019 Robert Krause\n\n", VERSION);

  /* scan for options and arguments */
  while ((c = getopt_long(argc, argv, ":t:ko:v::d::s::n::", long_options, &option_index)) != -1) {
    switch (c) {
      case 0:	/* getopt_long options evaluation */
        break;
      case 'd':	/* deep scan */
        deep_scan++;
        break;
      case 's':	/* soft mode */
        soft_mode++;
        break;
      case 'k': /* keep outfile even if nothing needed fixing */
        keep_outfile++;
        break;
      case 'n':	/* pcapng format */
        pcapng++;
        break;
      case 'o':	/* output file name */
        filename_fix = malloc(strlen(optarg)+1);
	strcpy(filename_fix, optarg);
        break;
      case 't':	/* data link type */
        data_link_type = atoi(optarg);
        break;
      case 'v':	/* verbose */
        verbose++;
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

  /* check for preassigned fixed file name */
  if (filename_fix == NULL) {

    /* open output file */
    /* we need to extract the basename first (windows and linux use different functions) */
    filebname = malloc(strlen(filename)+1);
    #ifdef __WIN32__
      char *fileext = malloc(strlen(filename));   /* file extention to be used in output file as well */
      _splitpath(filename, NULL, NULL, filebname, fileext);	/* windown method (_splitpath) */
      strcat(filebname, fileext);
      free(fileext);
    # else
      strcpy(filebname, basename(filename));		/* unix method (basename) */
    #endif
    filename_fix = malloc(strlen(filebname)+7);	/* size of outputfile depends on inputfile's length */

    /* prepare output file name: "fixed_" + inputfilename */
    strcpy(filename_fix, "fixed_");
    strcat(filename_fix, filebname);
    free(filebname);
  }

  /* open the file for writing */

  // is output == inputfile ?? if yes, then open for read / append
  // if no, then open for writing only
  if (strcmp(filename, filename_fix) == 0) pcap_fix = fopen(filename_fix, "rb+");
  else pcap_fix = fopen(filename_fix, "w+");

  if (!pcap_fix) {
    perror("[-] Cannot open output file for writing");
    return(-3);
  }
  printf("[*] Writing to file: %s\n", filename_fix);

  /* basic checks of input file */

  /* get file size */
  fseeko(pcap, 0, SEEK_END);
  filesize = ftello(pcap);
  printf("[*] File size: %" PRIu64 " bytes.\n", filesize);

  /* check for empty file */
  if (filesize == 0) {
    printf("[-] The source file is empty.\n\n");
    fclose(pcap);
    fclose(pcap_fix);
    if (strcmp(filename, filename_fix) != 0) remove(filename_fix);
    return(-4);
  }

  /* reset file pointer to file begin */
  fseeko(pcap, 0, SEEK_SET);

  /* read header to header magic for further inspection */
  bytes = fread(&header_magic, sizeof(header_magic), 1, pcap);
  if (bytes == 0) {
    printf("[-] Cannot read file header (file too small?).\n\n");
    fclose(pcap);
    fclose(pcap_fix);
    if (strcmp(filename, filename_fix) != 0) remove(filename_fix);
    return(-5);
  }
  fseeko(pcap, 0, SEEK_SET);

  /* check for file type */
  switch (header_magic) {

    /* etherpeek file format --> often used with pcapfix but NOT supported (yet) */
    case ETHERPEEK_MAGIC:
      printf("[-] This is a EtherPeek/AiroPeek/OmniPeek file, which is not supported.\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to no changes failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      return(-6);

    /* netmon file format --> often used with pcapfix but NOT supported (yet) */
    case NETMON_MAGIC:
    case NETMON11_MAGIC:
      printf("[-] This is a NetMon file, which is not supported.\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to no changes failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      return(-6);

    /* SNOOP file format --> often used with pcapfix but NOT supported (yet) */
    case SNOOP_MAGIC:
      printf("[-] This is a SNOOP file, which is not supported.\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to no changes failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      return(-6);

    case BTSNOOP_MAGIC:
      printf("[-] This is a BTSNOOP file, which is not supported.\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to no changes failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      return(-6);

    /* extended pcap format (KUZNETZOV) */
    case PCAP_EXT_MAGIC:
    case PCAP_EXT_MAGIC_SWAPPED:
      printf("[+] This is an extended tcpdump file.\n");
      res = fix_pcap_kuznetzov(pcap, pcap_fix);

      break;

    /* PCAPNG format */
    case PCAPNG_MAGIC:
      printf("[+] This is a PCAPNG file.\n");
      res = fix_pcapng(pcap, pcap_fix);
      break;

    /* classic PCAP format */
    case PCAP_MAGIC:
    case PCAP_MAGIC_SWAPPED:
      printf("[+] This is a PCAP file.\n");
      if (pcapng > 0) {
        printf("[!] Your wish is my command! I will handle it as PCAPNG nevertheless.\n");
        res = fix_pcapng(pcap, pcap_fix);
      } else {
        res = fix_pcap(pcap, pcap_fix);
      }
      break;

    /* if the file type is unknown (maybe header corrupted) assume classic PCAP format */
    default:
      if (pcapng > 0) {
        printf("[*] Unknown file type. Assuming PCAPNG format.\n");
        res = fix_pcapng(pcap, pcap_fix);
      } else {
        printf("[*] Unknown file type. Assuming PCAP format.\n");
        res = fix_pcap(pcap, pcap_fix);
      }
      break;
  }

  /* evaluate result of fixing function */
  switch (res) {

    /* no corruption found; all fields were valid */
    case 0:
      printf("[*] Your pcap file looks proper. Nothing to fix!\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to no changes failure */
      if ((strcmp(filename, filename_fix) != 0) && (0 == keep_outfile)) {
        remove(filename_fix);
      }

      return(0);

    /* there is NO indication that this has ever been a pcap file at all */
    case -1:
      printf("[-] FAILED: This file does not seem to be a pcap/pcapng file!\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      /* deep scan / soft mode dependent output */
      if (deep_scan == 0 || soft_mode == 0) printf("If you are SURE that there are pcap packets inside, try with deep scan (-d) (pcap only!) and/or soft mode (-s) to find them!\n\n");
      else printf("There is REALLY no pcap packet inside this file!!!\n\n");

      return(res-10);

    /* it seems to be a pcap file, but pcapfix can NOT repair it (yet) */
    case -2:
      printf("[-] FAILED: Unable to recover pcap file.\n\n");

      /* some hints for verbose mode and pcapfix improvement support */
      if (!verbose) printf("Try executing pcapfix with -v option to trace the corruption!\n");
      printf("You may help to improve pcapfix by sending your pcap file to ruport@f00l.de\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      return(res-10);

    /* fread did not succeed; might be caused by early EOF; but it should NOT happen at all */
    case -3:
      printf("[-] FAILED: EOF while reading input file.\n\n");

      /* some hints for verbose mode and pcapfix improvement support */
      if (!verbose) printf("Try executing pcapfix with -v option to trace the corruption!\n");
      printf("You may help to improve pcapfix by sending your pcap file to ruport@f00l.de\n\n");

      /* close input and output files */
      fclose(pcap);
      fclose(pcap_fix);

      /* delete output file due to failure */
      if (strcmp(filename, filename_fix) != 0) remove(filename_fix);

      return(res-10);
  }

  /* file has been progressed properly. what is the result (number of corruptions)? */

  if (res > 0) {
    /* Successful repaired! (res > 0) */

    fclose(pcap);
    off_t finalpos = ftello(pcap_fix);
    fclose(pcap_fix);
    int success = truncate(filename_fix, finalpos);
    if (success != 0) printf("[-] Truncating result file failed!");

    printf("[+] SUCCESS: %d Corruption(s) fixed!\n\n", res);
    return(0);

  } else {
    /* Unknown Error (res < 0); this should NEVER happen! */

    printf("[-] UNKNOWN ERROR (%d)\n\n", res);
    printf("Please report this bug to ruport@f00l.de (including -v -v output).\n\n");
    return(-255);

  }

}
