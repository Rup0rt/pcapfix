#ifndef PF_PCAPFIX
#define PF_PCAPFIX

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>

#ifdef __WIN32__
  #include <Winsock.h>   		/* needed for htons,htonl on windows systems */
#else
  #include <libgen.h>    		/* needed for basename */
  #include <arpa/inet.h>		/* htons, htonl */
#endif

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
unsigned short conshort(unsigned short var);
unsigned int conint(unsigned int var);
void print_progress(unsigned long pos, unsigned long filesize);

/* global configuration variables */
extern int deep_scan;       /* deep scan option (default: no depp scan) */
extern int nanoseconds;		  /* pcap file uses nanoseconds (instead of microseconds) */
extern int verbose;				  /* verbose output option (default: dont be verbose) */
extern int swapped;			    /* pcap file is swapped (big endian) */
extern int data_link_type;	/* data link type (default: LINKTYPE_ETHERNET) */

#endif
