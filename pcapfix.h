#ifndef PF_PCAPFIX
#define PF_PCAPFIX

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

unsigned short conshort(unsigned short var);
unsigned int conint(unsigned int var);
void print_progress(unsigned long pos, unsigned long filesize);
void usage(char *progname);

// configuration variables
extern int deep_scan;				// deep scan option (default: no depp scan)
extern int nanoseconds;			// pcap file uses nanoseconds (instead of microseconds)
extern int verbose;				// verbose output option (default: dont be verbose)
extern int swapped;			// pcap file is swapped (big endian)
extern int data_link_type;			// data link type (default: LINKTYPE_ETHERNET)

#endif
