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

#ifndef PF_PCAPFIX
#define PF_PCAPFIX

#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <inttypes.h>

#ifdef __WIN32__
  #include <Winsock.h>   		/* needed for htons,htonl on windows systems */

  /* fseeko, ftello are unkown on mingw, use o64 instead */
  #define fseeko fseeko64
  #define ftello ftello64

  /* compatibility for fixed size integer types on windows */
  typedef uint8_t u_int8_t;
  typedef uint16_t u_int16_t;
  typedef uint32_t u_int32_t;

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
unsigned int conint(unsigned int var);

/*
 * Function:  print_progress
 * -------------------------
 * prints the progess line when using pcapfix in non-verbose mode
 *
 * pos:       the current filepointer position
 * filesize:  the size of the input pcap file in bytes
 *
 */
void print_progress(uint64_t pos, uint64_t filesize);

/* global configuration variables */
extern int deep_scan;		/* deep scan option (default: no depp scan) */
extern int verbose;		/* verbose output option (default: dont be verbose) */
extern int swapped;		/* pcap file is swapped (big endian) */
extern int data_link_type;	/* data link type (default: LINKTYPE_ETHERNET) */
extern int soft_mode;		/* soft plausibility check (default: OFF) */

#endif
