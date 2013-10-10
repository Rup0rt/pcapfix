#ifndef PF_PCAP
#define PF_PCAP

#define PCAP_MAGIC 0xa1b2c3d4			  /* the magic of the pcap global header (non swapped) */
#define PCAPNG_MAGIC 0x0a0d0d0a			/* the magic of the pcap global header (non swapped) */
#define PCAP_NSEC_MAGIC 0xa1b23c4d	/* the magic of the pcap global header (nanoseconds - non swapped) */

/* Global header (http://v2.nat32.com/pcap.htm) */
struct global_hdr_s {
  u_int32_t magic_number;   /* magic number */
  u_short version_major;  	/* major version number */
  u_short version_minor;  	/* minor version number */
  int32_t thiszone;       	/* GMT to local correction */
  u_int32_t sigfigs;        /* accuracy of timestamps */
  u_int32_t snaplen;        /* max length of captured packets, in octets */
  u_int32_t network;        /* data link type */
};

/* Packet header (http://v2.nat32.com/pcap.htm) */
struct packet_hdr_s {
  u_int32_t ts_sec;         /* timestamp seconds */
  u_int32_t ts_usec;        /* timestamp microseconds */
  u_int32_t incl_len;       /* number of octets of packet saved in file */
  u_int32_t orig_len;       /* actual length of packet */
};

/*
 * Function:  is_plausible
 * -----------------------
 * check if the pcap packet header could be a plausible one by satisfying those conditions:
 * - packet size >= 16 bytes AND <= 65535 bytes (included length AND original length) (conditions 1,2,3,4)
 * - included length <= original lenth (condition 5)
 * - packet timestamp is NOT older OR younger than the prior packets timestamp -+ one day (conditions 6,7)
 * - usec (microseconds) field <= 1000000 (conditions 8)
 * - usec (nanoseconds) field <= 1000000000 (conditions 9)
 *
 * hdr:       the filled packet header struct to check for plausibility
 * prior_ts:  the prior packets timestamp (seconds) to check for time relation (condition 6,7)
 *
 * returns:  0   success
 *          -X   error (condition X failed)
 *
 */
int is_plausible(struct packet_hdr_s hdr, unsigned int prior_ts);

/*
 * Function:  check_header
 * -----------------------
 * this function takes a buffer and brute forces some possible ascii-corrupted bytes versus plausibility checks
 *
 * buffer:   the buffer that might contain the possible pcap packet header
 * size:     the size of the buffer (double pcap packet header size is a good choice)
 * priot_ts: the prior packets timestamp (to check for plausibility)
 * hdr:      the pointer to the packet header buffer (we use this to return the repaired header)
 *
 * returns: >=0   success (return value contains number of ascii corrupted bytes in hdr (we need this data to align the beginning of the packet body later)
 *           -1   error (no valid pcap header found inside buffer)
 *
 */
int check_header(char *buffer, unsigned int size, unsigned int prior_ts, struct packet_hdr_s *hdr);

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
int fix_pcap(FILE *pcap, FILE *pcap_fix);

#endif
