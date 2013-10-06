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

int check_header(char *buffer, unsigned int size, unsigned int prior_ts, struct packet_hdr_s *hdr);
int is_plausible(struct packet_hdr_s hdr, unsigned int prior_ts);
int fix_pcap(FILE *pcap, FILE *pcap_fix);

#endif
