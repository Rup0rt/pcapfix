#ifndef PF_PCAP
#define PF_PCAP

#define PCAP_MAGIC 0xa1b2c3d4			// the magic of the pcap global header (non swapped)
#define PCAPNG_MAGIC 0x0a0d0d0a			// the magic of the pcap global header (non swapped)
#define PCAP_NSEC_MAGIC 0xa1b23c4d		// the magic of the pcap global header (nanoseconds - non swapped)

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

int check_header(char *buffer, unsigned int size, unsigned int prior_ts, struct packet_hdr_s *hdr);
int is_plausible(struct packet_hdr_s hdr, unsigned int prior_ts);
int fix_pcap(FILE *pcap, FILE *pcap_fix);

#endif
