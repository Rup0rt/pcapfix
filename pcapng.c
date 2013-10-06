#include "pcapfix.h"
#include "pcapng.h"

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
  unsigned int block_pos;

  unsigned long bytes;
  unsigned int check;
  unsigned long padding;
  unsigned long pos;
  unsigned long filesize;
  signed long left;

  unsigned long i;

  fseek(pcap, 0, SEEK_END);
  filesize = ftell(pcap);
  fseek(pcap, 0, SEEK_SET);

  pos = 0;

  // check block header ()
  while (pos < filesize) {
    printf("%ld / %ld\n", pos, filesize);

    bytes = fread(&bh, sizeof(bh), 1, pcap);
    if (bytes != 1) return -1;

    printf("[*] Total Block Length: %u bytes\n", bh.total_length);
    left = bh.total_length-sizeof(bh)-sizeof(check);

printf("Type: 0x%08x\n", bh.block_type);

    new_block = malloc(bh.total_length);
    memcpy(new_block, &bh, 8);
    block_pos = 8;

    switch (bh.block_type) {
      case TYPE_SHB:
        printf("[+] Section Header Block: 0x%08x\n", bh.block_type);
        bytes = fread(&shb, sizeof(shb), 1, pcap);
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
          }

          if (oh.option_code > 0x04) {
            printf("[-] OPTION: Unknown option code: 0x%04x\n", oh.option_code);
            printf("SKIPPING OPTIONS...\n");
            break;
/*            oh.option_code = 0x00;*/
/*            oh.option_length = 0x00;*/
          }

          memcpy(new_block+block_pos, &oh, sizeof(oh));
          block_pos += sizeof(oh);

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
    }

    if (bh.block_type > TYPE_EPB) {
      printf("[-] Unknown block type!: 0x%08x\n", bh.block_type);
      printf("SKIPPING!\n");
    }

    block_pos += sizeof(bh.total_length);
    memcpy(new_block+4, &block_pos, sizeof(bh.total_length));
    memcpy(new_block+block_pos-4, &block_pos, sizeof(bh.total_length));

    printf("Writing %u bytes...\n", block_pos);
    fwrite(new_block, block_pos, 1, pcap_fix);
    free(new_block);

    // check for correct block end (block size)
    bytes = fread(&check, sizeof(check), 1, pcap);

    if (check == bh.total_length) {
      printf("[+] Block size matches (%u)!\n", check);
    } else {
      printf("[-] Block size mismatch (%u != %u)!\n", check, bh.total_length);
    }

    if (left == 0) {
      printf("[+] End of Block reached... byte counter is correct!\n");
    } else {
      printf("[-] Something went wrong! This should not be the end of the block! (%ld bytes left)\n", left);

      printf("[*] Trying to aling next block...\n");
      for (i=ftell(pcap)-4; i<filesize; i++) {
        fseek(pcap, i, SEEK_SET);
        fread(&bh, sizeof(bh), 1, pcap);
        if (bh.total_length >= 12 && bh.block_type >= TYPE_IDB && bh.block_type <= TYPE_EPB) {
          fseek(pcap, i+bh.total_length-4, SEEK_SET);
          fread(&check, sizeof(check), 1, pcap);
          if (check == bh.total_length) {
            printf("GOT POS AT %ld\n", i);
            fseek(pcap, i, SEEK_SET);
            break;
          }
        }
      }
    }

    pos = ftell(pcap);

  }

  printf("SUCCESS\n");

  return(1);
}
