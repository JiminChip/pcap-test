#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>

#define PACEKT_HEADER_SIZE 54
#define ETHER_TYPE_IPV4 0x0800
#define IP_PROTOCOL_TCP 0x06

#define PACKET_SIZE_ERROR 1
#define NOT_IPV4_ERROR 2
#define NOT_TCP_ERROR 3



typedef struct _EthernetHeader {
	uint8_t ether_dst_mac[6];
	uint8_t ether_src_mac[6];
	uint16_t ether_type;
} MyEthernetHeader;

typedef struct _IPHeader {
	uint8_t ip_ihl:4,
			ip_v:4;
	uint8_t ip_tos;
	uint16_t ip_totlen;
	uint16_t ip_identification;
	uint16_t ip_fl_offset;
	uint8_t ip_ttl;
	uint8_t ip_protocol;
	uint8_t ip_header_checksum;
	uint8_t ip_src_addr[4];
	uint8_t ip_dst_addr[4];
} MyIPHeader;

typedef struct _TCPHeader {
	uint16_t tcp_src_port;
	uint16_t tcp_dst_port;
	uint32_t tcp_seq_num;
	uint32_t tcp_ack_num;
	uint8_t tcp_dat_offset:4,
			tcp_reserved:4;
	uint8_t tcp_flags;
	uint16_t tcp_win_size;
	uint16_t tcp_checksum;
	uint16_t tcp_urg_ptr;
} MyTCPHeader;

typedef struct _packet {
	MyEthernetHeader eth_hdr;
	MyIPHeader ip_hdr;
	MyTCPHeader tcp_hdr;
	uint8_t data[20];
} MyPacket;

void print_mac (uint8_t* mac) {
	for (int i = 0; i < 6; i++) {
		printf("%02x", mac[i]);
		if (i < 5) {
			printf(":");
		}
	}
	printf("\n");
	return;
}

void print_ip (uint8_t* ip) {
	for (int i = 0; i < 4; i++) {
		printf("%u", ip[i]);
		if (i < 3) {
			printf(".");
		}
	}
	printf("\n");
	return;
}

void print_port (uint16_t port) {
	printf("%u\n", ntohs(port));
	return;
}

uint8_t parse_mypacket (MyPacket* packet, uint32_t p_len) {
	uint32_t data_len;
	
	//check size
	if (p_len < PACEKT_HEADER_SIZE) {
		return PACKET_SIZE_ERROR;
	}
	data_len = p_len - PACEKT_HEADER_SIZE;

	//parse Ethernet Header
	if (ntohs(packet->eth_hdr.ether_type) != ETHER_TYPE_IPV4) {
		return NOT_IPV4_ERROR;
	}
	printf("src mac: ");
	print_mac((uint8_t*)(&packet->eth_hdr.ether_src_mac));
	printf("dst mac: ");
	print_mac((uint8_t*)(&packet->eth_hdr.ether_dst_mac));
	
	//parse IPv4 Header
	if (packet->ip_hdr.ip_protocol != IP_PROTOCOL_TCP) {
		return NOT_TCP_ERROR;
	}
	printf("src ip: ");
	print_ip((uint8_t*)(&packet->ip_hdr.ip_src_addr));
	printf("dst ip: ");
	print_ip((uint8_t*)(&packet->ip_hdr.ip_dst_addr));

	//parse TCP Header
	printf("src port: ");
	print_port(packet->tcp_hdr.tcp_src_port);
	printf("dst port: ");
	print_port(packet->tcp_hdr.tcp_dst_port);
	
	//print data
	if (data_len > 20) {
		data_len = 20;
	}
	printf("data: ");
	for (int i = 0; i < data_len; i++) {
		printf("%02x ", packet->data[i]);
	}
	printf("\n");

	return 0;
}

void print_errmsg(uint8_t errnum) {
	switch (errnum) {
		case PACKET_SIZE_ERROR:
			fprintf(stderr, "not enough packet size\n");
			break;
		case NOT_IPV4_ERROR:
			fprintf(stderr, "not IPv4 protocol\n");
			break;
		case NOT_TCP_ERROR:
			fprintf(stderr, "not TCP protocol\n");
			break;
	}
}

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);
		uint8_t err_num = parse_mypacket((MyPacket*)packet, header->caplen);
		if (err_num) {
			print_errmsg(err_num);
		}
		printf("\n");
	}

	pcap_close(pcap);
}
