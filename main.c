#include <stdio.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	
	static int n = 1;
	struct ip *ip_header = (struct ip *)(packet + 14);
	int ip_header_length = ip_header->ip_hl * 4;
	struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_length);

	if (ip_header->ip_v != 4) {
		printf("\nPacket %d is not an IP packet. Dropping it...\n", n, ip_header->ip_p);
		n++;
		return;
	} else {

		char *protocol;
		switch (ip_header->ip_p) {
			case 1:
				protocol = "ICMP";
				break;
			case 6:
				protocol = "TCP";
				break;
			case 17:
				protocol = "UDP";
				break;
			default:
				protocol = "Other";
				break;
		}

		char *syn_flag = (tcp_header->th_flags & TH_SYN) ? "set" : "unset";

		printf("\nPacket %d captured.\n", n);
		printf("	Length: %d\n", header->len);
		printf("	Source IP: %s\n", inet_ntoa(ip_header->ip_src));
		printf("	Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
		printf("	Protocol: %s (Number: %d)\n", protocol, ip_header->ip_p);
		printf("	Source port: %d\n", ntohs(tcp_header->th_sport));
		printf("	Destination port: %d\n", ntohs(tcp_header->th_dport));
		printf("	SYN flag: %s\n", syn_flag);
		n++;
	}
}

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *device = "wlp61s0";
	
	pcap_if_t *alldevs;
	int dev_list = pcap_findalldevs(&alldevs, errbuf);
	
	pcap_t *handle = pcap_create(device, errbuf);

	// Add timeout to capture after 1s even if buffer isn't filled
	pcap_set_timeout(handle, 500);
	
	int activate = pcap_activate(handle);

	// Device listing
	if (dev_list != 0) {
		puts("Error finding devices to listen on.");
		printf("Error : %s\n", errbuf);
		return 1;
	} else {
		int n = 1;
		puts("\nSuccess finding devices to listen on.");
		for (pcap_if_t *i = alldevs; i != NULL; i = i->next) {
			printf("	* Device %d : %s\n", n, i->name);
			n++;
		}
	}
	
	// Handle creation
	if (handle == NULL) {
		puts("\nError creating the handle.");
		printf("Error : %s\n", errbuf);
		return 1;
	} else {
		printf("\nSuccess creating the handle for device %s.\n", device);
	}

	if (activate == 0) {
		printf("\nSuccess activating the handle %s.\n\n", device);
	} else {
		printf("\nError activating the handle %s.\n", device);
		printf("Error : %s\n", pcap_statustostr(activate));
		return 1;
	}


	struct bpf_program fp;
	int compile = pcap_compile(handle, &fp, "tcp", 1, PCAP_NETMASK_UNKNOWN);
	int filter = pcap_setfilter(handle, &fp);
	if (filter == 0) {
		puts("Compiling succeeded!\n");
	} else {
		puts("Compiling failed...\n");
		return -1;
	}

	printf("Starting capture in 5 seconds...\n\n");
	sleep(5);

	pcap_loop(handle, 20, got_packet, NULL);


	pcap_close(handle);
	pcap_freealldevs(alldevs);
	return 0;
}
