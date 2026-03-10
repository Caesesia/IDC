// List of libraries
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>



// Declare function to capture packets
void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {

	// Kill unusued args warning
	(void)args;

	// Initialize packet looping
	static int n = 1;
	struct ip *ip_header = (struct ip *)(packet + 14);
	int ip_header_length = ip_header->ip_hl * 4;
	struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_length);

	// Check IPv4 header, drop if false
	if (ip_header->ip_v != 4) {
		printf("\nPacket %d is not an IP packet. Dropping it...\n", n);
		n++;
		return;
	} else {

		// Check packet protocol
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

		// Check SYN flag
		char *syn_flag = (tcp_header->th_flags & TH_SYN) ? "set" : "unset";

		// Print packet info
		printf("\nPacket %d captured.\n", n);
		printf("	Length: %d\n", header->len);
		printf("	Source IP: %s\n", inet_ntoa(ip_header->ip_src));
		printf("	Destination IP: %s\n", inet_ntoa(ip_header->ip_dst));
		printf("	Protocol: %s (Number: %d)\n", protocol, ip_header->ip_p);
		printf("	Source port: %d\n", ntohs(tcp_header->th_sport));
		printf("	Destination port: %d\n", ntohs(tcp_header->th_dport));
		printf("	SYN flag: %s\n", syn_flag);
		n++;
		sleep(1);
	}
}

int main() {

	// Declare error buffer size to 256 iirc
	char errbuf[PCAP_ERRBUF_SIZE];

	// Set user input device buffer size
	char device[33];
	
	// Declare all devices for further processing
	pcap_if_t *alldevs;

	// Find all devices and put them in a variable
	int dev_list = pcap_findalldevs(&alldevs, errbuf);

	// List all devices found
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

	// User input device
	puts("Enter a device from the list [name] : ");
	scanf("%32s", device);

	// Initialize variable that checks if user device is found
	int dev_found = 0;

	// Compare user input device with each device from list
	for (pcap_if_t *i = alldevs; i != NULL; i = i->next) {
		if (strcmp(device, i->name) == 0) {
			dev_found = 1;
			break;
		}
	}

	// Check if user input device was found in device list
	if (!dev_found) {
		printf("\nError : device %s not found in list of devices.\n", device);
		return 1;
	}

	// Create the handle
	pcap_t *handle = pcap_create(device, errbuf);

	// Add timeout to capture after 0.5s even if buffer isn't filled
	pcap_set_timeout(handle, 500);

	// Activate the handle
	int activate = pcap_activate(handle);
	
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

	// Initialize port filtering
	char filtered[33];

	// Initialize and clean garbage from user_port
	char user_port[6] = {0};

	// Prompt user to enter a port
	puts("Enter a port to filter [number] (default 'tcp') : ");
	scanf("%5s", user_port);

	// Check if user inputted something
	if (strlen(user_port) == 0) {
		// Resort to default "tcp" if no input
		snprintf(filtered, sizeof(filtered), "tcp");
	} else {
		// Append user input if not empty
		snprintf(filtered, sizeof(filtered), "port %s", user_port);
	}

	struct bpf_program fp;
	pcap_compile(handle, &fp, filtered, 1, PCAP_NETMASK_UNKNOWN);
	
	// Initialize filter variable with setfilter() and user input
	int filter = pcap_setfilter(handle, &fp);

	// Check setfilter() return code
	if (filter == 0) {
		puts("Compiling succeeded!\n");
	} else {
		puts("Compiling failed...\n");
		return -1;
	}

	// Slow down stdout
	printf("Starting capture in 5 seconds...\n\n");
	sleep(5);

	// Capture packets 20 times
	pcap_loop(handle, 20, got_packet, NULL);

	// Close the handle
	pcap_close(handle);

	// Free all devices cleanly
	pcap_freealldevs(alldevs);

	// Return with success
	return 0;
}
