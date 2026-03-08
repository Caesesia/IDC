#include <stdio.h>
#include <pcap/pcap.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	printf("Packet captured! Length: %d\n", header->len);
}

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	const char *device = "wlp61s0";
	
	pcap_if_t *alldevs;
	int dev_list = pcap_findalldevs(&alldevs, errbuf);
	
	pcap_t *handle = pcap_create(device, errbuf);

	// Add timeout to capture after 1s even if buffer isn't filled
	pcap_set_timeout(handle, 1000);
	
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

	printf("Starting capture...\n\n");
	pcap_loop(handle, 5, got_packet, NULL);

	pcap_close(handle);
	pcap_freealldevs(alldevs);
	return 0;
}
