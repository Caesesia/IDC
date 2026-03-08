#include <stdio.h>
#include <pcap/pcap.h>

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	int dev_list = pcap_findalldevs(&alldevs, errbuf);
	pcap_t *handle = pcap_create("wlp61s0", errbuf);
	
	// Device listing
	if (dev_list != 0) {
		puts("Error finding devices to listen on.");
		printf("Error : %s\n", errbuf);
		return 1;
	} else {
		int n = 1;
		puts("Success finding devices to listen on.");
		for (pcap_if_t *i = alldevs; i != NULL; i = i->next) {
			printf("	* Device %d : %s\n", n, i->name);
			n++;
		}
	}
	
	// Handle creation
	if (handle == NULL) {
		puts("Error creating the handle.");
		printf("Error : %s\n", errbuf);
		return 1;
	} else {
		puts("Success creating the handle for device [wlp61s0].");
		return 0;
	}
}
