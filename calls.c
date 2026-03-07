#include <stdio.h>
#include <pcap/pcap.h>

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;
	int dev_list = pcap_findalldevs(&alldevs, errbuf);
	pcap_t *handle;
	int ret_handle = pcap_create(alldevs->name, errbuf);
	if (dev_list != 0) {
		puts("Error finding devices to listen on.");
		printf("Error : %s\n", errbuf);
		return 1;
	} else {
		puts("Success finding devices to listen on.");
		printf("List of devices : %s\n", d->name);
		return 0;
	}
	if (ret_handle != 0) {
		puts("Error creating the handle.");
		printf("Error : %s\n", errbuf);
		return 1;
	} else {
		puts("Success creating the handle.");
		return 0;
	}
}
