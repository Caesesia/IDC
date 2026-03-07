#include <pcap/pcap.h>
#include <stdio.h>

int main() {
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldevs;

	//

	if (int pcap_activate(pcap_t *p) == 1) {
		void pcap_close(pcap_t *p);
		return 1;
	} else {
		int pcap_findalldevs(pcap_t **alldevsp, char *errbuf);
		
}
