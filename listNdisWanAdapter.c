#include "pcap.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

void listNdisWanAdapter(int i) {
    pcap_if_t *alldevs;
    pcap_if_t *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    /* Retrieve the device list from the local machine */
    if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING,
                            NULL, // auth is not needed
                            &alldevs,
                            errbuf) == -1)
        {
            fprintf(stderr, "pcap_findalldevs_ex error: %s\n", errbuf);
            exit(1);
        }

    /* Print the NdisWan adapters */
    for (d = alldevs; d; d = d->next) {
        if (strstr(d->name, "NdisWan"))
            printf("%d. %s\n", i++,d->name);
    }

    /* We don't need any more the device list. Free it */
    pcap_freealldevs(alldevs);

    return;
}
