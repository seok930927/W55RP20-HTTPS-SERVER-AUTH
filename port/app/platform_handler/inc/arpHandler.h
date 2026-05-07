#ifndef __ARPHANDLER_H__
#define __ARPHANDLER_H__
#include <stdint.h>

#define ARP_MAX_ENTRIES 50
#define ARP_SCAN_COUNT  254

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
} arp_entry_t;
typedef struct {
    arp_entry_t entries[ARP_MAX_ENTRIES];
    uint8_t count;
} arp_table_t;

void arp_scan(uint8_t sock, arp_table_t *table_out);

#endif
