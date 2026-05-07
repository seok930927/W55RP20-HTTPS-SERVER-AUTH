#ifndef __PINGHANDLER_H__
#define __PINGHANDLER_H__
#include <stdint.h>

typedef struct {
    int      success;
    uint32_t rtt_ms;
} ping_result_t;

void ping_host(uint8_t sock, const uint8_t *dest_ip, ping_result_t *result);

#endif
