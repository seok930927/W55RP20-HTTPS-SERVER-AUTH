#include <string.h>
#include "socket.h"
#include "wizchip_conf.h"
#include "FreeRTOS.h"
#include "task.h"
#include "pingHandler.h"
#include "WIZ5XXSR-RP_Debug.h"

/*
    W5500 IPRAW does not deliver ICMP echo replies to user sockets
    (the chip processes ICMP internally).
    Use UDP sendto() to trigger the W5500 internal ARP, then read
    Sn_DHAR to confirm the host is reachable on the local subnet.
*/
void ping_host(uint8_t sock, const uint8_t *dest_ip, ping_result_t *result) {
    result->success = 0;
    result->rtt_ms  = 0;

    wiz_NetTimeout orig_to, fast_to;
    wizchip_gettimeout(&orig_to);
    fast_to.retry_cnt  = 2;
    fast_to.time_100us = 500; /* 50 ms per retry → up to ~100 ms total */
    wizchip_settimeout(&fast_to);

    if (socket(sock, Sn_MR_UDP, 0, 0) != sock) {
        wizchip_settimeout(&orig_to);
        return;
    }

    uint8_t dummy  = 0;
    uint32_t t0    = xTaskGetTickCount() * portTICK_PERIOD_MS;
    int32_t  ret   = sendto(sock, &dummy, 1, (uint8_t *)dest_ip, 12345);
    uint32_t t1    = xTaskGetTickCount() * portTICK_PERIOD_MS;

    if (ret > 0) {
        uint8_t mac[6];
        getSn_DHAR(sock, mac);

        int all_zero = 1, all_ff = 1;
        for (int j = 0; j < 6; j++) {
            if (mac[j] != 0x00) all_zero = 0;
            if (mac[j] != 0xFF) all_ff  = 0;
        }

        if (!all_zero && !all_ff) {
            result->success = 1;
            result->rtt_ms  = t1 - t0;
            PRT_INFO("ping: %d.%d.%d.%d reachable, ARP RTT=%ums\r\n",
                     dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3],
                     (unsigned)result->rtt_ms);
        } else {
            PRT_INFO("ping: %d.%d.%d.%d no ARP reply\r\n",
                     dest_ip[0], dest_ip[1], dest_ip[2], dest_ip[3]);
        }
    } else {
        PRT_INFO("ping: sendto failed ret=%d\r\n", (int)ret);
    }

    close(sock);
    wizchip_settimeout(&orig_to);
}
