#include <string.h>
#include "socket.h"
#include "wizchip_conf.h"
#include "FreeRTOS.h"
#include "task.h"
#include "arpHandler.h"
#include "WIZ5XXSR-RP_Debug.h"

/*
    UDP 기반 ARP 스캔:
    - sendto()가 내부적으로 ARP를 트리거하고 Sn_DHAR에 resolved MAC을 저장
    - 응답 없는 호스트: sendto()가 SOCKERR_TIMEOUT 반환
    - MACRAW(소켓 0 전용)를 피하기 위한 방식
*/
void arp_scan(uint8_t sock, arp_table_t *table_out) {
    table_out->count = 0;

    wiz_NetInfo netinfo;
    memset(&netinfo, 0, sizeof(netinfo));
    ctlnetwork(CN_GET_NETINFO, &netinfo);

    /* 스캔 속도를 위해 재시도 타임아웃을 임시로 단축 */
    wiz_NetTimeout orig_to, fast_to;
    wizchip_gettimeout(&orig_to);
    fast_to.retry_cnt  = 1;
    fast_to.time_100us = 100; /* 10ms per retry */
    wizchip_settimeout(&fast_to);

    uint8_t dummy = 0;
    uint8_t target[4];
    uint8_t mac[6];

    memcpy(target, netinfo.ip, 4);

    for (int i = 1; i <= ARP_SCAN_COUNT; i++) {
        target[3] = (uint8_t)i;
        if (target[3] == netinfo.ip[3]) {
            continue;    /* skip self */
        }

        if (socket(sock, Sn_MR_UDP, 0, 0) != sock) {
            continue;
        }

        int32_t ret = sendto(sock, &dummy, 1, target, 12345);
        if (ret > 0) {
            getSn_DHAR(sock, mac);

            /* 유효한 유니캐스트 MAC인지 확인 */
            int all_zero = 1, all_ff = 1;
            for (int j = 0; j < 6; j++) {
                if (mac[j] != 0x00) {
                    all_zero = 0;
                }
                if (mac[j] != 0xFF) {
                    all_ff  = 0;
                }
            }

            if (!all_zero && !all_ff && table_out->count < ARP_MAX_ENTRIES) {
                memcpy(table_out->entries[table_out->count].ip,  target, 4);
                memcpy(table_out->entries[table_out->count].mac, mac,    6);
                table_out->count++;
            }
        }

        close(sock);
    }

    /* 원래 타임아웃 복원 */
    wizchip_settimeout(&orig_to);

    PRT_INFO("ARP scan: %d host(s) found\r\n", table_out->count);
}
