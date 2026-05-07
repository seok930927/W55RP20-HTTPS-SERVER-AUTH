/**
    Copyright (c) 2022 WIZnet Co.,Ltd

    SPDX-License-Identifier: BSD-3-Clause
*/

/**
    ----------------------------------------------------------------------------------------------------
    Includes
    ----------------------------------------------------------------------------------------------------
*/
#include "tusb.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common.h"
#include "WIZnet_board.h"
#include "port_common.h"
#include "ConfigData.h"
#include "timerHandler.h"
#include "deviceHandler.h"
#include "flashHandler.h"
#include "httpHandler.h"
#include "wizchip_conf.h"
#include "netHandler.h"
#include "w5x00_spi.h"

/**
    ----------------------------------------------------------------------------------------------------
    Macros
    ----------------------------------------------------------------------------------------------------
*/
/* Task */

#define NET_TASK_STACK_SIZE 1024
#define NET_TASK_PRIORITY 8

#define HTTP_WEBSERVER_TASK_STACK_SIZE 2048
#define HTTP_WEBSERVER_TASK_PRIORITY 23

#define HEAP_MONITOR_TASK_STACK_SIZE 1024
#define HEAP_MONITOR_TASK_PRIORITY 6

#define START_TASK_STACK_SIZE 512
#define START_TASK_PRIORITY 65

/**
    ----------------------------------------------------------------------------------------------------
    Variables
    ----------------------------------------------------------------------------------------------------
*/
xSemaphoreHandle net_segcp_udp_sem = NULL;
xSemaphoreHandle net_segcp_tcp_sem = NULL;
xSemaphoreHandle net_http_webserver_sem = NULL;
xSemaphoreHandle net_seg_sem = NULL;
xSemaphoreHandle net_seg_u2e_sem = NULL;
xSemaphoreHandle eth_interrupt_sem = NULL;
xSemaphoreHandle segcp_udp_sem = NULL;
xSemaphoreHandle segcp_tcp_sem = NULL;
xSemaphoreHandle segcp_uart_sem = NULL;
xSemaphoreHandle seg_u2e_sem = NULL;
xSemaphoreHandle seg_e2u_sem = NULL;
xSemaphoreHandle seg_spi_pending_sem = NULL;
xSemaphoreHandle seg_sem = NULL;
xSemaphoreHandle seg_critical_sem = NULL;
xSemaphoreHandle seg_timer_sem = NULL;
xSemaphoreHandle wizchip_critical_sem = NULL;
xSemaphoreHandle flash_critical_sem = NULL;

TimerHandle_t seg_inactivity_timer = NULL;
TimerHandle_t seg_keepalive_timer = NULL;
TimerHandle_t seg_auth_timer = NULL;
TimerHandle_t spi_reset_timer = NULL;
TimerHandle_t reset_timer = NULL;

TaskHandle_t seg_mqtt_yield_task_handle = NULL;

/**
    ----------------------------------------------------------------------------------------------------
    Functions
    ----------------------------------------------------------------------------------------------------
*/
static void RP2040_Init(void);
static void RP2040_W5X00_Init(void);
static void set_W5X00_NetTimeout(void);
static void set_minimal_runtime_config(void);
void start_task(void *argument);
void heap_monitor_task(void *argument);

/**
    ----------------------------------------------------------------------------------------------------
    Main
    ----------------------------------------------------------------------------------------------------
*/
int main() {
    xTaskCreate(start_task, "Start_Task", START_TASK_STACK_SIZE, NULL, START_TASK_PRIORITY, NULL);
    vTaskStartScheduler();

    while (1) {
        ;
    }
}

/**
    ----------------------------------------------------------------------------------------------------
    Functions
    ----------------------------------------------------------------------------------------------------
*/
/* Task */

static void RP2040_Init(void) {
#if 0
    set_sys_clock_khz(PLL_SYS_KHZ, true);

    clock_configure(
        clk_peri,
        0,                                                // No glitchless mux
        CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, // System PLL on AUX mux
        PLL_SYS_KHZ * 1000,                               // Input frequency
        PLL_SYS_KHZ * 1000                                // Output (must be same as no divider)
    );
#endif
    //SystemCoreClockUpdate();
    flash_critical_section_init();
    sleep_ms(10);
}

static void RP2040_W5X00_Init(void) {
    wizchip_spi_initialize((PLL_SYS_KHZ * 1000 / 4)); //33.25Mhz
    wizchip_cris_initialize();

    wizchip_reset();
    wizchip_initialize();
    wizchip_check();
}

static void set_W5X00_NetTimeout(void) {
    DevConfig *dev_config = get_DevConfig_pointer();
    wiz_NetTimeout net_timeout;

    net_timeout.retry_cnt = dev_config->network_option.tcp_rcr_val;
    net_timeout.time_100us = 2000;
    wizchip_settimeout(&net_timeout);

    wizchip_gettimeout(&net_timeout); // TCP timeout settings
    PRT_INFO(" - Network Timeout Settings - RCR: %d, RTR: %d\r\n", net_timeout.retry_cnt, net_timeout.time_100us);
}

static void set_minimal_runtime_config(void) {
    DevConfig *dev_config = get_DevConfig_pointer();

    dev_config->network_option.dhcp_use = ENABLE;
    dev_config->network_connection.working_mode = TCP_SERVER_MODE;
    dev_config->network_connection.dns_use = DISABLE;
}

void heap_monitor_task(void *argument) {
    (void)argument;

    while (1) {
        printf("Free heap: %d\n", xPortGetFreeHeapSize());
        printf("Min free heap: %d\n", xPortGetMinimumEverFreeHeapSize());
        vTaskDelay(pdMS_TO_TICKS(200));
    }
}

void start_task(void *argument) {
    (void)argument;

    RP2040_Init();
    RP2040_W5X00_Init();

    // 현재 시스템 클럭(Hz) 가져오기
    uint32_t current_hz = clock_get_hz(clk_sys);

    // MHz 단위로 변환해서 출력
    printf("Current System Clock: %lu Hz (%lu MHz)\n", current_hz, current_hz / 1000000);

    load_DevConfig_from_storage();
    set_minimal_runtime_config();
    RP2040_Board_Init();

    Net_Conf();
    display_Dev_Info_main();
    display_Net_Info();

    set_W5X00_NetTimeout();
    Timer_Configuration();
    net_http_webserver_sem = xSemaphoreCreateCounting((unsigned portBASE_TYPE)0x7fffffff, (unsigned portBASE_TYPE)0);

#if defined(MBEDTLS_PLATFORM_C) && defined(MBEDTLS_PLATFORM_MEMORY)
    mbedtls_platform_set_calloc_free(pvPortCalloc, vPortFree);
#endif
    reset_timer = xTimerCreate("reset_timer", pdMS_TO_TICKS(5000), pdFALSE, 0, reset_timer_callback);
    xTaskCreate(net_status_task, "Net_Status_Task", NET_TASK_STACK_SIZE, NULL, NET_TASK_PRIORITY, NULL);
    xTaskCreate(http_webserver_task, "http_webserver_task", HTTP_WEBSERVER_TASK_STACK_SIZE, NULL, HTTP_WEBSERVER_TASK_PRIORITY, NULL);
    // xTaskCreate(heap_monitor_task, "Heap_Monitor_Task", HEAP_MONITOR_TASK_STACK_SIZE, NULL, HEAP_MONITOR_TASK_PRIORITY, NULL);
#ifdef __USE_WATCHDOG__
    watchdog_enable(8388, 0);
#endif
    vTaskDelete(NULL);
}

void vApplicationPassiveIdleHook(void) {
#ifdef __USE_WATCHDOG__
    static uint8_t core_num = 0;
    uint8_t core_num_tmp = get_core_num();

    if (core_num != core_num_tmp) {
        device_wdt_reset();
        core_num = core_num_tmp;
    }
#endif

}

void vApplicationStackOverflowHook(TaskHandle_t pxTask, char *pcTaskName) {
    (void) pcTaskName;
    (void) pxTask;

    /*  Run time stack overflow checking is performed if
        configCHECK_FOR_STACK_OVERFLOW is defined to 1 or 2.  This hook
        function is called if a stack overflow is detected. */

    /* Force an assert. */
    printf("vApplicationStackOverflowHook [%s]\r\n", pcTaskName);
    configASSERT((volatile void *) NULL);
}
