
#include "port_common.h"
#include "common.h"
#include "WIZnet_board.h"

#include "timerHandler.h"
#include "uartHandler.h"
#include "gpioHandler.h"
#include "wizchip_conf.h"

volatile uint16_t phylink_check_time_msec = 0;
uint8_t flag_check_phylink = 0;
uint8_t serial_if = 0;  //0:UART, 1:SPI

// LEDs on board
const uint16_t LED_PIN[LEDn] = {LED1_PIN, LED2_PIN, LED3_PIN};
uint8_t GPIO_INIT[LEDn] = {DISABLE, DISABLE, DISABLE};

/* RP2040 Board Initialization */
void RP2040_Board_Init(void) {
#ifdef __USE_SERIAL_FLASH__
    /* On-board Serial Flash Initialize */
    SFlash_Init();
#endif

    /*  EVB-Pico 핀제어 데모 펌웨어:
        S2E 전용 핀 기능은 사용하지 않으므로 초기화하지 않는다.
        (팩토리리셋 GP18, IF선택 GP12/13, 상태LED GP10/11,
         DTR/DSR GP8/9, HW트리거 GP14)
        → GP4~GP15는 웹 핀 제어(pinCtrl)에서 자유롭게 사용 가능. */

    /* GPIO19 - 온보드 사용자 LED: 부팅 표시로 ON */
    GPIO_Configuration(19, IO_OUTPUT, IO_NOPULL);
    GPIO_Output_Set(19);
}

uint8_t get_phylink(void) {
    return wizphy_getphylink();
}

// Hardware mode switch pin, active low
void init_hw_trig_pin(void) {
    GPIO_Configuration(HW_TRIG_PIN, IO_INPUT, IO_PULLUP);
}

uint8_t get_hw_trig_pin(void) {
    // HW_TRIG input; Active low
    uint8_t hw_trig, i;
    for (i = 0; i < 5; i++) {
        hw_trig = GPIO_Input_Read(HW_TRIG_PIN);
        if (hw_trig != 0) {
            return 1;    // High
        }
        vTaskDelay(5);
    }
    return 0; // Low
}

void init_uart_spi_if_sel_pin(void) {
    GPIO_Configuration(UART_SPI_IF_SEL_PIN, IO_INPUT, IO_PULLDOWN);
    if (GPIO_Input_Read(UART_SPI_IF_SEL_PIN)) {
        serial_if = 1;
    } else {
        serial_if = 0;
    }
}

uint8_t get_uart_spi_if(void) {
    // Status of interface selector pin input; [0] UART mode, [1] SPI mode
    return serial_if;
}

uint8_t get_spi_uart_if_sel_pin(void) {
    // Status of UART interface selector pin input; [0] RS-232/TTL mode, [1] RS-422/485 mode
    if (GPIO_Input_Read(UART_SPI_IF_SEL_PIN)) {
        return UART_IF_RS485;
    } else {
        return UART_IF_DEFAULT;
    }
}


void init_uart_if_sel_pin(void) {
    GPIO_Configuration(UART_IF_SEL_PIN, IO_INPUT, IO_PULLDOWN);
}


uint8_t get_uart_if_sel_pin(void) {
    // Status of UART interface selector pin input; [0] RS-232/TTL mode, [1] RS-422/485 mode
#ifdef __USE_UART_IF_SELECTOR__
    if (GPIO_Input_Read(UART_IF_SEL_PIN)) {
        return UART_IF_RS485;
    } else {
        return UART_IF_DEFAULT;
    }
#else
    return UART_IF_DEFAULT;
#endif
}

// TCP connection status pin
void init_tcpconnection_status_pin(void) {
    GPIO_Configuration(STATUS_TCPCONNECT_PIN, IO_OUTPUT, IO_NOPULL);

#if (DEVICE_BOARD_NAME == PLATYPUS_S2E)
    set_connection_status_io(STATUS_TCPCONNECT_PIN, ON);
#else
    // Pin initial state; Low
    //GPIO_Output_Reset(STATUS_TCPCONNECT_PIN);
    set_connection_status_io(STATUS_TCPCONNECT_PIN, OFF);
#endif
}


#ifdef __USE_HW_FACTORY_RESET__
void init_factory_reset_pin(void) {
    GPIO_Configuration(FAC_RSTn_PIN, IO_INPUT, IO_PULLUP);
    GPIO_Configuration_IRQ(FAC_RSTn_PIN, IO_IRQ_FALL);
}

uint8_t get_factory_reset_pin(void) {
    return GPIO_Input_Read(FAC_RSTn_PIN);
}
#endif

/**
    @brief  Configures LED GPIO.
    @param  Led: Specifies the Led to be configured.
      This parameter can be one of following parameters:
        @arg LED1
        @arg LED2
    @retval None
*/
void LED_Init(Led_TypeDef Led) {
    if (Led >= LEDn) {
        return;
    }

    /* Configure the GPIO_LED pin */
    gpio_init(LED_PIN[Led]);
    gpio_set_dir(LED_PIN[Led], GPIO_OUT);

    /* LED off */
    LED_Off(Led);
}

/**
    @brief  Turns selected LED On.
    @param  Led: Specifies the Led to be set on.
      This parameter can be one of following parameters:
        @arg LED1
        @arg LED2
    @retval None
*/
void LED_On(Led_TypeDef Led) {
    if (Led >= LEDn) {
        return;
    }
    gpio_put(LED_PIN[Led], 1);
}

/**
    @brief  Turns selected LED Off.
    @param  Led: Specifies the Led to be set off.
      This parameter can be one of following parameters:
        @arg LED1
        @arg LED2
    @retval None
*/
void LED_Off(Led_TypeDef Led) {
    if (Led >= LEDn) {
        return;
    }
    gpio_put(LED_PIN[Led], 0);
}

/**
    @brief  Toggles the selected LED.
    @param  Led: Specifies the Led to be toggled.
      This parameter can be one of following parameters:
        @arg LED1
        @arg LED2
    @retval None
*/
void LED_Toggle(Led_TypeDef Led) {
    uint32_t pin_mask = (1ul << LED_PIN[Led]);

    if (Led >= LEDn) {
        return;
    }
    gpio_xor_mask(pin_mask);
}

uint8_t get_LED_Status(Led_TypeDef Led) {
    if (GPIO_INIT[Led] != ENABLE) {
        return 0;
    }
    return gpio_get(LED_PIN[Led]);
}
