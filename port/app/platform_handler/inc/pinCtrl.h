#ifndef PINCTRL_H_
#define PINCTRL_H_

#include <stdint.h>
#include <stddef.h>

/*
    pinCtrl: 웹 UI에서 제어 가능한 사용자 핀 관리

    사용 가능 핀 (W55RP20-S2E 기준, S2E/W5500/시스템 예약 핀 제외):
      GP0, GP1, GP2, GP3, GP16, GP17, GP19, GP26, GP27, GP28

    예약 핀:
      GP4-7   : DATA UART1 (TX/RX/CTS/RTS)
      GP8-9   : DTR/DSR
      GP10-11 : 상태 LED (PHY/TCP)
      GP12-15 : IF 선택/HW 트리거/부트 모드
      GP18    : Factory Reset
      GP20-25 : W5500 내부 연결
*/

#define PINCTRL_JSON_BUF_SIZE   2048
#define PINCTRL_SPI_MAX_LEN     16
#define PINCTRL_I2C_MAX_LEN     16

void pinctrl_init(void);

/*  핀 모드 설정. mode 문자열:
    "dis","in","out","pwm","adc",
    "i2c0sda","i2c0scl","i2c1sda","i2c1scl",
    "spi0rx","spi0cs","spi0sck","spi0tx"
    pull: "none"|"up"|"down" (in 모드에서만 사용)
    성공 0, 실패 음수 */
int pinctrl_set_mode(uint8_t gp, const char *mode, const char *pull,
                     int out_val, uint32_t pwm_freq, uint8_t pwm_duty);

/* 전체 핀 상태를 JSON으로 작성. 작성된 길이 반환 */
int pinctrl_build_json(char *out, size_t out_len);

/*  I2C 유틸 (해당 버스의 SDA/SCL이 모두 설정된 경우에만 동작)
    결과 JSON을 out에 작성, 성공 0 / 실패 음수 (실패 시에도 에러 JSON 작성) */
int pinctrl_i2c_scan(int bus, char *out, size_t out_len);
int pinctrl_i2c_read(int bus, uint8_t addr, uint8_t reg, uint8_t len,
                     char *out, size_t out_len);
int pinctrl_i2c_write(int bus, uint8_t addr, uint8_t reg,
                      const uint8_t *data, uint8_t len,
                      char *out, size_t out_len);

/* SPI0 전송 (SCK/TX/RX 설정 시 동작, CS는 선택) */
int pinctrl_spi_xfer(const uint8_t *tx, uint8_t len,
                     char *out, size_t out_len);

#endif /* PINCTRL_H_ */
