#include <string.h>
#include <stdio.h>

#include "pico/stdlib.h"
#include "hardware/gpio.h"
#include "hardware/pwm.h"
#include "hardware/adc.h"
#include "hardware/i2c.h"
#include "hardware/spi.h"
#include "hardware/clocks.h"

#include "pinCtrl.h"
#include "WIZ5XXSR-RP_Debug.h"

typedef enum {
    MODE_DIS = 0,
    MODE_IN,
    MODE_OUT,
    MODE_PWM,
    MODE_ADC,
    MODE_I2C0_SDA,
    MODE_I2C0_SCL,
    MODE_I2C1_SDA,
    MODE_I2C1_SCL,
    MODE_SPI0_RX,
    MODE_SPI0_CS,
    MODE_SPI0_SCK,
    MODE_SPI0_TX,
    MODE_MAX
} mode_t_;

static const char *MODE_STR[MODE_MAX] = {
    "dis", "in", "out", "pwm", "adc",
    "i2c0sda", "i2c0scl", "i2c1sda", "i2c1scl",
    "spi0rx", "spi0cs", "spi0sck", "spi0tx"
};

#define CAP(m)  (1u << (m))
#define CAP_GPIO (CAP(MODE_DIS) | CAP(MODE_IN) | CAP(MODE_OUT) | CAP(MODE_PWM))

typedef struct {
    uint8_t  gp;
    uint16_t caps;
    /* 현재 상태 */
    uint8_t  mode;      /* mode_t_ */
    uint8_t  pull;      /* 0 none, 1 up, 2 down */
    uint8_t  out_val;
    uint32_t pwm_freq;
    uint8_t  pwm_duty;
} pin_state_t;

static pin_state_t s_pins[] = {
    { 0,  CAP_GPIO | CAP(MODE_I2C0_SDA) | CAP(MODE_SPI0_RX)  },
    { 1,  CAP_GPIO | CAP(MODE_I2C0_SCL) | CAP(MODE_SPI0_CS)  },
    { 2,  CAP_GPIO | CAP(MODE_I2C1_SDA) | CAP(MODE_SPI0_SCK) },
    { 3,  CAP_GPIO | CAP(MODE_I2C1_SCL) | CAP(MODE_SPI0_TX)  },
    { 4,  CAP_GPIO | CAP(MODE_I2C0_SDA) | CAP(MODE_SPI0_RX)  },
    { 5,  CAP_GPIO | CAP(MODE_I2C0_SCL) | CAP(MODE_SPI0_CS)  },
    { 6,  CAP_GPIO | CAP(MODE_I2C1_SDA) | CAP(MODE_SPI0_SCK) },
    { 7,  CAP_GPIO | CAP(MODE_I2C1_SCL) | CAP(MODE_SPI0_TX)  },
    { 8,  CAP_GPIO | CAP(MODE_I2C0_SDA) },
    { 9,  CAP_GPIO | CAP(MODE_I2C0_SCL) },
    { 10, CAP_GPIO | CAP(MODE_I2C1_SDA) },
    { 11, CAP_GPIO | CAP(MODE_I2C1_SCL) },
    { 12, CAP_GPIO | CAP(MODE_I2C0_SDA) },
    { 13, CAP_GPIO | CAP(MODE_I2C0_SCL) },
    { 14, CAP_GPIO | CAP(MODE_I2C1_SDA) },
    { 15, CAP_GPIO | CAP(MODE_I2C1_SCL) },
    { 26, CAP_GPIO | CAP(MODE_ADC) | CAP(MODE_I2C1_SDA) },
    { 27, CAP_GPIO | CAP(MODE_ADC) | CAP(MODE_I2C1_SCL) },
    { 28, CAP_GPIO | CAP(MODE_ADC) },
};
#define PIN_COUNT  (sizeof(s_pins) / sizeof(s_pins[0]))

static uint8_t s_adc_inited  = 0;
static uint8_t s_i2c_ready[2] = { 0, 0 };
static uint8_t s_spi_ready    = 0;

static pin_state_t *find_pin(uint8_t gp) {
    for (size_t i = 0; i < PIN_COUNT; i++) {
        if (s_pins[i].gp == gp) {
            return &s_pins[i];
        }
    }
    return NULL;
}

static int mode_from_str(const char *str) {
    for (int m = 0; m < MODE_MAX; m++) {
        if (strcmp(str, MODE_STR[m]) == 0) {
            return m;
        }
    }
    return -1;
}

static int spi_cs_pin(void) {
    for (size_t i = 0; i < PIN_COUNT; i++) {
        if (s_pins[i].mode == MODE_SPI0_CS) {
            return s_pins[i].gp;
        }
    }
    return -1;
}

/* I2C/SPI 버스 구성이 바뀔 때마다 재평가 */
static void update_buses(void) {
    uint8_t sda[2] = { 0, 0 }, scl[2] = { 0, 0 };
    uint8_t sck = 0, tx = 0, rx = 0;

    for (size_t i = 0; i < PIN_COUNT; i++) {
        switch (s_pins[i].mode) {
        case MODE_I2C0_SDA: sda[0] = 1; break;
        case MODE_I2C0_SCL: scl[0] = 1; break;
        case MODE_I2C1_SDA: sda[1] = 1; break;
        case MODE_I2C1_SCL: scl[1] = 1; break;
        case MODE_SPI0_SCK: sck = 1;    break;
        case MODE_SPI0_TX:  tx = 1;     break;
        case MODE_SPI0_RX:  rx = 1;     break;
        default: break;
        }
    }

    for (int b = 0; b < 2; b++) {
        uint8_t ready = (sda[b] && scl[b]) ? 1 : 0;
        if (ready && !s_i2c_ready[b]) {
            i2c_init(b == 0 ? i2c0 : i2c1, 100 * 1000);
            PRT_INFO("pinCtrl: i2c%d ready (100kHz)\r\n", b);
        } else if (!ready && s_i2c_ready[b]) {
            i2c_deinit(b == 0 ? i2c0 : i2c1);
        }
        s_i2c_ready[b] = ready;
    }

    uint8_t spi_ok = (sck && tx && rx) ? 1 : 0;
    if (spi_ok && !s_spi_ready) {
        spi_init(spi0, 1000 * 1000);
        PRT_INFO("pinCtrl: spi0 ready (1MHz)\r\n");
    } else if (!spi_ok && s_spi_ready) {
        spi_deinit(spi0);
    }
    s_spi_ready = spi_ok;
}

static void apply_pwm(uint8_t gp, uint32_t freq, uint8_t duty) {
    uint32_t sys = clock_get_hz(clk_sys);
    uint slice  = pwm_gpio_to_slice_num(gp);
    float div;
    uint32_t wrap;

    if (freq < 50) {
        freq = 50;
    }
    if (duty > 100) {
        duty = 100;
    }

    if (freq < 2000) {
        /* 저주파: wrap 고정, divider로 조절 */
        wrap = 10000;
        div  = (float)sys / ((float)freq * (float)wrap);
        if (div > 255.0f) {
            div = 255.0f;
        }
    } else {
        div  = 1.0f;
        wrap = sys / freq;
        if (wrap < 2) {
            wrap = 2;
        }
        if (wrap > 65536) {
            wrap = 65536;
        }
    }

    gpio_set_function(gp, GPIO_FUNC_PWM);
    pwm_set_clkdiv(slice, div);
    pwm_set_wrap(slice, (uint16_t)(wrap - 1));
    pwm_set_gpio_level(gp, (uint16_t)((uint64_t)wrap * duty / 100));
    pwm_set_enabled(slice, true);
}

static void teardown_pin(pin_state_t *p) {
    switch (p->mode) {
    case MODE_PWM:
        pwm_set_enabled(pwm_gpio_to_slice_num(p->gp), false);
        break;
    default:
        break;
    }
    gpio_deinit(p->gp);
    gpio_disable_pulls(p->gp);
}

void pinctrl_init(void) {
    /* 상태만 초기화. 핀은 사용자가 설정하기 전까지 건드리지 않음 */
    for (size_t i = 0; i < PIN_COUNT; i++) {
        s_pins[i].mode     = MODE_DIS;
        s_pins[i].pull     = 0;
        s_pins[i].out_val  = 0;
        s_pins[i].pwm_freq = 1000;
        s_pins[i].pwm_duty = 50;
    }
}

int pinctrl_set_mode(uint8_t gp, const char *mode, const char *pull,
                     int out_val, uint32_t pwm_freq, uint8_t pwm_duty) {
    pin_state_t *p = find_pin(gp);
    if (!p) {
        return -1;
    }

    int m = mode_from_str(mode);
    if (m < 0) {
        return -2;
    }
    if (m != MODE_DIS && !(p->caps & CAP(m))) {
        return -3;
    }

    /* 같은 버스 역할이 이미 다른 핀에 있으면 그 핀을 해제 (역할당 1핀) */
    if (m >= MODE_I2C0_SDA && m < MODE_MAX) {
        for (size_t i = 0; i < PIN_COUNT; i++) {
            if (&s_pins[i] != p && s_pins[i].mode == (uint8_t)m) {
                teardown_pin(&s_pins[i]);
                s_pins[i].mode = MODE_DIS;
            }
        }
    }

    teardown_pin(p);
    p->mode = (uint8_t)m;

    switch (m) {
    case MODE_DIS:
        break;

    case MODE_IN:
        gpio_init(gp);
        gpio_set_dir(gp, GPIO_IN);
        p->pull = 0;
        if (pull && strcmp(pull, "up") == 0) {
            gpio_pull_up(gp);
            p->pull = 1;
        } else if (pull && strcmp(pull, "down") == 0) {
            gpio_pull_down(gp);
            p->pull = 2;
        }
        break;

    case MODE_OUT:
        gpio_init(gp);
        gpio_set_dir(gp, GPIO_OUT);
        p->out_val = out_val ? 1 : 0;
        gpio_put(gp, p->out_val);
        break;

    case MODE_PWM:
        if (pwm_freq < 50) {
            pwm_freq = 1000;
        }
        if (pwm_duty > 100) {
            pwm_duty = 50;
        }
        p->pwm_freq = pwm_freq;
        p->pwm_duty = pwm_duty;
        apply_pwm(gp, pwm_freq, pwm_duty);
        break;

    case MODE_ADC:
        if (!s_adc_inited) {
            adc_init();
            s_adc_inited = 1;
        }
        adc_gpio_init(gp);
        break;

    case MODE_I2C0_SDA:
    case MODE_I2C0_SCL:
    case MODE_I2C1_SDA:
    case MODE_I2C1_SCL:
        gpio_set_function(gp, GPIO_FUNC_I2C);
        gpio_pull_up(gp);
        break;

    case MODE_SPI0_CS:
        /* CS는 SIO로 직접 제어 */
        gpio_init(gp);
        gpio_set_dir(gp, GPIO_OUT);
        gpio_put(gp, 1);
        break;

    case MODE_SPI0_RX:
    case MODE_SPI0_SCK:
    case MODE_SPI0_TX:
        gpio_set_function(gp, GPIO_FUNC_SPI);
        break;

    default:
        return -2;
    }

    update_buses();
    PRT_INFO("pinCtrl: GP%d -> %s\r\n", gp, MODE_STR[m]);
    return 0;
}

int pinctrl_build_json(char *out, size_t out_len) {
    int off = snprintf(out, out_len, "{\"pins\":[");

    for (size_t i = 0; i < PIN_COUNT && off < (int)out_len - 96; i++) {
        pin_state_t *p = &s_pins[i];

        off += snprintf(out + off, out_len - (size_t)off,
                        "%s{\"gp\":%d,\"m\":\"%s\"",
                        i ? "," : "", p->gp, MODE_STR[p->mode]);

        switch (p->mode) {
        case MODE_IN:
            off += snprintf(out + off, out_len - (size_t)off,
                            ",\"p\":\"%s\",\"v\":%d",
                            p->pull == 1 ? "up" : (p->pull == 2 ? "down" : "none"),
                            gpio_get(p->gp) ? 1 : 0);
            break;
        case MODE_OUT:
            off += snprintf(out + off, out_len - (size_t)off,
                            ",\"v\":%d", p->out_val);
            break;
        case MODE_PWM:
            off += snprintf(out + off, out_len - (size_t)off,
                            ",\"f\":%lu,\"d\":%d",
                            (unsigned long)p->pwm_freq, p->pwm_duty);
            break;
        case MODE_ADC:
            adc_select_input(p->gp - 26);
            off += snprintf(out + off, out_len - (size_t)off,
                            ",\"v\":%d", (int)adc_read());
            break;
        default:
            break;
        }
        off += snprintf(out + off, out_len - (size_t)off, "}");
    }

    off += snprintf(out + off, out_len - (size_t)off,
                    "],\"i2c0\":%d,\"i2c1\":%d,\"spi0\":%d}",
                    s_i2c_ready[0], s_i2c_ready[1], s_spi_ready);
    return off;
}

/*  -----------------------------------------------------------------------
    I2C
    --------------------------------------------------------------------- */
static i2c_inst_t *i2c_bus(int bus) {
    return bus == 0 ? i2c0 : i2c1;
}

int pinctrl_i2c_scan(int bus, char *out, size_t out_len) {
    if (bus < 0 || bus > 1 || !s_i2c_ready[bus]) {
        snprintf(out, out_len, "{\"err\":\"i2c%d not configured\"}", bus);
        return -1;
    }

    int off  = snprintf(out, out_len, "{\"found\":[");
    int n    = 0;
    uint8_t b;
    for (uint8_t addr = 0x08; addr <= 0x77 && off < (int)out_len - 16; addr++) {
        if (i2c_read_timeout_us(i2c_bus(bus), addr, &b, 1, false, 2000) >= 1) {
            off += snprintf(out + off, out_len - (size_t)off,
                            "%s\"0x%02X\"", n ? "," : "", addr);
            n++;
        }
    }
    snprintf(out + off, out_len - (size_t)off, "]}");
    return 0;
}

int pinctrl_i2c_read(int bus, uint8_t addr, uint8_t reg, uint8_t len,
                     char *out, size_t out_len) {
    if (bus < 0 || bus > 1 || !s_i2c_ready[bus]) {
        snprintf(out, out_len, "{\"err\":\"i2c%d not configured\"}", bus);
        return -1;
    }
    if (len < 1) {
        len = 1;
    }
    if (len > PINCTRL_I2C_MAX_LEN) {
        len = PINCTRL_I2C_MAX_LEN;
    }

    uint8_t buf[PINCTRL_I2C_MAX_LEN];
    if (i2c_write_timeout_us(i2c_bus(bus), addr, &reg, 1, true, 5000) != 1) {
        snprintf(out, out_len, "{\"err\":\"no ack (addr 0x%02X)\"}", addr);
        return -2;
    }
    int rd = i2c_read_timeout_us(i2c_bus(bus), addr, buf, len, false, 10000);
    if (rd < 1) {
        snprintf(out, out_len, "{\"err\":\"read failed\"}");
        return -3;
    }

    int off = snprintf(out, out_len, "{\"data\":\"");
    for (int i = 0; i < rd && off < (int)out_len - 8; i++) {
        off += snprintf(out + off, out_len - (size_t)off, "%02X", buf[i]);
    }
    snprintf(out + off, out_len - (size_t)off, "\"}");
    return 0;
}

int pinctrl_i2c_write(int bus, uint8_t addr, uint8_t reg,
                      const uint8_t *data, uint8_t len,
                      char *out, size_t out_len) {
    if (bus < 0 || bus > 1 || !s_i2c_ready[bus]) {
        snprintf(out, out_len, "{\"err\":\"i2c%d not configured\"}", bus);
        return -1;
    }
    if (len > PINCTRL_I2C_MAX_LEN) {
        len = PINCTRL_I2C_MAX_LEN;
    }

    uint8_t buf[PINCTRL_I2C_MAX_LEN + 1];
    buf[0] = reg;
    memcpy(buf + 1, data, len);
    if (i2c_write_timeout_us(i2c_bus(bus), addr, buf, (size_t)len + 1, false, 10000)
            != (int)(len + 1)) {
        snprintf(out, out_len, "{\"err\":\"write failed (addr 0x%02X)\"}", addr);
        return -2;
    }
    snprintf(out, out_len, "{\"ok\":1}");
    return 0;
}

/*  -----------------------------------------------------------------------
    SPI
    --------------------------------------------------------------------- */
int pinctrl_spi_xfer(const uint8_t *tx, uint8_t len,
                     char *out, size_t out_len) {
    if (!s_spi_ready) {
        snprintf(out, out_len, "{\"err\":\"spi0 not configured (need sck/tx/rx)\"}");
        return -1;
    }
    if (len < 1 || len > PINCTRL_SPI_MAX_LEN) {
        snprintf(out, out_len, "{\"err\":\"invalid length\"}");
        return -2;
    }

    uint8_t rx[PINCTRL_SPI_MAX_LEN];
    int cs = spi_cs_pin();

    if (cs >= 0) {
        gpio_put((uint)cs, 0);
    }
    spi_write_read_blocking(spi0, tx, rx, len);
    if (cs >= 0) {
        gpio_put((uint)cs, 1);
    }

    int off = snprintf(out, out_len, "{\"rx\":\"");
    for (int i = 0; i < len && off < (int)out_len - 8; i++) {
        off += snprintf(out + off, out_len - (size_t)off, "%02X", rx[i]);
    }
    snprintf(out + off, out_len - (size_t)off, "\"}");
    return 0;
}
