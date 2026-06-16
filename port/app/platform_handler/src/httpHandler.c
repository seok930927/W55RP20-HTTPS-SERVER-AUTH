#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "port_common.h"
#include "httpHandler.h"
#include "httpsAuth.h"
#include "socket.h"
#include "netHandler.h"
#include "SSLInterface.h"
#include "deviceHandler.h"
#include "pinCtrl.h"
#include "board_page.h"

#define HTTPS_SERVER_PORT   443
#define HTTPS_RX_BUF_SIZE   2048
#define HTTPS_TX_CHUNK_SIZE 512   /* 레퍼런스(W55RP20-HTTPS)와 동일 — 검증된 값 */
#define HTTPS_HDR_BUF_SIZE  512

/*  keep-alive 유휴 타임아웃.
    핸드셰이크(RSA ≈ 2초)를 매 요청마다 반복하지 않도록 연결을 유지한다.
    UI 폴링 주기(3초)보다 충분히 길게. */
#define HTTPS_KEEPALIVE_IDLE_MS 15000

extern xSemaphoreHandle net_http_webserver_sem;

static char    s_json_buf[PINCTRL_JSON_BUF_SIZE];

static const uint8_t https_server_socks[MAX_HTTPSOCK] = {
    SOCK_HTTPSERVER_1,
    SOCK_HTTPSERVER_2,
    SOCK_HTTPSERVER_3
};
static wiz_tls_context https_tls_ctx[MAX_HTTPSOCK];
static uint8_t https_tls_active[MAX_HTTPSOCK]      = { FALSE, };
static unsigned char https_rx_buf[MAX_HTTPSOCK][HTTPS_RX_BUF_SIZE];
static uint8_t https_last_sock_state[MAX_HTTPSOCK];
static uint32_t https_last_req_ms[MAX_HTTPSOCK] = { 0, };

/*  -----------------------------------------------------------------------
    HTML 페이지 (최소 크기)
    --------------------------------------------------------------------- */
static const char PAGE_LOGIN[] =
    "<!DOCTYPE html><html><head><meta charset=UTF-8><title>Login</title>"
    "<style>body{font-family:sans-serif;max-width:360px;margin:60px auto}"
    "input{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}"
    "button{width:100%;padding:10px;background:#0055aa;color:#fff;border:none;cursor:pointer}"
    ".e{color:red;font-size:.9em}</style></head><body>"
    "<h2>Login</h2>"
    "<form method=post action=/login>"
    "ID: <input name=user autocomplete=username><br>"
    "PW: <input type=password name=pass autocomplete=current-password><br>"
    "<button>Login</button>"
    "</form>"
    "<p class=e>%s</p>"
    "<hr><a href=/setup>Create Account</a>"
    "</body></html>";

static const char PAGE_SETUP[] =
    "<!DOCTYPE html><html><head><meta charset=UTF-8><title>Create Account</title>"
    "<style>body{font-family:sans-serif;max-width:360px;margin:60px auto}"
    "input{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}"
    "button{width:100%;padding:10px;background:#0055aa;color:#fff;border:none;cursor:pointer}"
    ".e{color:red;font-size:.9em}</style></head><body>"
    "<h2>Create Account</h2>"
    "<form method=post action=/setup>"
    "Creation PW: <input type=password name=cpass><br>"
    "ID: <input name=user autocomplete=username><br>"
    "PW: <input type=password name=pass autocomplete=new-password><br>"
    "<button>Create</button>"
    "</form>"
    "<p class=e>%s</p>"
    "<a href=/login>Back to Login</a>"
    "</body></html>";

static const char PAGE_ACCOUNT[] =
    "<!DOCTYPE html><html><head><meta charset=UTF-8><title>Settings</title>"
    "<style>body{font-family:sans-serif;max-width:400px;margin:60px auto}"
    "input{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}"
    "button{width:100%;padding:10px;background:#0055aa;color:#fff;border:none;cursor:pointer}"
    ".del{background:#cc2200}.e{color:red;font-size:.9em}"
    "ul{padding:0}li{list-style:none;padding:4px 0;border-bottom:1px solid #eee}"
    "</style></head><body>"
    "<h2>Settings — Account Management</h2>"
    "<h3>Accounts (%d/%d)</h3><ul>%s</ul>"
    "<h3>Add Account</h3>"
    "<form method=post action=/account/add>"
    "Creation PW: <input type=password name=cpass><br>"
    "ID: <input name=user><br>"
    "PW: <input type=password name=pass><br>"
    "<button>Add</button>"
    "</form>"
    "<h3>Delete Account</h3>"
    "<form method=post action=/account/del>"
    "ID: <input name=user><br>"
    "<button class=del>Delete</button>"
    "</form>"
    "<p class=e>%s</p>"
    "<hr><a href=/>Board Control</a> | <a href=/logout>Logout</a>"
    "</body></html>";

/*  -----------------------------------------------------------------------
    저수준 송신
    --------------------------------------------------------------------- */
static int https_write_all(wiz_tls_context *ctx, const unsigned char *buf, size_t len) {
    size_t sent = 0;
    while (sent < len) {
        device_wdt_reset();
        int ret = mbedtls_ssl_write(ctx->ssl, buf + sent, len - sent);
        if (ret > 0) {
            sent += (size_t)ret;
            continue;
        }
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            vTaskDelay(pdMS_TO_TICKS(10)); continue;
        }
        return -1;
    }
    return 0;
}

/*  -----------------------------------------------------------------------
    HTTP 응답 헬퍼
    --------------------------------------------------------------------- */
static int send_html(wiz_tls_context *ctx, const char *body, size_t body_len) {
    char hdr[HTTPS_HDR_BUF_SIZE];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 200 OK\r\n"
                           "Content-Type: text/html; charset=UTF-8\r\n"
                           "Content-Length: %u\r\n"
                           "Connection: keep-alive\r\n\r\n",
                           (unsigned int)body_len);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        return -1;
    }
    if (https_write_all(ctx, (const unsigned char *)hdr, (size_t)hdr_len) < 0) {
        return -1;
    }

    size_t sent = 0;
    while (sent < body_len) {
        size_t chunk = body_len - sent;
        if (chunk > HTTPS_TX_CHUNK_SIZE) {
            chunk = HTTPS_TX_CHUNK_SIZE;
        }
        if (https_write_all(ctx, (const unsigned char *)body + sent, chunk) < 0) {
            return -1;
        }
        sent += chunk;
        vTaskDelay(pdMS_TO_TICKS(1));
    }
    return 0;
}

static int send_json(wiz_tls_context *ctx, int status, const char *body) {
    char hdr[HTTPS_HDR_BUF_SIZE];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 %s\r\n"
                           "Content-Type: application/json\r\n"
                           "Content-Length: %u\r\n"
                           "Cache-Control: no-store\r\n"
                           "Connection: keep-alive\r\n\r\n",
                           (status == 200) ? "200 OK" : "401 Unauthorized",
                           (unsigned int)strlen(body));
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        return -1;
    }
    if (https_write_all(ctx, (const unsigned char *)hdr, (size_t)hdr_len) < 0) {
        return -1;
    }
    return https_write_all(ctx, (const unsigned char *)body, strlen(body));
}

static int send_redirect(wiz_tls_context *ctx, const char *location) {
    char hdr[HTTPS_HDR_BUF_SIZE];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: keep-alive\r\n\r\n",
                           location);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        return -1;
    }
    return https_write_all(ctx, (const unsigned char *)hdr, (size_t)hdr_len);
}

static int send_redirect_with_cookie(wiz_tls_context *ctx, const char *location,
                                     const char *token_hex) {
    char hdr[HTTPS_HDR_BUF_SIZE];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s\r\n"
                           "Set-Cookie: session=%s; HttpOnly; Secure; SameSite=Strict\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: keep-alive\r\n\r\n",
                           location, token_hex);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        return -1;
    }
    return https_write_all(ctx, (const unsigned char *)hdr, (size_t)hdr_len);
}

static int send_redirect_clear_cookie(wiz_tls_context *ctx, const char *location) {
    char hdr[HTTPS_HDR_BUF_SIZE];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s\r\n"
                           "Set-Cookie: session=; HttpOnly; Secure; SameSite=Strict; Max-Age=0\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: keep-alive\r\n\r\n",
                           location);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        return -1;
    }
    return https_write_all(ctx, (const unsigned char *)hdr, (size_t)hdr_len);
}

/*  -----------------------------------------------------------------------
    HTTP 요청 파싱 헬퍼
    --------------------------------------------------------------------- */
static void parse_cookie(const char *req, char *token_out, size_t token_len) {
    token_out[0] = '\0';
    const char *p = strstr(req, "Cookie:");
    if (!p) {
        return;
    }
    p = strstr(p, "session=");
    if (!p) {
        return;
    }
    p += 8;
    size_t i = 0;
    while (*p && *p != ';' && *p != '\r' && *p != '\n' && i < token_len - 1) {
        token_out[i++] = *p++;
    }
    token_out[i] = '\0';
}

static const char *find_body(const char *req) {
    const char *p = strstr(req, "\r\n\r\n");
    return p ? p + 4 : NULL;
}

static void url_decode(const char *src, char *dst, size_t dst_len) {
    size_t i = 0;
    while (*src && i < dst_len - 1) {
        if (*src == '%' && src[1] && src[2]) {
            unsigned int val;
            if (sscanf(src + 1, "%02x", &val) == 1) {
                dst[i++] = (char)val;
                src += 3;
            } else {
                dst[i++] = *src++;
            }
        } else if (*src == '+') {
            dst[i++] = ' ';
            src++;
        } else {
            dst[i++] = *src++;
        }
    }
    dst[i] = '\0';
}

static void get_form_field(const char *body, const char *name,
                           char *out, size_t out_len) {
    out[0] = '\0';
    if (!body) {
        return;
    }
    size_t nlen = strlen(name);
    const char *p = body;
    while (*p) {
        if (strncmp(p, name, nlen) == 0 && p[nlen] == '=') {
            p += nlen + 1;
            char raw[256] = {0};
            size_t i = 0;
            while (*p && *p != '&' && i < sizeof(raw) - 1) {
                raw[i++] = *p++;
            }
            raw[i] = '\0';
            url_decode(raw, out, out_len);
            return;
        }
        while (*p && *p != '&') {
            p++;
        }
        if (*p == '&') {
            p++;
        }
    }
}

/*  -----------------------------------------------------------------------
    라우트 핸들러
    --------------------------------------------------------------------- */
static void handle_get_root(wiz_tls_context *ctx, const char *session) {
    if (https_auth_account_count() == 0) {
        send_redirect(ctx, "/setup");
        return;
    }
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }
    send_html(ctx, (const char *)BOARD_PAGE, BOARD_PAGE_LEN);
}

static void handle_get_login(wiz_tls_context *ctx, const char *query) {
    char body[sizeof(PAGE_LOGIN) + 64];
    const char *err = "";
    if (query && strstr(query, "err=1")) {
        err = "Invalid ID or password.";
    }
    snprintf(body, sizeof(body), PAGE_LOGIN, err);
    send_html(ctx, body, strlen(body));
}

static void handle_post_login(wiz_tls_context *ctx, const char *body_str) {
    char user[HTTPS_USER_LEN] = {0};
    char pass[64]             = {0};
    get_form_field(body_str, "user", user, sizeof(user));
    get_form_field(body_str, "pass", pass, sizeof(pass));

    char token[HTTPS_SESSION_TOKEN_HEX] = {0};
    if (https_auth_login(user, pass, token) == 0) {
        send_redirect_with_cookie(ctx, "/", token);
    } else {
        send_redirect(ctx, "/login?err=1");
    }
}

static void handle_get_setup(wiz_tls_context *ctx, const char *query) {
    char body[sizeof(PAGE_SETUP) + 64];
    const char *err = "";
    if (query) {
        if (strstr(query, "err=1")) {
            err = "Invalid creation password.";
        } else if (strstr(query, "err=2")) {
            err = "Account limit reached (5).";
        } else if (strstr(query, "err=3")) {
            err = "ID already exists.";
        } else if (strstr(query, "err=4")) {
            err = "Enter ID and password.";
        }
    }
    snprintf(body, sizeof(body), PAGE_SETUP, err);
    send_html(ctx, body, strlen(body));
}

static void handle_post_setup(wiz_tls_context *ctx, const char *body_str) {
    char cpass[64]            = {0};
    char user[HTTPS_USER_LEN] = {0};
    char pass[64]             = {0};
    get_form_field(body_str, "cpass", cpass, sizeof(cpass));
    get_form_field(body_str, "user",  user,  sizeof(user));
    get_form_field(body_str, "pass",  pass,  sizeof(pass));

    if (!https_auth_verify_creation_pass(cpass)) {
        send_redirect(ctx, "/setup?err=1");
        return;
    }
    if (strlen(user) == 0 || strlen(pass) == 0)  {
        send_redirect(ctx, "/setup?err=4");
        return;
    }

    int ret = https_auth_create_account(user, pass);
    if (ret == -1) {
        send_redirect(ctx, "/setup?err=2");
        return;
    } else if (ret == -4) {
        send_redirect(ctx, "/setup?err=3");
        return;
    } else if (ret < 0)   {
        send_redirect(ctx, "/setup?err=4");
        return;
    }

    send_redirect(ctx, "/login");
}

static void handle_get_account(wiz_tls_context *ctx, const char *session, const char *query) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }

    https_account_t accs[HTTPS_MAX_ACCOUNTS];
    uint8_t count = 0;
    https_auth_get_accounts(accs, &count);

    char list_buf[256] = {0};
    for (int i = 0; i < count; i++) {
        char item[64];
        snprintf(item, sizeof(item), "<li>%s</li>", accs[i].user);
        strncat(list_buf, item, sizeof(list_buf) - strlen(list_buf) - 1);
    }

    const char *err = "";
    if (query) {
        if (strstr(query, "err=1")) {
            err = "Invalid creation password.";
        } else if (strstr(query, "err=2")) {
            err = "Account limit reached (5).";
        } else if (strstr(query, "err=3")) {
            err = "ID already exists.";
        } else if (strstr(query, "err=4")) {
            err = "Enter ID and password.";
        } else if (strstr(query, "err=5")) {
            err = "ID not found.";
        } else if (strstr(query, "ok=1")) {
            err = "Account added.";
        } else if (strstr(query, "ok=2")) {
            err = "Account deleted.";
        }
    }

    char body[sizeof(PAGE_ACCOUNT) + 512];
    snprintf(body, sizeof(body), PAGE_ACCOUNT,
             (int)count, HTTPS_MAX_ACCOUNTS, list_buf, err);
    send_html(ctx, body, strlen(body));
}

static void handle_post_account_add(wiz_tls_context *ctx, const char *session,
                                    const char *body_str) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }

    char cpass[64]            = {0};
    char user[HTTPS_USER_LEN] = {0};
    char pass[64]             = {0};
    get_form_field(body_str, "cpass", cpass, sizeof(cpass));
    get_form_field(body_str, "user",  user,  sizeof(user));
    get_form_field(body_str, "pass",  pass,  sizeof(pass));

    if (!https_auth_verify_creation_pass(cpass)) {
        send_redirect(ctx, "/account?err=1");
        return;
    }
    if (strlen(user) == 0 || strlen(pass) == 0)  {
        send_redirect(ctx, "/account?err=4");
        return;
    }

    int ret = https_auth_create_account(user, pass);
    if (ret == -1) {
        send_redirect(ctx, "/account?err=2");
        return;
    } else if (ret == -4) {
        send_redirect(ctx, "/account?err=3");
        return;
    } else if (ret < 0)   {
        send_redirect(ctx, "/account?err=4");
        return;
    }

    send_redirect(ctx, "/account?ok=1");
}

static void handle_post_account_del(wiz_tls_context *ctx, const char *session,
                                    const char *body_str) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }

    char user[HTTPS_USER_LEN] = {0};
    get_form_field(body_str, "user", user, sizeof(user));

    if (https_auth_delete_account(user) < 0) {
        send_redirect(ctx, "/account?err=5");
    } else {
        send_redirect(ctx, "/account?ok=2");
    }
}

static void handle_get_logout(wiz_tls_context *ctx, const char *session) {
    if (session[0]) {
        https_auth_logout(session);
    }
    send_redirect_clear_cookie(ctx, "/login");
}

/*  -----------------------------------------------------------------------
    핀 제어 JSON API
    --------------------------------------------------------------------- */
/* API용 인증 체크. 실패 시 401 JSON 응답까지 처리 */
static int api_auth(wiz_tls_context *ctx, const char *session) {
    if (https_auth_verify_session(session)) {
        return 1;
    }
    send_json(ctx, 401, "{\"err\":\"auth\"}");
    return 0;
}

/* "A1B2C3" 형식 hex 문자열 → 바이트 배열. 변환된 개수 반환, 오류 -1 */
static int parse_hex_bytes(const char *str, uint8_t *out, int max) {
    int n = 0;
    while (str[0] && str[1] && n < max) {
        unsigned int byte;
        char tmp[3] = { str[0], str[1], '\0' };
        if (sscanf(tmp, "%02x", &byte) != 1) {
            return -1;
        }
        out[n++] = (uint8_t)byte;
        str += 2;
    }
    if (str[0] != '\0' && n < max) {
        return -1;    /* 홀수 길이 */
    }
    return n;
}

static void handle_api_pins(wiz_tls_context *ctx, const char *session) {
    if (!api_auth(ctx, session)) {
        return;
    }
    pinctrl_build_json(s_json_buf, sizeof(s_json_buf));
    send_json(ctx, 200, s_json_buf);
}

static void handle_api_pin(wiz_tls_context *ctx, const char *session,
                           const char *body_str) {
    if (!api_auth(ctx, session)) {
        return;
    }

    char gp_s[8] = {0}, mode_s[12] = {0}, pull_s[8] = {0};
    char val_s[8] = {0}, freq_s[12] = {0}, duty_s[8] = {0};
    get_form_field(body_str, "gp",   gp_s,   sizeof(gp_s));
    get_form_field(body_str, "mode", mode_s, sizeof(mode_s));
    get_form_field(body_str, "pull", pull_s, sizeof(pull_s));
    get_form_field(body_str, "val",  val_s,  sizeof(val_s));
    get_form_field(body_str, "freq", freq_s, sizeof(freq_s));
    get_form_field(body_str, "duty", duty_s, sizeof(duty_s));

    if (gp_s[0] == '\0' || mode_s[0] == '\0') {
        send_json(ctx, 200, "{\"err\":\"missing gp/mode\"}");
        return;
    }

    int ret = pinctrl_set_mode((uint8_t)atoi(gp_s), mode_s, pull_s,
                               atoi(val_s),
                               (uint32_t)strtoul(freq_s, NULL, 10),
                               (uint8_t)atoi(duty_s));
    if (ret < 0) {
        snprintf(s_json_buf, sizeof(s_json_buf),
                 "{\"err\":\"invalid pin/mode (%d)\"}", ret);
        send_json(ctx, 200, s_json_buf);
        return;
    }

    /* 변경 후 전체 상태 반환 → UI가 한 번에 동기화 */
    pinctrl_build_json(s_json_buf, sizeof(s_json_buf));
    send_json(ctx, 200, s_json_buf);
}

static void handle_api_i2c(wiz_tls_context *ctx, const char *session,
                           const char *body_str) {
    if (!api_auth(ctx, session)) {
        return;
    }

    char op[8] = {0}, bus_s[4] = {0}, addr_s[8] = {0};
    char reg_s[8] = {0}, len_s[8] = {0}, data_s[64] = {0};
    get_form_field(body_str, "op",   op,     sizeof(op));
    get_form_field(body_str, "bus",  bus_s,  sizeof(bus_s));
    get_form_field(body_str, "addr", addr_s, sizeof(addr_s));
    get_form_field(body_str, "reg",  reg_s,  sizeof(reg_s));
    get_form_field(body_str, "len",  len_s,  sizeof(len_s));
    get_form_field(body_str, "data", data_s, sizeof(data_s));

    int     bus  = atoi(bus_s);
    uint8_t addr = (uint8_t)strtoul(addr_s, NULL, 16);
    uint8_t reg  = (uint8_t)strtoul(reg_s, NULL, 16);

    if (strcmp(op, "scan") == 0) {
        pinctrl_i2c_scan(bus, s_json_buf, sizeof(s_json_buf));
    } else if (strcmp(op, "read") == 0) {
        pinctrl_i2c_read(bus, addr, reg, (uint8_t)atoi(len_s),
                         s_json_buf, sizeof(s_json_buf));
    } else if (strcmp(op, "write") == 0) {
        uint8_t data[PINCTRL_I2C_MAX_LEN];
        int n = parse_hex_bytes(data_s, data, sizeof(data));
        if (n < 0) {
            snprintf(s_json_buf, sizeof(s_json_buf), "{\"err\":\"bad hex data\"}");
        } else {
            pinctrl_i2c_write(bus, addr, reg, data, (uint8_t)n,
                              s_json_buf, sizeof(s_json_buf));
        }
    } else {
        snprintf(s_json_buf, sizeof(s_json_buf), "{\"err\":\"bad op\"}");
    }
    send_json(ctx, 200, s_json_buf);
}

static void handle_api_spi(wiz_tls_context *ctx, const char *session,
                           const char *body_str) {
    if (!api_auth(ctx, session)) {
        return;
    }

    char data_s[64] = {0};
    get_form_field(body_str, "data", data_s, sizeof(data_s));

    uint8_t tx[PINCTRL_SPI_MAX_LEN];
    int n = parse_hex_bytes(data_s, tx, sizeof(tx));
    if (n <= 0) {
        snprintf(s_json_buf, sizeof(s_json_buf), "{\"err\":\"bad hex data\"}");
    } else {
        pinctrl_spi_xfer(tx, (uint8_t)n, s_json_buf, sizeof(s_json_buf));
    }
    send_json(ctx, 200, s_json_buf);
}

/*  -----------------------------------------------------------------------
    요청 디스패처
    --------------------------------------------------------------------- */
static void dispatch_request(wiz_tls_context *ctx, const char *req) {
    char method[16]  = {0};
    char path[256]   = {0};
    char session[HTTPS_SESSION_TOKEN_HEX] = {0};

    /* query string 보존용 */
    char full_path[256] = {0};
    sscanf(req, "%15s %255s", method, full_path);

    /* path와 query 분리 */
    strncpy(path, full_path, sizeof(path) - 1);
    char *q = strchr(path, '?');
    const char *query = NULL;
    if (q) {
        *q   = '\0';
        query = q + 1;
    }

    parse_cookie(req, session, sizeof(session));
    const char *body = find_body(req);

    PRT_SSL("HTTPS %s %s\r\n", method, full_path);

    if (strcmp(method, "GET") == 0) {
        if (strcmp(path, "/")        == 0) {
            handle_get_root(ctx, session);
        } else if (strcmp(path, "/login")   == 0) {
            handle_get_login(ctx, query);
        } else if (strcmp(path, "/setup")   == 0) {
            handle_get_setup(ctx, query);
        } else if (strcmp(path, "/account") == 0) {
            handle_get_account(ctx, session, query);
        } else if (strcmp(path, "/logout")  == 0) {
            handle_get_logout(ctx, session);
        } else if (strcmp(path, "/api/pins") == 0) {
            handle_api_pins(ctx, session);
        } else {
            send_redirect(ctx, "/");
        }
    } else if (strcmp(method, "POST") == 0) {
        if (strcmp(path, "/login")       == 0) {
            handle_post_login(ctx, body);
        } else if (strcmp(path, "/setup")       == 0) {
            handle_post_setup(ctx, body);
        } else if (strcmp(path, "/account/add") == 0) {
            handle_post_account_add(ctx, session, body);
        } else if (strcmp(path, "/account/del") == 0) {
            handle_post_account_del(ctx, session, body);
        } else if (strcmp(path, "/api/pin")  == 0) {
            handle_api_pin(ctx, session, body);
        } else if (strcmp(path, "/api/i2c")  == 0) {
            handle_api_i2c(ctx, session, body);
        } else if (strcmp(path, "/api/spi")  == 0) {
            handle_api_spi(ctx, session, body);
        } else {
            send_redirect(ctx, "/");
        }
    } else {
        send_redirect(ctx, "/");
    }
}

/*  -----------------------------------------------------------------------
    세션 종료
    --------------------------------------------------------------------- */
static void https_close_session(uint8_t sock, wiz_tls_context *ctx, uint8_t *tls_active) {
    if (*tls_active) {
        wiz_tls_close_notify(ctx);
        wiz_tls_deinit(ctx);
        *tls_active = FALSE;
    }
    if (getSn_SR(sock) != SOCK_CLOSED) {
        /*  블로킹 disconnect() 사용 금지!
            서버가 먼저 끊는 keep-alive 유휴 종료에서는 피어(브라우저)가
            FIN에 ACK만 하고 자기 FIN을 보내지 않을 수 있다. 그 경우
            disconnect()는 FIN_WAIT_2에서 무한 대기 → 워치독(30s) 리셋.
            DISCON 명령만 보내고 최대 500ms 기다린 뒤 강제 close 한다. */
        setSn_CR(sock, Sn_CR_DISCON);
        while (getSn_CR(sock));
        for (int w = 0; w < 50 && getSn_SR(sock) != SOCK_CLOSED; w++) {
            vTaskDelay(pdMS_TO_TICKS(10));
            device_wdt_reset();
        }
        close(sock);
    }
}

/*  -----------------------------------------------------------------------
    HTTPS 서버 Task
    --------------------------------------------------------------------- */
void http_webserver_task(void *argument) {
    uint8_t i;
    (void)argument;

    https_auth_init();
    pinctrl_init();

    memset(https_tls_ctx, 0, sizeof(https_tls_ctx));
    memset(https_rx_buf, 0, sizeof(https_rx_buf));
    for (i = 0; i < MAX_HTTPSOCK; i++) {
        https_last_sock_state[i] = 0xff;
    }

    while (1) {
        device_wdt_reset();

        if (get_net_status() == NET_LINK_DISCONNECTED) {
            for (i = 0; i < MAX_HTTPSOCK; i++) {
                https_close_session(https_server_socks[i], &https_tls_ctx[i], &https_tls_active[i]);
            }
            xSemaphoreTake(net_http_webserver_sem, portMAX_DELAY);
        }

        for (i = 0; i < MAX_HTTPSOCK; i++) {
            uint8_t sock       = https_server_socks[i];
            uint8_t sock_state = getSn_SR(sock);

            if (sock_state != https_last_sock_state[i]) {
                PRT_SSL("HTTPS socket[%d] state = 0x%02x\r\n", sock, sock_state);
                https_last_sock_state[i] = sock_state;
            }

            switch (sock_state) {
            case SOCK_CLOSED:
                if (socket(sock, Sn_MR_TCP, HTTPS_SERVER_PORT, 0x00) == sock) {
                    PRT_SSL("HTTPS socket[%d] opened on port %d\r\n", sock, HTTPS_SERVER_PORT);
                    listen(sock);
                }
                break;

            case SOCK_INIT:
                listen(sock);
                break;

            case SOCK_ESTABLISHED:
                if (getSn_IR(sock) & Sn_IR_CON) {
                    setSn_IR(sock, Sn_IR_CON);
                }

                if (!https_tls_active[i]) {
                    if (getSn_RX_RSR(sock) == 0) {
                        break;
                    }

                    int socket_fd = sock;
                    memset(&https_tls_ctx[i], 0, sizeof(https_tls_ctx[i]));
                    if (wiz_tls_server_init(&https_tls_ctx[i], &socket_fd) < 0) {
                        wiz_tls_deinit(&https_tls_ctx[i]);
                        https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                        break;
                    }
                    if (wiz_tls_server_handshake(&https_tls_ctx[i]) < 0) {
                        wiz_tls_deinit(&https_tls_ctx[i]);
                        https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                        break;
                    }
                    https_tls_active[i]   = TRUE;
                    https_last_req_ms[i] = millis();
                    break;
                }

                if (getSn_RX_RSR(sock) == 0 &&
                        mbedtls_ssl_check_pending(https_tls_ctx[i].ssl) == 0) {
                    /* keep-alive 연결 유휴 타임아웃 → 소켓 회수 */
                    if ((millis() - https_last_req_ms[i]) >= HTTPS_KEEPALIVE_IDLE_MS) {
                        https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                    }
                    break;
                }

                {
                    memset(https_rx_buf[i], 0, sizeof(https_rx_buf[i]));
                    int total   = 0;
                    int rd_err  = 0;
                    int wait_ms = 0;

                    /*  Read until complete HTTP request received (headers + body).
                        Over the internet, POST body may arrive in a separate TLS record. */
                    while (total < (int)sizeof(https_rx_buf[i]) - 1) {
                        int ret = mbedtls_ssl_read(https_tls_ctx[i].ssl,
                                                   https_rx_buf[i] + total,
                                                   sizeof(https_rx_buf[i]) - (size_t)total - 1);
                        if (ret > 0) {
                            total += ret;
                            https_rx_buf[i][total] = '\0';
                            wait_ms = 0;

                            const char *hdr_end = strstr((const char *)https_rx_buf[i], "\r\n\r\n");
                            if (hdr_end) {
                                const char *cl = strstr((const char *)https_rx_buf[i], "Content-Length:");
                                if (!cl) {
                                    break;    /* GET — no body */
                                }
                                int clen = 0;
                                sscanf(cl + 15, "%d", &clen);
                                int body_recv = total - (int)(hdr_end - (const char *)https_rx_buf[i]) - 4;
                                if (body_recv >= clen) {
                                    break;    /* body complete */
                                }
                            }
                        } else if (ret == MBEDTLS_ERR_SSL_WANT_READ ||
                                   ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
                            if (wait_ms >= 2000) {
                                break;    /* 2s read timeout */
                            }
                            vTaskDelay(pdMS_TO_TICKS(10));
                            wait_ms += 10;
                        } else if (ret == 0 || ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY ||
                                   ret == MBEDTLS_ERR_SSL_TIMEOUT) {
                            rd_err = ret;
                            break;
                        } else {
                            PRT_SSL("HTTPS socket[%d] read err: -0x%x\r\n", sock, -ret);
                            rd_err = ret;
                            break;
                        }
                    }

                    if (rd_err != 0) {
                        https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                    } else if (total > 0) {
                        dispatch_request(&https_tls_ctx[i], (const char *)https_rx_buf[i]);
                        /* keep-alive: 연결 유지, 다음 요청 대기 */
                        https_last_req_ms[i] = millis();
                    }
                }
                break;

            case SOCK_CLOSE_WAIT:
                https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                break;

            default:
                break;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
