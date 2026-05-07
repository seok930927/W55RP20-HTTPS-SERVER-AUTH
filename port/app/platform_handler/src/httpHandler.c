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
#include "gpioHandler.h"
#include "pingHandler.h"
#include "arpHandler.h"

#define HTTPS_SERVER_PORT   443
#define HTTPS_RX_BUF_SIZE   1024
#define HTTPS_TX_CHUNK_SIZE 512
#define HTTPS_HDR_BUF_SIZE  512

extern xSemaphoreHandle net_http_webserver_sem;

static uint8_t s_led19 = 1;
static char    s_ping_ip[32]     = {0};
static char    s_ping_result[64] = {0};
static arp_table_t s_arp_table;
static char    s_arp_rows[2048];
static char    s_main_body[4096];

static void render_main_page(wiz_tls_context *ctx, const char *session);

static const uint8_t https_server_socks[MAX_HTTPSOCK] = {
    SOCK_HTTPSERVER_1,
    SOCK_HTTPSERVER_2,
    SOCK_HTTPSERVER_3
};
static wiz_tls_context https_tls_ctx[MAX_HTTPSOCK];
static uint8_t https_tls_active[MAX_HTTPSOCK]      = { FALSE, };
static uint8_t https_response_sent[MAX_HTTPSOCK]   = { FALSE, };
static unsigned char https_rx_buf[MAX_HTTPSOCK][HTTPS_RX_BUF_SIZE];
static uint8_t https_last_sock_state[MAX_HTTPSOCK];
static uint32_t https_response_sent_ms[MAX_HTTPSOCK] = { 0, };

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
    "<hr><a href=/setup>계정 생성</a>"
    "</body></html>";

static const char PAGE_SETUP[] =
    "<!DOCTYPE html><html><head><meta charset=UTF-8><title>계정 생성</title>"
    "<style>body{font-family:sans-serif;max-width:360px;margin:60px auto}"
    "input{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}"
    "button{width:100%;padding:10px;background:#0055aa;color:#fff;border:none;cursor:pointer}"
    ".e{color:red;font-size:.9em}</style></head><body>"
    "<h2>계정 생성</h2>"
    "<form method=post action=/setup>"
    "생성 PW: <input type=password name=cpass><br>"
    "ID: <input name=user autocomplete=username><br>"
    "PW: <input type=password name=pass autocomplete=new-password><br>"
    "<button>생성</button>"
    "</form>"
    "<p class=e>%s</p>"
    "<a href=/login>로그인으로 돌아가기</a>"
    "</body></html>";

static const char PAGE_ACCOUNT[] =
    "<!DOCTYPE html><html><head><meta charset=UTF-8><title>계정 관리</title>"
    "<style>body{font-family:sans-serif;max-width:400px;margin:60px auto}"
    "input{width:100%;padding:8px;margin:4px 0;box-sizing:border-box}"
    "button{width:100%;padding:10px;background:#0055aa;color:#fff;border:none;cursor:pointer}"
    ".del{background:#cc2200}.e{color:red;font-size:.9em}"
    "ul{padding:0}li{list-style:none;padding:4px 0;border-bottom:1px solid #eee}"
    "</style></head><body>"
    "<h2>계정 관리</h2>"
    "<h3>현재 계정 (%d/%d)</h3><ul>%s</ul>"
    "<h3>계정 추가</h3>"
    "<form method=post action=/account/add>"
    "생성 PW: <input type=password name=cpass><br>"
    "ID: <input name=user><br>"
    "PW: <input type=password name=pass><br>"
    "<button>추가</button>"
    "</form>"
    "<h3>계정 삭제</h3>"
    "<form method=post action=/account/del>"
    "ID: <input name=user><br>"
    "<button class=del>삭제</button>"
    "</form>"
    "<p class=e>%s</p>"
    "<hr><a href=/>홈</a> | <a href=/logout>로그아웃</a>"
    "</body></html>";

static const char PAGE_MAIN[] =
    "<!DOCTYPE html><html><head><meta charset=UTF-8><title>W55RP20 Demo</title>"
    "<style>"
    "body{font-family:sans-serif;max-width:580px;margin:40px auto;padding:0 12px}"
    "h1{color:#0055aa;margin-bottom:4px}"
    "nav{text-align:right;margin-bottom:16px}nav a{color:#0055aa}"
    ".sec{border:1px solid #ccc;border-radius:4px;margin:14px 0;padding:14px}"
    ".sec h3{margin:0 0 10px;color:#333;border-bottom:1px solid #eee;padding-bottom:6px}"
    ".led{font-size:1.6em;font-weight:bold;margin:8px 0}"
    ".btn{padding:9px 26px;border:none;font-size:.95em;cursor:pointer;color:#fff;margin:3px}"
    ".on{background:#118811}.off{background:#cc2200}.blue{background:#0055aa}"
    "input[type=text]{padding:7px;width:180px;border:1px solid #ccc}"
    ".res{font-weight:bold;margin-top:8px;min-height:1.2em}"
    "table{width:100%;border-collapse:collapse;margin-top:8px}"
    "th,td{border:1px solid #ccc;padding:5px 8px;text-align:left;font-size:.9em}"
    "th{background:#f0f0f0}"
    "</style></head><body>"
    "<h1>W55RP20 Demo</h1>"
    "<nav><a href=/account>계정관리</a> | <a href=/logout>로그아웃</a></nav>"
    "<div class=sec><h3>GPIO 19 (LED)</h3>"
    "<div class=led style='color:%s'>%s</div>"
    "<form method=post action=/gpio/on style=display:inline>"
    "<button class='btn on'>ON</button></form> "
    "<form method=post action=/gpio/off style=display:inline>"
    "<button class='btn off'>OFF</button></form>"
    "</div>"
    "<div class=sec><h3>Ping</h3>"
    "<form method=post action=/ping>"
    "<input type=text name=ip value='%s' placeholder='192.168.1.1'> "
    "<button class='btn blue'>Ping</button>"
    "</form>"
    "<div class=res>%s</div>"
    "</div>"
    "<div class=sec><h3>ARP Scan (x.x.x.1~254)</h3>"
    "<form method=post action=/arp/scan>"
    "<button class='btn blue'>Scan</button>"
    "</form>"
    "%s"
    "</div>"
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
                           "Connection: close\r\n\r\n",
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

static int send_redirect(wiz_tls_context *ctx, const char *location) {
    char hdr[HTTPS_HDR_BUF_SIZE];
    int hdr_len = snprintf(hdr, sizeof(hdr),
                           "HTTP/1.1 302 Found\r\n"
                           "Location: %s\r\n"
                           "Content-Length: 0\r\n"
                           "Connection: close\r\n\r\n",
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
                           "Connection: close\r\n\r\n",
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
                           "Connection: close\r\n\r\n",
                           location);
    if (hdr_len <= 0 || hdr_len >= (int)sizeof(hdr)) {
        return -1;
    }
    return https_write_all(ctx, (const unsigned char *)hdr, (size_t)hdr_len);
}

/*  -----------------------------------------------------------------------
    HTTP 요청 파싱 헬퍼
    --------------------------------------------------------------------- */
static void parse_request_line(const char *req, char *method, size_t mlen,
                               char *path, size_t plen) {
    method[0] = '\0'; path[0] = '\0';
    sscanf(req, "%15s %255s", method, path);
    /* query string 제거 */
    char *q = strchr(path, '?');
    if (q) {
        *q = '\0';
    }
}

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
    render_main_page(ctx, session);
}

static void handle_get_login(wiz_tls_context *ctx, const char *query) {
    char body[sizeof(PAGE_LOGIN) + 64];
    const char *err = "";
    if (query && strstr(query, "err=1")) {
        err = "아이디 또는 패스워드가 틀렸습니다.";
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
            err = "계정생성 패스워드가 틀렸습니다.";
        } else if (strstr(query, "err=2")) {
            err = "계정이 이미 5개입니다.";
        } else if (strstr(query, "err=3")) {
            err = "이미 존재하는 아이디입니다.";
        } else if (strstr(query, "err=4")) {
            err = "아이디 또는 패스워드를 입력하세요.";
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
            err = "계정생성 패스워드가 틀렸습니다.";
        } else if (strstr(query, "err=2")) {
            err = "계정이 이미 5개입니다.";
        } else if (strstr(query, "err=3")) {
            err = "이미 존재하는 아이디입니다.";
        } else if (strstr(query, "err=4")) {
            err = "아이디 또는 패스워드를 입력하세요.";
        } else if (strstr(query, "err=5")) {
            err = "존재하지 않는 아이디입니다.";
        } else if (strstr(query, "ok=1")) {
            err = "계정이 추가됐습니다.";
        } else if (strstr(query, "ok=2")) {
            err = "계정이 삭제됐습니다.";
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

static int parse_ip(const char *str, uint8_t *ip) {
    unsigned a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        return 0;
    }
    if (a > 255 || b > 255 || c > 255 || d > 255) {
        return 0;
    }
    ip[0] = (uint8_t)a; ip[1] = (uint8_t)b; ip[2] = (uint8_t)c; ip[3] = (uint8_t)d;
    return 1;
}

static void render_main_page(wiz_tls_context *ctx, const char *session) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }

    /* ARP 테이블 행 빌드 */
    int off = 0;
    if (s_arp_table.count == 0) {
        off = snprintf(s_arp_rows, sizeof(s_arp_rows), "<p style='color:#888'>스캔 결과 없음</p>");
    } else {
        off = snprintf(s_arp_rows, sizeof(s_arp_rows),
                       "<p>발견: %d개</p><table><tr><th>IP</th><th>MAC</th></tr>",
                       s_arp_table.count);
        for (int i = 0; i < s_arp_table.count && off < (int)sizeof(s_arp_rows) - 80; i++) {
            arp_entry_t *e = &s_arp_table.entries[i];
            off += snprintf(s_arp_rows + off, sizeof(s_arp_rows) - (size_t)off,
                            "<tr><td>%d.%d.%d.%d</td>"
                            "<td>%02X:%02X:%02X:%02X:%02X:%02X</td></tr>",
                            e->ip[0], e->ip[1], e->ip[2], e->ip[3],
                            e->mac[0], e->mac[1], e->mac[2],
                            e->mac[3], e->mac[4], e->mac[5]);
        }
        snprintf(s_arp_rows + off, sizeof(s_arp_rows) - (size_t)off, "</table>");
    }

    int len = snprintf(s_main_body, sizeof(s_main_body), PAGE_MAIN,
                       s_led19 ? "#118811" : "#cc2200",
                       s_led19 ? "ON" : "OFF",
                       s_ping_ip,
                       s_ping_result,
                       s_arp_rows);
    if (len > 0) {
        send_html(ctx, s_main_body, (size_t)len);
    }
}

static void handle_post_gpio_on(wiz_tls_context *ctx, const char *session) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }
    GPIO_Output_Set(19);
    s_led19 = 1;
    render_main_page(ctx, session);
}

static void handle_post_gpio_off(wiz_tls_context *ctx, const char *session) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }
    GPIO_Output_Reset(19);
    s_led19 = 0;
    render_main_page(ctx, session);
}

static void handle_post_ping(wiz_tls_context *ctx, const char *session,
                             const char *body_str) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }

    char ip_str[32] = {0};
    get_form_field(body_str, "ip", ip_str, sizeof(ip_str));
    strncpy(s_ping_ip, ip_str, sizeof(s_ping_ip) - 1);

    uint8_t ip[4] = {0};
    if (!parse_ip(ip_str, ip)) {
        snprintf(s_ping_result, sizeof(s_ping_result), "Invalid IP address.");
    } else {
        ping_result_t pr = {0, 0};
        ping_host(SOCK_UTILITY, ip, &pr);
        if (pr.success) {
            snprintf(s_ping_result, sizeof(s_ping_result), "RTT: %lums", (unsigned long)pr.rtt_ms);
        } else {
            snprintf(s_ping_result, sizeof(s_ping_result), "Request timed out.");
        }
    }
    render_main_page(ctx, session);
}

static void handle_post_arp_scan(wiz_tls_context *ctx, const char *session) {
    if (!https_auth_verify_session(session)) {
        send_redirect(ctx, "/login");
        return;
    }
    arp_scan(SOCK_UTILITY, &s_arp_table);
    render_main_page(ctx, session);
}

static void handle_get_logout(wiz_tls_context *ctx, const char *session) {
    if (session[0]) {
        https_auth_logout(session);
    }
    send_redirect_clear_cookie(ctx, "/login");
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
        } else if (strcmp(path, "/gpio/on")     == 0) {
            handle_post_gpio_on(ctx, session);
        } else if (strcmp(path, "/gpio/off")    == 0) {
            handle_post_gpio_off(ctx, session);
        } else if (strcmp(path, "/ping")     == 0) {
            handle_post_ping(ctx, session, body);
        } else if (strcmp(path, "/arp/scan") == 0) {
            handle_post_arp_scan(ctx, session);
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
        disconnect(sock);
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
                https_response_sent[i] = FALSE;
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
                    https_tls_active[i]    = TRUE;
                    https_response_sent[i] = FALSE;
                    break;
                }

                if (https_response_sent[i]) {
                    if ((millis() - https_response_sent_ms[i]) >= 2000) {
                        https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                        https_response_sent[i] = FALSE;
                    }
                    break;
                }

                if (getSn_RX_RSR(sock) == 0 &&
                        mbedtls_ssl_check_pending(https_tls_ctx[i].ssl) == 0) {
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
                        https_response_sent[i] = FALSE;
                    } else if (total > 0) {
                        dispatch_request(&https_tls_ctx[i], (const char *)https_rx_buf[i]);
                        https_response_sent[i]    = TRUE;
                        https_response_sent_ms[i] = millis();
                    }
                }
                break;

            case SOCK_CLOSE_WAIT:
                https_close_session(sock, &https_tls_ctx[i], &https_tls_active[i]);
                https_response_sent[i] = FALSE;
                break;

            default:
                break;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(20));
    }
}
