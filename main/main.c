#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <math.h>

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_wifi.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "nvs_flash.h"

#include "lwip/sockets.h"
#include "esp_bridge.h"
#include "esp_mesh_lite.h"
#include "mdns.h"
#include "coap3/coap.h"
#include "dht.h"

#define TAG "DHT_NODE"

/* Parametres communs : identiques sur toutes les cartes */
#define ROUTER_SSID     "MERCUSYS_112E"
#define ROUTER_PASS     "44288006"
#define MESH_AP_SSID    "mesh_ferme"
#define MESH_AP_PASS    "12345678"

#define COAPS_PORT      5684
#define PSK_IDENTITY    "carte_esp32"
#define PSK_KEY         "PSK123456"

/* Parametres DHT11 */
#define DHT_GPIO        4
#define DHT_TYPE        DHT_TYPE_DHT11

#define MAX_PEERS       8
#define DISCOVERY_MS    10000
#define PEER_TTL_MS     60000
#define RETRY_MS        10000
#define RX_TIMEOUT_MS   45000
#define HEARTBEAT_MS    20000

#define SEUIL_T         0.5f
#define SEUIL_H         2.0f

typedef struct {
    bool used;
    char host[32];
    char ip[16];
    uint16_t port;
    coap_session_t *session;
    TickType_t last_rx;
    TickType_t last_try;
    bool retry;
} peer_t;

typedef struct {
    bool used;
    char host[32];
    char ip[16];
    uint16_t port;
    TickType_t seen;
} found_t;

static volatile float s_temp = 0.0f;
static volatile float s_hum = 0.0f;
static volatile bool s_changed = false;

static peer_t s_peers[MAX_PEERS];
static found_t s_found[MAX_PEERS];

static SemaphoreHandle_t s_found_mtx;
static char s_host[24];

/* ---------------------------------------------------------
   EVENEMENTS RESEAU
--------------------------------------------------------- */

static void net_event_handler(void *arg,
                              esp_event_base_t base,
                              int32_t id,
                              void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        ESP_LOGW(TAG, "STA deconnectee");
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_CONNECTED) {
        ESP_LOGI(TAG, "STA connectee");
    }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = (ip_event_got_ip_t *)data;

        ESP_LOGI(TAG,
                 "IP STA : " IPSTR " | Mesh level : %d",
                 IP2STR(&e->ip_info.ip),
                 (int)esp_mesh_lite_get_level());
    }
    else if (base == WIFI_EVENT && id == WIFI_EVENT_AP_STACONNECTED) {
        ESP_LOGI(TAG, "Un enfant s'est connecte au SoftAP");
    }
}

/* ---------------------------------------------------------
   INITIALISATION MESH-LITE
--------------------------------------------------------- */

static void mesh_init(void)
{
    esp_err_t e = esp_netif_init();
    if (e != ESP_OK) {
        ESP_ERROR_CHECK(e);
    }

    e = esp_event_loop_create_default();
    if (e != ESP_OK && e != ESP_ERR_INVALID_STATE) {
        ESP_ERROR_CHECK(e);
    }

    ESP_ERROR_CHECK(esp_event_handler_register(
        WIFI_EVENT, ESP_EVENT_ANY_ID, net_event_handler, NULL));

    ESP_ERROR_CHECK(esp_event_handler_register(
        IP_EVENT, IP_EVENT_STA_GOT_IP, net_event_handler, NULL));

    esp_bridge_create_all_netif();

    wifi_init_config_t wcfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&wcfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    wifi_config_t sta = {0};

    strlcpy((char *)sta.sta.ssid,
            ROUTER_SSID, sizeof(sta.sta.ssid));

    strlcpy((char *)sta.sta.password,
            ROUTER_PASS, sizeof(sta.sta.password));

    ESP_ERROR_CHECK(esp_bridge_wifi_set_config(WIFI_IF_STA, &sta));

    wifi_config_t ap = {0};

    strlcpy((char *)ap.ap.ssid,
            MESH_AP_SSID, sizeof(ap.ap.ssid));

    strlcpy((char *)ap.ap.password,
            MESH_AP_PASS, sizeof(ap.ap.password));

    ap.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap.ap.max_connection = 4;

    ESP_ERROR_CHECK(esp_bridge_wifi_set_config(WIFI_IF_AP, &ap));

    ESP_ERROR_CHECK(esp_wifi_start());

    esp_mesh_lite_config_t cfg = ESP_MESH_LITE_DEFAULT_INIT();

    esp_mesh_lite_init(&cfg);
    esp_mesh_lite_start();

    ESP_LOGI(TAG, "Mesh-Lite initialise");
}

/* ---------------------------------------------------------
   mDNS : ANNONCE DE LA CARTE
--------------------------------------------------------- */

static void mdns_demarrer(void)
{
    uint8_t mac[6];

    ESP_ERROR_CHECK(esp_read_mac(mac, ESP_MAC_WIFI_STA));

    snprintf(s_host, sizeof(s_host),
             "esp32-%02x%02x%02x",
             mac[3], mac[4], mac[5]);

    ESP_ERROR_CHECK(mdns_init());
    ESP_ERROR_CHECK(mdns_hostname_set(s_host));
    ESP_ERROR_CHECK(mdns_instance_name_set(s_host));

    ESP_ERROR_CHECK(mdns_service_add(
        s_host, "_coaps", "_udp", COAPS_PORT, NULL, 0));

    ESP_LOGI(TAG, "mDNS : %s.local", s_host);
    ESP_LOGI(TAG, "Service CoAP DTLS : port %d", COAPS_PORT);
}

/* ---------------------------------------------------------
   DECOUVERTE DES AUTRES ESP32
--------------------------------------------------------- */

static void discovery_task(void *arg)
{
    while (1) {
        mdns_result_t *r = NULL;

        esp_err_t e = mdns_query_ptr(
            "_coaps", "_udp", 3000, 8, &r);

        if (e == ESP_OK && r != NULL) {

            for (mdns_result_t *p = r; p != NULL; p = p->next) {

                if (!p->hostname ||
                    strcmp(p->hostname, s_host) == 0) {
                    continue;
                }

                for (mdns_ip_addr_t *a = p->addr;
                     a != NULL; a = a->next) {

                    if (a->addr.type != ESP_IPADDR_TYPE_V4) {
                        continue;
                    }

                    char ip[16];

                    snprintf(ip, sizeof(ip), IPSTR,
                             IP2STR(&a->addr.u_addr.ip4));

                    xSemaphoreTake(s_found_mtx, portMAX_DELAY);

                    found_t *slot = NULL;

                    for (int i = 0; i < MAX_PEERS; i++) {
                        if (s_found[i].used &&
                            strcmp(s_found[i].ip, ip) == 0) {
                            slot = &s_found[i];
                            break;
                        }
                    }

                    if (slot == NULL) {
                        for (int i = 0; i < MAX_PEERS; i++) {
                            if (!s_found[i].used) {
                                slot = &s_found[i];
                                break;
                            }
                        }
                    }

                    if (slot != NULL) {
                        slot->used = true;

                        strlcpy(slot->host, p->hostname,
                                sizeof(slot->host));

                        strlcpy(slot->ip, ip,
                                sizeof(slot->ip));

                        slot->port = p->port ?
                                     p->port : COAPS_PORT;

                        slot->seen = xTaskGetTickCount();
                    }

                    xSemaphoreGive(s_found_mtx);

                    break;
                }
            }

            mdns_query_results_free(r);
        }

        vTaskDelay(pdMS_TO_TICKS(DISCOVERY_MS));
    }
}

/* ---------------------------------------------------------
   LECTURE DU DHT11
--------------------------------------------------------- */

static void dht_task(void *arg)
{
    float last_t = 0.0f;
    float last_h = 0.0f;
    bool first = true;

    while (1) {
        float h = 0.0f;
        float t = 0.0f;

        if (dht_read_float_data(
                DHT_TYPE, DHT_GPIO, &h, &t) == ESP_OK) {

            s_temp = t;
            s_hum = h;

            if (first ||
                fabsf(t - last_t) >= SEUIL_T ||
                fabsf(h - last_h) >= SEUIL_H) {

                last_t = t;
                last_h = h;
                first = false;

                s_changed = true;
            }

            ESP_LOGI(TAG,
                     "LOCAL DHT11 : Temperature %.1f C | Humidite %.1f %%",
                     t, h);
        }
        else {
            ESP_LOGW(TAG, "Lecture DHT11 echouee");
        }

        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

/* ---------------------------------------------------------
   SERVEUR COAP : RESSOURCE /temperature
--------------------------------------------------------- */

static void hnd_get_temperature(
    coap_resource_t *resource,
    coap_session_t *session,
    const coap_pdu_t *request,
    const coap_string_t *query,
    coap_pdu_t *response)
{
    char buf[64];
    uint8_t cf[4];

    int n = snprintf(buf, sizeof(buf),
                     "{\"t\":%.1f,\"h\":%.1f}",
                     (float)s_temp, (float)s_hum);

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);

    size_t cf_len = coap_encode_var_safe(
        cf, sizeof(cf), COAP_MEDIATYPE_APPLICATION_JSON);

    coap_add_option(response,
                    COAP_OPTION_CONTENT_FORMAT,
                    cf_len, cf);

    coap_add_data(response, (size_t)n,
                  (const uint8_t *)buf);
}

/* ---------------------------------------------------------
   GESTION DES PAIRS
--------------------------------------------------------- */

static peer_t *peer_by_session(coap_session_t *s)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (s_peers[i].used &&
            s_peers[i].session == s) {
            return &s_peers[i];
        }
    }

    return NULL;
}

static peer_t *peer_by_ip(const char *ip)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (s_peers[i].used &&
            strcmp(s_peers[i].ip, ip) == 0) {
            return &s_peers[i];
        }
    }

    return NULL;
}

static peer_t *peer_alloc(void)
{
    for (int i = 0; i < MAX_PEERS; i++) {
        if (!s_peers[i].used) {
            memset(&s_peers[i], 0, sizeof(peer_t));
            s_peers[i].used = true;
            return &s_peers[i];
        }
    }

    return NULL;
}

static void peer_remove(peer_t *p)
{
    if (p->session != NULL) {
        coap_session_release(p->session);
        p->session = NULL;
    }

    ESP_LOGI(TAG, "Pair retire : %s (%s)", p->host, p->ip);

    memset(p, 0, sizeof(peer_t));
}

/* ---------------------------------------------------------
   CLIENT COAP : ENVOI D'UN ABONNEMENT OBSERVE
--------------------------------------------------------- */

static bool envoyer_observe(
    coap_session_t *session,
    const char *resource)
{
    coap_pdu_t *pdu = coap_pdu_init(
        COAP_MESSAGE_CON,
        COAP_REQUEST_CODE_GET,
        coap_new_message_id(session),
        coap_session_max_pdu_size(session));

    if (pdu == NULL) {
        ESP_LOGE(TAG, "Creation PDU impossible : /%s", resource);
        return false;
    }

    uint8_t token[8];
    size_t token_len = sizeof(token);

    coap_session_new_token(session, &token_len, token);

    if (!coap_add_token(pdu, token_len, token)) {
        coap_delete_pdu(pdu);
        return false;
    }

    uint8_t observe[4];

    size_t observe_len = coap_encode_var_safe(
        observe, sizeof(observe), COAP_OBSERVE_ESTABLISH);

    coap_add_option(pdu, COAP_OPTION_OBSERVE,
                    observe_len, observe);

    coap_add_option(pdu, COAP_OPTION_URI_PATH,
                    strlen(resource),
                    (const uint8_t *)resource);

    coap_mid_t mid = coap_send(session, pdu);

    if (mid == COAP_INVALID_MID) {
        ESP_LOGW(TAG, "Envoi Observe impossible : /%s", resource);
        return false;
    }

    ESP_LOGI(TAG, "Observe demande : /%s", resource);

    return true;
}

/* ---------------------------------------------------------
   CLIENT COAP : OUVERTURE SESSION DTLS
   Chaque pair recoit DEUX abonnements :
   /temperature ET /gas
--------------------------------------------------------- */

static coap_session_t *ouvrir_session_client(
    coap_context_t *ctx,
    const char *ip_str,
    uint16_t port)
{
    coap_address_t dst;
    coap_address_init(&dst);

    dst.size = sizeof(struct sockaddr_in);
    dst.addr.sin.sin_family = AF_INET;
    dst.addr.sin.sin_port = htons(port);

    if (inet_pton(AF_INET, ip_str,
                  &dst.addr.sin.sin_addr) != 1) {
        ESP_LOGE(TAG, "Adresse IP invalide : %s", ip_str);
        return NULL;
    }

    coap_dtls_cpsk_t cpsk;
    memset(&cpsk, 0, sizeof(cpsk));

    cpsk.version = COAP_DTLS_CPSK_SETUP_VERSION;

    cpsk.psk_info.identity.s =
        (const uint8_t *)PSK_IDENTITY;

    cpsk.psk_info.identity.length =
        strlen(PSK_IDENTITY);

    cpsk.psk_info.key.s =
        (const uint8_t *)PSK_KEY;

    cpsk.psk_info.key.length =
        strlen(PSK_KEY);

    coap_session_t *session =
        coap_new_client_session_psk2(
            ctx, NULL, &dst, COAP_PROTO_DTLS, &cpsk);

    if (session == NULL) {
        ESP_LOGE(TAG, "Session DTLS impossible vers %s", ip_str);
        return NULL;
    }

    ESP_LOGI(TAG, "Session DTLS creee vers %s:%u", ip_str, port);

    envoyer_observe(session, "temperature");
    envoyer_observe(session, "gas");

    return session;
}

/* ---------------------------------------------------------
   RECEPTION DES REPONSES ET NOTIFICATIONS
--------------------------------------------------------- */

static coap_response_t message_handler(
    coap_session_t *session,
    const coap_pdu_t *sent,
    const coap_pdu_t *received,
    const coap_mid_t mid)
{
    peer_t *p = peer_by_session(session);

    const char *who = p ? p->ip : "?";

    coap_pdu_code_t code = coap_pdu_get_code(received);

    if (code == COAP_RESPONSE_CODE_NOT_FOUND) {
        ESP_LOGI(TAG,
                 "[%s] 4.04 : ressource absente sur cette carte (normal)",
                 who);
        return COAP_RESPONSE_OK;
    }

    if (code != COAP_RESPONSE_CODE_CONTENT) {
        ESP_LOGW(TAG,
                 "[%s] Reponse CoAP : %d.%02d",
                 who, code >> 5, code & 0x1F);
        return COAP_RESPONSE_OK;
    }

    if (p != NULL) {
        p->last_rx = xTaskGetTickCount();
    }

    coap_opt_iterator_t it;

    coap_opt_t *o = coap_check_option(
        received, COAP_OPTION_OBSERVE, &it);

    if (o != NULL) {
        ESP_LOGI(TAG,
                 "[%s] NOTIFICATION Observe seq=%u",
                 who,
                 (unsigned)coap_decode_var_bytes(
                     coap_opt_value(o),
                     coap_opt_length(o)));
    }
    else {
        ESP_LOGI(TAG, "[%s] Reponse initiale CoAP", who);
    }

    size_t len;
    const uint8_t *data;

    if (coap_get_data(received, &len, &data)) {
        ESP_LOGI(TAG,
                 "[MESURE DISTANTE %s] %.*s",
                 who, (int)len, (const char *)data);
    }

    return COAP_RESPONSE_OK;
}

/* ---------------------------------------------------------
   GESTION DES ERREURS
--------------------------------------------------------- */

static void nack_handler(
    coap_session_t *session,
    const coap_pdu_t *sent,
    const coap_nack_reason_t reason,
    const coap_mid_t mid)
{
    peer_t *p = peer_by_session(session);

    ESP_LOGW(TAG,
             "NACK raison=%d pair=%s",
             (int)reason, p ? p->ip : "?");

    if (p != NULL) {
        p->retry = true;
    }
}

static int event_handler(
    coap_session_t *session,
    const coap_event_t event)
{
    peer_t *p = peer_by_session(session);

    const char *who = p ? p->ip : "entrant";

    switch (event) {

    case COAP_EVENT_DTLS_CONNECTED:
        ESP_LOGI(TAG, "DTLS handshake OK : %s", who);
        break;

    case COAP_EVENT_DTLS_CLOSED:
        ESP_LOGW(TAG, "DTLS ferme : %s", who);
        if (p) p->retry = true;
        break;

    case COAP_EVENT_DTLS_ERROR:
        ESP_LOGE(TAG, "Erreur DTLS : %s", who);
        if (p) p->retry = true;
        break;

    case COAP_EVENT_SESSION_FAILED:
        ESP_LOGE(TAG, "Session echouee : %s", who);
        if (p) p->retry = true;
        break;

    default:
        break;
    }

    return 0;
}

/* ---------------------------------------------------------
   SYNCHRONISATION DES PAIRS DECOUVERTS
--------------------------------------------------------- */

static void sync_peers(void)
{
    TickType_t now = xTaskGetTickCount();

    xSemaphoreTake(s_found_mtx, portMAX_DELAY);

    for (int i = 0; i < MAX_PEERS; i++) {

        found_t *f = &s_found[i];

        if (!f->used) continue;

        if ((now - f->seen) > pdMS_TO_TICKS(PEER_TTL_MS)) {
            f->used = false;
            continue;
        }

        peer_t *p = peer_by_ip(f->ip);

        if (p == NULL) {
            p = peer_alloc();

            if (p == NULL) {
                ESP_LOGW(TAG, "Table des pairs pleine");
                continue;
            }

            strlcpy(p->ip, f->ip, sizeof(p->ip));
            p->port = f->port;
            p->last_rx = now;

            ESP_LOGI(TAG,
                     "NOUVEL ESP32 : %s (%s:%u)",
                     f->host, f->ip, f->port);
        }

        strlcpy(p->host, f->host, sizeof(p->host));
        p->port = f->port;
    }

    for (int i = 0; i < MAX_PEERS; i++) {

        peer_t *p = &s_peers[i];

        if (!p->used) continue;

        bool found = false;

        for (int j = 0; j < MAX_PEERS; j++) {
            if (s_found[j].used &&
                strcmp(s_found[j].ip, p->ip) == 0) {
                found = true;
                break;
            }
        }

        if (!found) {
            peer_remove(p);
        }
    }

    xSemaphoreGive(s_found_mtx);
}

/* ---------------------------------------------------------
   TACHE COAP
--------------------------------------------------------- */

static void coap_task(void *arg)
{
    coap_set_log_level(COAP_LOG_WARN);

    if (!coap_dtls_is_supported()) {
        ESP_LOGE(TAG, "Libcoap compilee sans DTLS");
        vTaskDelete(NULL);
        return;
    }

    coap_context_t *ctx = coap_new_context(NULL);

    if (ctx == NULL) {
        ESP_LOGE(TAG, "Creation contexte CoAP impossible");
        vTaskDelete(NULL);
        return;
    }

    coap_context_set_block_mode(
        ctx, COAP_BLOCK_USE_LIBCOAP | COAP_BLOCK_SINGLE_BODY);

    /* Configuration serveur DTLS-PSK */
    coap_dtls_spsk_t spsk;
    memset(&spsk, 0, sizeof(spsk));

    spsk.version = COAP_DTLS_SPSK_SETUP_VERSION;

    spsk.psk_info.hint.s = (const uint8_t *)"serveur";
    spsk.psk_info.hint.length = strlen("serveur");

    spsk.psk_info.key.s = (const uint8_t *)PSK_KEY;
    spsk.psk_info.key.length = strlen(PSK_KEY);

    coap_context_set_psk2(ctx, &spsk);

    /* Endpoint DTLS */
    coap_address_t addr;
    coap_address_init(&addr);

    addr.size = sizeof(struct sockaddr_in);
    addr.addr.sin.sin_family = AF_INET;
    addr.addr.sin.sin_port = htons(COAPS_PORT);
    addr.addr.sin.sin_addr.s_addr = htonl(INADDR_ANY);

    if (coap_new_endpoint(ctx, &addr, COAP_PROTO_DTLS) == NULL) {
        ESP_LOGE(TAG, "Endpoint DTLS impossible");
        coap_free_context(ctx);
        vTaskDelete(NULL);
        return;
    }

    /* Ressource locale /temperature */
    coap_resource_t *res = coap_resource_init(
        coap_make_str_const("temperature"), 0);

    coap_register_handler(
        res, COAP_REQUEST_GET, hnd_get_temperature);

    coap_resource_set_get_observable(res, 1);
    coap_add_resource(ctx, res);

    /* Handlers */
    coap_register_response_handler(ctx, message_handler);
    coap_register_nack_handler(ctx, nack_handler);
    coap_register_event_handler(ctx, event_handler);

    TickType_t dernier_notify = xTaskGetTickCount();

    ESP_LOGI(TAG, "Serveur DHT11 DTLS-PSK actif");
    ESP_LOGI(TAG, "Ressource publiee : /temperature");
    ESP_LOGI(TAG, "Client : abonnement /temperature + /gas");

    while (1) {

        coap_io_process(ctx, 200);

        TickType_t now = xTaskGetTickCount();

        /* Notifications Observe */
        if (s_changed ||
            (now - dernier_notify) > pdMS_TO_TICKS(HEARTBEAT_MS)) {

            s_changed = false;
            dernier_notify = now;

            coap_resource_notify_observers(res, NULL);
        }

        sync_peers();

        /* Connexion et abonnements aux autres ESP32 */
        for (int i = 0; i < MAX_PEERS; i++) {

            peer_t *p = &s_peers[i];

            if (!p->used) continue;

            bool silence =
                (now - p->last_rx) > pdMS_TO_TICKS(RX_TIMEOUT_MS);

            if ((!p->session || p->retry || silence) &&
                (now - p->last_try) > pdMS_TO_TICKS(RETRY_MS)) {

                p->last_try = now;
                p->retry = false;

                if (p->session != NULL) {
                    coap_session_release(p->session);
                    p->session = NULL;
                }

                p->session = ouvrir_session_client(
                    ctx, p->ip, p->port);

                p->last_rx = now;
            }
        }
    }
}

/* ---------------------------------------------------------
   APP MAIN
--------------------------------------------------------- */

void app_main(void)
{
    esp_err_t r = nvs_flash_init();

    if (r == ESP_ERR_NVS_NO_FREE_PAGES ||
        r == ESP_ERR_NVS_NEW_VERSION_FOUND) {

        ESP_ERROR_CHECK(nvs_flash_erase());
        r = nvs_flash_init();
    }

    ESP_ERROR_CHECK(r);

    s_found_mtx = xSemaphoreCreateMutex();

    if (s_found_mtx == NULL) {
        ESP_LOGE(TAG, "Creation mutex impossible");
        return;
    }

    mesh_init();
    mdns_demarrer();

    xTaskCreate(dht_task, "dht", 4096, NULL, 5, NULL);
    xTaskCreate(discovery_task, "mdns_disc", 4096, NULL, 4, NULL);
    xTaskCreate(coap_task, "coap", 16 * 1024, NULL, 5, NULL);

    ESP_LOGI(TAG, "Carte DHT11 demarree");
}
