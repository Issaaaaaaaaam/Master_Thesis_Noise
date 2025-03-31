#include "string.h"
#include <noise/protocol.h>
#include <sodium.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "ha/esp_zigbee_ha_standard.h"
#include "esp_zb_light.h"
#include "aps/esp_zigbee_aps.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_check.h"
#include "esp_timer.h"
#include <inttypes.h>

#if !defined ZB_ED_ROLE
#error Define ZB_ED_ROLE in idf.py menuconfig to compile light (End Device) source code.
#endif

#define HANDSHAKE_PATTERN "Noise_KEMNN_Kyber512_ChaChaPoly_SHA256"
#define MAX_NOISE_MESSAGE_SIZE 1024
#define TAG "ESP32_NOISE_RECEIVER"
static NoiseHandshakeState *responder = NULL;
static NoiseCipherState *responder_send_cipher = NULL;
static NoiseCipherState *responder_recv_cipher = NULL;
static bool handshake_complete = false;
static volatile bool waiting_for_last_confirm = false;
static volatile bool last_confirm_received = false;
#define BENCHMARKLOOP
#define CONFIG_ENABLE_NOISE_BENCHMARK
#ifdef CONFIG_ENABLE_NOISE_BENCHMARK

typedef struct {
    uint64_t start_us;
    uint32_t start_cycles;
} benchmark_entry_t;

static benchmark_entry_t current;

void bench_start(const char *label) {
    current.start_us = esp_timer_get_time();
    current.start_cycles = esp_cpu_get_cycle_count();
    ESP_LOGD("BENCH", "[%s] Benchmark started", label);
}

void bench_end(const char *label) {
    uint64_t end_us = esp_timer_get_time();
    uint32_t end_cycles = esp_cpu_get_cycle_count();
    ESP_LOGW("BENCH", "[%s] Took %" PRIu64 " us and %" PRIu32 " cycles",
                label, end_us - current.start_us, end_cycles - current.start_cycles);
}

#else

void bench_start(const char *label) {}
void bench_end(const char *label) {}

#endif

#ifdef BENCHMARKLOOP
static uint8_t i = 10; 
void reset_noise_state() {
    if (responder != NULL) {
        noise_handshakestate_free(responder);
        responder = NULL;
    }
    if (responder_send_cipher != NULL) {
        noise_cipherstate_free(responder_send_cipher);
        responder_send_cipher = NULL;
    }
    if (responder_recv_cipher != NULL) {
        noise_cipherstate_free(responder_recv_cipher);
        responder_recv_cipher = NULL;
    }
    handshake_complete = false;
}
#endif


/********************* Noise Helper Functions **************************/

const char* noise_action_to_string(int action) {
    switch (action) {
        case NOISE_ACTION_NONE: return "NO ACTION";
        case NOISE_ACTION_WRITE_MESSAGE: return "WRITE MESSAGE";
        case NOISE_ACTION_READ_MESSAGE: return "READ MESSAGE";
        case NOISE_ACTION_FAILED: return "FAILED";
        case NOISE_ACTION_SPLIT: return "SPLIT (Handshake Complete)";
        case NOISE_ACTION_COMPLETE: return "COMPLETE";
        default: return "UNKNOWN ACTION";
    }
}

static void log_handshake_state(NoiseHandshakeState *hs, const char *role)
{
    ESP_LOGI(TAG, "%s handshake state: %s", role, noise_action_to_string(noise_handshakestate_get_action(hs)));
}
/********************* Start Noise Handshake (Responder) **************************/

void start_noise_handshake() {
    ESP_LOGI(TAG, "Starting Noise handshake as Responder...");

    int err;

    // **Initialize Noise Framework**
    bench_start("Framework Init");
    err = noise_init_framework();
    bench_end("Framework Init");
    if (err != NOISE_ERROR_NONE) {
        noise_log_error(TAG, "Failed to initialize Noise framework:", err);
        return; 
    }

    // **Create Responder Handshake State**
    bench_start("Handshake creation");
    err = noise_handshakestate_new_by_name(&responder, HANDSHAKE_PATTERN, NOISE_ROLE_RESPONDER);
    bench_end("Handshake creation");
    if (err != NOISE_ERROR_NONE) {
        noise_log_error(TAG, "Failed to create responder handshake:", err);
        return; 
    }

    // **Start the handshake process**
    bench_start("Handshake start");
    err = noise_handshakestate_start(responder);
    bench_end("Handshake start");
    if (err != NOISE_ERROR_NONE) {
        noise_log_error(TAG, "Failed to start responder handshake:", err);
        return;
    }

    ESP_LOGI(TAG, "Responder is ready to process incoming handshake messages.");
}

/********************* APS Data Indication Handler (Receiver) **************************/

bool zb_apsde_data_indication_handler(esp_zb_apsde_data_ind_t data_ind) {
    ESP_LOGI(TAG, "Received APS Data Indication");

    if (data_ind.dst_endpoint == HA_ESP_LIGHT_ENDPOINT &&
        data_ind.profile_id == ESP_ZB_AF_HA_PROFILE_ID &&
        data_ind.cluster_id == 0xFFC0) {
        
        if (data_ind.status || data_ind.asdu_length < 1) {
            ESP_LOGE(TAG, "Invalid APS message");
            return false;
        }

        int handshake_state = noise_handshakestate_get_action(responder);
        ESP_LOGI(TAG, "Current handshake state: %s", noise_action_to_string(handshake_state));

        NoiseBuffer message_buf;
        int err;

        // **Process Handshake Message**
        if (handshake_state != NOISE_ACTION_COMPLETE) {
            ESP_LOGI(TAG, "Processing handshake message...");

            noise_buffer_set_input(message_buf, data_ind.asdu, data_ind.asdu_length);
            bench_start("Read Message");
            err = noise_handshakestate_read_message(responder, &message_buf, NULL);
            bench_end("Read Message");
            if (err != NOISE_ERROR_NONE) {
                noise_log_error(TAG, "Failed to process handshake message:", err);
                return false;
            }

            ESP_LOGI(TAG, "Processed handshake message successfully.");

            // **Check if handshake is complete**
            handshake_state = noise_handshakestate_get_action(responder);
            ESP_LOGI(TAG, "Current handshake state: %s", noise_action_to_string(handshake_state));
            // **Send handshake response**
            ESP_LOGI(TAG, "Sending handshake response...");
            uint8_t message[MAX_NOISE_MESSAGE_SIZE];
            noise_buffer_set_output(message_buf, message, sizeof(message));
            bench_start("Write message");
            err = noise_handshakestate_write_message(responder, &message_buf, NULL);
            bench_end("Write message");
            if (err != NOISE_ERROR_NONE) {
                noise_log_error(TAG, "Failed to generate handshake response:", err);
                return false;
            }

            // **Send response via Zigbee**
            esp_zb_apsde_data_req_t req;
            memset(&req, 0, sizeof(req));
            req.dst_addr_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
            req.dst_addr.addr_short = data_ind.src_short_addr;
            req.dst_endpoint = data_ind.src_endpoint;
            req.profile_id = ESP_ZB_AF_HA_PROFILE_ID;
            req.cluster_id = 0xFFC0;
            req.src_endpoint = HA_ESP_LIGHT_ENDPOINT;
            req.asdu_length = message_buf.size;
            req.asdu = message_buf.data;
            req.radius = 10;
            req.tx_options = (ESP_ZB_APSDE_TX_OPT_ACK_TX | ESP_ZB_APSDE_TX_OPT_FRAG_PERMITTED);
            req.use_alias = false;
            waiting_for_last_confirm = true;
            last_confirm_received = false;
            bench_start("Zigbee APS send message");
            esp_zb_lock_acquire(portMAX_DELAY);
            esp_zb_aps_data_request(&req);
            esp_zb_lock_release();
            bench_end("Zigbee APS send message");
            ESP_LOGI(TAG, "Sent handshake response.");
            log_handshake_state(responder, "responder");
        
            ESP_LOGI(TAG, "Handshake complete! Switching to encrypted mode.");
            handshake_complete = true;

            // **Split cipher states for encryption/decryption**
            bench_start("Handshake split");
            err = noise_handshakestate_split(responder, &responder_send_cipher, &responder_recv_cipher);
            bench_end("Handshake split");
            if (err != NOISE_ERROR_NONE) {
                noise_log_error(TAG, "Failed to split cipher states:", err);
                return false;
            }

            ESP_LOGI(TAG, "Cipher states created. Secure communication ready.");
            #ifdef BENCHMARKLOOP
                vTaskDelay(pdMS_TO_TICKS(500));
                reset_noise_state();
                i--; 
                if (i == 0) {
                    return true; 
                }
                start_noise_handshake(); 
            #endif
            return true;
        
        }

        // **Process Encrypted Message**
        else {
            ESP_LOGI(TAG, "Processing Encrypted Noise message...");

            if (!responder_recv_cipher) {
                ESP_LOGE(TAG, "Cipher state is NULL. Handshake may not be complete.");
                return false;
            }

            // Prepare buffer for decryption
            noise_buffer_set_input(message_buf, data_ind.asdu, data_ind.asdu_length);

            // Decrypt message
            bench_start("Decrypting message");
            err = noise_cipherstate_decrypt(responder_recv_cipher, &message_buf);
            bench_end("Decrypting message");
            if (err != NOISE_ERROR_NONE) {
                noise_log_error(TAG, "Decryption failed:", err);
                return false;
            }

            ESP_LOGI(TAG, "Decrypted Message: %.*s", message_buf.size, (char *)message_buf.data);
            return true; 
        }
    }
    return false;
}

void zb_apsde_data_confirm_handler(esp_zb_apsde_data_confirm_t confirm)
{
    if (waiting_for_last_confirm && confirm.status == 0x00) {
        last_confirm_received = true;
        waiting_for_last_confirm = false;
        ESP_LOGI(TAG, "APS Confirm received for last message.");
    }
}

static void bdb_start_top_level_commissioning_cb(uint8_t mode_mask)
{
    ESP_ERROR_CHECK(esp_zb_bdb_start_top_level_commissioning(mode_mask));
}


void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct)
{
    uint32_t *p_sg_p = signal_struct->p_app_signal;
    esp_err_t err_status = signal_struct->esp_err_status;
    esp_zb_app_signal_type_t sig_type = *p_sg_p;

    switch (sig_type) {
    case ESP_ZB_ZDO_SIGNAL_SKIP_STARTUP:
        ESP_LOGI(TAG, "Zigbee stack initialized");
        esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_INITIALIZATION);
        break;

    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "Device started up in %s factory-reset mode", esp_zb_bdb_is_factory_new() ? "" : "non");
            if (esp_zb_bdb_is_factory_new()) {
                ESP_LOGI(TAG, "Start network steering");
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
            } else {
                ESP_LOGI(TAG, "Device rebooted");
            }
        } else {
            /* commissioning failed */
            ESP_LOGW(TAG, "Failed to initialize Zigbee stack (status: %s)", esp_err_to_name(err_status));
        }
        break;

    case ESP_ZB_BDB_SIGNAL_STEERING:
        if (err_status == ESP_OK) {
            esp_zb_ieee_addr_t extended_pan_id;
            esp_zb_get_extended_pan_id(extended_pan_id);
            ESP_LOGI(TAG, "Joined network successfully (Extended PAN ID: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
                          "PAN ID: 0x%04hx, Channel:%d, Short Address: 0x%04hx)",
                     extended_pan_id[7], extended_pan_id[6], extended_pan_id[5], extended_pan_id[4],
                     extended_pan_id[3], extended_pan_id[2], extended_pan_id[1], extended_pan_id[0],
                     esp_zb_get_pan_id(), esp_zb_get_current_channel(), esp_zb_get_short_address());
        } else {
            ESP_LOGI(TAG, "Network steering was not successful (status: %s)", esp_err_to_name(err_status));
            esp_zb_scheduler_alarm((esp_zb_callback_t)bdb_start_top_level_commissioning_cb,
                                   ESP_ZB_BDB_MODE_NETWORK_STEERING, 1000);
        }
        break;

    default:
        ESP_LOGI(TAG, "ZDO signal: %s (0x%x), status: %s",
                 esp_zb_zdo_signal_to_string(sig_type), sig_type, esp_err_to_name(err_status));
        break;
    }
}




/********************* Zigbee Task **************************/

static void esp_zb_task(void *pvParameters)
{
    /* initialize Zigbee stack as an End Device */
    esp_zb_cfg_t zb_nwk_cfg = ESP_ZB_ZED_CONFIG();
    esp_zb_init(&zb_nwk_cfg);
    light_driver_init(LIGHT_DEFAULT_OFF); // or LIGHT_DEFAULT_ON if you prefer
    // Register a default "On/Off Light" endpoint, though for raw APS you only
    // really need an endpoint. This is the typical sample code.
    esp_zb_on_off_light_cfg_t light_cfg = ESP_ZB_DEFAULT_ON_OFF_LIGHT_CONFIG();
    esp_zb_ep_list_t *esp_zb_on_off_light_ep = esp_zb_on_off_light_ep_create(HA_ESP_LIGHT_ENDPOINT, &light_cfg);
    esp_zb_device_register(esp_zb_on_off_light_ep);

    // Register the APS data indication callback to catch raw cluster=0xFFC0 messages
    esp_zb_aps_data_indication_handler_register(zb_apsde_data_indication_handler);
    // This line is missing in the responder code:
    esp_zb_aps_data_confirm_handler_register(zb_apsde_data_confirm_handler);

    // Choose Zigbee channel(s) and start the stack
    esp_zb_set_primary_network_channel_set(ESP_ZB_PRIMARY_CHANNEL_MASK);
    ESP_ERROR_CHECK(esp_zb_start(false));

    // Main Zigbee event loop
    esp_zb_stack_main_loop();
}

/********************* ESP-IDF Entry Point **************************/

void app_main(void) {
    // Basic setup
    esp_zb_platform_config_t config = {
        .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_ZB_DEFAULT_HOST_CONFIG(),
    };
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_zb_platform_config(&config));

    // Create the Zigbee task
    xTaskCreate(esp_zb_task, "Zigbee_main", 16384, NULL, 5, NULL);

    // Start Noise Protocol handshake
    start_noise_handshake();
}
