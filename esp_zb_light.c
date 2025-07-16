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
#include "keys.h"
#include "noise_log.h"
#if !defined ZB_ED_ROLE
#error Define ZB_ED_ROLE in idf.py menuconfig to compile light (End Device) source code.
#endif

#define TAG "ESP32_NOISE_RECEIVER"
static NoiseHandshakeState *responder = NULL;
static NoiseCipherState *responder_send_cipher = NULL;
static NoiseCipherState *responder_recv_cipher = NULL;
static bool handshake_complete = false;
static volatile bool waiting_for_last_confirm = false;
static volatile bool last_confirm_received = false;
static uint32_t benchmark_start_cycles = 0;
static uint32_t benchmark_end_cycles = 0;
static uint64_t benchmark_start_time_us = 0;
static uint64_t benchmark_end_time_us = 0;


////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////Benchmark parameters////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////////////
#if ENABLE_NOISE_BENCHMARK
    #define LOOP_AMOUNT_BENCHMARK 10
    #if PQ_BENCHMARK
        #if KYBER_768 
            #define NUM_PATTERNS 11
            #define USE_KYBER_KEYS 1
            #define MAX_NOISE_MESSAGE_SIZE 4096 
            static const char *noise_patterns[NUM_PATTERNS] = {
                "Noise_KEMNN_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMNK_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMNX_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMXN_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMXK_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMKN_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMKK_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMKX_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMIN_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMIK_Kyber768_ChaChaPoly_SHA256",
                "Noise_KEMXX_Kyber768_ChaChaPoly_SHA256"
            };
            static bool frag_step = false;
            static uint8_t frag_Step_XX = 0;  
            static size_t reassembly_offset = 0;
        #else
            #define NUM_PATTERNS 11
            #define USE_KYBER_KEYS 1
            #define MAX_NOISE_MESSAGE_SIZE 4096 
            static const char *noise_patterns[NUM_PATTERNS] = {
                "Noise_KEMNN_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMNK_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMNX_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMXN_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMXK_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMKN_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMKK_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMKX_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMIN_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMIK_Kyber512_ChaChaPoly_SHA256",
                "Noise_KEMXX_Kyber512_ChaChaPoly_SHA256"
            };
            static bool frag_step = false;
            static uint8_t frag_Step_XX = 0;  
            static size_t reassembly_offset = 0;
        #endif 
    #endif 
    #if REG_BENCHMARK
        #define MAX_NOISE_MESSAGE_SIZE 2056
        #define NUM_PATTERNS 11
        #define USE_KYBER_KEYS 0
        static const char *noise_patterns[NUM_PATTERNS] = {
            "Noise_NN_25519_ChaChaPoly_SHA256",
            "Noise_NK_25519_ChaChaPoly_SHA256",
            "Noise_NX_25519_ChaChaPoly_SHA256",
            "Noise_XN_25519_ChaChaPoly_SHA256",
            "Noise_XK_25519_ChaChaPoly_SHA256",
            "Noise_XX_25519_ChaChaPoly_SHA256",
            "Noise_KN_25519_ChaChaPoly_SHA256",
            "Noise_KK_25519_ChaChaPoly_SHA256",
            "Noise_KX_25519_ChaChaPoly_SHA256",
            "Noise_IN_25519_ChaChaPoly_SHA256",
            "Noise_IK_25519_ChaChaPoly_SHA256"
        };
    #endif 
    static uint8_t pattern_index = 0;
    static uint8_t loop_counter = LOOP_AMOUNT_BENCHMARK;
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
    
#elif PQ_BENCHMARK
    #define HANDSHAKE_PATTERN "Noise_KEMNN_Kyber512_ChaChaPoly_SHA256"
    #define MAX_NOISE_MESSAGE_SIZE 4096    
    #define USE_KYBER_KEYS 1
    static uint8_t flex_buffer[MAX_NOISE_MESSAGE_SIZE];
    static bool frag_step = false;
    static uint8_t frag_Step_XX = 0;  
    static size_t reassembly_offset = 0;
#else
    #define HANDSHAKE_PATTERN "Noise_NN_25519_ChaChaPoly_SHA256"
    #define MAX_NOISE_MESSAGE_SIZE 2056
    #define USE_KYBER_KEYS 0 
#endif

static bool envelope_ready(size_t buf_len, size_t expected_len)
{
    // return true as soon as we've buffered at least expected_len bytes
    return buf_len >= expected_len;
}


static size_t buf_len = 0;
static uint8_t reasm_buf[MAX_NOISE_MESSAGE_SIZE]; 

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
    NOISE_LOGI(TAG, "%s handshake state: %s", role, noise_action_to_string(noise_handshakestate_get_action(hs)));
}
/********************* Start Noise Handshake (Responder) **************************/

void start_noise_handshake() {
    NOISE_LOGI(TAG, "Starting Noise handshake as Responder...");
    int err;

    // **Initialize Noise Framework**
    err = noise_init_framework();
    if (err != NOISE_ERROR_NONE) {
        noise_log_error(TAG, "Failed to initialize Noise framework:", err);
        return; 
    }

    benchmark_start_cycles = esp_cpu_get_cycle_count();
    benchmark_start_time_us = esp_timer_get_time();

    // **Create Responder Handshake State**
    #if ENABLE_NOISE_BENCHMARK 
        bench_start("Handshake creation");
        NOISE_LOGW(TAG, "SETUP: Receiver_%s", noise_patterns[pattern_index]);
        err = noise_handshakestate_new_by_name(&responder, noise_patterns[pattern_index], NOISE_ROLE_RESPONDER);
    #else
        bench_start("Handshake creation");
        NOISE_LOGI(TAG, "SETUP: Receiver_%s", HANDSHAKE_PATTERN);
        err = noise_handshakestate_new_by_name(&responder, HANDSHAKE_PATTERN, NOISE_ROLE_RESPONDER);
    #endif 
    bench_end("Handshake creation");
    if (err != NOISE_ERROR_NONE) {
        noise_log_error(TAG, "Failed to create responder handshake:", err);
        return; 
    }

    if (noise_handshakestate_needs_local_keypair(responder)) {
        NoiseDHState *local_dh = noise_handshakestate_get_local_keypair_dh(responder);
    
        #if USE_KYBER_KEYS
            #if KYBER_768
                err = noise_dhstate_set_keypair(local_dh,
                                                local_private_pq_768, sizeof(local_private_pq_768),
                                                local_public_pq_768, sizeof(local_public_pq_768));
            #else
                err = noise_dhstate_set_keypair(local_dh,
                                                local_private_pq_512, sizeof(local_private_pq_512),
                                                local_public_pq_512, sizeof(local_public_pq_512)); 
            #endif 
        #else
        err = noise_dhstate_set_keypair(local_dh,
                                        local_private, sizeof(local_private),
                                        local_public, sizeof(local_public));
        #endif
    
        if (err != NOISE_ERROR_NONE) {
            noise_log_error(TAG, "Failed to set local static keypair", err);
            return;
        }
    }

    if (noise_handshakestate_needs_remote_public_key(responder)) {
        NoiseDHState *remote_dh = noise_handshakestate_get_remote_public_key_dh(responder);
    
        #if USE_KYBER_KEYS
            #if KYBER_768
                err = noise_dhstate_set_public_key(remote_dh, remote_public_pq_768, sizeof(remote_public_pq_768));
            #else
                err = noise_dhstate_set_public_key(remote_dh, remote_public_pq_512, sizeof(remote_public_pq_512));
            #endif 
        #else
        err = noise_dhstate_set_public_key(remote_dh, remote_public, sizeof(remote_public));
        #endif
    
        if (err != NOISE_ERROR_NONE) {
            noise_log_error(TAG, "Failed to set remote public key", err);
            return;
        }
    }

    // **Start the handshake process**
    bench_start("Handshake start");
    err = noise_handshakestate_start(responder);
    bench_end("Handshake start");
    if (err != NOISE_ERROR_NONE) {
        noise_log_error(TAG, "Failed to start responder handshake:", err);
        return;
    }

    NOISE_LOGI(TAG, "Responder is ready to process incoming handshake messages.");
}

/********************* APS Data Indication Handler (Receiver) **************************/

bool zb_apsde_data_indication_handler(esp_zb_apsde_data_ind_t data_ind) {
    NOISE_LOGI(TAG, "Received APS fragment of length: %"PRId32, data_ind.asdu_length);

    if (data_ind.dst_endpoint == HA_ESP_LIGHT_ENDPOINT &&
        data_ind.profile_id == ESP_ZB_AF_HA_PROFILE_ID &&
        data_ind.cluster_id == 0xFFC0) {
        
        if (data_ind.status || data_ind.asdu_length < 1) {
            ESP_LOGE(TAG, "Invalid APS message");
            return false;
        }

        int handshake_state = noise_handshakestate_get_action(responder);
        log_handshake_state(responder, "Responder");

        NoiseBuffer message_buf;
        int err;

        // **Process Handshake Message**
        if (handshake_state != NOISE_ACTION_COMPLETE) {
            if (handshake_state == NOISE_ACTION_READ_MESSAGE) { 
                NOISE_LOGI(TAG, "Processing handshake message...");
                unsigned expected = noise_expected_read_length(responder);
                NOISE_LOGW(TAG, "Expecting message length of: %u bytes", expected);
                log_handshake_state(responder, "Initiator");
                memcpy(reasm_buf + buf_len, data_ind.asdu, data_ind.asdu_length);
                buf_len += data_ind.asdu_length; 
                //NOISE_LOG_BUFFER_HEX_LEVEL("Received APS Message", data_ind.asdu, data_ind.asdu_length, ESP_LOG_INFO);
                NOISE_LOGW(TAG, "Buffered %u/%u bytes", (unsigned)buf_len, expected);
                if (!envelope_ready(buf_len, expected)) {
                    return true;  // keep waiting for more fragments
                }
                NOISE_LOGW(TAG, "Consuming %u bytes (expected %u)", (unsigned)buf_len, (unsigned)expected);
                noise_buffer_set_input(message_buf, reasm_buf, buf_len);
                bench_start("Read Message");
                err = noise_handshakestate_read_message(responder, &message_buf, NULL);
                bench_end("Read Message");
                if (err != NOISE_ERROR_NONE) {
                    noise_log_error(TAG, "Failed to process handshake message:", err);
                    return false;
                }
                buf_len = 0;
                NOISE_LOGI(TAG, "Processed handshake message successfully.");
                handshake_state = noise_handshakestate_get_action(responder);
                log_handshake_state(responder, "Responder");
            }

            // **Check if handshake is complete**
            if (handshake_state == NOISE_ACTION_WRITE_MESSAGE) { 
                // **Send handshake response**
                NOISE_LOGI(TAG, "Sending handshake response...");
                uint8_t message[MAX_NOISE_MESSAGE_SIZE];
                noise_buffer_set_output(message_buf, message, sizeof(message));
                bench_start("Write message");
                err = noise_handshakestate_write_message(responder, &message_buf, NULL);
                bench_end("Write message");
                if (err != NOISE_ERROR_NONE) {
                    noise_log_error(TAG, "Failed to generate handshake response:", err);
                    return false;
                }

                size_t total_len = message_buf.size;
                uint8_t *data     = message_buf.data;

                for (size_t offset = 0; offset < total_len; offset += 1600) {
                    size_t chunk_len = total_len - offset;
                    if (chunk_len > 1600) {
                        chunk_len = 1600;
                    }

                    esp_zb_apsde_data_req_t req = { 0 };
                    req.dst_addr_mode  = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
                    req.dst_addr.addr_short = data_ind.src_short_addr;
                    req.dst_endpoint   = data_ind.src_endpoint;
                    req.profile_id     = ESP_ZB_AF_HA_PROFILE_ID;
                    req.cluster_id     = 0xFFC0;
                    req.src_endpoint   = HA_ESP_LIGHT_ENDPOINT;
                    req.asdu_length    = (uint16_t)chunk_len;
                    req.asdu           = data + offset;
                    req.radius         = 10;
                    req.tx_options     = (ESP_ZB_APSDE_TX_OPT_ACK_TX | ESP_ZB_APSDE_TX_OPT_FRAG_PERMITTED);
                    req.use_alias      = false;

                    NOISE_LOGI(TAG, "Sending APS fragment at offset %u, length %u",
                                (unsigned)offset, (unsigned)chunk_len);

                    bench_start("Zigbee Packet TX");
                    esp_zb_lock_acquire(portMAX_DELAY);
                    esp_zb_aps_data_request(&req);
                    esp_zb_lock_release();
                    bench_end("Zigbee Packet TX");
                }
                
                NOISE_LOGI(TAG, "Sent %u byte handshake message in %u fragments",
                            (unsigned)total_len,
                            (unsigned)((total_len + 1600 - 1) / 1600));
                handshake_state = noise_handshakestate_get_action(responder);
                log_handshake_state(responder, "Responder");
            }

            if (handshake_state == NOISE_ACTION_SPLIT) { 
                NOISE_LOGI(TAG, "Handshake complete! Switching to encrypted mode.");
                handshake_complete = true;

                // **Split cipher states for encryption/decryption**
                bench_start("Handshake split");
                err = noise_handshakestate_split(responder, &responder_send_cipher, &responder_recv_cipher);
                bench_end("Handshake split");
                if (err != NOISE_ERROR_NONE) {
                    noise_log_error(TAG, "Failed to split cipher states:", err);
                    return false;
                }
                benchmark_end_cycles = esp_cpu_get_cycle_count();
                benchmark_end_time_us = esp_timer_get_time();
                NOISE_LOGI(TAG, "Cipher states created. Secure communication ready.");
                uint32_t elapsed_cycles = benchmark_end_cycles - benchmark_start_cycles;
                uint64_t elapsed_us = benchmark_end_time_us - benchmark_start_time_us;
                ESP_LOGW("BENCH", "[Handshake] Took %" PRIu64 " us and %" PRIu32 " cycles",elapsed_us, elapsed_cycles);
                #if ENABLE_NOISE_BENCHMARK
                    loop_counter--;
                    if (loop_counter > 0) {
                        reset_noise_state();
                        ESP_LOGW("LOOP", "Remaining handshakes for current pattern (%s): %d", noise_patterns[pattern_index], loop_counter);
                    } 
                    else {
                        pattern_index++;
                        if (pattern_index < NUM_PATTERNS) {
                            loop_counter = LOOP_AMOUNT_BENCHMARK;
                            reset_noise_state();
                            ESP_LOGW("BENCH", "Switching to next pattern: %s", noise_patterns[pattern_index]);
                        } 
                        else {
                            ESP_LOGW("BENCH", "All patterns completed.");
                            return true;
                        }
                    }
                    #if PQ_BENCHMARK
                    if (strcmp(noise_patterns[pattern_index], "Noise_KEMIK_Kyber512_ChaChaPoly_SHA256") == 0 || strcmp(noise_patterns[pattern_index], "Noise_KEMXX_Kyber512_ChaChaPoly_SHA256") == 0 || strcmp(noise_patterns[pattern_index], "Noise_KEMIK_Kyber768_ChaChaPoly_SHA256") == 0 || strcmp(noise_patterns[pattern_index], "Noise_KEMXX_Kyber768_ChaChaPoly_SHA256") == 0) {
                        frag_step = false;
                    }
                    #endif
                    esp_zb_scheduler_alarm((esp_zb_callback_t)start_noise_handshake, 0, 0);  // 10 ms delay
                #endif
            }
            return true; 
        }

        // **Process Encrypted Message**
        else {
            NOISE_LOGI(TAG, "Processing Encrypted Noise message...");

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

            NOISE_LOGI(TAG, "Decrypted Message: %.*s", message_buf.size, (char *)message_buf.data);
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
        NOISE_LOGI(TAG, "APS Confirm received for last message.");
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
        NOISE_LOGI(TAG, "Zigbee stack initialized");
        esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_INITIALIZATION);
        break;

    case ESP_ZB_BDB_SIGNAL_DEVICE_FIRST_START:
    case ESP_ZB_BDB_SIGNAL_DEVICE_REBOOT:
        if (err_status == ESP_OK) {
            NOISE_LOGI(TAG, "Device started up in %s factory-reset mode", esp_zb_bdb_is_factory_new() ? "" : "non");
            if (esp_zb_bdb_is_factory_new()) {
                NOISE_LOGI(TAG, "Start network steering");
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
            } else {
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_FORMATION);
                NOISE_LOGI(TAG, "Device rebooted");
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
            NOISE_LOGI(TAG, "Joined network successfully (Extended PAN ID: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
                          "PAN ID: 0x%04hx, Channel:%d, Short Address: 0x%04hx)",
                     extended_pan_id[7], extended_pan_id[6], extended_pan_id[5], extended_pan_id[4],
                     extended_pan_id[3], extended_pan_id[2], extended_pan_id[1], extended_pan_id[0],
                     esp_zb_get_pan_id(), esp_zb_get_current_channel(), esp_zb_get_short_address());
        } else {
            NOISE_LOGI(TAG, "Network steering was not successful (status: %s)", esp_err_to_name(err_status));
            esp_zb_scheduler_alarm((esp_zb_callback_t)bdb_start_top_level_commissioning_cb,
                                   ESP_ZB_BDB_MODE_NETWORK_STEERING, 1000);
        }
        break;

    default:
        NOISE_LOGI(TAG, "ZDO signal: %s (0x%x), status: %s",
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
    // Basic initialization
    esp_err_t ret = esp_zb_io_buffer_size_set(253);
    if (ret != ESP_OK) {
        NOISE_LOGE(TAG, "Failed to set IO buffer size, error = %s", esp_err_to_name(ret));
    } else {
        NOISE_LOGI(TAG, "Successfully set Zigbee IO buffer size");
    }
    ret = esp_zb_scheduler_queue_size_set(254);
    if (ret != ESP_OK) {
        NOISE_LOGE(TAG, "Failed to set IO buffer size, error = %s", esp_err_to_name(ret));
    } else {
        NOISE_LOGI(TAG, "Successfully set Zigbee IO buffer size");
    }
    // Basic setup
    esp_zb_platform_config_t config = {
        .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
        .host_config = ESP_ZB_DEFAULT_HOST_CONFIG(),
    };
    
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_zb_platform_config(&config));
    
    // Create the Zigbee task
    xTaskCreate(esp_zb_task, "Zigbee_main", 65536, NULL, 5, NULL);

    // Start Noise Protocol handshake
    start_noise_handshake();
}
