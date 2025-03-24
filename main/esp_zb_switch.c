#include "string.h"
#include <noise/protocol.h>
#include <sodium.h> 
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_zb_switch.h"
#include "ha/esp_zigbee_ha_standard.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"
#include "aps/esp_zigbee_aps.h"

#define HANDSHAKE_PATTERN "Noise_KEMNN_Kyber512_ChaChaPoly_SHA256"
#define MAX_NOISE_MESSAGE_SIZE 1024

#define TAG "ESP32_NOISE_TEST"
static NoiseHandshakeState *initiator = NULL;
static NoiseCipherState *initiator_send_cipher = NULL;
static NoiseCipherState *initiator_recv_cipher = NULL;
static bool handshake_complete = false;
// This ensures we are building as a Coordinator (ZB_COORDINATOR_ROLE)
#if defined ZB_ED_ROLE
#error Define ZB_COORDINATOR_ROLE in idf.py menuconfig to compile light switch source code.
#endif


const char* noise_action_to_string(int action)
{
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


typedef struct light_bulb_device_params_s {
    esp_zb_ieee_addr_t ieee_addr;
    uint8_t  endpoint;
    uint16_t short_addr;
} light_bulb_device_params_t;

// We store the remote short address here once discovered.
static uint16_t g_remote_short_addr = 0xFFFF;

static switch_func_pair_t button_func_pair[] = {
    { GPIO_INPUT_IO_TOGGLE_SWITCH, SWITCH_ONOFF_TOGGLE_CONTROL }
};



void start_noise_handshake()
{
    ESP_LOGI(TAG, "Starting Noise handshake as Initiator...");

    int err;
    NoiseBuffer message_buf;
    uint8_t message[MAX_NOISE_MESSAGE_SIZE];

    // **Initialize Noise framework (if not done already)**
    err = noise_init_framework();
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to initialize Noise framework: %d", err);
        return;
    }

    // **Create initiator handshake state (Global)**
    err = noise_handshakestate_new_by_name(&initiator, HANDSHAKE_PATTERN, NOISE_ROLE_INITIATOR);
    if (err != NOISE_ERROR_NONE) {
        char err_str[64];
        noise_strerror(err, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "Failed to initiator handshake state: %s (code=%d)", err_str, err);
        return;
    }

    // **Start the handshake process**
    err = noise_handshakestate_start(initiator);
    if (err != NOISE_ERROR_NONE) {
        ESP_LOGE(TAG, "Failed to start initiator handshake: %d", err);
        return;
    }

    // **Generate first handshake message**
    noise_buffer_set_output(message_buf, message, sizeof(message));
    err = noise_handshakestate_write_message(initiator, &message_buf, NULL);
    if (err != NOISE_ERROR_NONE) {
        char err_str[64];
        noise_strerror(err, err_str, sizeof(err_str));
        ESP_LOGE(TAG, "Failed to generate first handshake message: %s (code=%d)", err_str, err);
        return;
    }

    // **Send handshake message over Zigbee APS layer**
    esp_zb_apsde_data_req_t req;
    memset(&req, 0, sizeof(req));
    req.dst_addr_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
    req.dst_addr.addr_short = g_remote_short_addr;
    req.dst_endpoint = 10;
    req.profile_id = ESP_ZB_AF_HA_PROFILE_ID;
    req.cluster_id = 0xFFC0;
    req.src_endpoint = HA_ONOFF_SWITCH_ENDPOINT;
    req.asdu_length = message_buf.size;
    req.asdu = message_buf.data;
    req.radius = 10; // You can increase if multi-hop
    req.tx_options = (ESP_ZB_APSDE_TX_OPT_ACK_TX | ESP_ZB_APSDE_TX_OPT_FRAG_PERMITTED);
    req.use_alias = false;
    esp_zb_lock_acquire(portMAX_DELAY);
    esp_zb_aps_data_request(&req);
    esp_zb_lock_release();

    ESP_LOGI(TAG, "Sent first handshake message.");
}

// ────────────────────────────────────────────────────────────────────────────────
// 1) Button Handler: Send a 128-bit key at the APS layer
// ────────────────────────────────────────────────────────────────────────────────
static void esp_zb_buttons_handler(switch_func_pair_t *button_func_pair)
{
    if (button_func_pair->func == SWITCH_ONOFF_TOGGLE_CONTROL) {
        if (g_remote_short_addr == 0xFFFF) {
            // We haven't found or stored the remote device's address yet
            ESP_LOGW(TAG, "Remote device short address not set. Press button again after device is discovered.");
            return;
        }
        if (!handshake_complete) {
            ESP_LOGW(TAG, "Handshake not complete. Cannot send encrypted message.");
            return;
        }
    
        ESP_LOGI(TAG, "Sending encrypted 'Hello World'...");
    
        const char *plaintext = "Hello World!";
        uint8_t message[MAX_NOISE_MESSAGE_SIZE]; 
        size_t message_size;
        NoiseBuffer mbuf;
        int err;
    
        // **Prepare buffer for encryption**
        noise_buffer_set_inout(mbuf, message, strlen(plaintext), sizeof(message) );
        memcpy(message, plaintext, strlen(plaintext));
    
        // **Encrypt the message**
        err = noise_cipherstate_encrypt(initiator_send_cipher, &mbuf);
        if (err != NOISE_ERROR_NONE) {
            ESP_LOGE(TAG, "Encryption failed: %d", err);
            return;
        }
    
    
        ESP_LOGI(TAG, "Encrypted Message (Hex):");
        for (size_t i = 0; i < mbuf.size; i++) {
            printf("%02X ", message[i]); // Print encrypted payload
        }
        printf("\n");
    
        // **Send the encrypted message via Zigbee APS layer**
        esp_zb_apsde_data_req_t req;
        memset(&req, 0, sizeof(req));
        req.dst_addr_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
        req.dst_addr.addr_short = g_remote_short_addr;
        req.dst_endpoint = 10;
        req.profile_id = ESP_ZB_AF_HA_PROFILE_ID;
        req.cluster_id = 0xFFC0;
        req.src_endpoint = HA_ONOFF_SWITCH_ENDPOINT;
        req.asdu_length = mbuf.size; // Include the length header
        req.asdu = message;
        req.radius = 10;
        req.tx_options = (ESP_ZB_APSDE_TX_OPT_ACK_TX | ESP_ZB_APSDE_TX_OPT_FRAG_PERMITTED);
        req.use_alias = false;
    
        esp_zb_lock_acquire(portMAX_DELAY);
        esp_zb_aps_data_request(&req);
        esp_zb_lock_release();
    
        ESP_LOGI(TAG, "Encrypted message sent.");
        }
    return;
}


// ────────────────────────────────────────────────────────────────────────────────
// X) APS layer callback
// ────────────────────────────────────────────────────────────────────────────────


bool zb_apsde_data_indication_handler_switch(esp_zb_apsde_data_ind_t data_ind)
{
    ESP_LOGI(TAG, "Received APS Data Indication");
    if (data_ind.dst_endpoint == HA_ONOFF_SWITCH_ENDPOINT &&
        data_ind.profile_id == ESP_ZB_AF_HA_PROFILE_ID &&
        data_ind.cluster_id == 0xFFC0)
    {
        if (data_ind.status || data_ind.asdu_length < 1) {
            ESP_LOGE(TAG, "Invalid APS message");
            return false;
        }

        int handshake_state = noise_handshakestate_get_action(initiator);
        ESP_LOGI(TAG, "Current handshake state: %s", noise_action_to_string(handshake_state));

        NoiseBuffer message_buf;
        int err;

        // **If handshake is still in progress**
        if (handshake_state != NOISE_ACTION_COMPLETE) {
            ESP_LOGI(TAG, "Processing handshake response...");
            log_handshake_state(initiator, "Initiator");
            noise_buffer_set_input(message_buf, data_ind.asdu, data_ind.asdu_length);
            ESP_LOGI(TAG, "Received APS Message Length: %d", (int)data_ind.asdu_length);
            ESP_LOG_BUFFER_HEX_LEVEL("Received APS Message", data_ind.asdu, data_ind.asdu_length, ESP_LOG_INFO);

            if ((err = noise_handshakestate_read_message(initiator, &message_buf, NULL)) != NOISE_ERROR_NONE) {
                noise_perror("Failed to process handshake response", err);
                return false;
            }

            ESP_LOGI(TAG, "Processed handshake response successfully.");

            // **Check if handshake is complete after this step**
            handshake_state = noise_handshakestate_get_action(initiator);
            if (handshake_state == NOISE_ACTION_SPLIT) {
                ESP_LOGI(TAG, "Handshake complete! Switching to encrypted mode.");
                handshake_complete = true;

                // **Split cipher states for encryption/decryption**
                if ((err =  noise_handshakestate_split(initiator, &initiator_send_cipher, &initiator_recv_cipher)) != NOISE_ERROR_NONE) {
                    noise_perror("Failed to split cipher states:", err);
                    return false;
                }

                ESP_LOGI(TAG, "Cipher states created. Secure communication ready.");
                return true;
            }

            // **If handshake is not yet complete, send the next handshake message**
            ESP_LOGI(TAG, "Sending next handshake message...");

            noise_buffer_set_output(message_buf, data_ind.asdu, sizeof(data_ind.asdu));
            if ((err =  noise_handshakestate_write_message(initiator, &message_buf, NULL)) != NOISE_ERROR_NONE) {
                noise_perror("Failed to generate handshake message:", err);
                return false;
            }
            

            // **Send handshake message over Zigbee**
            esp_zb_apsde_data_req_t req;
            memset(&req, 0, sizeof(req));
            req.dst_addr_mode = ESP_ZB_APS_ADDR_MODE_16_ENDP_PRESENT;
            req.dst_addr.addr_short = data_ind.src_short_addr;
            req.dst_endpoint = data_ind.src_endpoint;
            req.profile_id = ESP_ZB_AF_HA_PROFILE_ID;
            req.cluster_id = 0xFFC0;
            req.src_endpoint = HA_ONOFF_SWITCH_ENDPOINT;
            req.asdu_length = message_buf.size;
            req.asdu = message_buf.data;
            req.radius = 10; // You can increase if multi-hop
            req.tx_options = (ESP_ZB_APSDE_TX_OPT_ACK_TX | ESP_ZB_APSDE_TX_OPT_FRAG_PERMITTED);
            req.use_alias = false;
            esp_zb_lock_acquire(portMAX_DELAY);
            esp_zb_aps_data_request(&req);
            esp_zb_lock_release();
            ESP_LOGI(TAG, "Sent handshake message.");
        }

        // **If handshake is complete, process encrypted messages**
        else {
            ESP_LOGI(TAG, "Processing Encrypted Noise message...");

            if (!initiator_recv_cipher) {
                ESP_LOGE(TAG, "Cipher state is NULL. Handshake may not be complete.");
                return false;
            }

            // Prepare buffer for decryption
            noise_buffer_set_input(message_buf, data_ind.asdu, data_ind.asdu_length);

            // Decrypt message
            if ((err =  noise_cipherstate_decrypt(initiator_recv_cipher, &message_buf)) != NOISE_ERROR_NONE) {
                noise_perror("Decryption failed:", err);
                return false;
            }

            ESP_LOGI(TAG, "Decrypted Message: %.*s", message_buf.size, (char *)message_buf.data);
        }
    }
    return false;
}
// ────────────────────────────────────────────────────────────────────────────────
// 2) Binding & Discovery Callbacks
// ────────────────────────────────────────────────────────────────────────────────
static void bind_cb(esp_zb_zdp_status_t zdo_status, void *user_ctx)
{
    if (zdo_status == ESP_ZB_ZDP_STATUS_SUCCESS) {
        ESP_LOGI(TAG, "Bound successfully!");
        
        if (user_ctx) {
            light_bulb_device_params_t *light = (light_bulb_device_params_t *)user_ctx;
            ESP_LOGI(TAG, "Bound device at short_addr=0x%04x, endpoint=%d", light->short_addr, light->endpoint);
            g_remote_short_addr = light->short_addr; // Save the bound device address
            
            // **Start the Noise Handshake immediately**
            start_noise_handshake();  
            free(light);
        }
    }
}

static void user_find_cb(esp_zb_zdp_status_t zdo_status, uint16_t addr, uint8_t endpoint, void *user_ctx)
{
    if (zdo_status == ESP_ZB_ZDP_STATUS_SUCCESS) {
        ESP_LOGI(TAG, "Found light with short_addr=0x%04hx, endpoint=%d", addr, endpoint);

        // Save the remote short address in our global var so we can use it in the button handler
        g_remote_short_addr = addr;

        // Example: try binding for On/Off cluster
        esp_zb_zdo_bind_req_param_t bind_req;
        light_bulb_device_params_t *light = (light_bulb_device_params_t *)malloc(sizeof(light_bulb_device_params_t));
        if (!light) {
            return;
        }
        light->endpoint = endpoint;
        light->short_addr = addr;
        esp_zb_ieee_address_by_short(light->short_addr, light->ieee_addr);

        // Fill out the bind request
        esp_zb_get_long_address(bind_req.src_address);
        bind_req.src_endp = HA_ONOFF_SWITCH_ENDPOINT;
        bind_req.cluster_id = ESP_ZB_ZCL_CLUSTER_ID_ON_OFF;
        bind_req.dst_addr_mode = ESP_ZB_ZDO_BIND_DST_ADDR_MODE_64_BIT_EXTENDED;
        memcpy(bind_req.dst_address_u.addr_long, light->ieee_addr, sizeof(esp_zb_ieee_addr_t));
        bind_req.dst_endp = endpoint;
        bind_req.req_dst_addr = esp_zb_get_short_address();

        ESP_LOGI(TAG, "Try to bind On/Off cluster");
        esp_zb_zdo_device_bind_req(&bind_req, bind_cb, (void *)light);
    }
}

static void bdb_start_top_level_commissioning_cb(uint8_t mode_mask)
{
    ESP_ERROR_CHECK(esp_zb_bdb_start_top_level_commissioning(mode_mask));
}

// ────────────────────────────────────────────────────────────────────────────────
// 3) APS Data Confirm Callback
// ────────────────────────────────────────────────────────────────────────────────
void zb_apsde_data_confirm_handler(esp_zb_apsde_data_confirm_t confirm)
{
    if (confirm.status == 0x00) {
        ESP_LOGI("APSDE CONFIRM",
                "Sent successfully from endpoint %d (short=0x%04hx) to endpoint %d (short=0x%04hx)",
                confirm.src_endpoint, esp_zb_get_short_address(),
                confirm.dst_endpoint, confirm.dst_addr.addr_short);

        // Optionally print the data we sent again
        ESP_LOG_BUFFER_HEX_LEVEL("APSDE CONFIRM", confirm.asdu, confirm.asdu_length, ESP_LOG_INFO);
    } else {
        ESP_LOGE("APSDE CONFIRM", "Failed to send APSDE-DATA request, error code: %d", confirm.status);
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// 4) Zigbee Application Signal Callback
// ────────────────────────────────────────────────────────────────────────────────
void esp_zb_app_signal_handler(esp_zb_app_signal_t *signal_struct)
{
    uint32_t *p_sg_p = signal_struct->p_app_signal;
    esp_err_t err_status = signal_struct->esp_err_status;
    esp_zb_app_signal_type_t sig_type = *p_sg_p;
    esp_zb_zdo_signal_device_annce_params_t *dev_annce_params = NULL;

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
                ESP_LOGI(TAG, "Start network formation");
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_FORMATION);
            } else {
                esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_FORMATION);
                ESP_LOGI(TAG, "Device rebooted, already part of a network");
            }
        } else {
            ESP_LOGE(TAG, "Failed to initialize Zigbee stack (status: %s)", esp_err_to_name(err_status));
        }
        break;

    case ESP_ZB_BDB_SIGNAL_FORMATION:
        if (err_status == ESP_OK) {
            esp_zb_ieee_addr_t extended_pan_id;
            esp_zb_get_extended_pan_id(extended_pan_id);
            ESP_LOGI(TAG, "Formed network successfully (Ext PAN ID: %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x, "
                        "PAN ID: 0x%04hx, Channel:%d, Short Address: 0x%04hx)",
                    extended_pan_id[7], extended_pan_id[6], extended_pan_id[5], extended_pan_id[4],
                    extended_pan_id[3], extended_pan_id[2], extended_pan_id[1], extended_pan_id[0],
                    esp_zb_get_pan_id(), esp_zb_get_current_channel(), esp_zb_get_short_address());

            // After forming, start steering so other devices can join
            esp_zb_bdb_start_top_level_commissioning(ESP_ZB_BDB_MODE_NETWORK_STEERING);
        } else {
            ESP_LOGI(TAG, "Restart network formation (status: %s)", esp_err_to_name(err_status));
            esp_zb_scheduler_alarm((esp_zb_callback_t)bdb_start_top_level_commissioning_cb,
                                ESP_ZB_BDB_MODE_NETWORK_FORMATION, 1000);
        }
        break;

    case ESP_ZB_BDB_SIGNAL_STEERING:
        if (err_status == ESP_OK) {
            ESP_LOGI(TAG, "Network steering started");
        }
        break;

    case ESP_ZB_ZDO_SIGNAL_DEVICE_ANNCE:
        dev_annce_params = (esp_zb_zdo_signal_device_annce_params_t *)esp_zb_app_signal_get_params(p_sg_p);
        ESP_LOGI(TAG, "New device commissioned or rejoined (short: 0x%04hx)", dev_annce_params->device_short_addr);

        // Attempt to find a device that supports On/Off cluster (e.g. a light)
        {
            esp_zb_zdo_match_desc_req_param_t cmd_req;
            cmd_req.dst_nwk_addr = dev_annce_params->device_short_addr;
            cmd_req.addr_of_interest = dev_annce_params->device_short_addr;
            esp_zb_zdo_find_on_off_light(&cmd_req, user_find_cb, NULL);
        }
        break;

    case ESP_ZB_NWK_SIGNAL_PERMIT_JOIN_STATUS:
        if (err_status == ESP_OK) {
            uint8_t *permit_time = (uint8_t *)esp_zb_app_signal_get_params(p_sg_p);
            if (*permit_time) {
                ESP_LOGI(TAG, "Network(0x%04hx) is open for %d seconds", esp_zb_get_pan_id(), *permit_time);
            } else {
                ESP_LOGW(TAG, "Network(0x%04hx) closed, no longer permitting joins", esp_zb_get_pan_id());
            }
        }
        break;

    default:
        ESP_LOGI(TAG, "ZDO signal: %s (0x%x), status: %s",
                 esp_zb_zdo_signal_to_string(sig_type), sig_type, esp_err_to_name(err_status));
        break;
    }
}

// ────────────────────────────────────────────────────────────────────────────────
// 5) Main Zigbee Task
// ────────────────────────────────────────────────────────────────────────────────
static void esp_zb_task(void *pvParameters)
{
    // Initialize Zigbee stack as Coordinator
    esp_zb_cfg_t zb_nwk_cfg = ESP_ZB_ZC_CONFIG();
    esp_zb_init(&zb_nwk_cfg);
    light_driver_init(LIGHT_DEFAULT_OFF); // or LIGHT_DEFAULT_ON if you prefer


    // Register a default On/Off Switch endpoint (standard cluster roles) 
    esp_zb_on_off_switch_cfg_t switch_cfg = ESP_ZB_DEFAULT_ON_OFF_SWITCH_CONFIG();
    esp_zb_ep_list_t *esp_zb_on_off_switch_ep = esp_zb_on_off_switch_ep_create(HA_ONOFF_SWITCH_ENDPOINT, &switch_cfg);
    esp_zb_device_register(esp_zb_on_off_switch_ep);

    // Register APS data confirm callback (to see if our APS data got sent)
    esp_zb_aps_data_confirm_handler_register(zb_apsde_data_confirm_handler);
    // Register APS receiving callback
    esp_zb_aps_data_indication_handler_register(zb_apsde_data_indication_handler_switch);

    // Choose channel(s) and start
    esp_zb_set_primary_network_channel_set(ESP_ZB_PRIMARY_CHANNEL_MASK);
    ESP_ERROR_CHECK(esp_zb_start(false));

    // Main loop
    esp_zb_stack_main_loop();
}

// ────────────────────────────────────────────────────────────────────────────────
// 6) ESP-IDF Entry Point (app_main)
// ────────────────────────────────────────────────────────────────────────────────
void app_main(void)
{
    // Basic initialization
    esp_zb_platform_config_t config = {
        .radio_config = ESP_ZB_DEFAULT_RADIO_CONFIG(),
        .host_config  = ESP_ZB_DEFAULT_HOST_CONFIG(),
    };
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_zb_platform_config(&config));

    // Initialize button(s) and pass our button handler
    switch_driver_init(button_func_pair, PAIR_SIZE(button_func_pair), esp_zb_buttons_handler);

    // Start Zigbee in a FreeRTOS task
    xTaskCreate(esp_zb_task, "Zigbee_main", 16384, NULL, 5, NULL);
}
