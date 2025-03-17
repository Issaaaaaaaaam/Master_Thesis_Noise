#include "string.h"
#include <noise/protocol.h>
#include <sodium.h> 
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_zb_switch.h"
#include "ha/esp_zigbee_ha_standard.h"
#include "freertos/task.h"
#include "freertos/FreeRTOS.h"

#define HANDSHAKE_PATTERN "Noise_NN_25519_ChaChaPoly_SHA256"

static const char *TAG = "ESP32_NOISE_TEST";

static void handle_error(const char *msg, int err)
{
    char err_buf[256];
    noise_strerror(err, err_buf, sizeof(err_buf));
    fprintf(stderr, "%s failed! ❌ Error: %s\n", msg, err_buf);
    exit(EXIT_FAILURE);
}



void app_main()
{
    ESP_LOGI(TAG, "Starting ESP32 Noise Protocol Test...");
    sodium_init();
}
