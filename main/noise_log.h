#pragma once

// ─────────────────────────────────────────────────────────────
//  Enable or disable logging and benchmarking (1 = ON, 0 = OFF)
// ─────────────────────────────────────────────────────────────
#define ENABLE_NOISE_LOGGING     0
#define ENABLE_NOISE_BENCHMARK   0

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_system.h"

// ─────────────────────────────────────────────────────────────
//  Logging Macros
// ─────────────────────────────────────────────────────────────
#if ENABLE_NOISE_LOGGING
    #define NOISE_LOGI(tag, fmt, ...) ESP_LOGI(tag, fmt, ##__VA_ARGS__)
    #define NOISE_LOGW(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
    #define NOISE_LOGE(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
    #define NOISE_LOGD(tag, fmt, ...) ESP_LOGD(tag, fmt, ##__VA_ARGS__)
    #define NOISE_LOG_BUFFER_HEX(tag, buf, len) ESP_LOG_BUFFER_HEX(tag, buf, len)
    #define NOISE_LOG_BUFFER_HEX_LEVEL(tag, buf, len, level) ESP_LOG_BUFFER_HEX_LEVEL(tag, buf, len, level)
#else
    #define NOISE_LOGI(tag, fmt, ...)
    #define NOISE_LOGW(tag, fmt, ...) ESP_LOGW(tag, fmt, ##__VA_ARGS__)
    #define NOISE_LOGE(tag, fmt, ...) ESP_LOGE(tag, fmt, ##__VA_ARGS__)
    #define NOISE_LOGD(tag, fmt, ...)
    #define NOISE_LOG_BUFFER_HEX(tag, buf, len)
    #define NOISE_LOG_BUFFER_HEX_LEVEL(tag, buf, len, level)
#endif

// ─────────────────────────────────────────────────────────────
//  Benchmarking Macros
// ─────────────────────────────────────────────────────────────
#if ENABLE_NOISE_BENCHMARK

typedef struct {
    uint64_t start_us;
    uint32_t start_cycles;
} noise_benchmark_t;

static noise_benchmark_t __bench;

#define bench_start(label) do { \
    __bench.start_us = esp_timer_get_time(); \
    __bench.start_cycles = esp_cpu_get_cycle_count(); \
    ESP_LOGD("BENCH", "[%s] Benchmark started", label); \
} while(0)

#define bench_end(label) do { \
    uint64_t end_us = esp_timer_get_time(); \
    uint32_t end_cycles = esp_cpu_get_cycle_count(); \
    ESP_LOGW("BENCH", "[%s] Took %" PRIu64 " us and %" PRIu32 " cycles", \
                label, end_us - __bench.start_us, end_cycles - __bench.start_cycles); \
} while(0)

#else

#define bench_start(label)
#define bench_end(label)

#endif
