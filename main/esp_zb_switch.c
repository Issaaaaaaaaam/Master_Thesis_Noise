#include <stdio.h>
#include <string.h>
#include "noise/protocol.h"

#define HANDSHAKE_PATTERN "Noise_NN_25519_ChaChaPoly_SHA256"
#define MESSAGE_BUFFER_SIZE 128

// Function to translate Noise error codes into readable messages
void explain_error(int result) {
    switch (result) {
        case NOISE_ERROR_NONE:
            printf("✅ No error.\n");
            break;
        case NOISE_ERROR_INVALID_PARAM:
            printf("❌ Error: Invalid parameter passed to function.\n");
            break;
        case NOISE_ERROR_UNKNOWN_NAME:
            printf("❌ Error: Unknown algorithm name.\n");
            break;
        case NOISE_ERROR_NO_MEMORY:
            printf("❌ Error: Memory allocation failed.\n");
            break;
        case NOISE_ERROR_MAC_FAILURE:
            printf("❌ Error: MAC verification failed (decryption issue).\n");
            break;
        case NOISE_ERROR_INVALID_LENGTH:
            printf("❌ Error: Invalid buffer size.\n");
            break;
        case NOISE_ERROR_INVALID_STATE:
            printf("❌ Error: Function called in an invalid state.\n");
            break;
        case NOISE_ERROR_INVALID_NONCE:
            printf("❌ Error: Nonce has overflowed (too many messages sent).\n");
            break;
        default:
            printf("❌ Error: Unknown error code (%d).\n", result);
    }
}

// Function to check results and print explanations
void check_result(int result, const char *msg) {
    if (result != NOISE_ERROR_NONE) {
        printf("%s failed! ", msg);
        explain_error(result);
    } else {
        printf("%s succeeded ✅\n", msg);
    }
}

void app_main(void) {
    int result;
    NoiseHandshakeState *initiator = NULL;
    NoiseHandshakeState *responder = NULL;
    uint8_t message_data[MESSAGE_BUFFER_SIZE];
    NoiseBuffer message_buf;

    // ✅ Create Handshake States
    result = noise_handshakestate_new_by_name(&initiator, HANDSHAKE_PATTERN, NOISE_ROLE_INITIATOR);
    check_result(result, "Initiator HandshakeState creation");
    
    result = noise_handshakestate_new_by_name(&responder, HANDSHAKE_PATTERN, NOISE_ROLE_RESPONDER);
    check_result(result, "Responder HandshakeState creation");

    // ✅ Initiator writes first message
    noise_buffer_set_output(message_buf, message_data, MESSAGE_BUFFER_SIZE);
    result = noise_handshakestate_write_message(initiator, &message_buf, NULL);
    check_result(result, "Initiator writes first message");

    // ✅ Responder reads first message
    noise_buffer_set_input(message_buf, message_buf.data, message_buf.size);
    result = noise_handshakestate_read_message(responder, &message_buf, NULL);
    check_result(result, "Responder reads first message");

    // ✅ Responder writes second message
    noise_buffer_set_output(message_buf, message_data, MESSAGE_BUFFER_SIZE);
    result = noise_handshakestate_write_message(responder, &message_buf, NULL);
    check_result(result, "Responder writes second message");

    // ✅ Initiator reads second message
    noise_buffer_set_input(message_buf, message_buf.data, message_buf.size);
    result = noise_handshakestate_read_message(initiator, &message_buf, NULL);
    check_result(result, "Initiator reads second message");

    // ✅ Handshake Complete
    printf("\n🚀 HANDSHAKE SUCCESSFUL! 🎉\n");

    // Cleanup
    noise_handshakestate_free(initiator);
    noise_handshakestate_free(responder);
}
