# components/libsodium/CMakeLists.txt

# Set the base directory for libsodium sources.
set(LIBSODIUM_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium")

# Initialize the list of sources.
set(LIBSODIUM_SOURCES "")

# The srcFilter starts with "-<*>" (exclude everything) and then adds:
#
# +<crypto_generichash/blake2b> → include all files in that directory.
file(GLOB_RECURSE TEMP_FILES "${LIBSODIUM_BASE_DIR}/crypto_generichash/blake2b/*.c")
list(APPEND LIBSODIUM_SOURCES ${TEMP_FILES})

# +<crypto_stream/salsa20>
file(GLOB_RECURSE TEMP_FILES "${LIBSODIUM_BASE_DIR}/crypto_stream/salsa20/*.c")
list(APPEND LIBSODIUM_SOURCES ${TEMP_FILES})

# +<crypto_core/salsa>
file(GLOB_RECURSE TEMP_FILES "${LIBSODIUM_BASE_DIR}/crypto_core/salsa/*.c")
list(APPEND LIBSODIUM_SOURCES ${TEMP_FILES})

# +<randombytes>
file(GLOB_RECURSE TEMP_FILES "${LIBSODIUM_BASE_DIR}/randombytes/*.c")
list(APPEND LIBSODIUM_SOURCES ${TEMP_FILES})

# +<crypto_pwhash/argon2>
file(GLOB_RECURSE TEMP_FILES "${LIBSODIUM_BASE_DIR}/crypto_pwhash/argon2/*.c")
list(APPEND LIBSODIUM_SOURCES ${TEMP_FILES})

# +<crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c")

# +<crypto_core/ed25519/core_ed25519.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_core/ed25519/core_ed25519.c")

# +<crypto_core/ed25519/core_ristretto255.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_core/ed25519/core_ristretto255.c")

# +<crypto_core/ed25519/ref10/ed25519_ref10.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_core/ed25519/ref10/ed25519_ref10.c")

# +<crypto_hash/crypto_hash.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_hash/crypto_hash.c")

# +<crypto_sign/ed25519/sign_ed25519.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_sign/ed25519/sign_ed25519.c")

# +<crypto_sign/ed25519/ref10/keypair.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_sign/ed25519/ref10/keypair.c")

# +<crypto_sign/ed25519/ref10/open.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_sign/ed25519/ref10/open.c")

# +<crypto_sign/ed25519/ref10/sign.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_sign/ed25519/ref10/sign.c")

# +<crypto_sign/ed25519/ref10/obsolete.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_sign/ed25519/ref10/obsolete.c")

# +<crypto_sign/crypto_sign.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_sign/crypto_sign.c")

# +<crypto_hash/sha256/cp/hash_sha256_cp.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_hash/sha256/cp/hash_sha256_cp.c")

# +<crypto_hash/sha256/hash_sha256.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_hash/sha256/hash_sha256.c")

# +<crypto_hash/sha512/cp/hash_sha512_cp.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_hash/sha512/cp/hash_sha512_cp.c")

# +<crypto_hash/sha512/hash_sha512.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_hash/sha512/hash_sha512.c")

# +<crypto_onetimeauth/crypto_onetimeauth.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_onetimeauth/crypto_onetimeauth.c")

# +<crypto_onetimeauth/poly1305/donna/poly1305_donna.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_onetimeauth/poly1305/donna/poly1305_donna.c")

# +<crypto_onetimeauth/poly1305/onetimeauth_poly1305.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c")

# +<crypto_scalarmult/crypto_scalarmult.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_scalarmult/crypto_scalarmult.c")

# +<crypto_scalarmult/curve25519/ref10/x25519_ref10.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_scalarmult/curve25519/ref10/x25519_ref10.c")

# +<crypto_scalarmult/curve25519/scalarmult_curve25519.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_scalarmult/curve25519/scalarmult_curve25519.c")

# +<crypto_stream/chacha20/ref/chacha20_ref.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_stream/chacha20/ref/chacha20_ref.c")

# +<crypto_stream/chacha20/stream_chacha20.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_stream/chacha20/stream_chacha20.c")

# +<crypto_stream/crypto_stream.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_stream/crypto_stream.c")

# +<crypto_verify/sodium/verify.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/crypto_verify/sodium/verify.c")

# +<sodium/codecs.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/sodium/codecs.c")

# +<sodium/core.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/sodium/core.c")

# +<sodium/runtime.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/sodium/runtime.c")

# +<sodium/utils.c>
list(APPEND LIBSODIUM_SOURCES "${LIBSODIUM_BASE_DIR}/sodium/utils.c")

# +<../../port/version.c>
# Note: The relative path is relative to the current component directory.
set(VERSION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/port/version.c")
list(APPEND LIBSODIUM_SOURCES ${VERSION_FILE})


idf_component_register(
    SRCS ${LIBSODIUM_SOURCES}
    INCLUDE_DIRS "${CMAKE_CURRENT_SOURCE_DIR}/port_include" "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include" "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include/sodium" "${CMAKE_CURRENT_SOURCE_DIR}/libsodium/src/libsodium/include/sodium/private"
)