file(GLOB_RECURSE NOISE_SOURCES "src/**/*.c")
set(COMPONENT_COMPILE_DEFINITIONS "NOISE_USE_LIBSODIUM")
idf_component_register(SRCS ${NOISE_SOURCES}
                      INCLUDE_DIRS "include" "src" "src/protocol"
                      REQUIRES libsodium 
                      )  

