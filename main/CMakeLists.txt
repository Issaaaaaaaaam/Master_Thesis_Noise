idf_component_register(
    SRC_DIRS  "."
                "${IDF_PATH}/examples/zigbee/common/zcl_utility/src"
    INCLUDE_DIRS "."
                "${IDF_PATH}/examples/zigbee/common/zcl_utility/include"
)
set(EXTRA_COMPONENT_DIRS components/noise-c )
