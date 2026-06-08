idf_component_register(
    SRCS "sniffer.c"
    INCLUDE_DIRS "."
    REQUIRES ieee802154 nvs_flash
)
