idf_component_register(SRCS "main.c"
                    INCLUDE_DIRS "include")

add_compile_definitions(SECRET_WIFI_SSID="$ENV{SECRET_WIFI_SSID}" SECRET_WIFI_PASS="$ENV{SECRET_WIFI_PASS}")

target_compile_options(${COMPONENT_LIB} PRIVATE "-Wno-format")
