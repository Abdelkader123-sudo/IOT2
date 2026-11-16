idf_component_register(SRCS "main.c"
                       INCLUDE_DIRS "."
                       PRIV_REQUIRES nvs_flash esp_netif esp_event esp_wifi
                                     driver lwip esp_system
                                     espressif__iot_bridge espressif__mdns)