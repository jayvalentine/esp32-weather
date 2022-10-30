#ifndef _WIFI_H
#define _WIFI_H

typedef enum
{
    CONNECTED,
    FAILED_TO_CONNECT
} wifi_connect_status_t;

wifi_connect_status_t wifi_connect(const char * ssid, const char * password);

#endif /* _WIFI_H */
