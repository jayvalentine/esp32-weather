#include "log.h"

#include <stdio.h>

void log(char * msg)
{
    printf("[esp32-weather] %s\n", msg);
}
