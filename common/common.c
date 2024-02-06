#include "common.h"

R_O_ALL = 0444;

bool isIpAddr(char* buf) {
    int num_dots = 0;
    int num_octets = 0;
    int octet_value = 0;

    for(int i = 0; buf[i] != '\0'; i++) 
    {
        if (!isdigit(buf[i]) && buf[i] != '.') 
        {
            return false;
        }
        if (buf[i] == '.') 
        {
            num_dots++;
            // Check if the dot is not at the start or end, and if the previous character is not a dot
            if (i == 0 || i == strlen(buf) - 1 || buf[i - 1] == '.') 
                return false;

            // Check if the octet is within the valid range (0-255)
            if (octet_value < 0 || octet_value > 255) 
                return false;

            octet_value = 0; // Reset the octet value for the next octet
            num_octets++;
        } 
        else octet_value = octet_value * 10 + (buf[i] - '0');

    }

    // Check if there are exactly three dots, making four octets in total
    if (num_dots != 3 || num_octets != 3) 
        return false;

    // Check the last octet after the loop ends
    if (octet_value < 0 || octet_value > 255) 
        return false;

    return true;
}
