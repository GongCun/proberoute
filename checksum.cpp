#include "ProbeRoute.hpp"

inline uint16_t CKSUM_CARRY(uint32_t x) {
    return (x = (x >> 16) + (x & 0xffff), ~(x + (x >> 16)) & 0xffff);
}

inline uint32_t in_checksum(uint16_t *addr, int len)
{
    uint32_t sum = 0;

    while (len > 1) {
        sum += *addr++;
        len -= 2;
    }

    if (len == 1)
        sum += *(uint16_t *)addr;

    return sum;
}

inline uint16_t checksum(uint16_t *addr, int len)
{
    return CKSUM_CARRY(in_checksum(addr, len));
}

