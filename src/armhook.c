/*
 gamepwnage -- Cross Platform Game Hacking API(s)
 Copyright (c) 2024-2025 bitware. All rights reserved.

 "gamepwnage" is released under the New BSD license (see LICENSE.txt).
 Go to the project home page for more info:
 https://github.com/bitwaree/gamepwnage
*/

#ifdef GPWN_USING_BUILD_CONFIG
#include "config.h"
#else
#ifndef GPWNAPI
#define GPWNAPI
#endif
#ifndef GPWN_BKND
#define GPWN_BKND
#endif
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <limits.h>

#include "mem.h"
#include "armhook.h"

#if defined(__aarch64__)
GPWNAPI uintptr_t arm64_detour(uintptr_t address, uintptr_t branch_address,
    size_t length)
{
    /* ADR x17, literal; LDR x17, [x17]; BR x17; .quad branch_address */
    const uint32_t stub[3] = { 0x10000071u, 0xf9400231u, 0xd61f0220u };
    const uint32_t nop = 0xd503201fu;
    uint8_t patch[64];

    if ((address & 3u) != 0 || length < 20 || (length & 3u) != 0 ||
        length > sizeof(patch) || address > UINTPTR_MAX - length)
        return 0;

    memcpy(patch, stub, sizeof(stub));
    memcpy(patch + sizeof(stub), &branch_address, sizeof(branch_address));
    for (size_t offset = 20; offset < length; offset += sizeof(nop))
        memcpy(patch + offset, &nop, sizeof(nop));

    return write_mem((void *)address, patch, length) ? address + length : 0;
}
#elif defined(__arm__)
GPWNAPI uintptr_t arm32_detour(uintptr_t address, uintptr_t branch_address,
    size_t length)
{
    /* LDR ip, [pc]; BX ip; .word branch_address (ARM state only). */
    const uint32_t stub[2] = { 0xe59fc000u, 0xe12fff1cu };
    const uint32_t nop = 0xe1a00000u;
    uint8_t patch[64];
    uint32_t literal = (uint32_t)branch_address;

    if ((address & 3u) != 0 || length < 12 || (length & 3u) != 0 ||
        length > sizeof(patch) || address > UINTPTR_MAX - length ||
        branch_address > UINT32_MAX)
        return 0;

    memcpy(patch, stub, sizeof(stub));
    memcpy(patch + sizeof(stub), &literal, sizeof(literal));
    for (size_t offset = 12; offset < length; offset += sizeof(nop))
        memcpy(patch + offset, &nop, sizeof(nop));

    return write_mem((void *)address, patch, length) ? address + length : 0;
}
#endif
