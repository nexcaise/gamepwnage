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
#include <stdlib.h>
#include <string.h>
#include <limits.h>

#include "mem.h"
#include "hook86.h"

GPWNAPI uintptr_t hook_x86(void *address, void *hook_function, size_t length)
{
    uintptr_t patch_address = (uintptr_t)address;
    uintptr_t target_address = (uintptr_t)hook_function;
    uintptr_t next_instruction;
    int64_t displacement;
    int32_t relative;
    uint8_t *patch;
    bool success;

    if (!address || !hook_function || length < 5 ||
        patch_address > UINTPTR_MAX - 5)
        return 0;

    next_instruction = patch_address + 5;
    displacement = (int64_t)target_address - (int64_t)next_instruction;
    if (displacement < INT32_MIN || displacement > INT32_MAX)
        return 0;

    patch = (uint8_t *)malloc(length);
    if (!patch)
        return 0;

    memset(patch, 0x90, length);
    patch[0] = 0xE9;
    relative = (int32_t)displacement;
    memcpy(patch + 1, &relative, sizeof(relative));

    success = write_mem(address, patch, length);
    free(patch);
    return success ? patch_address + length : 0;
}
