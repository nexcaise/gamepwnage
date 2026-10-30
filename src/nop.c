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

#include "mem.h"
#include "nop.h"

GPWNAPI bool patch_nop(void *address, size_t length)
{
#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__i686__) || defined(__x86__)
    static const uint8_t nop_bytes[] = { 0x90 };
#elif defined(__aarch64__)
    static const uint8_t nop_bytes[] = { 0x1f, 0x20, 0x03, 0xd5 };
#elif defined(__arm__)
    static const uint8_t nop_bytes[] = { 0x00, 0xf0, 0x20, 0xe3 };
#else
#error "Unsupported architecture."
#endif
    const size_t nop_length = sizeof(nop_bytes);
    uint8_t *patch;
    bool success;

    if (!length)
        return true;
    if (!address || length % nop_length != 0)
        return false;

    patch = (uint8_t *)malloc(length);
    if (!patch)
        return false;

    for (size_t offset = 0; offset < length; offset += nop_length)
        memcpy(patch + offset, nop_bytes, nop_length);

    success = write_mem(address, patch, length);
    free(patch);
    return success;
}
