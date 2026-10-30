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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

#include "mem.h"
#include "proc.h"

#ifndef MAP_FIXED_NOREPLACE
/* Linux ABI value. Kernels which do not implement it reject the flag or
 * treat the address as a normal mmap hint; both cases are handled below. */
#define MAP_FIXED_NOREPLACE 0x100000
#endif

typedef struct {
    uintptr_t start;
    size_t length;
    int old_protection;
} protection_change;

static size_t get_page_size(void)
{
    long value = sysconf(_SC_PAGESIZE);
    return value > 0 ? (size_t)value : 0;
}

static bool page_range(const void *address, size_t length,
    uintptr_t *start_out, size_t *length_out)
{
    size_t page_size = get_page_size();
    uintptr_t start = (uintptr_t)address;
    uintptr_t end;

    if (!page_size || (page_size & (page_size - 1)) != 0 || !length)
        return false;
    if (length > UINTPTR_MAX - start)
        return false;

    end = start + length;
    if (end > UINTPTR_MAX - (page_size - 1))
        return false;

    *start_out = start & ~((uintptr_t)page_size - 1);
    end = (end + page_size - 1) & ~((uintptr_t)page_size - 1);
    if (end < *start_out || end - *start_out > SIZE_MAX)
        return false;

    *length_out = (size_t)(end - *start_out);
    return *length_out != 0;
}

/* Change protections per mapping, rather than assuming that an arbitrary
 * range has the same permissions as its first page. Every changed segment is
 * rolled back if a later mprotect() fails. */
static bool change_range_protection(uintptr_t start, size_t length,
    int add_protection, protection_change **changes_out,
    size_t *change_count_out)
{
    unsigned int map_count;
    proc_map *maps = NULL;
    protection_change *changes = NULL;
    uintptr_t end;
    uintptr_t cursor;
    size_t count = 0;

    if (!length || length > UINTPTR_MAX - start)
        return false;
    end = start + length;

    map_count = get_proc_map_count(NULL);
    if (!map_count)
        return false;

    maps = (proc_map *)calloc(map_count, sizeof(*maps));
    changes = (protection_change *)calloc(map_count, sizeof(*changes));
    if (!maps || !changes)
        goto fail;

    map_count = get_proc_map(NULL, maps, map_count);
    cursor = start;

    for (unsigned int i = 0; i < map_count && cursor < end; ++i) {
        uintptr_t segment_start;
        uintptr_t segment_end;
        int new_protection;

        if (maps[i].end <= cursor)
            continue;
        if (maps[i].start > cursor)
            goto rollback; /* The requested range contains an unmapped gap. */

        segment_start = cursor > maps[i].start ? cursor : maps[i].start;
        segment_end = end < maps[i].end ? end : maps[i].end;
        if (segment_end <= segment_start)
            continue;

        new_protection = maps[i].prot | add_protection;
        changes[count].start = segment_start;
        changes[count].length = (size_t)(segment_end - segment_start);
        changes[count].old_protection = maps[i].prot;

        if (new_protection != maps[i].prot &&
            mprotect((void *)segment_start, changes[count].length,
                new_protection) == -1) {
            goto rollback;
        }

        ++count;
        cursor = segment_end;
    }

    if (cursor != end)
        goto rollback;

    free(maps);
    *changes_out = changes;
    *change_count_out = count;
    return true;

rollback:
    while (count > 0) {
        protection_change *change = &changes[--count];
        (void)mprotect((void *)change->start, change->length,
            change->old_protection);
    }
fail:
    free(changes);
    free(maps);
    return false;
}

static bool restore_range_protection(protection_change *changes, size_t count)
{
    bool success = true;
    while (count > 0) {
        protection_change *change = &changes[--count];
        if (mprotect((void *)change->start, change->length,
                change->old_protection) == -1) {
            success = false;
        }
    }
    free(changes);
    return success;
}

GPWNAPI bool write_mem(void *dest, void *src, size_t len)
{
    uintptr_t aligned_start;
    size_t aligned_length;
    protection_change *changes = NULL;
    size_t change_count = 0;
    bool restored;

    if (!len)
        return true;
    if (!dest || !src || !page_range(dest, len, &aligned_start,
            &aligned_length))
        return false;

    if (!change_range_protection(aligned_start, aligned_length,
            PROT_READ | PROT_WRITE, &changes, &change_count)) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "write_mem() failed to make %p writable.\n", dest);
#endif
        return false;
    }

    memmove(dest, src, len);
#if defined(__GNUC__) || defined(__clang__)
    /* Required on architectures where data and instruction caches are not
     * automatically coherent (notably ARM/ARM64). */
    __builtin___clear_cache((char *)dest, (char *)dest + len);
#endif

    restored = restore_range_protection(changes, change_count);
#ifdef GPWN_DEBUG
    if (!restored)
        fprintf(stderr, "write_mem() could not fully restore protection at %p.\n", dest);
#endif
    return restored;
}

GPWNAPI bool read_mem(void *dest, void *src, size_t len)
{
    uintptr_t aligned_start;
    size_t aligned_length;
    protection_change *changes = NULL;
    size_t change_count = 0;
    bool restored;

    if (!len)
        return true;
    if (!dest || !src || !page_range(src, len, &aligned_start,
            &aligned_length))
        return false;

    if (!change_range_protection(aligned_start, aligned_length,
            PROT_READ, &changes, &change_count)) {
#ifdef GPWN_DEBUG
        fprintf(stderr, "read_mem() failed to make %p readable.\n", src);
#endif
        return false;
    }

    memmove(dest, src, len);
    restored = restore_range_protection(changes, change_count);
#ifdef GPWN_DEBUG
    if (!restored)
        fprintf(stderr, "read_mem() could not fully restore protection at %p.\n", src);
#endif
    return restored;
}

GPWNAPI uintptr_t get_addr(uintptr_t Baseaddr, uintptr_t offsets[], int TotalOffset)
{
    uintptr_t address = Baseaddr;

    if (!address || TotalOffset < 0 || (TotalOffset > 0 && !offsets))
        return 0;

    for (int i = 0; i < TotalOffset; ++i) {
        if (address > UINTPTR_MAX - sizeof(uintptr_t))
            return 0;
        address = *(const uintptr_t *)address;
        if (!address || offsets[i] > UINTPTR_MAX - address)
            return 0;
        address += offsets[i];
    }

    return address;
}

GPWNAPI void *mmap_near(void *hint, size_t size, int prot)
{
    size_t page_size = get_page_size();
    uintptr_t hint_address = (uintptr_t)hint;
    uintptr_t aligned_address;
    size_t aligned_size;
    uintptr_t candidate;
    void *mapped;

    if (!page_size || !hint || !size ||
        size > SIZE_MAX - (page_size - 1))
        return MAP_FAILED;

    aligned_address = hint_address & ~((uintptr_t)page_size - 1);
    aligned_size = (size + page_size - 1) & ~(page_size - 1);

    candidate = (uintptr_t)find_unmapped((void *)aligned_address, aligned_size);
    if (!candidate || (candidate & (page_size - 1)) != 0)
        return MAP_FAILED;

    /* Never use MAP_FIXED here: another thread could claim the gap after
     * find_unmapped() and MAP_FIXED would silently destroy that mapping. */
    mapped = mmap((void *)candidate, aligned_size, prot,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (mapped != MAP_FAILED) {
        if ((uintptr_t)mapped == candidate)
            return mapped;
        /* Older kernels may ignore an unknown flag and treat the address as
         * a hint. Do not keep a mapping at an unexpected address. */
        munmap(mapped, aligned_size);
    }

    if (errno == EINVAL) {
        mapped = mmap((void *)candidate, aligned_size, prot,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (mapped == MAP_FAILED)
            return MAP_FAILED;
        if ((uintptr_t)mapped != candidate) {
            munmap(mapped, aligned_size);
            errno = EEXIST;
            return MAP_FAILED;
        }
        return mapped;
    }

    return MAP_FAILED;
}
