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
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "proc.h"

GPWNAPI unsigned int get_proc_map_count(const char *module)
{
    FILE *fd = fopen("/proc/self/maps", "r");
    char line[2048];
    unsigned int count = 0;

    if (!fd)
        return 0;

    while (fgets(line, sizeof(line), fd) != NULL) {
        if (!module || strstr(line, module) != NULL)
            ++count;
    }

    fclose(fd);
    return count;
}

GPWNAPI unsigned int get_proc_map(const char *module,
    proc_map *map_array, unsigned int max_map_count)
{
    FILE *fd;
    char line[2048];
    unsigned int count = 0;

    if (!map_array || !max_map_count)
        return 0;

    fd = fopen("/proc/self/maps", "r");
    if (!fd)
        return 0;

    while (count < max_map_count && fgets(line, sizeof(line), fd) != NULL) {
        uintptr_t start;
        uintptr_t end;
        char permissions[5] = {0};

        if (module && strstr(line, module) == NULL)
            continue;

        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %4s",
                &start, &end, permissions) != 3 || end <= start)
            continue;

        map_array[count].start = start;
        map_array[count].end = end;
        map_array[count].prot = 0;
        if (permissions[0] == 'r')
            map_array[count].prot |= PROT_READ;
        if (permissions[1] == 'w')
            map_array[count].prot |= PROT_WRITE;
        if (permissions[2] == 'x')
            map_array[count].prot |= PROT_EXEC;
        ++count;
    }

    fclose(fd);
    return count;
}

GPWNAPI void *get_module_addr(char *_module, char *_permissions)
{
    unsigned int map_count = get_proc_map_count(_module);
    proc_map *maps;
    uintptr_t address = 0;

    if (!map_count)
        return NULL;

    maps = (proc_map *)calloc(map_count, sizeof(*maps));
    if (!maps)
        return NULL;

    map_count = get_proc_map(_module, maps, map_count);
    if (!_permissions || strlen(_permissions) < 3) {
        if (map_count)
            address = maps[0].start;
    } else {
        int requested = 0;
        if (_permissions[0] == 'r') requested |= PROT_READ;
        if (_permissions[1] == 'w') requested |= PROT_WRITE;
        if (_permissions[2] == 'x') requested |= PROT_EXEC;

        for (unsigned int i = 0; i < map_count; ++i) {
            if (maps[i].prot == requested) {
                address = maps[i].start;
                break;
            }
        }
    }

    free(maps);
    return (void *)address;
}

GPWNAPI int get_prot(uintptr_t address)
{
    unsigned int map_count = get_proc_map_count(NULL);
    proc_map *maps;
    int protection = -1;

    if (!map_count)
        return -1;

    maps = (proc_map *)calloc(map_count, sizeof(*maps));
    if (!maps)
        return -1;

    map_count = get_proc_map(NULL, maps, map_count);
    for (unsigned int i = 0; i < map_count; ++i) {
        if (address >= maps[i].start && address < maps[i].end) {
            protection = maps[i].prot;
            break;
        }
    }

    free(maps);
    return protection;
}

GPWNAPI void *find_unmapped(void *target, size_t size)
{
    unsigned int map_count = get_proc_map_count(NULL);
    proc_map *maps;
    unsigned int actual_count;
    uintptr_t target_address = (uintptr_t)target;
    uintptr_t best = 0;
    uintptr_t best_distance = UINTPTR_MAX;
    long page_size_value = sysconf(_SC_PAGESIZE);
    uintptr_t page_mask;

    if (!target || !size || !map_count || page_size_value <= 0)
        return NULL;
    page_mask = (uintptr_t)page_size_value - 1;
    if (((uintptr_t)page_size_value & page_mask) != 0)
        return NULL;

    maps = (proc_map *)calloc(map_count, sizeof(*maps));
    if (!maps)
        return NULL;

    actual_count = get_proc_map(NULL, maps, map_count);
    if (actual_count < 2) {
        free(maps);
        return NULL;
    }

    /* Linux reports mappings in ascending address order. Consider every
     * inter-map gap and pick the candidate nearest to the requested address. */
    for (unsigned int i = 0; i + 1 < actual_count; ++i) {
        uintptr_t gap_start = maps[i].end;
        uintptr_t gap_end = maps[i + 1].start;
        uintptr_t candidate;
        uintptr_t distance;

        if (gap_end <= gap_start || gap_end - gap_start < size)
            continue;

        if (gap_end <= target_address) {
            candidate = gap_end - size;
        } else if (gap_start >= target_address) {
            candidate = gap_start;
        } else {
            /* The target lies inside this gap. Align it down to a page and
             * use it only if the complete requested range still fits. */
            candidate = target_address & ~page_mask;
        }

        if (candidate < gap_start || candidate > gap_end - size)
            candidate = gap_start;

        distance = candidate >= target_address
            ? candidate - target_address : target_address - candidate;
        if (distance < best_distance) {
            best_distance = distance;
            best = candidate;
        }
    }

    free(maps);
    return (void *)best;
}
