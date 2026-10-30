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

#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "mem.h"
#include "nop.h"
#include "proc.h"
#include "inlinehook.h"

#if defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
#include "hook86.h"
#elif defined(__arm__) || defined(__aarch64__)
#include "armhook.h"
#endif

#define GPWN_MAX_ORIGINAL_BYTES 64
#define GPWN_TRAMPOLINE_CODE_CAPACITY 512

typedef struct {
    hook_handle public_handle;
    size_t allocation_size;
    uint8_t original_bytes[GPWN_MAX_ORIGINAL_BYTES];
} hook_handle_internal;

static hook_handle_internal *hook_internal(hook_handle *handle)
{
    return (hook_handle_internal *)handle;
}

static bool pointer_distance_in_range(uintptr_t from, uintptr_t to,
    int64_t minimum, int64_t maximum, int64_t *distance_out)
{
    int64_t distance;

    if (to >= from) {
        uintptr_t delta = to - from;
        if (delta > (uintptr_t)INT64_MAX)
            return false;
        distance = (int64_t)delta;
    } else {
        uintptr_t delta = from - to;
        if (delta > (uintptr_t)INT64_MAX)
            return false;
        distance = -(int64_t)delta;
    }

    if (distance < minimum || distance > maximum)
        return false;
    if (distance_out)
        *distance_out = distance;
    return true;
}

static bool add_signed_address(uintptr_t base, int64_t displacement,
    uintptr_t *result)
{
    if (displacement >= 0) {
        uintptr_t amount = (uintptr_t)displacement;
        if (amount > UINTPTR_MAX - base)
            return false;
        *result = base + amount;
    } else {
        uintptr_t amount = (uintptr_t)(-(displacement + 1)) + 1;
        if (amount > base)
            return false;
        *result = base - amount;
    }
    return true;
}

#if defined(__aarch64__)
#define AARCH64_LEGACY_HOOKBYTES_LEN 20u
#define AARCH64_MICRO_HOOKBYTES_LEN  12u
#define AARCH64_NANO_HOOKBYTES_LEN    4u

static int64_t sign_extend_u64(uint64_t value, unsigned int bit_count)
{
    const unsigned int shift = 64u - bit_count;
    return ((int64_t)(value << shift)) >> shift;
}

static bool encode_adrp(int64_t byte_offset, uint32_t *instruction)
{
    int64_t page_offset;
    uint64_t immediate;

    if (!instruction || (byte_offset & 0xfff) != 0)
        return false;

    page_offset = byte_offset / 4096;
    if (page_offset < -(INT64_C(1) << 20) ||
        page_offset > ((INT64_C(1) << 20) - 1))
        return false;

    immediate = (uint64_t)page_offset & 0x1fffff;
    *instruction = 0x90000011u |
        (uint32_t)((immediate & 0x3u) << 29) |
        (uint32_t)(((immediate >> 2) & 0x7ffffu) << 5);
    return true;
}

static bool encode_b_aarch64(int64_t byte_offset, uint32_t *instruction)
{
    int64_t immediate;

    if (!instruction || (byte_offset & 3) != 0 ||
        byte_offset < -(INT64_C(1) << 27) ||
        byte_offset > ((INT64_C(1) << 27) - 4))
        return false;

    immediate = byte_offset / 4;
    *instruction = 0x14000000u | ((uint32_t)immediate & 0x03ffffffu);
    return true;
}

static bool relocate_aarch64_block(const uint8_t *source,
    uintptr_t source_address, uint8_t *destination,
    uintptr_t destination_address, size_t byte_length)
{
    if (!source || !destination || (byte_length & 3u) != 0)
        return false;

    for (size_t offset = 0; offset < byte_length; offset += 4) {
        uint32_t instruction;
        uintptr_t pc = source_address + offset;
        uintptr_t relocated_pc = destination_address + offset;
        uintptr_t target = 0;
        bool is_relative = false;
        bool is_adr = false;
        bool is_adrp = false;
        unsigned int immediate_bits = 0;
        unsigned int immediate_shift = 0;
        unsigned int immediate_bit_position = 0;

        memcpy(&instruction, source + offset, sizeof(instruction));

        /* ADR / ADRP. */
        if ((instruction & 0x9f000000u) == 0x10000000u ||
            (instruction & 0x9f000000u) == 0x90000000u) {
            uint64_t imm21 = (((uint64_t)(instruction >> 5) & 0x7ffffu) << 2) |
                ((instruction >> 29) & 0x3u);
            int64_t signed_imm = sign_extend_u64(imm21, 21);
            is_adrp = (instruction & 0x80000000u) != 0;
            is_adr = !is_adrp;

            if (is_adrp) {
                uintptr_t page = pc & ~(uintptr_t)0xfff;
                if (!add_signed_address(page, signed_imm * 4096, &target))
                    return false;
            } else if (!add_signed_address(pc, signed_imm, &target)) {
                return false;
            }

            is_relative = true;
            immediate_bits = 21;
        }
        /* B / BL. */
        else if ((instruction & 0x7c000000u) == 0x14000000u) {
            int64_t displacement = sign_extend_u64(instruction & 0x03ffffffu, 26) * 4;
            if (!add_signed_address(pc, displacement, &target))
                return false;
            is_relative = true;
            immediate_bits = 26;
            immediate_shift = 2;
            immediate_bit_position = 0;
        }
        /* B.cond. */
        else if ((instruction & 0xff000010u) == 0x54000000u) {
            int64_t displacement = sign_extend_u64((instruction >> 5) & 0x7ffffu, 19) * 4;
            if (!add_signed_address(pc, displacement, &target))
                return false;
            is_relative = true;
            immediate_bits = 19;
            immediate_shift = 2;
            immediate_bit_position = 5;
        }
        /* CBZ / CBNZ. */
        else if ((instruction & 0x7e000000u) == 0x34000000u) {
            int64_t displacement = sign_extend_u64((instruction >> 5) & 0x7ffffu, 19) * 4;
            if (!add_signed_address(pc, displacement, &target))
                return false;
            is_relative = true;
            immediate_bits = 19;
            immediate_shift = 2;
            immediate_bit_position = 5;
        }
        /* TBZ / TBNZ. */
        else if ((instruction & 0x7e000000u) == 0x36000000u) {
            int64_t displacement = sign_extend_u64((instruction >> 5) & 0x3fffu, 14) * 4;
            if (!add_signed_address(pc, displacement, &target))
                return false;
            is_relative = true;
            immediate_bits = 14;
            immediate_shift = 2;
            immediate_bit_position = 5;
        }
        /* LDR/LDRAA-family literal, LDRSW literal and PRFM literal. */
        else if ((instruction & 0x3b000000u) == 0x18000000u) {
            int64_t displacement = sign_extend_u64((instruction >> 5) & 0x7ffffu, 19) * 4;
            if (!add_signed_address(pc, displacement, &target))
                return false;
            is_relative = true;
            immediate_bits = 19;
            immediate_shift = 2;
            immediate_bit_position = 5;
        }

        if (is_relative) {
            /* Branches/literal references into the overwritten block must
             * continue to refer to the corresponding relocated instruction. */
            if (target >= source_address &&
                target < source_address + byte_length) {
                uintptr_t inside_offset = target - source_address;
                if ((inside_offset & 3u) != 0)
                    return false;
                target = destination_address + inside_offset;
            }

            if (is_adrp) {
                int64_t page_delta;
                uintptr_t source_page = relocated_pc & ~(uintptr_t)0xfff;
                uintptr_t target_page = target & ~(uintptr_t)0xfff;
                if (!pointer_distance_in_range(source_page, target_page,
                        -(INT64_C(1) << 32), (INT64_C(1) << 32) - 4096,
                        &page_delta))
                    return false;
                if (!encode_adrp(page_delta, &instruction))
                    return false;
            } else if (is_adr) {
                int64_t delta;
                uint64_t immediate;
                if (!pointer_distance_in_range(relocated_pc, target,
                        -(INT64_C(1) << 20), (INT64_C(1) << 20) - 1,
                        &delta))
                    return false;
                immediate = (uint64_t)delta & 0x1fffff;
                instruction &= ~((3u << 29) | (0x7ffffu << 5));
                instruction |= (uint32_t)((immediate & 3u) << 29);
                instruction |= (uint32_t)(((immediate >> 2) & 0x7ffffu) << 5);
            } else {
                int64_t delta;
                int64_t scaled;
                uint64_t mask = (UINT64_C(1) << immediate_bits) - 1;

                if (!pointer_distance_in_range(relocated_pc, target,
                        -(INT64_C(1) << (immediate_bits + immediate_shift - 1)),
                        (INT64_C(1) << (immediate_bits + immediate_shift - 1)) -
                            (INT64_C(1) << immediate_shift), &delta))
                    return false;
                if ((delta & ((INT64_C(1) << immediate_shift) - 1)) != 0)
                    return false;
                scaled = delta / (INT64_C(1) << immediate_shift);
                instruction &= ~((uint32_t)mask << immediate_bit_position);
                instruction |= ((uint32_t)scaled & (uint32_t)mask)
                    << immediate_bit_position;
            }
        }

        memcpy(destination + offset, &instruction, sizeof(instruction));
    }

    return true;
}

#elif defined(__arm__)
#define ARM_LEGACY_HOOKBYTES_LEN 12u
#define ARM_NANO_HOOKBYTES_LEN    4u

static int32_t sign_extend_24(uint32_t value)
{
    value &= 0x00ffffffu;
    if (value & 0x00800000u)
        value |= 0xff000000u;
    return (int32_t)value;
}

static bool relocate_arm32_block(const uint8_t *source,
    uintptr_t source_address, uint8_t *destination,
    uintptr_t destination_address, size_t byte_length)
{
    if (!source || !destination || (byte_length & 3u) != 0)
        return false;

    for (size_t offset = 0; offset < byte_length; offset += 4) {
        uint32_t instruction;
        memcpy(&instruction, source + offset, sizeof(instruction));

        /* ARM-state B/BL is PC-relative (PC is instruction address + 8). */
        if ((instruction & 0x0e000000u) == 0x0a000000u) {
            uintptr_t old_pc = source_address + offset + 8;
            uintptr_t new_pc = destination_address + offset + 8;
            int64_t old_delta = (int64_t)sign_extend_24(instruction) * 4;
            uintptr_t target;
            int64_t new_delta;

            if (!add_signed_address(old_pc, old_delta, &target))
                return false;
            if (target >= source_address && target < source_address + byte_length)
                target = destination_address + (target - source_address);
            if (!pointer_distance_in_range(new_pc, target,
                    -(INT64_C(1) << 25), (INT64_C(1) << 25) - 4,
                    &new_delta) || (new_delta & 3) != 0)
                return false;

            instruction = (instruction & 0xff000000u) |
                ((uint32_t)(new_delta / 4) & 0x00ffffffu);
        }
        /* LDR/STR with Rn == PC and ADR-style data-processing instructions
         * are also PC-relative. Refuse them instead of copying broken bytes. */
        else if (((instruction & 0x0c000000u) == 0x04000000u &&
                    ((instruction >> 16) & 0xfu) == 0xfu) ||
                 ((instruction & 0x0c000000u) == 0 &&
                    ((instruction >> 16) & 0xfu) == 0xfu &&
                    (instruction & 0x02000000u))) {
            return false;
        }

        memcpy(destination + offset, &instruction, sizeof(instruction));
    }

    return true;
}

#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
#define X86_MAX_INSTRUCTION_LENGTH 15u
#define X86_MAX_INSTRUCTIONS 64u
#define X86_MAX_STOLEN_BYTES GPWN_MAX_ORIGINAL_BYTES

#if defined(__x86_64__) || defined(__amd64__)
#define GPWN_X86_64 1
#else
#define GPWN_X86_64 0
#endif

typedef struct {
    size_t length;
    size_t opcode_offset;
    size_t relative_offset;
    size_t relative_size;
    size_t rip_displacement_offset;
    uint8_t opcode;
    uint8_t opcode_map;
    bool has_relative;
    bool is_loop_relative;
    bool has_rip_relative;
} x86_instruction;

typedef struct {
    size_t original_offset;
    size_t relocated_offset;
    size_t original_length;
    size_t relocated_length;
    x86_instruction decoded;
} x86_instruction_plan;

static bool x86_one_byte_has_modrm(uint8_t opcode)
{
    return (opcode <= 0x03) || (opcode >= 0x08 && opcode <= 0x0b) ||
        (opcode >= 0x10 && opcode <= 0x13) || (opcode >= 0x18 && opcode <= 0x1b) ||
        (opcode >= 0x20 && opcode <= 0x23) || (opcode >= 0x28 && opcode <= 0x2b) ||
        (opcode >= 0x30 && opcode <= 0x33) || (opcode >= 0x38 && opcode <= 0x3b) ||
        opcode == 0x62 || opcode == 0x63 || opcode == 0x69 || opcode == 0x6b ||
        (opcode >= 0x80 && opcode <= 0x8f) || opcode == 0xc0 || opcode == 0xc1 ||
        (opcode >= 0xc4 && opcode <= 0xc7) ||
        (opcode >= 0xd0 && opcode <= 0xd3) ||
        (opcode >= 0xd8 && opcode <= 0xdf) || opcode == 0xf6 || opcode == 0xf7 ||
        opcode == 0xfe || opcode == 0xff;
}

static bool x86_two_byte_has_modrm(uint8_t opcode, bool vector_encoding)
{
    if (vector_encoding)
        return opcode != 0x77; /* VZEROUPPER/VZEROALL */

    if (opcode == 0x05 || opcode == 0x06 || opcode == 0x07 ||
        opcode == 0x08 || opcode == 0x09 || opcode == 0x0b ||
        opcode == 0x0e || (opcode >= 0x30 && opcode <= 0x37) ||
        opcode == 0x77 || (opcode >= 0x80 && opcode <= 0x8f) ||
        opcode == 0xa0 || opcode == 0xa1 || opcode == 0xa2 ||
        opcode == 0xa8 || opcode == 0xa9 || opcode == 0xaa ||
        (opcode >= 0xc8 && opcode <= 0xcf))
        return false;
    return true;
}

static int64_t x86_read_signed(const uint8_t *bytes, size_t size)
{
    if (size == 1) {
        int8_t value;
        memcpy(&value, bytes, sizeof(value));
        return value;
    }
    if (size == 2) {
        int16_t value;
        memcpy(&value, bytes, sizeof(value));
        return value;
    }
    if (size == 4) {
        int32_t value;
        memcpy(&value, bytes, sizeof(value));
        return value;
    }
    return 0;
}

static bool x86_decode_instruction(const uint8_t *code, size_t available,
    bool is_64bit, x86_instruction *decoded)
{
    size_t offset = 0;
    size_t immediate_size = 0;
    size_t displacement_offset = 0;
    uint8_t opcode;
    uint8_t opcode_map = 0;
    uint8_t modrm = 0;
    uint8_t mod = 0;
    uint8_t reg = 0;
    uint8_t rm = 0;
    bool operand16 = false;
    bool address_override = false;
    bool f2_prefix = false;
    bool rex_w = false;
    bool has_modrm = false;
    bool vector_encoding = false;
    bool evex_encoding = false;
    bool xop_encoding = false;
    bool rip_relative = false;
    bool loop_relative = false;
    size_t relative_size = 0;
    size_t relative_offset = 0;
    size_t opcode_offset;

    if (!code || !decoded || !available)
        return false;
    if (available > X86_MAX_INSTRUCTION_LENGTH)
        available = X86_MAX_INSTRUCTION_LENGTH;

    memset(decoded, 0, sizeof(*decoded));

    /* Legacy prefixes and REX. */
    while (offset < available && offset < X86_MAX_INSTRUCTION_LENGTH) {
        uint8_t value = code[offset];
        if (value == 0x66) {
            rex_w = false;
            operand16 = true;
            ++offset;
        } else if (value == 0x67) {
            rex_w = false;
            address_override = true;
            ++offset;
        } else if (value == 0xf0 || value == 0xf2 || value == 0xf3 ||
                   value == 0x2e || value == 0x36 || value == 0x3e ||
                   value == 0x26 || value == 0x64 || value == 0x65) {
            rex_w = false;
            if (value == 0xf2)
                f2_prefix = true;
            ++offset;
        } else if (is_64bit && value >= 0x40 && value <= 0x4f) {
            rex_w = (value & 0x08u) != 0;
            ++offset;
        } else {
            break;
        }
    }

    if (offset >= available || offset >= X86_MAX_INSTRUCTION_LENGTH)
        return false;

    /* VEX2, VEX3, EVEX and XOP prefixes. */
    if ((code[offset] == 0xc5 && (is_64bit ||
            (offset + 1 < available && (code[offset + 1] & 0xc0u) == 0xc0u)))) {
        if (offset + 2 >= available)
            return false;
        vector_encoding = true;
        opcode_map = 1;
        offset += 2;
    } else if (code[offset] == 0xc4 && (is_64bit ||
            (offset + 2 < available && (code[offset + 1] & 0xc0u) == 0xc0u))) {
        if (offset + 3 >= available)
            return false;
        vector_encoding = true;
        opcode_map = code[offset + 1] & 0x1fu;
        if (opcode_map < 1 || opcode_map > 3)
            return false;
        offset += 3;
    } else if (code[offset] == 0x62 && (is_64bit ||
            (offset + 3 < available && (code[offset + 1] & 0xc0u) == 0xc0u))) {
        if (offset + 4 >= available)
            return false;
        vector_encoding = true;
        evex_encoding = true;
        opcode_map = code[offset + 1] & 0x03u;
        if (opcode_map < 1 || opcode_map > 3)
            return false;
        offset += 4;
    } else if (code[offset] == 0x8f && offset + 1 < available &&
            (code[offset + 1] & 0x1fu) >= 8u) {
        if (offset + 3 >= available)
            return false;
        vector_encoding = true;
        xop_encoding = true;
        opcode_map = code[offset + 1] & 0x1fu;
        if (opcode_map < 8 || opcode_map > 10)
            return false;
        offset += 3;
    }

    if (!vector_encoding) {
        if (code[offset] == 0x0f) {
            ++offset;
            if (offset >= available)
                return false;
            opcode_map = 1;
            if (code[offset] == 0x38 || code[offset] == 0x3a) {
                opcode_map = code[offset] == 0x38 ? 2 : 3;
                ++offset;
                if (offset >= available)
                    return false;
            }
        }
    }

    if (offset >= available || offset >= X86_MAX_INSTRUCTION_LENGTH)
        return false;

    opcode_offset = offset;
    opcode = code[offset++];

    if (opcode_map == 0) {
        has_modrm = x86_one_byte_has_modrm(opcode);

        if (opcode >= 0xb0 && opcode <= 0xb7)
            immediate_size = 1;
        else if (opcode >= 0xb8 && opcode <= 0xbf)
            immediate_size = (is_64bit && rex_w) ? 8 : (operand16 ? 2 : 4);
        else if (opcode == 0xe8 || opcode == 0xe9) {
            relative_size = (is_64bit || !operand16) ? 4 : 2;
            immediate_size = relative_size;
        } else if (opcode == 0xeb || (opcode >= 0x70 && opcode <= 0x7f) ||
                   (opcode >= 0xe0 && opcode <= 0xe3)) {
            relative_size = 1;
            immediate_size = 1;
            loop_relative = opcode >= 0xe0 && opcode <= 0xe3;
        } else if (opcode == 0xc2 || opcode == 0xca) {
            immediate_size = 2;
        } else if (opcode == 0x6a || opcode == 0xcd || opcode == 0xa8 ||
                   opcode == 0xd4 || opcode == 0xd5) {
            immediate_size = 1;
        } else if (opcode == 0x68) {
            immediate_size = operand16 ? 2 : 4;
        } else if (opcode == 0xa9) {
            immediate_size = operand16 ? 2 : 4;
        } else if (opcode >= 0xa0 && opcode <= 0xa3) {
            immediate_size = is_64bit && !address_override ? 8 :
                (address_override && !is_64bit ? 2 : 4);
        } else if (opcode == 0xc8) {
            immediate_size = 3;
        } else if (opcode == 0x69 || opcode == 0x81 || opcode == 0xc7) {
            immediate_size = operand16 ? 2 : 4;
        } else if (opcode == 0x6b || opcode == 0x80 || opcode == 0x82 ||
                   opcode == 0x83 || opcode == 0xc0 || opcode == 0xc1 ||
                   opcode == 0xc6) {
            immediate_size = 1;
        } else if (opcode == 0x04 || opcode == 0x0c || opcode == 0x14 ||
                   opcode == 0x1c || opcode == 0x24 || opcode == 0x2c ||
                   opcode == 0x34 || opcode == 0x3c) {
            immediate_size = 1;
        } else if (opcode == 0x05 || opcode == 0x0d || opcode == 0x15 ||
                   opcode == 0x1d || opcode == 0x25 || opcode == 0x2d ||
                   opcode == 0x35 || opcode == 0x3d) {
            immediate_size = operand16 ? 2 : 4;
        } else if (opcode == 0x9a || opcode == 0xea) {
            if (is_64bit)
                return false;
            immediate_size = operand16 ? 4 : 6;
        }
    } else if (opcode_map == 1) {
        has_modrm = x86_two_byte_has_modrm(opcode, vector_encoding);
        if (!vector_encoding && opcode >= 0x80 && opcode <= 0x8f) {
            relative_size = (is_64bit || !operand16) ? 4 : 2;
            immediate_size = relative_size;
        } else if (opcode == 0x0f || opcode == 0x70 ||
                   (opcode >= 0x71 && opcode <= 0x73) || opcode == 0xa4 ||
                   opcode == 0xac || opcode == 0xba || opcode == 0xc2 ||
                   opcode == 0xc4 || opcode == 0xc5 || opcode == 0xc6) {
            immediate_size = 1;
        } else if ((opcode == 0x78 || opcode == 0x79) && operand16 && !f2_prefix) {
            /* EXTRQ/INSERTQ immediate form: two trailing imm8 values. */
            immediate_size = 2;
        }
    } else if (opcode_map == 2 || opcode_map == 3) {
        has_modrm = true;
        if (opcode_map == 3)
            immediate_size = 1;
    } else {
        /* Unknown opcode map; fail closed rather than guessing a length. */
        return false;
    }

    if (xop_encoding)
        has_modrm = true;
    if (evex_encoding && opcode_map == 1 && opcode == 0x77)
        has_modrm = false;

    if (has_modrm) {
        size_t address_size;
        if (offset >= available)
            return false;

        modrm = code[offset++];
        mod = (modrm >> 6) & 3u;
        reg = (modrm >> 3) & 7u;
        rm = modrm & 7u;

        if (opcode_map == 0 && (opcode == 0xf6 || opcode == 0xf7) && reg <= 1)
            immediate_size = opcode == 0xf6 ? 1 : (operand16 ? 2 : 4);

        if (is_64bit)
            address_size = address_override ? 32 : 64;
        else
            address_size = address_override ? 16 : 32;

        if (mod != 3 && address_size != 16 && rm == 4) {
            uint8_t sib;
            uint8_t base;
            if (offset >= available)
                return false;
            sib = code[offset++];
            base = sib & 7u;
            if (mod == 0 && base == 5) {
                if (offset + 4 > available)
                    return false;
                offset += 4;
            } else if (mod == 1) {
                if (offset + 1 > available)
                    return false;
                offset += 1;
            } else if (mod == 2) {
                if (offset + 4 > available)
                    return false;
                offset += 4;
            }
        } else if (address_size == 16) {
            if (mod == 0 && rm == 6) {
                if (offset + 2 > available)
                    return false;
                offset += 2;
            } else if (mod == 1) {
                if (offset + 1 > available)
                    return false;
                offset += 1;
            } else if (mod == 2) {
                if (offset + 2 > available)
                    return false;
                offset += 2;
            }
        } else {
            if (mod == 0 && rm == 5) {
                displacement_offset = offset;
                if (offset + 4 > available)
                    return false;
                if (is_64bit && !address_override)
                    rip_relative = true;
                offset += 4;
            } else if (mod == 1) {
                if (offset + 1 > available)
                    return false;
                offset += 1;
            } else if (mod == 2) {
                if (offset + 4 > available)
                    return false;
                offset += 4;
            }
        }
    }

    relative_offset = offset;
    if (offset + immediate_size > available ||
        offset + immediate_size > X86_MAX_INSTRUCTION_LENGTH)
        return false;
    offset += immediate_size;

    if (!offset || offset > X86_MAX_INSTRUCTION_LENGTH)
        return false;

    decoded->length = offset;
    decoded->opcode_offset = opcode_offset;
    decoded->opcode = opcode;
    decoded->opcode_map = opcode_map;
    decoded->relative_offset = relative_offset;
    decoded->relative_size = relative_size;
    decoded->has_relative = relative_size != 0;
    decoded->is_loop_relative = loop_relative;
    decoded->has_rip_relative = rip_relative;
    decoded->rip_displacement_offset = displacement_offset;

    /* C7 F8 is XBEGIN rel16/rel32, another PC-relative encoding. */
    if (opcode_map == 0 && opcode == 0xc7 && has_modrm && modrm == 0xf8) {
        decoded->has_relative = true;
        decoded->relative_offset = relative_offset;
        decoded->relative_size = is_64bit ? 4 : (operand16 ? 2 : 4);
    }

    return true;
}

static bool x86_read_and_decode(uintptr_t address, bool is_64bit,
    uint8_t *bytes, x86_instruction *decoded)
{
    uint8_t candidate[X86_MAX_INSTRUCTION_LENGTH];

    for (size_t length = 1; length <= X86_MAX_INSTRUCTION_LENGTH; ++length) {
        if (!read_mem(candidate, (void *)address, length))
            return false;
        if (x86_decode_instruction(candidate, length, is_64bit, decoded)) {
            memcpy(bytes, candidate, decoded->length);
            return true;
        }
    }
    return false;
}

static bool x86_map_internal_target(uintptr_t target,
    uintptr_t original_address, size_t original_length,
    uintptr_t trampoline_address, const x86_instruction_plan *plans,
    size_t plan_count, size_t relocated_length, uintptr_t *mapped_target)
{
    if (target < original_address || target > original_address + original_length) {
        *mapped_target = target;
        return true;
    }

    if (target == original_address + original_length) {
        *mapped_target = trampoline_address + relocated_length;
        return true;
    }

    for (size_t i = 0; i < plan_count; ++i) {
        uintptr_t instruction_address = original_address + plans[i].original_offset;
        if (target == instruction_address) {
            *mapped_target = trampoline_address + plans[i].relocated_offset;
            return true;
        }
    }

    /* A branch/RIP reference into the middle of a stolen instruction cannot
     * be mapped unambiguously, so reject the hook. */
    return false;
}

static bool x86_build_relocated_block(uintptr_t original_address,
    const uint8_t *original_bytes, size_t original_length,
    const x86_instruction_plan *plans, size_t plan_count,
    uintptr_t trampoline_address, uint8_t *output,
    size_t output_capacity, size_t *output_length, bool is_64bit)
{
    size_t relocated_length = 0;

    for (size_t i = 0; i < plan_count; ++i) {
        const x86_instruction_plan *plan = &plans[i];
        if (plan->relocated_offset > output_capacity ||
            plan->relocated_length > output_capacity - plan->relocated_offset)
            return false;
        relocated_length = plan->relocated_offset + plan->relocated_length;
    }

    for (size_t i = 0; i < plan_count; ++i) {
        const x86_instruction_plan *plan = &plans[i];
        const x86_instruction *decoded = &plan->decoded;
        const uint8_t *source = original_bytes + plan->original_offset;
        uint8_t *destination = output + plan->relocated_offset;
        uintptr_t original_pc = original_address + plan->original_offset;
        uintptr_t relocated_pc = trampoline_address + plan->relocated_offset;

        if (decoded->has_relative && decoded->is_loop_relative)
            return false; /* LOOP/LOOPE/LOOPNE/JCXZ cannot be widened safely. */

        if (decoded->has_relative && decoded->relative_size == 1) {
            int64_t old_displacement = x86_read_signed(
                source + decoded->relative_offset, decoded->relative_size);
            uintptr_t branch_target;
            uintptr_t mapped_target;
            int64_t new_displacement;

            if (plan->relocated_length == 5 && source[decoded->opcode_offset] == 0xeb) {
                if (!add_signed_address(original_pc + decoded->length,
                        old_displacement, &branch_target) ||
                    !x86_map_internal_target(branch_target, original_address,
                        original_length, trampoline_address, plans, plan_count,
                        relocated_length, &mapped_target) ||
                    !pointer_distance_in_range(relocated_pc + 5, mapped_target,
                        INT32_MIN, INT32_MAX, &new_displacement))
                    return false;
                destination[0] = 0xe9;
                {
                    int32_t relative = (int32_t)new_displacement;
                    memcpy(destination + 1, &relative, sizeof(relative));
                }
            } else if (plan->relocated_length == 6 &&
                    source[decoded->opcode_offset] >= 0x70 &&
                    source[decoded->opcode_offset] <= 0x7f) {
                if (!add_signed_address(original_pc + decoded->length,
                        old_displacement, &branch_target) ||
                    !x86_map_internal_target(branch_target, original_address,
                        original_length, trampoline_address, plans, plan_count,
                        relocated_length, &mapped_target) ||
                    !pointer_distance_in_range(relocated_pc + 6, mapped_target,
                        INT32_MIN, INT32_MAX, &new_displacement))
                    return false;
                destination[0] = 0x0f;
                destination[1] = (uint8_t)(0x80u +
                    (source[decoded->opcode_offset] - 0x70u));
                {
                    int32_t relative = (int32_t)new_displacement;
                    memcpy(destination + 2, &relative, sizeof(relative));
                }
            } else {
                return false;
            }
            continue;
        }

        memcpy(destination, source, plan->original_length);

        if (decoded->has_relative) {
            int64_t old_displacement = x86_read_signed(
                source + decoded->relative_offset, decoded->relative_size);
            uintptr_t branch_target;
            uintptr_t mapped_target;
            int64_t new_displacement;

            if (!add_signed_address(original_pc + decoded->length,
                    old_displacement, &branch_target) ||
                !x86_map_internal_target(branch_target, original_address,
                    original_length, trampoline_address, plans, plan_count,
                    relocated_length, &mapped_target) ||
                !pointer_distance_in_range(relocated_pc + plan->original_length,
                    mapped_target, INT32_MIN, INT32_MAX, &new_displacement))
                return false;

            if (decoded->relative_size == 4) {
                int32_t relative = (int32_t)new_displacement;
                memcpy(destination + decoded->relative_offset,
                    &relative, sizeof(relative));
            } else if (decoded->relative_size == 2) {
                int16_t relative;
                if (new_displacement < INT16_MIN || new_displacement > INT16_MAX)
                    return false;
                relative = (int16_t)new_displacement;
                memcpy(destination + decoded->relative_offset,
                    &relative, sizeof(relative));
            } else {
                return false;
            }
        }

        if (decoded->has_rip_relative) {
            int64_t old_displacement = x86_read_signed(
                source + decoded->rip_displacement_offset, 4);
            uintptr_t memory_target;
            uintptr_t mapped_target;
            int64_t new_displacement;

            if (!add_signed_address(original_pc + plan->original_length,
                    old_displacement, &memory_target) ||
                !x86_map_internal_target(memory_target, original_address,
                    original_length, trampoline_address, plans, plan_count,
                    relocated_length, &mapped_target) ||
                !pointer_distance_in_range(relocated_pc + plan->original_length,
                    mapped_target, INT32_MIN, INT32_MAX, &new_displacement))
                return false;

            {
                int32_t relative = (int32_t)new_displacement;
                memcpy(destination + decoded->rip_displacement_offset,
                    &relative, sizeof(relative));
            }
        }
    }

    *output_length = relocated_length;
    (void)is_64bit;
    return true;
}

static bool x86_append_jump(uint8_t *output, size_t capacity,
    uintptr_t instruction_address, uintptr_t target_address,
    size_t *written, bool is_64bit)
{
    if (is_64bit) {
        /* JMP qword ptr [RIP+0], followed by an absolute 64-bit target. */
        if (capacity < 14)
            return false;
        output[0] = 0xff;
        output[1] = 0x25;
        memset(output + 2, 0, 4);
        memcpy(output + 6, &target_address, sizeof(target_address));
        *written = 14;
        return true;
    }

    if (capacity < 5)
        return false;
    output[0] = 0xe9;
    {
        uint32_t relative = (uint32_t)(target_address - (instruction_address + 5));
        memcpy(output + 1, &relative, sizeof(relative));
    }
    *written = 5;
    return true;
}

static bool x86_build_plan(uintptr_t address, size_t minimum_length,
    bool is_64bit, uint8_t *original_bytes, size_t *original_length,
    x86_instruction_plan *plans, size_t *plan_count,
    size_t *relocated_length)
{
    size_t source_offset = 0;
    size_t destination_offset = 0;
    size_t count = 0;

    while (source_offset < minimum_length) {
        x86_instruction decoded;
        uint8_t instruction_bytes[X86_MAX_INSTRUCTION_LENGTH];
        size_t relocated_instruction_length;

        if (count >= X86_MAX_INSTRUCTIONS ||
            source_offset >= X86_MAX_STOLEN_BYTES)
            return false;
        if (!x86_read_and_decode(address + source_offset, is_64bit,
                instruction_bytes, &decoded))
            return false;
        if (!decoded.length || source_offset + decoded.length > X86_MAX_STOLEN_BYTES)
            return false;

        memcpy(original_bytes + source_offset, instruction_bytes, decoded.length);
        relocated_instruction_length = decoded.length;

        if (decoded.has_relative && decoded.relative_size == 1) {
            uint8_t branch_opcode = instruction_bytes[decoded.opcode_offset];
            /* Widen short JMP/Jcc instructions in the trampoline. */
            if (decoded.opcode_offset != 0)
                return false; /* Prefix-bearing short branches are uncommon; fail closed. */
            if (branch_opcode == 0xeb)
                relocated_instruction_length = 5;
            else if (branch_opcode >= 0x70 && branch_opcode <= 0x7f)
                relocated_instruction_length = 6;
            else
                return false;
        }

        plans[count].original_offset = source_offset;
        plans[count].relocated_offset = destination_offset;
        plans[count].original_length = decoded.length;
        plans[count].relocated_length = relocated_instruction_length;
        plans[count].decoded = decoded;

        source_offset += decoded.length;
        destination_offset += relocated_instruction_length;
        ++count;
    }

    *original_length = source_offset;
    *plan_count = count;
    *relocated_length = destination_offset;
    return true;
}
#endif

static void cleanup_hook_allocation(hook_handle_internal *internal)
{
    if (!internal)
        return;
    if (internal->public_handle.trampoline_addr &&
        internal->public_handle.trampoline_addr != MAP_FAILED &&
        internal->allocation_size) {
        munmap(internal->public_handle.trampoline_addr,
            internal->allocation_size);
    }
    free(internal);
}

GPWNAPI hook_handle *hook_addr(void *address, void *fake,
    void **original_func, int flags)
{
    hook_handle_internal *internal;
    hook_handle *handle;
    size_t page_size;
    uintptr_t aligned_address;

    if (!address || !fake || !original_func)
        return NULL;
    *original_func = NULL;

    page_size = (size_t)sysconf(_SC_PAGESIZE);
    if (!page_size || (page_size & (page_size - 1)) != 0)
        return NULL;

    internal = (hook_handle_internal *)calloc(1, sizeof(*internal));
    if (!internal)
        return NULL;

    handle = &internal->public_handle;
    handle->address = address;
    handle->fake = fake;
    internal->allocation_size = page_size;

    aligned_address = (uintptr_t)address & ~((uintptr_t)page_size - 1);
    handle->trampoline_addr = mmap_near((void *)aligned_address, page_size,
#if defined(__aarch64__) || defined(__arm__)
        PROT_READ | PROT_WRITE
#else
        PROT_READ | PROT_WRITE
#endif
    );
    if (handle->trampoline_addr == MAP_FAILED) {
        internal->allocation_size = 0;
        cleanup_hook_allocation(internal);
        return NULL;
    }

#if defined(__aarch64__)
    {
        uint8_t relocated[GPWN_TRAMPOLINE_CODE_CAPACITY];
        uint32_t patch_instruction;
        uintptr_t trampoline = (uintptr_t)handle->trampoline_addr;
        uintptr_t target = (uintptr_t)address;
        uintptr_t fake_address = (uintptr_t)fake;
        size_t stolen_length = 0;
        size_t trampoline_offset = 0;
        bool installed = false;

        if ((target & 3u) != 0)
            goto arm64_fail;

        {
            int64_t nano_delta;
            if ((!flags || flags == GPWN_AARCH64_NANOHOOK) &&
                pointer_distance_in_range(target, trampoline,
                    -(INT64_C(1) << 27), (INT64_C(1) << 27) - 4,
                    &nano_delta) &&
                encode_b_aarch64(nano_delta, &patch_instruction) &&
                read_mem(internal->original_bytes, address,
                    AARCH64_NANO_HOOKBYTES_LEN)) {
                stolen_length = AARCH64_NANO_HOOKBYTES_LEN;
                trampoline_offset = AARCH64_LEGACY_HOOKBYTES_LEN;

                if (!arm64_detour(trampoline, fake_address,
                    AARCH64_LEGACY_HOOKBYTES_LEN) ||
                !relocate_aarch64_block(internal->original_bytes, target,
                    relocated, trampoline + trampoline_offset,
                    stolen_length) ||
                !write_mem((void *)(trampoline + trampoline_offset), relocated,
                    stolen_length) ||
                    !arm64_detour(trampoline + trampoline_offset + stolen_length,
                        target + stolen_length, AARCH64_LEGACY_HOOKBYTES_LEN))
                    goto arm64_fail;

                handle->rbyte_len = stolen_length;
                handle->flags = GPWN_AARCH64_NANOHOOK;
                if (!write_mem(address, &patch_instruction, sizeof(patch_instruction)))
                    goto arm64_fail;

                *original_func = (void *)(trampoline + trampoline_offset);
                installed = true;
            }
        }

        if (!installed && (!flags || flags == GPWN_AARCH64_MICROHOOK)) {
            uint32_t hook_instructions[3];
            uintptr_t target_page = target & ~(uintptr_t)0xfff;
            uintptr_t trampoline_page = trampoline & ~(uintptr_t)0xfff;
            int64_t page_delta;

            if (pointer_distance_in_range(target_page, trampoline_page,
                    -(INT64_C(1) << 32), (INT64_C(1) << 32) - 4096,
                    &page_delta) && encode_adrp(page_delta, &hook_instructions[0]) &&
                read_mem(internal->original_bytes, address,
                    AARCH64_MICRO_HOOKBYTES_LEN)) {
                hook_instructions[1] = 0xf9400231u; /* ldr x17, [x17] */
                hook_instructions[2] = 0xd61f0220u; /* br x17 */
                stolen_length = AARCH64_MICRO_HOOKBYTES_LEN;
                trampoline_offset = 8;

                if (!write_mem((void *)trampoline, &fake_address,
                        sizeof(fake_address)) ||
                    !relocate_aarch64_block(internal->original_bytes, target,
                        relocated, trampoline + trampoline_offset,
                        stolen_length) ||
                    !write_mem((void *)(trampoline + trampoline_offset), relocated,
                        stolen_length) ||
                    !arm64_detour(trampoline + trampoline_offset + stolen_length,
                        target + stolen_length, AARCH64_LEGACY_HOOKBYTES_LEN))
                    goto arm64_fail;

                handle->flags = GPWN_AARCH64_MICROHOOK;
                handle->rbyte_len = stolen_length;
                if (!write_mem(address, hook_instructions, sizeof(hook_instructions)))
                    goto arm64_fail;
                *original_func = (void *)(trampoline + trampoline_offset);
                installed = true;
            }
        }

        if (!installed && (!flags || flags == GPWN_AARCH64_LEGACYHOOK)) {
            stolen_length = AARCH64_LEGACY_HOOKBYTES_LEN;
            if (!read_mem(internal->original_bytes, address, stolen_length) ||
                !relocate_aarch64_block(internal->original_bytes, target,
                    relocated, trampoline, stolen_length) ||
                !write_mem(handle->trampoline_addr, relocated, stolen_length) ||
                !arm64_detour(trampoline + stolen_length,
                    target + stolen_length, AARCH64_LEGACY_HOOKBYTES_LEN))
                goto arm64_fail;

            handle->flags = GPWN_AARCH64_LEGACYHOOK;
            handle->rbyte_len = stolen_length;
            if (!arm64_detour(target, fake_address,
                    AARCH64_LEGACY_HOOKBYTES_LEN))
                goto arm64_fail;
            *original_func = handle->trampoline_addr;
            installed = true;
        }

        if (!installed)
            goto arm64_fail;

        if (mprotect(handle->trampoline_addr, page_size,
                PROT_READ | PROT_EXEC) == -1) {
            (void)write_mem(address, internal->original_bytes, handle->rbyte_len);
            *original_func = NULL;
            goto arm64_fail;
        }
        __builtin___clear_cache((char *)handle->trampoline_addr,
            (char *)handle->trampoline_addr + page_size);
        return handle;

arm64_fail:
        if (handle->rbyte_len)
            (void)write_mem(address, internal->original_bytes, handle->rbyte_len);
        *original_func = NULL;
        cleanup_hook_allocation(internal);
        return NULL;
    }

#elif defined(__arm__)
    {
        uint8_t relocated[GPWN_TRAMPOLINE_CODE_CAPACITY];
        uintptr_t trampoline = (uintptr_t)handle->trampoline_addr;
        uintptr_t target = (uintptr_t)address;
        uintptr_t fake_address = (uintptr_t)fake;
        uint32_t branch_instruction;
        size_t stolen_length = 0;
        size_t trampoline_offset = 0;
        bool installed = false;

        if ((target & 3u) != 0)
            goto arm32_fail;

        if ((!flags || flags == GPWN_ARM_NANOHOOK) &&
            pointer_distance_in_range(target, trampoline,
                -(INT64_C(1) << 25), (INT64_C(1) << 25) - 4, NULL) &&
            read_mem(internal->original_bytes, address, ARM_NANO_HOOKBYTES_LEN)) {
            int64_t branch_delta;
            if (pointer_distance_in_range(target + 8, trampoline,
                    -(INT64_C(1) << 25), (INT64_C(1) << 25) - 4,
                    &branch_delta)) {
                int64_t word_offset = branch_delta / 4;
                branch_instruction = 0xea000000u |
                    ((uint32_t)word_offset & 0x00ffffffu);
                stolen_length = ARM_NANO_HOOKBYTES_LEN;
                trampoline_offset = ARM_LEGACY_HOOKBYTES_LEN;

                if (!arm32_detour(trampoline, fake_address,
                        ARM_LEGACY_HOOKBYTES_LEN) ||
                    !relocate_arm32_block(internal->original_bytes, target,
                        relocated, trampoline + trampoline_offset,
                        stolen_length) ||
                    !write_mem((void *)(trampoline + trampoline_offset), relocated,
                        stolen_length) ||
                    !arm32_detour(trampoline + trampoline_offset + stolen_length,
                        target + stolen_length, ARM_LEGACY_HOOKBYTES_LEN))
                    goto arm32_fail;

                handle->flags = GPWN_ARM_NANOHOOK;
                handle->rbyte_len = stolen_length;
                if (!write_mem(address, &branch_instruction,
                        sizeof(branch_instruction)))
                    goto arm32_fail;
                *original_func = (void *)(trampoline + trampoline_offset);
                installed = true;
            }
        }

        if (!installed && (!flags || flags == GPWN_ARM_LEGACYHOOK)) {
            stolen_length = ARM_LEGACY_HOOKBYTES_LEN;
            if (!read_mem(internal->original_bytes, address, stolen_length) ||
                !relocate_arm32_block(internal->original_bytes, target,
                    relocated, trampoline, stolen_length) ||
                !write_mem(handle->trampoline_addr, relocated, stolen_length) ||
                !arm32_detour(trampoline + stolen_length,
                    target + stolen_length, ARM_LEGACY_HOOKBYTES_LEN))
                goto arm32_fail;

            handle->flags = GPWN_ARM_LEGACYHOOK;
            handle->rbyte_len = stolen_length;
            if (!arm32_detour(target, fake_address,
                    ARM_LEGACY_HOOKBYTES_LEN))
                goto arm32_fail;
            *original_func = handle->trampoline_addr;
            installed = true;
        }

        if (!installed)
            goto arm32_fail;

        if (mprotect(handle->trampoline_addr, page_size,
                PROT_READ | PROT_EXEC) == -1) {
            (void)write_mem(address, internal->original_bytes, handle->rbyte_len);
            *original_func = NULL;
            goto arm32_fail;
        }
        __builtin___clear_cache((char *)handle->trampoline_addr,
            (char *)handle->trampoline_addr + page_size);
        return handle;

arm32_fail:
        if (handle->rbyte_len)
            (void)write_mem(address, internal->original_bytes, handle->rbyte_len);
        *original_func = NULL;
        cleanup_hook_allocation(internal);
        return NULL;
    }

#elif defined(__x86_64__) || defined(__amd64__) || defined(__i386__) || defined(__x86__)
    {
        x86_instruction_plan plans[X86_MAX_INSTRUCTIONS];
        uint8_t trampoline_code[GPWN_TRAMPOLINE_CODE_CAPACITY];
        uint8_t target_patch[GPWN_MAX_ORIGINAL_BYTES];
        size_t plan_count = 0;
        size_t stolen_length = 0;
        size_t relocated_length = 0;
        size_t jump_back_length = 0;
        size_t patch_minimum;
        size_t trampoline_entry_offset = 0;
        bool use_long_hook = false;
        bool force_short = false;
        uintptr_t target = (uintptr_t)address;
        uintptr_t fake_address = (uintptr_t)fake;
        uintptr_t trampoline = (uintptr_t)handle->trampoline_addr;

#if GPWN_X86_64
        if (flags == GPWN_X86_64_LONGHOOK)
            use_long_hook = true;
        else if (flags == GPWN_X86_SHORTHOOK)
            force_short = true;
        else if (flags != 0)
            goto x86_fail;

        if (!force_short && !use_long_hook &&
            !pointer_distance_in_range(target + 5, fake_address,
                INT32_MIN, INT32_MAX, NULL))
            use_long_hook = true;
        if (force_short && !pointer_distance_in_range(target + 5,
                fake_address, INT32_MIN, INT32_MAX, NULL))
            goto x86_fail;
        patch_minimum = use_long_hook ? 6u : 5u;
        trampoline_entry_offset = use_long_hook ? sizeof(uintptr_t) : 0u;
#else
        if (flags != 0 && flags != GPWN_X86_SHORTHOOK)
            goto x86_fail;
        if (!pointer_distance_in_range(target + 5, fake_address,
                INT32_MIN, INT32_MAX, NULL))
            goto x86_fail;
        patch_minimum = 5u;
#endif

        if (!pointer_distance_in_range(target, trampoline,
                INT32_MIN, INT32_MAX, NULL))
            goto x86_fail;

        if (!x86_build_plan(target, patch_minimum, GPWN_X86_64 != 0,
                internal->original_bytes, &stolen_length, plans,
                &plan_count, &relocated_length))
            goto x86_fail;

        if (!x86_build_relocated_block(target, internal->original_bytes,
                stolen_length, plans, plan_count,
                trampoline + trampoline_entry_offset,
                trampoline_code, sizeof(trampoline_code),
                &relocated_length, GPWN_X86_64 != 0))
            goto x86_fail;

        if (!x86_append_jump(trampoline_code + relocated_length,
                sizeof(trampoline_code) - relocated_length,
                trampoline + trampoline_entry_offset + relocated_length,
                target + stolen_length, &jump_back_length,
                GPWN_X86_64 != 0))
            goto x86_fail;

        if (trampoline_entry_offset + relocated_length + jump_back_length > page_size)
            goto x86_fail;
#if GPWN_X86_64
        if (use_long_hook && !write_mem(handle->trampoline_addr,
                &fake_address, sizeof(fake_address)))
            goto x86_fail;
#endif
        if (!write_mem((void *)(trampoline + trampoline_entry_offset),
                trampoline_code, relocated_length + jump_back_length))
            goto x86_fail;

        memset(target_patch, 0x90, stolen_length);
#if GPWN_X86_64
        if (use_long_hook) {
            int64_t pointer_delta;
            int32_t relative;
            if (!pointer_distance_in_range(target + 6, trampoline,
                    INT32_MIN, INT32_MAX, &pointer_delta))
                goto x86_fail;
            relative = (int32_t)pointer_delta;
            target_patch[0] = 0xff;
            target_patch[1] = 0x25;
            memcpy(target_patch + 2, &relative, sizeof(relative));
            handle->flags = GPWN_X86_64_LONGHOOK;
        } else
#endif
        {
            int64_t relative_delta;
            int32_t relative;
            if (!pointer_distance_in_range(target + 5, fake_address,
                    INT32_MIN, INT32_MAX, &relative_delta))
                goto x86_fail;
            relative = (int32_t)relative_delta;
            target_patch[0] = 0xe9;
            memcpy(target_patch + 1, &relative, sizeof(relative));
            handle->flags = GPWN_X86_SHORTHOOK;
        }

        if (mprotect(handle->trampoline_addr, page_size,
                PROT_READ | PROT_EXEC) == -1)
            goto x86_fail;
        __builtin___clear_cache((char *)handle->trampoline_addr,
            (char *)handle->trampoline_addr + trampoline_entry_offset +
                relocated_length + jump_back_length);

        handle->rbyte_len = stolen_length;
        if (!write_mem(address, target_patch, stolen_length)) {
            (void)write_mem(address, internal->original_bytes, stolen_length);
            goto x86_fail;
        }

        *original_func = (void *)(trampoline + trampoline_entry_offset);
        return handle;

x86_fail:
        *original_func = NULL;
        cleanup_hook_allocation(internal);
        return NULL;
    }
#else
    (void)flags;
    cleanup_hook_allocation(internal);
    return NULL;
#endif
}

GPWNAPI bool rm_hook(hook_handle *handle)
{
    hook_handle_internal *internal;

    if (!handle)
        return false;

    internal = hook_internal(handle);
    if (!handle->address || !handle->rbyte_len ||
        handle->rbyte_len > sizeof(internal->original_bytes))
        return false;

    /* The caller must ensure that no thread is currently executing the target
     * or its trampoline before unhooking. The library does not suspend threads. */
    if (!write_mem(handle->address, internal->original_bytes,
            handle->rbyte_len))
        return false;

    if (handle->trampoline_addr && handle->trampoline_addr != MAP_FAILED &&
        internal->allocation_size) {
        if (munmap(handle->trampoline_addr, internal->allocation_size) == -1)
            return false;
    }

    free(internal);
    return true;
}
