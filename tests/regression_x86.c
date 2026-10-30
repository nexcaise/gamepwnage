#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "inlinehook.h"
#include "mem.h"
#include "proc.h"

#if !defined(__x86_64__) && !defined(__amd64__)
int main(void) { return 0; }
#else
static int call_target(void *address)
{
    int (*function)(void) = (int (*)(void))address;
    return function();
}

static void test_memory_protection(void)
{
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory = mmap(NULL, page_size * 2,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const uint8_t patch[4] = { 0x11, 0x22, 0x33, 0x44 };
    uint8_t output[4] = {0};

    assert(memory != MAP_FAILED);
    assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
    assert(mprotect(memory + page_size, page_size, PROT_READ) == 0);
    assert(write_mem(memory + page_size - 2, (void *)patch, sizeof(patch)));
    assert(read_mem(output, memory + page_size - 2, sizeof(output)));
    assert(memcmp(output, patch, sizeof(patch)) == 0);
    assert(get_prot((uintptr_t)memory) == (PROT_READ | PROT_EXEC));
    assert(get_prot((uintptr_t)(memory + page_size)) == PROT_READ);
    assert(get_prot((uintptr_t)0x1) == -1);
    assert(munmap(memory, page_size * 2) == 0);
}

static void test_basic_hook(void)
{
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory = mmap(NULL, page_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *original = NULL;
    hook_handle *handle;

    assert(memory != MAP_FAILED);
    /* target(): mov eax, 42; ret */
    memory[0] = 0xb8;
    memory[1] = 42;
    memory[2] = memory[3] = memory[4] = 0;
    memory[5] = 0xc3;
    /* fake(): mov eax, 99; ret */
    memory[64] = 0xb8;
    memory[65] = 99;
    memory[66] = memory[67] = memory[68] = 0;
    memory[69] = 0xc3;

    assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
    assert(call_target(memory) == 42);

    handle = hook_addr(memory, memory + 64, &original, 0);
    assert(handle != NULL);
    assert(original != NULL);
    assert(call_target(memory) == 99);
    assert(call_target(original) == 42);
    assert(rm_hook(handle));
    assert(call_target(memory) == 42);
    assert(munmap(memory, page_size) == 0);
}


static void test_relative_relocations_execute(void)
{
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory = mmap(NULL, page_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *original = NULL;
    hook_handle *handle;
    int32_t displacement;
    uint64_t value = 42;

    assert(memory != MAP_FAILED);

    /* RIP-relative data load: mov rax, [rip + disp32]; ret */
    memcpy(memory + 0x300, &value, sizeof(value));
    memory[0x100] = 0x48;
    memory[0x101] = 0x8b;
    memory[0x102] = 0x05;
    displacement = (int32_t)((memory + 0x300) - (memory + 0x107));
    memcpy(memory + 0x103, &displacement, sizeof(displacement));
    memory[0x107] = 0xc3;

    /* fake(): mov eax, 99; ret */
    memory[0x20] = 0xb8;
    memory[0x21] = 99;
    memory[0x22] = memory[0x23] = memory[0x24] = 0;
    memory[0x25] = 0xc3;

    assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
    handle = hook_addr(memory + 0x100, memory + 0x20, &original, 0);
    assert(handle != NULL && original != NULL);
    assert(call_target(original) == 42);
    assert(call_target(memory + 0x100) == 99);
    assert(rm_hook(handle));
    assert(call_target(memory + 0x100) == 42);

    /* Short JMP in the stolen block is widened to rel32 in the trampoline. */
    assert(mprotect(memory, page_size, PROT_READ | PROT_WRITE) == 0);
    memset(memory + 0x180, 0x90, 32);
    memory[0x180] = 0xeb;
    memory[0x181] = 0x03;
    memory[0x185] = 0xb8;
    memory[0x186] = 42;
    memory[0x187] = memory[0x188] = memory[0x189] = 0;
    memory[0x18a] = 0xc3;

    assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
    original = NULL;
    handle = hook_addr(memory + 0x180, memory + 0x20, &original, 0);
    assert(handle != NULL && original != NULL);
    assert(call_target(original) == 42);
    assert(rm_hook(handle));

    /* Near CALL is relocated and still reaches the original helper. */
    assert(mprotect(memory, page_size, PROT_READ | PROT_WRITE) == 0);
    memset(memory + 0x200, 0x90, 32);
    memory[0x200] = 0xe8;
    displacement = (int32_t)((memory + 0x240) - (memory + 0x205));
    memcpy(memory + 0x201, &displacement, sizeof(displacement));
    memory[0x205] = 0xc3;
    memory[0x240] = 0xb8;
    memory[0x241] = 77;
    memory[0x242] = memory[0x243] = memory[0x244] = 0;
    memory[0x245] = 0xc3;

    assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
    original = NULL;
    handle = hook_addr(memory + 0x200, memory + 0x20, &original, 0);
    assert(handle != NULL && original != NULL);
    assert(call_target(original) == 77);
    assert(rm_hook(handle));

    assert(munmap(memory, page_size) == 0);
}

static void test_long_hook(void)
{
#ifdef MAP_32BIT
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *target_memory = mmap(NULL, page_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_32BIT, -1, 0);
    uint8_t *fake_memory = mmap(NULL, page_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    void *original = NULL;
    hook_handle *handle;

    if (target_memory == MAP_FAILED || fake_memory == MAP_FAILED) {
        if (target_memory != MAP_FAILED) munmap(target_memory, page_size);
        if (fake_memory != MAP_FAILED) munmap(fake_memory, page_size);
        return; /* MAP_32BIT may be unavailable under a constrained runtime. */
    }

    /* target(): mov eax, 42; ret; padding supplies the 6-byte indirect long hook. */
    target_memory[0] = 0xb8;
    target_memory[1] = 42;
    target_memory[2] = target_memory[3] = target_memory[4] = 0;
    target_memory[5] = 0xc3;
    memset(target_memory + 6, 0x90, 32);
    fake_memory[0] = 0xb8;
    fake_memory[1] = 99;
    fake_memory[2] = fake_memory[3] = fake_memory[4] = 0;
    fake_memory[5] = 0xc3;

    assert(mprotect(target_memory, page_size, PROT_READ | PROT_EXEC) == 0);
    assert(mprotect(fake_memory, page_size, PROT_READ | PROT_EXEC) == 0);
    original = NULL;
    handle = hook_addr(target_memory, fake_memory, &original, 0);
    assert(handle != NULL && original != NULL);
    assert(handle->flags == GPWN_X86_64_LONGHOOK);
    assert(call_target(target_memory) == 99);
    assert(call_target(original) == 42);
    assert(rm_hook(handle));
    assert(call_target(target_memory) == 42);

    assert(munmap(target_memory, page_size) == 0);
    assert(munmap(fake_memory, page_size) == 0);
#endif
}

static void test_decoder_and_relocation_cases(void)
{
    const struct {
        const char *name;
        const uint8_t *bytes;
        size_t length;
    } cases[] = {
        { "near jcc", (const uint8_t[]){ 0x0f, 0x84, 0x00, 0x00, 0x00, 0x00 }, 6 },
        { "rex mov imm32", (const uint8_t[]){ 0x41, 0xb8, 0x78, 0x56, 0x34, 0x12 }, 6 },
        { "test al imm8", (const uint8_t[]){ 0xa8, 0x7f }, 2 },
        { "test eax imm32", (const uint8_t[]){ 0xa9, 1, 2, 3, 4 }, 5 },
        { "test r/m8 imm8", (const uint8_t[]){ 0xf6, 0xc0, 0x7f }, 3 },
        { "test r/m32 imm32", (const uint8_t[]){ 0xf7, 0xc0, 1, 2, 3, 4 }, 6 },
        { "mov r/m32 imm32", (const uint8_t[]){ 0xc7, 0x45, 0xfc, 1, 0, 0, 0 }, 7 },
        { "add r/m32 imm8", (const uint8_t[]){ 0x83, 0xc0, 1 }, 3 },
        { "imul r32 r/m32 imm32", (const uint8_t[]){ 0x69, 0xc0, 1, 0, 0, 0 }, 6 },
        { "xbegin rel32", (const uint8_t[]){ 0xc7, 0xf8, 0, 0, 0, 0 }, 6 },
        { "cpuid", (const uint8_t[]){ 0x0f, 0xa2 }, 2 },
        { "bswap r10d", (const uint8_t[]){ 0x41, 0x0f, 0xca }, 3 },
        { "pshufd", (const uint8_t[]){ 0x66, 0x0f, 0x70, 0xc0, 0x01 }, 5 },
        { "shufps", (const uint8_t[]){ 0x0f, 0xc6, 0xc0, 0x01 }, 4 },
        { "palignr", (const uint8_t[]){ 0x66, 0x0f, 0x3a, 0x0f, 0xc0, 0x01 }, 6 },
        { "vzeroupper", (const uint8_t[]){ 0xc5, 0xf8, 0x77 }, 3 },
        { "vaddps", (const uint8_t[]){ 0xc5, 0xf8, 0x58, 0xc1 }, 4 },
        { "vex map 2", (const uint8_t[]){ 0xc4, 0xe2, 0x79, 0x00, 0xc0 }, 5 },
        { "x87", (const uint8_t[]){ 0xd9, 0xe8 }, 2 },
        { "short jmp", (const uint8_t[]){ 0xeb, 0x05 }, 2 },
        { "short jcc", (const uint8_t[]){ 0x74, 0x05 }, 2 },
        { "rip relative mov", (const uint8_t[]){ 0x48, 0x8b, 0x05, 0x79, 0x00, 0x00, 0x00 }, 7 },
        { "near call", (const uint8_t[]){ 0xe8, 0x00, 0x00, 0x00, 0x00 }, 5 }
    };
    const size_t page_size = (size_t)sysconf(_SC_PAGESIZE);
    uint8_t *memory = mmap(NULL, page_size,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    const uint8_t fake_code[] = { 0xb8, 0x63, 0, 0, 0, 0xc3 };
    size_t offset = 0x100;

    assert(memory != MAP_FAILED);
    memcpy(memory + 0x20, fake_code, sizeof(fake_code));

    for (size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        void *original = NULL;
        hook_handle *handle;
        uint8_t *target = memory + offset;

        memset(target, 0x90, 32);
        memcpy(target, cases[i].bytes, cases[i].length);
        target[24] = 0xc3;
        offset += 0x80;

        assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
        handle = hook_addr(target, memory + 0x20, &original, 0);
        if (!handle) {
            fprintf(stderr, "hook failed on decoder case: %s\n", cases[i].name);
            assert(handle != NULL);
        }
        assert(original != NULL);
        assert(rm_hook(handle));
        assert(mprotect(memory, page_size, PROT_READ | PROT_WRITE) == 0);
    }

    /* LOOP has an 8-bit relative target and cannot be widened transparently;
     * the hooker must reject it rather than emit a broken trampoline. */
    {
        void *original = NULL;
        uint8_t *target = memory + offset;
        hook_handle *handle;
        memset(target, 0x90, 32);
        target[0] = 0xe2;
        target[1] = 0xfe;
        assert(mprotect(memory, page_size, PROT_READ | PROT_EXEC) == 0);
        handle = hook_addr(target, memory + 0x20, &original, 0);
        assert(handle == NULL);
        assert(target[0] == 0xe2 && target[1] == 0xfe);
        assert(mprotect(memory, page_size, PROT_READ | PROT_WRITE) == 0);
    }

    assert(munmap(memory, page_size) == 0);
}

int main(void)
{
    test_memory_protection();
    test_basic_hook();
    test_relative_relocations_execute();
    test_long_hook();
    test_decoder_and_relocation_cases();
    puts("gamepwnage regression tests passed");
    return 0;
}
#endif
