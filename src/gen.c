#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "gen.h"

#define SHF_WRITE 0x1
#define SHF_ALLOC 0x2
#define SHF_EXECINSTR 0x4
#define SHF_MERGE 0x10
#define SHF_STRINGS 0x20
#define SHF_INFO_LINK 0x40
#define SHF_LINK_ORDER 0x80
#define SHF_OS_NONCONFORMING 0x100
#define SHF_GROUP 0x200
#define SHF_TLS 0x400
#define SHF_MASKOS 0x0ff00000
#define SHF_MASKPROC 0xf0000000

#define E_MAGIC_NUMBER "\x7f""ELF"
#define E_CLASS 2
#define E_ENDIANESS 1
#define E_VERSION 1
#define E_ABIVERSION 0
#define E_TYPE 1
#define E_ARCHITECTURE 0x3e
#define E_OSABI_NONE 0
#define E_ENTRY 0 // b0 00 40 00 00 00 00 00 in exec
#define E_PHOFF 0 // 40 00 00 00 in exec
#define E_SHOFF 0x40
#define E_EFLAGS 0
#define E_EHSIZE 0x40
#define E_PHENTSIZE 0 // 38 00 in exec 56 bytes long
#define E_PHNUM 0 // 02 00 in exec
#define E_SHENTSIZE 0x40 // 40 00
#define E_SHNUM 3 // number of sections, none (or magic ?), .data and .shstrtab section
#define E_SHSTRNDX 2 // Index of .shstrtab section in the section header table

#define SH_DATA 1 // 01 00 00 00
#define SH_TYPE 1 // 01 00 00 00: SHT_PROGBITS
#define SH_FLAGS 3 // + 03 00 00 00 00 00 00 00: SHF_WRITE and SHF_ALLOC

#define SH_DATA_FLAGS SHF_ALLOC

#define SH_SHSTRTAB 0x3

uint64_t data_addr = 0;
uint64_t data_size = 0;

uint64_t shstrtab_addr = 0;
uint64_t shstrtab_size = 0;

Gen* newGen(const char* outName) {
    Gen* gen = malloc(sizeof(Gen));
    gen->buf = malloc(sizeof(uint8_t));
    gen->bufSize = 0;
    gen->outName = outName;
    return gen;
}

void genAppendBuf(Gen* gen, uint8_t item) {
    gen->buf[gen->bufSize++] = item;
    gen->buf = realloc(gen->buf, sizeof(uint8_t) * (gen->bufSize + 1));
}

void genWrite(Gen* gen, const char* b) {
    for (int i = 0; i < strlen(b); ++i) {
        genAppendBuf(gen, b[i]);
    }
}

void genWrite8(Gen* gen, uint8_t n) {
    genAppendBuf(gen, (uint8_t)n);
}

void genWrite16(Gen* gen, uint16_t n) {
    for (int i = 0; i < 2; ++i) {
        genAppendBuf(gen, (uint8_t)(n >> (i * 8)));
    }
}

void genWrite32(Gen* gen, uint32_t n) {
    for (int i = 0; i < 4; ++i) {
        genAppendBuf(gen, (uint8_t)(n >> (i * 8)));
    }
}

void genWrite64(Gen* gen, uint64_t n) {
    for (int i = 0; i < 8; ++i) {
        genAppendBuf(gen, (uint8_t)(n >> (i * 8)));
    }
}

void genZeros(Gen* gen, size_t n) {
    for (int i = 0; i < n; ++i) {
        genAppendBuf(gen, 0);
    }
}

void genWrite64At(Gen* gen, uint64_t n, uint64_t addr) {
    for (int i = 0; i < 8; ++i) {
        gen->buf[addr + i] = (uint8_t)(n >> (i * 8));
    }
}

void genPadding(Gen* gen) {
    genZeros(gen, 16 - (gen->bufSize % 16));
}

void genElfHeader(Gen* gen) {
    genWrite(gen, E_MAGIC_NUMBER);
    genAppendBuf(gen, E_CLASS);
    genAppendBuf(gen, E_ENDIANESS);
    genAppendBuf(gen, E_VERSION);
    genAppendBuf(gen, E_OSABI_NONE);
    genWrite64(gen, 0); // padding
    genWrite16(gen, E_TYPE);
    genWrite16(gen, E_ARCHITECTURE);
    genWrite32(gen, E_VERSION);
    genWrite64(gen, E_ENTRY);
    genWrite64(gen, E_PHOFF);
    genWrite64(gen, E_SHOFF);
    genWrite32(gen, E_EFLAGS);
    genWrite16(gen, E_EHSIZE);
    genWrite16(gen, E_PHENTSIZE);
    genWrite16(gen, E_PHNUM);
    genWrite16(gen, E_SHENTSIZE);
    genWrite16(gen, E_SHNUM);
    genWrite16(gen, E_SHSTRNDX);

    genSectionHeader(gen);
    genSections(gen);
}

void genSectionHeader(Gen* gen) {}

void genSections(Gen* gen) {
    // TODO: Generate all section without hard-coding :)
    // magic section ?
    genZeros(gen, 64);

    // .data section
    genWrite32(gen, SH_DATA);
    genWrite32(gen, SH_TYPE);
    genWrite64(gen, SH_DATA_FLAGS);
    genWrite64(gen, 0); // addr

    uint64_t __data_addr = gen->bufSize;
    // we don't know the address yet
    genWrite64(gen, 0); // offset
    genWrite64(gen, 12); // size, "Hello World\n" is 12 characters

    genWrite64(gen, 0); // sh_link | sh_info
    genWrite64(gen, 4); // sh_addralign
    genWrite64(gen, 0); // sh_entrysize

    /** .shstrtab section
     *
     *   . . d a t a . . s h s t r t a b
     *   0 1 2 3 4 5 6 7 8 9 . . . . . .
     *                 ^ index here
     */
    genWrite32(gen, 7); // offset to the start of name
    genWrite32(gen, SH_SHSTRTAB); // section type
    genWrite64(gen, SH_DATA_FLAGS);
    genWrite64(gen, 0); // addr

    uint64_t __shstrtab_addr = gen->bufSize;
    // we don't know the address yet
    genWrite64(gen, 0); // offset
    genWrite64(gen, 16); // size

    genWrite64(gen, 0); // sh_link | sh_info
    genWrite64(gen, 0); // sh_addralign
    genWrite64(gen, 0); // sh_entrysize

    uint64_t raw_data_addr = gen->bufSize;
    genWrite(gen, "Hello World\n");
    genPadding(gen);
    genWrite64At(gen, raw_data_addr, __data_addr);

    shstrtab_addr = gen->bufSize;
    genWrite8(gen, 0);
    genWrite(gen, ".data");
    genWrite8(gen, 0);
    genWrite(gen, ".shstrtab");
    genWrite64At(gen, shstrtab_addr, __shstrtab_addr);
}

void writeFile(Gen* gen) {
    FILE *in = fopen(gen->outName, "w");
    if (in == NULL) {
        fputs("File not found\n", stderr);
        exit(1);
    }

    for (int i = 0; i < gen->bufSize; ++i) {
        fprintf(in, "%c", gen->buf[i]);
    }
}
