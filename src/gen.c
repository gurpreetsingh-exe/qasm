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
#define E_SHENTSIZE 458816 // 40 00 07 00
#define E_SHSTRNDX 3 // 03 00

#define SH_DATA 1 // 01 00 00 00
#define SH_TYPE 1 // 01 00 00 00: SHT_PROGBITS
#define SH_FLAGS 3 // + 03 00 00 00 00 00 00 00: SHF_WRITE and SHF_ALLOC

#define SH_DATA_FLAGS SHF_ALLOC | SHF_WRITE

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
    genWrite32(gen, E_SHENTSIZE);
    genWrite16(gen, E_SHSTRNDX);

    genSectionHeader(gen);
    genSections(gen);
}

void genSectionHeader(Gen* gen) {}

void genSections(Gen* gen) {
    // magic section ?
    genZeros(gen, 64);

    // .data section
    genWrite32(gen, SH_DATA);
    genWrite32(gen, SH_TYPE);
    genWrite64(gen, SH_DATA_FLAGS);
    genWrite64(gen, 0); // addr
    genWrite64(gen, 0x200); // offset
    genWrite64(gen, 0x0d); // size
    genWrite64(gen, 0); // sh_link | sh_info
    genWrite64(gen, 4); // sh_addralign
    genWrite64(gen, 0); // sh_entrysize
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
