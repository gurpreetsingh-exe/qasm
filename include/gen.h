#pragma once

#include <stdint.h>

typedef struct Gen {
    uint8_t* buf;
    size_t bufSize;
    const char* outName;
} Gen;

Gen* newGen(const char* outName);
void genElfHeader(Gen* gen);
void genSectionHeader(Gen* gen);
void genSections(Gen* gen);
void genAppendBuf(Gen* gen, uint8_t item);
void genWrite(Gen* gen, const char* b);
void writeFile(Gen* gen);

void genWrite8(Gen* gen, uint8_t n);
void genWrite16(Gen* gen, uint16_t n);
void genWrite32(Gen* gen, uint32_t n);
void genWrite64(Gen* gen, uint64_t n);
void genZeros(Gen* gen, size_t n);
