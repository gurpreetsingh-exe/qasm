#include <stdio.h>
#include "qasm.h"
#include "gen.h"

int main() {
    Gen* gen = newGen("elf.o");

    genElfHeader(gen);
    writeFile(gen);

    return 0;
}
