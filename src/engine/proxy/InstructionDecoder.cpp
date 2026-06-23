#include "InstructionDecoder.h"

static bool IsPrefix(uint8_t b)
{
    switch (b) {
    case 0xF0: case 0xF2: case 0xF3:
    case 0x2E: case 0x36: case 0x3E: case 0x26:
    case 0x64: case 0x65:
    case 0x66: case 0x67:
        return true;
    default:
        return false;
    }
}

static bool g_modrm[256] = {
    // 0x00-0x0F
    1,1,1,1, 0,0,0,0, 1,1,1,1, 0,0,0,0,
    // 0x10-0x1F
    1,1,1,1, 0,0,0,0, 1,1,1,1, 0,0,0,0,
    // 0x20-0x2F
    1,1,1,1, 0,0,0,0, 1,1,1,1, 0,0,0,0,
    // 0x30-0x3F
    1,1,1,1, 0,0,0,0, 1,1,1,1, 0,0,0,0,
    // 0x40-0x4F (REX handled before opcode)
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0x50-0x5F (push/pop)
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0x60-0x6F
    0,0,0,1, 0,0,0,0, 0,1,0,1, 0,0,0,0,
    // 0x70-0x7F (jcc rel8)
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0x80-0x8F
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    // 0x90-0x9F
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0xA0-0xAF
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0xB0-0xBF
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0xC0-0xCF
    1,1,0,0, 0,0,1,1, 0,0,0,0, 0,0,0,0,
    // 0xD0-0xDF
    1,1,1,1, 0,0,0,0, 1,1,1,1, 1,1,1,1,
    // 0xE0-0xEF
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0xF0-0xFF
    0,0,0,1, 0,0,1,1, 0,0,0,0, 0,0,1,1,
};

static int g_imm[256] = {
    // 0x00-0x0F
    0,0,0,0, 1,4,0,0, 0,0,0,0, 1,4,0,0,
    // 0x10-0x1F
    0,0,0,0, 1,4,0,0, 0,0,0,0, 1,4,0,0,
    // 0x20-0x2F
    0,0,0,0, 1,4,0,0, 0,0,0,0, 1,4,0,0,
    // 0x30-0x3F
    0,0,0,0, 1,4,0,0, 0,0,0,0, 1,4,0,0,
    // 0x40-0x4F
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0x50-0x5F
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0x60-0x6F
    0,0,0,0, 0,0,0,0, 4,0,1,0, 0,0,0,0,
    // 0x70-0x7F
    1,1,1,1, 1,1,1,1, 1,1,1,1, 1,1,1,1,
    // 0x80-0x8F - ModRM opcodes, g_imm not used
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0x90-0x9F
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0xA0-0xAF
    8,8,8,8, 0,0,0,0, 0,0,0,0, 0,0,0,0,
    // 0xB0-0xBF
    1,1,1,1, 1,1,1,1, 4,4,4,4, 4,4,4,4,
    // 0xC0-0xCF - ModRM opcodes
    0,0,2,0, 0,0,0,0, 3,0,2,0, 0,1,0,0,
    // 0xD0-0xDF - ModRM opcodes
    0,0,0,0, 1,1,0,0, 0,0,0,0, 0,0,0,0,
    // 0xE0-0xEF
    1,1,1,1, 1,1,1,1, 4,4,0,1, 0,0,0,0,
    // 0xF0-0xFF
    0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0,
};

int GetInstructionLength(const uint8_t* code)
{
    int pos = 0;
    int prefixCount = 0;

    while (IsPrefix(code[pos]) && prefixCount < 14) {
        pos++; prefixCount++;
    }

    int rex = 0;
    if ((code[pos] & 0xF0) == 0x40 && code[pos] <= 0x4F) {
        rex = code[pos];
        pos++;
    }

    if (code[pos] == 0xC4) {
        pos += 3;
        goto decodeModRM;
    }
    if (code[pos] == 0xC5) {
        pos += 2;
        goto decodeModRM;
    }
    if (code[pos] == 0x62) {
        pos += 4;
        goto decodeModRM;
    }

    {
        uint8_t op = code[pos++];
        int immSize = 0;

        if (op == 0x0F) {
            uint8_t op2 = code[pos++];
            if (op2 == 0x38) {
                pos++;
                goto decodeModRM;
            }
            if (op2 == 0x3A) {
                pos++;
                immSize = 1;
                goto doneImm;
            }
            if (op2 >= 0x80 && op2 <= 0x8F) {
                immSize = 4;
                goto doneImm;
            }
            goto decodeModRM;
        }

        if (!g_modrm[op]) {
            immSize = g_imm[op];
            if (op >= 0xB8 && op <= 0xBF && (rex & 0x48) == 0x48) {
                immSize = 8;
            }
            goto doneImm;
        }

        {
            uint8_t modrm = code[pos];
            uint8_t mod = (modrm >> 6) & 3;
            uint8_t reg = (modrm >> 3) & 7;
            uint8_t rm = modrm & 7;

            pos++;

            if (mod != 3 && rm == 4) {
                uint8_t sib = code[pos++];
                uint8_t base = sib & 7;
                if (mod == 1) pos += 1;
                else if (mod == 2) pos += 4;
                else if (mod == 0 && base == 5) pos += 4;
            } else {
                if (mod == 1) pos += 1;
                else if (mod == 2) pos += 4;
                else if (mod == 0 && rm == 5) pos += 4;
            }

            if (op == 0x80 || op == 0x82 || op == 0xC0 || op == 0xC6) {
                immSize = 1;
            } else if (op == 0x81 || op == 0xC7) {
                immSize = 4;
            } else if (op == 0x83 || op == 0xC1) {
                immSize = 1;
            } else if (op == 0xF6) {
                immSize = (reg == 0) ? 1 : 0;
            } else if (op == 0xF7) {
                immSize = (reg == 0) ? 4 : 0;
            } else if (op >= 0xD0 && op <= 0xD3) {
                immSize = 0;
            } else if (op == 0xFE || op == 0xFF) {
                immSize = 0;
            } else {
                immSize = 0;
            }
        }

    doneImm:
        pos += immSize;
    }

    return pos;

decodeModRM:
    {
        uint8_t modrm = code[pos];
        uint8_t mod = (modrm >> 6) & 3;
        uint8_t rm = modrm & 7;
        pos++;

        if (mod != 3 && rm == 4) {
            uint8_t sib = code[pos++];
            uint8_t base = sib & 7;
            if (mod == 1) pos += 1;
            else if (mod == 2) pos += 4;
            else if (mod == 0 && base == 5) pos += 4;
        } else {
            if (mod == 1) pos += 1;
            else if (mod == 2) pos += 4;
            else if (mod == 0 && rm == 5) pos += 4;
        }
    }

    return pos;
}

int FindInstructionBoundary(const uint8_t* code, int minBytes, int maxBytes)
{
    int pos = 0;
    while (pos < maxBytes) {
        int len = GetInstructionLength(code + pos);
        if (len <= 0) return -1;
        pos += len;
        if (pos >= minBytes) return pos;
    }
    return -1;
}
