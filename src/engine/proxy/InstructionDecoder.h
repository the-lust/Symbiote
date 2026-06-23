#pragma once
#include <cstdint>

int GetInstructionLength(const uint8_t* code);
int FindInstructionBoundary(const uint8_t* code, int minBytes, int maxBytes);
