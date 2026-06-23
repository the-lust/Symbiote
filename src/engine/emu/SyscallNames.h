#pragma once
#include <cstdint>
#include <string>

const char* GetSyscallName(uint64_t syscallNumber);
uint64_t GetSyscallCount();
