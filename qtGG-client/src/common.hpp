#pragma once
#include <string>
#include <cstdint>
#include <mutex>
#include <array>

extern std::string g_jwt;

using AES256Key = std::array<uint8_t, 32>;
