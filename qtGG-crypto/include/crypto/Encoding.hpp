#pragma once
#include <string>
#include <string_view>
#include <cstdint>
#include <vector>

namespace Encoding {
    std::string base64UrlEncode(std::string_view s);
    std::string base64UrlEncode(const char* input, size_t length);
    std::string base64UrlEncode(const unsigned char* input, size_t length);
    std::string base64UrlDecode(std::string_view input);
    std::vector<uint8_t> base64UrlDecodeBytes(std::string_view input);
}
