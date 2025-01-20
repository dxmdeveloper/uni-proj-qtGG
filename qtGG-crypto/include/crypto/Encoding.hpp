#pragma once
#include <string_view>
#include <cstdint>

namespace Encoding {
    std::string base64UrlEncode(std::string_view s);
    std::string base64UrlEncode(const char* input, size_t length);
    std::string base64UrlEncode(const unsigned char* input, size_t length);
    std::string base64UrlDecode(std::string_view input);
}
