#include <Encoding.hpp>
#include <string>
#include <string_view>
#include <vector>
#include <openssl/evp.h>

namespace Encoding {
    std::string base64UrlEncode(std::string_view s) {
        return base64UrlEncode(reinterpret_cast<const unsigned char *>(s.data()), s.size());
    }

    std::string base64UrlEncode(const char *input, size_t length) {
        return base64UrlEncode(reinterpret_cast<const unsigned char *>(input), length);
    }

    std::string base64UrlEncode(const unsigned char *input, size_t length) {
        size_t encLen = 4 * ((length + 2) / 3);
        std::vector<unsigned char> encoded(encLen + 1);
        int returnedSize = EVP_EncodeBlock(encoded.data(), input, length);
        std::string encodedStr(reinterpret_cast<char *>(encoded.data()), returnedSize);

        for (char &c: encodedStr) {
            if (c == '+') c = '-';
            else if (c == '/') c = '_';
        }
        for (int i = encodedStr.size() - 1; i >= 0; i--) {
            if (encodedStr[i] == '=') encodedStr.pop_back();
            else break;
        }

        return encodedStr;
    }

    std::string base64UrlDecode(std::string_view input) {
        auto decoded = base64UrlDecodeBytes(input);
        return std::string(reinterpret_cast<char*>(decoded.data()), decoded.size());
    }

    std::vector<uint8_t> base64UrlDecodeBytes(std::string_view input) {
        std::string encodedStr(input);
        for (char &c: encodedStr) {
            if (c == '-') c = '+';
            else if (c == '_') c = '/';
        }

        while (encodedStr.size() % 4 != 0) {
            encodedStr.append("=");
        }

        std::vector<unsigned char> decoded(encodedStr.size());
        int decodedLength = EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char*>(encodedStr.data()), encodedStr.size());

        if (decodedLength < 0)
            return {};

        // Trim extra null characters
        while (decodedLength > 0 && decoded[decodedLength - 1] == '\0') {
            decodedLength--;
        }

        decoded.resize(decodedLength);
        return decoded;
    }
}
